/*
 * Copyright @ 2015 - present 8x8, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Some of the code in this class is derived from ccRtp's SRTP implementation,
 * which has the following copyright notice:
 *
 * Copyright (C) 2004-2006 the Minisip Team
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
*/
package org.jitsi.srtp;

import java.security.*;
import javax.crypto.*;
import org.jitsi.srtp.crypto.*;
import org.jitsi.utils.*;
import org.jitsi.utils.logging2.*;

/**
 * SrtpCryptoContext class is the core class of SRTP implementation. There can
 * be multiple SRTP sources in one SRTP session. And each SRTP stream has a
 * corresponding SrtpCryptoContext object, identified by SSRC. In this way,
 * different sources can be protected independently.
 *
 * SrtpCryptoContext class acts as a manager class and maintains all the
 * information used in SRTP transformation. It is responsible for deriving
 * encryption/salting/authentication keys from master keys. And it will invoke
 * certain class to encrypt/decrypt (transform/reverse transform) RTP packets.
 * It will hold a replay check db and do replay check against incoming packets.
 *
 * Refer to section 3.2 in RFC3711 for detailed description of cryptographic
 * context.
 *
 * Cryptographic related parameters, i.e. encryption mode / authentication mode,
 * master encryption key and master salt key are determined outside the scope of
 * SRTP implementation. They can be assigned manually, or can be assigned
 * automatically using some key management protocol, such as MIKEY (RFC3830),
 * SDES (RFC4568) or Phil Zimmermann's ZRTP protocol (RFC6189).
 *
 * @author Bing SU (nova.su@gmail.com)
 * @author Lyubomir Marinov
 */
public class BaseSrtpCryptoContext
{
    /**
     * The replay check windows size.
     */
    protected static final long REPLAY_WINDOW_SIZE = 64;

    /**
     * Cipher to encrypt packets.
     */
    protected final SrtpCipher cipher;

    /**
     * Temp store.
     */
    protected final byte[] ivStore;

    /**
     * The HMAC object we used to do packet authentication
     */
    protected final Mac mac; // used for various HMAC computations

    /**
     * Encryption / Authentication policy for this session
     */
    protected final SrtpPolicy policy;

    /**
     * Temp store.
     */
    protected final byte[] rbStore = new byte[4];

    /**
     * Bit mask for replay check
     */
    protected long replayWindow;

    /**
     * Derived session salting key
     */
    protected final byte[] saltKey;

    /**
     * RTP/RTCP SSRC of this cryptographic context
     */
    protected final int ssrc;

    /**
     * this is a working store, used by some methods to avoid new operations
     * the methods must use this only to store results for immediate processing
     */
    protected final byte[] tempStore = new byte[100];

    /**
     * Logger for BaseSrtpCryptoContext and derived objects.
     */
    protected final Logger logger;

    protected BaseSrtpCryptoContext(
            int ssrc,
            byte[] masterK,
            byte[] masterS,
            SrtpPolicy policy,
            Logger parentLogger)
        throws GeneralSecurityException
    {
        logger = parentLogger.createChildLogger(this.getClass().getName());
        this.ssrc = ssrc;
        this.policy = policy;

        int encKeyLength = policy.getEncKeyLength();

        if (masterK != null)
        {
            if (masterK.length != encKeyLength)
            {
                throw new IllegalArgumentException("masterK.length != encKeyLength");
            }
        }
        else
        {
            if (encKeyLength != 0)
            {
                throw new IllegalArgumentException("null masterK but encKeyLength != 0");
            }
        }
        int saltKeyLength = policy.getSaltKeyLength();

        if (masterS != null)
        {
            if (masterS.length != saltKeyLength)
            {
                throw new IllegalArgumentException("masterS.length != saltKeyLength");
            }
        }
        else {
            if (saltKeyLength != 0)
            {
                throw new IllegalArgumentException("null masterS but saltKeyLength != 0");
            }
        }

        saltKey = new byte[saltKeyLength];
        int ivSize = 16;
        switch (policy.getEncType())
        {
        case SrtpPolicy.AESCM_ENCRYPTION:
            cipher = new SrtpCipherCtr(Aes.createCipher("AES/CTR/NoPadding"));
            break;
        case SrtpPolicy.AESGCM_ENCRYPTION:
            if (policy.getAuthTagLength() != 16)
            {
                throw new IllegalArgumentException("SRTP only supports 16-octet GCM auth tags");
            }
            cipher = new SrtpCipherGcm(Aes.createCipher("AES/GCM/NoPadding"));
            ivSize = 12;
            break;
        case SrtpPolicy.AESF8_ENCRYPTION:
            cipher = new SrtpCipherF8(Aes.createCipher("AES/ECB/NoPadding"));
            break;
        case SrtpPolicy.TWOFISHF8_ENCRYPTION:
            cipher = new SrtpCipherF8(Cipher.getInstance("Twofish/ECB/NoPadding"));
            break;
        case SrtpPolicy.TWOFISH_ENCRYPTION:
            cipher = new SrtpCipherCtr(Cipher.getInstance("Twofish/CTR/NoPadding"));
            break;
        case SrtpPolicy.NULL_ENCRYPTION:
        default:
            cipher = null;
            ivSize = 0;
            break;
        }

        ivStore = new byte[ivSize];

        Mac mac;
        switch (policy.getAuthType())
        {
        case SrtpPolicy.HMACSHA1_AUTHENTICATION:
            mac = HmacSha1.createMac(parentLogger);
            break;

        case SrtpPolicy.SKEIN_AUTHENTICATION:
            mac = Mac.getInstance("SkeinMac_512_" + (policy.getAuthTagLength() * 8));
            break;

        case SrtpPolicy.NULL_AUTHENTICATION:
        default:
            mac = null;
            break;
        }
        this.mac = mac;
    }


    /**
     * Writes roc / index to the rbStore buffer.
     */
    protected void writeRoc(int rocIn)
    {
        rbStore[0] = (byte) (rocIn >> 24);
        rbStore[1] = (byte) (rocIn >> 16);
        rbStore[2] = (byte) (rocIn >> 8);
        rbStore[3] = (byte) rocIn;
    }

    /**
     * Authenticates a packet.
     *
     * @param pkt the RTP packet to be authenticated
     * @param rocIn Roll-Over-Counter
     */
    synchronized protected byte[] authenticatePacketHmac(ByteArrayBuffer pkt, int rocIn)
    {
        mac.update(pkt.getBuffer(), pkt.getOffset(), pkt.getLength());
        writeRoc(rocIn);
        mac.update(rbStore, 0, rbStore.length);
        return mac.doFinal();
    }

    /**
     * Gets the authentication tag length of this SRTP cryptographic context
     *
     * @return the authentication tag length of this SRTP cryptographic context
     */
    public int getAuthTagLength()
    {
        return policy.getAuthTagLength();
    }

    /**
     * Gets the SSRC of this SRTP cryptographic context
     *
     * @return the SSRC of this SRTP cryptographic context
     */
    public int getSsrc()
    {
        return ssrc;
    }
}
