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
 */
package org.jitsi.srtp;

import java.util.*;

import org.bouncycastle.crypto.params.*;
import org.jitsi.bccontrib.params.*;
import org.jitsi.srtp.utils.*;
import org.jitsi.utils.*;
import org.jitsi.utils.logging2.*;

/**
 * SrtcpCryptoContext class is the core class of SRTCP implementation. There can
 * be multiple SRTCP sources in one SRTP session. And each SRTCP stream has a
 * corresponding SrtcpCryptoContext object, identified by sender SSRC. In this way,
 * different sources can be protected independently.
 *
 * SrtcpCryptoContext class acts as a manager class and maintains all the
 * information used in SRTCP transformation. It is responsible for deriving
 * encryption/salting/authentication keys from master keys. And it will invoke
 * certain class to encrypt/decrypt (transform/reverse transform) RTCP packets.
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
public class SrtcpCryptoContext
    extends BaseSrtpCryptoContext
{
    /**
     * Index received so far
     */
    private int receivedIndex = 0;

    /**
     * Index sent so far
     */
    private int sentIndex = 0;

    /**
     * Construct an empty SrtcpCryptoContext using ssrc. The other parameters are
     * set to default null value.
     *
     * @param ssrc SSRC of this SrtcpCryptoContext
     */
    public SrtcpCryptoContext(int ssrc, Logger parentLogger)
    {
        super(ssrc, parentLogger);
    }

    /**
     * Construct a normal SrtcpCryptoContext based on the given parameters.
     *
     * @param ssrc the RTP SSRC that this SRTCP cryptographic context protects.
     * @param masterK byte array holding the master key for this SRTCP
     * cryptographic context. Refer to chapter 3.2.1 of the RFC about the role
     * of the master key.
     * @param masterS byte array holding the master salt for this SRTCP
     * cryptographic context. It is used to computer the initialization vector
     * that in turn is input to compute the session key, session authentication
     * key and the session salt.
     * @param policy SRTP policy for this SRTCP cryptographic context, defined
     * the encryption algorithm, the authentication algorithm, etc
     */
    @SuppressWarnings("fallthrough")
    public SrtcpCryptoContext(
            int ssrc,
            byte[] masterK,
            byte[] masterS,
            SrtpPolicy policy,
            Logger parentLogger)
    {
        super(ssrc, masterK, masterS, policy, parentLogger);

        deriveSrtcpKeys(masterK, masterS);
    }

    /**
     * Checks if a packet is a replayed on based on its sequence number. The
     * method supports a 64 packet history relative to the given sequence
     * number. Sequence Number is guaranteed to be real (not faked) through
     * authentication.
     *
     * @param index index number of the SRTCP packet
     * @return true if this sequence number indicates the packet is not a
     * replayed one, false if not
     */
    SrtpErrorStatus checkReplay(int index)
    {
        // compute the index of previously received packet and its
        // delta to the new received packet
        long delta = index - receivedIndex;

        if (delta > 0)
            return SrtpErrorStatus.OK; // Packet not yet received
        else if (-delta >= REPLAY_WINDOW_SIZE)
            return SrtpErrorStatus.REPLAY_OLD; // Packet too old
        else if (((replayWindow >>> (-delta)) & 0x1) != 0)
            return SrtpErrorStatus.REPLAY_FAIL; // Packet already received!
        else
            return SrtpErrorStatus.OK; // Packet not yet received
    }

    /**
     * Derives the srtcp session keys from the master key.
     */
    private void deriveSrtcpKeys(byte[] masterKey, byte[] masterSalt)
    {
        SrtpKdf kdf = new SrtpKdf(masterKey, masterSalt, policy);

        // compute the session salt
        kdf.deriveSessionKey(saltKey, SrtpKdf.LABEL_RTCP_SALT);

        // compute the session encryption key
        if (cipherCtr != null)
        {
            byte[] encKey = new byte[policy.getEncKeyLength()];
            kdf.deriveSessionKey(encKey, SrtpKdf.LABEL_RTCP_ENCRYPTION);

            if (cipherF8 != null)
            {
                cipherF8.init(encKey, saltKey);
            }
            cipherCtr.init(encKey);
            Arrays.fill(encKey, (byte) 0);
        }

        // compute the session authentication key
        if (mac != null)
        {
            byte[] authKey = new byte[policy.getAuthKeyLength()];
            kdf.deriveSessionKey(authKey, SrtpKdf.LABEL_RTCP_MSG_AUTH);

            switch (policy.getAuthType())
            {
            case SrtpPolicy.HMACSHA1_AUTHENTICATION:
                mac.init(new KeyParameter(authKey));
                break;

            case SrtpPolicy.SKEIN_AUTHENTICATION:
                // Skein MAC uses number of bits as MAC size, not just bytes
                mac.init(
                        new ParametersForSkein(
                                new KeyParameter(authKey),
                                ParametersForSkein.Skein512,
                                tagStore.length * 8));
                break;
            }

            Arrays.fill(authKey, (byte) 0);
        }

        kdf.close();
    }

    /**
     * Performs Counter Mode AES encryption/decryption
     *
     * @param pkt the RTP packet to be encrypted/decrypted
     */
    private void processPacketAesCm(ByteArrayBuffer pkt, int index)
    {
        int ssrc = SrtcpPacketUtils.getSenderSsrc(pkt);

        /* Compute the CM IV (refer to chapter 4.1.1 in RFC 3711):
        *
        * k_s   XX XX XX XX XX XX XX XX XX XX XX XX XX XX
        * SSRC              XX XX XX XX
        * index                               XX XX XX XX
        * ------------------------------------------------------XOR
        * IV    XX XX XX XX XX XX XX XX XX XX XX XX XX XX 00 00
        *        0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
        */
        ivStore[0] = saltKey[0];
        ivStore[1] = saltKey[1];
        ivStore[2] = saltKey[2];
        ivStore[3] = saltKey[3];

        // The shifts transform the ssrc and index into network order
        ivStore[4] = (byte) (((ssrc >> 24) & 0xff) ^ saltKey[4]);
        ivStore[5] = (byte) (((ssrc >> 16) & 0xff) ^ saltKey[5]);
        ivStore[6] = (byte) (((ssrc >> 8) & 0xff) ^ saltKey[6]);
        ivStore[7] = (byte) ((ssrc & 0xff) ^ saltKey[7]);

        ivStore[8] = saltKey[8];
        ivStore[9] = saltKey[9];

        ivStore[10] = (byte) (((index >> 24) & 0xff) ^ saltKey[10]);
        ivStore[11] = (byte) (((index >> 16) & 0xff) ^ saltKey[11]);
        ivStore[12] = (byte) (((index >> 8) & 0xff) ^ saltKey[12]);
        ivStore[13] = (byte) ((index & 0xff) ^ saltKey[13]);

        ivStore[14] = ivStore[15] = 0;

        // Encrypted part excludes fixed header (8 bytes)
        int payloadOffset = 8;
        int payloadLength = pkt.getLength() - payloadOffset;

        cipherCtr.process(
                pkt.getBuffer(), pkt.getOffset() + payloadOffset, payloadLength,
                ivStore);
    }

    /**
     * Performs F8 Mode AES encryption/decryption
     *
     * @param pkt the RTP packet to be encrypted/decrypted
     */
    private void processPacketAesF8(ByteArrayBuffer pkt, int index)
    {
        // 4 bytes of the iv are zero
        // the first byte of the RTP header is not used.
        ivStore[0] = 0;
        ivStore[1] = 0;
        ivStore[2] = 0;
        ivStore[3] = 0;

        // Need the encryption flag
        index = index | 0x80000000;

        // set the index and the encrypt flag in network order into IV
        ivStore[4] = (byte) (index >> 24);
        ivStore[5] = (byte) (index >> 16);
        ivStore[6] = (byte) (index >> 8);
        ivStore[7] = (byte) index;

        // The fixed header follows and fills the rest of the IV
        System.arraycopy(pkt.getBuffer(), pkt.getOffset(), ivStore, 8, 8);

        // Encrypted part excludes fixed header (8 bytes), index (4 bytes), and
        // authentication tag (variable according to policy)
        int payloadOffset = 8;
        int payloadLength = pkt.getLength() - (4 + policy.getAuthTagLength());

        cipherF8.process(
                pkt.getBuffer(), pkt.getOffset() + payloadOffset, payloadLength,
                ivStore);
    }

    /**
     * Transform a SRTCP packet into a RTCP packet. The method is called when an
     * SRTCP packet was received. Operations done by the method include:
     * authentication check, packet replay check and decryption. Both encryption
     * and authentication functionality can be turned off as long as the
     * SrtpPolicy used in this SrtpCryptoContext requires no encryption and no
     * authentication. Then the packet will be sent out untouched. However, this
     * is not encouraged. If no SRTCP feature is enabled, then we shall not use
     * SRTP TransformConnector. We should use the original method (RTPManager
     * managed transportation) instead.
     *
     * @param pkt the received RTCP packet
     * @return <tt>SrtpErrorStatus#OK</tt> if the packet can be accepted or another
     * error status if authentication or replay check failed
     */
    synchronized public SrtpErrorStatus reverseTransformPacket(ByteArrayBuffer pkt)
    {
        boolean decrypt = false;
        int tagLength = policy.getAuthTagLength();

        if (!SrtcpPacketUtils.validatePacketLength(pkt, tagLength))
            /* Too short to be a valid SRTCP packet */
            return SrtpErrorStatus.INVALID_PACKET;

        int indexEflag = SrtcpPacketUtils.getIndex(pkt, tagLength);

        if ((indexEflag & 0x80000000) == 0x80000000)
            decrypt = true;

        int index = indexEflag & ~0x80000000;

        SrtpErrorStatus err;

        /* Replay control */
        if ((err = checkReplay(index)) != SrtpErrorStatus.OK)
        {
            return err;
        }

        /* Authenticate the packet */
        if (policy.getAuthType() != SrtpPolicy.NULL_AUTHENTICATION)
        {
            // get original authentication data and store in tempStore
            pkt.readRegionToBuff(pkt.getLength() - tagLength, tagLength,
                    tempStore);

            // Shrink packet to remove the authentication tag and index
            // because this is part of authenticated data
            pkt.shrink(tagLength + 4);

            // compute, then save authentication in tagStore
            authenticatePacketHmac(pkt, indexEflag);

            // compare authentication tags using constant time comparison
            int nonEqual = 0;
            for (int i = 0; i < tagLength; i++)
            {
                nonEqual |= (tempStore[i] ^ tagStore[i]);
            }
            if (nonEqual != 0)
                return SrtpErrorStatus.AUTH_FAIL;
        }

        if (decrypt)
        {
            /* Decrypt the packet using Counter Mode encryption */
            if (policy.getEncType() == SrtpPolicy.AESCM_ENCRYPTION
                    || policy.getEncType() == SrtpPolicy.TWOFISH_ENCRYPTION)
            {
                processPacketAesCm(pkt, index);
            }

            /* Decrypt the packet using F8 Mode encryption */
            else if (policy.getEncType() == SrtpPolicy.AESF8_ENCRYPTION
                    || policy.getEncType() == SrtpPolicy.TWOFISHF8_ENCRYPTION)
            {
                processPacketAesF8(pkt, index);
            }
        }
        update(index);

        return SrtpErrorStatus.OK;
    }


    /**
     * Transform a RTCP packet into a SRTCP packet. The method is called when a
     * normal RTCP packet ready to be sent. Operations done by the transformation
     * may include: encryption, using either Counter Mode encryption, or F8 Mode
     * encryption, adding authentication tag, currently HMC SHA1 method. Both
     * encryption and authentication functionality can be turned off as long as
     * the SrtpPolicy used in this SrtcpCryptoContext is requires no encryption
     * and no authentication. Then the packet will be sent out untouched.
     * However, this is not encouraged. If no SRTP feature is enabled, then we
     * shall not use SRTP TransformConnector. We should use the original method
     * (RTPManager managed transportation) instead.
     *
     * @param pkt the RTP packet that is going to be sent out
     */
    synchronized public SrtpErrorStatus transformPacket(ByteArrayBuffer pkt)
    {
        boolean encrypt = false;
        /* Encrypt the packet using Counter Mode encryption */
        if (policy.getEncType() == SrtpPolicy.AESCM_ENCRYPTION ||
                policy.getEncType() == SrtpPolicy.TWOFISH_ENCRYPTION)
        {
            processPacketAesCm(pkt, sentIndex);
            encrypt = true;
        }

        /* Encrypt the packet using F8 Mode encryption */
        else if (policy.getEncType() == SrtpPolicy.AESF8_ENCRYPTION ||
                policy.getEncType() == SrtpPolicy.TWOFISHF8_ENCRYPTION)
        {
            processPacketAesF8(pkt, sentIndex);
            encrypt = true;
        }
        int index = 0;
        if (encrypt)
            index = sentIndex | 0x80000000;

        // Grow packet storage in one step
        pkt.grow(4 + policy.getAuthTagLength());

        // Authenticate the packet
        // The authenticate method gets the index via parameter and stores
        // it in network order in rbStore variable.
        if (policy.getAuthType() != SrtpPolicy.NULL_AUTHENTICATION)
        {
            authenticatePacketHmac(pkt, index);
            pkt.append(rbStore, 4);
            pkt.append(tagStore, policy.getAuthTagLength());
        }
        sentIndex++;
        sentIndex &= ~0x80000000;       // clear possible overflow

        return SrtpErrorStatus.OK;
    }

    /**
     * Logs the current state of the replay window, for debugging purposes.
     */
    private void logReplayWindow(long newIdx)
    {
        logger.debug(() -> "Updated replay window with " + newIdx + ". " +
            SrtpPacketUtils.formatReplayWindow(receivedIndex, replayWindow, REPLAY_WINDOW_SIZE));
    }

    /**
     * Updates the SRTP packet index. The method is called after all checks were
     * successful.
     *
     * @param index index number of the accepted packet
     */
    private void update(int index)
    {
        int delta = index - receivedIndex;

        /* update the replay bit mask */
        if (delta >= REPLAY_WINDOW_SIZE)
        {
            replayWindow = 1;
            receivedIndex = index;
        }
        else if (delta > 0)
        {
            replayWindow <<= delta;
            replayWindow |= 1;
            receivedIndex = index;
        }
        else
        {
            replayWindow |= ( 1L << -delta );
        }

        logReplayWindow(index);
    }
}
