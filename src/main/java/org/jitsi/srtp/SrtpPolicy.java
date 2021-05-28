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

/**
 * SrtpPolicy holds the SRTP encryption / authentication policy of a SRTP
 * session.
 *
 * @author Bing SU (nova.su@gmail.com)
 */
public class SrtpPolicy
{
    /**
     * Null Cipher, does not change the content of RTP payload
     */
    public final static int NULL_ENCRYPTION = 0;

    /**
     * Counter Mode AES Cipher, defined in Section 4.1.1, RFC3711
     */
    public final static int AESCM_ENCRYPTION = 1;

    /**
     * Galois/Counter Mode AES Cipher, defined in RFC 7714
     */
    public final static int AESGCM_ENCRYPTION = 5;

    /**
     * Counter Mode TwoFish Cipher
     */
    public final static int TWOFISH_ENCRYPTION = 3;

    /**
     * F8 mode AES Cipher, defined in Section 4.1.2, RFC 3711
     */
    public final static int AESF8_ENCRYPTION = 2;

    /**
     * F8 Mode TwoFish Cipher
     */
    public final static int TWOFISHF8_ENCRYPTION = 4;

    /**
     * Null Authentication, no authentication
     *
     * This should be set if GCM or other AEAD encryption is used.
     */
    public final static int NULL_AUTHENTICATION = 0;

    /**
     * HMAC SHA1 Authentication, defined in Section 4.2.1, RFC3711
     */
    public final static int HMACSHA1_AUTHENTICATION = 1;

    /**
     * Skein Authentication
     */
    public final static int SKEIN_AUTHENTICATION = 2;

    /**
     * SRTP encryption type
     */
    private int encType;

    /**
     * SRTP encryption key length
     */
    private int encKeyLength;

    /**
     * SRTP authentication type
     */
    private int authType;

    /**
     * SRTP authentication key length
     */
    private int authKeyLength;

    /**
     * SRTP authentication tag length.  Also used for GCM tag.
     */
    private int authTagLength;

    /**
     * SRTP salt key length
     */
    private int saltKeyLength;

    /**
     * Whether send-side replay protection is enabled
     */
    private boolean sendReplayEnabled = true;

    /**
     * Whether receive-side replay protection is enabled
     */
    private boolean receiveReplayEnabled = true;

    /**
     * Whether cryptex (header extension encryption) is enabled
     * Note that receiving cryptex is always supported; this only configures
     * whether it will be sent.
     */
    private boolean cryptexEnabled = false;

    /**
     * Construct a SrtpPolicy object based on given parameters.
     * This class acts as a storage class, so all the parameters are passed in
     * through this constructor.
     *
     * @param encType SRTP encryption type
     * @param encKeyLength SRTP encryption key length
     * @param authType SRTP authentication type
     * @param authKeyLength SRTP authentication key length
     * @param authTagLength SRTP authentication tag length
     * @param saltKeyLength SRTP salt key length
     */
    public SrtpPolicy(int encType,
                      int encKeyLength,
                      int authType,
                      int authKeyLength,
                      int authTagLength,
                      int saltKeyLength)
    {
        this.encType = encType;
        this.encKeyLength = encKeyLength;
        this.authType = authType;
        this.authKeyLength = authKeyLength;
        this.authTagLength = authTagLength;
        this.saltKeyLength = saltKeyLength;
    }

    /**
     * Get the authentication key length
     *
     * @return the authentication key length
     */
    public int getAuthKeyLength()
    {
        return this.authKeyLength;
    }

    /**
     * Set the authentication key length
     *
     * @param authKeyLength the authentication key length
     */
    public void setAuthKeyLength(int authKeyLength)
    {
        this.authKeyLength = authKeyLength;
    }

    /**
     * Get the authentication tag length
     *
     * @return the authentication tag length
     */
    public int getAuthTagLength()
    {
        return this.authTagLength;
    }

    /**
     * Set the authentication tag length
     *
     * @param authTagLength the authentication tag length
     */
    public void setAuthTagLength(int authTagLength)
    {
        this.authTagLength = authTagLength;
    }

    /**
     * Get the authentication type
     *
     * @return the authentication type
     */
    public int getAuthType()
    {
        return this.authType;
    }

    /**
     * Set the authentication type
     *
     * @param authType the authentication type
     */
    public void setAuthType(int authType)
    {
        this.authType = authType;
    }

    /**
     * Get the encryption key length
     *
     * @return the encryption key length
     */
    public int getEncKeyLength()
    {
        return this.encKeyLength;
    }

    /**
     * Set the encryption key length
     *
     * @param encKeyLength the encryption key length
     */
    public void setEncKeyLength(int encKeyLength)
    {
        this.encKeyLength = encKeyLength;
    }

    /**
     * Get the encryption type
     *
     * @return the encryption type
     */
    public int getEncType()
    {
        return this.encType;
    }

    /**
     * Set the encryption type
     *
     * @param encType encryption type
     */
    public void setEncType(int encType)
    {
        this.encType = encType;
    }

    /**
     * Get the salt key length
     *
     * @return the salt key length
     */
    public int getSaltKeyLength()
    {
        return this.saltKeyLength;
    }

    /**
     * Set the salt key length
     *
     * @param keyLength the salt key length
     */
    public void setSaltKeyLength(int keyLength)
    {
        this.saltKeyLength = keyLength;
    }

    /**
     * Set whether send-side RTP replay protection is to be enabled.
     * <p>
     * Turn this off if you need to send identical packets more than once (e.g.,
     * retransmission to a peer that does not support the rtx payload.)
     * <b>Note</b>: Never re-send a packet with a different payload!
     *
     * @param enabled {@code true} if send-side replay protection is to be
     *                enabled; {@code false} if not.
     */
    public void setSendReplayEnabled(boolean enabled)
    {
        sendReplayEnabled = enabled;
    }

    /**
     * Get whether send-side RTP replay protection is enabled.
     *
     * @see #isSendReplayDisabled
     */
    public boolean isSendReplayEnabled()
    {
        return sendReplayEnabled;
    }

    /**
     * Get whether send-side RTP replay protection is disabled.
     *
     * @see #isSendReplayEnabled
     */
    public boolean isSendReplayDisabled()
    {
        return !sendReplayEnabled;
    }

    /**
     * Set whether receive-side RTP replay protection is to be enabled.
     * <p>
     * Turn this off if you need to be able to receive identical packets more
     * than once (e.g., if you are an RTP translator, with peers that are doing
     * retransmission without using the rtx payload.)
     * <b>Note</b>: You must make sure your packet handling is idempotent!
     *
     * @param enabled {@code true} if receive-side replay protection is to be
     *                enabled; {@code false} if not.
     */
    public void setReceiveReplayEnabled(boolean enabled)
    {
        receiveReplayEnabled = enabled;
    }

    /**
     * Get whether receive-side RTP replay protection is enabled.
     *
     * @see #isReceiveReplayDisabled
     */
    public boolean isReceiveReplayEnabled()
    {
        return receiveReplayEnabled;
    }

    /**
     * Get whether receive-side RTP replay protection is enabled.
     *
     * @see #isReceiveReplayEnabled
     */
    public boolean isReceiveReplayDisabled()
    {
        return !receiveReplayEnabled;
    }

    /**
     * Set whether cryptex (header extension encryption) is to be enabled,
     * as defined in draft-uberti-avtcore-cryptex-01.
     * <p>
     * Turn this off if you want to send header extensions in the clear.
     * Note that decryption of encrypted header extensions (based on the
     * appropriate values of the "defined by profile" field) is always supported.
     *
     * @param enabled {@code true} if sending encrypted header extensions is to be
     *                enabled; {@code false} if not.
     */
    public void setCryptexEnabled(boolean enabled)
    {
        cryptexEnabled = enabled;
    }

    /**
     * Get whether cryptex (header extension encryption) is enabled,
     * as defined in draft-uberti-avtcore-cryptex-01.
     *
     * @see #isCryptexDisabled
     */
    public boolean isCryptexEnabled()
    {
        return cryptexEnabled;
    }

    /**
     * Get whether cryptex (header extension encryption) is disabled,
     * as defined in draft-uberti-avtcore-cryptex-01.
     *
     * @see #isCryptexEnabled
     */
    public boolean isCryptexDisabled()
    {
        return !cryptexEnabled;
    }
}
