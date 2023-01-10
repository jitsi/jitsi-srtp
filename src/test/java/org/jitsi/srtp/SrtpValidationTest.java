/*
 * Copyright @ 2019 - present 8x8, Inc
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

import static org.junit.jupiter.api.Assertions.*;
import static org.jitsi.srtp.Assertions.*;

import jakarta.xml.bind.*;
import org.jitsi.utils.*;
import org.jitsi.utils.logging2.*;
import org.junit.jupiter.api.*;

import static jakarta.xml.bind.DatatypeConverter.parseHexBinary;
import java.util.*;


public class SrtpValidationTest {
    /* Test cases from libsrtp's srtp_driver.c. */
    private static final byte[] test_key =
            parseHexBinary("e1f97a0d3e018be0d64fa32c06de4139");
    private static final byte[] test_key_salt =
            parseHexBinary("0ec675ad498afeebb6960b3aabe6");

    private static final byte[] rtp_plaintext_ref =
            parseHexBinary("800f1234decafbad" +
					     "cafebabeabababab" +
					     "abababababababab" +
					     "abababab");
    private static final byte[] rtp_plaintext =
            parseHexBinary("800f1234decafbad" +
					     "cafebabeabababab" +
					     "abababababababab" +
					     "abababab00000000" +
					     "000000000000");
    private static final byte[] srtp_ciphertext =
            parseHexBinary("800f1234decafbad" +
					     "cafebabe4e55dc4c" +
					     "e79978d88ca4d215" +
					     "949d2402b78d6acc" +
					     "99ea179b8dbb");
    private static final byte[] rtcp_plaintext_ref =
            parseHexBinary("81c8000bcafebabe" +
					     "abababababababab" +
					     "abababababababab");
    private static final byte[] rtcp_plaintext =
            parseHexBinary("81c8000bcafebabe" +
					     "abababababababab" +
					     "abababababababab" +
					     "0000000000000000" +
					     "000000000000");
    private static final byte[] srtcp_ciphertext =
            parseHexBinary("81c8000bcafebabe" +
					     "7128035be487b9bd" +
					     "bef89041f977a5a8" +
					     "80000001993e08cd" +
					     "54d6c1230798");

    @Test
    public void srtpValidateCtrHmac() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
                new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                        80/8, 112/8 );

        SrtpContextFactory senderFactory = new SrtpContextFactory(true, test_key, test_key_salt, policy, policy, logger);
        SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy, logger);

        SrtpCryptoContext rtpSend = senderFactory.deriveContext(0xcafebabe, 0);

        ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(rtp_plaintext, 0, rtp_plaintext_ref.length);

        assertEquals(SrtpErrorStatus.OK, rtpSend.transformPacket(rtpPkt));
        assertEquals(srtp_ciphertext.length, rtpPkt.getLength());
        assertArrayEquals(srtp_ciphertext, rtpPkt.getBuffer());

        SrtcpCryptoContext rtcpSend = senderFactory.deriveControlContext(0xcafebabe);

        ByteArrayBuffer rtcpPkt = new ByteArrayBufferImpl(rtcp_plaintext, 0, rtcp_plaintext_ref.length);
        rtcpSend.transformPacket(rtcpPkt);

        /* The reference srtcp buffer, above, includes an RTCP index of 1.
         * Our implementation writes the srtcp index itself, counting from 0.
         * Thus, reset the packet and encrypt it a second time to get the expected output.
         */
        System.arraycopy(rtcp_plaintext_ref, 0, rtcpPkt.getBuffer(), 0, rtcp_plaintext_ref.length);
        rtcpPkt.setLength(rtcp_plaintext_ref.length);

        assertEquals(SrtpErrorStatus.OK, rtcpSend.transformPacket(rtcpPkt));
        assertEquals(srtcp_ciphertext.length, rtcpPkt.getLength());
        assertArrayEquals(srtcp_ciphertext, rtcpPkt.getBuffer());

        SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

        assertEquals(SrtpErrorStatus.OK, rtpRecv.reverseTransformPacket(rtpPkt, false));
        assertEquals(rtp_plaintext_ref.length, rtpPkt.getLength());
        assertArrayEquals(rtp_plaintext_ref, Arrays.copyOf(rtpPkt.getBuffer(), rtpPkt.getLength()));

        SrtcpCryptoContext rtcpRecv = receiverFactory.deriveControlContext(0xcafebabe);

        assertEquals(SrtpErrorStatus.OK, rtcpRecv.reverseTransformPacket(rtcpPkt));
        assertEquals(rtcp_plaintext_ref.length, rtcpPkt.getLength());
        assertArrayEquals(rtcp_plaintext_ref, Arrays.copyOf(rtcpPkt.getBuffer(), rtcpPkt.getLength()));

        senderFactory.close();
        receiverFactory.close();
    }

    @Test
    public void rejectInvalidCtrHmac() throws Exception
    {
        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                    SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                    80/8, 112/8 );
        Logger logger = new LoggerImpl(getClass().getName());

        for (int len = srtp_ciphertext.length; len > 0; len--)
        {
            SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy, logger);
            SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

            ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(Arrays.copyOf(srtp_ciphertext, len), 0, len);

            SrtpErrorStatus status = rtpRecv.reverseTransformPacket(rtpPkt, false);

            if (len == srtp_ciphertext.length)
            {
                assertEquals(SrtpErrorStatus.OK, status, "Rejected valid SRTP packet");
            }
            else
            {
                assertNotEquals(SrtpErrorStatus.OK, status, "Accepted truncated SRTP packet");
            }
        }

        for (int i = 0; i < srtp_ciphertext.length; i++) {
            for (int j = 0; j < 8; j++) {
                SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy, logger);
                SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

                ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(srtp_ciphertext.clone(), 0, srtp_ciphertext.length);

                /* Flip one bit */
                rtpPkt.getBuffer()[i] ^= (1 << j);

                assertNotEquals(SrtpErrorStatus.OK, rtpRecv.reverseTransformPacket(rtpPkt, false),
                    "Accepted RTP packet with bit flipped");
            }
        }

        for (int len = srtcp_ciphertext.length; len > 0; len--) {
            SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy, logger);
            SrtcpCryptoContext rtcpRecv = receiverFactory.deriveControlContext(0xcafebabe);

            ByteArrayBuffer rtcpPkt = new ByteArrayBufferImpl(Arrays.copyOf(srtcp_ciphertext, len), 0, len);

            SrtpErrorStatus status = rtcpRecv.reverseTransformPacket(rtcpPkt);

            if (len == srtcp_ciphertext.length)
            {
                assertEquals(SrtpErrorStatus.OK, status, "Rejected valid SRTCP packet");
            }
            else
            {
                assertNotEquals(SrtpErrorStatus.OK, status, "Accepted truncated SRTCP packet");
            }
        }

        for (int i = 0; i < srtcp_ciphertext.length; i++) {
            for (int j = 0; j < 8; j++) {
                SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy, logger);
                SrtcpCryptoContext rtcpRecv = receiverFactory.deriveControlContext(0xcafebabe);

                ByteArrayBuffer rtcpPkt = new ByteArrayBufferImpl(srtcp_ciphertext.clone(), 0, srtcp_ciphertext.length);

                /* Flip one bit */
                rtcpPkt.getBuffer()[i] ^= (1 << j);

                assertNotEquals(SrtpErrorStatus.OK, rtcpRecv.reverseTransformPacket(rtcpPkt),
                    "Accepted RTCP packet with bit flipped");
            }
        }
    }

    @Test
    public void skipDecryptionCtrHmac() throws Exception
    {
        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                80/8, 112/8 );
        Logger logger = new LoggerImpl(getClass().getName());

        for (int len = srtp_ciphertext.length; len > 0; len--)
        {
            SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy, logger);
            SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

            ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(Arrays.copyOf(srtp_ciphertext, len), 0, len);

            SrtpErrorStatus status = rtpRecv.reverseTransformPacket(rtpPkt, true);

            if (len == srtp_ciphertext.length)
            {
                assertEquals(SrtpErrorStatus.OK, status, "Rejected valid SRTP packet when skipping decryption");
            }
            else
            {
                assertNotEquals(SrtpErrorStatus.OK, status, "Accepted truncated SRTP packet when skipping decryption");
            }
        }

        for (int i = 0; i < srtp_ciphertext.length; i++) {
            for (int j = 0; j < 8; j++) {
                SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy, logger);
                SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

                ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(srtp_ciphertext.clone(), 0, srtp_ciphertext.length);

                /* Flip one bit */
                rtpPkt.getBuffer()[i] ^= (1 << j);

                assertNotEquals(SrtpErrorStatus.OK, rtpRecv.reverseTransformPacket(rtpPkt, true),
                    "Accepted RTP packet with bit flipped when skipping decryption");
            }
        }
    }

    /* GCM test cases from libsrtp's srtp_driver.c. */
    private static final byte[] test_key_gcm =
        parseHexBinary("0001020304050607" +
            "08090a0b0c0d0e0f");

    private static final byte[] test_key_salt_gcm =
        parseHexBinary("a0a1a2a3a4a5a6a7" +
            "a8a9aaab");

    private static final byte[] rtp_plaintext_gcm =
        parseHexBinary("800f1234decafbad" +
            "cafebabeabababab" +
            "abababababababab" +
            "abababab00000000" +
            "0000000000000000" +
            "00000000");

    private static final byte[] srtp_ciphertext_gcm =
        parseHexBinary("800f1234decafbad" +
            "cafebabec5002ede" +
            "04cfdd2eb91159e0" +
            "880aa06ed2976826" +
            "f796b201df3131a1" +
            "27e8a392");

    private static final byte[] rtcp_plaintext_gcm =
        parseHexBinary("81c8000bcafebabe" +
            "abababababababab" +
            "abababababababab" +
            "0000000000000000" +
            "0000000000000000" +
            "00000000");


    private static final byte[] srtcp_ciphertext_gcm =
        parseHexBinary("81c8000bcafebabe" +
            "c98b8b5df0392a55" +
            "852b6c21ac8e7025" +
            "c52c6fbea2b3b446" +
            "ea31123ba88ce61e" +
            "80000001");

    @Test
    public void srtpValidateGcm() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128/8,
                SrtpPolicy.NULL_AUTHENTICATION, 0,
                128/8, 96/8 );

        SrtpContextFactory senderFactory = new SrtpContextFactory(true, test_key_gcm, test_key_salt_gcm, policy, policy, logger);
        SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key_gcm, test_key_salt_gcm, policy, policy, logger);

        SrtpCryptoContext rtpSend = senderFactory.deriveContext(0xcafebabe, 0);

        ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(rtp_plaintext_gcm, 0, rtp_plaintext_ref.length);

        assertEquals(SrtpErrorStatus.OK, rtpSend.transformPacket(rtpPkt));
        assertByteArrayBufferEquals(srtp_ciphertext_gcm, rtpPkt);
        assertEquals(srtp_ciphertext_gcm.length, rtpPkt.getLength());
        assertArrayEquals(srtp_ciphertext_gcm, rtpPkt.getBuffer());

        SrtcpCryptoContext rtcpSend = senderFactory.deriveControlContext(0xcafebabe);

        ByteArrayBuffer rtcpPkt = new ByteArrayBufferImpl(rtcp_plaintext_gcm, 0, rtcp_plaintext_ref.length);
        rtcpSend.transformPacket(rtcpPkt);

        /* The reference srtcp buffer, above, includes an RTCP index of 1.
         * Our implementation writes the srtcp index itself, counting from 0.
         * Thus, reset the packet and encrypt it a second time to get the expected output.
         */
        System.arraycopy(rtcp_plaintext_ref, 0, rtcpPkt.getBuffer(), 0, rtcp_plaintext_ref.length);
        rtcpPkt.setLength(rtcp_plaintext_ref.length);

        assertEquals(SrtpErrorStatus.OK, rtcpSend.transformPacket(rtcpPkt));
        assertEquals(srtcp_ciphertext_gcm.length, rtcpPkt.getLength());
        assertArrayEquals(srtcp_ciphertext_gcm, rtcpPkt.getBuffer());

        SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

        assertEquals(SrtpErrorStatus.OK, rtpRecv.reverseTransformPacket(rtpPkt, false));
        assertEquals(rtp_plaintext_ref.length, rtpPkt.getLength());
        assertArrayEquals(
            rtp_plaintext_ref, Arrays.copyOf(rtpPkt.getBuffer(), rtpPkt.getLength()));

        SrtcpCryptoContext rtcpRecv = receiverFactory.deriveControlContext(0xcafebabe);

        assertEquals(SrtpErrorStatus.OK, rtcpRecv.reverseTransformPacket(rtcpPkt));
        assertEquals(rtcp_plaintext_ref.length, rtcpPkt.getLength());
        assertArrayEquals(rtcp_plaintext_ref, Arrays.copyOf(rtcpPkt.getBuffer(), rtcpPkt.getLength()));

        senderFactory.close();
        receiverFactory.close();
    }

    @Test
    public void rejectInvalidGcm() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128/8,
                SrtpPolicy.NULL_AUTHENTICATION, 0,
                128/8, 96/8 );

        for (int len = srtp_ciphertext_gcm.length; len > 0; len--)
        {
            SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key_gcm, test_key_salt_gcm, policy, policy, logger);
            SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

            ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(Arrays.copyOf(srtp_ciphertext_gcm, len), 0, len);

            SrtpErrorStatus status = rtpRecv.reverseTransformPacket(rtpPkt, false);

            if (len == srtp_ciphertext_gcm.length)
            {
                assertEquals(SrtpErrorStatus.OK, status, "Rejected valid SRTP packet");
            }
            else
            {
                assertNotEquals(SrtpErrorStatus.OK, status, "Accepted truncated SRTP packet");
            }
        }

        for (int i = 0; i < srtp_ciphertext_gcm.length; i++) {
            for (int j = 0; j < 8; j++) {
                SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key_gcm, test_key_salt_gcm, policy, policy, logger);
                SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

                ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(srtp_ciphertext_gcm.clone(), 0, srtp_ciphertext_gcm.length);

                /* Flip one bit */
                rtpPkt.getBuffer()[i] ^= (1 << j);

                assertNotEquals(SrtpErrorStatus.OK, rtpRecv.reverseTransformPacket(rtpPkt, false),
                    "Accepted RTP packet with bit flipped");
            }
        }

        for (int len = srtcp_ciphertext_gcm.length; len > 0; len--) {
            SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key_gcm, test_key_salt_gcm, policy, policy, logger);
            SrtcpCryptoContext rtcpRecv = receiverFactory.deriveControlContext(0xcafebabe);

            ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(Arrays.copyOf(srtcp_ciphertext_gcm, len), 0, len);

            SrtpErrorStatus status = rtcpRecv.reverseTransformPacket(rtpPkt);

            if (len == srtcp_ciphertext_gcm.length)
            {
                assertEquals(SrtpErrorStatus.OK, status, "Rejected valid SRTCP packet");
            }
            else
            {
                assertNotEquals(SrtpErrorStatus.OK, status, "Accepted truncated SRTCP packet");
            }
        }

        for (int i = 0; i < srtcp_ciphertext_gcm.length; i++) {
            for (int j = 0; j < 8; j++) {
                SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key_gcm, test_key_salt_gcm, policy, policy, logger);
                SrtcpCryptoContext rtcpRecv = receiverFactory.deriveControlContext(0xcafebabe);

                ByteArrayBuffer rtcpPkt = new ByteArrayBufferImpl(srtcp_ciphertext_gcm.clone(), 0, srtcp_ciphertext_gcm.length);

                /* Flip one bit */
                rtcpPkt.getBuffer()[i] ^= (1 << j);

                assertNotEquals(SrtpErrorStatus.OK, rtcpRecv.reverseTransformPacket(rtcpPkt),
                    "Accepted RTCP packet with bit flipped");
            }
        }
    }

    @Test
    public void skipDecryptionGcm() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128/8,
                SrtpPolicy.NULL_AUTHENTICATION, 0,
                128/8, 96/8 );

        for (int len = srtp_ciphertext_gcm.length; len > 0; len--)
        {
            SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key_gcm, test_key_salt_gcm, policy, policy, logger);
            SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

            ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(Arrays.copyOf(srtp_ciphertext_gcm, len), 0, len);

            SrtpErrorStatus status = rtpRecv.reverseTransformPacket(rtpPkt, true);

            if (len == srtp_ciphertext_gcm.length)
            {
                assertEquals(SrtpErrorStatus.OK, status, "Rejected valid SRTP packet when skipping decryption");
            }
            else
            {
                assertNotEquals(SrtpErrorStatus.OK, status, "Accepted truncated SRTP packet when skipping decryption");
            }
        }

        for (int i = 0; i < srtp_ciphertext_gcm.length; i++) {
            for (int j = 0; j < 8; j++) {
                SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key_gcm, test_key_salt_gcm, policy, policy, logger);
                SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

                ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(srtp_ciphertext_gcm.clone(), 0, srtp_ciphertext_gcm.length);

                /* Flip one bit */
                rtpPkt.getBuffer()[i] ^= (1 << j);

                assertNotEquals(SrtpErrorStatus.OK, rtpRecv.reverseTransformPacket(rtpPkt, true),
                    "Accepted RTP packet with bit flipped when skipping decryption");
            }
        }
    }

    /* Plaintext packet with 1-byte header extension */
    private static final byte[] rtp_1bytehdrext =
        parseHexBinary("900f1235decafbad" +
            "cafebabe" +
            "bede0001" +
            "51000200" +
            "abababab" +
            "abababababababab" +
            "abababab"
        );

    /* AES-CTR/HMAC-SHA1 Ciphertext packet with 1-byte header extension */
    private static final byte[] srtp_1bytehdrext_cryptex =
        parseHexBinary("900f1235decafbad" +
            "cafebabe" +
            "c0de0001" +
            "eb923652" +
            "51c3e036f8de27e9" +
            "c27ee3e0" +
            "b4651d9f" +
            "bc4218a70244522f34a5"
        );

    /* Plaintext packet with 2-byte header extension */
    private static final byte[] rtp_2bytehdrext =
        parseHexBinary("900f1236decafbad" +
            "cafebabe" +
            "10000001" +
            "05020002" +
            "abababab" +
            "abababababababab" +
            "abababab");

    /* AES-CTR/HMAC-SHA1 Ciphertext packet with 2-byte header extension */
    private static final byte[] srtp_2bytehdrext_cryptex =
        parseHexBinary("900f1236decafbad" +
            "cafebabe" +
            "c2de0001" +
            "4ed9cc4e" +
            "6a712b309" +
            "6c5ca77339d4204ce0" +
            "d77396cab" +
            "69585fbce38194a5");

    /* Plaintext packet with unknown header extension type.  Cryptex should
     * leave it unchanged.
     */
    private static final byte[] rtp_unkhdrext =
        parseHexBinary("900f1237decafbad" +
            "cafebabe" +
            "0bad0001" +
            "dededede" +
            "abababab" +
            "abababababababab" +
            "abababab");

    private static final byte[] srtp_unkhdrext_cryptex =
        parseHexBinary("900f1237decafbad" +
            "cafebabe" +
            "0bad0001" +
            "dededede" +
            "f0d0ad5d" +
            "827c05082c5e8a9d" +
            "3515a8ff" +
            "9faae0dda2f8787c254e");

    /* Plaintext packet with 1-byte header extension and CSRC fields. */
    private static final byte[] rtp_1bytehdrext_cc =
        parseHexBinary("920f1238decafbad" +
            "cafebabe" +
            "0001e240" +
            "0000b26e" +
            "bede0001" +
            "51000200" +
            "abababab" +
            "abababababababab" +
            "abababab");

    private static final byte[] srtp_1bytehdrext_cc_cryptex =
        parseHexBinary("920f1238decafbad" +
            "cafebabe" +
            "8bb6e12b" +
            "5cff16dd" +
            "c0de0001" +
            "92838c8c" +
            "09e58393" +
            "e1de3a9a74734d67" +
            "45671338" +
            "c3acf11da2df8423bee0");

    /* Plaintext packet with 2-byte header extension and CSRC fields. */
    private static final byte[] rtp_2bytehdrext_cc =
        parseHexBinary("920f1239decafbad" +
            "cafebabe" +
            "0001e240" +
            "0000b26e" +
            "10000001" +
            "05020002" +
            "abababab" +
            "abababababababab" +
            "abababab");

    private static final byte[] srtp_2bytehdrext_cc_cryptex =
        parseHexBinary("920f1239decafbad"
            + "cafebabe"
            + "f70e513e"
            + "b90b9b25"
            + "c2de0001"
            + "bbed4848"
            + "faa64466"
            + "5f3d7f34125914e9"
            + "f4d0ae92"
            + "3c6f479b95a0f7b53133");

    /* Plaintext packet with no header extension and CSRC fields. */
    private static final byte[] rtp_nohdr_cc =
        parseHexBinary("820f123adecafbad" +
            "cafebabe" +
            "0001e240" +
            "0000b26e" +
            "abababab" +
            "abababababababab" +
            "abababab");


    /* Plaintext packet with empty 1-byte header extension and CSRC fields. */
    private static final byte[] rtp_1byte_empty_hdrext_cc =
        parseHexBinary("920f123adecafbad" +
            "cafebabe" +
            "0001e240" +
            "0000b26e" +
            "bede0000" +
            "abababab" +
            "abababababababab" +
            "abababab");

    private static final byte[] srtp_1byte_empty_hdrext_cc_cryptex =
        parseHexBinary("920f123adecafbad" +
            "cafebabe" +
            "7130b6ab" +
            "fe2ab0e3" +
            "c0de0000" +
            "e3d9f64b" +
            "25c9e74cb4cf8e43" +
            "fb92e378" +
            "1c2c0ceab6b3a499a14c");

    /* Plaintext packet with empty 2-byte header extension and CSRC fields. */
    private static final byte[] rtp_2byte_empty_hdrext_cc =
        parseHexBinary("920f123bdecafbad" +
            "cafebabe" +
            "0001e240" +
            "0000b26e" +
            "10000000" +
            "abababab" +
            "abababababababab" +
            "abababab");

    private static final byte[] srtp_2byte_empty_hdrext_cc_cryptex =
        parseHexBinary("920f123bdecafbad" +
            "cafebabe" +
            "cbf24c12" +
            "4330e1c8" +
            "c2de0000" +
            "599dd45b" +
            "c9d687b603e8b59d" +
            "771fd38e" +
            "88b170e0cd31e125eabe");


    /* Test a single packet, verifying it encrypts to the given ciphertext and decrypts back to its plaintext. */
    private static void testPacketOnce(SrtpCryptoContext rtpSend, SrtpCryptoContext rtpRecv,
        byte[] plaintext, byte[] ciphertext,
        int authTagLen, int offset)
        throws Exception
    {
        byte[] data = new byte[offset + plaintext.length + authTagLen];
        System.arraycopy(plaintext, 0, data, offset, plaintext.length);
        ByteArrayBuffer pkt = new ByteArrayBufferImpl(data, offset, plaintext.length);

        assertEquals(SrtpErrorStatus.OK, rtpSend.transformPacket(pkt));
        // Uncomment this to generate or debug ciphertext
        // System.out.println(DatatypeConverter.printHexBinary(pkt.getBuffer()).toLowerCase());
        assertByteArrayBufferEquals(ciphertext, pkt);

        assertEquals(SrtpErrorStatus.OK, rtpRecv.reverseTransformPacket(pkt, false));
        assertByteArrayBufferEquals(plaintext, pkt);
    }

    /* Test a single packet, with it placed at various offsets in the ByteArrayBuffer. */
    private static void testPacket(SrtpCryptoContext rtpSend, SrtpCryptoContext rtpRecv,
        byte[] plaintext, byte[] ciphertext,
        int authTagLen)
        throws Exception
    {
        for (int offset = 0; offset < 16; offset++) {
            testPacketOnce(rtpSend, rtpRecv, plaintext, ciphertext, authTagLen, offset);
        }
    }


    /* Test a single packet, when the reconstructed plaintext is not identical to the original encrypted plaintext. */
    private static void testPacketAsymmetricOnce(SrtpCryptoContext rtpSend, SrtpCryptoContext rtpRecv,
        byte[] plaintextOrig, byte[] ciphertext, byte[] plainTextDecrypted,
        int extraBufSpace, int offset)
        throws Exception
    {
        byte[] data = new byte[offset + plaintextOrig.length + extraBufSpace];
        System.arraycopy(plaintextOrig, 0, data, offset, plaintextOrig.length);
        ByteArrayBuffer pkt = new ByteArrayBufferImpl(data, offset, plaintextOrig.length);

        assertEquals(SrtpErrorStatus.OK, rtpSend.transformPacket(pkt));
        // Uncomment this to generate or debug ciphertext
        // System.out.println(DatatypeConverter.printHexBinary(pkt.getBuffer()).toLowerCase());
        assertByteArrayBufferEquals(ciphertext, pkt);

        assertEquals(SrtpErrorStatus.OK, rtpRecv.reverseTransformPacket(pkt, false));
        assertByteArrayBufferEquals(plainTextDecrypted, pkt);
    }

    private static void testPacketAsymmetric(SrtpCryptoContext rtpSend, SrtpCryptoContext rtpRecv,
        byte[] plaintextOrig, byte[] ciphertext, byte[] plainTextDecrypted,
        int authTagLen)
        throws Exception
    {
        for (int offset = 0; offset < 16; offset++) {
            testPacketAsymmetricOnce(rtpSend, rtpRecv, plaintextOrig, ciphertext, plainTextDecrypted, authTagLen, offset);
        }
        for (int offset = 0; offset < 16; offset++) {
            testPacketAsymmetricOnce(rtpSend, rtpRecv, plaintextOrig, ciphertext, plainTextDecrypted, authTagLen, offset + 4);
        }
    }


    /* Test that a packet authenticates and decrypts when unmodified, and
     * fails to decrypt when truncated or bit-flipped.
     */
    private static void testRejectInvalid(SrtpCryptoContext rtpRecv, byte[] ciphertext)
    throws Exception
    {
        for (int i = 0; i < srtp_ciphertext.length; i++) {
            for (int j = 0; j < 8; j++) {
                ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(ciphertext.clone(), 0, ciphertext.length);

                /* Flip one bit */
                rtpPkt.getBuffer()[i] ^= (1 << j);

                assertNotEquals(SrtpErrorStatus.OK, rtpRecv.reverseTransformPacket(rtpPkt, false),
                    "Accepted RTP packet with bit flipped");
            }
        }

        for (int len = srtp_ciphertext.length; len > 0; len--)
        {
            ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(Arrays.copyOf(ciphertext, len), 0, len);

            SrtpErrorStatus status = rtpRecv.reverseTransformPacket(rtpPkt, false);

            if (len == ciphertext.length)
            {
                assertEquals(SrtpErrorStatus.OK, status, "Rejected valid SRTP packet");
            }
            else
            {
                assertNotEquals(SrtpErrorStatus.OK, status, "Accepted truncated SRTP packet");
            }
        }
    }

    @Test
    public void testCryptexCtrHmac() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                80/8, 112/8 );
        policy.setCryptexEnabled(true);

        policy.setSendReplayEnabled(false);
        policy.setReceiveReplayEnabled(false);
        // So we can encrypt and decrypt packets multiple times, with different offsets.

        SrtpContextFactory senderFactory = new SrtpContextFactory(true, test_key, test_key_salt, policy, policy, logger);
        SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy, logger);

        SrtpCryptoContext rtpSend = senderFactory.deriveContext(0xcafebabe, 0);
        SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

        testPacket(rtpSend, rtpRecv, rtp_plaintext_ref, srtp_ciphertext, policy.getAuthTagLength());

        testPacket(rtpSend, rtpRecv, rtp_1bytehdrext, srtp_1bytehdrext_cryptex, policy.getAuthTagLength());
        testPacket(rtpSend, rtpRecv, rtp_2bytehdrext, srtp_2bytehdrext_cryptex, policy.getAuthTagLength());
        testPacket(rtpSend, rtpRecv, rtp_unkhdrext, srtp_unkhdrext_cryptex, policy.getAuthTagLength());

        testPacket(rtpSend, rtpRecv, rtp_1bytehdrext_cc, srtp_1bytehdrext_cc_cryptex, policy.getAuthTagLength());
        testPacket(rtpSend, rtpRecv, rtp_2bytehdrext_cc, srtp_2bytehdrext_cc_cryptex, policy.getAuthTagLength());

        testPacket(rtpSend, rtpRecv, rtp_1byte_empty_hdrext_cc, srtp_1byte_empty_hdrext_cc_cryptex, policy.getAuthTagLength());
        testPacket(rtpSend, rtpRecv, rtp_2byte_empty_hdrext_cc, srtp_2byte_empty_hdrext_cc_cryptex, policy.getAuthTagLength());

        testPacketAsymmetric(rtpSend, rtpRecv, rtp_nohdr_cc, srtp_1byte_empty_hdrext_cc_cryptex, rtp_1byte_empty_hdrext_cc, policy.getAuthTagLength() + 4);
    }

    @Test
    public void rejectInvalidCryptexCtrHmac() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                80/8, 112/8 );
        policy.setCryptexEnabled(true);

        SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy, logger);

        SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

        testRejectInvalid(rtpRecv, srtp_ciphertext);

        testRejectInvalid(rtpRecv, srtp_1bytehdrext_cryptex);
        testRejectInvalid(rtpRecv, srtp_2bytehdrext_cryptex);
        testRejectInvalid(rtpRecv, srtp_unkhdrext_cryptex);

        testRejectInvalid(rtpRecv, srtp_1bytehdrext_cc_cryptex);
        testRejectInvalid(rtpRecv, srtp_2bytehdrext_cc_cryptex);

        testRejectInvalid(rtpRecv, srtp_1byte_empty_hdrext_cc_cryptex);
        testRejectInvalid(rtpRecv, srtp_2byte_empty_hdrext_cc_cryptex);
    }

    /* GCM Ciphertext packet with 1-byte header extension */
    private static final byte[] srtp_1bytehdrext_cryptex_gcm =
        parseHexBinary("900f1235decafbad" +
            "cafebabe" +
            "c0de0001" +
            "39972dc9" +
            "572c4d99" +
            "e8fc355de743fb2e" +
            "94f9d8ff" +
            "54e72f4193bbc5c74ffab0fa9fa0fbeb"
        );

    /* GCM Ciphertext packet with 2-byte header extension */
    private static final byte[] srtp_2bytehdrext_cryptex_gcm =
        parseHexBinary("900f1236decafbad" +
            "cafebabe" +
            "c2de0001" +
            "bb75a4c5" +
            "45cd1f41" +
            "3bdb7daa2b1e3263" +
            "de313667" +
            "c963249081b35a65f5cb6c88b394235f");

    private static final byte[] srtp_unkhdrext_cryptex_gcm =
        parseHexBinary("900f1237decafbad" +
            "cafebabe" +
            "0bad0001" +
            "dededede" +
            "0b30fff4" +
            "66b596a57241d861" +
            "b7b1c681" +
            "e065d1bf3edb6b45e39b36d3c7765ebd");

    private static final byte[] srtp_1bytehdrext_cc_cryptex_gcm =
        parseHexBinary("920f1238decafbad"
            + "cafebabe"
            + "63bbccc4"
            + "a7f695c4"
            + "c0de0001"
            + "8ad7c71f"
            + "ac70a80c"
            + "92866b4c6ba98546"
            + "ef913586"
            + "e95ffaaffe956885bb0647a8bc094ac8");

    private static final byte[] srtp_2bytehdrext_cc_cryptex_gcm =
        parseHexBinary("920f1239decafbad"
            + "cafebabe"
            + "3680524f"
            + "8d312b00"
            + "c2de0001"
            + "c78d1200"
            + "38422bc1"
            + "11a7187a18246f98"
            + "0c059cc6"
            + "bc9df8b626394eca344e4b05d80fea83");

    private static final byte[] srtp_1byte_empty_hdrext_cc_cryptex_gcm =
        parseHexBinary("920f123adecafbad"
            + "cafebabe"
            + "15b6bb43"
            + "37906fff"
            + "c0de0000"
            + "b7b96453"
            + "7a2b03ab7ba5389c"
            + "e9331712"
            + "6b5d974df30c6884dcb651c5e120c1da");

    private static final byte[] srtp_2byte_empty_hdrext_cc_cryptex_gcm =
        parseHexBinary("920f123bdecafbad"
            + "cafebabe"
            + "dcb38c9e"
            + "48bf95f4"
            + "c2de0000"
            + "61ee432c"
            + "f920317076613258"
            + "d3ce4236"
            + "c06ac429681ad08413512dc98b5207d8");

    @Test
    public void testCryptexGcm() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128/8,
                SrtpPolicy.NULL_AUTHENTICATION, 0,
                128/8, 96/8 );
        policy.setCryptexEnabled(true);

        policy.setSendReplayEnabled(false);
        policy.setReceiveReplayEnabled(false);
        // So we can encrypt and decrypt packets multiple times, with different offsets.

        SrtpContextFactory senderFactory = new SrtpContextFactory(true, test_key_gcm, test_key_salt_gcm, policy, policy, logger);
        SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key_gcm, test_key_salt_gcm, policy, policy, logger);

        SrtpCryptoContext rtpSend = senderFactory.deriveContext(0xcafebabe, 0);
        SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

        testPacket(rtpSend, rtpRecv, rtp_plaintext_ref, srtp_ciphertext_gcm, policy.getAuthTagLength());

        testPacket(rtpSend, rtpRecv, rtp_1bytehdrext, srtp_1bytehdrext_cryptex_gcm, policy.getAuthTagLength());
        testPacket(rtpSend, rtpRecv, rtp_2bytehdrext, srtp_2bytehdrext_cryptex_gcm, policy.getAuthTagLength());
        testPacket(rtpSend, rtpRecv, rtp_unkhdrext, srtp_unkhdrext_cryptex_gcm, policy.getAuthTagLength());

        testPacket(rtpSend, rtpRecv, rtp_1bytehdrext_cc, srtp_1bytehdrext_cc_cryptex_gcm, policy.getAuthTagLength());
        testPacket(rtpSend, rtpRecv, rtp_2bytehdrext_cc, srtp_2bytehdrext_cc_cryptex_gcm, policy.getAuthTagLength());

        testPacket(rtpSend, rtpRecv, rtp_1byte_empty_hdrext_cc, srtp_1byte_empty_hdrext_cc_cryptex_gcm, policy.getAuthTagLength());
        testPacket(rtpSend, rtpRecv, rtp_2byte_empty_hdrext_cc, srtp_2byte_empty_hdrext_cc_cryptex_gcm, policy.getAuthTagLength());

        testPacketAsymmetric(rtpSend, rtpRecv, rtp_nohdr_cc, srtp_1byte_empty_hdrext_cc_cryptex_gcm, rtp_1byte_empty_hdrext_cc, policy.getAuthTagLength() + 4);
    }

    @Test
    public void rejectInvalidCryptexGcm() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128/8,
                SrtpPolicy.NULL_AUTHENTICATION, 0,
                128/8, 96/8 );
        policy.setCryptexEnabled(true);

        SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key_gcm, test_key_salt_gcm, policy, policy, logger);

        SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

        testRejectInvalid(rtpRecv, srtp_ciphertext_gcm);

        testRejectInvalid(rtpRecv, srtp_1bytehdrext_cryptex_gcm);
        testRejectInvalid(rtpRecv, srtp_2bytehdrext_cryptex_gcm);
        testRejectInvalid(rtpRecv, srtp_unkhdrext_cryptex_gcm);

        testRejectInvalid(rtpRecv, srtp_1bytehdrext_cc_cryptex_gcm);
        testRejectInvalid(rtpRecv, srtp_2bytehdrext_cc_cryptex_gcm);

        testRejectInvalid(rtpRecv, srtp_1byte_empty_hdrext_cc_cryptex_gcm);
        testRejectInvalid(rtpRecv, srtp_2byte_empty_hdrext_cc_cryptex_gcm);
    }
}
