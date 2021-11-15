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
}
