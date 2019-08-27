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
import org.junit.jupiter.api.*;

import javax.xml.bind.*;
import java.util.*;


public class SrtpValidationTest {
    /* Test cases from libsrtp's srtp_driver.c. */
    private static final byte[] test_key =
            DatatypeConverter.parseHexBinary("e1f97a0d3e018be0d64fa32c06de4139");
    private static final byte[] test_key_salt =
            DatatypeConverter.parseHexBinary("0ec675ad498afeebb6960b3aabe6");

    private static final byte[] srtp_plaintext_ref =
            DatatypeConverter.parseHexBinary("800f1234decafbad" +
					     "cafebabeabababab" +
					     "abababababababab" +
					     "abababab");
    private static final byte[] srtp_plaintext =
            DatatypeConverter.parseHexBinary("800f1234decafbad" +
					     "cafebabeabababab" +
					     "abababababababab" +
					     "abababab00000000" +
					     "000000000000");
    private static final byte[] srtp_ciphertext =
            DatatypeConverter.parseHexBinary("800f1234decafbad" +
					     "cafebabe4e55dc4c" +
					     "e79978d88ca4d215" +
					     "949d2402b78d6acc" +
					     "99ea179b8dbb");
    private static final byte[] rtcp_plaintext_ref =
            DatatypeConverter.parseHexBinary("81c8000bcafebabe" +
					     "abababababababab" +
					     "abababababababab");
    private static final byte[] rtcp_plaintext =
            DatatypeConverter.parseHexBinary("81c8000bcafebabe" +
					     "abababababababab" +
					     "abababababababab" +
					     "0000000000000000" +
					     "000000000000");
    private static final byte[] srtcp_ciphertext =
            DatatypeConverter.parseHexBinary("81c8000bcafebabe" +
					     "7128035be487b9bd" +
					     "bef89041f977a5a8" +
					     "80000001993e08cd" +
					     "54d6c1230798");

    @Test
    public void srtpValidate()
    {
        SrtpPolicy policy =
                new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                        80/8, 112/8 );

        SrtpContextFactory senderFactory = new SrtpContextFactory(true, test_key, test_key_salt, policy, policy);
        SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy);

        SrtpCryptoContext rtpSend = senderFactory.getDefaultContext().deriveContext(0xcafebabe, 0, 0);
        rtpSend.deriveSrtpKeys(0);

        ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(srtp_plaintext, 0, srtp_plaintext_ref.length);

        assertTrue(rtpSend.transformPacket(rtpPkt));
        assertEquals(rtpPkt.getLength(), srtp_ciphertext.length);
        assertArrayEquals(rtpPkt.getBuffer(), srtp_ciphertext);

        SrtcpCryptoContext rtcpSend = senderFactory.getDefaultContextControl().deriveContext(0xcafebabe);
        rtcpSend.deriveSrtcpKeys();

        ByteArrayBuffer rtcpPkt = new ByteArrayBufferImpl(rtcp_plaintext, 0, rtcp_plaintext_ref.length);
        rtcpSend.transformPacket(rtcpPkt);

        /* The reference srtcp buffer, above, includes an RTCP index of 1.
         * Our implementation writes the srtcp index itself, counting from 0.
         * Thus, reset the packet and encrypt it a second time to get the expected output.
         */
        System.arraycopy(rtcp_plaintext_ref, 0, rtcpPkt.getBuffer(), 0, rtcp_plaintext_ref.length);
        rtcpPkt.setLength(rtcp_plaintext_ref.length);

        rtcpSend.transformPacket(rtcpPkt);

        assertEquals(rtcpPkt.getLength(), srtcp_ciphertext.length);
        assertArrayEquals(rtcpPkt.getBuffer(), srtcp_ciphertext);

        SrtpCryptoContext rtpRecv = receiverFactory.getDefaultContext().deriveContext(0xcafebabe, 0, 0);
        rtpRecv.deriveSrtpKeys(0);

        assertTrue(rtpRecv.reverseTransformPacket(rtpPkt, false));
        assertEquals(rtpPkt.getLength(), srtp_plaintext_ref.length);
        assertArrayEquals(Arrays.copyOf(rtpPkt.getBuffer(), rtpPkt.getLength()), srtp_plaintext_ref);

        SrtcpCryptoContext rtcpRecv = receiverFactory.getDefaultContextControl().deriveContext(0xcafebabe);
        rtcpRecv.deriveSrtcpKeys();

        assertTrue(rtcpRecv.reverseTransformPacket(rtcpPkt));
        assertEquals(rtcpPkt.getLength(), rtcp_plaintext_ref.length);
        assertArrayEquals(Arrays.copyOf(rtcpPkt.getBuffer(), rtcpPkt.getLength()), rtcp_plaintext_ref);

        rtpSend.close();
        rtpRecv.close();
        rtcpSend.close();
        rtcpRecv.close();
        senderFactory.close();
        receiverFactory.close();
    }

    @Test
    public void rejectInvalid()
    {
        for (int len = srtp_ciphertext.length; len > 0; len--)
        {
            SrtpPolicy policy =
                new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                        80/8, 112/8 );

            SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy);
            SrtpCryptoContext rtpRecv = receiverFactory.getDefaultContext().deriveContext(0xcafebabe, 0, 0);
            rtpRecv.deriveSrtpKeys(0);

            ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(Arrays.copyOf(srtp_ciphertext, len), 0, len);

            boolean accept = rtpRecv.reverseTransformPacket(rtpPkt, false);

            if (len == srtp_ciphertext.length)
            {
                assertTrue(accept, "Rejected valid SRTP packet");
            }
            else
            {
                assertFalse(accept, "Accepted truncated SRTP packet");
            }
        }

        for (int len = srtcp_ciphertext.length; len > 0; len--) {
            SrtpPolicy policy =
                    new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                            SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                            80/8, 112/8 );

            SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy);
            SrtcpCryptoContext rtcpRecv = receiverFactory.getDefaultContextControl().deriveContext(0xcafebabe);
            rtcpRecv.deriveSrtcpKeys();

            ByteArrayBuffer rtpPkt = new ByteArrayBufferImpl(Arrays.copyOf(srtcp_ciphertext, len), 0, len);

            boolean accept = rtcpRecv.reverseTransformPacket(rtpPkt);

            if (len == srtcp_ciphertext.length)
            {
                assertTrue(accept, "Rejected valid SRTCP packet");
            }
            else
            {
                assertFalse(accept, "Accepted truncated SRTCP packet");
            }
        }
    }

}
