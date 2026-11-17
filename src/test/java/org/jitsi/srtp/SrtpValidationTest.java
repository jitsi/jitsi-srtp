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
import java.security.*;
import java.util.*;
import javax.crypto.*;
import org.jitsi.srtp.crypto.*;


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

    /**
     * Checks that a packet is protected correctly with every amount of room after the data, from none to
     * {@code maxRoom}; the buffer is grown when needed. An SRTP packet gets the authentication tag appended, an SRTCP
     * packet the index and the authentication tag.
     *
     * @param maxRoom the most room to leave after the data, the number of bytes appended to an SRTCP packet.
     */
    private void checkBufferIsGrown(SrtpPolicy policy, byte[] key, byte[] salt, byte[] srtpReference,
        byte[] srtcpReference, int maxRoom) throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        for (int offset : new int[] { 0, 7 })
        {
            for (int room = 0; room <= maxRoom; room++)
            {
                String description = "offset " + offset + ", room for " + room + " bytes";
                SrtpContextFactory senderFactory = new SrtpContextFactory(true, key, salt, policy, policy, logger);

                SrtpCryptoContext rtpSend = senderFactory.deriveContext(0xcafebabe, 0);
                ByteArrayBuffer rtpPkt = packetInBuffer(rtp_plaintext_ref, offset, room);

                assertEquals(SrtpErrorStatus.OK, rtpSend.transformPacket(rtpPkt), description);
                assertPacketEquals(srtpReference, rtpPkt, description);

                SrtcpCryptoContext rtcpSend = senderFactory.deriveControlContext(0xcafebabe);
                /* The reference SRTCP packet has an index of 1, and the first packet protected gets an index of 0. */
                rtcpSend.transformPacket(packetInBuffer(rtcp_plaintext_ref, 0, maxRoom));
                ByteArrayBuffer rtcpPkt = packetInBuffer(rtcp_plaintext_ref, offset, room);

                assertEquals(SrtpErrorStatus.OK, rtcpSend.transformPacket(rtcpPkt), description);
                assertPacketEquals(srtcpReference, rtcpPkt, description);

                senderFactory.close();
            }
        }
    }

    /**
     * Returns a packet with the contents {@code data}, in a buffer with {@code offset} bytes before the data and
     * {@code room} bytes after it.
     */
    private static ByteArrayBuffer packetInBuffer(byte[] data, int offset, int room)
    {
        byte[] buffer = new byte[offset + data.length + room];
        System.arraycopy(data, 0, buffer, offset, data.length);
        return new ByteArrayBufferImpl(buffer, offset, data.length);
    }

    private static void assertPacketEquals(byte[] expected, ByteArrayBuffer pkt, String description)
    {
        assertTrue(pkt.getOffset() + pkt.getLength() <= pkt.getBuffer().length, description);
        assertByteArrayBufferEquals(expected, pkt);
    }

    /**
     * A packet whose buffer does not grow, so that protecting it with AES-GCM fails when it has no room for the tag.
     */
    private static class FixedBuffer extends ByteArrayBufferImpl
    {
        FixedBuffer(byte[] data)
        {
            super(data.clone(), 0, data.length);
        }

        @Override
        public void grow(int howMuch)
        {
        }
    }

    /**
     * A packet which cannot be protected is reported, and the context protects the packets after it.
     */
    @Test
    public void srtpGcmReportsFailure() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128/8,
                SrtpPolicy.NULL_AUTHENTICATION, 0,
                128/8, 96/8 );

        SrtpContextFactory senderFactory =
            new SrtpContextFactory(true, test_key_gcm, test_key_salt_gcm, policy, policy, logger);

        SrtpCryptoContext rtpSend = senderFactory.deriveContext(0xcafebabe, 0);

        /* The packet before the reference packet: a cipher may refuse the IV of a packet which failed. */
        byte[] previous = rtp_plaintext_ref.clone();
        previous[3]--;
        assertEquals(SrtpErrorStatus.FAIL, rtpSend.transformPacket(new FixedBuffer(previous)));

        ByteArrayBuffer rtpPkt = packetInBuffer(rtp_plaintext_ref, 0, 0);
        assertEquals(SrtpErrorStatus.OK, rtpSend.transformPacket(rtpPkt));
        assertPacketEquals(srtp_ciphertext_gcm, rtpPkt, "after a failure");

        SrtcpCryptoContext rtcpSend = senderFactory.deriveControlContext(0xcafebabe);

        assertEquals(SrtpErrorStatus.FAIL, rtcpSend.transformPacket(new FixedBuffer(rtcp_plaintext_ref)));

        /* The reference SRTCP packet has an index of 1. The packet which failed used up the index 0. */
        ByteArrayBuffer rtcpPkt = packetInBuffer(rtcp_plaintext_ref, 0, 0);
        assertEquals(SrtpErrorStatus.OK, rtcpSend.transformPacket(rtcpPkt));
        assertPacketEquals(srtcp_ciphertext_gcm, rtcpPkt, "after a failure");

        senderFactory.close();
    }

    @Test
    public void srtpCtrHmacGrowsBuffer() throws Exception
    {
        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                80/8, 112/8 );

        checkBufferIsGrown(policy, test_key, test_key_salt, srtp_ciphertext, srtcp_ciphertext, 4 + 80/8);
    }

    @Test
    public void srtpGcmGrowsBuffer() throws Exception
    {
        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128/8,
                SrtpPolicy.NULL_AUTHENTICATION, 0,
                128/8, 96/8 );

        checkBufferIsGrown(policy, test_key_gcm, test_key_salt_gcm, srtp_ciphertext_gcm, srtcp_ciphertext_gcm,
            4 + 128/8);
    }

    private static final SrtpPolicy F8_POLICY =
        new SrtpPolicy(SrtpPolicy.AESF8_ENCRYPTION, 128/8,
            SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
            80/8, 112/8 );

    /**
     * Protects the reference RTP packet with F8, and checks that all of the payload is encrypted and that a receiver
     * gets the packet back.
     */
    @Test
    public void srtpF8RoundTrip() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpContextFactory senderFactory =
            new SrtpContextFactory(true, test_key, test_key_salt, F8_POLICY, F8_POLICY, logger);
        SrtpContextFactory receiverFactory =
            new SrtpContextFactory(false, test_key, test_key_salt, F8_POLICY, F8_POLICY, logger);

        for (int offset : new int[] { 0, 7 })
        {
            ByteArrayBuffer rtpPkt = packetInBuffer(rtp_plaintext_ref, offset, 0);

            assertEquals(SrtpErrorStatus.OK, senderFactory.deriveContext(0xcafebabe, 0).transformPacket(rtpPkt));
            assertEquals(rtp_plaintext_ref.length + 80/8, rtpPkt.getLength());
            /* The RTP header is 12 bytes, and everything after it is encrypted. */
            assertEncrypted(rtp_plaintext_ref, rtpPkt, 12, rtp_plaintext_ref.length);

            assertEquals(SrtpErrorStatus.OK,
                receiverFactory.deriveContext(0xcafebabe, 0).reverseTransformPacket(rtpPkt, false));
            assertByteArrayBufferEquals(rtp_plaintext_ref, rtpPkt);
        }

        senderFactory.close();
        receiverFactory.close();
    }

    /**
     * Checks that {@code pkt} starts with the first {@code from} bytes of {@code plaintext}, and that no run of 4
     * bytes from {@code from} to {@code to} is the same as in {@code plaintext}.
     */
    private static void assertEncrypted(byte[] plaintext, ByteArrayBuffer pkt, int from, int to)
    {
        byte[] data = Arrays.copyOfRange(pkt.getBuffer(), pkt.getOffset(), pkt.getOffset() + pkt.getLength());

        assertArrayEquals(Arrays.copyOf(plaintext, from), Arrays.copyOf(data, from));
        for (int i = from; i + 4 <= to; i++)
        {
            assertFalse(
                Arrays.equals(Arrays.copyOfRange(plaintext, i, i + 4), Arrays.copyOfRange(data, i, i + 4)),
                "bytes " + i + " to " + (i + 3) + " are not encrypted");
        }
    }

    /**
     * Protects the reference RTCP packet with F8, and checks that all of it after the first 8 bytes is encrypted and
     * that a receiver gets the packet back.
     */
    @Test
    public void srtcpF8RoundTrip() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpContextFactory senderFactory =
            new SrtpContextFactory(true, test_key, test_key_salt, F8_POLICY, F8_POLICY, logger);
        SrtpContextFactory receiverFactory =
            new SrtpContextFactory(false, test_key, test_key_salt, F8_POLICY, F8_POLICY, logger);

        for (int offset : new int[] { 0, 7 })
        {
            ByteArrayBuffer rtcpPkt = packetInBuffer(rtcp_plaintext_ref, offset, 0);

            assertEquals(SrtpErrorStatus.OK, senderFactory.deriveControlContext(0xcafebabe).transformPacket(rtcpPkt));
            assertEquals(rtcp_plaintext_ref.length + 4 + 80/8, rtcpPkt.getLength());
            assertEncrypted(rtcp_plaintext_ref, rtcpPkt, 8, rtcp_plaintext_ref.length);

            assertEquals(SrtpErrorStatus.OK,
                receiverFactory.deriveControlContext(0xcafebabe).reverseTransformPacket(rtcpPkt));
            assertByteArrayBufferEquals(rtcp_plaintext_ref, rtcpPkt);
        }

        senderFactory.close();
        receiverFactory.close();
    }

    /**
     * Encrypts {@code packet} from {@code encryptFrom} with AES-F8, with the session keys for {@code encLabel} and
     * {@code saltLabel} and the IV {@code iv}. This does not use the crypto contexts: the keys come from the key
     * derivation function and the encryption from the cipher, which have their own tests against the vectors of
     * RFC 3711, and the caller builds the IV as RFC 3711 describes it.
     */
    private static byte[] f8Reference(byte[] packet, int encryptFrom, byte[] iv, byte encLabel, byte saltLabel)
        throws Exception
    {
        SrtpKdf kdf = new SrtpKdf(test_key, test_key_salt, F8_POLICY);
        byte[] encKey = new byte[F8_POLICY.getEncKeyLength()];
        byte[] saltKey = new byte[F8_POLICY.getSaltKeyLength()];
        kdf.deriveSessionKey(encKey, encLabel);
        kdf.deriveSessionKey(saltKey, saltLabel);

        SrtpCipherF8 cipher = new SrtpCipherF8(Aes.createCipher("AES/ECB/NoPadding"));
        cipher.init(encKey, saltKey);
        cipher.setIV(iv, Cipher.ENCRYPT_MODE);

        byte[] data = packet.clone();
        cipher.process(data, encryptFrom, data.length - encryptFrom);
        return data;
    }

    /**
     * The F8 round trip tests use this library on both sides. These check the packets on the wire against RFC 3711:
     * which bytes are encrypted, and the layout of the IV.
     */
    @Test
    public void srtpF8WireFormat() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        /* RFC 3711, section 4.1.2.2: IV = 0x00 || M || PT || SEQ || TS || SSRC || ROC. */
        byte[] iv = new byte[16];
        System.arraycopy(rtp_plaintext_ref, 1, iv, 1, 11);
        /* The ROC is 0, in bytes 12 to 15. */

        byte[] expected =
            f8Reference(rtp_plaintext_ref, 12, iv, SrtpKdf.LABEL_RTP_ENCRYPTION, SrtpKdf.LABEL_RTP_SALT);

        SrtpContextFactory senderFactory =
            new SrtpContextFactory(true, test_key, test_key_salt, F8_POLICY, F8_POLICY, logger);
        ByteArrayBuffer rtpPkt = packetInBuffer(rtp_plaintext_ref, 0, 0);

        assertEquals(SrtpErrorStatus.OK, senderFactory.deriveContext(0xcafebabe, 0).transformPacket(rtpPkt));
        /* The authentication tag follows the encrypted packet. */
        assertArrayEquals(expected, Arrays.copyOf(rtpPkt.getBuffer(), expected.length));

        senderFactory.close();
    }

    @Test
    public void srtcpF8WireFormat() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        /* RFC 3711, section 4.1.2.3: IV = 0..0 || E || SRTCP index || V || P || RC || PT || length || SSRC.
         * The first packet of a context has the index 0, and E is the highest bit of the index word. */
        byte[] iv = new byte[16];
        iv[4] = (byte) 0x80;
        System.arraycopy(rtcp_plaintext_ref, 0, iv, 8, 8);

        byte[] expected =
            f8Reference(rtcp_plaintext_ref, 8, iv, SrtpKdf.LABEL_RTCP_ENCRYPTION, SrtpKdf.LABEL_RTCP_SALT);

        SrtpContextFactory senderFactory =
            new SrtpContextFactory(true, test_key, test_key_salt, F8_POLICY, F8_POLICY, logger);
        ByteArrayBuffer rtcpPkt = packetInBuffer(rtcp_plaintext_ref, 0, 0);

        assertEquals(SrtpErrorStatus.OK, senderFactory.deriveControlContext(0xcafebabe).transformPacket(rtcpPkt));
        assertArrayEquals(expected, Arrays.copyOf(rtcpPkt.getBuffer(), expected.length));
        /* The E flag and the index follow the encrypted packet, and the authentication tag follows them. */
        assertArrayEquals(new byte[] { (byte) 0x80, 0, 0, 0 },
            Arrays.copyOfRange(rtcpPkt.getBuffer(), expected.length, expected.length + 4));

        senderFactory.close();
    }

    /**
     * A receiver accepts an SRTCP packet which is authenticated with AES-GCM and not encrypted, wherever the packet
     * is in its buffer.
     */
    @Test
    public void srtcpGcmWithoutEncryption() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128/8,
                SrtpPolicy.NULL_AUTHENTICATION, 0,
                128/8, 96/8 );

        SrtpContextFactory senderFactory =
            new SrtpContextFactory(true, test_key_gcm, test_key_salt_gcm, policy, policy, logger);
        SrtpContextFactory receiverFactory =
            new SrtpContextFactory(false, test_key_gcm, test_key_salt_gcm, policy, policy, logger);

        for (int offset : new int[] { 0, 7 })
        {
            ByteArrayBuffer rtcpPkt = packetInBuffer(rtcp_plaintext_ref, offset, 16 + 4);

            /* transformPacket always encrypts. Call processPacketAesGcm directly to authenticate without encrypting. */
            SrtcpCryptoContext rtcpSend = senderFactory.deriveControlContext(0xcafebabe);
            assertEquals(SrtpErrorStatus.OK, rtcpSend.processPacketAesGcm(rtcpPkt, 0, true, true));
            /* The index 0, with the flag which says that the packet is encrypted not set. */
            rtcpPkt.append(new byte[4], 4);

            assertEquals(rtcp_plaintext_ref.length + 16 + 4, rtcpPkt.getLength());
            assertArrayEquals(rtcp_plaintext_ref,
                Arrays.copyOfRange(rtcpPkt.getBuffer(), offset, offset + rtcp_plaintext_ref.length));

            /* A changed packet is refused. */
            ByteArrayBuffer changed = new ByteArrayBufferImpl(rtcpPkt.getBuffer().clone(), offset, rtcpPkt.getLength());
            changed.getBuffer()[offset + 9] ^= 1;
            assertEquals(SrtpErrorStatus.AUTH_FAIL,
                receiverFactory.deriveControlContext(0xcafebabe).reverseTransformPacket(changed));

            assertEquals(SrtpErrorStatus.OK,
                receiverFactory.deriveControlContext(0xcafebabe).reverseTransformPacket(rtcpPkt));
            assertByteArrayBufferEquals(rtcp_plaintext_ref, rtcpPkt);
        }

        senderFactory.close();
        receiverFactory.close();
    }

    @Test
    public void unknownTypesAreRefused() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy unknownEncryption =
            new SrtpPolicy(99, 128/8, SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8, 80/8, 112/8);
        SrtpContextFactory factory =
            new SrtpContextFactory(true, test_key, test_key_salt, unknownEncryption, unknownEncryption, logger);
        assertThrows(IllegalArgumentException.class, () -> factory.deriveContext(0xcafebabe, 0));
        assertThrows(IllegalArgumentException.class, () -> factory.deriveControlContext(0xcafebabe));
        factory.close();

        SrtpPolicy unknownAuthentication =
            new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8, 99, 160/8, 80/8, 112/8);
        SrtpContextFactory factory2 = new SrtpContextFactory(
            true, test_key, test_key_salt, unknownAuthentication, unknownAuthentication, logger);
        assertThrows(IllegalArgumentException.class, () -> factory2.deriveContext(0xcafebabe, 0));
        assertThrows(IllegalArgumentException.class, () -> factory2.deriveControlContext(0xcafebabe));
        factory2.close();
    }

    /**
     * The keys of a context are derived with the cipher of its encryption type. Without one, an authentication key
     * cannot be derived.
     */
    @Test
    public void authenticationWithoutEncryptionIsRefused() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.NULL_ENCRYPTION, 0, SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8, 80/8, 0);
        SrtpContextFactory factory = new SrtpContextFactory(true, null, null, policy, policy, logger);
        assertThrows(GeneralSecurityException.class, () -> factory.deriveContext(0xcafebabe, 0));
        assertThrows(GeneralSecurityException.class, () -> factory.deriveControlContext(0xcafebabe));
        factory.close();
    }

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
    private static void testPacketOnce(SrtpContextFactory senderFactory, SrtpContextFactory receiverFactory,
        byte[] plaintext, byte[] ciphertext,
        int authTagLen, int offset)
        throws Exception
    {
        SrtpCryptoContext rtpSend = senderFactory.deriveContext(0xcafebabe, 0);
        SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

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
    private static void testPacket(SrtpContextFactory senderFactory, SrtpContextFactory receiverFactory,
        byte[] plaintext, byte[] ciphertext,
        int authTagLen)
        throws Exception
    {
        for (int offset = 0; offset < 16; offset++) {
            testPacketOnce(senderFactory, receiverFactory, plaintext, ciphertext, authTagLen, offset);
        }
    }

    /* Test a single packet, when the reconstructed plaintext is not identical to the original encrypted plaintext. */
    private static void testPacketAsymmetricOnce(SrtpContextFactory senderFactory, SrtpContextFactory receiverFactory,
        byte[] plaintextOrig, byte[] ciphertext, byte[] plainTextDecrypted,
        int extraBufSpace, int offset)
        throws Exception
    {
        SrtpCryptoContext rtpSend = senderFactory.deriveContext(0xcafebabe, 0);
        SrtpCryptoContext rtpRecv = receiverFactory.deriveContext(0xcafebabe, 0);

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

    private static void testPacketAsymmetric(SrtpContextFactory senderFactory, SrtpContextFactory receiverFactory,
        byte[] plaintextOrig, byte[] ciphertext, byte[] plainTextDecrypted,
        int authTagLen)
        throws Exception
    {
        // When grow is needed
        for (int offset = 0; offset < 16; offset++) {
            testPacketAsymmetricOnce(senderFactory, receiverFactory, plaintextOrig, ciphertext, plainTextDecrypted, authTagLen, offset);
        }
        // When grow is not needed
        for (int offset = 0; offset < 16; offset++) {
            testPacketAsymmetricOnce(senderFactory, receiverFactory, plaintextOrig, ciphertext, plainTextDecrypted, authTagLen, offset + 4);
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

        SrtpContextFactory senderFactory = new SrtpContextFactory(true, test_key, test_key_salt, policy, policy, logger);
        SrtpContextFactory receiverFactory = new SrtpContextFactory(false, test_key, test_key_salt, policy, policy, logger);

        testPacket(senderFactory, receiverFactory, rtp_plaintext_ref, srtp_ciphertext, policy.getAuthTagLength());

        testPacket(senderFactory, receiverFactory, rtp_1bytehdrext, srtp_1bytehdrext_cryptex, policy.getAuthTagLength());
        testPacket(senderFactory, receiverFactory, rtp_2bytehdrext, srtp_2bytehdrext_cryptex, policy.getAuthTagLength());
        testPacket(senderFactory, receiverFactory, rtp_unkhdrext, srtp_unkhdrext_cryptex, policy.getAuthTagLength());

        testPacket(senderFactory, receiverFactory, rtp_1bytehdrext_cc, srtp_1bytehdrext_cc_cryptex, policy.getAuthTagLength());
        testPacket(senderFactory, receiverFactory, rtp_2bytehdrext_cc, srtp_2bytehdrext_cc_cryptex, policy.getAuthTagLength());

        testPacket(senderFactory, receiverFactory, rtp_1byte_empty_hdrext_cc, srtp_1byte_empty_hdrext_cc_cryptex, policy.getAuthTagLength());
        testPacket(senderFactory, receiverFactory, rtp_2byte_empty_hdrext_cc, srtp_2byte_empty_hdrext_cc_cryptex, policy.getAuthTagLength());

        testPacketAsymmetric(senderFactory, receiverFactory, rtp_nohdr_cc, srtp_1byte_empty_hdrext_cc_cryptex, rtp_1byte_empty_hdrext_cc,
            policy.getAuthTagLength() + 4);
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

        testPacket(senderFactory, receiverFactory, rtp_plaintext_ref, srtp_ciphertext_gcm, policy.getAuthTagLength());

        testPacket(senderFactory, receiverFactory, rtp_1bytehdrext, srtp_1bytehdrext_cryptex_gcm, policy.getAuthTagLength());
        testPacket(senderFactory, receiverFactory, rtp_2bytehdrext, srtp_2bytehdrext_cryptex_gcm, policy.getAuthTagLength());
        testPacket(senderFactory, receiverFactory, rtp_unkhdrext, srtp_unkhdrext_cryptex_gcm, policy.getAuthTagLength());

        testPacket(senderFactory, receiverFactory, rtp_1bytehdrext_cc, srtp_1bytehdrext_cc_cryptex_gcm, policy.getAuthTagLength());
        testPacket(senderFactory, receiverFactory, rtp_2bytehdrext_cc, srtp_2bytehdrext_cc_cryptex_gcm, policy.getAuthTagLength());

        testPacket(senderFactory, receiverFactory, rtp_1byte_empty_hdrext_cc, srtp_1byte_empty_hdrext_cc_cryptex_gcm, policy.getAuthTagLength());
        testPacket(senderFactory, receiverFactory, rtp_2byte_empty_hdrext_cc, srtp_2byte_empty_hdrext_cc_cryptex_gcm, policy.getAuthTagLength());

        testPacketAsymmetric(senderFactory, receiverFactory, rtp_nohdr_cc, srtp_1byte_empty_hdrext_cc_cryptex_gcm, rtp_1byte_empty_hdrext_cc,
            policy.getAuthTagLength() + 4);
    }

    /**
     * With cryptex, a packet that has CSRCs and no header extension gets an empty header extension, which is four
     * more bytes. The buffer is grown for those bytes and for the authentication tag, whatever room it has.
     */
    @Test
    public void cryptexGcmGrowsBufferForInsertedHeader() throws Exception
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128/8,
                SrtpPolicy.NULL_AUTHENTICATION, 0,
                128/8, 96/8 );
        policy.setCryptexEnabled(true);

        /* Below an offset of 4 the payload is moved forward, from 4 the header is moved back. */
        for (int offset : new int[] { 0, 3, 4, 7 })
        {
            for (int room = 0; room <= 4 + policy.getAuthTagLength(); room++)
            {
                String description = "offset " + offset + ", room for " + room + " bytes";
                SrtpContextFactory senderFactory =
                    new SrtpContextFactory(true, test_key_gcm, test_key_salt_gcm, policy, policy, logger);
                SrtpCryptoContext rtpSend = senderFactory.deriveContext(0xcafebabe, 0);
                ByteArrayBuffer pkt = packetInBuffer(rtp_nohdr_cc, offset, room);

                assertEquals(SrtpErrorStatus.OK, rtpSend.transformPacket(pkt), description);
                assertPacketEquals(srtp_1byte_empty_hdrext_cc_cryptex_gcm, pkt, description);

                senderFactory.close();
            }
        }
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
