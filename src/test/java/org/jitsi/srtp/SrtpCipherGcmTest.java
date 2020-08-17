/*
 * Copyright @ 2016 - present 8x8, Inc
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

import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.modes.*;
import org.jitsi.srtp.crypto.*;
import org.junit.jupiter.api.*;

import java.util.*;

import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static org.junit.jupiter.api.Assertions.*;

public class SrtpCipherGcmTest
{
    // RFC 7714 AES GCM Test vectors
    private static final byte[] TV_Packet =
        parseHexBinary("8040f17b8041f8d35501a0b247616c6c"
            + "696120657374206f6d6e697320646976"
            + "69736120696e20706172746573207472"
            + "6573");

    private static final int TV_AEAD_length = 12;

    private static final byte[] TV_IV =
        parseHexBinary("51753c6580c2726f20718414");

    private static final byte[] fake_IV =
        new byte[TV_IV.length];

    private static final byte[] TV_Key_128 =
        parseHexBinary("000102030405060708090a0b0c0d0e0f");

    private static final byte[] TV_Cipher_AES_GCM_128 =
        parseHexBinary("8040f17b8041f8d35501a0b2f24de3a3"
            + "fb34de6cacba861c9d7e4bcabe633bd5"
            + "0d294e6f42a5f47a51c7d19b36de3adf"
            + "8833899d7f27beb16a9152cf765ee439"
            + "0cce");

    private static final byte[] TV_Key_256 =
        parseHexBinary("000102030405060708090a0b0c0d0e0f"
            + "101112131415161718191a1b1c1d1e1f");

    private static final byte[] TV_Cipher_AES_GCM_256 =
        parseHexBinary("8040f17b8041f8d35501a0b232b1de78"
            + "a822fe12ef9f78fa332e33aab1801238"
            + "9a58e2f3b50b2a0276ffae0f1ba63799"
            + "b87b7aa3db36dfffd6b0f9bb7878d7a7"
            + "6c13");

    private void encryptBuffer(SrtpCipherGcm cipher, byte[] data)
        throws SrtpCipherGcm.BadAuthTag
    {
        /* Hack to allow us to re-use the same IV for the same cipher. */
        cipher.reset(true, fake_IV);

        cipher.reset(true, TV_IV);
        cipher.processAad(data, 0, TV_AEAD_length);
        int lenDelta = cipher.process(data, TV_AEAD_length, TV_Packet.length - TV_AEAD_length);
        assertEquals(16, lenDelta);
    }

    private void decryptBuffer(SrtpCipherGcm cipher, byte[] data)
        throws SrtpCipherGcm.BadAuthTag
    {
        /* Hack to allow us to re-use the same IV for the same cipher. */
        /* Never do this for real data */
        cipher.reset(false, fake_IV);

        cipher.reset(false, TV_IV);
        cipher.processAad(data, 0, TV_AEAD_length);
        int lenDelta = cipher.process(data, TV_AEAD_length, TV_Cipher_AES_GCM_128.length - TV_AEAD_length);
        assertEquals(-16, lenDelta);
    }

    private void testGcmCipherKey(SrtpCipherGcm cipher, final byte[] key, final byte[] expectedCiphertext)
        throws SrtpCipherGcm.BadAuthTag
    {
        byte[] data = Arrays.copyOf(TV_Packet, expectedCiphertext.length);

        cipher.init(key, 128);
        encryptBuffer(cipher, data);

        assertArrayEquals(expectedCiphertext, data);

        byte[] data2 = Arrays.copyOf(expectedCiphertext, expectedCiphertext.length);
        decryptBuffer(cipher, data2);

        assertArrayEquals(TV_Packet, Arrays.copyOf(data2, TV_Packet.length));

        for (int i = 0; i < TV_Packet.length; i++) {
            for (int j = 0; j < 8; j++) {
                byte[] mungedData = Arrays.copyOf(expectedCiphertext, expectedCiphertext.length);
                mungedData[i] ^= (1 << j);

                assertThrows(SrtpCipherGcm.BadAuthTag.class, () -> decryptBuffer(cipher, mungedData));
            }
        }
    }

    private void testGcmCipher(SrtpCipherGcm cipher)
        throws SrtpCipherGcm.BadAuthTag
    {
        testGcmCipherKey(cipher, TV_Key_128, TV_Cipher_AES_GCM_128);
        testGcmCipherKey(cipher, TV_Key_256, TV_Cipher_AES_GCM_256);
    }

    @Test
    public void testSrtpCipherGcmBC()
        throws SrtpCipherGcm.BadAuthTag
    {
        SrtpCipherGcm cipher = new SrtpCipherGcmBC(new GCMBlockCipher(new AESEngine()));

        testGcmCipher(cipher);
    }

    /* TODO add tests for other implementations as they're written */
}
