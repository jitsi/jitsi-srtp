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

import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Arrays;
import javax.crypto.*;
import org.bouncycastle.jce.provider.*;
import org.jitsi.srtp.crypto.*;
import org.junit.jupiter.api.*;

public class SrtpCipherF8Test
{
    // RFC 3711 AES F8 Tests vectors
    public static final byte[] TV_Key =
        parseHexBinary("234829008467be186c3de14aae72d62c");

    public static final byte[] TV_Salt =
        parseHexBinary("32f2870d");

    public static final byte[] TV_IV =
        parseHexBinary("006e5cba50681de55c621599d462564a");

    public static final byte[] TV_Plain =
        parseHexBinary(
            "70736575646f72616e646f6d6e65737320697320746865206e6578742062657374207468696e67");

    public static final byte[] TV_Cipher_AES =
        parseHexBinary(
            "019ce7a26e7854014a6366aa95d4eefd1ad4172a14f9faf455b7f1d4b62bd08f562c0eef7c4802");

    // Generated with our own implementation
    public static final byte[] TV_Cipher_TwoFish =
        parseHexBinary(
            "346d91e0d4c3908c476ba25f2792fbb65456f2d90736f40353da7865a8989f01947f6f09385fb5");

    /**
     * Validate our F8 mode implementation with tests vectors provided in
     * RFC3711
     */
    @Test
    public void testAESF8() throws Exception
    {
        SrtpCipherF8 cipher =
            new SrtpCipherF8(Aes.createCipher("AES/ECB/NoPadding"));
        cipher.init(TV_Key, TV_Salt);
        byte[] data = Arrays.copyOf(TV_Plain, TV_Plain.length);
        byte[] iv = Arrays.copyOf(TV_IV, TV_IV.length);
        cipher.setIV(iv, true);
        cipher.process(data, 0, data.length);

        assertArrayEquals(TV_Cipher_AES, data);
    }

    /**
     * Validate our F8 mode implementation work with TwoFish
     */
    @Test
    public void testTwoFish() throws Exception
    {
        SrtpCipherF8 cipher = new SrtpCipherF8(Cipher
            .getInstance("Twofish/ECB/NoPadding", new BouncyCastleProvider()));
        cipher.init(TV_Key, TV_Salt);
        byte[] data = Arrays.copyOf(TV_Plain, TV_Plain.length);
        byte[] iv = Arrays.copyOf(TV_IV, TV_IV.length);
        cipher.setIV(iv, true);
        cipher.process(data, 0, data.length);

        assertArrayEquals(TV_Cipher_TwoFish, data);
    }
}
