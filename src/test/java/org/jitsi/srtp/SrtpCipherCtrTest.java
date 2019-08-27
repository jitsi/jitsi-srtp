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

import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import javax.xml.bind.*;
import org.bouncycastle.crypto.engines.*;
import org.jitsi.srtp.crypto.*;
import org.junit.jupiter.api.*;

public class SrtpCipherCtrTest
{
    // RFC 3711 AES CTR Tests vectors
    private static final byte[] TV_Key =
        DatatypeConverter.parseHexBinary("2B7E151628AED2A6ABF7158809CF4F3C");

    private static final byte[] TV_IV_1 =
        DatatypeConverter.parseHexBinary("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000");

    private static final byte[] TV_Cipher_AES_1 =
        DatatypeConverter.parseHexBinary("E03EAD0935C95E80E166B16DD92B4EB4"
            + "D23513162B02D0F72A43A2FE4A5F97AB"
            + "41E95B3BB0A2E8DD477901E4FCA894C0");

    private static final byte[] TV_IV_2 =
        DatatypeConverter.parseHexBinary("F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");

    private static final byte[] TV_Cipher_AES_2 =
        DatatypeConverter.parseHexBinary("EC8CDF7398607CB0F2D21675EA9EA1E4"
            + "362B7C3C6773516318A077D7FC5073AE"
            + "6A2CC3787889374FBEB4C81B17BA6C44");

    @Test
    public void testJavaCtrAes()
    {
        SrtpCipherCtr cipher = new SrtpCipherCtrJava(new AESEngine());
        cipher.init(TV_Key);
        byte[] data = new byte[TV_Cipher_AES_1.length];

        Arrays.fill(data, (byte) 0);
        byte[] iv = Arrays.copyOf(TV_IV_1, TV_IV_1.length);
        cipher.process(data, 0, data.length, iv);
        assertArrayEquals(data, TV_Cipher_AES_1);

        Arrays.fill(data, (byte) 0);
        iv = Arrays.copyOf(TV_IV_2, TV_IV_2.length);
        cipher.process(data, 0, data.length, iv);
        assertArrayEquals(data, TV_Cipher_AES_2);
    }

    @Test
    public void testOpenSslCtrAes()
    {
        boolean haveOpenSsl = OpenSslWrapperLoader.isLoaded();

        if (System.getProperty("os.name").toLowerCase().contains("linux"))
        {
            assertTrue(haveOpenSsl, "should always have OpenSSL on Linux");
        }

        if (!haveOpenSsl)
        {
            return;
        }

        SrtpCipherCtr cipher = new SrtpCipherCtrOpenSsl();
        cipher.init(TV_Key);
        byte[] data = new byte[TV_Cipher_AES_1.length];

        Arrays.fill(data, (byte) 0);
        byte[] iv = Arrays.copyOf(TV_IV_1, TV_IV_1.length);
        cipher.process(data, 0, data.length, iv);
        assertArrayEquals(data, TV_Cipher_AES_1);

        Arrays.fill(data, (byte) 0);
        iv = Arrays.copyOf(TV_IV_2, TV_IV_2.length);
        cipher.process(data, 0, data.length, iv);
        assertArrayEquals(data, TV_Cipher_AES_2);
    }
}
