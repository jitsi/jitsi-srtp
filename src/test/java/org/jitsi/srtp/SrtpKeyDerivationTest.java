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

import org.junit.jupiter.api.*;

import javax.xml.bind.*;

public class SrtpKeyDerivationTest {

    /* Key derivation test vectors from RFC 3711. */
    private static final byte[] masterKey128 =
            DatatypeConverter.parseHexBinary("E1F97A0D3E018BE0D64FA32C06DE4139");
    private static final byte[] masterSalt128 =
            DatatypeConverter.parseHexBinary("0EC675AD498AFEEBB6960B3AABE6");

    private static final byte[] cipherKey128 =
            DatatypeConverter.parseHexBinary("C61E7A93744F39EE10734AFE3FF7A087");
    private static final byte[] cipherSalt128 =
            DatatypeConverter.parseHexBinary("30CBBC08863D8C85D49DB34A9AE1");
    private static final byte[] authKey128 =
            DatatypeConverter.parseHexBinary("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4");

    @Test
    public void srtpKdf128Test()
    {
        SrtpPolicy policy =
                new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                        80/8, 112/8 );
        SrtpKdf kdf = new SrtpKdf(masterKey128, masterSalt128, policy);

        byte[] encKey = new byte[policy.getEncKeyLength()];
        kdf.deriveSessionKey(encKey, SrtpKdf.LABEL_RTP_ENCRYPTION);
        assertArrayEquals(encKey, cipherKey128);

        byte[] authKey = new byte[policy.getAuthKeyLength()];
        kdf.deriveSessionKey(authKey, SrtpKdf.LABEL_RTP_MSG_AUTH);
        assertArrayEquals(authKey, authKey128);

        byte[] saltKey = new byte[policy.getSaltKeyLength()];
        kdf.deriveSessionKey(saltKey, SrtpKdf.LABEL_RTP_SALT);
        assertArrayEquals(saltKey, cipherSalt128);

        kdf.close();
    }

    /* Key derivation test vectors from RFC 6188. */
    private static final byte[] masterKey256 =
            DatatypeConverter.parseHexBinary("f0f04914b513f2763a1b1fa130f10e29" +
                    "98f6f6e43e4309d1e622a0e332b9f1b6");
    private static final byte[] masterSalt256 =
            DatatypeConverter.parseHexBinary("3b04803de51ee7c96423ab5b78d2");

    private static final byte[] cipherKey256 =
            DatatypeConverter.parseHexBinary("5ba1064e30ec51613cad926c5a28ef73" +
                    "1ec7fb397f70a960653caf06554cd8c4");
    private static final byte[] cipherSalt256 =
            DatatypeConverter.parseHexBinary("fa31791685ca444a9e07c6c64e93");
    private static final byte[] authKey256 =
            DatatypeConverter.parseHexBinary("fd9c32d39ed5fbb5a9dc96b30818454d1313dc05");

    @Test
    public void srtpKdf256Test()
    {
        SrtpPolicy policy =
                new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 256/8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                        80/8, 112/8 );
        SrtpKdf kdf = new SrtpKdf(masterKey256, masterSalt256, policy);

        byte[] encKey = new byte[policy.getEncKeyLength()];
        kdf.deriveSessionKey(encKey, SrtpKdf.LABEL_RTP_ENCRYPTION);
        assertArrayEquals(encKey, cipherKey256);

        byte[] authKey = new byte[policy.getAuthKeyLength()];
        kdf.deriveSessionKey(authKey, SrtpKdf.LABEL_RTP_MSG_AUTH);
        assertArrayEquals(authKey, authKey256);

        byte[] saltKey = new byte[policy.getSaltKeyLength()];
        kdf.deriveSessionKey(saltKey, SrtpKdf.LABEL_RTP_SALT);
        assertArrayEquals(saltKey, cipherSalt256);

        kdf.close();
    }
}
