/*
 * Copyright @ 2026 - present 8x8, Inc.
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
package org.jitsi.srtp.crypto;

import org.junit.jupiter.api.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.*;

/**
 * Tests of the parameters that {@link OpenSslAesGcmCipherSpi} accepts.
 */
public class OpenSslAesGcmCipherSpiTest
{
    private static final SecretKey KEY = new SecretKeySpec(new byte[16], "AES");

    private static Cipher openSslGcm() throws Exception
    {
        assumeTrue(JitsiOpenSslProvider.isLoaded(), "the OpenSSL native library is not loaded");
        return Cipher.getInstance("AES/GCM/NoPadding", new JitsiOpenSslProvider());
    }

    @Test
    public void refusesAnEmptyIv() throws Exception
    {
        Cipher cipher = openSslGcm();

        assertThrows(InvalidAlgorithmParameterException.class,
            () -> cipher.init(Cipher.ENCRYPT_MODE, KEY, new GCMParameterSpec(128, new byte[0])));
        assertThrows(InvalidAlgorithmParameterException.class,
            () -> cipher.init(Cipher.DECRYPT_MODE, KEY, new GCMParameterSpec(128, new byte[0])));

        /* The cipher can still be used with an IV after that. */
        cipher.init(Cipher.ENCRYPT_MODE, KEY, new GCMParameterSpec(128, new byte[12]));
        assertEquals(16, cipher.doFinal(new byte[0]).length);
    }
}
