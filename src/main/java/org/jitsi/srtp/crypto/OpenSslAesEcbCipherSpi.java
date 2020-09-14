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
package org.jitsi.srtp.crypto;

import java.security.*;
import java.security.spec.*;

/**
 * AES-ECB Cipher implementation using OpenSSL via JNI.
 */
public final class OpenSslAesEcbCipherSpi
    extends OpenSslAesCipherSpi
{
    private static native long EVP_aes_128_ecb();
    private static native long EVP_aes_192_ecb();
    private static native long EVP_aes_256_ecb();

    public OpenSslAesEcbCipherSpi()
    {
        super("ECB");
    }

    @Override
    protected void engineInit(int opmode, Key key,
        AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            throw new InvalidAlgorithmParameterException
                ("ECB mode cannot use IV");
        }

        iv = null;

        doEngineInit(opmode, key);
    }

    @Override
    protected long getOpenSSLCipher(Key key) throws InvalidKeyException
    {
        switch (key.getEncoded().length)
        {
        case 16:
            return EVP_aes_128_ecb();
        case 24:
            return EVP_aes_192_ecb();
        case 32:
            return EVP_aes_256_ecb();
        default:
            throw new InvalidKeyException("Invalid AES key length: "
                + key.getEncoded().length + " bytes");
        }
    }
}
