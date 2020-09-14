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

import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;

public final class OpenSslAesCtrCipherSpi
    extends OpenSslAesCipherSpi
{
    public OpenSslAesCtrCipherSpi()
    {
        super("CTR");
    }

    @Override
    protected void engineInit(int opmode, Key key,
        AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            if (params instanceof IvParameterSpec)
            {
                iv = ((IvParameterSpec) params).getIV();
                if (iv.length != BLKLEN)
                {
                    throw new InvalidAlgorithmParameterException
                        ("Unsupported IV length: must be " + BLKLEN + " bytes");
                }
            }
            else
            {
                throw new InvalidAlgorithmParameterException
                    ("Unsupported parameter: " + params);
            }
        }
        else
        {
            /* According to the SPI spec we should use random to generate the
             * IV in this case if we're encrypting, but we never want to do this for SRTP.
             */
            throw new InvalidAlgorithmParameterException
                ("IV parameter missing");
        }

        doEngineInit(opmode, key);
    }

    @Override
    protected long getOpenSSLCipher(Key key) throws InvalidKeyException
    {
        switch (key.getEncoded().length)
        {
        case 16:
            return EVP_aes_128_ctr();
        case 24:
            return EVP_aes_192_ctr();
        case 32:
            return EVP_aes_256_ctr();
        default:
            throw new InvalidKeyException("Invalid AES key length: "
                + key.getEncoded().length + " bytes");
        }
    }
}
