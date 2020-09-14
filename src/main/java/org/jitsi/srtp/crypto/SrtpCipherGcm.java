/*
 * Copyright @ 2015 - present 8x8, Inc
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

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

/**
 * SRTP encryption in GCM mode.
 */
public class SrtpCipherGcm
    extends SrtpCipher
{
    private static final byte[] zeroIv = new byte[12];
    private final GCMParameterSpec param;

    private SecretKeySpec key = null;

    public SrtpCipherGcm(Cipher cipher, int authTagBits)
    {
        super(cipher);
        param = new GCMParameterSpec(authTagBits, zeroIv);
    }

    @Override
    public void init(byte[] key, byte[] saltKey)
        throws GeneralSecurityException
    {
        if (key.length != 16 && key.length != 24 && key.length != 32)
        {
            throw new IllegalArgumentException("Invalid key length");
        }

        this.key = getSecretKey(key);
        cipher.init(Cipher.ENCRYPT_MODE, this.key, param);
    }

    @Override
    public void setIV(byte[] iv, int opmode) throws GeneralSecurityException
    {
        cipher.init(opmode, key, new GCMParameterSpec(param.getTLen(), iv));
    }

    @Override
    public void processAAD(byte[] data, int off, int len)
        throws GeneralSecurityException
    {
        cipher.updateAAD(data, off, len);
    }

    @Override
    public int process(byte[] data, int off, int len)
        throws GeneralSecurityException
    {
        return cipher.doFinal(data, off, len, data, off);
    }
}
