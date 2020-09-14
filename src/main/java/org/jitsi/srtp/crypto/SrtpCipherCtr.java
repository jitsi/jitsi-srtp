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

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * SRTP encryption in CTR mode.
 */
public class SrtpCipherCtr
    extends SrtpCipher
{
    private static final IvParameterSpec zeroIV =
        new IvParameterSpec(new byte[16]);

    private SecretKeySpec key = null;

    public SrtpCipherCtr(Cipher cipher)
    {
        super(cipher);
    }

    @Override
    public void init(byte[] key, byte[] saltKey)
    {
        if (key.length != 16 && key.length != 24 && key.length != 32)
        {
            throw new IllegalArgumentException("Invalid key length");
        }

        this.key = getSecretKey(key);
    }

    @Override
    public void setIV(byte[] iv, int opmode) throws GeneralSecurityException
    {
        if (iv.length != cipher.getBlockSize())
        {
            throw new IllegalArgumentException("iv.length != BLKLEN");
        }

        cipher.init(opmode, key, new IvParameterSpec(iv));
    }

    @Override
    public void processAAD(byte[] data, int off, int len)
    {
        throw new IllegalStateException("CTR mode does not accept AAD");
    }

    @Override
    public int process(byte[] data, int off, int len)
        throws GeneralSecurityException
    {
        return cipher.doFinal(data, off, len, data, off);
    }
}
