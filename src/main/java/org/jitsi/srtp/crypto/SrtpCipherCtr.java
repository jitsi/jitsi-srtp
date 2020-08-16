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
        throws GeneralSecurityException
    {
        if (key.length != 16 && key.length != 24 && key.length != 32)
        {
            throw new IllegalArgumentException("Invalid key length");
        }

        this.key = getSecretKey(key);
        cipher.init(Cipher.ENCRYPT_MODE, this.key, zeroIV);
    }

    @Override
    public void process(byte[] data, int off, int len, byte[] iv)
        throws GeneralSecurityException
    {
        checkProcessArgs(data, off, len, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        cipher.update(data, off, len, data, off);
    }
}
