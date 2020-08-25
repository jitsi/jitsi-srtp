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
 * SRTP encryption.
 */
public abstract class SrtpCipher
{
    /**
     * block size, just a short name.
     */
    public static final int BLKLEN = 16;

    /**
     * A 128 bits block cipher (AES or TwoFish)
     */
    protected final Cipher cipher;

    protected SrtpCipher(Cipher cipher)
    {
        this.cipher = cipher;
    }

    public abstract void init(byte[] k_e, byte[] k_s)
        throws GeneralSecurityException;

    public abstract void setIV(byte[] iv, boolean enc)
        throws GeneralSecurityException;

    public abstract void processAAD(byte[] data, int off, int len)
        throws GeneralSecurityException;

    public abstract int process(byte[] data, int off, int len)
        throws GeneralSecurityException;

    protected SecretKeySpec getSecretKey(byte[] key)
    {
        return new SecretKeySpec(key, cipher.getAlgorithm()
            .substring(0, cipher.getAlgorithm().indexOf('/')));
    }
}
