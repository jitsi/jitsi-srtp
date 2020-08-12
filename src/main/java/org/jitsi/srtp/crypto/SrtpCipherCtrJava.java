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

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.params.*;

/**
 * @see SrtpCipherCtr
 * SrtpCipherCtr implementation using Java and a {@link StreamCipher}.
 *
 * You can use any <tt>StreamCipher</tt> like TwofishEngine/CTR instead of AES.
 */
public class SrtpCipherCtrJava extends SrtpCipherCtr
{
    private final byte[] tmpCipherBlock = new byte[BLKLEN];
    private final StreamCipher cipher;

    private static final byte[] zeroIV = new byte[BLKLEN];

    private KeyParameter key = null;

    public SrtpCipherCtrJava(StreamCipher cipher)
    {
        this.cipher = cipher;
    }

    /**
     * {@inheritDoc}
     */
    public void init(byte[] key)
    {
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new IllegalArgumentException("Not an AES key length");

        this.key = new KeyParameter(key);

        cipher.init(true, new ParametersWithIV(this.key, zeroIV));
    }

    /**
     * {@inheritDoc}
     */
    public void process(byte[] data, int off, int len, byte[] iv)
    {
        checkProcessArgs(data, off, len, iv);
        cipher.init(true, new ParametersWithIV(this.key, iv));
        cipher.processBytes(data, off, len, data, off);
    }
}
