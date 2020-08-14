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

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.*;

import javax.crypto.spec.*;

/**
 * Implement the SrtpCipherGcm interface using a BouncyCastle AEADCipher
 */
public class SrtpCipherGcmBC implements SrtpCipherGcm
{
    private final AEADCipher cipher;

    private KeyParameter key = null;
    private int authTagBits = -1;

    public SrtpCipherGcmBC(AEADCipher cipher)
    {
        this.cipher = cipher;
    }

    @Override
    public void init(byte[] key, int authTagBits)
    {
        this.key = new KeyParameter(key);
        this.authTagBits = authTagBits;
    }

    @Override
    public void reset(boolean forEncryption, byte[] iv)
    {
        cipher.init(forEncryption, new AEADParameters(key, authTagBits, iv));
        key = null; /* Re-use key next time */
    }

    @Override
    public void processAad(byte[] data, int off, int len)
    {
        cipher.processAADBytes(data, off, len);
    }

    @Override
    public void process(byte[] data, int off, int len)
        throws BadAuthTag
    {
        int written = cipher.processBytes(data, off, len, data, off);

        try
        {
            cipher.doFinal(data, off + written);
        }
        catch (InvalidCipherTextException e)
        {
            throw new BadAuthTag();
        }
    }
}
