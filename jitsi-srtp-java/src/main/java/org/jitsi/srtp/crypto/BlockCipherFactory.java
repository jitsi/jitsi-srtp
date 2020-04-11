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

/**
 * Defines the application programming interface (API) of a factory of
 * <tt>org.bouncycastle.crypto.BlockCipher</tt> instances.
 *
 * @author Lyubomir Marinov
 */
public interface BlockCipherFactory
{
    /**
     * Initializes a new <tt>BlockCipher</tt> instance.
     * @param keySize AES key size (16, 24, 32 bytes)
     *
     * @return a new <tt>BlockCipher</tt> instance
     * @throws Exception if anything goes wrong while initializing a new
     * <tt>BlockCipher</tt> instance
     */
    public BlockCipher createBlockCipher(int keySize)
        throws Exception;
}
