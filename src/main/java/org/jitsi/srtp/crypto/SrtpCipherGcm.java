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

/**
 * SrtpCipherGcm implementations implement SRTP Galois/Counter Mode Encryption
 * and decryption.  Galois/Counter Mode is an AEAD (Authenticated Encryption
 * with Associated Data) mode which performs encryption and authentication in
 * a single pass.
 *
 * SRTP Counter Mode AES Encryption algorithm is defined in RFC 7714.
 */
public interface SrtpCipherGcm
{
    /**
     * (Re)Initialize the cipher with key
     *
     * @param key the key.
     * @oaram authTagBits the size of the auth tag, in bits
     */
    void init(byte[] key, int authTagBits);

    /**
     * Reset the cipher with a new IV.
     */
    void reset(boolean forEncryption, byte[] iv);

    /**
     * Add AAD (additional authenticated data) to the cipher context.
     *
     * Note that this must be called before any call to process
     * *
     * @param data byte array to be processed
     * @param off the offset
     * @param len the length
     */
    void processAad(byte[] data, int off, int len);

    /**
     * Process (encrypt/decrypt) data from offset for len bytes, then
     * add auth tag (encrypt) or verify auth tag (decrypt).
     * @param data byte array to be processed
     * @param off the offset
     * @param len the length
     * @return The delta in total length, after the auth tag is added or removed.
     * @throws BadAuthTag if the auth tag is incorrect for decryption.
     */
    int process(byte[] data, int off, int len) throws BadAuthTag;

    class BadAuthTag extends Exception
    {

    }
}
