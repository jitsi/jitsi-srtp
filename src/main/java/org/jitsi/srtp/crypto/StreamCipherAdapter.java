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
import org.jitsi.utils.logging2.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

/**
 * Adapts the {@link javax.crypto.Cipher} class to the
 * {@link org.bouncycastle.crypto.BlockCipher} interface.
 *
 * @author Lyubomir Marinov
 */
public class StreamCipherAdapter
    implements StreamCipher
{
    /**
     * The name of the cipher used by this instance.
     */
    private final String cipherName;

    /**
     * The name of the algorithm implemented by this instance.
     */
    private final String algorithmName;

    /**
     * The {@link javax.crypto.Cipher} instance which is adapted to the
     * {@link org.bouncycastle.crypto.StreamCipher} interface by this instance.
     */
    private final Cipher cipher;

    /**
     * Initializes a new <tt>StreamCipherAdapter</tt> instance which is to adapt
     * a specific {@link javax.crypto.Cipher} instance to the
     * {@link org.bouncycastle.crypto.StreamCipher} interface.
     *
     * @param cipher the {@link javax.crypto.Cipher} instance to be adapted to
     * the {@link org.bouncycastle.crypto.StreamCipher} interface by the new
     * instance
     */
    public StreamCipherAdapter(Cipher cipher, Logger parentLogger)
    {
        if (cipher == null)
            throw new NullPointerException("cipher");

        this.cipher = cipher;

        // The value of the algorithm property of javax.crypto.Cipher is a
        // transformation i.e. it may contain mode and padding. StreamCipher
        // in BouncyCastle includes mode but not padding.
        String algorithmName = cipher.getAlgorithm();
        String cipherName = null, modeName = null;

        if (algorithmName != null)
        {
            int endIndex = algorithmName.indexOf('/');

            if (endIndex > 0)
            {
                cipherName = algorithmName.substring(0, endIndex);

                int endIndex2 = algorithmName.indexOf('/', endIndex + 1);
                if (endIndex2 != -1)
                {
                    modeName = algorithmName.substring(endIndex + 1, endIndex2);
                }
            }

            int len = cipherName.length();

            if ((len > 4)
                && (cipherName.endsWith("_128")
                || cipherName.endsWith("_192")
                || cipherName.endsWith("_256")))
            {
                cipherName = cipherName.substring(0, len - 4);
            }

        }
        if (cipherName != null && modeName != null)
        {
            this.algorithmName = cipherName + "/" + modeName;
        }
        else
        {
            this.algorithmName = cipherName;
        }
        this.cipherName = cipherName;
    }

    /**
     * The last value of forEncryption passed to {@link #init}.
     */
    private int opMode = -1;

    /**
     * The last value of params passed, for {@link #reset}.
     */
    private IvParameterSpec iv = null;

    @Override
    public void init(boolean forEncryption, CipherParameters params)
        throws IllegalArgumentException
    {
        if (!(params instanceof ParametersWithIV)) {
            throw new IllegalArgumentException();
        }
        iv = new IvParameterSpec(((ParametersWithIV)params).getIV());

        Key key;

        if (((ParametersWithIV)params).getParameters() instanceof KeyParameter) {
            KeyParameter kP = (KeyParameter)((ParametersWithIV)params).getParameters();
            key = new SecretKeySpec(kP.getKey(), cipherName);
        }
        else {
            key = null;
        }

        opMode = forEncryption ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;

        try
        {
            cipher.init(opMode, key, iv);
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException e)
        {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public String getAlgorithmName()
    {
        return algorithmName;
    }

    private byte[] buf = null;

    @Override
    public byte returnByte(byte in)
    {
        if (buf == null)
        {
            buf = new byte[1];
        }
        buf[0] = in;
        byte[] result = cipher.update(buf);
        return result[0];
    }

    @Override
    public int processBytes(byte[] in, int inOff, int len, byte[] out,
        int outOff) throws DataLengthException
    {
        try
        {
            return cipher.update(in, inOff, len, out, outOff);
        }
        catch (ShortBufferException e)
        {
            throw new DataLengthException(e.getMessage());
        }
    }

    @Override
    public void reset()
    {
        try
        {
            /* A null key means keep the old key for all the ciphers I've checked. */
            cipher.init(opMode, null, iv);
        }
        catch (InvalidKeyException | InvalidAlgorithmParameterException e)
        {
            throw new IllegalStateException(e);
        }
    }
}
