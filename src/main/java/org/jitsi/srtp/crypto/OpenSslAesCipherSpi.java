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

import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * AES-CTR, AES-GCM, and AES-ECB implementation using OpenSSL via JNI.
 */
public abstract class OpenSslAesCipherSpi
    extends CipherSpi
{
    protected static final int BLKLEN = 16;

    private static native long EVP_CIPHER_CTX_new();

    private static native void EVP_CIPHER_CTX_free(long ctx);

    private static native boolean EVP_CipherInit(long ctx, long type,
        byte[] key, byte[] iv, int enc);

    private static native boolean EVP_CipherUpdate(long ctx,
        byte[] in, int inOffset, int len, byte[] out, int outOffset);

    /**
     * The current key used for this cipher.
     */
    private Key key;

    /**
     * The current mode of this cipher.
     */
    private final String cipherMode;

    /**
     * the OpenSSL EVP_CIPHER_CTX context
     */
    protected long ctx;

    /**
     * The most recent initialization vector set
     */
    protected byte[] iv;

    /**
     * The Cipher operation mode with which the cipher was initialized.
     */
    protected int opmode = 0;

    protected OpenSslAesCipherSpi(String cipherMode)
    {
        if (!JitsiOpenSslProvider.isLoaded())
        {
            throw new RuntimeException("OpenSSL wrapper not loaded");
        }

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == 0)
        {
            throw new RuntimeException("EVP_CIPHER_CTX_create");
        }

        this.cipherMode = cipherMode;
    }

    @Override
    public void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        if (!cipherMode.equalsIgnoreCase(mode))
        {
            throw new NoSuchAlgorithmException("Unsupported mode " + mode);
        }
    }

    /**
     * Get the appropriate OpenSSL cipher object for the given key length.
     */
    protected abstract long getOpenSSLCipher(Key key)
        throws InvalidKeyException;

    @Override
    public void engineSetPadding(String padding)
        throws NoSuchPaddingException
    {
        if (!"nopadding".equalsIgnoreCase(padding))
        {
            throw new NoSuchPaddingException("No padding support");
        }
    }

    @Override
    protected int engineGetBlockSize()
    {
        return BLKLEN;
    }

    protected int getOutputSize(int inputLen, boolean forFinal)
    {
        return inputLen;
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        return getOutputSize(inputLen, true);
    }

    @Override
    protected byte[] engineGetIV()
    {
        return Arrays.copyOf(iv, iv.length);
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        /* Not used by jitsi-srtp. */
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameterSpec) null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new InvalidKeyException("could not create params", e);
        }
    }

    protected void doEngineInit(int opmode, Key key)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (!key.getAlgorithm().equalsIgnoreCase("AES")
            || !key.getFormat().equalsIgnoreCase("RAW")
            || (key.getEncoded().length != 16
            && key.getEncoded().length != 24
            && key.getEncoded().length != 32))
        {
            throw new InvalidKeyException(
                "AES SecretKeySpec expected, got " + key.getEncoded().length
                    + " " + key.getAlgorithm() + "/" + key.getFormat());
        }

        int openSslEncryptMode;
        switch (opmode)
        {
        case Cipher.ENCRYPT_MODE:
            openSslEncryptMode = 1;
            break;
        case Cipher.DECRYPT_MODE:
            openSslEncryptMode = 0;
            break;
        default:
            throw new InvalidAlgorithmParameterException("Unsupported opmode " + opmode);
        }
        this.opmode = opmode;

        byte[] keyParam = null;
        long cipherType = 0;
        if (key != this.key)
        {
            this.key = key;
            keyParam = key.getEncoded();
            cipherType = getOpenSSLCipher(key);
        }

        if (!EVP_CipherInit(ctx, cipherType, keyParam, this.iv, openSslEncryptMode))
        {
            throw new InvalidKeyException("EVP_CipherInit");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
        SecureRandom random)
    {
        /* Not used by jitsi-srtp - parameters are always set externally. */
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        int bufNeeded = getOutputSize(inputLen, false);
        byte[] buf = new byte[bufNeeded];
        try
        {
            int len = engineUpdate(input, inputOffset, inputLen, buf, 0);
            assert(len == bufNeeded);
        }
        catch (ShortBufferException e)
        {
            /* Shouldn't happen, we allocated enough. */
            throw new IllegalStateException(e);
        }
        return buf;
    }

    /**
     * Call EVP_CipherUpdate, throwing on failure.
     */
    protected void doCipherUpdate(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset)
    {
        if (!EVP_CipherUpdate(ctx, input, inputOffset, inputLen, output,
            outputOffset))
        {
            throw new IllegalStateException("Failure in EVP_CipherUpdate");
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset) throws ShortBufferException
    {
        int needed = getOutputSize(inputLen, false);
        if (output.length - outputOffset < needed)
        {
            throw new ShortBufferException("Output buffer needs at least " +
                needed + "bytes");
        }
        if (inputOffset + inputLen > input.length)
        {
            throw new IllegalArgumentException("Input buffer length " + input.length +
                " is too short for offset " + inputOffset + " plus length " + inputLen);
        }

        doCipherUpdate(input, inputOffset, inputLen, output, outputOffset);
        return inputLen;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws AEADBadTagException
    {
        int bufNeeded = getOutputSize(inputLen, true);
        byte[] buf = new byte[bufNeeded];
        try
        {
            int len = engineDoFinal(input, inputOffset, inputLen, buf, 0);
            assert(len == bufNeeded);
        }
        catch (ShortBufferException e)
        {
            /* Shouldn't happen, we allocated enough. */
            throw new IllegalStateException(e);
        }
        return buf;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset) throws
        ShortBufferException, AEADBadTagException
    {
        int needed = getOutputSize(inputLen, false);
        if (output.length - outputOffset < needed)
        {
            throw new ShortBufferException("Output buffer needs at least " +
                needed + "bytes");
        }
        if (inputOffset + inputLen > input.length)
        {
            throw new IllegalArgumentException("Input buffer length " + input.length +
                " is too short for offset " + inputOffset + " plus length " + inputLen);
        }

        doCipherUpdate(input, inputOffset, inputLen, output, outputOffset);
        return inputLen;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void finalize() throws Throwable
    {
        try
        {
            // Well, the destroying in the finalizer should exist as a backup
            // anyway. There is no way to explicitly invoke the destroying at
            // the time of this writing but it is a start.
            if (ctx != 0)
            {
                EVP_CIPHER_CTX_free(ctx);
                ctx = 0;
            }
        }
        finally
        {
            super.finalize();
        }
    }

}
