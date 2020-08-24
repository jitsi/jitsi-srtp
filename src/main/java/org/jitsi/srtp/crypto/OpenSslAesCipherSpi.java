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
 * AES-CTR implementation using OpenSSL via JNI.
 */
public class OpenSslAesCipherSpi
    extends CipherSpi
{
    private static final int BLKLEN = 16;

    private static native long EVP_aes_128_ctr();
    private static native long EVP_aes_192_ctr();
    private static native long EVP_aes_256_ctr();

    private static native long EVP_CIPHER_CTX_new();

    private static native void EVP_CIPHER_CTX_free(long ctx);

    private static native boolean EVP_CipherInit(long ctx, long type,
        byte[] key, byte[] iv, int enc);

    private static native boolean EVP_CipherUpdate(long ctx,
        byte[] in, int inOffset, int len, byte[] out, int outOffset);

    private static native boolean EVP_CipherFinal(long ctx,
        byte[] out, int offset);

    private Key key;

    /**
     * the OpenSSL AES_CTR context
     */
    private long ctx;

    private byte[] iv;

    private AlgorithmParameters parameters;

    public OpenSslAesCipherSpi()
    {
        if (!JitsiOpenSslProvider.isLoaded())
        {
            throw new RuntimeException("OpenSSL wrapper not loaded");
        }

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == 0)
        {
            throw new RuntimeException("CIPHER_CTX_create");
        }
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        if (!"ctr".equalsIgnoreCase(mode))
        {
            throw new NoSuchAlgorithmException("Only CTR mode is supported");
        }
    }

    @Override
    protected void engineSetPadding(String padding)
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

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        return inputLen;
    }

    @Override
    protected byte[] engineGetIV()
    {
        return Arrays.copyOf(iv, iv.length);
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        return parameters;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random)
        throws InvalidKeyException
    {
        try
        {
            engineInit(opmode, key, (AlgorithmParameters) null, random);
        }
        catch (InvalidAlgorithmParameterException e)
        {
            throw new InvalidKeyException("could not create params", e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key,
        AlgorithmParameterSpec paramGenSpec, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameters params;
        try
        {
            params = AlgorithmParameters.getInstance("AES");
            params.init(paramGenSpec);
        }
        catch (NoSuchAlgorithmException | InvalidParameterSpecException e)
        {
            throw new InvalidAlgorithmParameterException(
                "AES params not found", e);
        }

        engineInit(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
        SecureRandom random)
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

        int enc;
        switch (opmode)
        {
        case Cipher.ENCRYPT_MODE:
            enc = 1;
            break;
        case Cipher.DECRYPT_MODE:
            enc = 0;
            break;
        default:
            throw new InvalidAlgorithmParameterException("Unsupported opmode " + opmode);
        }

        try
        {
            this.iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        }
        catch (InvalidParameterSpecException e)
        {
            throw new InvalidAlgorithmParameterException(e);
        }

        this.parameters = params;
        byte[] keyParam = null;
        long cipherType = 0;
        if (key != this.key)
        {
            this.key = key;
            keyParam = key.getEncoded();
            cipherType = getCTRCipher(key);
        }
        if (!EVP_CipherInit(ctx, cipherType, keyParam, this.iv, enc))
        {
            throw new InvalidKeyException("AES_CTR_CTX_init");
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        return engineDoFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset) throws ShortBufferException
    {
        return engineDoFinal(input, inputOffset, inputLen, output,
            outputOffset);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
    {
        byte[] out = new byte[inputLen];
        try
        {
            engineDoFinal(input, inputOffset, inputLen, out, 0);
        }
        catch (ShortBufferException e)
        {
            // nope, we allocated enough
        }
        return out;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset) throws
        ShortBufferException
    {
        if (!EVP_CipherUpdate(ctx, input, inputOffset, inputLen, output, outputOffset))
        {
            throw new ShortBufferException("EVP_CipherUpdate");
        }

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

    /** Get the appropriate OpenSSL cipher for CTR mode. */
    private static long getCTRCipher(Key key)
        throws InvalidKeyException
    {
        switch (key.getEncoded().length)
        {
        case 16:
            return EVP_aes_128_ctr();
        case 24:
            return EVP_aes_192_ctr();
        case 32:
            return EVP_aes_256_ctr();
        default:
            throw new InvalidKeyException("Invalid AES key length: "
                + key.getEncoded().length + " bytes");
        }
    }
}
