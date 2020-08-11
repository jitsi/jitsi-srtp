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

    private Key key;

    private static native long AES_CTR_CTX_create();

    private static native void AES_CTR_CTX_destroy(long ctx);

    private static native boolean AES_CTR_CTX_init(long ctx, byte[] key);

    private static native boolean AES_CTR_CTX_process(long ctx, byte[] iv,
        byte[] inOut, int offset, int len);

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

        ctx = AES_CTR_CTX_create();
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
        return BLKLEN;
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

        try
        {
            this.iv = params.getParameterSpec(IvParameterSpec.class).getIV();
        }
        catch (InvalidParameterSpecException e)
        {
            throw new InvalidAlgorithmParameterException(e);
        }

        this.parameters = params;
        if (key != this.key)
        {
            this.key = key;
            if (!AES_CTR_CTX_init(ctx, key.getEncoded()))
            {
                throw new InvalidKeyException("AES_CTR_CTX_init");
            }
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
        if (!AES_CTR_CTX_process(ctx, iv, input, inputOffset, inputLen))
        {
            throw new ShortBufferException("AES_CTR_CTX_process");
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
                AES_CTR_CTX_destroy(ctx);
                ctx = 0;
            }
        }
        finally
        {
            super.finalize();
        }
    }
}
