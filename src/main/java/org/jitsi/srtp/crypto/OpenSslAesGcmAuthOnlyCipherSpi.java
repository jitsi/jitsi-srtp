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
 * AES-GCM auth-only Cipher SPI.
 * Can only be used for "decryption".
 */
public class OpenSslAesGcmAuthOnlyCipherSpi
    extends CipherSpi
{
    private static final int BLKLEN = 16;

    private static native long CRYPTO_gcm128_new();

    private static native void CRYPTO_gcm128_release(long ctx);

    private static native boolean CRYPTO_gcm128_init(long ctx, byte[] key);

    private static native boolean CRYPTO_gcm128_setiv(long ctx, byte[] iv, int len);

    private static native boolean CRYPTO_gcm128_aad(long ctx,
        byte[] in, int inOffset, int len);

    private static native boolean CRYPTO_gcm128_decrypt(long ctx,
        byte[] out, int offset, int len);

    private static native boolean CRYPTO_gcm128_finish(long ctx,
        byte[] tag, int offset, int taglen);

    private Key key;

    /**
     * the OpenSSL AES_CTR context
     */
    private long ctx;

    private byte[] iv;

    /**
     * Buffer of bytes that might include the GCM tag when decrypting.
     */
    private byte[] buffer;

    /**
     * The number of bytes buffered.
     */
    private int buffered = 0;

    /**
     * For GCM, the size of the authentication tag, in bytes.
     */
    private int tagLen;

    public OpenSslAesGcmAuthOnlyCipherSpi()
    {
        if (!JitsiOpenSslProvider.isLoaded())
        {
            throw new RuntimeException("OpenSSL wrapper not loaded");
        }

        ctx = CRYPTO_gcm128_new();
        if (ctx == 0)
        {
            throw new IllegalStateException("Error constructing ctx");
        }
    }

    @Override
    public void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        if (!"gcm".equalsIgnoreCase(mode) &&
            !"gcm-authonly".equalsIgnoreCase(mode))
        {
            throw new NoSuchAlgorithmException("Unsupported mode " + mode);
        }
    }

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

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        return 0;
    }

    @Override
    protected byte[] engineGetIV()
    {
        return Arrays.copyOf(iv, iv.length);
    }

    @Override
    protected AlgorithmParameters engineGetParameters()
    {
        /* TODO: do we need this? */
        return null;
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

    @Override
    protected void engineInit(int opmode, Key key,
        AlgorithmParameterSpec params, SecureRandom random)
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

        if (opmode != Cipher.DECRYPT_MODE)
        {
            throw new InvalidAlgorithmParameterException(
                "Unsupported opmode " + opmode);
        }

        if (params != null)
        {
            if (params instanceof GCMParameterSpec)
            {
                if (((GCMParameterSpec)params).getTLen() != 128)
                {
                    /* ?? Do we need to enforce this? */
                    throw new InvalidAlgorithmParameterException
                        ("Unsupported GCM tag length: must be 128");
                }
                tagLen = ((GCMParameterSpec)params).getTLen() / 8;
                iv = ((GCMParameterSpec) params).getIV();
            }
            else
            {
                throw new InvalidAlgorithmParameterException
                    ("Unsupported parameter: " + params);
            }
        }
        else
        {
            throw new InvalidAlgorithmParameterException
                ("IV parameter missing");
        }

        byte[] keyParam = null;
        if (key != this.key)
        {
            this.key = key;
            keyParam = key.getEncoded();
        }

        if (keyParam != null)
        {
            if (!CRYPTO_gcm128_init(ctx, keyParam))
            {
                throw new InvalidKeyException("CRYPTO_gcm128_init");
            }
        }

        if (iv != null)
        {
            if (!CRYPTO_gcm128_setiv(ctx, iv, iv.length))
            {
                throw new InvalidAlgorithmParameterException("CRYPTO_gcm128_setiv");
            }
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params,
        SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        AlgorithmParameterSpec spec = null;
        if (params != null)
        {
            try
            {
                spec = params.getParameterSpec(GCMParameterSpec.class);
            }
            catch (InvalidParameterSpecException e)
            {
                throw new InvalidAlgorithmParameterException(e);
            }
        }
        engineInit(opmode, key, spec, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        engineUpdate(input, inputOffset, inputLen, null, 0);
        return new byte[0];
    }

    /**
     * Call EVP_CipherUpdate, throwing on failure.
     */
    private void doDecrypt(byte[] input, int inputOffset, int inputLen)
    {
        if (!CRYPTO_gcm128_decrypt(ctx, input, inputOffset, inputLen))
        {
            throw new IllegalStateException("Failure in CRYPTO_gcm128_decrypt");
        }
    }

    private int doGcmDecryptUpdateWithBuffer(byte[] input,
        int inputOffset, int inputLen)
    {
        /* For GCM decryption, we need to hold on to the bytes that might be
         * the auth tag. */
        if (buffer == null)
        {
            buffer = new byte[tagLen];
        }
        int len = buffered + inputLen - tagLen;
        int outLen = 0;
        if (len > 0)
        {
            if (len <= buffered)
            {
                doDecrypt(buffer, 0, len);
                buffered -= len;
                inputOffset += len;
                inputLen -= len;
                if (buffered > 0)
                {
                    System.arraycopy(buffer, len, buffer, 0, buffered);
                }
                outLen += len;
            }
            else
            {
                if (buffered > 0)
                {
                    doDecrypt(buffer, 0, buffered);
                    len -= buffered;
                    buffered = 0;
                    outLen += buffered;
                }
                if (len > 0)
                {
                    doDecrypt(input, inputLen, len
                    );
                    inputOffset += len;
                    inputLen -= len;
                    outLen += len;
                }
            }
        }
        assert(buffered + inputLen <= tagLen);
        if (inputLen > 0)
        {
            System.arraycopy(input, inputOffset, buffer, buffered, inputLen);
            buffered += inputLen;
        }

        return outLen;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset)
    {
        return doGcmDecryptUpdateWithBuffer(input, inputOffset, inputLen);
    }

    @Override
    protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen)
    {
        if (!CRYPTO_gcm128_aad(ctx, input, inputOffset, inputLen))
        {
            throw new IllegalStateException("Failure in CRYPTO_gcm128_aad");
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws AEADBadTagException
    {
        engineDoFinal(input, inputOffset, inputLen, null, 0);
        return new byte[0];
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset) throws
        AEADBadTagException
    {
        byte[] tagBuf;
        int tagOffset;
        int outLen;
        if (buffered == 0 && inputLen >= tagLen)
        {
            doDecrypt(input, inputOffset, inputLen - tagLen);
            outLen = inputLen - tagLen;
            tagBuf = input;
            tagOffset = inputOffset + inputLen - tagLen;
        }
        else {
            outLen = doGcmDecryptUpdateWithBuffer(input, inputOffset, inputLen);
            if (buffered != tagLen)
            {
                /* Not enough bytes sent to decryption operation */
                throw new AEADBadTagException("Input too short - need tag");
            }
            tagBuf = buffer;
            tagOffset = 0;
        }
        if (!CRYPTO_gcm128_finish(ctx, tagBuf, tagOffset, tagLen))
        {
            throw new AEADBadTagException("Bad AEAD tag");
        }

        return outLen;
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
                CRYPTO_gcm128_release(ctx);
                ctx = 0;
            }
        }
        finally
        {
            super.finalize();
        }
    }
}
