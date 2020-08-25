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

    private static native long EVP_aes_128_gcm();
    private static native long EVP_aes_192_gcm();
    private static native long EVP_aes_256_gcm();

    private static native long EVP_aes_128_ecb();
    private static native long EVP_aes_192_ecb();
    private static native long EVP_aes_256_ecb();

    private static native long EVP_CIPHER_CTX_new();

    private static native void EVP_CIPHER_CTX_free(long ctx);

    private static native boolean EVP_CipherInit(long ctx, long type,
        byte[] key, byte[] iv, int enc);

    private static native boolean EVP_CipherUpdate(long ctx,
        byte[] in, int inOffset, int len, byte[] out, int outOffset);

    private static native boolean EVP_CipherFinal(long ctx,
        byte[] out, int offset);

    private static native boolean EVP_CipherSetTag(long ctx,
        byte[] tag, int offset, int taglen);

    private static native boolean EVP_CipherGetTag(long ctx,
        byte[] tag, int offset, int taglen);

    private Key key;

    private static final int CTR_MODE = 1;
    private static final int GCM_MODE = 2;
    private static final int ECB_MODE = 3;

    private int cipherMode = 0;

    /**
     * the OpenSSL AES_CTR context
     */
    private long ctx;

    private byte[] iv;

    public OpenSslAesCipherSpi()
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
    }

    @Override
    public void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        if ("ctr".equalsIgnoreCase(mode))
        {
            cipherMode = CTR_MODE;
        }
        else if ("gcm".equalsIgnoreCase(mode))
        {
            cipherMode = GCM_MODE;
        }
        else if ("ecb".equalsIgnoreCase(mode))
        {
            cipherMode = ECB_MODE;
        }
        else
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

        if (params != null)
        {
            if (cipherMode == GCM_MODE)
            {
                if (params instanceof GCMParameterSpec)
                {
                    if (((GCMParameterSpec)params).getTLen() != 128)
                    {
                        throw new InvalidAlgorithmParameterException
                            ("Unsupported GCM tag length: must be 128");
                    }
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
                if (params instanceof IvParameterSpec)
                {
                    iv = ((IvParameterSpec) params).getIV();
                    if (iv.length != BLKLEN)
                    {
                        throw new InvalidAlgorithmParameterException
                            ("Unsupported IV length: must be " + BLKLEN + " bytes");
                    }
                }
                else
                {
                    throw new InvalidAlgorithmParameterException
                        ("Unsupported parameter: " + params);
                }
            }
        }
        else
        {
            iv = null;
        }

        if (cipherMode == ECB_MODE)
        {
            if (iv != null)
            {
                throw new InvalidAlgorithmParameterException
                    ("ECB mode cannot use IV");
            }
        }
        else if (iv == null)
        {
            /* According to the SPI spec we should use random to generate the
             * IV in this case if we're encrypting, but we never want to do this for SRTP.
             */
            throw new InvalidAlgorithmParameterException
                ("Parameters missing");
        }

        byte[] keyParam = null;
        long cipherType = 0;
        if (key != this.key)
        {
            this.key = key;
            keyParam = key.getEncoded();
            cipherType = getCipher(key);
        }

        if (!EVP_CipherInit(ctx, cipherType, keyParam, this.iv, enc))
        {
            throw new InvalidKeyException("AES_CTR_CTX_init");
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
                if (cipherMode == GCM_MODE)
                {
                    spec = params.getParameterSpec(GCMParameterSpec.class);
                }
                else
                {
                    spec = params.getParameterSpec(IvParameterSpec.class);
                }
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
    protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen)
    {
        if (!EVP_CipherUpdate(ctx, input, inputOffset, inputLen, null, 0))
        {
            throw new IllegalStateException("EVP_CipherUpdate");
        }
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

    private long getCipher(Key key)
        throws InvalidKeyException
    {
        switch (cipherMode)
        {
        case CTR_MODE:
            return getCTRCipher(key);
        case GCM_MODE:
            return getGCMCipher(key);
        case ECB_MODE:
            return getECBCipher(key);
        default:
            throw new IllegalStateException("Bad cipherMode " + cipherMode);
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

    /** Get the appropriate OpenSSL cipher for GCM mode. */
    private static long getGCMCipher(Key key)
        throws InvalidKeyException
    {
        switch (key.getEncoded().length)
        {
        case 16:
            return EVP_aes_128_gcm();
        case 24:
            return EVP_aes_192_gcm();
        case 32:
            return EVP_aes_256_gcm();
        default:
            throw new InvalidKeyException("Invalid AES key length: "
                + key.getEncoded().length + " bytes");
        }
    }

    /** Get the appropriate OpenSSL cipher for ECB mode. */
    private static long getECBCipher(Key key)
        throws InvalidKeyException
    {
        switch (key.getEncoded().length)
        {
        case 16:
            return EVP_aes_128_ecb();
        case 24:
            return EVP_aes_192_ecb();
        case 32:
            return EVP_aes_256_ecb();
        default:
            throw new InvalidKeyException("Invalid AES key length: "
                + key.getEncoded().length + " bytes");
        }
    }
}
