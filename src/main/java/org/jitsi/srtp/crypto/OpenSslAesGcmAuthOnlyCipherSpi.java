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

import java.lang.ref.Cleaner.*;
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
    extends CipherSpi implements AutoCloseable
{
    private static final class OpenSslAesGcmAuthOnlyCipherSpiCleanable implements Runnable
    {
        /**
         * The context of the OpenSSL (Crypto) library through which the actual
         * algorithm implementation is invoked by this instance.
         */
        long ptr;

        @Override
        public void run()
        {
            if (ptr != 0)
            {
                OpenSslAesGcmAuthOnlyCipherSpi.CRYPTO_gcm128_release(ptr);
                ptr = 0;
            }
        }
    }

    private static final int BLKLEN = 16;

    private static native long CRYPTO_gcm128_new();

    private static native void CRYPTO_gcm128_release(long ctx);

    /* Note: Native methods that take the 'ctx' (other than _release) need to be non-static,
     * to stop the Java GC from collecting the object (and thus running its Cleanable)
     * while the native methods are still executing.
     */
    private native boolean CRYPTO_gcm128_init(long ctx, byte[] key);

    private native boolean CRYPTO_gcm128_setiv(long ctx, byte[] iv, int len);

    private native boolean CRYPTO_gcm128_aad(long ctx,
        byte[] in, int inOffset, int len);

    private native boolean CRYPTO_gcm128_decrypt(long ctx,
        byte[] out, int offset, int len);

    private native boolean CRYPTO_gcm128_finish(long ctx,
        byte[] tag, int offset, int taglen);

    /**
     * The current key used for this cipher.
     */
    private Key key;

    /**
     * the OpenSSL CRYPTO_gcm128 context and EVP cipher.
     */
    private final OpenSslAesGcmAuthOnlyCipherSpiCleanable ctx;

    /**
     * Cleanable registration of the CRYPTO_gcm128 context.
     */
    private final Cleanable ctxCleanable;

    /**
     * The most recent initialization vector set.
     */
    private byte[] iv;

    /**
     * The size of the authentication tag, in bytes.
     */
    private int tagLen;

    /**
     * Empty byte array returned by update and final flavors returning arrays.
     */
    private static final byte[] EMPTY_BYTE_ARRAY = { };

    public OpenSslAesGcmAuthOnlyCipherSpi()
    {
        if (!JitsiOpenSslProvider.isLoaded())
        {
            throw new RuntimeException("OpenSSL wrapper not loaded");
        }

        ctx = new OpenSslAesGcmAuthOnlyCipherSpiCleanable();
        ctx.ptr = CRYPTO_gcm128_new();
        if (ctx.ptr == 0)
        {
            throw new IllegalStateException("Error constructing ctx");
        }

        ctxCleanable = JitsiOpenSslProvider.CLEANER.register(this, ctx);
    }

    @Override
    public void engineSetMode(String mode) throws NoSuchAlgorithmException
    {
        if (!"gcm-authonly".equalsIgnoreCase(mode))
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
                    /* The only length used by srtp transforms. */
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
            if (!CRYPTO_gcm128_init(ctx.ptr, keyParam))
            {
                throw new InvalidKeyException("CRYPTO_gcm128_init");
            }
        }

        if (iv != null)
        {
            if (!CRYPTO_gcm128_setiv(ctx.ptr, iv, iv.length))
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
        return EMPTY_BYTE_ARRAY;
    }

    /**
     * Call EVP_CipherUpdate, throwing on failure.
     */
    private void doDecrypt(byte[] input, int inputOffset, int inputLen)
    {
        if (!CRYPTO_gcm128_decrypt(ctx.ptr, input, inputOffset, inputLen))
        {
            throw new IllegalStateException("Failure in CRYPTO_gcm128_decrypt");
        }
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset)
    {
        /* Update for decryption is complicated for GCM, as bytes that might
         * be the tag rather than encrypted data need to be buffered.
         * jitsi-srtp never uses this operation (it always directly calls doFinal),
         * so this SPI doesn't support it.
         */
        throw new UnsupportedOperationException("Update not supported for GCM Decryption");
    }

    @Override
    protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen)
    {
        if (inputOffset + inputLen > input.length)
        {
            throw new IllegalArgumentException("Input buffer length " + input.length +
                " is too short for offset " + inputOffset + " plus length " + inputLen);
        }
        if (!CRYPTO_gcm128_aad(ctx.ptr, input, inputOffset, inputLen))
        {
            throw new IllegalStateException("Failure in CRYPTO_gcm128_aad");
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws AEADBadTagException
    {
        engineDoFinal(input, inputOffset, inputLen, null, 0);
        return EMPTY_BYTE_ARRAY;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset) throws
        AEADBadTagException
    {
        if (inputOffset + inputLen > input.length)
        {
            throw new IllegalArgumentException("Input buffer length " + input.length +
                " is too short for offset " + inputOffset + " plus length " + inputLen);
        }
        if (inputLen < tagLen)
        {
            /* Not enough bytes sent to decryption operation */
            throw new AEADBadTagException("Input too short - need tag");
        }

        int ciphertextLen = inputLen - tagLen;
        doDecrypt(input, inputOffset, ciphertextLen);
        int tagOffset = inputOffset + ciphertextLen;

        if (!CRYPTO_gcm128_finish(ctx.ptr, input, tagOffset, tagLen))
        {
            throw new AEADBadTagException("Bad AEAD tag");
        }

        return ciphertextLen;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close()
    {
        ctxCleanable.clean();
    }
}
