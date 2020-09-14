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

    private static native boolean EVP_CipherSetIVLen(long ctx, int ivlen);

    private static native boolean EVP_CipherSetTag(long ctx,
        byte[] tag, int offset, int taglen);

    private static native boolean EVP_CipherGetTag(long ctx,
        byte[] tag, int offset, int taglen);

    /**
     * The current key used for this cipher.
     */
    private Key key;

    /**
     * Valid modes supported by this cipher.
     */
    private enum CipherMode
    {
        Unspecified, CTR, GCM, ECB
    }

    /**
     * The current mode of this cipher.
     */
    private CipherMode cipherMode = CipherMode.Unspecified;

    /**
     * the OpenSSL EVP_CIPHER_CTX context
     */
    private long ctx;

    /**
     * The most recent initialization vector set
     */
    private byte[] iv;

    /**
     * The Cipher operation mode with which the cipher was initialized.
     */
    private int opmode = 0;

    /**
     * For GCM, the size of the authentication tag, in bytes.
     */
    private int tagLen;

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
            cipherMode = CipherMode.CTR;
        }
        else if ("gcm".equalsIgnoreCase(mode))
        {
            cipherMode = CipherMode.GCM;
        }
        else if ("ecb".equalsIgnoreCase(mode))
        {
            cipherMode = CipherMode.ECB;
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

    private int getOutputSize(int inputLen, boolean forFinal)
    {
        if (cipherMode != CipherMode.GCM)
        {
            return inputLen;
        }
        if (opmode == Cipher.ENCRYPT_MODE)
        {
            if (forFinal)
            {
                return inputLen + tagLen;
            }
            else
            {
                return inputLen;
            }
        }
        else
        {
            return Math.max(inputLen - tagLen, 0);
        }
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

    @Override
    protected void engineInit(int opmode, Key key,
        AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (cipherMode == CipherMode.Unspecified)
        {
            throw new IllegalStateException("Cipher mode has not been initialized");
        }

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

        int newIvLen = 0;

        if (params != null)
        {
            if (cipherMode == CipherMode.GCM)
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
                    byte[] newIv = ((GCMParameterSpec) params).getIV();
                    /* We only want to call EVP_CipherSetIVLen if the iv length
                     * has changed.  The default IV length is 12. */
                    if ((iv == null && newIv.length != 12) ||
                        (iv != null && iv.length != newIv.length))
                    {
                        newIvLen = newIv.length;
                    }
                    iv = newIv;
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

        if (cipherMode == CipherMode.ECB)
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
                ("IV parameter missing");
        }

        byte[] keyParam = null;
        long cipherType = 0;
        if (key != this.key)
        {
            this.key = key;
            keyParam = key.getEncoded();
            cipherType = getCipher(key);
        }

        if (newIvLen != 0)
        {
            if (!EVP_CipherSetIVLen(ctx, newIvLen))
            {
                throw new InvalidAlgorithmParameterException
                    ("Unsupported IV length " + newIvLen);
            }
        }

        if (!EVP_CipherInit(ctx, cipherType, keyParam, this.iv, openSslEncryptMode))
        {
            throw new InvalidKeyException("EVP_CipherInit");
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
                if (cipherMode == CipherMode.GCM)
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
    private void doCipherUpdate(byte[] input, int inputOffset, int inputLen,
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
        if (cipherMode != CipherMode.GCM || opmode == Cipher.ENCRYPT_MODE)
        {
            doCipherUpdate(input, inputOffset, inputLen, output, outputOffset);
            return inputLen;
        }
        else
        {
            /* Update for decryption is complicated for GCM, as bytes that might
             * be the tag rather than encrypted data need to be buffered.
             * jitsi-srtp never uses this operation (it always directly calls doFinal),
             * so this SPI doesn't support it.
             */
            throw new UnsupportedOperationException("Update not supported for GCM Decryption");
        }
    }

    @Override
    protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen)
    {
        if (inputOffset + inputLen > input.length)
        {
            throw new IllegalArgumentException("Input buffer length " + input.length +
                " is too short for offset " + inputOffset + " plus length " + inputLen);
        }
        doCipherUpdate(input, inputOffset, inputLen, null, 0);
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
        int outLen;
        if (cipherMode != CipherMode.GCM || opmode == Cipher.ENCRYPT_MODE)
        {
            doCipherUpdate(input, inputOffset, inputLen, output, outputOffset);
            outLen = inputLen;
        }
        else
        {
            if (inputLen < tagLen)
            {
                /* Not enough bytes sent to decryption operation */
                throw new AEADBadTagException("Input too short - need tag");
            }

            doCipherUpdate(input, inputOffset, inputLen - tagLen, output, outputOffset);
            outLen = inputLen - tagLen;
            int tagOffset = inputOffset + outLen;

            if (!EVP_CipherSetTag(ctx, input, tagOffset, tagLen))
            {
                throw new IllegalStateException("Failure in EVP_CipherSetTag");
            }
        }

        if (cipherMode != CipherMode.GCM)
        {
            return outLen;
        }

        if (!EVP_CipherFinal(ctx, output, outputOffset + outLen))
        {
            if (opmode == Cipher.DECRYPT_MODE)
            {
                throw new AEADBadTagException("Bad AEAD tag");
            }
            else
            {
                throw new IllegalStateException("Failure in EVP_CipherFinal");
            }
        }

        if (opmode == Cipher.ENCRYPT_MODE)
        {
            if (!EVP_CipherGetTag(ctx, output, outputOffset + outLen, tagLen))
            {
                throw new IllegalStateException("Failure in EVP_CipherGetTag");
            }
            outLen += tagLen;
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
        case CTR:
            return getCTRCipher(key);
        case GCM:
            return getGCMCipher(key);
        case ECB:
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

    abstract static class Impl extends OpenSslAesCipherSpi
    {
        public Impl(String mode)
        {
            super();
            try
            {
                engineSetMode(mode);
            }
            catch (GeneralSecurityException e)
            {
                throw new ProviderException("Internal Error", e);
            }
        }
    }

    public static final class CTR extends Impl
    {
        public CTR()
        {
            super("CTR");
        }
    }

    public static final class GCM extends Impl
    {
        public GCM()
        {
            super("GCM");
        }
    }

    public static final class ECB extends Impl
    {
        public ECB()
        {
            super("ECB");
        }
    }

}
