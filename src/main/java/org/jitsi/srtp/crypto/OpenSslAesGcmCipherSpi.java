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

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;

/**
 * AES-GCM Cipher implementation using OpenSSL via JNI.
 */
public final class OpenSslAesGcmCipherSpi
    extends OpenSslAesCipherSpi
{
    private static native long EVP_aes_128_gcm();
    private static native long EVP_aes_192_gcm();
    private static native long EVP_aes_256_gcm();

    private native boolean EVP_CipherFinal(long ctx,
        byte[] out, int offset);

    private native boolean CipherSetIVLen(long ctx, int ivlen);
    private native boolean CipherSetTag(long ctx,
        byte[] tag, int offset, int taglen);
    private native boolean CipherGetTag(long ctx,
        byte[] tag, int offset, int taglen);

    public OpenSslAesGcmCipherSpi()
    {
        super("GCM");
    }

    /**
     * The size of the authentication tag, in bytes.
     */
    private int tagLen;

    @Override
    protected int getOutputSize(int inputLen, boolean forFinal)
    {
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
    protected void engineInit(int opmode, Key key,
        AlgorithmParameterSpec params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        int newIvLen = 0;

        if (params != null)
        {
            if (params instanceof GCMParameterSpec)
            {
                if (((GCMParameterSpec) params).getTLen() != 128)
                {
                    /* The only length used by srtp transforms. */
                    throw new InvalidAlgorithmParameterException
                        ("Unsupported GCM tag length: must be 128");
                }
                tagLen = ((GCMParameterSpec) params).getTLen() / 8;
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
            /* According to the SPI spec we should use random to generate the
             * IV in this case if we're encrypting, but we never want to do this for SRTP.
             */
            throw new InvalidAlgorithmParameterException
                ("IV parameter missing");
        }

        if (newIvLen != 0)
        {
            if (!CipherSetIVLen(ctx.ptr, newIvLen))
            {
                throw new InvalidAlgorithmParameterException
                    ("Unsupported IV length " + newIvLen);
            }
        }

        doEngineInit(opmode, key);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen,
        byte[] output, int outputOffset) throws ShortBufferException
    {
        if (opmode != Cipher.ENCRYPT_MODE)
        {
            /* Update for decryption is complicated for GCM, as bytes that might
             * be the tag rather than encrypted data need to be buffered.
             * jitsi-srtp never uses this operation (it always directly calls doFinal),
             * so this SPI doesn't support it.
             */
            throw new UnsupportedOperationException(
                "Update not supported for GCM Decryption");
        }
        return super
            .engineUpdate(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen)
    {
        if (inputOffset + inputLen > input.length)
        {
            throw new IllegalArgumentException(
                "Input buffer length " + input.length +
                    " is too short for offset " + inputOffset + " plus length "
                    + inputLen);
        }
        doCipherUpdate(input, inputOffset, inputLen, null, 0);
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
            throw new IllegalArgumentException(
                "Input buffer length " + input.length +
                    " is too short for offset " + inputOffset + " plus length "
                    + inputLen);
        }

        int outLen;

        if (opmode == Cipher.ENCRYPT_MODE)
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

            int ciphertextLen = inputLen - tagLen;
            doCipherUpdate(input, inputOffset, ciphertextLen, output,
                outputOffset);
            outLen = ciphertextLen;
            int tagOffset = inputOffset + ciphertextLen;

            if (!CipherSetTag(ctx.ptr, input, tagOffset, tagLen))
            {
                throw new IllegalStateException("Failure in EVP_CipherSetTag");
            }
        }

        if (!EVP_CipherFinal(ctx.ptr, output, outputOffset + outLen))
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
            if (!CipherGetTag(ctx.ptr, output, outputOffset + outLen, tagLen))
            {
                throw new IllegalStateException("Failure in EVP_CipherGetTag");
            }
            outLen += tagLen;
        }

        return outLen;
    }

    @Override
    protected long getOpenSSLCipher(Key key) throws InvalidKeyException
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
}
