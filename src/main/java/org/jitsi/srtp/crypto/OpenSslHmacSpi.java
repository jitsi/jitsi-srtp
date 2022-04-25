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

import java.lang.ref.Cleaner.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;

/**
 * Implements the interface {@link MacSpi} using the OpenSSL Crypto library.
 *
 * @author Lyubomir Marinov
 */
public class OpenSslHmacSpi
    extends MacSpi implements AutoCloseable
{
    private static class OpenSslHmacSpiCleanable implements Runnable
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
                OpenSslHmacSpi.HMAC_CTX_destroy(ptr);
                ptr = 0;
            }
        }
    }

    private static native int EVP_MD_size(long md);

    private static native long EVP_sha1();

    private static native long HMAC_CTX_create();

    private static native void HMAC_CTX_destroy(long ctx);

    private static native int HMAC_Final(
            long ctx,
            byte[] md, int mdOff, int mdLen);

    private static native boolean HMAC_Init_ex(
            long ctx,
            byte[] key, int keyLen,
            long md,
            long impl);

    private static native boolean HMAC_Update(
            long ctx,
            byte[] data, int off, int len);

    /**
     * Cleanable-wrapped context of the OpenSSL (Crypto) library through which the actual
     * algorithm implementation is invoked by this instance.
     */
    private final OpenSslHmacSpiCleanable ctx = new OpenSslHmacSpiCleanable();

    /**
     * Cleanable registration of the OpenSSL HMAC context.
     */
    private final Cleanable ctxCleanable;

    /**
     * The key provided for the HMAC.
     */
    private Key key;

    /**
     * The block size in bytes for this MAC.
     */
    private final int macSize;

    /**
     * The OpenSSL Crypto type of the message digest implemented by this
     * instance.
     */
    private final long md;

    /**
     * Initializes a new of this class for {@code HMAC-SHA1}.
     */
    public OpenSslHmacSpi()
    {
        if (!JitsiOpenSslProvider.isLoaded())
            throw new RuntimeException("OpenSSL wrapper not loaded");

        md = EVP_sha1();
        if (md == 0)
            throw new IllegalStateException("EVP_sha1 == 0");

        macSize = EVP_MD_size(md);
        if (macSize == 0)
            throw new IllegalStateException("EVP_MD_size == 0");

        ctx.ptr = HMAC_CTX_create();
        if (ctx.ptr == 0)
            throw new RuntimeException("HMAC_CTX_create == 0");

        ctxCleanable = JitsiOpenSslProvider.CLEANER.register(this, ctx);
    }

    @Override
    protected int engineGetMacLength()
    {
        return macSize;
    }

    @Override
    protected byte[] engineDoFinal()
    {
        long ctx = this.ctx.ptr;

        if (ctx == 0)
        {
            throw new IllegalStateException("ctx");
        }
        else
        {
            byte[] out = new byte[macSize];
            int outLen = HMAC_Final(ctx, out, 0, out.length);
            if (outLen < 0)
            {
                throw new RuntimeException("HMAC_Final");
            }
            else
            {
                // As the javadoc on interface method specifies, the doFinal
                // call leaves this Digest reset.
                engineReset();
                return out;
            }
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params)
        throws InvalidKeyException
    {
        this.key = key;

        if (key == null)
            throw new InvalidKeyException("key == null");

        long ctx = this.ctx.ptr;
        if (ctx == 0)
            throw new IllegalStateException("ctx == 0");

        byte[] k = key.getEncoded();
        if (!HMAC_Init_ex(ctx, k, k.length, md, 0))
            throw new RuntimeException("HMAC_Init_ex() init failed");
    }

    @Override
    protected void engineReset()
    {
        if (key == null)
            throw new IllegalStateException("key == null");

        long ctx = this.ctx.ptr;
        if (ctx == 0)
            throw new IllegalStateException("ctx == 0");

        // just reset the ctx (keep same key and md)
        if (!HMAC_Init_ex(ctx, null, 0, 0, 0))
            throw new RuntimeException("HMAC_Init_ex() reset failed");
    }

    @Override
    protected void engineUpdate(byte in)
        throws IllegalStateException
    {
        long ctx = this.ctx.ptr;
        if (ctx == 0)
            throw new IllegalStateException("ctx");
        else if (!HMAC_Update(ctx, new byte[]{in}, 0, 1))
            throw new RuntimeException("HMAC_Update");
    }

    @Override
    protected void engineUpdate(byte[] in, int off, int len)
    {
        if (len != 0)
        {
            if (in == null)
                throw new NullPointerException("in");
            if ((off < 0) || (in.length <= off))
                throw new ArrayIndexOutOfBoundsException(off);
            if ((len < 0) || (in.length < off + len))
                throw new IllegalArgumentException("len " + len);

            long ctx = this.ctx.ptr;
            if (ctx == 0)
                throw new IllegalStateException("ctx");
            else if (!HMAC_Update(ctx, in, off, len))
                throw new RuntimeException("HMAC_Update");
        }
    }

    @Override
    public void close()
    {
        ctxCleanable.clean();
    }
}
