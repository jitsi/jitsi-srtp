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

import java.security.*;

import javax.crypto.*;

import org.bouncycastle.crypto.*;
import org.jetbrains.annotations.*;
import org.jitsi.srtp.crypto.*;
import org.jitsi.utils.logging2.*;

/**
 * Implements a <tt>BlockCipherFactory</tt> which initializes
 * <tt>BlockCipher</tt>s that are implemented by a
 * <tt>java.security.Provider</tt>.
 *
 * @author Lyubomir Marinov
 */
public class SecurityProviderBlockCipherFactory
    implements BlockCipherFactory
{
    /**
     * The <tt>java.security.Provider</tt> which provides the implementations of
     * the <tt>BlockCipher</tt>s to be initialized by this instance.
     */
    private final Provider provider;

    /**
     * The name of the transformation.
     */
    private final String transformation;

    /**
     * The <tt>Logger</tt> used by the
     * instance to print out debug information.
     */
    private final Logger logger;

    /**
     * Initializes a new <tt>SecurityProvider</tt> instance which is to
     * initialize <tt>BlockCipher</tt>s that are implemented by a specific
     * <tt>java.security.Provider</tt>.
     *
     * @param transformation the name of the transformation
     * @param provider the <tt>java.security.Provider</tt> which provides the
     * implementations of the <tt>BlockCipher</tt>s to be initialized by the new
     * instance
     */
    public SecurityProviderBlockCipherFactory(
            String transformation,
            Provider provider,
            @NotNull Logger parentLogger)
    {
        if (transformation == null)
            throw new NullPointerException("transformation");
        if (transformation.length() == 0)
            throw new IllegalArgumentException("transformation");
        if (provider == null)
            throw new NullPointerException("provider");

        logger = parentLogger.createChildLogger(getClass().getName());
        this.transformation = transformation;
        this.provider = provider;
    }

    /**
     * Initializes a new <tt>SecurityProvider</tt> instance which is to
     * initialize <tt>BlockCipher</tt>s that are implemented by a specific
     * <tt>java.security.Provider</tt>.
     *
     * @param transformation the name of the transformation
     * @param providerName the name of the <tt>java.security.Provider</tt> which
     * provides the implementations of the <tt>BlockCipher</tt>s to be
     * initialized by the new instance
     */
    public SecurityProviderBlockCipherFactory(
            String transformation,
            String providerName,
            @NotNull Logger parentLogger)
    {
        this(transformation, Security.getProvider(providerName), parentLogger);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public BlockCipher createBlockCipher(int keySize)
        throws Exception
    {
        return
            new BlockCipherAdapter(
                    Cipher.getInstance(
                            transformation.replaceFirst(
                                    "<size>",
                                    Integer.toString(keySize * 8)),
                            provider),
                logger);
    }
}
