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

import java.lang.reflect.*;
import java.security.*;
import java.util.*;

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.*;
import org.jitsi.utils.logging2.*;

/**
 * Implements a factory for an AES/CTR <tt>StreamCipher</tt>.
 *
 * @author Lyubomir Marinov
 */
public class Aes
{
    /**
     * The block size in bytes of the AES algorithm (implemented by the
     * <tt>StreamCipher</tt>s initialized by the <tt>Aes</tt> class).
     */
    private static final int BLOCK_SIZE = 16;

    /**
     * The simple name of the <tt>StreamCipherFactory</tt> class/interface which
     * is used as a class name suffix by the well-known
     * <tt>StreamCipherFactory</tt> implementations.
     */
    private static final String STREAM_CIPHER_FACTORY_SIMPLE_CLASS_NAME
        = "StreamCipherFactory";

    /**
     * The <tt>StreamCipherFactory</tt> implemented with BouncyCastle. It is the
     * well-known fallback.
     */
    private static final StreamCipherFactory BOUNCYCASTLE_FACTORY
        = new BouncyCastleStreamCipherFactory();

    /**
     * The <tt>StreamCipherFactory</tt> implementations known to the <tt>Aes</tt>
     * class among which the fastest is to be elected as {@link #factory}.
     */
    private static StreamCipherFactory[] factories;

    /**
     * The <tt>StreamCipherFactory</tt> implementation which is (to be) used by
     * the class <tt>Aes</tt> to initialize <tt>StreamCipher</tt>s.
     */
    private static StreamCipherFactory factory;

    /**
     * The name of the class to instantiate as a <tt>StreamCipherFactory</tt>
     * implementation to be used by the class <tt>Aes</tt> to initialize
     * <tt>StreamCipher</tt>s.
     */
    private static String FACTORY_CLASS_NAME = null;

    /**
     * The <tt>Class</tt>es of the well-known <tt>StreamCipherFactory</tt>
     * implementations.
     */
    private static final Class<?>[] FACTORY_CLASSES
        = {
            BouncyCastleStreamCipherFactory.class,
            SunJCEStreamCipherFactory.class,
            SunPKCS11StreamCipherFactory.class,
        };

    /**
     * The number of milliseconds after which the benchmark which elected
     * {@link #factory} is to be considered expired.
     */
    public static final long FACTORY_TIMEOUT = 60 * 1000;

    /**
     * The class to instantiate as a <tt>StreamCipherFactory</tt> implementation
     * to be used to initialized <tt>StreamCipher</tt>s.
     *
     * @see #FACTORY_CLASS_NAME
     */
    private static Class<? extends StreamCipherFactory> factoryClass;

    /**
     * The time in milliseconds at which {@link #factories} were benchmarked and
     * {@link #factory} was elected.
     */
    private static long factoryTimestamp;

    /**
     * The size of the data to be used for AES cipher benchmarks.
     * This is chosen to be comparable in size to an SRTP packet.
     */
    private static final int BENCHMARK_SIZE = 1500;

    /**
     * The number of times to pre-execute the benchmark before executing it for real,
     * to give the JVM time to run JITs and the like.
     */
    private static final int NUM_WARMUPS = 1000;

    /**
     * The input buffer to be used for the benchmarking of {@link #factories}.
     * It consists of blocks and its length specifies the number of blocks to
     * process for the purposes of the benchmark.
     */ 
    private static final byte[] in = new byte[BENCHMARK_SIZE];

    /**
     * The output buffer to be used for the benchmarking of {@link #factories}.
     */
    private static final byte[] out = new byte[BENCHMARK_SIZE];

    /**
     * The <tt>Logger</tt> used by the <tt>Aes</tt> class to print out debug
     * information.
     */
    private static final Logger logger = new LoggerImpl(Aes.class.getName());

    /**
     * The random number generator which generates keys and inputs for the
     * benchmarking of the <tt>StreamCipherFactory</tt> implementations.
     */
    private static final Random random = new Random();

    /** Set the class to use as the factory class for AES cryptography.
     * @param name the name of the class
     */
    public static synchronized void setFactoryClassName(String name)
    {
        FACTORY_CLASS_NAME = name;
        factoryClass = null;
    }

    /**
     * Benchmarks a specific array/list of <tt>StreamCipherFactory</tt> instances
     * and returns the fastest-performing element.
     *
     * @param factories the <tt>StreamCipherFactory</tt> instances to benchmark
     * @param keySize AES key size (16, 24, 32 bytes)
     * @return the fastest-performing <tt>StreamCipherFactory</tt> among the
     * specified <tt>factories</tt>
     */
    private static StreamCipherFactory benchmark(
            StreamCipherFactory[] factories,
            int keySize)
    {
        Random random = Aes.random;
        byte[] key = new byte[keySize];
        byte[] iv = new byte[BLOCK_SIZE];
        byte[] in = Aes.in;

        random.nextBytes(key);
        random.nextBytes(iv);
        random.nextBytes(in);

        CipherParameters params = new ParametersWithIV(new KeyParameter(key), iv);
        byte[] out = Aes.out;
        long minTime = Long.MAX_VALUE;
        StreamCipherFactory minFactory = null;

        StringBuilder log = new StringBuilder();

        for (int f = 0; f < factories.length; ++f)
        {
            StreamCipherFactory factory = factories[f];

            if (factory == null)
                continue;

            try
            {
                StreamCipher cipher = factory.createStreamCipher(keySize);

                if (cipher == null)
                {
                    // The StreamCipherFactory failed to initialize a new
                    // StreamCipher instance. We will not use it again because
                    // the failure may persist.
                    factories[f] = null;
                }
                else
                {
                    /* Let the JVM "warm up" (do JIT compilation and the like) */

                    for (int i = 0; i < NUM_WARMUPS; i++) {
                        cipher.init(true, params);

                        cipher.processBytes(in, 0, in.length, out, 0);
                    }

                    long startTime = System.nanoTime();

                    cipher.init(true, params);

                    cipher.processBytes(in, 0, in.length, out, 0);

                    // We do not invoke the method StreamCipher.reset() so we do
                    // not need to take it into account in the benchmark.

                    long endTime = System.nanoTime();
                    long time = endTime - startTime;

                    if (time < minTime)
                    {
                        minTime = time;
                        minFactory = factory;
                    }

                    if (log.length() != 0)
                        log.append(", ");

                    log.append(getSimpleClassName(factory))
                        .append(' ')
                        .append(time);
                }
            }
            catch (Throwable t)
            {
                if (t instanceof InterruptedException)
                    Thread.currentThread().interrupt();
                else if (t instanceof ThreadDeath)
                    throw (ThreadDeath) t;
            }
        }

        if (log.length() != 0)
        {
            logger.info(() ->
                    "AES benchmark"
                        + " (of execution times expressed in nanoseconds): "
                        + log);
        }

        return minFactory;
    }

    /**
     * Initializes a new <tt>StreamCipher</tt> instance which implements Advanced
     * Encryption Standard (AES) CTR mode.
     * @param keySize length of the AES key (16, 24, 32 bytes)
     *
     * @return a new <tt>StreamCipher</tt> instance which implements Advanced
     * Encryption Standard (AES) in the specified mode
     */
    public static StreamCipher createStreamCipher(int keySize)
    {
        StreamCipherFactory factory;

        synchronized (Aes.class)
        {
            long now = System.currentTimeMillis();

            factory = Aes.factory;
            if ((factory != null) && (now > factoryTimestamp + FACTORY_TIMEOUT))
                factory = null;
            if (factory == null)
            {
                try
                {
                    factory = getStreamCipherFactory(keySize);
                }
                catch (Throwable t)
                {
                    if (t instanceof InterruptedException)
                    {
                        Thread.currentThread().interrupt();
                    }
                    else if (t instanceof ThreadDeath)
                    {
                        throw (ThreadDeath) t;
                    }
                    else
                    {
                        logger.warn(() ->
                                "Failed to initialize an optimized AES"
                                    + " implementation: "
                                    + t.getLocalizedMessage());
                    }
                }
                finally
                {
                    if (factory == null)
                    {
                        factory = Aes.factory;
                        if (factory == null)
                            factory = BOUNCYCASTLE_FACTORY;
                    }

                    Aes.factoryTimestamp = now;
                    if (Aes.factory != factory)
                    {
                        Aes.factory = factory;
                        // Simplify the name of the StreamCipherFactory class to
                        // be employed for the purposes of brevity and ease.
                        logger.info(() ->
                                "Will employ AES implemented by "
                                    + getSimpleClassName(Aes.factory) + ".");
                    }
                }
            }
        }

        try
        {
            return factory.createStreamCipher(keySize);
        }
        catch (Exception ex)
        {
            if (ex instanceof RuntimeException)
                throw (RuntimeException) ex;
            else
                throw new RuntimeException(ex);
        }
    }

    private static String getEffectiveFactoryClassName()
    {
        String factoryClassName = FACTORY_CLASS_NAME;

        if ((factoryClassName == null) || (factoryClassName.length() == 0))
        {
            return null;
        }
        // Support specifying FACTORY_CLASS_NAME without a package and
        // without StreamCipherFactory at the end for the purposes of
        // brevity and ease.
        if (Character.isUpperCase(factoryClassName.charAt(0))
            && !factoryClassName.contains(".")
            && !factoryClassName.endsWith(
            STREAM_CIPHER_FACTORY_SIMPLE_CLASS_NAME))
        {
            factoryClassName
                = Aes.class.getName() + "$" + factoryClassName
                + STREAM_CIPHER_FACTORY_SIMPLE_CLASS_NAME;
        }
        return factoryClassName;
    }

    /**
     * Initializes the <tt>StreamCipherFactory</tt> instances to be benchmarked
     * by the class <tt>Aes</tt> and among which the fastest-performing one is
     * to be selected.
     * 
     * @return the <tt>StreamCipherFactory</tt> instances to be benchmarked by
     * the class <tt>Aes</tt> and among which the fastest-performing one is to
     * be selected
     */
    @SuppressWarnings("unchecked")
    private static StreamCipherFactory[] createStreamCipherFactories()
    {
        // The user may have specified a specific StreamCipherFactory class
        // (name) through setFactoryClassName(String). Practically, the specified FACTORY_CLASS_NAME
        // will override all other FACTORY_CLASSES and, consequently, it does
        // not seem necessary to try FACTORY_CLASSES at all. Technically though,
        // the specified StreamCipherFactory may malfunction. That is why all
        // FACTORY_CLASSES are tried as well and FACTORY_CLASS_NAME is selected
        // later on after it has proven itself functional.
        Class<? extends StreamCipherFactory> factoryClass = Aes.factoryClass;
        Class<?>[] factoryClasses = FACTORY_CLASSES;
        boolean add = true;

        if (factoryClass == null)
        {
            String factoryClassName = getEffectiveFactoryClassName();

            if (factoryClassName != null)
            {
                // Is the specified FACTORY_CLASS_NAME one of the well-known
                // FACTORY_CLASSES? If it is, then we do not have to invoke the
                // method Class.forName(String) and add a new Class to
                // FACTORY_CLASSES.
                for (Class<?> clazz : factoryClasses)
                {
                    if ((clazz != null)
                            && clazz.getName().equals(factoryClassName)
                            && StreamCipherFactory.class.isAssignableFrom(clazz))
                    {
                        Aes.factoryClass
                            = factoryClass
                                = (Class<? extends StreamCipherFactory>)
                                    clazz;
                        add = false;
                        break;
                    }
                }

                // If FACTORY_CLASS_NAME does not specify a well-known Class,
                // find and load the Class.
                if (add)
                {
                    try
                    {
                        Class<?> clazz = Class.forName(factoryClassName);
    
                        if (StreamCipherFactory.class.isAssignableFrom(clazz))
                        {
                            Aes.factoryClass
                                = factoryClass
                                    = (Class<? extends StreamCipherFactory>)
                                        clazz;
                        }
                    }
                    catch (Throwable t)
                    {
                        if (t instanceof InterruptedException)
                        {
                            Thread.currentThread().interrupt();
                        }
                        else if (t instanceof ThreadDeath)
                        {
                            throw (ThreadDeath) t;
                        }
                        else
                        {
                            logger.warn(() ->
                                    "Failed to employ class " + factoryClassName
                                        + " as an AES implementation: "
                                        + t.getLocalizedMessage());
                        }
                    }
                }
            }
        }

        // If FACTORY_CLASS_NAME does not specify a well-known Class, add the
        // new Class to FACTORY_CLASSES.
        if (add && (factoryClass != null))
        {
            for (Class<?> clazz : factoryClasses)
            {
                if (factoryClass.equals(clazz))
                {
                    add = false;
                    break;
                }
            }
            if (add)
            {
                Class<?>[] newFactoryClasses
                    = new Class<?>[1 + factoryClasses.length];

                newFactoryClasses[0] = factoryClass;
                System.arraycopy(
                        factoryClasses, 0,
                        newFactoryClasses, 1,
                        factoryClasses.length);
                factoryClasses = newFactoryClasses;
            }
        }

        return createStreamCipherFactories(factoryClasses);
    }

    /**
     * Initializes <tt>StreamCipherFactory</tt> instances of specific
     * <tt>Class</tt>es.
     *
     * @param classes the runtime <tt>Class</tt>es to instantiate
     * @return the <tt>StreamCipherFactory</tt> instances initialized by the
     * specified <tt>classes</tt>
     */
    private static StreamCipherFactory[] createStreamCipherFactories(
            Class<?>[] classes)
    {
        StreamCipherFactory[] factories = new StreamCipherFactory[classes.length];
        int i = 0;

        for (Class<?> clazz : classes)
        {
            try
            {
                if (StreamCipherFactory.class.isAssignableFrom(clazz))
                {
                    StreamCipherFactory factory;

                    if (BouncyCastleStreamCipherFactory.class.equals(clazz))
                        factory = BOUNCYCASTLE_FACTORY;
                    else
                        factory = (StreamCipherFactory) clazz.getConstructor().newInstance();

                    factories[i++] = factory;
                }
            }
            catch (Throwable t)
            {
                if (t instanceof InterruptedException)
                    Thread.currentThread().interrupt();
                else if (t instanceof ThreadDeath)
                    throw (ThreadDeath) t;
            }
        }
        return factories;
    }

    /**
     * Gets a <tt>StreamCipherFactory</tt> instance to be used by the
     * <tt>Aes</tt> class to initialize <tt>StreamCipher</tt>s.
     *
     * <p>
     * Benchmarks the well-known <tt>StreamCipherFactory</tt> implementations and
     * returns the fastest one. 
     * </p>
     * @param keySize AES key size (16, 24, 32 bytes)
     *
     * @return a <tt>StreamCipherFactory</tt> instance to be used by the
     * <tt>Aes</tt> class to initialize <tt>StreamCipher</tt>s
     */
    private static StreamCipherFactory getStreamCipherFactory(int keySize)
    {
        StreamCipherFactory[] factories = Aes.factories;

        if (factories == null)
        {
            // A single instance of each well-known StreamCipherFactory
            // implementation will be initialized i.e. the attempt to initialize
            // StreamCipherFactory instances will be made once only.
            Aes.factories = factories = createStreamCipherFactories();
        }

        // Benchmark the StreamCiphers provided by the available
        // StreamCipherFactories in order to select the fastest-performing
        // StreamCipherFactory.
        StreamCipherFactory minFactory = benchmark(factories, keySize);

        // The user may have specified a specific StreamCipherFactory class
        // (name) through setFactoryClassName(String), Practically, FACTORY_CLASS_NAME may override
        // minFactory and, consequently, it may appear that the benchmark is
        // unnecessary. Technically though, the specified StreamCipherFactory may
        // malfunction. That is why FACTORY_CLASS_NAME is selected after it has
        // proven itself functional.
        {
            Class<? extends StreamCipherFactory> factoryClass = Aes.factoryClass;

            if (factoryClass != null)
            {
                for (StreamCipherFactory factory : factories)
                {
                    if ((factory != null)
                            && factory.getClass().equals(factoryClass))
                    {
                        minFactory = factory;
                        break;
                    }
                }
            }
        }

        return minFactory;
    }

    /**
     * Gets the simple name of the runtime <tt>Class</tt> of a specific
     * <tt>StreamCipherFactory</tt> to be used for display purposes of brevity
     * and readability.
     *
     * @param factory the <tt>StreamCipherFactory</tt> for which a simple class
     * name is to be returned
     * @return the simple name of the runtime <tt>Class</tt> of the specified
     * <tt>factory</tt> to be used for display purposes of brevity and
     * readability
     */
    private static String getSimpleClassName(StreamCipherFactory factory)
    {
        Class<?> clazz = factory.getClass();
        String className = clazz.getSimpleName();

        if (className == null || className.length() == 0)
            className = clazz.getName();

        String suffix = STREAM_CIPHER_FACTORY_SIMPLE_CLASS_NAME;

        if (className.endsWith(suffix))
        {
            String simpleClassName
                = className.substring(0, className.length() - suffix.length());
            String prefix = Aes.class.getName() + "$";

            if (simpleClassName.startsWith(prefix))
            {
                className = simpleClassName.substring(prefix.length());
            }
            else if (simpleClassName.contains("."))
            {
                Package pkg = Aes.class.getPackage();

                if (pkg != null)
                {
                    prefix = pkg.getName() + ".";
                    if (simpleClassName.startsWith(prefix))
                        className = simpleClassName.substring(prefix.length());
                }
            }
            else
            {
                className = simpleClassName;
            }
        }
        return className;
    }

    /**
     * Implements <tt>StreamCipherFactory</tt> using BouncyCastle.
     *
     * @author Lyubomir Marinov
     */
    public static class BouncyCastleStreamCipherFactory
        implements StreamCipherFactory
    {
        /**
         * {@inheritDoc}
         */
        @Override
        public StreamCipher createStreamCipher(int keySize)
            throws Exception
        {
            return new SICBlockCipher(new AESEngine());
        }
    }

    /**
     * Implements <tt>StreamCipherFactory</tt> using Sun JCE.
     *
     * @author Lyubomir Marinov
     */
    public static class SunJCEStreamCipherFactory
        extends SecurityProviderStreamCipherFactory
    {
        /**
         * Initializes a new <tt>SunJCEStreamCipherFactory</tt> instance.
         */
        public SunJCEStreamCipherFactory()
        {
            super("AES/CTR/NoPadding", "SunJCE", logger);
        }
    }

    /**
     * Implements <tt>StreamCipherFactory</tt> using Sun PKCS#11.
     *
     * @author Lyubomir Marinov
     */
    public static class SunPKCS11StreamCipherFactory
        extends SecurityProviderStreamCipherFactory
    {
        /**
         * The <tt>java.security.Provider</tt> instance (to be) employed for an
         * (optimized) AES implementation.
         */
        private static Provider provider;

        /**
         * The indicator which determines whether {@link #provider} is to be
         * used. If <tt>true</tt>, an attempt will be made to initialize a
         * <tt>java.security.Provider</tt> instance. If the attempt fails,
         * <tt>false</tt> will be assigned in order to not repeatedly attempt
         * the initialization which is known to have failed.
         */
        private static boolean useProvider = true;

        /**
         * Gets the <tt>java.security.Provider</tt> instance (to be) employed
         * for an (optimized) AES implementation.
         *
         * @return the <tt>java.security.Provider</tt> instance (to be) employed
         * for an (optimized) AES implementation
         */
        private static synchronized Provider getProvider()
            throws Exception
        {
            Provider provider = SunPKCS11StreamCipherFactory.provider;

            if ((provider == null) && useProvider)
            {
                try
                {
                    Class<?> clazz
                        = Class.forName("sun.security.pkcs11.SunPKCS11");

                    if (Provider.class.isAssignableFrom(clazz))
                    {
                        Constructor<?> contructor
                            = clazz.getConstructor(String.class);

                        // The SunPKCS11 Config name should be unique in order
                        // to avoid repeated initialization exceptions.
                        String name = null;
                        Package pkg = Aes.class.getPackage();

                        if (pkg != null)
                            name = pkg.getName();
                        if (name == null || name.length() == 0)
                            name = "org.jitsi.srtp";

                        provider
                            = (Provider)
                                contructor.newInstance(
                                        "--name=" + name + "\\n"
                                            + "nssDbMode=noDb\\n"
                                            + "attributes=compatibility");
                    }
                }
                finally
                {
                    if (provider == null)
                        useProvider = false;
                    else
                        SunPKCS11StreamCipherFactory.provider = provider;
                }
            }
            return provider;
        }

        /**
         * Initializes a new <tt>SunPKCS11StreamCipherFactory</tt> instance.
         *
         * @throws Exception if anything goes wrong while initializing a new
         * <tt>SunPKCS11StreamCipherFactory</tt> instance
         */
        public SunPKCS11StreamCipherFactory()
            throws Exception
        {
            super("AES/CTR/NoPadding", getProvider(), logger);
        }
    }
}
