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

import java.util.concurrent.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.*;
import org.jitsi.utils.logging2.*;

import javax.crypto.*;

/**
 * Implements a factory for an AES/CTR {@link Cipher}.
 *
 * @author Lyubomir Marinov
 */
public class Aes
{
    /**
     * The {@link Logger} used by the {@link Aes} class to print out debug
     * information.
     */
    private static final Logger logger = new LoggerImpl(Aes.class.getName());

    /**
     * The block size in bytes of the AES algorithm (implemented by the
     * {@link Cipher}s initialized by the {@link Aes} class).
     */
    private static final int BLOCK_SIZE = 16;

    /**
     * The simple name of the {@link CipherFactory} class/interface which
     * is used as a class name suffix by the well-known
     * {@link CipherFactory} implementations.
     */
    private static final String CIPHER_FACTORY_SIMPLE_CLASS_NAME
        = CipherFactory.class.getSimpleName();

    /**
     * The default {@link CipherFactory} which is used as fallback.
     */
    private static final CipherFactory DEFAULT_FACTORY
        = new SunJCECipherFactory();

    /**
     * The {@link CipherFactory} implementations known to the {@link Aes}
     * class among which the fastest is to be elected as {@link #factory}
     * for each transformation.
     */
    private static CipherFactory[] factories;

    /**
     * The {@link CipherFactory} implementation which is (to be) used by
     * the class {@link Aes} to initialize {@link Cipher}s.
     */
    private static final Map<String, CipherFactory> factory = new HashMap<>();

    /**
     * The name of the class to instantiate as a {@link CipherFactory}
     * implementation to be used by the class {@link Aes} to initialize
     * {@link Cipher}s.
     */
    private static String FACTORY_CLASS_NAME = null;

    /**
     * The {@link Class}es of the well-known {@link CipherFactory}
     * implementations.
     */
    private static final Class<?>[] FACTORY_CLASSES
        = {
            OpenSSLCipherFactory.class,
            SunJCECipherFactory.class,
            BouncyCastleCipherFactory.class,
            SunPKCS11CipherFactory.class,
        };

    /**
     * The number of nanoseconds after which the benchmark which elected
     * {@link #factory} is to be considered expired.
     */
    public static final long FACTORY_TIMEOUT = TimeUnit.SECONDS.toNanos(60);

    /**
     * The class to instantiate as a {@link CipherFactory} implementation
     * to be used to initialized {@link Cipher}s.
     *
     * @see #FACTORY_CLASS_NAME
     */
    private static Class<? extends CipherFactory> factoryClass;

    /**
     * The time in nanoseconds at which {@link #factories} were benchmarked and
     * {@link #factory} was elected for a given transformation.
     */
    private static final Map<String, Long> factoryTimestamps = new HashMap<>();

    /**
     * The size of the data to be used for AES cipher benchmarks.
     * This is chosen to be comparable in size to an SRTP packet.
     */
    private static final int BENCHMARK_SIZE = 1500;

    /**
     * The number of times to pre-execute the benchmark before executing it for real,
     * to give the JVM time to run JITs and the like.
     *
     * 10000 is the threshold to trigger "C2" compilation in the OpenJDK JVM.
     */
    private static final int NUM_WARMUPS = 11000;

    /**
     * The input buffer to be used for the benchmarking of {@link #factories}.
     * It consists of blocks and its length specifies the number of blocks to
     * process for the purposes of the benchmark.
     */ 
    private static final byte[] in = new byte[BENCHMARK_SIZE];

    /**
     * The output buffer to be used for the benchmarking of {@link #factories}.
     */
    private static final byte[] out = new byte[BENCHMARK_SIZE + BLOCK_SIZE];

    /**
     * The random number generator which generates keys and inputs for the
     * benchmarking of the {@link CipherFactory} implementations.
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

    private static abstract class BenchmarkOperation
    {
        abstract void run(Cipher cipher) throws Exception;

        static BenchmarkOperation getBenchmark(String transformation, int keySize)
            throws Exception
        {
            if (transformation.contains("/CTR/"))
            {
                return new CtrBenchmark(keySize);
            }
            if (transformation.contains("/GCM/"))
            {
                return new GcmBenchmark(keySize);
            }
            else if (transformation.contains("/ECB/"))
            {
                return new EcbBenchmark(keySize);
            }
            else {
                throw new NoSuchAlgorithmException("Unsupported transformation " + transformation + " for benchmark");
            }
        }
    }

    private static class CtrBenchmark extends BenchmarkOperation
    {
        private final Key keySpec;
        private final IvParameterSpec ivSpec;

        public CtrBenchmark(int keySize)
        {
            byte[] key = new byte[keySize];

            byte[] iv = new byte[BLOCK_SIZE];
            Random random = Aes.random;
            random.nextBytes(key);
            random.nextBytes(iv);
            random.nextBytes(in);

            keySpec = new SecretKeySpec(key, "AES");
            ivSpec = new IvParameterSpec(iv);
        }

        public void run(Cipher cipher) throws Exception
        {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            cipher.update(in, 0, in.length, out, 0);
        }
    }

    private static class GcmBenchmark extends BenchmarkOperation
    {
        private static final int AAD_SIZE = 20; /* RTP header plus extensions */

        private final Key keySpec;
        private final byte[] aad = new byte[AAD_SIZE];
        private final byte[] iv = new byte[12];

        public GcmBenchmark(int keySize)
        {
            byte[] key = new byte[keySize];

            Random random = Aes.random;
            random.nextBytes(key);
            random.nextBytes(iv);
            random.nextBytes(aad);
            random.nextBytes(in);

            keySpec = new SecretKeySpec(key, "AES");
        }

        public void run(Cipher cipher) throws Exception
        {
            /* Many GCM providers don't let us use two identical IVs in a row
               with the same key. */
            iv[0] ^= 1;
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            cipher.updateAAD(aad, 0, aad.length);
            cipher.doFinal(in, 0, in.length, out, 0);
        }
    }


    private static class EcbBenchmark extends BenchmarkOperation
    {
        private final Key keySpec;

        public EcbBenchmark(int keySize)
        {
            byte[] key = new byte[keySize];

            Random random = Aes.random;
            random.nextBytes(key);
            random.nextBytes(in);

            keySpec = new SecretKeySpec(key, "AES");
        }

        public void run(Cipher cipher) throws Exception
        {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            cipher.update(in, 0, in.length, out, 0);
        }
    }


    /**
     * Benchmarks a specific array/list of {@link CipherFactory} instances
     * and returns the fastest-performing element.
     *
     * @param factories the {@link CipherFactory} instances to benchmark
     * @param keySize AES key size (16, 24, 32 bytes)
     * @param transformation String describing transformation to be created.
     * @return the fastest-performing {@link CipherFactory} among the
     * specified {@code factories}
     */
    private static CipherFactory benchmark(
            CipherFactory[] factories,
            int keySize,
            String transformation,
            boolean warmup
        )
    {
        byte[] out = Aes.out;
        long minTime = Long.MAX_VALUE;
        CipherFactory minFactory = null;

        StringBuilder log = new StringBuilder();

        for (int f = 0; f < factories.length; ++f)
        {
            CipherFactory factory = factories[f];

            if (factory == null)
                continue;

            try
            {
                Cipher cipher = factory.createCipher(transformation);

                if (cipher == null)
                {
                    // The CipherFactory failed to initialize a new
                    // StreamCipher instance. We will not use it again because
                    // the failure may persist.
                    factories[f] = null;
                }
                else
                {
                    BenchmarkOperation benchmark = BenchmarkOperation.getBenchmark(transformation, keySize);
                    if (warmup)
                    {
                        // Let the JVM "warm up" (do JIT compilation and the like)
                        for (int i = 0; i < NUM_WARMUPS; i++)
                        {
                            benchmark.run(cipher);
                        }
                    }

                    long startTime = System.nanoTime();
                    benchmark.run(cipher);

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
                        + log
                        + " for " + transformation
            );
        }

        return minFactory;
    }

    /**
     * Initializes a new {@link Cipher} instance which implements Advanced
     * Encryption Standard (AES) in some mode.
     * @param transformation String describing transformation to be created. Must
     *                       be an AES variant.
     *
     * @return a new {@link Cipher} instance which implements Advanced
     * Encryption Standard (AES) in CTR mode
     */
    public static Cipher createCipher(String transformation)
    {
        CipherFactory factory;

        synchronized (Aes.class)
        {
            long now = System.nanoTime();

            factory = Aes.factory.getOrDefault(transformation, null);
            long factoryTimestamp = Aes.factoryTimestamps.getOrDefault(transformation, Long.MIN_VALUE);
            boolean warmup = true;
            if ((factory != null) && (now > factoryTimestamp + FACTORY_TIMEOUT))
            {
                factory = null;
                warmup = false;
            }
            if (factory == null)
            {
                try
                {
                    factory = getCipherFactory(transformation, warmup);
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
                        factory = Aes.factory.getOrDefault(transformation, null);
                        if (factory == null)
                            factory = DEFAULT_FACTORY;
                    }

                    Aes.factoryTimestamps.put(transformation, now);
                    CipherFactory oldFactory = Aes.factory.put(transformation, factory);
                    if (oldFactory != factory)
                    {
                        // Simplify the name of the CipherFactory class to
                        // be employed for the purposes of brevity and ease.
                        logger.info("Will employ AES implemented by "
                                    + getSimpleClassName(factory) +
                                    " for " + transformation + ".");
                    }
                }
            }
        }

        try
        {
            return factory.createCipher(transformation);
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
        // without CipherFactory at the end for the purposes of
        // brevity and ease.
        if (Character.isUpperCase(factoryClassName.charAt(0))
            && !factoryClassName.contains(".")
            && !factoryClassName.endsWith(
            CIPHER_FACTORY_SIMPLE_CLASS_NAME))
        {
            factoryClassName
                = Aes.class.getName() + "$" + factoryClassName
                + CIPHER_FACTORY_SIMPLE_CLASS_NAME;
        }
        return factoryClassName;
    }

    /**
     * Initializes the {@link CipherFactory} instances to be benchmarked
     * by the class {@link Aes} and among which the fastest-performing one is
     * to be selected.
     * 
     * @return the {@link CipherFactory} instances to be benchmarked by
     * the class {@link Aes} and among which the fastest-performing one is to
     * be selected
     */
    @SuppressWarnings("unchecked")
    private static CipherFactory[] createCipherFactories()
    {
        // The user may have specified a specific CipherFactory class
        // (name) through setFactoryClassName(String). Practically, the specified FACTORY_CLASS_NAME
        // will override all other FACTORY_CLASSES and, consequently, it does
        // not seem necessary to try FACTORY_CLASSES at all. Technically though,
        // the specified CipherFactory may malfunction. That is why all
        // FACTORY_CLASSES are tried as well and FACTORY_CLASS_NAME is selected
        // later on after it has proven itself functional.
        Class<? extends CipherFactory> factoryClass = Aes.factoryClass;
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
                            && CipherFactory.class.isAssignableFrom(clazz))
                    {
                        Aes.factoryClass
                            = factoryClass
                                = (Class<? extends CipherFactory>)
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
    
                        if (CipherFactory.class.isAssignableFrom(clazz))
                        {
                            Aes.factoryClass
                                = factoryClass
                                    = (Class<? extends CipherFactory>)
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

        return createCipherFactories(factoryClasses);
    }

    /**
     * Initializes {@link CipherFactory} instances of specific
     * {@link Class}es.
     *
     * @param classes the runtime {@link Class}es to instantiate
     * @return the {@link CipherFactory} instances initialized by the
     * specified {@code classes}
     */
    private static CipherFactory[] createCipherFactories(
            Class<?>[] classes)
    {
        CipherFactory[] factories = new CipherFactory[classes.length];
        int i = 0;

        for (Class<?> clazz : classes)
        {
            try
            {
                if (CipherFactory.class.isAssignableFrom(clazz))
                {
                    CipherFactory factory;

                    if (DEFAULT_FACTORY.getClass().equals(clazz))
                        factory = DEFAULT_FACTORY;
                    else
                        factory = (CipherFactory) clazz.getConstructor().newInstance();

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
     * Gets a {@link CipherFactory} instance to be used by the
     * {@link Aes} class to initialize {@link Cipher}s.
     *
     * <p>
     * Benchmarks the well-known {@link CipherFactory} implementations and
     * returns the fastest one. 
     * </p>
     * @param transformation The transformation for which to get a factory.
     *
     * @return a {@link CipherFactory} instance to be used by the
     * {@link Aes} class to initialize {@link Cipher}s
     */
    private static CipherFactory getCipherFactory(String transformation, boolean warmup)
    {
        CipherFactory[] factories = Aes.factories;
        /* TODO: figure out keysize for transformation? */
        final int keySize = 16;

        if (factories == null)
        {
            // A single instance of each well-known CipherFactory
            // implementation will be initialized i.e. the attempt to initialize
            // CipherFactory instances will be made once only.
            Aes.factories = factories = createCipherFactories();
        }

        // Benchmark the StreamCiphers provided by the available
        // StreamCipherFactories in order to select the fastest-performing
        // CipherFactory.
        CipherFactory minFactory = benchmark(factories, keySize, transformation, warmup);

        // The user may have specified a specific CipherFactory class
        // (name) through setFactoryClassName(String), Practically, FACTORY_CLASS_NAME may override
        // minFactory and, consequently, it may appear that the benchmark is
        // unnecessary. Technically though, the specified CipherFactory may
        // malfunction. That is why FACTORY_CLASS_NAME is selected after it has
        // proven itself functional.
        {
            Class<? extends CipherFactory> factoryClass = Aes.factoryClass;

            if (factoryClass != null)
            {
                for (CipherFactory factory : factories)
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
     * Gets the simple name of the runtime {@link Class} of a specific
     * {@link CipherFactory} to be used for display purposes of brevity
     * and readability.
     *
     * @param factory the {@link CipherFactory} for which a simple class
     * name is to be returned
     * @return the simple name of the runtime {@link Class} of the specified
     * {@code factory} to be used for display purposes of brevity and
     * readability
     */
    private static String getSimpleClassName(CipherFactory factory)
    {
        Class<?> clazz = factory.getClass();
        String className = clazz.getSimpleName();

        if (className == null || className.length() == 0)
            className = clazz.getName();

        String suffix = CIPHER_FACTORY_SIMPLE_CLASS_NAME;

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
     * Implements {@link CipherFactory} using Jitsi SRTP's OpenSSL.
     */
    public static class OpenSSLCipherFactory
        extends CipherFactory
    {
        public OpenSSLCipherFactory()
        {
            super(new JitsiOpenSslProvider());
        }

        private boolean trySuperApi = true;
        private Constructor<Cipher> cipherConstructor;
        private Field cipherProviderField;

        private synchronized void getMethods()
            throws NoSuchAlgorithmException
        {
            if (cipherConstructor == null || cipherProviderField == null)
            {
                try
                {
                    cipherConstructor = Cipher.class
                        .getDeclaredConstructor(CipherSpi.class, String.class);
                    cipherConstructor.setAccessible(true);
                    cipherProviderField =
                        Cipher.class.getDeclaredField("provider");
                    cipherProviderField.setAccessible(true);
                }
                catch (NoSuchMethodException | NoSuchFieldException e)
                {
                    cipherConstructor = null;
                    cipherProviderField = null;
                    throw new NoSuchAlgorithmException(
                        "Cannot instantiate OpenSSL Cipher");
                }
            }
        }

        @Override
        public Cipher createCipher(String transformation) throws Exception
        {
            if (trySuperApi)
            {
                try
                {
                    return super.createCipher(transformation);
                }
                catch (SecurityException e)
                {
                    trySuperApi = false;
                }
            }
            /* Work around the fact that we can't install our own security
             * providers on Oracle JVMs.
             *
             * Note this will trigger a illegal reflective access warning on JVM 11+.
             */
            getMethods();

            OpenSslAesCipherSpi spi = new OpenSslAesCipherSpi();
            String[] parts = transformation.split("/");
            spi.engineSetMode(parts[1]);
            spi.engineSetPadding(parts[2]);

            Cipher cipher = cipherConstructor.newInstance(spi, transformation);
            cipherProviderField.set(cipher, provider);

            return cipher;
        }
    }

    /**
     * Implements {@link CipherFactory} using BouncyCastle.
     *
     * @author Lyubomir Marinov
     */
    public static class BouncyCastleCipherFactory
        extends CipherFactory
    {
        public BouncyCastleCipherFactory()
        {
            super(new BouncyCastleProvider());
        }
    }

    /**
     * Implements {@link CipherFactory} using Sun JCE.
     *
     * @author Lyubomir Marinov
     */
    public static class SunJCECipherFactory
        extends CipherFactory
    {
        public SunJCECipherFactory()
        {
            super("SunJCE");
        }
    }

    /**
     * Implements {@link CipherFactory} using Sun PKCS#11.
     *
     * @author Lyubomir Marinov
     */
    public static class SunPKCS11CipherFactory
        extends CipherFactory
    {
        /**
         * The {@link Provider} instance (to be) employed for an (optimized) AES
         * implementation.
         */
        private static Provider provider;

        /**
         * The indicator which determines whether {@link #provider} is to be
         * used. If {@code true}, an attempt will be made to initialize a {@link
         * Provider} instance. If the attempt fails, {@code false} will be
         * assigned in order to not repeatedly attempt the initialization which
         * is known to have failed.
         */
        private static boolean useProvider = true;

        /**
         * Gets the {@code java.security.Provider} instance (to be) employed
         * for an (optimized) AES implementation.
         *
         * @return the {@code java.security.Provider} instance (to be) employed
         * for an (optimized) AES implementation
         */
        public static synchronized Provider getProvider()
            throws Exception
        {
            Provider provider = SunPKCS11CipherFactory.provider;

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
                        SunPKCS11CipherFactory.provider = provider;
                }
            }
            return provider;
        }

        /**
         * Initializes a new instance of this class.
         *
         * @throws Exception if anything goes wrong while initializing a new
         *                   instance
         */
        public SunPKCS11CipherFactory()
            throws Exception
        {
            super(getProvider());
        }
    }
}
