/*
 * Copyright @ 2019 - present 8x8, Inc
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
package org.jitsi.srtp;

import static jakarta.xml.bind.DatatypeConverter.parseHexBinary;

import gnu.getopt.*;
import java.security.*;
import org.jitsi.srtp.crypto.*;
import org.jitsi.utils.*;
import org.jitsi.utils.logging2.*;
import org.junit.jupiter.api.*;

import java.time.*;
import java.util.*;

public class SrtpPerfTest {
    private static final byte[] test_key =
            parseHexBinary("e1f97a0d3e018be0d64fa32c06de4139");
    private static final byte[] test_key_salt =
            parseHexBinary("0ec675ad498afeebb6960b3aabe6");

    private static final byte[] rtp_header =
            parseHexBinary("800f1234decafbadcafebabe");

    private ByteArrayBuffer packet = null;
    private int seq = 0x1234;

    private void resetPacket(int payloadSize)
    {
        Arrays.fill(packet.getBuffer(),
                packet.getOffset() + rtp_header.length,
                packet.getOffset() + rtp_header.length + payloadSize,
                (byte) 0xab);

        seq++; seq %= 0x10000;

        int s = packet.getOffset() + 2;
        packet.getBuffer()[s]   = (byte) (seq >> 8);
        packet.getBuffer()[s+1] = (byte) seq;

        packet.setLength(rtp_header.length + payloadSize);
    }

    private void setupPacket(int payloadSize, SrtpPolicy policy)
    {
        int srtpPacketSize = rtp_header.length + payloadSize + policy.getAuthTagLength();
        if (packet == null || packet.getBuffer().length < srtpPacketSize)
        {
            packet = new ByteArrayBufferImpl(srtpPacketSize);
        }
        packet.setLength(0);
        packet.append(rtp_header, rtp_header.length);
        packet.grow(payloadSize);
    }

    private byte[] encryptedPacket = null;
    private int encryptedPacketLength = 0;

    private void setupEncryptedPacket(int payloadSize, SrtpPolicy policy)
        throws GeneralSecurityException
    {
        setupPacket(payloadSize, policy);
        resetPacket(payloadSize);
        createContext(policy, true);
        doEncrypt(1, payloadSize);
        encryptedPacket = packet.getBuffer().clone();
        encryptedPacketLength = packet.getLength();
    }

    private void resetEncryptedPacket()
    {
        if (packet == null || packet.getBuffer().length < encryptedPacket.length)
        {
            packet = new ByteArrayBufferImpl(encryptedPacket.length);
        }

        System.arraycopy(encryptedPacket, 0, packet.getBuffer(), 0, encryptedPacket.length);
        packet.setLength(encryptedPacketLength);
    }

    private SrtpContextFactory factory;
    private SrtpCryptoContext context;

    private void createContext(SrtpPolicy policy, boolean sender)
        throws GeneralSecurityException
    {
        Logger logger = new LoggerImpl(getClass().getName());
        factory = new SrtpContextFactory(sender,
            Arrays.copyOf(test_key, policy.getEncKeyLength()),
            Arrays.copyOf(test_key_salt, policy.getSaltKeyLength()),
            policy, policy, logger);
        context = factory.deriveContext(0xcafebabe, 0);
    }

    public void doEncrypt(int num, int payloadSize)
        throws GeneralSecurityException
    {
        for (int i = 0; i < num; i++)
        {
            resetPacket(payloadSize);
            SrtpErrorStatus status = context.transformPacket(packet);
            if (status != SrtpErrorStatus.OK) {
                throw new GeneralSecurityException(status.desc);
            }
        }
    }

    public void doDecrypt(int num, int payloadSize, boolean skipDecryption)
        throws GeneralSecurityException
    {
        for (int i = 0; i < num; i++)
        {
            resetEncryptedPacket();
            SrtpErrorStatus status = context.reverseTransformPacket(packet, skipDecryption);
            if (status != SrtpErrorStatus.OK) {
                throw new GeneralSecurityException(status.desc);
            }
        }
    }

    public void doEncPerfTest(SrtpPolicy policy, String desc, int num, int payloadSize, int numWarmups)
        throws GeneralSecurityException
    {
        setupPacket(payloadSize, policy);
        createContext(policy, true);

        /* Warm up JVM */
        doEncrypt(numWarmups, payloadSize);

        long startTime = System.nanoTime();

        doEncrypt(num, payloadSize);

        long endTime = System.nanoTime();

        long elapsed = endTime - startTime;
        long average = elapsed / num;

        System.out.printf("Executed %d SRTP %s encrypt (%d byte payload) in %s: %.3f µs/pkt\n",
                num, desc, payloadSize, Duration.ofNanos(elapsed).toString(), average / 1000.0);
    }

    public void doDecPerfTest(SrtpPolicy policy, String desc, int num, int payloadSize, int numWarmups,
        boolean skipDecryption)
        throws GeneralSecurityException
    {
        setupEncryptedPacket(payloadSize, policy);
        policy.setReceiveReplayEnabled(false);
        createContext(policy, false);

        /* Warm up JVM */
        doDecrypt(numWarmups, payloadSize, skipDecryption);

        long startTime = System.nanoTime();

        doDecrypt(num, payloadSize, skipDecryption);

        long endTime = System.nanoTime();

        long elapsed = endTime - startTime;
        long average = elapsed / num;

        System.out.printf("Executed %d SRTP %s decrypt%s (%d byte payload) in %s: %.3f µs/pkt\n",
            num, desc, skipDecryption ?" auth only" : "", payloadSize,
            Duration.ofNanos(elapsed).toString(), average / 1000.0);
    }

    public void doPerfTest(SrtpPolicy policy, String desc, int num, int payloadSize, int numWarmups)
        throws GeneralSecurityException
    {
        doEncPerfTest(policy, desc, num, payloadSize, numWarmups);
        doDecPerfTest(policy, desc, num, payloadSize, numWarmups, false);
        doDecPerfTest(policy, desc, num, payloadSize, numWarmups, true);
    }

    public void doCtrPerfTest(int num, int payloadSize, int numWarmups)
        throws GeneralSecurityException
    {
        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                80/8, 112/8 );

        doPerfTest(policy, "CTR/HMAC", num, payloadSize, numWarmups);
    }

    public void doGcmPerfTest(int num, int payloadSize, int numWarmups)
        throws GeneralSecurityException
    {
        SrtpPolicy policy =
            new SrtpPolicy(SrtpPolicy.AESGCM_ENCRYPTION, 128/8,
                SrtpPolicy.NULL_AUTHENTICATION, 0,
                128/8, 96/8 );

        doPerfTest(policy, "GCM", num, payloadSize, numWarmups);
    }

    private static final int DEFAULT_NUM_TESTS = 100000;
    private static final int DEFAULT_PAYLOAD_SIZE = 1250;
    /* 10000 is the threshold for full (C2) JIT optimization. */
    private static final int DEFAULT_NUM_WARMUPS = 20000;

    @Test
    public void srtpPerf()
        throws GeneralSecurityException
    {
        doCtrPerfTest(DEFAULT_NUM_TESTS, DEFAULT_PAYLOAD_SIZE, DEFAULT_NUM_WARMUPS);
    }

    @Test
    public void srtpPerfGcm()
        throws GeneralSecurityException
    {
        doGcmPerfTest(DEFAULT_NUM_TESTS, DEFAULT_PAYLOAD_SIZE, DEFAULT_NUM_WARMUPS);
    }

    private static final String progName = "SrtpPerfTest";

    private static void usage()
    {
        System.err.println ("Usage: " + progName + " [-f AES factory] [-p payloadSize] [numTests]");
        System.exit(2);
    }

    public static void main(String[] args)
        throws GeneralSecurityException
    {
        int numTests = DEFAULT_NUM_TESTS;
        int payloadSize = DEFAULT_PAYLOAD_SIZE;
        int numWarmups = DEFAULT_NUM_WARMUPS;
        String factoryClassName = null;

        Getopt g = new Getopt(progName, args, "f:p:w:");

        int c;
        String arg;
        while ((c = g.getopt()) != -1)
        {
            switch(c)
            {
                case 'f':
                    arg = g.getOptarg();
                    Aes.setFactoryClassName(arg);
                    break;
                case 'p':
                    arg = g.getOptarg();
                    try {
                        payloadSize = Integer.parseInt(arg);
                    }
                    catch (NumberFormatException e) {
                        System.err.println("Invalid payload size " + arg + ": " + e.getMessage());
                        usage();
                    }
                    if (payloadSize < 0) {
                        System.err.println("Invalid payload size " + arg);
                        usage();
                    }
                    break;
                case 'w':
                    arg = g.getOptarg();
                    try {
                        numWarmups = Integer.parseInt(arg);
                    }
                    catch (NumberFormatException e) {
                        System.err.println("Invalid number of warmups " + arg + ": " + e.getMessage());
                        usage();
                    }
                    if (numWarmups < 0) {
                        System.err.println("Invalid number of warmups " + arg);
                        usage();
                    }
                    break;
                case '?':
                    // getopt() already printed an error
                    usage();
                    break;
                default:
                    /* Shouldn't happen */
                    assert(false);
                    /* In case asserts are off */
                    usage();
                    break;
            }
        }

        int optind = g.getOptind();

        if (g.getOptind() < args.length) {
            try
            {
                numTests = Integer.parseInt(args[optind]);
            }
            catch (NumberFormatException e)
            {
                System.err.println("Invalid number of tests " + args[optind]+ ": " + e.getMessage());
                usage();
            }
            if (numTests < 0)
            {
                System.err.println("Invalid number of tests " + args[optind]);
                usage();
            }
        }

        SrtpPerfTest test = new SrtpPerfTest();
        test.doCtrPerfTest(numTests, payloadSize, numWarmups);
        test.doGcmPerfTest(numTests, payloadSize, numWarmups);
    }
}
