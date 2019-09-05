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

import gnu.getopt.*;
import org.jitsi.srtp.crypto.*;
import org.jitsi.utils.*;
import org.jitsi.utils.logging2.*;
import org.junit.jupiter.api.*;

import javax.xml.bind.*;
import java.time.*;
import java.util.*;

public class SrtpPerfTest {
    private static final byte[] test_key =
            DatatypeConverter.parseHexBinary("e1f97a0d3e018be0d64fa32c06de4139");
    private static final byte[] test_key_salt =
            DatatypeConverter.parseHexBinary("0ec675ad498afeebb6960b3aabe6");

    private static final byte[] rtp_header =
            DatatypeConverter.parseHexBinary("800f1234decafbadcafebabe");

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

    private SrtpContextFactory factory;
    private SrtpCryptoContext context;

    private void createContext(SrtpPolicy policy)
    {
        Logger logger = new LoggerImpl(getClass().getName());
        factory = new SrtpContextFactory(true, test_key, test_key_salt, policy, policy, logger);
        context = factory.deriveContext(0xcafebabe, 0);
    }

    public void doEncrypt(int num, int payloadSize)
    {
        for (int i = 0; i < num; i++)
        {
            resetPacket(payloadSize);
            context.transformPacket(packet);
        }
    }

    public void doPerfTest(int num, int payloadSize)
    {
        SrtpPolicy policy =
                new SrtpPolicy(SrtpPolicy.AESCM_ENCRYPTION, 128/8,
                        SrtpPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                        80/8, 112/8 );

        createContext(policy);
        setupPacket(payloadSize, policy);

        /* Warm up JVM */
        doEncrypt(10, payloadSize);

        Clock clock = Clock.systemUTC();
        Instant startTime = clock.instant();

        doEncrypt(num, payloadSize);

        Instant endTime = clock.instant();

        Duration elapsed = Duration.between(startTime, endTime);
        Duration average = elapsed.dividedBy(num);

        System.out.printf("Executed %d SRTP enc/auth (%d byte payload) in %s: %.3f µs/pkt\n",
                num, payloadSize, elapsed.toString(), average.toNanos() / 1000.0);
    }

    private static final int DEFAULT_NUM_TESTS = 100000;
    private static final int DEFAULT_PAYLOAD_SIZE = 1250;

    @Test
    public void srtpPerf()
    {
        doPerfTest(DEFAULT_NUM_TESTS, DEFAULT_PAYLOAD_SIZE);
    }

    private static final String progName = "SrtpPerfTest";

    private static void usage()
    {
        System.err.println ("Usage: " + progName + " [-f AES factory] [-p payloadSize] [numTests]");
        System.exit(2);
    }

    public static void main(String[] args)
    {
        int numTests = DEFAULT_NUM_TESTS;
        int payloadSize = DEFAULT_PAYLOAD_SIZE;
        String factoryClassName = null;

        Getopt g = new Getopt(progName, args, "f:p:");

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
                        System.err.println("Invalid payload size " + arg);
                        usage();
                    }
                    if (payloadSize < 0) {
                        System.err.println("Invalid payload size " + arg);
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
                System.err.println("Invalid number of tests " + args[optind]);
                usage();
            }
            if (numTests < 0)
            {
                System.err.println("Invalid number of tests " + args[optind]);
                usage();
            }
        }

        SrtpPerfTest test = new SrtpPerfTest();
        test.doPerfTest(numTests, payloadSize);
    }
}
