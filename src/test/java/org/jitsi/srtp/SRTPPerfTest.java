package org.jitsi.srtp;

import org.jitsi.utils.ByteArrayBuffer;

import javax.xml.bind.DatatypeConverter;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;

public class SRTPPerfTest {
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

    private void setupPacket(int payloadSize, SRTPPolicy policy)
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

    private SRTPContextFactory factory;
    private SRTPCryptoContext context;

    private void createContext(SRTPPolicy policy)
    {
        factory = new SRTPContextFactory(true, test_key, test_key_salt, policy, policy);
        context = factory.getDefaultContext().deriveContext(0xcafebabe, 0, 0);
        context.deriveSrtpKeys(0);
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
        SRTPPolicy policy =
                new SRTPPolicy(SRTPPolicy.AESCM_ENCRYPTION, 128/8,
                        SRTPPolicy.HMACSHA1_AUTHENTICATION, 160/8,
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

        System.out.printf("Executed %d SRTP enc/auth in %s: %.3f µs/pkt\n",
                num, elapsed.toString(), average.toNanos() / 1000.0);
    }

    private static final int DEFAULT_NUM_TESTS = 100000;
    private static final int DEFAULT_PAYLOAD_SIZE = 1250;

    public static void main(String[] args)
    {
        int numTests = DEFAULT_NUM_TESTS;
        int payloadSize = DEFAULT_PAYLOAD_SIZE;

        if (args.length > 0)
            numTests = Integer.parseInt(args[0]);
        if (args.length > 1)
            payloadSize = Integer.parseInt(args[1]);

        SRTPPerfTest test = new SRTPPerfTest();
        test.doPerfTest(numTests, payloadSize);
    }
}
