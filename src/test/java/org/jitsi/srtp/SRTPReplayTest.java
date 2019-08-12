package org.jitsi.srtp;

import static org.junit.Assert.*;

import org.jitsi.utils.ByteArrayBuffer;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;

public class SRTPReplayTest {
    private static final byte[] rtpPacketData =
            DatatypeConverter.parseHexBinary("800f1234decafbad" +
                    "cafebabeabababab" +
                    "abababababababab" +
                    "abababab");

    private static final ByteArrayBuffer rtpPacket = new ByteArrayBufferImpl(rtpPacketData, 0, rtpPacketData.length);

    private void setRtpPacketSequence(int seq) {
        if (seq > 0xffff || seq < 0)
            throw new IllegalArgumentException("Bad sequence number");
        rtpPacketData[2] = (byte) (seq >> 8);
        rtpPacketData[3] = (byte) seq;
    }

    /* Expected replay window size, to match value defined in the code being tested. */
    private static final long REPLAY_WINDOW_SIZE = 64;

    private static final long NUM_SEQ_TESTS = 100000;

    @Test
    public void TestRTPReplay()
    {
        SRTPPolicy nullPolicy = new SRTPPolicy(SRTPPolicy.NULL_ENCRYPTION, 0, SRTPPolicy.NULL_AUTHENTICATION, 0, 0, 0);

        SRTPCryptoContext receiver = new SRTPCryptoContext(false, 0xcafebabe, 0, 0, null, null, nullPolicy);

        int latestSeq = -1;
        UtSim utSim = new UtSim();

        for (int i = 0; i < NUM_SEQ_TESTS; i++) {
            int seq = utSim.getNextIndex();
            if (latestSeq < seq) latestSeq = seq;
            setRtpPacketSequence(seq & 0xffff);

            boolean accepted = receiver.reverseTransformPacket(rtpPacket, false);
            int delta = latestSeq - seq;
            if (delta >= REPLAY_WINDOW_SIZE)
                assertFalse("packet outside RTP replay window accepted", accepted);
            else
                assertTrue("packet inside RTP replay window rejected", accepted);

            /* Should always reject packet when it's replayed. */
            assertFalse("replayed RTP packet accepted",
                    receiver.reverseTransformPacket(rtpPacket, false));
        }
    }


    private static final byte[] srtcpPacketData =
            DatatypeConverter.parseHexBinary("81c8000bcafebabe" +
                    "abababababababab" +
                    "abababababababab" +
                    "00000000");


    private static final ByteArrayBuffer rtcpPacket = new ByteArrayBufferImpl(srtcpPacketData, 0, srtcpPacketData.length);

    private void setRtcpPacketSequence(int seq, boolean enc) {
        if (seq < 0)
            throw new IllegalArgumentException("Bad sequence number");
        int pos = srtcpPacketData.length - 4;
        srtcpPacketData[pos]   = (byte) ((seq >> 24) | (enc ? 0x80 : 0));
        srtcpPacketData[pos+1] = (byte) (seq >> 16);
        srtcpPacketData[pos+2] = (byte) (seq >> 8);
        srtcpPacketData[pos+3] = (byte) seq;
    }

    @Test
    public void TestRTCPReplay()
    {
        SRTPPolicy nullPolicy = new SRTPPolicy(SRTPPolicy.NULL_ENCRYPTION, 0, SRTPPolicy.NULL_AUTHENTICATION, 0, 0, 0);

        SRTCPCryptoContext receiver = new SRTCPCryptoContext(0xcafebabe, null, null, nullPolicy);

        int latestSeq = -1;
        UtSim utSim = new UtSim();

        for (int i = 0; i < NUM_SEQ_TESTS; i++) {
            int seq = utSim.getNextIndex();
            if (latestSeq < seq) latestSeq = seq;
            setRtcpPacketSequence(seq, true);

            boolean accepted = receiver.reverseTransformPacket(rtcpPacket);
            int delta = latestSeq - seq;
            if (delta >= REPLAY_WINDOW_SIZE)
                assertFalse("packet outside RTCP replay window accepted", accepted);
            else
                assertTrue("packet inside RTCP replay window rejected", accepted);

            /* Should always reject packet when it's replayed. */
            assertFalse("replayed RTCP packet accepted",
                    receiver.reverseTransformPacket(rtcpPacket));
        }
    }
}
