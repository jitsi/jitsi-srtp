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

import static org.junit.jupiter.api.Assertions.*;

import org.jitsi.utils.*;
import org.jitsi.utils.logging2.*;
import org.junit.jupiter.api.*;

import javax.xml.bind.*;

public class SrtpReplayTest {
    private static final byte[] rtpPacketData =
            DatatypeConverter.parseHexBinary("800f1234decafbad" +
                    "cafebabeabababab" +
                    "abababababababab" +
                    "abababab");

    private static final ByteArrayBuffer rtpPacket = new ByteArrayBufferImpl(rtpPacketData, 0, rtpPacketData.length);

    private void setRtpPacketSequence(int seq)
    {
        if (seq > 0xffff || seq < 0)
        {
            throw new IllegalArgumentException("Bad sequence number");
        }
        rtpPacketData[2] = (byte) (seq >> 8);
        rtpPacketData[3] = (byte) seq;
    }

    /* Expected replay window size, to match value defined in the code being tested. */
    private static final long REPLAY_WINDOW_SIZE = 64;

    private static final long NUM_SEQ_TESTS = 100000;

    @Test
    public void TestRTPReplay()
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy nullPolicy = new SrtpPolicy(SrtpPolicy.NULL_ENCRYPTION, 0, SrtpPolicy.NULL_AUTHENTICATION, 0, 0, 0);

        SrtpCryptoContext receiver = new SrtpCryptoContext(false, 0xcafebabe, 0, null, null, nullPolicy, logger);

        int latestSeq = -1;
        UtSim utSim = new UtSim();

        for (int i = 0; i < NUM_SEQ_TESTS; i++)
        {
            int seq = utSim.getNextIndex();
            if (latestSeq < seq) latestSeq = seq;
            setRtpPacketSequence(seq & 0xffff);

            SrtpErrorStatus status = receiver.reverseTransformPacket(rtpPacket, false);
            int delta = latestSeq - seq;
            if (delta >= REPLAY_WINDOW_SIZE)
            {
                assertEquals(status, SrtpErrorStatus.REPLAY_OLD,
                    "packet outside RTP replay window accepted");
            }
            else
            {
                assertEquals(status, SrtpErrorStatus.OK,
                    "packet inside RTP replay window rejected");
            }

            /* Should always reject packet when it's replayed. */
            /* Status might be either REPLAY_OLD or REPLAY_FAIL. */
            assertNotEquals(receiver.reverseTransformPacket(rtpPacket, false),
                    SrtpErrorStatus.OK,
                    "replayed RTP packet accepted");
        }
    }


    private static final byte[] srtcpPacketData =
            DatatypeConverter.parseHexBinary("81c8000bcafebabe" +
                    "abababababababab" +
                    "abababababababab" +
                    "00000000");


    private static final ByteArrayBuffer rtcpPacket = new ByteArrayBufferImpl(srtcpPacketData, 0, srtcpPacketData.length);

    private void setRtcpPacketSequence(int seq, boolean enc)
    {
        if (seq < 0)
        {
            throw new IllegalArgumentException("Bad sequence number");
        }
        int pos = srtcpPacketData.length - 4;
        srtcpPacketData[pos]   = (byte) ((seq >> 24) | (enc ? 0x80 : 0));
        srtcpPacketData[pos+1] = (byte) (seq >> 16);
        srtcpPacketData[pos+2] = (byte) (seq >> 8);
        srtcpPacketData[pos+3] = (byte) seq;
    }

    @Test
    public void TestRTCPReplay()
    {
        Logger logger = new LoggerImpl(getClass().getName());

        SrtpPolicy nullPolicy = new SrtpPolicy(SrtpPolicy.NULL_ENCRYPTION, 0, SrtpPolicy.NULL_AUTHENTICATION, 0, 0, 0);

        SrtcpCryptoContext receiver = new SrtcpCryptoContext(0xcafebabe, null, null, nullPolicy, logger);

        int latestSeq = -1;
        UtSim utSim = new UtSim();

        for (int i = 0; i < NUM_SEQ_TESTS; i++)
        {
            int seq = utSim.getNextIndex();
            if (latestSeq < seq) latestSeq = seq;
            setRtcpPacketSequence(seq, true);

            SrtpErrorStatus status = receiver.reverseTransformPacket(rtcpPacket);
            int delta = latestSeq - seq;
            if (delta >= REPLAY_WINDOW_SIZE)
            {
                assertEquals(status, SrtpErrorStatus.REPLAY_OLD,
                    "packet outside RTCP replay window accepted");
            }
            else
            {
                assertEquals(status, SrtpErrorStatus.OK,
                    "packet inside RTCP replay window rejected");
            }

            /* Should always reject packet when it's replayed. */
            /* Status might be either REPLAY_OLD or REPLAY_FAIL. */
            assertNotEquals( receiver.reverseTransformPacket(rtcpPacket),
                SrtpErrorStatus.OK,
                "replayed RTCP packet accepted");
        }
    }
}
