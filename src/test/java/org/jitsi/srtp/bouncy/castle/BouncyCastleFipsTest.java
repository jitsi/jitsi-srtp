package org.jitsi.srtp.bouncy.castle;


import org.jitsi.service.neomedia.RawPacket;
import org.jitsi.srtp.SrtpCryptoContext;
import org.jitsi.srtp.SrtpPolicy;
import org.jitsi.utils.logging2.Logger;
import org.jitsi.utils.logging2.LoggerImpl;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class BouncyCastleFipsTest {

    @Test
    public void testSrtpEncryptionDecryption() throws Exception {
        // **1. Set Up Bouncy Castle FIPS Provider**

        // Add Bouncy Castle FIPS provider if not already added
//        if (Security.getProvider(BouncyCastleFipsProvider.PROVIDER_NAME) == null) {
//            BouncyCastleFipsProvider provider = new BouncyCastleFipsProvider();
//            Security.addProvider(provider);
//        }

        // **2. Set the Cipher Factory to BouncyCastleFipsCipherFactory**


//        // Get the default SRTP crypto senderContext factory
//        SrtpCryptoContextFactory factory = SrtpCryptoContextFactory.getDefaultFactory();

        // **3. Define Master Key and Salt**

        // Define master key and salt
        byte[] masterKey = new byte[16]; // 128-bit key
        byte[] masterSalt = new byte[14]; // 112-bit salt

        // Initialize your key material here
        // For testing purposes, we'll fill them with sequential values
        for (int i = 0; i < masterKey.length; i++) {
            masterKey[i] = (byte) i;
        }
        for (int i = 0; i < masterSalt.length; i++) {
            masterSalt[i] = (byte) (i + 16);
        }

        // **4. Define SRTP Policies for Encryption and Authentication**

        SrtpPolicy srtpPolicy = new SrtpPolicy(
            SrtpPolicy.AESCM_ENCRYPTION, 16,            // Encryption algorithm and key length
            SrtpPolicy.HMACSHA1_AUTHENTICATION, 20,     // Authentication algorithm and key length
            10,                                          // Authentication tag length in bits
            14                                          // Salt key length in bits
        );

        int key_derivation_rate = 2^8;

        // **5. Create SRTP Crypto Context**

        int ssrc = 0xdecafbad; // Example SSRC
        Logger logger = new LoggerImpl("test-logger");
        logger.info("creating senderContext.");
        SrtpCryptoContext senderContext = new SrtpCryptoContext(
            true, // sender = true
            ssrc,
            0,      // Roll-over counter (ROC)
            masterKey,
            masterSalt,
            srtpPolicy,
            logger
        );

        // Receiver context (for decryption)
        logger.info("creating receiverContext.");
        SrtpCryptoContext receiverContext = new SrtpCryptoContext(
            false, // sender = false
            ssrc,
            0, //ROC
            masterKey,
            masterSalt,
            srtpPolicy,
            logger
        );

        // **6. Create a Dummy RTP Packet**

        byte[] rtpData = new byte[160]; // Example RTP packet size
        int previousRoc = 0;
        for (int packetsCounter = 0; packetsCounter < 200000; packetsCounter++) {

            for (int i = 0; i < rtpData.length; i++) {
                rtpData[i] = (byte) ((i * packetsCounter) % 256);
            }
            int sequenceBeforeRollover = packetsCounter + 50000;
            int rolloverCounter = sequenceBeforeRollover / 0xFFFF;
            if (rolloverCounter != previousRoc) {
                logger.info("rolloverCounter updated form: " + previousRoc + " to new: " + rolloverCounter);
                previousRoc = rolloverCounter;
            }

            int sequence = sequenceBeforeRollover % 0xFFFF;
            RawPacket packet = new RawPacket(rtpData, 0, rtpData.length);
            packet.setSequenceNumber(sequence);
            packet.setTimestamp(30000 + (packetsCounter * 160));
            packet.setSSRC(ssrc);
            // Save original packet data for comparison
            int originalLength = packet.getLength();
            byte[] originalData = Arrays.copyOfRange(
                packet.getBuffer(),
                packet.getOffset(),
                packet.getOffset() + packet.getLength()
            );

            // **7. Encrypt the RTP Packet**
//            logger.info("before senderContext.transformPacket()");
            senderContext.transformPacket(packet);

            // **8. Verify Encryption**

            // Ensure the packet data has changed after encryption
            byte[] encryptedData = Arrays.copyOfRange(
                packet.getBuffer(),
                packet.getOffset(),
                packet.getOffset() + packet.getLength()
            );
            assertFalse(
                Arrays.equals(originalData, encryptedData),
                "Packet data should be different after encryption"
            );

            // **9. Decrypt the RTP Packet**

//            logger.info("before receiverContext.reverseTransformPacket()");
            receiverContext.reverseTransformPacket(packet, false);

            // **10. Verify Decryption**

            // Ensure the packet length is reset to the original length
            assertEquals(
                originalLength,
                packet.getLength(),
                "Packet length after decryption should be the same as original length"
            );

            // Extract the decrypted data
            byte[] decryptedData = Arrays.copyOfRange(
                packet.getBuffer(),
                packet.getOffset(),
                packet.getOffset() + packet.getLength()
            );

            // Ensure the decrypted data matches the original data
            assertArrayEquals(
                originalData,
                decryptedData,
                "Decrypted data does not match original data"
            );
        }
        logger.info("test over.");
    }
}
