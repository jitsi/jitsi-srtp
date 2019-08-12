package org.jitsi.srtp;

import static org.junit.Assert.*;

import org.junit.Test;

import javax.xml.bind.DatatypeConverter;

public class SRTPKeyDerivationTest {

    /* Key derivation test vectors from RFC 3711. */
    private static final byte[] masterKey128 =
            DatatypeConverter.parseHexBinary("E1F97A0D3E018BE0D64FA32C06DE4139");
    private static final byte[] masterSalt128 =
            DatatypeConverter.parseHexBinary("0EC675AD498AFEEBB6960B3AABE6");

    private static final byte[] cipherKey128 =
            DatatypeConverter.parseHexBinary("C61E7A93744F39EE10734AFE3FF7A087");
    private static final byte[] cipherSalt128 =
            DatatypeConverter.parseHexBinary("30CBBC08863D8C85D49DB34A9AE1");
    private static final byte[] authKey128 =
            DatatypeConverter.parseHexBinary("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4");

    @Test
    public void srtpKdf128Test() {
        SRTPPolicy policy =
                new SRTPPolicy(SRTPPolicy.AESCM_ENCRYPTION, 128/8,
                        SRTPPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                        80/8, 112/8 );
        SRTPContextFactory factory = new SRTPContextFactory(true, masterKey128, masterSalt128, policy, policy);

        SRTPCryptoContext srtpContext = factory.getDefaultContext();
        SRTCPCryptoContext srtcpContext = factory.getDefaultContextControl();

        srtpContext.deriveSrtpKeysInternal(0);
        srtcpContext.deriveSrtcpKeys();

        assertArrayEquals(srtpContext.encKey, cipherKey128);
        assertArrayEquals(srtpContext.saltKey, cipherSalt128);
        assertArrayEquals(srtpContext.authKey, authKey128);
    }

    /* Key derivation test vectors from RFC 6188. */
    private static final byte[] masterKey256 =
            DatatypeConverter.parseHexBinary("f0f04914b513f2763a1b1fa130f10e29" +
                    "98f6f6e43e4309d1e622a0e332b9f1b6");
    private static final byte[] masterSalt256 =
            DatatypeConverter.parseHexBinary("3b04803de51ee7c96423ab5b78d2");

    private static final byte[] cipherKey256 =
            DatatypeConverter.parseHexBinary("5ba1064e30ec51613cad926c5a28ef73" +
                    "1ec7fb397f70a960653caf06554cd8c4");
    private static final byte[] cipherSalt256 =
            DatatypeConverter.parseHexBinary("fa31791685ca444a9e07c6c64e93");
    private static final byte[] authKey256 =
            DatatypeConverter.parseHexBinary("fd9c32d39ed5fbb5a9dc96b30818454d1313dc05");

    @Test
    public void srtpKdf256Test() {
        SRTPPolicy policy =
                new SRTPPolicy(SRTPPolicy.AESCM_ENCRYPTION, 256/8,
                        SRTPPolicy.HMACSHA1_AUTHENTICATION, 160/8,
                        80/8, 112/8 );
        SRTPContextFactory factory = new SRTPContextFactory(true, masterKey256, masterSalt256, policy, policy);

        SRTPCryptoContext srtpContext = factory.getDefaultContext();
        SRTCPCryptoContext srtcpContext = factory.getDefaultContextControl();

        srtpContext.deriveSrtpKeysInternal(0);
        srtcpContext.deriveSrtcpKeys();

        assertArrayEquals(srtpContext.encKey, cipherKey256);
        assertArrayEquals(srtpContext.saltKey, cipherSalt256);
        assertArrayEquals(srtpContext.authKey, authKey256);
    }
}
