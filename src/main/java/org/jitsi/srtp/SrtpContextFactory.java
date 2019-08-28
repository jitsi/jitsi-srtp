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
package org.jitsi.srtp;

/**
 * The <tt>SrtpContextFactory</tt> creates the initial crypto contexts for RTP
 * and RTCP encryption using the supplied key material.
 *
 * @author Bing SU (nova.su@gmail.com)
 */
public class SrtpContextFactory
{
    /**
     * The default SrtpCryptoContext, which will be used to derive other
     * contexts.
     */
    private SrtpCryptoContext defaultContext;

    /**
     * The default SrtcpCryptoContext, which will be used to derive other
     * contexts.
     */
    private SrtcpCryptoContext defaultContextControl;

    /**
     * Construct a SrtpTransformEngine based on given master encryption key,
     * master salt key and Srtp/Srtcp policy.
     *
     * @param sender <tt>true</tt> if the new instance is to be used by an SRTP
     * sender; <tt>false</tt> if the new instance is to be used by an SRTP
     * receiver
     * @param masterKey the master encryption key
     * @param masterSalt the master salt key
     * @param srtpPolicy SRTP policy
     * @param srtcpPolicy SRTCP policy
     */
    public SrtpContextFactory(
            boolean sender,
            byte[] masterKey,
            byte[] masterSalt,
            SrtpPolicy srtpPolicy,
            SrtpPolicy srtcpPolicy)
    {
        defaultContext
            = new SrtpCryptoContext(
                    sender,
                    0,
                    0,
                    0,
                    masterKey,
                    masterSalt,
                    srtpPolicy);
        defaultContextControl
            = new SrtcpCryptoContext(0, masterKey, masterSalt, srtcpPolicy);
    }

    /**
     * Close the transformer engine.
     *
     * The close functions closes all stored default crypto contexts. This
     * deletes key data and forces a cleanup of the crypto contexts.
     */
    public void close()
    {
        if (defaultContext != null)
        {
            defaultContext.close();
            defaultContext = null;
        }
        if (defaultContextControl != null)
        {
            defaultContextControl.close();
            defaultContextControl = null;
        }
    }

    /**
     * Get the default SrtpCryptoContext
     *
     * @return the default SrtpCryptoContext
     */
    public SrtpCryptoContext getDefaultContext()
    {
        return defaultContext;
    }

    /**
     * Get the default SrtpCryptoContext
     *
     * @return the default SrtpCryptoContext
     */
    public SrtcpCryptoContext getDefaultContextControl()
    {
        return defaultContextControl;
    }
}
