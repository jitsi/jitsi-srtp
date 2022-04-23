/*
 * Copyright @ 2016 - present 8x8, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.jitsi.srtp.crypto;

import java.security.*;
import org.jitsi.utils.*;
import org.jitsi.utils.logging2.*;

public class JitsiOpenSslProvider
    extends Provider
{
    private static final Logger logger =
        new LoggerImpl(JitsiOpenSslProvider.class.getName());

    /**
     * The indicator which determines whether OpenSSL (Crypto) library wrapper
     * was loaded.
     */
    private static boolean libraryLoaded = false;

    private static native boolean OpenSSL_Init();

    static
    {
        String[] versions = { "1.1", "3" };
        for (int i = 0; i < versions.length; i++)
        {
            String version = versions[i];
            try
            {
                JNIUtils.loadLibrary("jitsisrtp_" + version,
                    JitsiOpenSslProvider.class.getClassLoader());
                if (OpenSSL_Init())
                {
                    logger.info(() -> "jitsisrtp successfully loaded for OpenSSL " + version);
                    libraryLoaded = true;
                    break;
                }
                else
                {
                    logger.warn("OpenSSL_Init failed");
                }
            }
            catch (UnsatisfiedLinkError t)
            {
                if (i == versions.length - 1)
                {
                    logger.warn("Unable to load jitsisrtp", t);
                }
                else
                {
                    logger.debug(() -> "Unable to load jitsisrtp for OpenSSL " + version + ": " + t);
                }
            }
        }
    }

    public static boolean isLoaded()
    {
        return libraryLoaded;
    }

    public JitsiOpenSslProvider()
    {
        super("JitsiOpenSslProvider", "1",
            "Jitsi OpenSSL SRTP security provider");
        put("Cipher.AES/CTR/NoPadding", OpenSslAesCtrCipherSpi.class.getName());
        put("Cipher.AES/GCM/NoPadding", OpenSslAesGcmCipherSpi.class.getName());
        put("Cipher.AES/ECB/NoPadding", OpenSslAesEcbCipherSpi.class.getName());
        put("Cipher.AES/GCM-AuthOnly/NoPadding", OpenSslAesGcmAuthOnlyCipherSpi.class.getName());
        put("MAC.HmacSHA1", OpenSslHmacSpi.class.getName());
    }
}
