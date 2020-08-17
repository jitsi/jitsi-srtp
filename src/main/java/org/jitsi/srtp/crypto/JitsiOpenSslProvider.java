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

    static
    {
        try
        {
            JNIUtils.loadLibrary("jitsisrtp",
                JitsiOpenSslProvider.class.getClassLoader());
            logger.info(() -> "jitsisrtp successfully loaded");
            libraryLoaded = true;
        }
        catch (Throwable t)
        {
            logger.warn(() -> "Unable to load jitsisrtp: " + t.toString());
        }
    }

    public static boolean isLoaded()
    {
        return libraryLoaded;
    }

    public JitsiOpenSslProvider()
    {
        super("JitsiOpenSslProvider", 1,
            "Jitsi OpenSSL SRTP security provider");
        put("Cipher.AES/CTR/NoPadding", OpenSslAesCipherSpi.class.getName());
        put("MAC.HMAC-SHA1", OpenSslHmacSpi.class.getName());
    }
}
