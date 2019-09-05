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

import org.jitsi.utils.*;
import org.jitsi.utils.logging2.*;

public class OpenSslWrapperLoader
{
    /**
     * The <tt>Logger</tt> used by the <tt>OpenSslWrapperLoader</tt> class to
     * print out debug information.
     */
    private static final Logger logger =
        new LoggerImpl(OpenSslWrapperLoader.class.getName());

    /**
     * The indicator which determines whether OpenSSL (Crypto) library wrapper
     * was loaded.
     */
    private static boolean libraryLoaded = false;

    private static native boolean OpenSSL_Init();

    static
    {
        try
        {
            JNIUtils.loadLibrary("jitsisrtp",
                OpenSslWrapperLoader.class.getClassLoader());
            if (OpenSSL_Init())
            {
                logger.info(() -> "jitsisrtp successfully loaded");
                libraryLoaded = true;
            }
            else
            {
                logger.warn(() -> "OpenSSL_Init failed");
            }
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
}
