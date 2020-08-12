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
package org.jitsi.srtp.crypto;

import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.macs.*;
import org.jitsi.utils.logging2.*;

import javax.crypto.*;
import java.security.*;

/**
 * Implements a factory for an HMAC-SHA1 <tt>org.bouncycastle.crypto.Mac</tt>.
 *
 * @author Lyubomir Marinov
 */
public class HmacSha1
{
    /**
     * The <tt>Logger</tt> used by the <tt>Aes</tt> class to print out debug
     * information.
     */
    private static final Logger logger = new LoggerImpl(HmacSha1.class.getName());

    /**
     * Initializes a new <tt>org.bouncycastle.crypto.Mac</tt> instance which
     * implements a keyed-hash message authentication code (HMAC) with SHA-1.
     *
     * @return a new <tt>org.bouncycastle.crypto.Mac</tt> instance which
     * implements a keyed-hash message authentication code (HMAC) with SHA-1
     */
    public static org.bouncycastle.crypto.Mac createMac()
    {
        if (OpenSslWrapperLoader.isLoaded())
        {
            return new OpenSslHmac(OpenSslHmac.SHA1);
        }
        else
        {
            // Fallback to JCE.
            try
            {
                Mac mac = Mac.getInstance("HmacSHA1");
                logger.info("Using HmacSHA1 from provider " + mac.getProvider().getName());
                return new MacAdapter(mac);
            }
            catch (NoSuchAlgorithmException e) {
                // Fallback to BouncyCastle
                return new HMac(new SHA1Digest());
            }
        }
    }
}
