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

import org.jitsi.utils.*;
import org.junit.platform.commons.util.StringUtils;

import java.util.function.*;

import static org.junit.jupiter.api.Assertions.fail;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Assertions useful for testing jitsi-srtp
 */
public class Assertions
{
    public static void assertByteArrayBufferEquals(byte[] expected, ByteArrayBuffer actual)
    {
        assertEquals(expected.length, actual.getLength(), "buffer length");
        for (int i = 0; i < expected.length; i++)
        {
            byte expectedByte = expected[i];
            byte actualByte = actual.getBuffer()[i + actual.getOffset()];
            assertEquals(expectedByte, actualByte,
                "at byte position " + i + " (after offset " + actual.getOffset() + ")");
        }
    }
}
