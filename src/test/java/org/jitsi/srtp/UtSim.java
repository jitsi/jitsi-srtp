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

import java.util.*;

/**
 * an unreliable transport simulator
 * (for testing replay protection and suchlike)
 * Inspired by ut_sim implementation in libsrtp.
 */
public class UtSim {
    private final static int UT_BUF = 160;

    private int index;
    private ArrayList<Integer> buffer;
    private Random random;
    private long seed = System.currentTimeMillis(); // Pass an explicit seed for reproducible tests

    public UtSim(int size)
    {
        buffer = new ArrayList<Integer>(size);
        for (int i = 0; i < size; i++)
        {
            buffer.add(i);
        }

        random = new Random(seed);

        Collections.shuffle(buffer, random);

        index = size-1;
    }

    public UtSim()
    {
        this(UT_BUF);
    }

    public int getNextIndex()
    {
        int ret = buffer.get(0);

        index++;
        buffer.set(0, index);

        Collections.shuffle(buffer, random);

        return ret;
    }
}
