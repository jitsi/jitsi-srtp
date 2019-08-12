package org.jitsi.srtp;

import java.util.ArrayList;
import java.util.Collections;

/**
 * an unreliable transport simulator
 * (for testing replay protection and suchlike)
 * Inspired by ut_sim implementation in libsrtp.
 */

public class UtSim {
    private final static int UT_BUF = 160;

    private int index;
    private ArrayList<Integer> buffer;

    public UtSim(int size)
    {
        buffer = new ArrayList<Integer>(size);
        for (int i = 0; i < size; i++) {
            buffer.set(i, i);
        }
        Collections.shuffle(buffer);

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

        Collections.shuffle(buffer);

        return ret;
    }
}
