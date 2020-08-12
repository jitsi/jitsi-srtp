/*
 * Copyright @ 2020 - present 8x8, Inc
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

import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.params.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

/**
 * Adapts the {@link javax.crypto.Mac} class to the
 * {@link org.bouncycastle.crypto.Mac} interface.
 */
public class MacAdapter implements org.bouncycastle.crypto.Mac
{
    /**
     * The {@link javax.crypto.Mac} instance which is adapted to the
     * {@link org.bouncycastle.crypto.Mac} interface by this instance.
     */
    private final javax.crypto.Mac mac;

    /**
     * Initializes a new <tt>MacAdapter</tt> instance which is to adapt
     * a specific {@link javax.crypto.Mac} instance to the
     * {@link org.bouncycastle.crypto.Mac} interface.
     *
     * @param mac the {@link javax.crypto.Mac} instance to be adapted to
     * the {@link org.bouncycastle.crypto.Mac} interface by the new
     * instance
     */
    public MacAdapter(javax.crypto.Mac mac) {
        this.mac = mac;
    }

    /**
     * Gets the {@link javax.crypto.Mac} instance which is adapted to the
     * {@link org.bouncycastle.crypto.Mac} interface by this instance.
     *
     * @return the {@link javax.crypto.Mac} instance which is adapted to the
     * {@link org.bouncycastle.crypto.Mac} interface by this instance
     */
    public javax.crypto.Mac getJavaxMac()
    {
        return mac;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void init(CipherParameters params) throws IllegalArgumentException
    {
        byte[] key = (params instanceof KeyParameter)
            ? ((KeyParameter) params).getKey()
            : null;

        SecretKey secretKey = new SecretKeySpec(key, mac.getAlgorithm());

        try
        {
            mac.init(secretKey);
        }
        catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getAlgorithmName()
    {
        return mac.getAlgorithm();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getMacSize()
    {
        return mac.getMacLength();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void update(byte in) throws IllegalStateException
    {
        mac.update(in);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        mac.update(in, inOff, len);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        try
        {
            mac.doFinal(out, outOff);
            return mac.getMacLength();
        }
        catch (ShortBufferException e) {
            throw new DataLengthException(e.getMessage());
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void reset()
    {
        mac.reset();
    }
}
