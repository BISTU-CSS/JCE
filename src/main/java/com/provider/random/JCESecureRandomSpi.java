package com.provider.random;


import com.jna.api.LibCrypto;

import java.security.SecureRandomSpi;

public final class JCESecureRandomSpi extends SecureRandomSpi {
    private byte[] seed;

    @Override
    protected void engineSetSeed(byte[] seed) {
        throw new UnsupportedOperationException("Not Implemented");
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {

        LibCrypto libCrypto = new LibCrypto();
        byte[] buffer = libCrypto.generateRandom(bytes.length);

        //把bytes装入并返回
        System.arraycopy(buffer, 0, bytes, 0, buffer.length);
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        LibCrypto libCrypto = new LibCrypto();
        return libCrypto.generateRandom(numBytes);
    }

}
