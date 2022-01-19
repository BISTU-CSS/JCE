package com.provider.serialize;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;

/**
 * @author pengshaocheng
 */
public class SecretKeySerDesImpl implements IKeySerDes<SecretKey> {
    private final String algorithm;

    public SecretKeySerDesImpl(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public SecretKey deserialize(byte[] enc) throws IOException {
        return new SecretKeySpec(enc, algorithm);
    }

    @Override
    public byte[] serialize(SecretKey key) throws IOException {
        return key.getEncoded();
    }

}
