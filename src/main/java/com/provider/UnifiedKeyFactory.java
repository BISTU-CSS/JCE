package com.provider;

import com.provider.serialize.IKeySerDes;
import com.provider.serialize.SecretKeySerDesImpl;
import com.provider.serialize.rsa.RSAPrivateKeySerDesImpl;
import com.provider.serialize.rsa.RSAPublicKeySerDesImpl;
import com.provider.serialize.sm2.SM2PrivateKeySerDesImpl;
import com.provider.serialize.sm2.SM2PublicKeySerDesImpl;

import java.security.Key;
import java.util.HashMap;
import java.util.Map;

public class UnifiedKeyFactory {
    public static final int PUBLIC_KEY = 1;
    public static final int PRIVATE_KEY = 2;
    public static final int SECRET_KEY = 3;
    private static final Map<String, IKeySerDes<?>> table = new HashMap<>();

    static {
        table.put(tableKey("SM2", PUBLIC_KEY), new SM2PublicKeySerDesImpl());
        table.put(tableKey("SM2", PRIVATE_KEY), new SM2PrivateKeySerDesImpl());

        table.put(tableKey("RSA", PUBLIC_KEY), new RSAPublicKeySerDesImpl());
        table.put(tableKey("RSA", PRIVATE_KEY), new RSAPrivateKeySerDesImpl());

        table.put(tableKey("AES", SECRET_KEY), new SecretKeySerDesImpl("AES"));

        table.put(tableKey("SM1", SECRET_KEY), new SecretKeySerDesImpl("SM1"));
        table.put(tableKey("SM4", SECRET_KEY), new SecretKeySerDesImpl("SM4"));

        table.put(tableKey("SSF33", SECRET_KEY), new SecretKeySerDesImpl("SSF33"));
    }

    private static String tableKey(String algorithm, int keyType) {
        return algorithm + ":" + keyType;
    }

    public static <K extends Key> IKeySerDes<K> getKeySerDes(String algorithm, int keyType) {
        return (IKeySerDes<K>) table.get(tableKey(algorithm, keyType));
    }

}
