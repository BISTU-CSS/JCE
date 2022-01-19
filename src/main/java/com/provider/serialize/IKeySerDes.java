package com.provider.serialize;

import java.io.IOException;
import java.security.Key;

/**
 * 公钥/私钥/密钥序列化和反序列化
 *
 * @param <K> Key
 * @author pengshaocheng
 */
public interface IKeySerDes<K extends Key> {

    K deserialize(byte[] enc) throws IOException;

    byte[] serialize(K key) throws IOException;
}
