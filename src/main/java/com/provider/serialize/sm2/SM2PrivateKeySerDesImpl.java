package com.provider.serialize.sm2;

import com.provider.serialize.IKeySerDes;

import java.io.*;
import java.math.BigInteger;

/**
 * @author pengshaocheng
 */
public class SM2PrivateKeySerDesImpl implements IKeySerDes<JCEECPrivateKey> {

    @Override
    public JCEECPrivateKey deserialize(byte[] enc) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(enc));
        int keyIndex = dis.readInt();
        int keyType = dis.readInt();
        int bits = dis.readInt();
        byte[] s = new byte[dis.readInt()];
        dis.readFully(s);
        byte[] x = new byte[dis.readInt()];
        dis.readFully(x);
        byte[] y = new byte[dis.readInt()];
        dis.readFully(y);
        return new JCEECPrivateKey(keyIndex, keyType, bits, new BigInteger(s), new BigInteger(x), new BigInteger(y));
    }

    @Override
    public byte[] serialize(JCEECPrivateKey key) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos);
        dos.writeInt(key.getKeyIndex());
        dos.writeInt(key.getKeyType());
        dos.writeInt(key.getBits());
        byte[] s = key.getS().toByteArray();
        dos.writeInt(s.length);
        dos.write(s);
        byte[] x = key.getW().getAffineX().toByteArray();
        dos.writeInt(x.length);
        dos.write(x);
        byte[] y = key.getW().getAffineY().toByteArray();
        dos.writeInt(y.length);
        dos.write(y);
        return bos.toByteArray();
    }
}
