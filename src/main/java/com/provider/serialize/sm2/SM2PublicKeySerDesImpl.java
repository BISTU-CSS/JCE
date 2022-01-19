package com.provider.serialize.sm2;

import com.provider.serialize.IKeySerDes;

import java.io.*;
import java.math.BigInteger;

/**
 * @author pengshaocheng 2020/8/4
 */
public class SM2PublicKeySerDesImpl implements IKeySerDes<JCEECPublicKey> {

    @Override
    public JCEECPublicKey deserialize(byte[] enc) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(enc));
        int keyIndex = dis.readInt();
        int keyType = dis.readInt();
        int bits = dis.readInt();
        byte[] x = new byte[dis.readInt()];
        dis.readFully(x);
        byte[] y = new byte[dis.readInt()];
        dis.readFully(y);
        return new JCEECPublicKey(keyIndex, keyType, bits, new BigInteger(x), new BigInteger(y));
    }

    @Override
    public byte[] serialize(JCEECPublicKey key) throws IOException {
        ByteArrayOutputStream bis = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bis);
        dos.writeInt(key.getKeyIndex());
        dos.writeInt(key.getKeyType());
        dos.writeInt(key.getBits());
        byte[] x = key.getW().getAffineX().toByteArray();
        dos.writeInt(x.length);
        dos.write(x);
        byte[] y = key.getW().getAffineY().toByteArray();
        dos.writeInt(y.length);
        dos.write(y);
        return bis.toByteArray();
    }
}
