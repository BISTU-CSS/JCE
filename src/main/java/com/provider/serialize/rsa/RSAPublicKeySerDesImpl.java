package com.provider.serialize.rsa;

import com.provider.serialize.IKeySerDes;

import java.io.*;
import java.math.BigInteger;

/**
 * @author pengshaocheng
 */
public class RSAPublicKeySerDesImpl implements IKeySerDes<JCERSAPublicKey> {

    @Override
    public JCERSAPublicKey deserialize(byte[] enc) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(enc));
        int bits = dis.readInt();
        byte[] modulus = new byte[dis.readInt()];
        dis.readFully(modulus);
        byte[] publicExponent = new byte[dis.readInt()];
        dis.readFully(publicExponent);
        return new JCERSAPublicKey(new BigInteger(modulus), new BigInteger(publicExponent), bits);
    }

    @Override
    public byte[] serialize(JCERSAPublicKey key) throws IOException {
        ByteArrayOutputStream bis = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bis);
        dos.writeInt(key.getBits());
        byte[] modulus = key.getModulus().toByteArray();
        dos.writeInt(modulus.length);
        dos.write(modulus);
        byte[] publicExponent = key.getPublicExponent().toByteArray();
        dos.writeInt(publicExponent.length);
        dos.write(publicExponent);
        return bis.toByteArray();
    }
}
