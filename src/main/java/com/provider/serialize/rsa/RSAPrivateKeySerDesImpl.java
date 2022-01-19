package com.provider.serialize.rsa;

import com.provider.serialize.IKeySerDes;

import java.io.*;
import java.math.BigInteger;

/**
 * @author pengshaocheng
 */
public class RSAPrivateKeySerDesImpl implements IKeySerDes<JCERSAPrivateKey> {

    @Override
    public JCERSAPrivateKey deserialize(byte[] enc) throws IOException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(enc));
        int bits = dis.readInt();
        byte[] e = new byte[dis.readInt()];
        dis.readFully(e);
        byte[] p = new byte[dis.readInt()];
        dis.readFully(p);
        byte[] q = new byte[dis.readInt()];
        dis.readFully(q);
        byte[] pe = new byte[dis.readInt()];
        dis.readFully(pe);
        byte[] qe = new byte[dis.readInt()];
        dis.readFully(qe);
        byte[] coeff = new byte[dis.readInt()];
        dis.readFully(coeff);
        byte[] n = new byte[dis.readInt()];
        dis.readFully(n);
        byte[] d = new byte[dis.readInt()];
        dis.readFully(d);
        return new JCERSAPrivateKey(
                new BigInteger(e),
                new BigInteger(p),
                new BigInteger(q),
                new BigInteger(pe),
                new BigInteger(qe),
                new BigInteger(coeff),
                new BigInteger(n),
                new BigInteger(d),
                bits);
    }

    @Override
    public byte[] serialize(JCERSAPrivateKey key) throws IOException {
        ByteArrayOutputStream bis = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bis);
        dos.writeInt(key.getBits());
        byte[] e = key.getPublicExponent().toByteArray();
        dos.writeInt(e.length);
        dos.write(e);
        byte[] p = key.getPrimeP().toByteArray();
        dos.writeInt(p.length);
        dos.write(p);
        byte[] q = key.getPrimeQ().toByteArray();
        dos.writeInt(q.length);
        dos.write(q);
        byte[] pe = key.getPrimeExponentP().toByteArray();
        dos.writeInt(pe.length);
        dos.write(pe);
        byte[] qe = key.getPrimeExponentQ().toByteArray();
        dos.writeInt(qe.length);
        dos.write(qe);
        byte[] coeff = key.getCrtCoefficient().toByteArray();
        dos.writeInt(coeff.length);
        dos.write(coeff);
        byte[] n = key.getModulus().toByteArray();
        dos.writeInt(n.length);
        dos.write(n);
        byte[] d = key.getPrivateExponent().toByteArray();
        dos.writeInt(d.length);
        dos.write(d);
        return bis.toByteArray();
    }
}
