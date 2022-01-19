package com.jna.model.sm2;

import org.bouncycastle.asn1.*;

import java.math.BigInteger;
import java.util.Enumeration;

public class SM2StructCipher extends ASN1Object {
    private BigInteger x;// X分量
    private BigInteger y;// Y分量
    private byte[] C;// 密文数据
    private byte[] M;// 明文的杂凑值

    public static SM2StructCipher getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static SM2StructCipher getInstance(Object obj) {
        if (obj instanceof SM2StructCipher) {
            return (SM2StructCipher) obj;
        }

        return obj != null ? new SM2StructCipher(ASN1Sequence.getInstance(obj)) : null;
    }

    public SM2StructCipher(BigInteger x, BigInteger y, byte[] C, byte[] M) {
        this.x = x;
        this.y = y;
        this.C = C;
        this.M = M;
    }

    public SM2StructCipher(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.x = ((ASN1Integer) e.nextElement()).getValue();
        this.y = ((ASN1Integer) e.nextElement()).getValue();
        this.M = ((DEROctetString) e.nextElement()).getOctets();
        this.C = ((DEROctetString) e.nextElement()).getOctets();
    }

    public BigInteger getX() {
        return this.x;
    }

    public BigInteger getY() {
        return this.y;
    }

    public byte[] getC() {
        return this.C;
    }

    public byte[] getM() {
        return this.M;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(this.getX()));
        v.add(new ASN1Integer(this.getY()));
        v.add(new DEROctetString(this.getM()));
        v.add(new DEROctetString(this.getC()));
        return new DERSequence(v);
    }
}
