package com.jna.model.sm2;

import org.bouncycastle.asn1.*;

import java.math.BigInteger;
import java.util.Enumeration;

public class SM2StructSignature extends ASN1Object {
    private BigInteger r;
    private BigInteger s;

    public SM2StructSignature(BigInteger r, BigInteger s) {
        this.r = r;
        this.s = s;
    }

    public SM2StructSignature(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.r = ((ASN1Integer) e.nextElement()).getValue();
        this.s = ((ASN1Integer) e.nextElement()).getValue();
    }

    public static SM2StructSignature getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public BigInteger getR() {
        return r;
    }

    public static SM2StructSignature getInstance(Object obj) {
        if (obj instanceof SM2StructSignature) {
            return (SM2StructSignature) obj;
        } else {
            return obj != null ? new SM2StructSignature(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public BigInteger getS() {
        return s;
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(this.getR()));
        v.add(new ASN1Integer(this.getS()));
        return new DERSequence(v);
    }
}
