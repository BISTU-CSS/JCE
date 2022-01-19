package com.provider.mac;


import com.jna.api.LibCrypto;
import com.util.CipherUtil;
import com.util.SymmetryUtil;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.List;

public final class SM1MacSpi extends MacSpi {
    private String algName = "SM1";
    private SecretKey secretKey;
    private byte[] input;

    @Override
    protected int engineGetMacLength() {
        return 0;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.secretKey = (SecretKey) key;
        if (!key.getAlgorithm().equals(algName)) {
            throw new InvalidParameterException("Wrong key algorithm parameter");
        }
    }

    @Override
    protected void engineUpdate(byte input) {
        throw new UnsupportedOperationException("Not Implemented");
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        this.input = input;
    }

    @Override
    protected byte[] engineDoFinal() {
        if (input.length < 1) {
            return new byte[0];
        }

        int algId = 272;
        int mlength = SymmetryUtil.inputBaseLength(algId);

        List<byte[]> list = CipherUtil.splitArraysAndPKCS7Padding(input, mlength);
        byte[] result = new byte[list.size() * mlength];

        LibCrypto libCrypto = new LibCrypto();
        //内部
        for (int i = 0; i < list.size(); i++) {
            byte[] temp = libCrypto.generateHMAC(algId, secretKey.getEncoded(), list.get(i));
            System.arraycopy(temp, 0, result, i * mlength, mlength);
        }

        return result;
    }

    @Override
    protected void engineReset() {
        this.input = null;
    }

}
