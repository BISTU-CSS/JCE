package com.provider.cipher;


import com.jna.api.LibCrypto;
import com.padding.PKCS7Padding;
import com.util.CipherUtil;

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;

/**
 * aes 加解密接口 todo
 *
 * @author fuxiaopeng 20200604
 */
public final class AESCipherSpi extends CipherSpi {
    private int opmode;
    private Key key;
    private byte[] iv = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -31};

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {

//        byte[] iv = new byte[inputLen];
//        System.out.println("IV长度为"+inputLen);
//        (new Random()).nextBytes(iv);

        int algId = 1025;
        LibCrypto libCrypto = new LibCrypto();
        if (opmode == Cipher.ENCRYPT_MODE) {
            // 填充
            input = CipherUtil.encryptPadding(algId, input);
            return libCrypto.encrypt(algId, key.getEncoded(), iv, input);
        }

        if (opmode == Cipher.DECRYPT_MODE) {
            byte[] output = libCrypto.decrypt(algId, key.getEncoded(), iv, input);
            // 逆填充
            return PKCS7Padding.getUnPaddingData(output);
        }

        return null;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        return 0;
    }

    @Override
    protected int engineGetBlockSize() {

        return 0;
    }

    @Override
    protected byte[] engineGetIV() {

        return iv;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {

        return 0;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {

        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.key = key;
        this.opmode = opmode;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.key = key;
        this.opmode = opmode;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.key = key;
        this.opmode = opmode;
    }

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {

    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {

    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {

        return null;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {

        return 0;
    }

}
