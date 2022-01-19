package com.provider.cipher;

import com.jna.api.LibCrypto;
import com.padding.PKCS7Padding;
import com.util.CipherUtil;

import javax.crypto.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public final class SM1CipherSpi extends CipherSpi {
    private int opmode;
    private Key key;
    private byte[] iv = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -31};

    /**
     * 加解密
     *
     * @param input
     * @param inputOffset
     * @param inputLen
     * @return
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
//            byte[] iv = new byte[inputLen];
//            (new Random()).nextBytes(iv);

        int algId = 264;
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
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return 0;
    }

    @Override
    protected byte[] engineGetIV() {

        return iv;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.opmode = opmode;
        this.key = key;

    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opmode = opmode;
        this.key = key;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.opmode = opmode;
        this.key = key;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        return 0;
    }


    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return 0;
    }
}
