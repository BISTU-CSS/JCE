package com.provider.cipher;


import com.jna.api.LibCrypto;
import com.jna.model.sm2.*;
import com.padding.PKCS7Padding;
import com.provider.serialize.sm2.JCEECPrivateKey;
import com.provider.serialize.sm2.JCEECPublicKey;

import javax.crypto.*;
import java.io.IOException;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.List;

/**
 * sm2 加解密接口
 *
 * @author fuxiaopeng 20200604
 */
public final class SM2CipherSpi extends CipherSpi {
    private int opmode;
    private Key key;

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {

        if (opmode == Cipher.ENCRYPT_MODE) {
            //加密模式
            JCEECPublicKey k = (JCEECPublicKey) key;
            ECPoint point = k.getW();
            SM2refPublicKey publicKey = new SM2refPublicKey(point.getAffineX().toByteArray(), point.getAffineY().toByteArray());

            try {
                int mlength = 256;
                List<byte[]> list = splitArrays(input, inputLen, LibCrypto.SM2_BLOCK_LENGTH);
                byte[] result = new byte[list.size() * mlength];

                LibCrypto libCrypto = new LibCrypto();
                //内部
                for (int i = 0; i < list.size(); i++) {
                    SM2refCipher cipher = libCrypto.sm2ExternalEncrypt(publicKey, list.get(i));
                    SM2StructCipher structCipher = SM2StructureUtil.convertStruct(cipher);
                    byte[] encrypts = structCipher.getEncoded("DER");

                    byte[] temp = PKCS7Padding.getPaddingData(encrypts, mlength);
                    System.arraycopy(temp, 0, result, i * mlength, mlength);
                }

                return result;

            } catch (IOException ec) {
                throw new BadPaddingException(ec.getMessage());
            }

        }

        if (opmode == Cipher.DECRYPT_MODE) {
            //解密模式
            JCEECPrivateKey k = (JCEECPrivateKey) key;
            SM2refPrivateKey privateKey = new SM2refPrivateKey(k.getS().toByteArray());

            int mlength = 256;
            List<byte[]> list = splitArrays(input, inputLen, mlength);

            List<byte[]> tmpList = new ArrayList<>();

            LibCrypto libCrypto = new LibCrypto();
            //内部
            for (int i = 0; i < list.size(); i++) {
                byte[] decrypts = PKCS7Padding.getUnPaddingData(list.get(i));
                SM2StructCipher structCipher = SM2StructCipher.getInstance(decrypts);
                SM2refCipher cipher = SM2StructureUtil.convertCipher(structCipher);
                byte[] temp = libCrypto.sm2ExternalDecrypt(privateKey, cipher);
                tmpList.add(temp);
            }

            int length = 0;
            for (byte[] b : tmpList) {
                length += b.length;
            }

            byte[] result = new byte[length];
            int countLength = 0;
            for (byte[] b : tmpList) {
                System.arraycopy(b, 0, result, countLength, b.length);
                countLength += b.length;
            }
            return result;
        }

        return null;
    }


    public static List<byte[]> splitArrays(byte[] input, int inputLen, int mlength) {
        int a = inputLen / mlength;//获取输入长度/模长的倍数
        int b = inputLen % mlength;//获取输入长度/模长的余数

        List<byte[]> list = new ArrayList<>();

        for (int i = 0; i < a; i++) {
            byte[] temp = new byte[mlength];
            System.arraycopy(input, i * mlength, temp, 0, mlength);
            list.add(temp);
        }
        if (b > 0) {
            byte[] temp = new byte[b];
            System.arraycopy(input, a * mlength, temp, 0, b);
            list.add(temp);
        }

        return list;
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

        return null;
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
        this.opmode = opmode;
        this.key = key;
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {


    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {


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
