package com.provider.keypairgenerator;

import com.provider.NDSecProvider;
import com.util.CipherUtil;
import com.util.encoders.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.IOException;
import java.security.KeyPair;
import java.security.Security;

import static org.junit.Assert.assertEquals;

public class SM2KeyPairGeneratorSpiTest {

    private BouncyCastleProvider bouncyCastleProvider;
    private NDSecProvider baseProvider;


    @Before
    public void setUp() throws Exception {
        bouncyCastleProvider = new BouncyCastleProvider();
        baseProvider = new NDSecProvider();
        Security.addProvider(baseProvider);
        Security.addProvider(bouncyCastleProvider);
    }

    @Test
    public void generateKeyPair() throws Exception {
        // SM2密钥长度只能是256
        SM2KeyPairGeneratorSpi sm2KeyPairGeneratorSpi = new SM2KeyPairGeneratorSpi();
        sm2KeyPairGeneratorSpi.initialize(256, null);
        KeyPair keyPair = sm2KeyPairGeneratorSpi.generateKeyPair();
        // 公钥加密，私钥解密
        {
            String plain = "@#￥#%#*&(()&*&*)))&^%%#@$";
            String alg = "SM2";
            byte[] encryptBytes = CipherUtil.encrypt(plain.getBytes(), keyPair.getPublic(), alg, baseProvider);
            byte[] decryptBytes = CipherUtil.decrypt(encryptBytes, keyPair.getPrivate(), alg, baseProvider);
            assertEquals(plain, new String(decryptBytes));
        }

        {
            String plain = "Hello world!";
            String alg = "SM2";
            byte[] encryptBytes = CipherUtil.encrypt(plain.getBytes(), keyPair.getPublic(), alg, baseProvider);
            byte[] decryptBytes = CipherUtil.decrypt(encryptBytes, keyPair.getPrivate(), alg, baseProvider);
            assertEquals(plain, new String(decryptBytes));
        }

        {
            String plain = "13473859318473";
            String alg = "SM2";
            byte[] encryptBytes = CipherUtil.encrypt(plain.getBytes(), keyPair.getPublic(), alg, baseProvider);
            byte[] decryptBytes = CipherUtil.decrypt(encryptBytes, keyPair.getPrivate(), alg, baseProvider);
            assertEquals(plain, new String(decryptBytes));
        }

        {
            String plain = "爱我中国";
            String alg = "SM2";
            byte[] encryptBytes = CipherUtil.encrypt(plain.getBytes(), keyPair.getPublic(), alg, baseProvider);
            byte[] decryptBytes = CipherUtil.decrypt(encryptBytes, keyPair.getPrivate(), alg, baseProvider);
            assertEquals(plain, new String(decryptBytes));
        }
        // 私钥钥加密，公钥解密, 不支持???
        // TODO
    }

    /**
     * PBE 基于口令的加解密算法
     *
     * @throws IOException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    @Test
    public void makePBECipher() throws IOException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = makePBECipher("PBEWithSHAAnd3-KeyTripleDES-CBC", Cipher.ENCRYPT_MODE, "123456".toCharArray(), new byte[20], 20);
        String str = "AAAAFGyxeBjIVPLmyaFyfq7doGT/vif6AAAFM7irySTf8DE3dmT4Z+kqm8ZjD5mBCEM+7rwu5Gn8s43HsiZkzVqHUBh/SH8flY5az9pyeq2ahVAYgJK6gBEh975hCBOe0d5QkRaOhAW1eBiPEZxGNod64E8l++dyyFT9btJ/Y/xFJrEF4I0W9cpq5LGlZxtTM7E42I269xZXmEhmDD5dOPqqjh8=";
        byte[] strBytes = Base64.decode(str);
        byte[] enc = cipher.doFinal(strBytes);
        cipher = makePBECipher("PBEWithSHAAnd3-KeyTripleDES-CBC", Cipher.DECRYPT_MODE, "123456".toCharArray(), new byte[20], 20);
        byte[] dec = cipher.doFinal(enc);
        assertEquals(str, Base64.toBase64String(dec));
    }

    private Cipher makePBECipher(String algorithm, int mode, char[] password, byte[] salt, int iterationCount) throws IOException {
        try {
            PBEKeySpec pbeSpec = new PBEKeySpec(password);
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm, "BC");
            PBEParameterSpec defParams = new PBEParameterSpec(salt, iterationCount);
            Cipher cipher = Cipher.getInstance(algorithm, "BC");
            cipher.init(mode, keyFact.generateSecret(pbeSpec), defParams);
            return cipher;
        } catch (Exception var10) {
            throw new IOException("Error initialising store of key store: " + var10);
        }
    }
}