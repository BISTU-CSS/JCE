package com.provider.keypairgenerator;

import com.provider.NDSecProvider;
import com.util.CipherUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.Security;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * @author pengshaocheng
 */
public class RSAKeyPairGeneratorSpiTest {

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
        RSAKeyPairGeneratorSpi rsaKeyPairGeneratorSpi = new RSAKeyPairGeneratorSpi();
        rsaKeyPairGeneratorSpi.initialize(1024, null);
        KeyPair keyPair = rsaKeyPairGeneratorSpi.generateKeyPair();
        // 公钥加密，私钥解密
        {
            // String plain = "@#￥#%#*&(()&*&*)))&^%%#@$";
            byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -30, 45, -15, -109, 102, -118, 109, -93, -122, -51, 99, -114, -93, -67, 8, 37, 26, -123, 16, 3, -21, -50, -2, -40, -125, 95, -52, 25, -41, -58, 8, 16, -13, 85, 1, 76, 84, 114, 70, 7, -32, 96, -83, -98, -116, 38, -120, -99, -77, 31, -27, 49, -97, -121, 57, 67, -84, 20, -72, -31, -63, 82, -117, 57, -33, -42, 25, 93, 8, 124, -31, -63, 24, 117, -118, 72, 53, 126, 70, -79, -112, 53, -110, -51, -67, -64, 48, 79, 71, 99, 93, 86, -78, 127, 77, 126, 26, 72, -15, 31, 10, -77, -87, -88, -127, -5, -97, 124, 93, -97, -25, 24, 121};

            String alg = "RSA";
            byte[] encryptBytes = CipherUtil.encrypt(plain, keyPair.getPublic(), alg, baseProvider);
            byte[] decryptBytes = CipherUtil.decrypt(encryptBytes, keyPair.getPrivate(), alg, baseProvider);
            assertArrayEquals(plain, decryptBytes);
        }

        {
            String plain = "Hello world!";
            String alg = "RSA";
            byte[] encryptBytes = CipherUtil.encrypt(plain.getBytes(), keyPair.getPublic(), alg, baseProvider);
            byte[] decryptBytes = CipherUtil.decrypt(encryptBytes, keyPair.getPrivate(), alg, baseProvider);
            assertEquals(plain, new String(decryptBytes));
        }

        {
            String plain = "13473859318473";
            String alg = "RSA";
            byte[] encryptBytes = CipherUtil.encrypt(plain.getBytes(), keyPair.getPublic(), alg, baseProvider);
            byte[] decryptBytes = CipherUtil.decrypt(encryptBytes, keyPair.getPrivate(), alg, baseProvider);
            assertEquals(plain, new String(decryptBytes));
        }

        {
            String plain = "爱我中国";
            String alg = "RSA";
            byte[] encryptBytes = CipherUtil.encrypt(plain.getBytes(), keyPair.getPublic(), alg, baseProvider);
            byte[] decryptBytes = CipherUtil.decrypt(encryptBytes, keyPair.getPrivate(), alg, baseProvider);
            assertEquals(plain, new String(decryptBytes));
        }
    }
}