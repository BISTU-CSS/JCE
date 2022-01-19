package com.provider.cipher;

import com.provider.NDSecProvider;
import com.util.CipherUtil;
import com.util.encoders.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Security;

import static org.junit.Assert.assertEquals;

/**
 * @author pengshaocheng
 */
public class AESCipherSpiTest {

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
    public void engineDoFinal() throws Exception {

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", baseProvider);
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        {
            String plain = "Hello Word! hong";
            String alg = "AES";
            //byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -30};
            byte[] encryptBytes = CipherUtil.encrypt(plain.getBytes(), secretKey, alg, baseProvider);
            System.out.println(Base64.toBase64String(encryptBytes));
            byte[] decryptBytes = CipherUtil.decrypt(encryptBytes, secretKey, alg, baseProvider);
            assertEquals(plain, new String(decryptBytes));
        }

        {
            String plain = "@##%#*&(()&*&*)))&^%%#@$#$@#$%#&";
            String alg = "AES";
            //byte[] plain = {1, -128, -115, 90, 127, 23, -10, -31, 109, 59, 118, -6, 99, 29, -34, -30};
            byte[] encryptBytes = CipherUtil.encrypt(plain.getBytes(), secretKey, alg, bouncyCastleProvider);
            System.out.println(Base64.toBase64String(encryptBytes));
            byte[] decryptBytes = CipherUtil.decrypt(encryptBytes, secretKey, alg, bouncyCastleProvider);
            assertEquals(plain, new String(decryptBytes));
        }
    }

}