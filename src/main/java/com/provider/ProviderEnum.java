package com.provider;

public enum ProviderEnum {
    // 随机数
    RND("SecureRandom.RND", "com.provider.random.JCESecureRandomSpi"),

    // 密钥对生成器（非对称算法：RSA、SM2）
    KEY_PAIR_GENERATOR_RSA("KeyPairGenerator.RSA", "com.provider.keypairgenerator.RSAKeyPairGeneratorSpi"),
    KEY_PAIR_GENERATOR_SM2("KeyPairGenerator.SM2", "com.provider.keypairgenerator.SM2KeyPairGeneratorSpi"),

    // 密钥生成器（对称算法：AES、SM1、SM4、SMS4、SSF33）
    KEY_GENERATOR_AES("KeyGenerator.AES", "com.provider.keygenerator.AESKeyGeneratorSpi"),
    KEY_GENERATOR_SM1("KeyGenerator.SM1", "com.provider.keygenerator.SM1KeyGeneratorSpi"),
    KEY_GENERATOR_SM4("KeyGenerator.SM4", "com.provider.keygenerator.SM4KeyGeneratorSpi"),
    KEY_GENERATOR_SMS4("KeyGenerator.SMS4", "com.provider.keygenerator.SMS4KeyGeneratorSpi"),
    KEY_GENERATOR_SSF33("KeyGenerator.SSF33", "com.provider.keygenerator.SSF33KeyGeneratorSpi"),

    // 加解密
    // 非对称加解密
    CIPHER_RSA("Cipher.RSA", "com.provider.cipher.RSACipherSpi"),
    CIPHER_SM2("Cipher.SM2", "com.provider.cipher.SM2CipherSpi"),
    // 对称加解密
    CIPHER_AES("Cipher.AES", "com.provider.cipher.AESCipherSpi"),
    CIPHER_SM1("Cipher.SM1", "com.provider.cipher.SM1CipherSpi"),
    CIPHER_SM4("Cipher.SM4", "com.provider.cipher.SM4CipherSpi"),
    CIPHER_SSF33("Cipher.SSF33", "com.provider.cipher.SSF33CipherSpi"),

    // 哈希值
    MAC_SM1("Mac.SM1", "com.provider.mac.SM1MacSpi"),
    MAC_SMS4("Mac.SMS4", "com.provider.mac.SMS4MacSpi"),

    // 哈希算法
    MESSAGE_DIGEST_MD5("MessageDigest.MD5", "com.provider.messagedigest.MD5MessageDigestSpi"),
    MESSAGE_DIGEST_SHA1("MessageDigest.SHA1", "com.provider.messagedigest.SHA1MessageDigestSpi"),
    MESSAGE_DIGEST_SHA224("MessageDigest.SHA224", "com.provider.messagedigest.SHA224MessageDigestSpi"),
    MESSAGE_DIGEST_SHA256("MessageDigest.SHA256", "com.provider.messagedigest.SHA256MessageDigestSpi"),
    MESSAGE_DIGEST_SHA384("MessageDigest.SHA384", "com.provider.messagedigest.SHA384MessageDigestSpi"),
    MESSAGE_DIGEST_SHA512("MessageDigest.SHA512", "com.provider.messagedigest.SHA512MessageDigestSpi"),
    MESSAGE_DIGEST_SHA3224("MessageDigest.SHA3224", "com.provider.messagedigest.SHA3224MessageDigestSpi"),
    MESSAGE_DIGEST_SHA3256("MessageDigest.SHA3256", "com.provider.messagedigest.SHA3256MessageDigestSpi"),
    MESSAGE_DIGEST_SHA3384("MessageDigest.SHA3384", "com.provider.messagedigest.SHA3384MessageDigestSpi"),
    MESSAGE_DIGEST_SHA3512("MessageDigest.SHA3512", "com.provider.messagedigest.SHA3512MessageDigestSpi"),
    MESSAGE_DIGEST_SM3("MessageDigest.SM3", "com.provider.messagedigest.SM3MessageDigestSpi"),
    MESSAGE_DIGEST_SM3WithID("MessageDigest.SM3WithID", "com.provider.messagedigest.SM3WithIDMessageDigestSpi"),
    MESSAGE_DIGEST_SM3WithoutID("MessageDigest.SM3WithoutID", "com.provider.messagedigest.SM3WithoutIDMessageDigestSpi"),

    // 数字签名
    SIGNATURE_MD5WithRSA("Signature.MD5WithRSA", "com.provider.signature.MD5WithRSASignatureSpi"),
    SIGNATURE_SHA1WithRSA("Signature.SHA1WithRSA", "com.provider.signature.SHA1WithRSASignatureSpi"),
    SIGNATURE_SHA1WithSM2("Signature.SHA1WithSM2", "com.provider.signature.SHA1WithSM2SignatureSpi"),
    SIGNATURE_SHA224WithRSA("Signature.SHA224WithRSA", "com.provider.signature.SHA224WithRSASignatureSpi"),
    SIGNATURE_SHA224WithSM2("Signature.SHA224WithSM2", "com.provider.signature.SHA224WithSM2SignatureSpi"),
    SIGNATURE_SHA256WithRSA("Signature.SHA256WithRSA", "com.provider.signature.SHA256WithRSASignatureSpi"),
    SIGNATURE_SHA256WithSM2("Signature.SHA256WithSM2", "com.provider.signature.SHA256WithSM2SignatureSpi"),
    SIGNATURE_SHA384WithRSA("Signature.SHA384WithRSA", "com.provider.signature.SHA384WithRSASignatureSpi"),
    SIGNATURE_SHA512WithRSA("Signature.SHA512WithRSA", "com.provider.signature.SHA512WithRSASignatureSpi"),
    SIGNATURE_SM3WithSM2("Signature.SM3WithSM2", "com.provider.signature.SM3WithSM2SignatureSpi");


    private String code;
    private String classPath;

    ProviderEnum(String code, String classPath) {
        this.code = code;
        this.classPath = classPath;
    }

    public String getCode() {
        return code;
    }

    public String getClassPath() {
        return classPath;
    }

}
