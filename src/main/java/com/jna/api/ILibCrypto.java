package com.jna.api;


import com.jna.model.DeviceInfo;
import com.jna.model.DeviceRunStatus;
import com.jna.model.dsa.DSArefKeyPair;
import com.jna.model.dsa.DSArefSignature;
import com.jna.model.dsa.IDSArefPrivateKey;
import com.jna.model.dsa.IDSArefPublicKey;
import com.jna.model.ecdsa.ECDSArefKeyPair;
import com.jna.model.ecdsa.ECDSArefPrivateKey;
import com.jna.model.ecdsa.ECDSArefPublicKey;
import com.jna.model.ecdsa.ECDSArefSignature;
import com.jna.model.rsa.IRSArefPrivateKey;
import com.jna.model.rsa.IRSArefPublicKey;
import com.jna.model.rsa.RSArefKeyPair;
import com.jna.model.sm2.*;

public interface ILibCrypto {
    DeviceInfo getDeviceInfo();

    DeviceRunStatus getDeviceRunStatus();

    int[] getKeyStatus(int keyType);

    byte[] generateRandom(int randomLength);

    IRSArefPublicKey exportRSAPublicKey(int keyIndex, int keyType);

    RSArefKeyPair generateRSAKeyPair(int keySize);

    RSArefKeyPair generateRSAKeyPair(int keySize, int exponent);

    RSArefKeyPair generateRSAKeyPair(int keyIndex, int keyType, int keySize);

    byte[] rsaInternalPublicKey(int keyIndex, int keyType, byte[] input);

    byte[] rsaInternalPrivateKey(int keyIndex, int keyType, byte[] input);

    byte[] rsaExternalPublicKey(IRSArefPublicKey refPublicKey, byte[] input);

    byte[] rsaExternalPrivateKey(IRSArefPrivateKey refPrivateKey, byte[] input);

    void rsaImportKeyPair(int keyIndex, int keyType, IRSArefPublicKey refPublicKey, IRSArefPrivateKey refPrivateKey);

    SM2refPublicKey exportSM2PublicKey(int keyIndex, int keyType);

    SM2refKeyPair generateSM2KeyPair(int keySize);

    SM2refKeyPair generateSM2KeyPair(int keyIndex, int keyType, int keySize);

    SM2refCipher sm2InternalEncrypt(int keyIndex, int keyType, byte[] input);

    byte[] sm2InternalDecrypt(int keyIndex, int keyType, SM2refCipher refCipher);

    SM2refCipher sm2ExternalEncrypt(SM2refPublicKey publicKey, byte[] dataInput);

    byte[] sm2ExternalDecrypt(SM2refPrivateKey privateKey, SM2refCipher refCipher);

    SM2refSignature sm2InternalSign(int keyIndex, int keyType, byte[] input);

    boolean sm2InternalVerify(int keyIndex, int keyType, byte[] dataInput, SM2refSignature refSig);

    SM2refSignature sm2ExternalSign(SM2refPrivateKey refPrivateKey, byte[] input);

    boolean sm2ExternalVerify(SM2refPublicKey refPublicKey, byte[] dataInput, SM2refSignature refSig);

    byte[] sm2KeyAgreement(int flag, int keyIndex, SM2refPublicKey ownTmpPubKey, SM2refPrivateKey ownTmpPriKey, SM2refPublicKey opPubKey, SM2refPublicKey opTmpPubKey, int keyBits, byte[] ownId, byte[] opId) throws Exception;

    void sm2ImportKeyPair(int keyIndex, int keyType, SM2refPublicKey refPublicKey, SM2refPrivateKey refPrivateKey);

    ECDSArefKeyPair generateECDSAKeyPair(int keySize, int curetype);

    ECDSArefPublicKey exportECDSAPublicKey(int keyIndex, int keyType);

    ECDSArefSignature ecdsaInternalSign(int keyIndex, int keyType, byte[] input);

    boolean ecdsaInternalVerify(int keyIndex, int keyType, byte[] dataInput, ECDSArefSignature refSig);

    ECDSArefSignature ecdsaExternalSign(ECDSArefPrivateKey refPrivateKey, byte[] input);

    boolean ecdsaExternalVerify(ECDSArefPublicKey refPublicKey, byte[] dataInput, ECDSArefSignature refSig);

    DSArefKeyPair generateDSAKeyPair(int keySize);

    IDSArefPublicKey exportDSAPublicKey(int keyIndex, int keyType);

    DSArefSignature dsaInternalSign(int keyIndex, int keyType, byte[] input);

    boolean dsaInternalVerify(int keyIndex, int keyType, byte[] dataInput, DSArefSignature refSig);

    DSArefSignature dsaExternalSign(IDSArefPrivateKey refPrivateKey, byte[] input);

    boolean dsaExternalVerify(IDSArefPublicKey refPublicKey, byte[] dataInput, DSArefSignature refSig);

    void generateKey(int keyIndex, int keySize);

    byte[] encrypt(int algId, byte[] key, byte[] iv, byte[] input);

    byte[] decrypt(int algId, byte[] key, byte[] iv, byte[] input);

    byte[] encrypt(int algId, int keyIndex, byte[] iv, byte[] input);

    byte[] decrypt(int algId, int keyIndex, byte[] iv, byte[] input);

    byte[] encryptAdd(int algId, byte[] key, byte[] iv, byte[] input, byte[] addInput);

    byte[] decryptAdd(int algId, byte[] key, byte[] iv, byte[] input, byte[] addInput);

    byte[] encryptAdd(int algId, int keyIndex, byte[] iv, byte[] input, byte[] addInput);

    byte[] decryptAdd(int algId, int keyIndex, byte[] iv, byte[] input, byte[] addInput);

    void inputKEK(int keyIndex, byte[] key);

    void importKeyPairECC(int keyIndex, int keyType, int keyPriKeyIndex, byte[] eccPairEnvelopedKey);

    void importEncKeyPairECC(int keyIndex, byte[] eccPairEnvelopedKey);

    byte[] genKCV(int keyIndex);

    byte[] generateHMAC(int algId, int keyIndex, byte[] input);

    byte[] generateHMAC(int algId, byte[] key, byte[] input);

    byte[] genPBKDF2Key(int hashAlg, int iteraCount, int outLength, char[] pwd, byte[] salt);

    byte[] ecdhAgreement(int ecdsIndex, int keyType, byte[] pubKey);

    byte[] ecdhAgreement(byte[] priKey, byte[] pubKey);

    int hsmCreateFile(String fileName, int maxLength);

    byte[] hsmReadFile(String fileName, int startPosition, int readLength);

    int hsmWriteFile(String fileName, int startPosition, byte[] data);

    int hsmDeleteFile(String fileName);
}
