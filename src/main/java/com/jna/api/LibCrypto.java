package com.jna.api;

import com.api.SDFInterface;
import com.exceptions.RuntimeCryptoException;
import com.jna.model.DeviceInfo;
import com.jna.model.DeviceRunStatus;
import com.jna.model.GBErrorCode_SDR;
import com.jna.model.dsa.DSArefKeyPair;
import com.jna.model.dsa.DSArefSignature;
import com.jna.model.dsa.IDSArefPrivateKey;
import com.jna.model.dsa.IDSArefPublicKey;
import com.jna.model.ecdsa.ECDSArefKeyPair;
import com.jna.model.ecdsa.ECDSArefPrivateKey;
import com.jna.model.ecdsa.ECDSArefPublicKey;
import com.jna.model.ecdsa.ECDSArefSignature;
import com.jna.model.rsa.*;
import com.jna.model.sm2.*;
import com.provider.ProviderConfig;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.util.BytesUtil;
import com.util.ECDSAUtil;
import com.util.SymmetryUtil;
import java.math.BigInteger;


public final class LibCrypto implements ILibCrypto {

    private static String address;
    private static PointerByReference phDeviceHandle;

    // TODO 当前SDF底层对大块数据buffer设定的长度就是16384
    private static final int MAX_INPUT_LENGTH = 16384;

    public static final int SM2_BLOCK_LENGTH = 136;


    static {
        try {
            //address = FileUtil.getFileAsString("address.conf");
            ProviderConfig a = ProviderConfig.getProviderConfig();
            address = a.getFirstConfig();
        } catch (Exception e) {
            throw new RuntimeException("Load address.conf file error, " + e.getMessage());
        }
    }

    public LibCrypto() {
        this(address);
    }

    public LibCrypto(String conf) {
        setConfig(conf);
        openDevice();
    }

    private int setConfig(String conf) {
        int flag = SDFInterface.instanseLib.sdf_set_config_file(conf);
        if (flag != 0) {
            throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
        }
        return flag;
    }

    private void openDevice() {
        if (phDeviceHandle == null) {
            synchronized (LibCrypto.class) {
                if (phDeviceHandle == null) {
                    PointerByReference ppDevice = new PointerByReference(Pointer.NULL);
                    int flag = SDFInterface.instanseLib.SDF_OpenDevice(ppDevice);
                    if (flag != GBErrorCode_SDR.SDR_OK) {
                        throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
                    }
                    phDeviceHandle = ppDevice;
                }
            }
        }
    }


    @Override
    public DeviceInfo getDeviceInfo() {

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        DeviceInfo deviceInfo = new DeviceInfo();
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            int flag = SDFInterface.instanseLib.SDF_GetDeviceInfo(sessionPointer, deviceInfo);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }
        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return deviceInfo;
    }


    @Override
    public DeviceRunStatus getDeviceRunStatus() {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }


    @Override
    public int[] getKeyStatus(int keyType) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }


    @Override
    public byte[] generateRandom(int randomLength) {
        if (randomLength <= 0) {
            throw new IllegalArgumentException("Illegal random length.");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] random = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            random = new byte[randomLength];
            Pointer sessionPointer = sessionReference.getValue();
            int flag = SDFInterface.instanseLib.SDF_GenerateRandom(sessionPointer, randomLength, random);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return random;
    }


    @Override
    public IRSArefPublicKey exportRSAPublicKey(int keyIndex, int keyType) {
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        RSArefPublicKeyEx publicKeyEx = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            publicKeyEx = new RSArefPublicKeyEx();
            int flag = 0;
            if (keyType == 2) {
                flag = SDFInterface.instanseLib.SDF_ExportEncPublicKey_RSA(sessionPointer, keyIndex, publicKeyEx);
            } else {
                flag = SDFInterface.instanseLib.SDF_ExportSignPublicKey_RSA(sessionPointer, keyIndex, publicKeyEx);
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }

        IRSArefPublicKey publicKey = null;
        if (publicKeyEx.bits <= 2048) {
            publicKey = new RSArefPublicKeyLite(publicKeyEx.getBits(), BytesUtil.subbytes(publicKeyEx.getM(), 0, 256), BytesUtil.subbytes(publicKeyEx.getM(), 256, 256));
        } else {
            publicKey = new RSArefPublicKeyEx(publicKeyEx.getBits(), publicKeyEx.getM(), publicKeyEx.getE());
        }

        return publicKey;
    }

    @Override
    public RSArefKeyPair generateRSAKeyPair(int keySize) {
        if (keySize < 1024 || keySize > 4096 || keySize % 128 != 0) {
            throw new IllegalArgumentException("Illegal key length:" + keySize);
        }
//        if (keySize >= 1024 && keySize <= 4096 && keySize % 128 == 0)

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        IRSArefPublicKey publicKey = null;
        IRSArefPrivateKey privateKey = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            // 1024bits或2048bits属于标准组
            if (keySize <= 2048) {
                publicKey = new RSArefPublicKeyLite.ByReference();
                privateKey = new RSArefPrivateKeyLite.ByReference();
            } else {
                // 3072bits或4096bits属于扩展组
                publicKey = new RSArefPublicKeyEx.ByReference();
                privateKey = new RSArefPrivateKeyEx.ByReference();
            }
            Pointer sessionPointer = sessionReference.getValue();
            int flag = SDFInterface.instanseLib.SDF_GenerateKeyPair_RSA(sessionPointer, keySize, publicKey, privateKey);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return new RSArefKeyPair(publicKey, privateKey);
    }

    @Override
    public RSArefKeyPair generateRSAKeyPair(int keySize, int exponent) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public RSArefKeyPair generateRSAKeyPair(int keyIndex, int keyType, int keySize) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public byte[] rsaInternalPublicKey(int keyIndex, int keyType, byte[] input) {
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType + ".");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            RSArefPublicKeyEx pRsaPubKey = new RSArefPublicKeyEx();
            int keyFlag = 0;
            if (keyType == 2) {
                keyFlag = SDFInterface.instanseLib.SDF_ExportEncPublicKey_RSA(sessionPointer, keyIndex, pRsaPubKey);
            } else {
                keyFlag = SDFInterface.instanseLib.SDF_ExportSignPublicKey_RSA(sessionPointer, keyIndex, pRsaPubKey);
            }
            if (keyFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(keyFlag));
            }

            IRSArefPublicKey publicKey = null;
            if (pRsaPubKey.bits <= 2048) {
                publicKey = new RSArefPublicKeyLite(pRsaPubKey.getBits(), BytesUtil.subbytes(pRsaPubKey.getM(), 0, 256), BytesUtil.subbytes(pRsaPubKey.getM(), 256, 256));
            } else {
                publicKey = new RSArefPublicKeyEx(pRsaPubKey.getBits(), pRsaPubKey.getM(), pRsaPubKey.getE());
            }
            int keyLenth = publicKey.getBits() >> 3;
            if (keyLenth != input.length) {
                throw new RuntimeCryptoException("Illegal input data length[" + keyLenth + "]:" + input.length);
            }

            BigInteger inputInteger = new BigInteger(1, input);
            BigInteger publicM = new BigInteger(1, publicKey.getM());
            if (inputInteger.compareTo(publicM) > 0) {
                throw new RuntimeCryptoException("Illegal input data >publickey.M");
            }

            IntByReference puiOutputLength = new IntByReference(0);
            pucDataOutput = new byte[input.length];
            int flag = 0;
            if (keyType == 1) {
                flag = SDFInterface.instanseLib.SDF_InternalPublicKeyOperation_RSA(sessionPointer, keyIndex * 2 - 1, input, input.length, pucDataOutput, puiOutputLength);
            } else {
                flag = SDFInterface.instanseLib.SDF_InternalPublicKeyOperation_RSA(sessionPointer, keyIndex * 2, input, input.length, pucDataOutput, puiOutputLength);
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return pucDataOutput;
    }

    @Override
    public byte[] rsaInternalPrivateKey(int keyIndex, int keyType, byte[] input) {
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType);
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            RSArefPublicKeyEx pRsaPubKey = new RSArefPublicKeyEx();
            int keyFlag = 0;
            if (keyType == 2) {
                keyFlag = SDFInterface.instanseLib.SDF_ExportEncPublicKey_RSA(sessionPointer, keyIndex, pRsaPubKey);
            } else {
                keyFlag = SDFInterface.instanseLib.SDF_ExportSignPublicKey_RSA(sessionPointer, keyIndex, pRsaPubKey);
            }
            if (keyFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(keyFlag));
            }

            IRSArefPublicKey publicKey = null;
            if (pRsaPubKey.bits <= 2048) {
                publicKey = new RSArefPublicKeyLite(pRsaPubKey.getBits(), BytesUtil.subbytes(pRsaPubKey.getM(), 0, 256), BytesUtil.subbytes(pRsaPubKey.getM(), 256, 256));
            } else {
                publicKey = new RSArefPublicKeyEx(pRsaPubKey.getBits(), pRsaPubKey.getM(), pRsaPubKey.getE());
            }
            int keyLenth = publicKey.getBits() >> 3;
            if (keyLenth != input.length) {
                throw new RuntimeCryptoException("Illegal input data length[" + keyLenth + "]:" + input.length);
            }

            BigInteger inputInteger = new BigInteger(1, input);
            BigInteger publicM = new BigInteger(1, publicKey.getM());
            if (inputInteger.compareTo(publicM) > 0) {
                throw new RuntimeCryptoException("Illegal input data >publickey.M");
            }

            IntByReference puiOutputLength = new IntByReference(0);
            pucDataOutput = new byte[input.length];
            int flag = 0;
            if (keyType == 1) {
                flag = SDFInterface.instanseLib.SDF_InternalPrivateKeyOperation_RSA(sessionPointer, keyIndex * 2 - 1, input, input.length, pucDataOutput, puiOutputLength);
            } else {
                flag = SDFInterface.instanseLib.SDF_InternalPrivateKeyOperation_RSA(sessionPointer, keyIndex * 2, input, input.length, pucDataOutput, puiOutputLength);
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return pucDataOutput;
    }

    @Override
    public byte[] rsaExternalPublicKey(IRSArefPublicKey refPublicKey, byte[] input) {
        if (refPublicKey == null) {
            throw new IllegalArgumentException("The PublicKey data is null.");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }
        if (refPublicKey.getBits() >> 3 != input.length) {
            throw new IllegalArgumentException("Illegal input data length:" + input.length);
        }

        BigInteger inputInteger = new BigInteger(1, input);
        BigInteger publicM = new BigInteger(1, refPublicKey.getM());
        if (inputInteger.compareTo(publicM) > 0) {
            throw new RuntimeCryptoException("Illegal input data >publickey.M");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            IntByReference puiOutputLength = new IntByReference(0);
            pucDataOutput = new byte[input.length];
            int flag = SDFInterface.instanseLib.SDF_ExternalPublicKeyOperation_RSA(sessionPointer, refPublicKey, input, input.length, pucDataOutput, puiOutputLength);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }
        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }

        return pucDataOutput;
    }

    @Override
    public byte[] rsaExternalPrivateKey(IRSArefPrivateKey refPrivateKey, byte[] input) {
        if (null == refPrivateKey) {
            throw new IllegalArgumentException("The PrivateKey data is null.");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }
        int privateLenght = refPrivateKey.getBits() >> 3;
        if (privateLenght != input.length) {
            throw new IllegalArgumentException("Illegal input data length:" + input.length + "private length:" + privateLenght);
        }

        BigInteger inputInteger = new BigInteger(1, input);
        BigInteger publicM = new BigInteger(1, refPrivateKey.getM());
        if (inputInteger.compareTo(publicM) > 0) {
            throw new RuntimeCryptoException("Illegal input data > publickey.M");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            IntByReference puiOutputLength = new IntByReference(0);
            pucDataOutput = new byte[input.length];
            int flag = SDFInterface.instanseLib.SDF_ExternalPrivateKeyOperation_RSA(sessionPointer, refPrivateKey, input, input.length, pucDataOutput, puiOutputLength);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }
        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return pucDataOutput;
    }

    @Override
    public void rsaImportKeyPair(int keyIndex, int keyType, IRSArefPublicKey refPublicKey, IRSArefPrivateKey refPrivateKey) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public SM2refPublicKey exportSM2PublicKey(int keyIndex, int keyType) {
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        SM2refPublicKey pucPublicKey = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            pucPublicKey = new SM2refPublicKey();
            int flag = 0;
            if (keyType == 1) {
                flag = SDFInterface.instanseLib.SDF_ExportSignPublicKey_ECC(sessionPointer, keyIndex, pucPublicKey);
            } else {
                flag = SDFInterface.instanseLib.SDF_ExportEncPublicKey_ECC(sessionPointer, keyIndex, pucPublicKey);
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }

        return new SM2refPublicKey(pucPublicKey.getX(), pucPublicKey.getY());
    }

    @Override
    public SM2refKeyPair generateSM2KeyPair(int keySize) {
        if (keySize != 256) {
            throw new IllegalArgumentException("Illegal SM2 key length:" + keySize);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        SM2refPublicKey pucPublicKey = null;
        SM2refPrivateKey pucPrivateKey = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            pucPublicKey = new SM2refPublicKey();
            pucPrivateKey = new SM2refPrivateKey();
            int flag = SDFInterface.instanseLib.SDF_GenerateKeyPair_ECC(sessionPointer, 131072, keySize, pucPublicKey, pucPrivateKey);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }
        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return new SM2refKeyPair(pucPublicKey, pucPrivateKey);
    }

    @Override
    public SM2refKeyPair generateSM2KeyPair(int keyIndex, int keyType, int keySize) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public SM2refCipher sm2InternalEncrypt(int keyIndex, int keyType, byte[] input) {
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType);
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length > SM2_BLOCK_LENGTH) {
            throw new IllegalArgumentException("Illegal input data length:" + input.length);
        }
        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        SM2refCipher sm2refCipher = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            sm2refCipher = new SM2refCipher();
            int flag = 0;
            if (keyType == 1) {
                flag = SDFInterface.instanseLib.SDF_InternalEncrypt_ECC(sessionPointer, keyIndex, 131328, input, input.length, sm2refCipher);
            } else {
                flag = SDFInterface.instanseLib.SDF_InternalEncrypt_ECC(sessionPointer, keyIndex, 132096, input, input.length, sm2refCipher);
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }

        return sm2refCipher;
    }

    @Override
    public byte[] sm2InternalDecrypt(int keyIndex, int keyType, SM2refCipher refCipher) {
        if (refCipher == null) {
            throw new IllegalArgumentException("The SM2refCipher data is null.");
        }
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            IntByReference puiOutputLength = new IntByReference(0);
            pucDataOutput = new byte[refCipher.cLength];
            int flag = 0;
            if (keyType == 1) {
                flag = SDFInterface.instanseLib.SDF_InternalDecrypt_ECC(sessionPointer, keyIndex, 131328, refCipher, pucDataOutput, puiOutputLength);
            } else {
                flag = SDFInterface.instanseLib.SDF_InternalDecrypt_ECC(sessionPointer, keyIndex, 132096, refCipher, pucDataOutput, puiOutputLength);
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }

        return pucDataOutput;
    }

    @Override
    public SM2refCipher sm2ExternalEncrypt(SM2refPublicKey publicKey, byte[] input) {
        if (publicKey == null) {
            throw new IllegalArgumentException("The SM2refPublicKey data is null.");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length > SM2_BLOCK_LENGTH) {
            throw new IllegalArgumentException("Illegal input data length:" + input.length);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        SM2refCipher sm2refCipher = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            sm2refCipher = new SM2refCipher();
            int flag = SDFInterface.instanseLib.SDF_ExternalEncrypt_ECC(sessionPointer, 131328, publicKey, input, input.length, sm2refCipher);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return sm2refCipher;
    }

    @Override
    public byte[] sm2ExternalDecrypt(SM2refPrivateKey privateKey, SM2refCipher refCipher) {
        if (privateKey == null) {
            throw new IllegalArgumentException("The SM2refPrivateKey data is null.");
        }
        if (refCipher == null) {
            throw new IllegalArgumentException("The SM2refCipher data is null.");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            IntByReference puiOutputLength = new IntByReference(refCipher.cLength);
            pucDataOutput = new byte[refCipher.cLength];
            int flag = SDFInterface.instanseLib.SDF_ExternalDecrypt_ECC(sessionPointer, 131328, privateKey, refCipher, pucDataOutput, puiOutputLength);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }

        return pucDataOutput;
    }

    @Override
    public SM2refSignature sm2InternalSign(int keyIndex, int keyType, byte[] input) {
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType);
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length != 32) {
            throw new IllegalArgumentException("Illegal input data length:" + input.length);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        SM2refSignature sm2refSignature = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            sm2refSignature = new SM2refSignature();
            int flag = 0;
            if (keyType == 1) {
                flag = SDFInterface.instanseLib.SDF_InternalSign_ECC_Ex(sessionPointer, keyIndex, 131328, input, input.length, sm2refSignature);
            } else {
                flag = SDFInterface.instanseLib.SDF_InternalSign_ECC_Ex(sessionPointer, keyIndex, 132096, input, input.length, sm2refSignature);
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }

        return sm2refSignature;
    }

    @Override
    public boolean sm2InternalVerify(int keyIndex, int keyType, byte[] dataInput, SM2refSignature refSig) {
        if (refSig == null) {
            throw new IllegalArgumentException("The SM2refSignature data is null.");
        }
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType);
        }
        if (dataInput == null || dataInput.length == 0) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (dataInput.length != 32) {
            throw new IllegalArgumentException("Illegal input data length:" + dataInput.length);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        int flag = 1;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            if (keyType == 1) {
                flag = SDFInterface.instanseLib.SDF_InternalVerify_ECC_Ex(sessionPointer, keyIndex, 131328, dataInput, dataInput.length, refSig);
            } else {
                flag = SDFInterface.instanseLib.SDF_InternalVerify_ECC_Ex(sessionPointer, keyIndex, 132096, dataInput, dataInput.length, refSig);
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }
        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }

        return flag == GBErrorCode_SDR.SDR_OK;
    }

    @Override
    public SM2refSignature sm2ExternalSign(SM2refPrivateKey refPrivateKey, byte[] input) {
        if (refPrivateKey == null) {
            throw new IllegalArgumentException("The SM2refPrivateKey data is null.");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length != 32) {
            throw new IllegalArgumentException("Illegal input data length is not 32, inputlength: " + input.length);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        SM2refSignature sm2refSignature = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            sm2refSignature = new SM2refSignature();
            int flag = SDFInterface.instanseLib.SDF_ExternalSign_ECC(sessionPointer, 131328, refPrivateKey, input, input.length, sm2refSignature);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }

        return sm2refSignature;
    }

    @Override
    public boolean sm2ExternalVerify(SM2refPublicKey refPublicKey, byte[] input, SM2refSignature refSig) {
        if (refPublicKey == null) {
            throw new IllegalArgumentException("The SM2refPublicKey data is null.");
        }
        if (refSig == null) {
            throw new IllegalArgumentException("The SM2refSignature data is null.");
        }
        if (input == null || input.length == 0) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length != 32) {
            throw new IllegalArgumentException("Illegal input data length is not 32, inputlength: " + input.length);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        int flag = 1;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            flag = SDFInterface.instanseLib.SDF_ExternalVerify_ECC(sessionPointer, 131328, refPublicKey, input, input.length, refSig);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }
        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return flag == GBErrorCode_SDR.SDR_OK;
    }

    @Override
    public byte[] sm2KeyAgreement(int flag, int keyIndex, SM2refPublicKey ownTmpPubKey, SM2refPrivateKey ownTmpPriKey, SM2refPublicKey opPubKey, SM2refPublicKey opTmpPubKey, int keyBits, byte[] ownId, byte[] opId) throws Exception {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public void sm2ImportKeyPair(int keyIndex, int keyType, SM2refPublicKey refPublicKey, SM2refPrivateKey refPrivateKey) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public ECDSArefKeyPair generateECDSAKeyPair(int keySize, int curetype) {
        if (!ECDSAUtil.checkCurveType(curetype)) {
            throw new IllegalArgumentException("Illegal ECDSA curve parameters( " + curetype + " )");
        }
        if (!ECDSAUtil.checkKeyLength(curetype, keySize)) {
            throw new IllegalArgumentException("Illegal ECDSA curve parameters( " + curetype + " )," + "key n( " + keySize + " )");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        ECDSArefPublicKey pucPublicKey = null;
        ECDSArefPrivateKey pucPrivateKey = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            pucPublicKey = new ECDSArefPublicKey();
            pucPrivateKey = new ECDSArefPrivateKey();
            if (curetype == 524289) {
                curetype = 0;
            }
            int flag = SDFInterface.instanseLib.SDF_GenerateKeyPair_ECDSA(sessionPointer, 524288, keySize, curetype, pucPublicKey, pucPrivateKey);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }
        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        if (pucPublicKey.getCurvetype() == 0) {
            pucPublicKey.setCurvetype(524289);
            pucPrivateKey.setCurvetype(524289);
        }
        return new ECDSArefKeyPair(pucPublicKey, pucPrivateKey);
    }

    @Override
    public ECDSArefPublicKey exportECDSAPublicKey(int keyIndex, int keyType) {
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        ECDSArefPublicKey pucPublicKey = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            pucPublicKey = new ECDSArefPublicKey();
            int flag = 0;
            if (keyType == 1) {
                flag = SDFInterface.instanseLib.SDF_ExportSignPublicKey_ECDSA(sessionPointer, keyIndex, pucPublicKey);
            } else {
                flag = SDFInterface.instanseLib.SDF_ExportEncPublicKey_ECDSA(sessionPointer, keyIndex, pucPublicKey);
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        if (pucPublicKey.getCurvetype() == 0) {
            pucPublicKey.setCurvetype(524289);
        }
        return pucPublicKey;
    }

    @Override
    public ECDSArefSignature ecdsaInternalSign(int keyIndex, int keyType, byte[] input) {
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType);
        }
        if (keyIndex < 1) {
            throw new IllegalArgumentException("Illegal key index( " + keyIndex + " )");
        }
        if (input == null || input.length < 1) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        ECDSArefSignature refSignature = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            byte[] signOut = new byte[160];
            IntByReference uiSignatureDataLength = new IntByReference(0);
            refSignature = new ECDSArefSignature();
            int flag = 0;
            if (keyType == 1) {
                flag = SDFInterface.instanseLib.SDF_InternalSign_ECDSA(sessionPointer, keyIndex, 524544, input, input.length, signOut, uiSignatureDataLength);
            } else {
                flag = SDFInterface.instanseLib.SDF_InternalSign_ECDSA(sessionPointer, keyIndex, 524800, input, input.length, signOut, uiSignatureDataLength);
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

            int signLen = uiSignatureDataLength.getValue();
            byte[] signResult = new byte[signLen];
            System.arraycopy(signOut, 0, signResult, 0, signLen);
            refSignature.decode(signResult);

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return refSignature;
    }

    @Override
    public boolean ecdsaInternalVerify(int keyIndex, int keyType, byte[] input, ECDSArefSignature refSig) {
        if (refSig == null) {
            throw new IllegalArgumentException("The ECDSArefSignature data is null.");
        }
        if (keyIndex < 1) {
            throw new IllegalArgumentException("Illegal key index( " + keyIndex + " )");
        }
        if (keyType != 1 && keyType != 2) {
            throw new IllegalArgumentException("Illegal key type(KEY_TYPE_SIGN|KEY_TYPE_ENC):" + keyType);
        }
        if (input == null || input.length < 1) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        int flag = 1;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            if (keyType == 1) {
                flag = SDFInterface.instanseLib.SDF_InternalVerify_ECDSA(sessionPointer, keyIndex, 524544, input, input.length, refSig, refSig.size());
            } else {
                flag = SDFInterface.instanseLib.SDF_InternalVerify_ECDSA(sessionPointer, keyIndex, 524800, input, input.length, refSig, refSig.size());
            }
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return flag == GBErrorCode_SDR.SDR_OK;
    }

    @Override
    public ECDSArefSignature ecdsaExternalSign(ECDSArefPrivateKey refPrivateKey, byte[] input) {
        if (refPrivateKey == null) {
            throw new IllegalArgumentException("The ECDSArefPrivateKey data is null.");
        }
        if (input == null || input.length < 1) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        ECDSArefSignature refSignature = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            if (refPrivateKey.getCurvetype() == 524289) {
                refPrivateKey.setCurvetype(0);
            }
            byte[] signOut = new byte[160];
            IntByReference uiSignatureDataLength = new IntByReference(0);
            refSignature = new ECDSArefSignature();
            int flag = SDFInterface.instanseLib.SDF_ExternalSign_ECDSA(sessionPointer, 524544, refPrivateKey, input, input.length, signOut, uiSignatureDataLength);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

            int signLen = uiSignatureDataLength.getValue();
            byte[] signResult = new byte[signLen];
            System.arraycopy(signOut, 0, signResult, 0, signLen);
            refSignature.decode(signResult);

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return refSignature;
    }


    @Override
    public boolean ecdsaExternalVerify(ECDSArefPublicKey refPublicKey, byte[] input, ECDSArefSignature refSig) {
        if (refPublicKey == null) {
            throw new IllegalArgumentException("The ECDSArefPublicKey data is null.");
        }
        if (refSig == null) {
            throw new IllegalArgumentException("The ECDSArefSignature data is null.");
        }
        if (input == null || input.length < 1) {
            throw new IllegalArgumentException("The input data is null.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        int flag = 1;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            if (refPublicKey.getCurvetype() == 524289) {
                refPublicKey.setCurvetype(0);
            }
            Pointer sessionPointer = sessionReference.getValue();
            flag = SDFInterface.instanseLib.SDF_ExternalVerify_ECDSA(sessionPointer, 524544, refPublicKey, input, input.length, refSig, refSig.size());
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }
        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return flag == GBErrorCode_SDR.SDR_OK;
    }

    @Override
    public DSArefKeyPair generateDSAKeyPair(int keySize) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public IDSArefPublicKey exportDSAPublicKey(int keyIndex, int keyType) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public DSArefSignature dsaInternalSign(int keyIndex, int keyType, byte[] input) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public boolean dsaInternalVerify(int keyIndex, int keyType, byte[] dataInput, DSArefSignature refSig) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public DSArefSignature dsaExternalSign(IDSArefPrivateKey refPrivateKey, byte[] input) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public boolean dsaExternalVerify(IDSArefPublicKey refPublicKey, byte[] dataInput, DSArefSignature refSig) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public void generateKey(int keyIndex, int keySize) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public byte[] encrypt(int algId, byte[] key, byte[] iv, byte[] input) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("The Key data is null.");
        }
        if (!SymmetryUtil.isRightAlg(algId)) {
            throw new IllegalArgumentException("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
        }
        if (!SymmetryUtil.isRightIV(algId, iv)) {
            throw new IllegalArgumentException("IV data length error.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }
        if (!SymmetryUtil.isRightInput(algId, input)) {
            throw new IllegalArgumentException("Input data length error.");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            PointerByReference phKeyHandle = new PointerByReference(Pointer.NULL);
            int flag = SDFInterface.instanseLib.SDF_ImportKey(sessionPointer, key, key.length, phKeyHandle);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

            IntByReference puiOutputLength = new IntByReference(0);
            pucDataOutput = new byte[input.length];
            flag = SDFInterface.instanseLib.SDF_Encrypt(sessionPointer, phKeyHandle.getValue(), algId, iv, input, input.length, pucDataOutput, puiOutputLength);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return pucDataOutput;
    }

    @Override
    public byte[] decrypt(int algId, byte[] key, byte[] iv, byte[] input) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("The Key data is null.");
        }
        if (!SymmetryUtil.isRightAlg(algId)) {
            throw new IllegalArgumentException("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
        }
        if (!SymmetryUtil.isRightIV(algId, iv)) {
            throw new IllegalArgumentException("IV data length error.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }
        if (!SymmetryUtil.isRightInput(algId, input)) {
            throw new IllegalArgumentException("Input data length error.");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            PointerByReference phKeyHandle = new PointerByReference(Pointer.NULL);
            int flag = SDFInterface.instanseLib.SDF_ImportKey(sessionPointer, key, key.length, phKeyHandle);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

            IntByReference puiOutputLength = new IntByReference(0);
            pucDataOutput = new byte[input.length];
            flag = SDFInterface.instanseLib.SDF_Decrypt(sessionPointer, phKeyHandle.getValue(), algId, iv, input, input.length, pucDataOutput, puiOutputLength);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return pucDataOutput;
    }


    @Override
    public byte[] encrypt(int algId, int keyIndex, byte[] iv, byte[] input) {
        if (!SymmetryUtil.isRightAlg(algId)) {
            throw new IllegalArgumentException("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
        }
        if (!SymmetryUtil.isRightIV(algId, iv)) {
            throw new IllegalArgumentException("IV data length error.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }
        if (!SymmetryUtil.isRightInput(algId, input)) {
            throw new IllegalArgumentException("Input data length error.");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            PointerByReference phKeyHandle = new PointerByReference(Pointer.NULL);
            int flag = SDFInterface.instanseLib.SDF_GetSymmKeyHandle(sessionPointer, keyIndex, phKeyHandle);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

            IntByReference puiOutputLength = new IntByReference(0);
            pucDataOutput = new byte[input.length];
            flag = SDFInterface.instanseLib.SDF_Encrypt(sessionPointer, phKeyHandle.getValue(), algId, iv, input, input.length, pucDataOutput, puiOutputLength);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return pucDataOutput;
    }

    @Override
    public byte[] decrypt(int algId, int keyIndex, byte[] iv, byte[] input) {
        if (!SymmetryUtil.isRightAlg(algId)) {
            throw new IllegalArgumentException("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
        }
        if (!SymmetryUtil.isRightIV(algId, iv)) {
            throw new IllegalArgumentException("IV data length error.");
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }
        if (!SymmetryUtil.isRightInput(algId, input)) {
            throw new IllegalArgumentException("Input data length error.");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            PointerByReference phKeyHandle = new PointerByReference(Pointer.NULL);
            int flag = SDFInterface.instanseLib.SDF_GetSymmKeyHandle(sessionPointer, keyIndex, phKeyHandle);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

            IntByReference puiOutputLength = new IntByReference(0);
            pucDataOutput = new byte[input.length];
            flag = SDFInterface.instanseLib.SDF_Decrypt(sessionPointer, phKeyHandle.getValue(), algId, iv, input, input.length, pucDataOutput, puiOutputLength);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return pucDataOutput;
    }


    @Override
    public byte[] encryptAdd(int algId, byte[] key, byte[] iv, byte[] input, byte[] addInput) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public byte[] decryptAdd(int algId, byte[] key, byte[] iv, byte[] input, byte[] addInput) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public byte[] encryptAdd(int algId, int keyIndex, byte[] iv, byte[] input, byte[] addInput) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public byte[] decryptAdd(int algId, int keyIndex, byte[] iv, byte[] input, byte[] addInput) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public void inputKEK(int keyIndex, byte[] key) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public void importKeyPairECC(int keyIndex, int keyType, int keyPriKeyIndex, byte[] eccPairEnvelopedKey) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }


    @Override
    public void importEncKeyPairECC(int keyIndex, byte[] eccPairEnvelopedKey) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }


    @Override
    public byte[] genKCV(int keyIndex) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public byte[] generateHMAC(int algId, int keyIndex, byte[] input) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public byte[] generateHMAC(int algId, byte[] key, byte[] input) {
        if (!SymmetryUtil.isRightAlg(algId)) {
            throw new IllegalArgumentException("Illegal GBAlgorithmID_SGD:" + Integer.toHexString(algId));
        }
        if (input.length > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("The input data length must be less than " + MAX_INPUT_LENGTH);
        }
        if (!SymmetryUtil.isRightInput(algId, input)) {
            throw new IllegalArgumentException("Input data length error.");
        }

        PointerByReference sessionReference = new PointerByReference(Pointer.NULL);
        byte[] pucDataOutput = null;
        boolean sessionFlag = false;
        try {
            Pointer pointer = phDeviceHandle.getValue();
            int openFlag = SDFInterface.instanseLib.SDF_OpenSession(pointer, sessionReference);
            if (openFlag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(openFlag));
            }
            sessionFlag = true;

            Pointer sessionPointer = sessionReference.getValue();
            PointerByReference phKeyHandle = new PointerByReference(Pointer.NULL);
            IntByReference puiOutputLength = new IntByReference(0);
            pucDataOutput = new byte[input.length];

            int flag = SDFInterface.instanseLib.SDF_ImportKey(sessionPointer, key, key.length, phKeyHandle);
            if (flag != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag));
            }

            byte pbIV[] = {(byte) 0xe8, (byte) 0x3d, (byte) 0x17, (byte) 0x15, (byte) 0xac, (byte) 0xf3,
                    (byte) 0x48, (byte) 0x63, (byte) 0xac, (byte) 0xeb, (byte) 0x93,
                    (byte) 0xe0, (byte) 0xe5, (byte) 0xab, (byte) 0x8b, (byte) 0x90};
            int flag2 = SDFInterface.instanseLib.SDF_CalculateMAC(sessionPointer, phKeyHandle.getValue(), algId, pbIV, input, input.length, pucDataOutput, puiOutputLength);
            if (flag2 != GBErrorCode_SDR.SDR_OK) {
                throw new RuntimeCryptoException(GBErrorCode_SDR.toErrorInfo(flag2));
            }

        } finally {
            if (sessionFlag) {
                int closeFlag = SDFInterface.instanseLib.SDF_CloseSession(sessionReference.getValue());
                if (closeFlag != GBErrorCode_SDR.SDR_OK) {
                    System.out.println(GBErrorCode_SDR.toErrorInfo(closeFlag));
                }
            }
        }
        return pucDataOutput;
    }


    @Override
    public byte[] genPBKDF2Key(int hashAlg, int iteraCount, int outLength, char[] pwd, byte[] salt) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public byte[] ecdhAgreement(int ecdsIndex, int keyType, byte[] pubKey) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public byte[] ecdhAgreement(byte[] priKey, byte[] pubKey) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public int hsmCreateFile(String fileName, int maxLength) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public byte[] hsmReadFile(String fileName, int startPosition, int readLength) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public int hsmWriteFile(String fileName, int startPosition, byte[] data) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

    @Override
    public int hsmDeleteFile(String fileName) {
        throw new UnsupportedOperationException("CardCrypto unrealized method...");
    }

}
