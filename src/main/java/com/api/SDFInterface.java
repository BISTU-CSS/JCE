package com.api;

import com.jna.model.DeviceInfo;
import com.jna.model.ecdsa.ECDSArefPrivateKey;
import com.jna.model.ecdsa.ECDSArefPublicKey;
import com.jna.model.ecdsa.ECDSArefSignature;
import com.jna.model.rsa.IRSArefPrivateKey;
import com.jna.model.rsa.IRSArefPublicKey;
import com.jna.model.sm2.SM2refCipher;
import com.jna.model.sm2.SM2refPrivateKey;
import com.jna.model.sm2.SM2refPublicKey;
import com.jna.model.sm2.SM2refSignature;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

public interface SDFInterface extends Library {
    //todo 根据不同系统加载不同库
    SDFInterface instanseLib = (SDFInterface) Native.load("libhsm_core.so", SDFInterface.class);

    int sdf_set_config_file(String device_conf);

    // 设备管理类函数

    /**
     * @param phDeviceHandle 返回设备句柄
     * @return 程序执行成功与否
     * @brief 打开设备：打开密码设备
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_OpenDevice(PointerByReference phDeviceHandle);

    /**
     * @param hDeviceHandle 已打开的设备句柄
     * @return 程序执行成功与否
     * @brief 关闭设备：关闭密码设备，并释放相关资源
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_CloseDevice(Pointer hDeviceHandle);

    /**
     * @param hDeviceHandle   已打开的设备句柄
     * @param phSessionHandle 返回与密码设备建立的新会话句柄
     * @return 程序执行成功与否
     * @brief 创建会话:创建与密码设备的会话
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_OpenSession(Pointer hDeviceHandle, PointerByReference phSessionHandle);

    /**
     * @param hSessionHandle 与密码设备建立的会话句柄
     * @return 程序执行成功与否
     * @brief 关闭会话:关闭与密码设备已建立的会话，并释放相关资源
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_CloseSession(Pointer hSessionHandle);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param pstDeviceInfo  设备能力描述信息，内容及格式见设备信息定义
     * @return 程序执行成功与否
     * @brief 获取设备信息:获取密码设备能力描述
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GetDeviceInfo(Pointer hSessionHandle, DeviceInfo pstDeviceInfo);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiLength       欲获取的随机数长度
     * @param pucRandom      缓冲区指针，用于存放获取的随机数
     * @return 程序执行成功与否
     * @brief 产生随机数:获取指定长度的随机数
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateRandom(Pointer hSessionHandle, int uiLength, byte[] pucRandom);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyIndex     密码设备存储私钥的索引值
     * @param pucPassword    使用私钥权限的标识码
     * @param uiPwdLength    私钥访问控制码的长度，不少于8字节
     * @return 程序执行成功与否
     * @brief 获取私钥使用权限:获取密码设备内部存储的指定索引私钥的使用权
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GetPrivateKeyAccessRight(Pointer hSessionHandle, int uiKeyIndex, byte[] pucPassword, int uiPwdLength);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyIndex     密码设备存储私钥的索引值
     * @return 程序执行成功与否
     * @brief 释放私钥使用权限:释放密码设备存储的指定索引私钥的使用授权
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ReleasePrivateKeyAccessRight(Pointer hSessionHandle, int uiKeyIndex);


    // 密钥管理类函数

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyIndex     密码设备存储的RSA密钥对索引值
     * @param pucPublicKey   RSA公钥结构
     * @return 程序执行成功与否
     * @brief 导出RSA签名公钥:导出密码设备内部存储的指定索引位置的签名公钥
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExportSignPublicKey_RSA(Pointer hSessionHandle, int uiKeyIndex, IRSArefPublicKey pucPublicKey);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyIndex     密码设备存储的RSA密钥对索引值
     * @param pucPublicKey   RSA公钥结构
     * @return 程序执行成功与否
     * @brief 导出RSA加密公钥:导出密码设备内部存储的指定索引位置的加密公钥
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExportEncPublicKey_RSA(Pointer hSessionHandle, int uiKeyIndex, IRSArefPublicKey pucPublicKey);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyBits      指定密钥模长
     * @param pucPublicKey   RSA公钥结构
     * @param pucPrivateKey  RSA私钥结构
     * @return 程序执行成功与否
     * @brief 产生RSA密钥对并输出:请求密码设备产生指定模长的RSA密钥对
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateKeyPair_RSA(Pointer hSessionHandle, int uiKeyBits, IRSArefPublicKey pucPublicKey, IRSArefPrivateKey pucPrivateKey);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiIPKIndex     密码设备内部存储加密公钥的索引值
     * @param uiKeyBits      指定产生的会话密钥长度
     * @param pucKey         缓冲区指针，用于存放返回的密钥密文
     * @param puiKeyLength   返回的密钥密文长度
     * @param phKeyHandle    返回的密钥句柄
     * @return 程序执行成功与否
     * @brief 生成会话密钥并用内部RSA公钥加密输出:生成会话密钥并用指定索引的内部加密公钥加密输出，同时返回密钥句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateKeyWithIPK_RSA(Pointer hSessionHandle, int uiIPKIndex, int uiKeyBits, byte[] pucKey, IntByReference puiKeyLength, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyBits      指定产生的会话密钥长度
     * @param pucPublicKey   输入的外部RSA公钥结构
     * @param pucKey         缓冲区指针，用于存放返回的密钥密文
     * @param puiKeyLength   返回的密钥密文长度
     * @param phKeyHandle    返回的密钥句柄
     * @return 程序执行成功与否
     * @brief 生成会话密钥并用外部RSA公钥加密输出:生成会话密钥并用外部公钥加密输出，同时返回密钥句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateKeyWithEPK_RSA(Pointer hSessionHandle, int uiKeyBits, IRSArefPublicKey pucPublicKey, byte[] pucKey, IntByReference puiKeyLength, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiISKIndex     密码设备内部存储加密私钥的索引值，对应于加密时的公钥
     * @param pucKey         缓冲区指针，用于存放输入的密钥密文
     * @param uiKeyLength    输入的密钥密文长度
     * @param phKeyHandle    返回的密钥句柄
     * @return 程序执行成功与否
     * @brief 导入会话密钥并用内部RSA私钥解密:导入会话密钥并用内部私钥解密，同时返回密钥句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ImportKeyWithISK_RSA(Pointer hSessionHandle, int uiISKIndex, byte[] pucKey, int uiKeyLength, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyIndex     密码设备存储的内部RSA加密密钥对索引值
     * @param pucPublicKey   外部RSA公钥结构
     * @param pucDEInput     缓冲区指针，用于存放输入的会话密钥密文
     * @param uiDELength     输入的会话密钥密文长度
     * @param pucDEOutput    缓冲区指针，用于存放输出的会话密钥密文
     * @param puiDELength    输出的会话密钥密文长度
     * @return 程序执行成功与否
     * @brief 基于RSA算法的数字信封转换:将由内部加密公钥加密的会话密钥转换为由外部指定的公钥加密，可用于数字信封转换
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExchangeDigitEnvelopeBaseOnRSA(Pointer hSessionHandle, int uiKeyIndex, IRSArefPublicKey pucPublicKey, byte[] pucDEInput, int uiDELength, byte[] pucDEOutput, IntByReference puiDELength);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyIndex     密码设备存储的ECC密钥对索引值
     * @param pucPublicKey   ECC公钥结构
     * @return 程序执行成功与否
     * @brief 导出ECC签名公钥:导出密码设备内部存储的指定索引位置的签名公钥
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExportSignPublicKey_ECC(Pointer hSessionHandle, int uiKeyIndex, SM2refPublicKey pucPublicKey);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyIndex     密码设备存储的ECC密钥对索引值
     * @param pucPublicKey   ECC公钥结构
     * @return 程序执行成功与否
     * @brief 导出ECC加密公钥:导出密码设备内部存储的指定索引位置的加密公钥
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExportEncPublicKey_ECC(Pointer hSessionHandle, int uiKeyIndex, SM2refPublicKey pucPublicKey);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiAlgID        指定算法标识
     * @param uiKeyBits      指定密钥长度
     * @param pucPublicKey   ECC公钥结构
     * @param pucPrivateKey  ECC私钥结构
     * @return 程序执行成功与否
     * @brief 产生ECC密钥对并输出:请求密码设备产生指定类型和模长的ECC密钥对
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateKeyPair_ECC(Pointer hSessionHandle, int uiAlgID, int uiKeyBits, SM2refPublicKey pucPublicKey, SM2refPrivateKey pucPrivateKey);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiIPKIndex     密码设备内部存储加密公钥的索引值
     * @param uiKeyBits      指定产生的会话密钥长度
     * @param pucKey         缓冲区指针，用于存放返回的密钥密文
     * @param phKeyHandle    返回的密钥句柄
     * @return 程序执行成功与否
     * @brief 生成会话密钥并用内部ECC公钥加密输出:生成会话密钥并用指定索引的内部ECC加密公钥加密输出，同时返回密钥句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateKeyWithIPK_ECC(Pointer hSessionHandle, int uiIPKIndex, int uiKeyBits, SM2refCipher pucKey, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyBits      指定产生的会话密钥长度
     * @param uiAlgID        外部ECC公钥的算法标识
     * @param pucPublicKey   输入的外部ECC公钥结构
     * @param pucKey         缓冲区指针，用于存放返回的密钥密文
     * @param phKeyHandle    返回的密钥句柄
     * @return 程序执行成功与否
     * @brief 生成会话密钥并用外部ECC公钥加密输出:生成会话密钥并用外部公钥加密输出，同时返回密钥句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateKeyWithEPK_ECC(Pointer hSessionHandle, int uiKeyBits, int uiAlgID, SM2refPublicKey pucPublicKey, SM2refCipher pucKey, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiISKIndex     密码设备内部存储加密私钥的索引值，对应于加密时的公钥
     * @param pucKey         缓冲区指针，用于存放输入的密钥密文
     * @param phKeyHandle    返回的密钥句柄
     * @return 程序执行成功与否
     * @brief 导入会话密钥并用内部ECC私钥解密:导入会话密钥并用内部ECC加密私钥解密，同时返回密钥句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ImportKeyWithISK_ECC(Pointer hSessionHandle, int uiISKIndex, SM2refCipher pucKey, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle         与设备建立的会话句柄
     * @param uiISKIndex             密码设备内部存储加密私钥的索引值，该私钥用于参与密钥协商
     * @param uiKeyBits              要求协商的密钥长度
     * @param pucSponsorID           参与密钥协商的发起方ID值
     * @param uiSponsorIDLength      发起方ID长度
     * @param pucSponsorPublicKey    返回的发起方ECC公钥结构
     * @param pucSponsorTmpPublicKey 返回的发起方临时ECC公钥结构
     * @param phAgreementHandle      返回的密钥协商句柄，用于计算协商密钥
     * @return 程序执行成功与否
     * @brief 生成密钥协商参数并输出:使用ECC密钥协商算法，为计算会话密钥而产生协商参数，同时返回指定索引位置的ECC公钥、临时ECC密钥对的公钥及协商句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateAgreementDataWithECC(Pointer hSessionHandle, int uiISKIndex, int uiKeyBits, byte[] pucSponsorID, int uiSponsorIDLength, SM2refPublicKey pucSponsorPublicKey, SM2refPublicKey pucSponsorTmpPublicKey, PointerByReference phAgreementHandle);

    /**
     * @param hSessionHandle          与设备建立的会话句柄
     * @param pucResponseID           外部输入的响应方ID值
     * @param uiResponseIDLength      外部输入的响应方ID长度
     * @param pucResponsePublicKey    外部输入的响应方ECC公钥结构
     * @param pucResponseTmpPublicKey 外部输入的响应方临时ECC公钥结构
     * @param hAgreementHandle        协商句柄，用于计算协商密钥
     * @param phKeyHandle             返回密钥句柄
     * @return 程序执行成功与否
     * @brief 计算会话密钥:生成密钥协商参数并输出使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateKeyWithECC(Pointer hSessionHandle, PointerByReference pucResponseID, int uiResponseIDLength, SM2refPublicKey pucResponsePublicKey, SM2refPublicKey pucResponseTmpPublicKey, Pointer hAgreementHandle, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle          与设备建立的会话句柄
     * @param uiISKIndex              密码设备内部存储加密私钥的索引值，该私钥用于参与密钥协商
     * @param uiKeyBits               协商后要求输出的密钥长度
     * @param pucResponseID           响应方ID值
     * @param uiResponseIDLength      响应方ID长度
     * @param pucSponsorID            发起方ID值
     * @param uiSponsorIDLength       发起方ID长度
     * @param pucSponsorPublicKey     外部输入的发起方ECC公钥结构
     * @param pucSponsorTmpPublicKey  外部输入的发起方临时ECC公钥结构
     * @param pucResponsePublicKey    返回的响应方ECC公钥结构
     * @param pucResponseTmpPublicKey 返回的响应方临时ECC公钥结构
     * @param phKeyHandle             返回的密钥句柄
     * @return 程序执行成功与否
     * @brief 产生协商数据并计算会话密钥:使用ECC密钥协商算法，产生协商参数并计算会话密钥，同时返回产生的协商参数和会话密钥句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateAgreementDataAndKeyWithECC(Pointer hSessionHandle, int uiISKIndex, int uiKeyBits, byte[] pucResponseID, int uiResponseIDLength, byte[] pucSponsorID, int uiSponsorIDLength, SM2refPublicKey pucSponsorPublicKey, SM2refPublicKey pucSponsorTmpPublicKey, SM2refPublicKey pucResponsePublicKey, SM2refPublicKey pucResponseTmpPublicKey, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyIndex     密码设备存储的内部ECC密钥对索引值
     * @param uiAlgID        外部ECC公钥的算法标识
     * @param pucPublicKey   外部ECC公钥结构
     * @param pucEncDataIn   缓冲区指针，用于存放输入的会话密钥密文
     * @param pucEncDataOut  缓冲区指针，用于存放输出的会话密钥密文
     * @return 程序执行成功与否
     * @brief 基于ECC算法的数字信封转换:将由内部加密公钥加密的会话密钥转换为由外部指定的公钥加密，可用于数字信封转换
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExchangeDigitEnvelopeBaseOnECC(Pointer hSessionHandle, int uiKeyIndex, int uiAlgID, SM2refPublicKey pucPublicKey, SM2refCipher pucEncDataIn, SM2refCipher pucEncDataOut);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiKeyBits      指定产生的会话密钥长度
     * @param uiAlgID        算法标识，指定对称加密算法
     * @param uiKEKIndex     密码设备内部存储的密钥加密密钥的 索引值
     * @param pucKey         缓冲区指针，用于存放返回的会话密钥密文
     * @param puiKeyLength   返回的密钥密文长度
     * @param phKeyHandle    返回的密钥句柄
     * @return 程序执行成功与否
     * @brief 生成会话密钥并用密钥加密密钥加密输出:生成会话密钥并用密钥加密密钥加密输出，同时返回密钥句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_GenerateKeyWithKEK(Pointer hSessionHandle, int uiKeyBits, int uiAlgID, int uiKEKIndex, byte[] pucKey, IntByReference puiKeyLength, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiAlgID        算法标识，指定对称加密算法
     * @param uiKEKIndex     密码设备内部存储的密钥加密密钥的 索引值
     * @param pucKey         缓冲区指针，用于存放返回的会话密钥密文
     * @param uiKeyLength    输入的密钥密文长度
     * @param phKeyHandle    返回的密钥句柄
     * @return 程序执行成功与否
     * @brief 导入会话密钥并用密钥加密密钥解密:导入会话密钥并用密钥加密密钥解密，同时返回会话密钥句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ImportKeyWithKEK(Pointer hSessionHandle, int uiAlgID, int uiKEKIndex, byte[] pucKey, int uiKeyLength, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param pucKey         缓冲区指针，用于存放输入的密钥明文
     * @param uiKeyLength    输入的密钥明文长度
     * @param phKeyHandle    返回的密钥句柄
     * @return 程序执行成功与否
     * @brief 导入明文会话密钥:与设备建立的会话句柄
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ImportKey(Pointer hSessionHandle, byte[] pucKey, int uiKeyLength, PointerByReference phKeyHandle);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param hKeyHandle     输入的密钥句柄
     * @return 程序执行成功与否
     * @brief 销毁会话密钥:销毁会话密钥，并释放为密钥句柄分配的内存等资源
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_DestroyKey(Pointer hSessionHandle, Pointer hKeyHandle);


    // 非对称密码运算类函数

    /**
     * @param hSessionHandle  与设备建立的会话句柄
     * @param pucPublicKey    外部RSA公钥结构
     * @param pucDataInput    缓冲区指针，用于存放输入的数据
     * @param uiInputLength   输入的数据长度
     * @param pucDataOutput   缓冲区指针，用于存放输出的数据
     * @param puiOutputLength 输出的数据长度
     * @return 程序执行成功与否
     * @brief 外部公钥RSA运算:指定使用外部公钥对数据进行运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExternalPublicKeyOperation_RSA(Pointer hSessionHandle, IRSArefPublicKey pucPublicKey, byte[] pucDataInput, int uiInputLength, byte[] pucDataOutput, IntByReference puiOutputLength);

    /**
     * @param hSessionHandle  与设备建立的会话句柄
     * @param pucPrivateKey   外部RSA私钥结构
     * @param pucDataInput    缓冲区指针，用于存放外部输入的数据
     * @param uiInputLength   输入的数据长度
     * @param pucDataOutput   缓冲区指针，用于存放输出的数据
     * @param puiOutputLength 输出的数据长度
     * @return 程序执行成功与否
     * @brief 外部私钥RSA运算:指定使用外部私钥对数据进行运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExternalPrivateKeyOperation_RSA(Pointer hSessionHandle, IRSArefPrivateKey pucPrivateKey, byte[] pucDataInput, int uiInputLength, byte[] pucDataOutput, IntByReference puiOutputLength);

    /**
     * @param hSessionHandle  与设备建立的会话句柄
     * @param uiKeyIndex      密码设备内部存储公钥的索引值
     * @param pucDataInput    缓冲区指针，用于存放外部输入的数据
     * @param uiInputLength   输入的数据长度
     * @param pucDataOutput   缓冲区指针，用于存放输出的数据
     * @param puiOutputLength 输出的数据长度
     * @return 程序执行成功与否
     * @brief 内部公钥RSA运算:使用内部指定索引的RSA公钥对数据进行运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_InternalPublicKeyOperation_RSA(Pointer hSessionHandle, int uiKeyIndex, byte[] pucDataInput, int uiInputLength, byte[] pucDataOutput, IntByReference puiOutputLength);

    /**
     * @param hSessionHandle  与设备建立的会话句柄
     * @param uiKeyIndex      密码设备内部存储私钥的索引值
     * @param pucDataInput    缓冲区指针，用于存放外部输入的数据
     * @param uiInputLength   输入的数据长度
     * @param pucDataOutput   缓冲区指针，用于存放输出的数据
     * @param puiOutputLength 输出的数据长度
     * @return 程序执行成功与否
     * @brief 内部私钥RSA运算:使用内部指定索引的RSA私钥对数据进行运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_InternalPrivateKeyOperation_RSA(Pointer hSessionHandle, int uiKeyIndex, byte[] pucDataInput, int uiInputLength, byte[] pucDataOutput, IntByReference puiOutputLength);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiAlgID        算法标识，指定使用的ECC算法
     * @param pucPrivateKey  外部ECC私钥结构
     * @param pucData        缓冲区指针，用于存放外部输入的数据
     * @param uiDataLength   输入的数据长度
     * @param pucSignature   缓冲区指针，用于存放输出的签名值数据
     * @return 程序执行成功与否
     * @brief 外部密钥ECC签名:使用外部ECC私钥对数据进行签名运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExternalSign_ECC(Pointer hSessionHandle, int uiAlgID, SM2refPrivateKey pucPrivateKey, byte[] pucData, int uiDataLength, SM2refSignature pucSignature);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiAlgID        算法标识，指定使用的ECC算法
     * @param pucPublicKey   外部ECC公钥结构
     * @param pucDataInput   缓冲区指针，用于存放外部输入的数据
     * @param uiInputLength  输入的数据长度
     * @param pucSignature   缓冲区指针，用于存放输入的签名值数据
     * @return 程序执行成功与否
     * @brief 外部密钥ECC验证:使用外部ECC公钥对ECC签名值进行验证运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExternalVerify_ECC(Pointer hSessionHandle, int uiAlgID, SM2refPublicKey pucPublicKey, byte[] pucDataInput, int uiInputLength, SM2refSignature pucSignature);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiISKIndex     密码设备内部存储的ECC签名私钥的索引值
     * @param pucData        缓冲区指针，用于存放外部输入的数据
     * @param uiDataLength   输入的数据长度
     * @param pucSignature   缓冲区指针，用于存放输出的签名值数据
     * @return 程序执行成功与否
     * @brief 内部密钥ECC签名:使用内部ECC私钥对数据进行签名运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_InternalSign_ECC(Pointer hSessionHandle, int uiISKIndex, byte[] pucData, int uiDataLength, SM2refSignature pucSignature);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiISKIndex     密码设备内部存储的ECC签名公钥的索引值
     * @param pucData        缓冲区指针，用于存放外部输入的数据
     * @param uiDataLength   输入的数据长度
     * @param pucSignature   缓冲区指针，用于存放输入的签名值数据
     * @return 程序执行成功与否
     * @brief 内部密钥ECC验证:使用内部ECC公钥对ECC签名值进行验证运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_InternalVerify_ECC(Pointer hSessionHandle, int uiISKIndex, byte[] pucData, int uiDataLength, SM2refSignature pucSignature);


    /**
     * 内部密钥ECC签名:使用内部ECC私钥对数据进行签名运算
     */
    int SDF_InternalSign_ECC_Ex(Pointer hSessionHandle, int var2, int var3, byte[] var4, int var5, SM2refSignature var6);

    /**
     * 内部密钥ECC验证:使用内部ECC公钥对ECC签名值进行验证运算
     */
    int SDF_InternalVerify_ECC_Ex(Pointer hSessionHandle, int var2, int var3, byte[] var4, int var5, SM2refSignature var6);


    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiAlgID        算法标识，指定使用的ECC算法
     * @param pucPublicKey   外部ECC公钥结构
     * @param pucData        缓冲区指针，用于存放外部输入的数据
     * @param uiDataLength   输入的数据长度
     * @param pucEncData     缓冲区指针，用于存放输出的数据密文
     * @return 程序执行成功与否
     * @brief 外部密钥ECC公钥加密:使用外部ECC公钥对数据进行加密运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExternalEncrypt_ECC(Pointer hSessionHandle, int uiAlgID, SM2refPublicKey pucPublicKey, byte[] pucData, int uiDataLength, SM2refCipher pucEncData);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiAlgID        算法标识，指定使用的ECC算法
     * @param pucPrivateKey  外部ECC私钥结构
     * @param pucEncData     ECC加密数据密文结构
     * @param pucData        缓冲区指针，用于存放输出的数据
     * @param puiDataLength  输出的数据长度
     * @return 程序执行成功与否
     * @brief 外部密钥ECC私钥解密:使用外部ECC私钥对数据进行解密运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ExternalDecrypt_ECC(Pointer hSessionHandle, int uiAlgID, SM2refPrivateKey pucPrivateKey, SM2refCipher pucEncData, byte[] pucData, IntByReference puiDataLength);


    /**
     * 内部密钥ECC公钥加密:使用内部ECC公钥对数据进行加密运算
     */
    int SDF_InternalEncrypt_ECC(Pointer hSessionHandle, int var2, int var3, byte[] var4, int var5, SM2refCipher var6);

    /**
     * 内部密钥ECC私钥解密:使用内部ECC私钥对数据进行解密运算
     */
    int SDF_InternalDecrypt_ECC(Pointer hSessionHandle, int var2, int var3, SM2refCipher var4, byte[] var5, IntByReference var6);


    // 对称密码运算类函数

    /**
     * @param hSessionHandle   与设备建立的会话句柄
     * @param hKeyHandle       指定的密钥句柄
     * @param uiAlgID          算法标识，指定对称加密算法
     * @param pucIV            缓冲区指针，用于存放输入和返回的IV数据
     * @param pucData          缓冲区指针，用于存放输入的数据明文
     * @param uiDataLength     输入的数据长度
     * @param pucEncData       缓冲区指针，用于存放输出的数据密文
     * @param puiEncDataLength 输出的数据密文长度
     * @return 程序执行成功与否
     * @brief 对称加密:使用指定的密钥句柄和IV对数据进行对称加密运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_Encrypt(Pointer hSessionHandle, Pointer hKeyHandle, int uiAlgID, byte[] pucIV, byte[] pucData, int uiDataLength, byte[] pucEncData, IntByReference puiEncDataLength);

    /**
     * @param hSessionHandle  与设备建立的会话句柄
     * @param hKeyHandle      指定的密钥句柄
     * @param uiAlgID         算法标识，指定对称解密算法
     * @param pucIV           缓冲区指针，用于存放输入和返回的IV数据
     * @param pucEncData      缓冲区指针，用于存放输入的数据密文
     * @param uiEncDataLength 输入的数据密文长度
     * @param pucData         缓冲区指针，用于存放输出的数据明文
     * @param puiDataLength   输出的数据明文长度
     * @return 程序执行成功与否
     * @brief 对称解密:使用指定的密钥句柄和IV对数据进行对称解密运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_Decrypt(Pointer hSessionHandle, Pointer hKeyHandle, int uiAlgID, byte[] pucIV, byte[] pucEncData, int uiEncDataLength, byte[] pucData, IntByReference puiDataLength);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param hKeyHandle     指定的密钥句柄
     * @param uiAlgID        算法标识，指定MAC加密算法
     * @param pucIV          缓冲区指针，用于存放输入和返回的IV数据
     * @param pucData        缓冲区指针，用于存放输入的数据明文
     * @param uiDataLength   输入的数据明文长度
     * @param pucMAC         缓冲区指针，用于存放输出的MAC值
     * @param puiMACLength   输出的MAC值长度
     * @return 程序执行成功与否
     * @brief 计算MAC:使用指定的密钥句柄和IV对数据进行MAC运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_CalculateMAC(Pointer hSessionHandle, Pointer hKeyHandle, int uiAlgID, byte[] pucIV, byte[] pucData, int uiDataLength, byte[] pucMAC, IntByReference puiMACLength);


    // 杂凑运算类函数

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param uiAlgID        指定杂凑算法标识
     * @param pucPublicKey   签名者公钥，当uiAlgID为SGD_SM3时有效
     * @param pucID          签名者的ID值，当uiAlgID为SGD_SM3时有效
     * @param uiIDLength     签名者的ID的长度，当uiAlgID为SGD_SM3时有效
     * @return 程序执行成功与否
     * @brief 杂凑运算初始化:三步式数据杂凑运算第一步
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_HashInit(Pointer hSessionHandle, int uiAlgID, SM2refPublicKey pucPublicKey, byte[] pucID, int uiIDLength);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param pucData        缓冲区指针，用于存放输入的数据明文
     * @param uiDataLength   输入的数据明文长度
     * @return 程序执行成功与否
     * @brief 多包杂凑运算:三步式数据杂凑运算第二步，对输入的明文进行杂凑运算
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_HashUpdate(Pointer hSessionHandle, byte[] pucData, int uiDataLength);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param pucHash        缓冲区指针，用于存放输出的杂凑数据
     * @param puiHashLength  输出的杂凑数据长度
     * @return 程序执行成功与否
     * @brief 杂凑运算结束:三步式数据杂凑运算第三步，杂凑运算结束返回杂凑数据并清除中间数据
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_HashFinal(Pointer hSessionHandle, byte[] pucHash, IntByReference puiHashLength);


    // 用户文件操作类函数

    /**
     * @param hSessionHandle
     * @param pucFileName
     * @param uiNameLen
     * @param uiFileSize
     * @return 程序执行成功与否
     * @brief 创建文件:在密码设备内部创建用于存储用户数据的文件
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_CreateFile(Pointer hSessionHandle, byte[] pucFileName, int uiNameLen, int uiFileSize);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param pucFileName    缓冲区指针，用于存放输入的文件名，最大长度128字节
     * @param uiNameLen      文件名长度
     * @param uiOffset       指定读取文件时的偏移值
     * @param puiReadLength  入参时指定读取文件内容的长度；出参时返回实际读取文件内容的长度
     * @param pucBuffer      缓冲区指针，用于存放读取的文件数据
     * @return 程序执行成功与否
     * @brief 读取文件:读取密码设备内部存储的用户数据文件的内容
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_ReadFile(Pointer hSessionHandle, byte[] pucFileName, int uiNameLen, int uiOffset, IntByReference puiReadLength, byte[] pucBuffer);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param pucFileName    缓冲区指针，用于存放输入的文件名，最大长度128字节
     * @param uiNameLen      文件名长度
     * @param uiOffset       指定写入文件时的偏移值
     * @param uiWriteLength  指定写入文件内容的长度
     * @param pucBuffer      缓冲区指针，用于存放输入的写文件数据
     * @return 程序执行成功与否
     * @brief 写入文件：向密码设备内部存储用户数据的文件中写入内容
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_WriteFile(Pointer hSessionHandle, byte[] pucFileName, int uiNameLen, int uiOffset, int uiWriteLength, byte[] pucBuffer);

    /**
     * @param hSessionHandle 与设备建立的会话句柄
     * @param pucFileName    缓冲区指针，用于存放输入的文件名，最大长度128字节
     * @param uiNameLen      文件名长度
     * @return 程序执行成功与否
     * @brief 删除文件：删除指定文件名的密码设备内部存储用户数据的文件
     * @retval 0 成功
     * @retval 非0 失败，返回错误码
     */
    int SDF_DeleteFile(Pointer hSessionHandle, byte[] pucFileName, int uiNameLen);


    int SDF_GetSymmKeyHandle(Pointer hSessionHandle, int var2, PointerByReference var3);

    int SDF_ExportSignPublicKey_ECDSA(Pointer hSessionHandle, int var2, ECDSArefPublicKey var3);

    int SDF_ExportEncPublicKey_ECDSA(Pointer hSessionHandle, int var2, ECDSArefPublicKey var3);

    int SDF_GenerateKeyPair_ECDSA(Pointer hSessionHandle, int var2, int var3, int var4, ECDSArefPublicKey var5, ECDSArefPrivateKey var6);

    int SDF_ExternalSign_ECDSA(Pointer hSessionHandle, int var2, ECDSArefPrivateKey var3, byte[] var4, int var5, byte[] var6, IntByReference var7);

    int SDF_ExternalVerify_ECDSA(Pointer hSessionHandle, int var2, ECDSArefPublicKey var3, byte[] var4, int var5, ECDSArefSignature var6, int var7);

    int SDF_InternalSign_ECDSA(Pointer hSessionHandle, int var2, int var3, byte[] var4, int var5, byte[] var6, IntByReference var7);

    int SDF_InternalVerify_ECDSA(Pointer hSessionHandle, int var2, int var3, byte[] var4, int var5, ECDSArefSignature var6, int var7);

}
