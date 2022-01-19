package com.jna.model;

import java.lang.reflect.Field;

public class GBErrorCode_SDR {

    //标准错误码定义
    public static int SDR_OK = 0;                   // 成功
    public static int SDR_BASE = 16777216;          // 错误码基础值
    public static int SDR_UNKNOWERR;                // 未知错误
    public static int SDR_NOTSUPPORT;               // 不支持的接口调用
    public static int SDR_COMMFAIL;                 // 通信错误
    public static int SDR_HARDFAIL;                 // 硬件错误，运算模块无响应
    public static int SDR_OPENDEVICE;               // 打开设备错误
    public static int SDR_OPENSESSION;              // 打开会话句柄错误
    public static int SDR_PARDENY;                  // 权限不满足
    public static int SDR_KEYNOTEXIST;              // 密钥不存在
    public static int SDR_ALGNOTSUPPORT;            // 不支持的算法
    public static int SDR_ALGMODNOTSUPPORT;         // 不支持的算法模式
    public static int SDR_PKOPERR;                  // 公钥运算错误
    public static int SDR_SKOPERR;                  // 私钥运算错误
    public static int SDR_SIGNERR;                  // 签名错误
    public static int SDR_VERIFYERR;                // 验证错误
    public static int SDR_SYMOPERR;                 // 对称运算错误
    public static int SDR_STEPERR;                  // 步骤错误
    public static int SDR_FILESIZEERR;              // 文件大小错误或输入数据长度非法
    public static int SDR_FILENOEXIST;              // 文件不存在
    public static int SDR_FILEOFSERR;               // 文件操作偏移量错误
    public static int SDR_KEYTYPEERR;               // 密钥类型错误
    public static int SDR_KEYERR;                   // 密钥错误

    //扩展错误码
    public static int SWR_BASE;                     // 自定义错误码基础值
    public static int SWR_INVALID_USER;             // 无效的用户名
    public static int SWR_INVALID_AUTHENCODE;       // 无效的授权码
    public static int SWR_PROTOCOL_VER_ERR;         // 不支持的协议版本
    public static int SWR_INVALID_COMMAND;          // 错误的命令字
    public static int SWR_INVALID_PARAMETERS;       // 参数错误或错误的数据包格式
    public static int SWR_FILE_ALREADY_EXIST;       // 已存在同名文件
    public static int SWR_SYNCH_ERR;                // 多卡同步错误
    public static int SWR_SYNCH_LOGIN_ERR;          // 多卡同步后登录错误
    public static int SWR_SOCKET_TIMEOUT;           // 超时错误
    public static int SWR_CONNECT_ERR;              // 连接服务器错误
    public static int SWR_SET_SOCKOPT_ERR;          // 设置Socket参数错误
    public static int SWR_SOCKET_SEND_ERR;          // 发送LOGINRequest错误
    public static int SWR_SOCKET_RECV_ERR;          // 发送LOGINRequest错误
    public static int SWR_SOCKET_RECV_0;            // 发送LOGINRequest错误
    public static int SWR_SEM_TIMEOUT;              // 超时错误
    public static int SWR_NO_VALID_HSM;
    public static int SWR_NO_AVAILABLE_HSM;         // 没有可用的加密机
    public static int SWR_NO_AVAILABLE_CSM;         // 加密机内没有可用的加密模块
    public static int SWR_CONFIG_ERR;               // 配置文件错误
    public static int USER_KEY_NOT_EXISTS_ERR;

    //密码卡错误码
    public static int SWR_CARD_BASE;                    // 密码卡错误码基础值
    public static int SWR_CARD_UNKNOWERR;               // 未知错误
    public static int SWR_CARD_NOTSUPPORT;              // 不支持的接口调用
    public static int SWR_CARD_COMMFAIL;                // 与设备通信失败
    public static int SWR_CARD_HARDFAIL;                // 运算模块无响应
    public static int SWR_CARD_OPENDEVICE;              // 打开设备失败
    public static int SWR_CARD_OPENSESSION;             // 创建会话失败
    public static int SWR_CARD_PARDENY;                 // 无私钥使用权限
    public static int SWR_CARD_KEYNOTEXIST;             // 不存在的密钥调用
    public static int SWR_CARD_ALGNOTSUPPORT;           // 不支持的算法调用
    public static int SWR_CARD_ALGMODNOTSUPPORT;        // 不支持的算法调用
    public static int SWR_CARD_PKOPERR;                 // 公钥运算失败
    public static int SWR_CARD_SKOPERR;                 // 私钥运算失败
    public static int SWR_CARD_SIGNERR;                 // 签名运算失败
    public static int SWR_CARD_VERIFYERR;               // 验证签名失败
    public static int SWR_CARD_SYMOPERR;                // 对称算法运算失败
    public static int SWR_CARD_STEPERR;                 // 多步运算步骤错误
    public static int SWR_CARD_FILESIZEERR;             // 文件长度超出限制
    public static int SWR_CARD_FILENOEXIST;             // 指定的文件不存在
    public static int SWR_CARD_FILEOFSERR;              // 文件起始位置错误
    public static int SWR_CARD_KEYTYPEERR;              // 密钥类型错误
    public static int SWR_CARD_KEYERR;                  // 密钥错误
    public static int SWR_CARD_BUFFER_TOO_SMALL;        // 接收参数的缓存区太小
    public static int SWR_CARD_DATA_PAD;                // 数据没有按正确格式填充，或解密得到的脱密数据不符合填充格式
    public static int SWR_CARD_DATA_SIZE;               // 明文或密文长度不符合相应的算法要求
    public static int SWR_CARD_CRYPTO_NOT_INIT;         // 该错误表明没有为相应的算法调用初始化函数

    // 01/03/09版密码卡权限管理错误码
    public static int SWR_CARD_MANAGEMENT_DENY;         // 管理权限不满足
    public static int SWR_CARD_OPERATION_DENY;          // 操作权限不满足
    public static int SWR_CARD_DEVICE_STATUS_ERR;       // 当前设备状态不满足现有操作
    public static int SWR_CARD_LOGIN_ERR;               // 登录失败
    public static int SWR_CARD_USERID_ERR;              // 用户ID数目/号码错误
    public static int SWR_CARD_PARAMENT_ERR;            // 参数错误

    // 05/06版密码卡权限管理错误码
    public static int SWR_CARD_MANAGEMENT_DENY_05;      // 管理权限不满足
    public static int SWR_CARD_OPERATION_DENY_05;       // 操作权限不满足
    public static int SWR_CARD_DEVICE_STATUS_ERR_05;    // 当前设备状态不满足现有操作
    public static int SWR_CARD_LOGIN_ERR_05;            // 登录失败
    public static int SWR_CARD_USERID_ERR_05;           // 用户ID数目/号码错误
    public static int SWR_CARD_PARAMENT_ERR_05;         // 参数错误

    //读卡器错误
    public static int SWR_CARD_READER_BASE;             // 读卡器类型错误
    public static int SWR_CARD_READER_PIN_ERROR;        // 口令错误
    public static int SWR_CARD_READER_NO_CARD;          // IC未插入
    public static int SWR_CARD_READER_CARD_INSERT;      // IC插入方向错误或不到位
    public static int SWR_CARD_READER_CARD_INSERT_TYPE; // IC类型错误


    public static String toErrorInfo(int errorCode) {
        GBErrorCode_SDR instance = new GBErrorCode_SDR();
        Field[] fields = instance.getClass().getDeclaredFields();

        for (Field field : fields) {
            try {
                if (field.get(instance).equals(errorCode)) {
                    return field.getName() + ":" + Integer.toHexString(errorCode);
                }
            } catch (IllegalAccessException e) {
                e.printStackTrace();
            }
        }
        return "Unknown Error:" + Integer.toHexString(errorCode);
    }


    static {
        SDR_UNKNOWERR = SDR_BASE + 1;
        SDR_NOTSUPPORT = SDR_BASE + 2;
        SDR_COMMFAIL = SDR_BASE + 3;
        SDR_HARDFAIL = SDR_BASE + 4;
        SDR_OPENDEVICE = SDR_BASE + 5;
        SDR_OPENSESSION = SDR_BASE + 6;
        SDR_PARDENY = SDR_BASE + 7;
        SDR_KEYNOTEXIST = SDR_BASE + 8;
        SDR_ALGNOTSUPPORT = SDR_BASE + 9;
        SDR_ALGMODNOTSUPPORT = SDR_BASE + 10;
        SDR_PKOPERR = SDR_BASE + 11;
        SDR_SKOPERR = SDR_BASE + 12;
        SDR_SIGNERR = SDR_BASE + 13;
        SDR_VERIFYERR = SDR_BASE + 14;
        SDR_SYMOPERR = SDR_BASE + 15;
        SDR_STEPERR = SDR_BASE + 16;
        SDR_FILESIZEERR = SDR_BASE + 17;
        SDR_FILENOEXIST = SDR_BASE + 18;
        SDR_FILEOFSERR = SDR_BASE + 19;
        SDR_KEYTYPEERR = SDR_BASE + 20;
        SDR_KEYERR = SDR_BASE + 21;
        SWR_BASE = SDR_BASE + 65536;
        SWR_INVALID_USER = SWR_BASE + 1;
        SWR_INVALID_AUTHENCODE = SWR_BASE + 2;
        SWR_PROTOCOL_VER_ERR = SWR_BASE + 3;
        SWR_INVALID_COMMAND = SWR_BASE + 4;
        SWR_INVALID_PARAMETERS = SWR_BASE + 5;
        SWR_FILE_ALREADY_EXIST = SWR_BASE + 6;
        SWR_SOCKET_TIMEOUT = SWR_BASE + 256;
        SWR_CONNECT_ERR = SWR_BASE + 257;
        SWR_SET_SOCKOPT_ERR = SWR_BASE + 258;
        SWR_SOCKET_SEND_ERR = SWR_BASE + 260;
        SWR_SOCKET_RECV_ERR = SWR_BASE + 261;
        SWR_SOCKET_RECV_0 = SWR_BASE + 262;
        SWR_SEM_TIMEOUT = SWR_BASE + 513;
        SWR_NO_VALID_HSM = SWR_BASE + 514;
        SWR_CONFIG_ERR = SWR_BASE + 769;
        USER_KEY_NOT_EXISTS_ERR = 16908296;
        SWR_CARD_BASE = SDR_BASE + 131072;
        SWR_CARD_UNKNOWERR = SWR_CARD_BASE + 1;
        SWR_CARD_NOTSUPPORT = SWR_CARD_BASE + 2;
        SWR_CARD_COMMFAIL = SWR_CARD_BASE + 3;
        SWR_CARD_HARDFAIL = SWR_CARD_BASE + 4;
        SWR_CARD_OPENDEVICE = SWR_CARD_BASE + 5;
        SWR_CARD_OPENSESSION = SWR_CARD_BASE + 6;
        SWR_CARD_PARDENY = SWR_CARD_BASE + 7;
        SWR_CARD_KEYNOTEXIST = SWR_CARD_BASE + 8;
        SWR_CARD_ALGNOTSUPPORT = SWR_CARD_BASE + 9;
        SWR_CARD_ALGMODNOTSUPPORT = SWR_CARD_BASE + 16;
        SWR_CARD_PKOPERR = SWR_CARD_BASE + 17;
        SWR_CARD_SKOPERR = SWR_CARD_BASE + 18;
        SWR_CARD_SIGNERR = SWR_CARD_BASE + 19;
        SWR_CARD_VERIFYERR = SWR_CARD_BASE + 20;
        SWR_CARD_SYMOPERR = SWR_CARD_BASE + 21;
        SWR_CARD_STEPERR = SWR_CARD_BASE + 22;
        SWR_CARD_FILESIZEERR = SWR_CARD_BASE + 23;
        SWR_CARD_FILENOEXIST = SWR_CARD_BASE + 24;
        SWR_CARD_FILEOFSERR = SWR_CARD_BASE + 25;
        SWR_CARD_KEYTYPEERR = SWR_CARD_BASE + 32;
        SWR_CARD_KEYERR = SWR_CARD_BASE + 33;
        SWR_CARD_BUFFER_TOO_SMALL = SWR_CARD_BASE + 257;
        SWR_CARD_DATA_PAD = SWR_CARD_BASE + 258;
        SWR_CARD_DATA_SIZE = SWR_CARD_BASE + 259;
        SWR_CARD_CRYPTO_NOT_INIT = SWR_CARD_BASE + 260;
        SWR_CARD_MANAGEMENT_DENY = SWR_CARD_BASE + 4097;
        SWR_CARD_OPERATION_DENY = SWR_CARD_BASE + 4098;
        SWR_CARD_DEVICE_STATUS_ERR = SWR_CARD_BASE + 4099;
        SWR_CARD_LOGIN_ERR = SWR_CARD_BASE + 4113;
        SWR_CARD_USERID_ERR = SWR_CARD_BASE + 4114;
        SWR_CARD_PARAMENT_ERR = SWR_CARD_BASE + 4115;
        SWR_CARD_MANAGEMENT_DENY_05 = SWR_CARD_BASE + 2049;
        SWR_CARD_OPERATION_DENY_05 = SWR_CARD_BASE + 2050;
        SWR_CARD_DEVICE_STATUS_ERR_05 = SWR_CARD_BASE + 2051;
        SWR_CARD_LOGIN_ERR_05 = SWR_CARD_BASE + 2065;
        SWR_CARD_USERID_ERR_05 = SWR_CARD_BASE + 2066;
        SWR_CARD_PARAMENT_ERR_05 = SWR_CARD_BASE + 2067;
        SWR_CARD_READER_BASE = SDR_BASE + 196608;
        SWR_CARD_READER_PIN_ERROR = SWR_CARD_READER_BASE + 25550;
        SWR_CARD_READER_NO_CARD = SWR_CARD_READER_BASE + '!';
        SWR_CARD_READER_CARD_INSERT = SWR_CARD_READER_BASE + '"';
        SWR_CARD_READER_CARD_INSERT_TYPE = SWR_CARD_READER_BASE + '#';
    }
}
