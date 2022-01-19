package com.padding;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.SecureRandom;

public class PKCS1Padding {
    private static final int HEADER_LENGTH = 10;
    private SecureRandom random;
    private int bitSize;
    private boolean forEncryption;
    private boolean forPrivateKey;
    private int inblockSize;
    private int outblockSize;

    /**
     * @param modulus       RSA 密钥的模长
     * @param forEncryption true加密填充 false 解密反填充
     * @param forPrivateKey true私钥  false公钥
     */
    public PKCS1Padding(int modulus, boolean forEncryption, boolean forPrivateKey) {
        bitSize = modulus;
        this.random = new SecureRandom();
        this.forPrivateKey = forPrivateKey;
        this.forEncryption = forEncryption;
        if (forEncryption) {
            inblockSize = (bitSize + 7) / 8 - 1;
            outblockSize = (bitSize + 7) / 8;
        } else {
            inblockSize = (bitSize + 7) / 8;
            outblockSize = (bitSize + 7) / 8 - 1;
        }
    }

    /**
     * 得到输入的数据大小（数据应该不大于此大小）
     *
     * @return 输入的数据大小（数据应该不大于此大小）
     */
    public int getInputBlockSize() {

        if (forEncryption) {
            return inblockSize - HEADER_LENGTH;
        }

        return inblockSize;
    }


    /**
     * 得到输出的数据大小
     *
     * @return 输出的数据大小
     */
    public int getOutputBlockSize() {

        if (forEncryption) {
            return outblockSize;
        }

        return outblockSize - HEADER_LENGTH;
    }

    /**
     * 返回pkcs1填充后的数据
     *
     * @param inData 要进行填充的数据(不能超过128字节)
     * @param inOff  填充起始位置
     * @param inLen  要填充的数据长度
     * @return pkcs1填充后的数据
     * @throws IllegalBlockSizeException
     */
    public byte[] processBlock(byte[] inData, int inOff, int inLen) throws IllegalBlockSizeException, BadPaddingException {

        // 编码块
        if (forEncryption) {
            return encodeBlock(inData, inOff, inLen);
        }

        // 解码块
        return decodeBlock(inData, inOff, inLen);
    }

    private byte[] encodeBlock(byte[] in, int inOff, int inLen) throws IllegalBlockSizeException {

        if (inLen > getInputBlockSize()) {
            throw new IllegalBlockSizeException("input data too large");
        }

        byte[] block = new byte[inblockSize + 1];
        if (forPrivateKey) {
            block[0] = 0x00; // type code 0
            block[1] = 0x01; // type code 1，私钥

            // 私钥填充0xFF
            for (int i = 2; i != block.length - inLen - 1; i++) {
                block[i] = (byte) 0xFF;
            }

        } else {
            random.nextBytes(block); // random fill
            block[0] = 0x00; // type code 0
            block[1] = 0x02; // type code 2，公钥

            // 公钥填充非零随机数
            // a zero byte marks the end of the padding, so all the pad bytes must be non-zero.
            for (int i = 2; i != block.length - inLen - 1; i++) {
                while (block[i] == 0) {
                    block[i] = (byte) random.nextInt();
                }
            }
        }

        block[block.length - inLen - 1] = 0x00; // mark the end of the padding
        System.arraycopy(in, inOff, block, block.length - inLen, inLen);

        return block;
    }


    private byte[] decodeBlock(byte[] block, int inOff, int inLen) throws BadPaddingException, IllegalBlockSizeException {
        //输入必须大于117
        if (block.length < getOutputBlockSize()) {
            throw new IllegalBlockSizeException("block truncated");
        }

        // 私钥0x01，公钥0x02
        byte type = block[1];
        if (type != 1 && type != 2) {
            throw new BadPaddingException("unknown block type");
        }

        //并且输入数据长度必须等于128
        if (block.length != outblockSize + 1) {
            throw new IllegalBlockSizeException("block incorrect size");
        }

        // find and extract the message block.
        int start;
        for (start = 2; start != block.length; start++) {
            byte pad = block[start];

            if (pad == 0) {
                break;
            }

            // 对私钥增加一步校验
            if (type == 1 && pad != (byte) 0xff) {
                throw new BadPaddingException("block padding incorrect");
            }
        }

        start++; // data should start at the next byte

        if (start > block.length || start < HEADER_LENGTH) {
            throw new IllegalBlockSizeException("no data in block");
        }

        byte[] result = new byte[block.length - start];
        System.arraycopy(block, start, result, 0, result.length);

        return result;
    }

}
