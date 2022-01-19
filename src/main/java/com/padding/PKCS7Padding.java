package com.padding;

import javax.crypto.IllegalBlockSizeException;
import java.security.SecureRandom;
import java.util.Arrays;

public class PKCS7Padding implements BlockPadding {

    public void init(SecureRandom random) throws IllegalArgumentException {

    }

    public String getPaddingName() {
        return "PKCS7";
    }

    public int addPadding(byte[] in, int inOff) {
        byte code;
        for (code = (byte) (in.length - inOff); inOff < in.length; ++inOff) {
            in[inOff] = code;
        }
        return code;
    }

    public int padCount(byte[] in) throws IllegalBlockSizeException {
        int count = in[in.length - 1] & 255;
        byte countAsByte = (byte) count;
        boolean failed = count > in.length | count == 0;

        for (int i = 0; i < in.length; ++i) {
            failed |= in.length - i <= count & in[i] != countAsByte;
        }

        if (failed) {
            throw new IllegalBlockSizeException("pad block corrupted");
        }

        return count;
    }


    /**
     * 正向填充
     *
     * @param source
     * @param length
     * @return
     */
    public static byte[] getPaddingData(byte[] source, int length) {
        byte[] result = new byte[length];
        System.arraycopy(source, 0, result, 0, source.length);

        PKCS7Padding padding = new PKCS7Padding();
        padding.addPadding(result, source.length);

        return result;
    }


    /**
     * 逆向填充
     *
     * @param source
     * @return
     */
    public static byte[] getUnPaddingData(byte[] source) throws IllegalBlockSizeException {
        if (source == null || source.length == 0) {
            return null;
        }
        
//        int length = Math.abs(source[source.length - 1]);
//        byte[] process = new byte[source.length - length];
//        //该数组全部为填充数据，返回null
//        if (length == source.length) {
//            return null;
//        }
//        System.arraycopy(source, 0, process, 0, source.length - length);
//        return process;

        //取数据
        PKCS7Padding padding = new PKCS7Padding();
        //d为a数组后面有多少的填充数据
        int d = padding.padCount(source);
        //创建一个128-对应d数组的额外填充的数组
        byte[] paddingReturn = new byte[source.length - d];
        //将a数组的前128-d位（有效数字位）放入创建的paddingReturn中
        System.arraycopy(source, 0, paddingReturn, 0, source.length - d);
        return paddingReturn;
    }


    public static void main(String[] args) throws IllegalBlockSizeException {
        byte[] source = {1, 2};
        byte[] temp = getPaddingData(source, 128);
        byte[] process = getUnPaddingData(temp);
        System.out.println(Arrays.toString(process));
    }


}
