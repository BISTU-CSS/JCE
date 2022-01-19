package com.util;


public class KeyIndexUtil {
    public static KeyIndexUtil.KeyIndexStruct parse2KeyIndex(int exIndex) {
        KeyIndexUtil.KeyIndexStruct struct = new KeyIndexUtil.KeyIndexStruct();
        struct.keyIndex = (exIndex + 1) / 2;
        if (exIndex % 2 == 0) {
            struct.keyType = 2;
        } else {
            struct.keyType = 1;
        }

        return struct;
    }

    public static int parse2ExIndex(KeyIndexUtil.KeyIndexStruct struct) {
        if (struct == null) {
            throw new IllegalArgumentException("struct is null");
        }

        return struct.keyType == 1 ? struct.keyIndex * 2 - 1 : struct.keyIndex * 2;
    }

    public static class KeyIndexStruct {
        public int keyIndex;
        public int keyType;
    }
}
