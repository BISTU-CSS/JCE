package com.padding;

import javax.crypto.IllegalBlockSizeException;
import java.security.SecureRandom;

public interface BlockPadding {
    void init(SecureRandom var1) throws IllegalArgumentException;

    String getPaddingName();

    int addPadding(byte[] var1, int var2);

    int padCount(byte[] var1) throws IllegalBlockSizeException;
}
