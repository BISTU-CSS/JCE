package com.util;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * @Description: TODO
 * @Author: hongyi
 * @Date: 2020/8/25 11:31
 */
public class SymmetryUtilTest {


    @Test
    public void isRightIV() {

        boolean b = SymmetryUtil.isRightIV(8224, null);
        assertTrue(b);

        boolean b1 = SymmetryUtil.isRightIV(1026, null);
        assertFalse(b1);
    }

}
