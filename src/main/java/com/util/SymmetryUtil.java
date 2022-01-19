package com.util;

public class SymmetryUtil {

    public static boolean isRightAlg(int algId) {
        switch (algId) {
            case 257:
            case 258:
            case 260:
            case 264:
            case 272:
            case 288:
            case 513:
            case 514:
            case 516:
            case 520:
            case 528:
            case 544:
            case 1025:
            case 1026:
            case 1028:
            case 1032:
            case 1040:
            case 1056:
            case 1088:
            case 2049:
            case 2050:
            case 2052:
            case 2056:
            case 2064:
            case 2080:
            case 8193:
            case 8194:
            case 8224:
            case 16385:
            case 16386:
            case 16388:
            case 16392:
            case 16400:
            case 16416:
                return true;
            default:
                return false;
        }
    }


    public static boolean isRightIV(int algId, byte[] iv) {

        int ivBaseLength;
        switch (algId) {
            case 257:
            case 272:
            case 288:
            case 513:
            case 528:
            case 544:
            case 1025:
            case 1040:
            case 1056:
            case 2049:
            case 2064:
            case 2080:
            case 8193:
            case 8224:
            case 16385:
            case 16400:
            case 16416:
                return true;
            case 258:
            case 260:
            case 264:
            case 514:
            case 516:
            case 520:
            case 1026:
            case 1028:
            case 1032:
            case 8194:
                ivBaseLength = 16;
                break;
            case 1088:
                return true;
            case 2050:
            case 2052:
            case 2056:
            case 16386:
            case 16388:
            case 16392:
                ivBaseLength = 8;
                break;
            default:
                ivBaseLength = 10;
        }
        if (iv == null || 0 == iv.length) {
            return false;
        }
        if (iv.length % ivBaseLength == 0) {
            return true;
        }
        return false;
    }


    public static boolean isRightInput(int algId, byte[] input) {
        if (input == null || input.length == 0) {
            return false;
        }

        int baseLength = inputBaseLength(algId);
//        switch (algId) {
//            case 257:
//            case 258:
//            case 260:
//            case 264:
//            case 272:
//            case 288:
//            case 513:
//            case 514:
//            case 516:
//            case 520:
//            case 528:
//            case 544:
//            case 1025:
//            case 1026:
//            case 1028:
//            case 1032:
//            case 1040:
//            case 1056:
//            case 1088:
//            case 8193:
//            case 8194:
//            case 8224:
//                baseLength = 16;
//                break;
//            case 2049:
//            case 2050:
//            case 2052:
//            case 2056:
//            case 2064:
//            case 2080:
//            case 16385:
//            case 16386:
//            case 16388:
//            case 16392:
//            case 16400:
//            case 16416:
//                baseLength = 8;
//                break;
//            default:
//                baseLength = 10;
//        }

        if (input.length % baseLength == 0) {
            return true;
        }
        return false;
    }


    public static int inputBaseLength(int algId) {
        switch (algId) {
            case 257:
            case 258:
            case 260:
            case 264:
            case 272:
            case 288:
            case 513:
            case 514:
            case 516:
            case 520:
            case 528:
            case 544:
            case 1025:
            case 1026:
            case 1028:
            case 1032:
            case 1040:
            case 1056:
            case 1088:
            case 8193:
            case 8194:
            case 8224:
                return 16;
            case 2049:
            case 2050:
            case 2052:
            case 2056:
            case 2064:
            case 2080:
            case 16385:
            case 16386:
            case 16388:
            case 16392:
            case 16400:
            case 16416:
                return 8;
            default:
                return 10;
        }
    }


}
