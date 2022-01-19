package com.util;

public class ECDSAUtil {
	   public static boolean checkCurveType(int curveType) {
		      boolean flag = false;
		      flag = 524289 == curveType || 524290 == curveType || 524291 == curveType || 524292 == curveType || 524293 == curveType;
		      return flag;
		   }

		   public static boolean checkKeyLength(int curveType, int keyLength) {
		      boolean flag = false;
		      switch(curveType) {
		      case 524289:
		         flag = 192 == keyLength || 224 == keyLength || 256 == keyLength || 384 == keyLength || 521 == keyLength;
		         break;
		      case 524290:
		      case 524291:
		         flag = 163 == keyLength || 233 == keyLength || 283 == keyLength || 409 == keyLength || 571 == keyLength;
		         break;
		      case 524292:
		      case 524293:
		         flag = 160 == keyLength || 192 == keyLength || 224 == keyLength || 256 == keyLength || 320 == keyLength || 384 == keyLength || 512 == keyLength;
		      }

		      return flag;
		   }
}
