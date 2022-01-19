package com.util;

import java.io.ByteArrayOutputStream;

public class BytesUtil {
   public static final char[] HEX = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
   public static final String delimiter = "";

   public static byte[] subbytes(byte[] bytes, int srcPos, int length) {
      byte[] buf = new byte[length];
      System.arraycopy(bytes, srcPos, buf, 0, length);
      return buf;
   }

   public static byte[] combineBytes(byte[] byte1, byte[] byte2) {
      byte[] result = new byte[byte1.length + byte2.length];
      System.arraycopy(byte1, 0, result, 0, byte1.length);
      System.arraycopy(byte2, 0, result, byte1.length, byte2.length);
      return result;
   }

   public static boolean isEqual(byte[] dataa, byte[] datab) {
      if (dataa == datab) {
         return true;
      } else if (dataa != null && datab != null) {
         if (dataa.length != datab.length) {
            return false;
         } else {
            int result = 0;

            for(int i = 0; i < dataa.length; ++i) {
               result |= dataa[i] ^ datab[i];
            }

            return result == 0;
         }
      } else {
         return false;
      }
   }

   public static String bytes2hex(byte[] bytes) {
      return bytes2hex(bytes, "", bytes.length + 1);
   }

   public static byte[] hex2bytes(String str) {
      return hex2bytes(str, "");
   }

   private static byte[] hex2bytes(String str, String delimiter) {
      str = str.toLowerCase();
      int i;
      if (!"".equals(delimiter)) {
         ByteArrayOutputStream baos = new ByteArrayOutputStream();
         String[] arr = str.split(delimiter);

         for(i = 0; i < arr.length; ++i) {
            if (!arr[i].trim().equals("")) {
               baos.write(hex2byte(arr[i]));
            }
         }

         return baos.toByteArray();
      } else {
         byte[] buf = new byte[str.length() / 2];

         for(i = 0; i < buf.length; ++i) {
            char ch = str.charAt(i * 2);
            if (ch >= 'a' && ch <= 'f') {
               buf[i] = (byte)(ch - 97 + 10 << 4);
            } else {
               buf[i] = (byte)(ch - 48 << 4);
            }

            ch = str.charAt(i * 2 + 1);
            if (ch >= 'a' && ch <= 'f') {
               buf[i] += (byte)(ch - 97 + 10);
            } else {
               buf[i] += (byte)(ch - 48);
            }
         }

         return buf;
      }
   }

   private static String byte2hex(byte n) {
      String str = "";
      str = str + HEX[(n & 240) >> 4];
      str = str + HEX[n & 15];
      return str;
   }

   private static byte hex2byte(String str) {
      char ch = str.charAt(0);
      byte n;
      if (ch >= 'a' && ch <= 'f') {
         n = (byte)(ch - 97 + 10 << 4);
      } else {
         n = (byte)(ch - 48 << 4);
      }

      ch = str.charAt(1);
      if (ch >= 'a' && ch <= 'f') {
         n += (byte)(ch - 97 + 10);
      } else {
         n += (byte)(ch - 48);
      }

      return n;
   }

   private static String bytes2hex(byte[] data, String delimiter, int wrap) {
      StringBuffer sb = new StringBuffer();

      for(int i = 0; i < data.length; ++i) {
         if (i != 0 && i % wrap == 0) {
            sb.append("\n");
         }

         sb.append(byte2hex(data[i]));
         sb.append(delimiter);
      }

      sb.append(", " + data.length);
      return sb.toString();
   }

   public static byte[] int2bytes(int num) {
      byte[] bytes = new byte[4];

      for(int i = 0; i < 4; ++i) {
         bytes[i] = (byte)(255 & num >> i * 8);
      }

      return bytes;
   }

   public static byte[] int2bytesCat(int num, byte[] bytes, int offset) {
      for(int i = 0; i < 4; ++i) {
         bytes[offset + i] = (byte)(255 & num >> i * 8);
      }

      return bytes;
   }

   public static int bytes2int(byte[] bytes) {
      return bytes2int(bytes, 0);
   }

   public static int bytes2int(byte[] bytes, int offset) {
      int num = 0;

      for(int i = 0; i < 4; ++i) {
         num = (int)((long)num + ((255L & (long)bytes[i + offset]) << i * 8));
      }

      return num;
   }

   public static String hexEncode(byte[] data) {
      StringBuffer sb = new StringBuffer();

      for(int i = 0; i < data.length; ++i) {
         sb.append(byte2hex(data[i]));
      }

      return sb.toString();
   }

   public static byte[] longToBytes(long num) {
      byte[] bytes = new byte[8];

      for(int i = 0; i < 8; ++i) {
         bytes[i] = (byte)((int)(255L & num >> i * 8));
      }

      return bytes;
   }
}
