package com.util.encoders;


import org.bouncycastle.util.Strings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class Base64 {
   private static final int LINE_LENGTH = 64;
   private static final Encoder encoder = new Base64Encoder();

   public static String toBase64String(byte[] data) {
      return toBase64String(data, 0, data.length);
   }

   public static String toBase64String(byte[] data, int off, int length) {
      byte[] encoded = encode(data, off, length);
      return Strings.fromByteArray(encoded);
   }

   public static String toBase64StringLine(byte[] data) {
      StringBuffer buffer = new StringBuffer();
      String base64 = toBase64String(data);

      for(int index = 0; index < base64.length(); index += 64) {
         int iLineLength = 0;
         if (index + 64 > base64.length()) {
            iLineLength = base64.length() - index;
         } else {
            iLineLength = 64;
         }

         buffer.append(base64.substring(index, index + iLineLength) + "\n");
      }

      return buffer.toString();
   }

   public static byte[] encode(byte[] data) {
      return encode(data, 0, data.length);
   }

   public static byte[] encode(byte[] data, int off, int length) {
      int len = (length + 2) / 3 * 4;
      ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

      try {
         encoder.encode(data, off, length, bOut);
      } catch (Exception var6) {
         throw new EncoderException("exception encoding base64 string: " + var6.getMessage(), var6);
      }

      return bOut.toByteArray();
   }

   public static int encode(byte[] data, OutputStream out) throws IOException {
      return encoder.encode(data, 0, data.length, out);
   }

   public static int encode(byte[] data, int off, int length, OutputStream out) throws IOException {
      return encoder.encode(data, off, length, out);
   }

   public static byte[] decode(byte[] data) {
      int len = data.length / 4 * 3;
      ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

      try {
         encoder.decode(data, 0, data.length, bOut);
      } catch (Exception var4) {
         throw new DecoderException("unable to decode base64 data: " + var4.getMessage(), var4);
      }

      return bOut.toByteArray();
   }

   public static byte[] decode(String data) {
      int len = data.length() / 4 * 3;
      ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

      try {
         encoder.decode(data, bOut);
      } catch (Exception var4) {
         throw new DecoderException("unable to decode base64 string: " + var4.getMessage(), var4);
      }

      return bOut.toByteArray();
   }

   public static int decode(String data, OutputStream out) throws IOException {
      return encoder.decode(data, out);
   }

   public static int decode(byte[] base64Data, int start, int length, OutputStream out) {
      try {
         return encoder.decode(base64Data, start, length, out);
      } catch (Exception var5) {
         throw new DecoderException("unable to decode base64 data: " + var5.getMessage(), var5);
      }
   }

   public static boolean isBase64(byte[] data, int off, int length) {
      return ((Base64Encoder)encoder).isBase64(data, off, length);
   }

   public static boolean isBase64(byte[] data) {
      return isBase64(data, 0, data.length);
   }
}
