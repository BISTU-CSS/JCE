package com.util.encoders;


import org.bouncycastle.util.Strings;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class Hex {
   private static final Encoder encoder = new HexEncoder();

   public static String toHexString(byte[] data) {
      return toHexString(data, 0, data.length);
   }

   public static String toHexString(byte[] data, int off, int length) {
      byte[] encoded = encode(data, off, length);
      return Strings.fromByteArray(encoded);
   }

   public static byte[] encode(byte[] data) {
      return encode(data, 0, data.length);
   }

   public static byte[] encode(byte[] data, int off, int length) {
      ByteArrayOutputStream bOut = new ByteArrayOutputStream();

      try {
         encoder.encode(data, off, length, bOut);
      } catch (Exception var5) {
         throw new EncoderException("exception encoding Hex string: " + var5.getMessage(), var5);
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
      ByteArrayOutputStream bOut = new ByteArrayOutputStream();

      try {
         encoder.decode(data, 0, data.length, bOut);
      } catch (Exception var3) {
         throw new DecoderException("exception decoding Hex data: " + var3.getMessage(), var3);
      }

      return bOut.toByteArray();
   }

   public static byte[] decode(String data) {
      ByteArrayOutputStream bOut = new ByteArrayOutputStream();

      try {
         encoder.decode(data, bOut);
      } catch (Exception var3) {
         throw new DecoderException("exception decoding Hex string: " + var3.getMessage(), var3);
      }

      return bOut.toByteArray();
   }

   public static int decode(String data, OutputStream out) throws IOException {
      return encoder.decode(data, out);
   }
}
