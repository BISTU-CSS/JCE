package com.util.encoders;

public class DecoderException extends IllegalStateException {
   private Throwable cause;

   DecoderException(String msg, Throwable cause) {
      super(msg);
      this.cause = cause;
   }

   public Throwable getCause() {
      return this.cause;
   }
}
