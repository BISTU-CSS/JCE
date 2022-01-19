package com.util;

import java.io.File;
import java.util.logging.Level;
import java.util.logging.Logger;

public class CryptoLogger {
   public static final Logger logger = Logger.getLogger("SWSDSCrypto");

   public static Level toLevel(int n) {
      Level level = null;
      switch(n) {
      case 0:
         level = Level.OFF;
         break;
      case 1:
         level = Level.SEVERE;
         break;
      case 2:
         level = Level.WARNING;
         break;
      case 3:
         level = Level.INFO;
         break;
      case 4:
         level = Level.CONFIG;
         break;
      case 5:
         level = Level.FINE;
         break;
      case 6:
         level = Level.ALL;
         break;
      default:
         level = Level.ALL;
      }

      return level;
   }

   public static boolean isFullPath(String filePath) {
      if (filePath.startsWith("/")) {
         return true;
      } else {
         return filePath.contains(":\\") && filePath.substring(1).startsWith(":\\");
      }
   }

   public static String getParentPath(String filePath) {
      File f = new File(filePath);
      return f.getParent();
   }

   static {
      logger.setLevel(Level.SEVERE);
   }
}
