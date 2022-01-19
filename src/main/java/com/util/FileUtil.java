package com.util;

import java.io.*;

/**
 * 读取classpath中指定文件
 *
 * @author pengshaocheng
 */
public class FileUtil {

    private static final String CONFIG_HOME_NAME = "JCE_CONFIG_HOME";

    public static String getFileAsString(String fileName) throws IOException {

        // 从项目根目录查找
        String userDir = System.getProperty("user.dir");
        if (userDir != null && userDir.length() > 0) {
            File file = new File(userDir + File.separator + fileName);
            if (file.exists()) {
                return readFileContent(new FileInputStream(file));
            }
        }

        // 从用户家目录查找
        String userHome = System.getProperty("user.home");
        if (userHome != null && userHome.length() > 0) {
            File file = new File(userHome + File.separator + fileName);
            if (file.exists()) {
                return readFileContent(new FileInputStream(file));
            }
        }

        // 系统变量
        String configFile = System.getProperty(CONFIG_HOME_NAME);
        if (configFile == null || configFile.length() == 0) {
            // 环境变量
            configFile = System.getenv(CONFIG_HOME_NAME);
        }

        // 处理变量配置的目录还是文件
        if (configFile != null && !configFile.endsWith(fileName)) {
            configFile = configFile + File.separator + fileName;
        }

        // 加载配置的文件
        if (configFile != null) {
            File file = new File(configFile);
            if (file.exists()) {
                return readFileContent(new FileInputStream(file));
            }
        }

        // 从当前classpath中加载文件
        InputStream is = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
        if (is == null) {
            is = FileUtil.class.getClassLoader().getResourceAsStream(fileName);
        }
        return readFileContent(is);
    }


    private static String readFileContent(InputStream is) throws IOException {
        if (is == null) {
            throw new IllegalArgumentException("config file inputstream is null");
        }

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytes;
        while ((bytes = is.read(buffer)) != -1) {
            bos.write(buffer, 0, bytes);
        }
        return new String(bos.toByteArray());
    }


    public static void main(String[] args) throws IOException {
        String content = getFileAsString("address.conf");
        System.out.println(content);
    }

}
