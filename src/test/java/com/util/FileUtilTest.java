package com.util;

import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;

/**
 * @author pengshaocheng
 */
public class FileUtilTest {

    @Test
    public void getFileAsString() throws IOException {
        String ret = FileUtil.getFileAsString("address.conf");
        assertEquals("{\"device_type\": \"rpc\", \"device_socket\": \"166.111.134.50:35555\"}", ret);
    }

}