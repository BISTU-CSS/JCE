package com.util;

import java.io.IOException;

public interface Encodable {
    byte[] getEncoded() throws IOException;
}

