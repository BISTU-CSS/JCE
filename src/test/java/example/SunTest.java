package example;

import com.provider.NDSecProvider;
import com.provider.cipher.AESCipherSpi;

import java.math.BigInteger;

public class SunTest {
    public static void main(String[] args) {
        NDSecProvider baseProvider = new NDSecProvider();
        baseProvider.getMachineInfo();

    }
}
