package example;

import com.provider.NDSecProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

@RunWith(Parameterized.class)
public class MacExampleTest {
    private int keysize;
    private byte[] plain;
    private static SecureRandom random = new SecureRandom();
    NDSecProvider baseProvider;

    public MacExampleTest(int keysize, byte[] plain) {
        this.keysize = keysize;
        this.plain = plain;
    }

    @Before
    public void setUp() throws Exception {
        random.setSeed(System.currentTimeMillis());
        baseProvider = new NDSecProvider();
        Security.addProvider(baseProvider);
    }

    @Parameterized.Parameters
    public static List<Integer> prepareData() throws NullPointerException {
        Integer[] object = {
                127, 128, 129, 256
        };
        List<Integer> list = Arrays.asList(object);
        return list;
    }

    @Test
    public void SM1Mac() throws InvalidKeyException, NoSuchAlgorithmException {
        MacExample.SM1Mac(baseProvider, this.keysize, this.plain);
    }

    @Test
    public void SMS4Mac() throws InvalidKeyException, NoSuchAlgorithmException {
        MacExample.SMS4Mac(baseProvider, this.keysize, this.plain);
    }
}