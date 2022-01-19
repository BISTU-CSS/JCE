package example;

import com.provider.NDSecProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

@RunWith(Parameterized.class)
public class MessageDigestExampleTest {
    private byte[] plain;
    private static SecureRandom random = new SecureRandom();
    NDSecProvider baseProvider;
    public MessageDigestExampleTest(byte[] plain){
        this.plain = plain;
    }
    @Before
    public void setUp() throws Exception {
        random.setSeed(System.currentTimeMillis());
        baseProvider = new NDSecProvider();
        Security.addProvider(baseProvider);
    }
    @Parameterized.Parameters
    public static List<byte[]> prepareData() throws NullPointerException{
        byte[] tmp=new byte[0];
        byte[] tmp1 = new byte[127];
        byte[] tmp2 = new byte[128];
        byte[] tmp3 = new byte[129];
        byte[] tmp4 = new byte[135];
        byte[] tmp5 = new byte[136];
        byte[] tmp6 = new byte[137];
        byte[] tmp7 = new byte[10000];
        byte[] tmp8 = new byte[16255];
        byte[] tmp9 = new byte[16256];
        byte[] tmp10 = new byte[16257];
        byte[] tmp11 = new byte[16367];
        byte[] tmp12 = new byte[16368];
        byte[] tmp13 = new byte[16369];
        byte[] tmp14 = new byte[20000];
        random.nextBytes(tmp);
        random.nextBytes(tmp1);
        random.nextBytes(tmp3);
        random.nextBytes(tmp4);
        random.nextBytes(tmp5);
        random.nextBytes(tmp6);
        random.nextBytes(tmp7);
        random.nextBytes(tmp8);
        random.nextBytes(tmp9);
        random.nextBytes(tmp10);
        random.nextBytes(tmp11);
        random.nextBytes(tmp12);
        random.nextBytes(tmp13);
        random.nextBytes(tmp14);
        byte[][] object = {
                tmp,tmp1,tmp2,tmp3,tmp4,tmp5,
                tmp6,tmp7,tmp8,tmp9,tmp10,tmp11,
                tmp12,tmp13,tmp14
        };
        return Arrays.asList(object);
    }
    @Test
    public void MD5MessageDigest() throws Exception {
        MessageDigestExample.MD5MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SHA1MessageDigest() throws Exception {
        MessageDigestExample.SHA1MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SHA224MessageDigest() throws Exception{
        MessageDigestExample.SHA224MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SHA256MessageDigest() throws Exception{
        MessageDigestExample.SHA256MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SHA384MessageDigest() throws Exception{
        MessageDigestExample.SHA384MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SHA512MessageDigest() throws Exception{
        MessageDigestExample.SHA512MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SHA3224MessageDigest() throws Exception{
        MessageDigestExample.SHA3224MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SHA3256MessageDigest() throws Exception{
        MessageDigestExample.SHA3256MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SHA3384MessageDigest() throws Exception{
        MessageDigestExample.SHA3384MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SHA3512MessageDigest() throws Exception{
        MessageDigestExample.SHA3512MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SM3MessageDigest() throws Exception{
        MessageDigestExample.SM3MessageDigest(this.plain,baseProvider);
    }

    @Test
    public void SM3WithIDMessageDigest() throws Exception{
        MessageDigestExample.SM3WithIDMessageDigest(plain,baseProvider);
    }

    @Test
    public void SM3WithoutIDMessageDigest() throws Exception {
        MessageDigestExample.SM3WithoutIDMessageDigest(plain,baseProvider);
    }
}