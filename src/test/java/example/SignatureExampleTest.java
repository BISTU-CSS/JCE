package example;

import com.provider.NDSecProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

@RunWith(Parameterized.class)
public class SignatureExampleTest {
    private byte[] input;
    private static SecureRandom random = new SecureRandom();
    NDSecProvider baseProvider;
    KeyPair rsaKeyPair;
    KeyPair sm2KeyPair;
    public SignatureExampleTest(byte[] input){
        this.input=input;
    }
    @Before
    public void setUp() throws Exception {
        random.setSeed(System.currentTimeMillis());
        baseProvider = new NDSecProvider();    //申请provider
        Security.addProvider(baseProvider);//嵌入provider
        rsaKeyPair = KeyPairGeneratorExample.RSAKeyPairGenerator(baseProvider);
        sm2KeyPair = KeyPairGeneratorExample.SM2KeyPairGenerator(baseProvider);
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
        byte[] tmp11 = new byte[16383];
        byte[] tmp12 = new byte[16384];
        byte[] tmp13 = new byte[16385];
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
    public void MD5WithRSA() throws Exception {
        SignatureExample.MD5WithRSA(baseProvider, rsaKeyPair,this.input);
    }

    @Test
    public void SHA1WithRSA() throws Exception {
        SignatureExample.SHA1WithRSA(baseProvider, rsaKeyPair,this.input);
    }

    @Test
    public void SHA1WithSM2() throws Exception {
        SignatureExample.SHA1WithSM2(baseProvider, sm2KeyPair,this.input);
    }

    @Test
    public void SHA224WithRSA() throws Exception {
        SignatureExample.SHA224WithRSA(baseProvider, rsaKeyPair,this.input);
    }

    @Test
    public void SHA224WithSM2() throws Exception {
        SignatureExample.SHA224WithSM2(baseProvider, sm2KeyPair,this.input);
    }

    @Test
    public void SHA256WithRSA() throws Exception {
        SignatureExample.SHA256WithRSA(baseProvider, rsaKeyPair,this.input);
    }

    @Test
    public void SHA256WithSM2() throws Exception {
        SignatureExample.SHA256WithSM2(baseProvider, sm2KeyPair,this.input);
    }

    @Test
    public void SHA384WithRSA() throws Exception {
        SignatureExample.SHA384WithRSA(baseProvider, rsaKeyPair,this.input);
    }

    @Test
    public void SHA512WithRSA() throws Exception {
        SignatureExample.SHA512WithRSA(baseProvider, rsaKeyPair,this.input);
    }

    @Test
    public void SM3WithSM2() throws Exception {
        SignatureExample.SM3WithSM2(baseProvider, sm2KeyPair,this.input);
    }
}