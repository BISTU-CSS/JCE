package example;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class CipherExampleTest {
    private byte[] input;
    private static SecureRandom random = new SecureRandom();
    public CipherExampleTest(byte[] input){
        this.input=input;
    }
    @Before
    public void setUp() throws Exception {

        random.setSeed(System.currentTimeMillis());

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
//    @Test
//    public void testRSACipher() throws Exception {
//        System.out.println("RSA-test:"+this.input);
//        CipherExample.RSACipher(this.input);
//    }
//    @Test
//    public void testAESCipher() throws Exception {
//        System.out.println("ASE-test:"+this.input);
//        CipherExample.AESCipher(this.input);
//    }
    @Test
    public void testSM1Cipher() throws Exception {
        System.out.println("SM1-test:"+this.input);
        CipherExample.SM1Cipher(this.input);
    }

//    @Test
//    public void testSM4Cipher() throws Exception {
//        System.out.println("SM4-test:"+this.input);
//        CipherExample.SM4Cipher(this.input);
//    }
//
//    @Test
//    public void testSSF33Cipher() throws Exception {
//        System.out.println("SSF33-test:"+this.input);
//        CipherExample.SSF33Cipher(this.input);
//    }
//
//    @Test
//    public void testSM2Cipher() throws Exception {
//        System.out.println("SM2-test:"+this.input);
//        CipherExample.SM2Cipher(this.input);
//    }
}