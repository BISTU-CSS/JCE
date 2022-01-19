package example;


import com.provider.NDSecProvider;
import com.util.BytesUtil;

import java.security.SecureRandom;
import java.security.Security;

public class RandomExample {

    public static void main(String[] args) throws Exception {
        //对随机数进行测试setSeed
        NDSecProvider baseProvider = new NDSecProvider();
        Security.addProvider(baseProvider);

        SecureRandom secureRandom = SecureRandom.getInstance("RND", baseProvider);

//        byte[] seed = secureRandom.generateSeed(32);
//        System.out.println(BytesUtil.bytes2int(seed));
        for(int i=0;i<2;i++){
            byte[] random = new byte[10000];
            secureRandom.nextBytes(random);
            System.out.println(BytesUtil.bytes2hex(random));
        }
    }

}
