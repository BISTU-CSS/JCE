package com.provider;

import com.jna.api.LibCrypto;
import com.jna.model.DeviceInfo;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import java.security.AccessController;
import java.security.AuthProvider;
import java.security.PrivilegedAction;
import java.security.SecurityPermission;

public class NDSecProvider extends AuthProvider {

    private static final long serialVersionUID = 1L;

    private static final String name = "NDSecProvider";
    private static final double version = 1.0d;
    private static final String info = "Beijing Nine Dimensions Data Security JCE";
    public String getMachineInfo(){
        LibCrypto libCrypto = new LibCrypto();
        DeviceInfo a =  libCrypto.getDeviceInfo();
        return a.toString();
    }
    public NDSecProvider() {
        super(name, version, info);
        //向jce授权
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            @Override
            public Object run() {
                //放入自己的基础实现类
                //格式：类型.算法
                for (ProviderEnum provider : ProviderEnum.values()) {
                    put(provider.getCode(), provider.getClassPath());
                }
                return null;
            }
        });
    }

    protected NDSecProvider(String name, double version, String info) {
        super(name, version, info);
    }

    @Override
    public void login(Subject subject, CallbackHandler handler) throws LoginException {
        SecurityManager securityManager = System.getSecurityManager();
        securityManager.checkPermission(new SecurityPermission("authProvider." + this.getName()));
    }

    @Override
    public void logout() throws LoginException {

    }

    @Override
    public void setCallbackHandler(CallbackHandler handler) {

    }

    //获取名字等
    public String getName() {
        return name;
    }

    public String getInfo() {
        return info;
    }

    public double getVersion() {
        return version;
    }
}
