package com.provider;

import com.util.FileUtil;

import java.util.ArrayList;
import java.util.List;

public class ProviderConfig {
    //单例模式
    private String connect;     //设置打开设备超时时间，单位为秒
    private String poolsize;    //设置密码服务连接池
    private String service;     //密码业务超时时间，单位为秒
    private List<Machine> machinesList = new ArrayList<>();
    private class Machine{
        public Machine(String ip, String port, String password, String device_type) {
            this.ip = ip;
            this.port = port;
            this.password = password;
            this.device_type = device_type;
        }
        public String getSocket(){
            return "{\"device_type\": \""+this.device_type+"\", \"device_socket\": \""+this.ip+":"+this.port+"\"}";
        }
        public Machine(){}
        private String ip;       //设置密码机IP地址
        private String port;     //设置密码机服务端口
        private String password; //设置密码服务连接密码
        private String device_type;  //设置密码设备类型
    }
    private volatile static ProviderConfig providerConfig;

    private ProviderConfig() throws Exception {
        //获取config信息
        String config = FileUtil.getFileAsString("address.conf");
        this.poolsize = "";
        this.service = "";
        this.connect = "";
        String[] s1= config.split("\\r?\\n");
        List<String> stringList = new ArrayList<>();
        for(int i=0;i<s1.length;i++) {
            if(s1[i].contains("#"))
            {//带有#的表示注释
                continue;
            }
            stringList.add(s1[i]);
        }
        s1 = null;
        for(int i=0;i<stringList.size();i++){
            String x = stringList.get(i);
           // System.out.println(x);
            if(x.equals("[DeviceSocket1]")){    //后面4句分别是device_type,ip,port,password
                if(stringList.get(i+1).contains("device_type")&&stringList.get(i+2).contains("ip")&&
                stringList.get(i+3).contains("port")&&stringList.get(i+4).contains("password")){
                    String dt = stringList.get(i+1).substring(12);
                    String ip = stringList.get(i+2).substring(3);
                    String pt = stringList.get(i+3).substring(5);
                    String pw = stringList.get(i+4).substring(9);
                    i=i+4;
                    Machine machineIn = new Machine(ip,pt,pw,dt);
                    machinesList.add(machineIn);
                }
                else
                {
                    throw new Exception("Wrong configuration!!");
                }
            }else if(x.equals("[TimeLimit]")){
                if(stringList.get(i+1).contains("connect")&&stringList.get(i+2).contains("service")){
                    this.connect = stringList.get(i+1).substring(8);
                    this.service = stringList.get(i+2).substring(8);
                }else
                {
                    throw new Exception("Wrong configuration!!");
                }
            }else if(x.equals("[ConnectionPool]")){
                if(stringList.get(i+1).contains("poolsize")){
                    this.poolsize = stringList.get(i+1).substring(9);
                }else
                {
                    throw new Exception("Wrong configuration!!");
                }
            }else if(x.equals("")){

            }
        }
    }
    public String getConnect() {
        return connect;
    }
    public String getPoolsize() {
        return poolsize;
    }
    public String getService() {
        return service;
    }
    public List<Machine> getMachinesList() {
        return machinesList;
    }
    public String getFirstConfig() {
        return machinesList.get(0).getSocket();
    }
    public static ProviderConfig getProviderConfig() throws Exception {
        if(providerConfig == null) {
            synchronized (ProviderConfig.class){
                if(providerConfig == null){
                    providerConfig = new ProviderConfig();
                }
            }
        }
        return providerConfig;
    }

}
