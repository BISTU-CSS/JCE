package com.jna.model;

import java.util.Arrays;
import java.util.List;

public class DeviceRunStatus {
    public int onboot;
    public int service;
    public int concurrency;
    public int memtotal;
    public int memfree;
    public int cpu;
    public int reserve1;
    public int reserve2;

    public DeviceRunStatus() {
    }

    protected List getFieldOrder() {
        return Arrays.asList("onboot", "service", "concurrency", "memtotal", "memfree", "cpu", "reserve1", "reserve2");
    }

    public String toString() {
        StringBuilder buf = new StringBuilder();
        String nl = System.getProperty("line.separator");
        buf.append("    |    project      |   value  ").append(nl);
        buf.append("   _|_________________|______________________________________________________").append(nl);
        buf.append("   1| Onboot          | ").append(this.onboot).append(nl);
        buf.append("   2| Service         | ").append(this.service).append(nl);
        buf.append("   3| Concurrency     | ").append(this.concurrency).append(nl);
        buf.append("   4| Memtotal        | ").append(this.memtotal).append(nl);
        buf.append("   5| Memfree         | ").append(this.memfree).append(nl);
        buf.append("   6| CPU             | ").append(this.cpu).append(nl);
        return buf.toString();
    }

    public static class ByReference extends DeviceRunStatus implements com.sun.jna.Structure.ByReference {
        public ByReference() {
        }
    }
}
