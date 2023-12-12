package burp.vendor;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.util.List;

public enum Type {

    Tencent("腾讯云","myqcloud.com",0),
    AliYun("阿里云","aliyuncs.com",1),
    HauWeiCloud("华为云","myhuaweicloud.com",2);


    private String name;
    private String domain;
    private int index;

    Type(String name, String domain, int index) {
        this.name = name;
        this.domain = domain;
        this.index = index;

    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public static Type getTypeByServer(HttpRequestResponse base){
        List<HttpHeader> headers = base.response().headers();
        for (HttpHeader header : headers) {
            if (header.name().equals("Server") && header.value().equals("AliyunOSS"))
                return AliYun;
            if (header.name().equals("Server") && header.value().equals("tencent-cos")){
                return Tencent;
            }
            if (header.name().equals("Server") && header.value().equals("OBS")){
                return HauWeiCloud;
            }
        }
        return null;
    }

}
