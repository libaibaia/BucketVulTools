package burp.vendor;

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

}
