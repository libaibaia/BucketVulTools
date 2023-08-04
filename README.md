# BucketVulTools
Burpsuite存储桶配置不当漏洞检测插件
## 用法
- 存储桶相关配置检测自动化，访问目标网站将会自动检测，如：访问的网站引用存储桶上的静态资源，就会触发检测逻辑，目前是根据域名检测，但是某些网站会使用自己的域名指向存储桶，暂时不能检测
## 导入burpsuite，检测敏感字段，正则部分参考
## 存储桶相关配置问题检测结果同步到bp的issue
**检测结果，目前支持阿里云，华为云，腾讯三个厂商的检测，存储桶文件遍历，acl读写，Policy读写及未授权上传**
![image](https://github.com/libaibaia/BucketVulTools/assets/108923559/802404b9-d336-4bc1-979d-82dd5c616d6c)
## 部分敏感字段检测相关正则参考
**《云业务 AccessKey 标识特征整理》https://wiki.teamssix.com/cloudservice/more/**
**使用的新版bp接口，所以版本有要求，jdk17**
## 打包
**mvn package**
## 导入bp
![image](https://github.com/libaibaia/BucketVulTools/assets/108923559/4c5f6b3e-729b-468a-b268-c4a51a706f6b)
## 敏感字段会在这个面板展示
![image](https://github.com/libaibaia/BucketVulTools/assets/108923559/3105953b-2e8b-4490-b9e3-7fb7badf7908)
