# BucketVulTools
Burpsuite存储桶配置不当漏洞检测插件
## 用法
- 存储桶相关配置检测自动化，访问目标网站将会自动检测，如：访问的网站引用存储桶上的静态资源，就会触发检测逻辑,将指纹识别方式修改了下，通过server头及域名中的一个方式进行判断，另外由于敏感信息误报较多，已经取消了。
## 导入burpsuite
## 存储桶相关配置问题检测结果同步到bp的issue
**检测结果，目前支持阿里云，华为云，腾讯三个厂商的检测，存储桶文件遍历，acl读写，Policy读写及未授权上传**
![image](https://github.com/libaibaia/BucketVulTools/assets/108923559/802404b9-d336-4bc1-979d-82dd5c616d6c)
**使用的新版bp接口，所以版本有要求，jdk17**
## 打包
**mvn package**
## 导入bp
![image](https://github.com/libaibaia/BucketVulTools/assets/108923559/4c5f6b3e-729b-468a-b268-c4a51a706f6b)
## 敏感字段会在这个面板展示
![image](https://github.com/libaibaia/BucketVulTools/assets/108923559/3105953b-2e8b-4490-b9e3-7fb7badf7908)
