//package burp.vendor;
//
//import burp.common.Base;
//import burp.common.IAction;
//import burp.Main;
//import burp.api.montoya.http.message.HttpRequestResponse;
//import burp.api.montoya.scanner.audit.issues.AuditIssue;
//import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
//import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
//import burp.ui.ListsModule;
//import burp.ui.UI;
//
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.List;
//import java.util.Map;
//import java.util.regex.Matcher;
//import java.util.regex.Pattern;
//
//public class CheckAKSK implements Base {
//    private final HttpRequestResponse baseRequestResponse;
//    private static Map<String, String> map = new HashMap<>();
//    static {
//        map.put("AWS", "^AKIA[A-Za-z0-9]{16}$");
//        map.put("Google", "^GOOG[\\w\\W]{10,30}$");
//        map.put("Microsoft", "^AZ[A-Za-z0-9]{34,40}$");
//        map.put("IBM", "^IBM[A-Za-z0-9]{10,40}$");
//        map.put("Oracle", "^OCID[A-Za-z0-9]{10,40}$");
//        map.put("ALIYUN", "^LTAI[A-Za-z0-9]{12,20}$");
//        map.put("Tencent", "^AKID[A-Za-z0-9]{13,20}$");
//        map.put("Huawei", "^AK[\\w\\W]{10,62}$");
//    }
//
//
//    private final List<AuditIssue> list = new ArrayList<>();
////    public static final String[] keyWord = new String[]{"ACCESSKEYID","ACCESSKEYSECRET",
////            "ACCESS_KEY_ID","ACCESS_KEY_SECRET",
////            "AccessKey","AccessSecret","Secret",
////            "AccessKeySecret","SECRET_KEY",
////            "ACCESS_KEY",};
//    private final String regex = "(?i)((ACCESSKEYID|ACCESSKEYSECRET|access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\"]([0-9a-zA-Z\\-_=]{8,64})['\"]";
//    @Override
//    public List<AuditIssue> checkVul() {
//        IAction[] action = {
//                this::checkAKSK
//        };
//        for (IAction iAction : action) {
//            iAction.execute();
//        }
//        return list;
//    }
//
//    /***
//     * 检查响应结果，是否存在key泄露
//     */
//    private void checkAKSK(){
////        for (String s : keyWord) {
//////             || baseRequestResponse.response().bodyToString().toLowerCase().contains(s.toLowerCase())
////            if (baseRequestResponse.response().body().countMatches(s) >= 1){
////                AuditIssue auditIssue = AuditIssue.auditIssue("ACCESSKEYID LEAK","THERE MAY BE AN ACCESSKEYID LEAK","",baseRequestResponse.url(), AuditIssueSeverity.HIGH
////                        , AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,baseRequestResponse);
////                list.add(auditIssue);
////                String res = getStringPoint(s,baseRequestResponse.response().bodyToString());
////                UI.updateUIData(new ListsModule(baseRequestResponse),res);
////            }
////        }
//        String regex = "(?i)((access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .\\-,]{0,25})(=|>|:=|\\|\\|:|<=|=>|:).{0,5}['\\\"]([0-9a-zA-Z\\-_=]{8,64})['\\\"]";
//        Pattern pattern_keyword = Pattern.compile(regex);
//        Matcher matcher_keyword = pattern_keyword.matcher(baseRequestResponse.response().bodyToString());
//        while (matcher_keyword.find()) {
//            AuditIssue auditIssue = AuditIssue.auditIssue( " ACCESSKEYID LEAK","THERE MAY BE AN ACCESSKEYID LEAK","",baseRequestResponse.url(), AuditIssueSeverity.HIGH
//                    , AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,baseRequestResponse);
//            list.add(auditIssue);
//            String res = getStringPoint(matcher_keyword.group(),baseRequestResponse.response().bodyToString());
//            UI.updateUIData(new ListsModule(baseRequestResponse),res);
//        }
//        for (Map.Entry<String, String> entry : map.entrySet()) {
//            Pattern pattern = Pattern.compile(entry.getValue());
//            Matcher matcher = pattern.matcher(baseRequestResponse.response().body().toString());
//            if (matcher.matches()) {
//                AuditIssue auditIssue = AuditIssue.auditIssue( entry.getKey() + " ACCESSKEYID LEAK","THERE MAY BE AN ACCESSKEYID LEAK","",baseRequestResponse.url(), AuditIssueSeverity.HIGH
//                        , AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,baseRequestResponse);
//                list.add(auditIssue);
//                String res = getStringPoint(matcher.group(),baseRequestResponse.response().bodyToString());
//                UI.updateUIData(new ListsModule(baseRequestResponse),res);
//            } else if (matcher.find()) {
//                AuditIssue auditIssue = AuditIssue.auditIssue(entry.getKey() + "ACCESSKEYID LEAK","THERE MAY BE AN ACCESSKEYID LEAK","",baseRequestResponse.url(), AuditIssueSeverity.HIGH
//                        , AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,baseRequestResponse);
//                list.add(auditIssue);
//                String res = getStringPoint(matcher.group(),baseRequestResponse.response().bodyToString());
//                UI.updateUIData(new ListsModule(baseRequestResponse),res);
//            }
//        }
//
//    }
//
//    private String getStringPoint(String s,String targetString) {
//        int length = targetString.length();
//        String res = null;
//        int i = targetString.indexOf(s);
//        if ((i + 50) >= length){
//            res = targetString.substring(i);
//        }else {
//            res = targetString.substring(i,i + 50);
//        }
//        return res;
//    }
//
//    public CheckAKSK(HttpRequestResponse httpRequestResponse){
//        this.baseRequestResponse = httpRequestResponse;
//    }
//
//
//}
