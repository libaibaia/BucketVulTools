package burp.vendor.tencent;

import burp.common.Base;
import burp.common.Constant;
import burp.common.IAction;
import burp.Main;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;

public class COS implements Base {
    List<AuditIssue> auditIssueList = new ArrayList<>();

    private final HttpRequest httpRequest;

    /***
     * 检查acl权限
     */
    private void checkAcl() {
        String currentUrl = getService(httpRequest) +  "/?acl";
        if (Constant.putAcl){
            HttpRequestResponse put = Main.api.http().sendRequest(HttpRequest.httpRequestFromUrl(currentUrl).
                    withMethod("PUT").
                    withAddedHeader("x-cos-acl","public-read-write").
                    withAddedHeader("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36"));
            if (put.response().statusCode() <= successCodeRange) {
                auditIssueList.add(AuditIssue.auditIssue("ACL is writable","ACL is writable","",put.url(), AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,put));
            }
        }
        HttpRequestResponse get = Main.api.http().sendRequest(HttpRequest.httpRequestFromUrl(currentUrl).
                withMethod("GET").
                withAddedHeader("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36"));
        if (get.response().body().countMatches(ByteArray.byteArray("<Permission>")) != 0){
            auditIssueList.add(AuditIssue.auditIssue("ACL readable","ACL readable","",get.url(), AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,get));
        }

    }

    public COS(HttpRequestResponse baseRequestResponse){
        this.httpRequest = baseRequestResponse.request();
    }

    /***
     * 检查存储桶是否可遍历
     */
    private void bucketsTraversable(){
        String service = getService(httpRequest);
        HttpRequestResponse httpRequestResponse = Main.api.http().sendRequest(
                HttpRequest.httpRequestFromUrl(service).
                withAddedHeader("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36")
        );
        if (httpRequestResponse.response().statusCode() <= successCodeRange){
            ByteArray body = httpRequestResponse.response().body();
            if (body.countMatches("<ListBucketResult>") != 0 && body.countMatches("<Name>") != 0){
                auditIssueList.add(AuditIssue.auditIssue("Buckets are traversable","Buckets are traversable","",
                        httpRequestResponse.url(), AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,httpRequestResponse));
            }
        }
    }

    /*
    测试文件上传
     */
    private void checkUploadFile(){
        String fileName = "testFileByExt.testFileByExt";
        String service = getService(httpRequest);
        HttpRequestResponse testFileUpload = Main.api.http().sendRequest(HttpRequest.httpRequestFromUrl(service + "/" + fileName).
                withAddedHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36").withBody("test fileUpload").withMethod("PUT")
        );
        if (testFileUpload.response().statusCode() <= successCodeRange){
            AuditIssue auditIssue = AuditIssue.auditIssue("Support put to upload files","Support put to upload files","",
                    testFileUpload.url(), AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,testFileUpload);
            auditIssueList.add(auditIssue);
        }
    }


    @Override
    public List<AuditIssue> checkVul(){
        IAction[] iActions = {
                this::checkAcl,
                this::bucketsTraversable,
                this::checkUploadFile
        };
        for (IAction iAction : iActions) {
            iAction.execute();
        }
        return auditIssueList;
    }
}
