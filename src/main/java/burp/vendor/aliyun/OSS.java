package burp.vendor.aliyun;

import burp.common.Base;
import burp.common.Constant;
import burp.common.IAction;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.List;

public class OSS implements Base {

    List<AuditIssue> auditIssueList = new ArrayList<>();
    private final HttpRequest httpRequest;
    @Override
    public List<AuditIssue> checkVul() {
        IAction[] iActions = {
                this::bucketsTraversable,
                this::checkUploadFile,
                this::checkObjectAcl,
                this::checkBucketPolicy
        };
        for (IAction iAction : iActions) {
            iAction.execute();
        }
        return auditIssueList;
    }


    private void bucketsTraversable(){
        String service = getService(httpRequest);
        HttpRequestResponse get = Base.sendRequest(service, "GET", null, new ArrayList<>());
        if (get.response().statusCode() <= successCodeRange){
            ByteArray body = get.response().body();
            if (body.countMatches("<ListBucketResult>") != 0 && body.countMatches("<Name>") != 0){
                auditIssueList.add(AuditIssue.auditIssue("Buckets are traversable","Buckets are traversable","",
                        get.url(), AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,get));
            }
        }
    }

    private void checkUploadFile(){
        String fileName = "testFileByExt.testFileByExt";
        String service = getService(httpRequest) + "/" + fileName;
        HttpRequestResponse httpRequestResponse = Base.sendRequest(service, "PUT", "test fileUpload", new ArrayList<>());
        if (httpRequestResponse.response().statusCode() <= successCodeRange){
            AuditIssue auditIssue = AuditIssue.auditIssue("Support put to upload files","Support put to upload files","",
                    httpRequestResponse.url(), AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,httpRequestResponse);
            auditIssueList.add(auditIssue);
        }
    }

    public OSS(HttpRequestResponse baseRequestResponse){
        this.httpRequest = baseRequestResponse.request();
    }


    private void checkObjectAcl(){
        String currentUrl = Base.removedAllParameters(httpRequest);
        String currentBucketAcl = "default";
        HttpRequestResponse get = Base.sendRequest(currentUrl +  "?acl", "GET", null, new ArrayList<>());
        short i = get.response().statusCode();
        if (get.response().statusCode() <= successCodeRange){
            auditIssueList.add(AuditIssue.auditIssue("ACL readable","ACL readable","",get.url(), AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,get));
        }
        if (Constant.putAcl){
            ArrayList<HttpHeader> headers = new ArrayList<>();
            headers.add(HttpHeader.httpHeader("x-oss-object-acl",currentBucketAcl));
            HttpRequestResponse put = Base.sendRequest(currentUrl + "?acl", "PUT", null, headers);
            short i1 = put.response().statusCode();
            if (put.response().statusCode() <= successCodeRange) {
                auditIssueList.add(AuditIssue.auditIssue("ACL is writable","ACL is writable","",put.url(), AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,put));
            }
        }
    }



    private void checkBucketPolicy(){
        if (Constant.policyFlag){
            String service = getService(httpRequest);
            ArrayList<HttpHeader> objects = new ArrayList<>();
            String body = "{\n" +
                    "   \"Version\":\"1\",\n" +
                    "   \"Statement\":[\n" +
                    "   {\n" +
                    "     \"Action\":[\n" +
                    "       \"oss:PutObject\",\n" +
                    "       \"oss:GetObject\"\n" +
                    "    ],\n" +
                    "    \"Effect\":\"Allow\",\n" +
                    "    \"Principal\":[\"1234567890\"],\n" +
                    "    \"Resource\":[\"acs:oss:*:*/*\"]\n" +
                    "   }\n" +
                    "  ]\n" +
                    " }";
            HttpRequestResponse put = Base.sendRequest(service + "/?policy", "PUT", body, objects);
            if (put.response().statusCode() <= successCodeRange){
                auditIssueList.add(AuditIssue.auditIssue("policy is writable","policy  is writable","",put.url(), AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,put));
            }
        }
    }

}
