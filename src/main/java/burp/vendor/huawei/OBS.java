package burp.vendor.huawei;

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
import burp.http.RequestHandler;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OBS implements Base {
    List<AuditIssue> auditIssueList = new ArrayList<>();
    private final HttpRequest httpRequest;
    @Override
    public List<AuditIssue> checkVul() {
        IAction[] iActions = {
                this::checkPutObject,
                this::bucketsTraversable,
                this::checkObjectAcl,
                this::checkBucketAcl
        };
        for (IAction iAction : iActions) {
            iAction.execute();
        }
        return auditIssueList;
    }

    private void checkPutObject(){
        String service = getService(httpRequest);
        HttpRequestResponse httpRequestResponse = Base.sendRequest(service + "/testFileByExt.testFileByExt","PUT","test",new ArrayList<>());
        short i = httpRequestResponse.response().statusCode();
        if (i <= successCodeRange){
            AuditIssue auditIssue = AuditIssue.auditIssue("Support put to upload files","Support put to upload files","",
                    httpRequestResponse.url(), AuditIssueSeverity.HIGH,
                    AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,httpRequestResponse);
            auditIssueList.add(auditIssue);
        }
    }

    private void checkObjectAcl(){
        String url = httpRequest.url();
        String s = Base.removedAllParameters(HttpRequest.httpRequestFromUrl(url));
        String ownerId = null;
        HttpRequestResponse get = Base.sendRequest(s + "?acl", "GET", null, new ArrayList<>());
        if (get.response().statusCode() <= successCodeRange){
            AuditIssue auditIssue = AuditIssue.auditIssue("Object ACL is readable","Object ACL is readable","",
                    get.url(), AuditIssueSeverity.LOW,
                    AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.LOW,get);
            Map owner = RequestHandler.parse(get.url(), "Owner");
            if (owner != null&&!owner.isEmpty()) ownerId = (String) owner.get("ID");
            auditIssueList.add(auditIssue);
        }
        if (ownerId != null){
            String body = "<AccessControlPolicy><Owner>" +
                    "<ID>%s</ID>" +
                    "</Owner><Delivered>true</Delivered>" +
                    "<AccessControlList><Grant><Grantee>" +
                    "<ID>%s</ID>" +
                    "</Grantee>" +
                    "<Permission>FULL_CONTROL</Permission>" +
                    "</Grant>" +
                    "</AccessControlList></AccessControlPolicy>";
            HttpRequestResponse put = Base.sendRequest(get.url(), "PUT", body.formatted(ownerId, ownerId), new ArrayList<>());
            if (put.response().statusCode() <= successCodeRange){
                AuditIssue auditIssue = AuditIssue.auditIssue("Object ACLs are writable","Object ACLs are writable","",
                        put.url(), AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,put);
                auditIssueList.add(auditIssue);
            }
        }
    }
    private void bucketsTraversable(){
        String service = getService(httpRequest);
        HttpRequestResponse get = Base.sendRequest(service, "GET", null, new ArrayList<>());
        if (get.response().statusCode() <= successCodeRange){
            ByteArray body = get.response().body();
            if (body.countMatches("<Name>") != 0 && body.countMatches("<Contents>") != 0){
                auditIssueList.add(AuditIssue.auditIssue("Buckets are traversable","Buckets are traversable","",
                        get.url(), AuditIssueSeverity.HIGH,
                        AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,get));
            }
        }
    }

    private void checkBucketAcl(){
        String service = getService(httpRequest);
        HttpRequestResponse get = Base.sendRequest(service + "/?acl", "GET", null, new ArrayList<>());
        if (get.response().statusCode() <= successCodeRange){
            ByteArray body = get.response().body();
            if (body.countMatches("<Owner>") != 0 && body.countMatches("<AccessControlList>") != 0){
                auditIssueList.add(AuditIssue.auditIssue("The bucket ACL is readable","The bucket ACL is readable","",
                        get.url(), AuditIssueSeverity.LOW,
                        AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.LOW,get));
            }
        }
        ArrayList<HttpHeader> objects = new ArrayList<>();
       if (Constant.putAcl){
           objects.add(HttpHeader.httpHeader("x-obs-acl","public-read-write-delivered"));
           HttpRequestResponse put = Base.sendRequest(get.url(), "PUT",null,objects);
           if (put.response().statusCode() <= successCodeRange){
               auditIssueList.add(AuditIssue.auditIssue("The bucket ACL are traversable","The bucket ACL are traversable","",
                       put.url(), AuditIssueSeverity.HIGH,
                       AuditIssueConfidence.FIRM,"","",AuditIssueSeverity.HIGH,put));
           }
       }
    }

    public OBS(HttpRequestResponse baseRequestResponse) {
        this.httpRequest = baseRequestResponse.request();
    }

}
