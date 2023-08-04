package burp.task;

import burp.Main;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.http.RequestHandler;

import java.util.List;

public class IScanCheck implements ScanCheck {

    /*
     *
     * @param baseRequestResponse The base {@link HttpRequestResponse} that
     *                            should be actively audited.
     * @param auditInsertionPoint An {@link AuditInsertionPoint} object that
     *                            can be queried to obtain details of the insertion point being tested, and
     *                            can be used to build requests for particular payloads.
     * 主动扫描
     * @return
     */
    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint) {
        RequestHandler instance = RequestHandler.getInstance(Main.api);
        List<AuditIssue> auditIssues = instance.handlerRequest(baseRequestResponse);
        Main.api.logging().logToOutput("start scanner" + baseRequestResponse.url());
        return AuditResult.auditResult(auditIssues);
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse) {
        RequestHandler instance = RequestHandler.getInstance(Main.api);
        List<AuditIssue> auditIssues = instance.handlerRequest(baseRequestResponse);
        return AuditResult.auditResult(auditIssues);
    }

    /*
     *
     * @param newIssue      An {@link AuditIssue} at the same URL path that has been
     *                      newly reported by this Scan check.
     * @param existingIssue An {@link AuditIssue} that was previously reported
     *                      by this Scan check.
     * 主动扫描
     * @return
     */
    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue) {
        if (newIssue.httpService().host().equals(existingIssue.httpService().host())
                && newIssue.name().equals(existingIssue.name())
                && newIssue.detail().equals(existingIssue.detail())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        else {
            return ConsolidationAction.KEEP_BOTH;
        }
    }

}
