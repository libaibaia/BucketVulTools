package burp.common;

import burp.Main;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import java.util.List;

public interface Base {

    static final int successCodeRange = 299;
    static final int failedCodeRange = 400;
    //flag参数用于标记是否检测put acl权限
    HttpHeader header = HttpHeader.httpHeader("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36");
    List<AuditIssue> checkVul();
    default String getService(HttpRequest httpRequest) {
        String host = httpRequest.httpService().host();
        String p = httpRequest.httpService().secure() ? "https://" : "http://";
        return p + host;
    }


    static HttpRequestResponse sendRequest(String url, String method, String body, List<HttpHeader> header){

        HttpRequest httpRequest = HttpRequest.httpRequestFromUrl(url).withMethod(method);
        if (!header.isEmpty()){
            for (HttpHeader httpHeader : header) {
                httpRequest = httpRequest.withAddedHeader(httpHeader).withMethod(method);
            }
        }
        if (body != null) httpRequest = httpRequest.withBody(body).withAddedHeader(Base.header).withMethod(method);
        return Main.api.http().sendRequest(httpRequest);
    }
    static String removedAllParameters(HttpRequest httpRequest){
        List<ParsedHttpParameter> parameters = httpRequest.parameters();
        HttpRequest httpRequest1 = httpRequest;
        for (ParsedHttpParameter parameter : parameters) {
            httpRequest1 = httpRequest1.withRemovedParameters(parameter);
        }
        return httpRequest1.url();
    }
}
