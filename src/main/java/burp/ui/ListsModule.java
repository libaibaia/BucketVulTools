package burp.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

public class ListsModule {
    private final HttpRequestResponse requestResponse;

    public ListsModule(HttpRequestResponse requestResponse) {
        this.requestResponse = requestResponse;
    }

    @Override
    public String toString() {
        return requestResponse.url();
    }

    public HttpRequestResponse getRequestResponse(){
        return requestResponse;
    }
}
