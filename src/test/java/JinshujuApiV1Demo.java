package net.jinshuju;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Base64;

public class JinshujuApiV1Demo {

    public static void main(String[] args){

        String apiKey = "x";
        String apiSecret = "x";

        String credentials = apiKey + ":" + apiSecret;

        String base64EncodedCredentials = Base64.getEncoder().encodeToString(credentials.getBytes());
        String authHeaderPayload = "Basic " + base64EncodedCredentials;

        BufferedReader httpResponseReader = null;
        try {
            URL apiEndpointUrl = new URL("https://jinshuju.net/api/v1/forms");
            HttpURLConnection urlConnection = (HttpURLConnection) apiEndpointUrl.openConnection();
            urlConnection.setRequestMethod("GET");
            urlConnection.addRequestProperty("Authorization", authHeaderPayload);

            httpResponseReader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream(), "UTF-8"));
            String lineRead;
            while ((lineRead = httpResponseReader.readLine()) != null) {
                System.out.println(lineRead);
            }
        } catch (IOException ioe) {
            ioe.printStackTrace();
        } finally {
            if (httpResponseReader != null) {
                try {
                    httpResponseReader.close();
                } catch (IOException ignored) {
                }
            }
        }
    }
}
