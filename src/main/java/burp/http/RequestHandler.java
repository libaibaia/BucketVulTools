package burp.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.vendor.Type;
import burp.vendor.aliyun.OSS;
import burp.vendor.huawei.OBS;
import burp.vendor.tencent.COS;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static burp.vendor.Type.*;

public class RequestHandler {
    private final MontoyaApi api;
    private static RequestHandler requestHandler = null;

    public static RequestHandler getInstance(MontoyaApi api) {
        if (requestHandler == null){
            requestHandler = new RequestHandler(api);
        }
        return requestHandler;
    }

    private RequestHandler(MontoyaApi api) {
        this.api = api;
    }


    public List<AuditIssue> handlerRequest(HttpRequestResponse baseRequestResponse){
        // 截取host判断厂商类型
        String host = baseRequestResponse.request().httpService().host();
        String[] split = host.split("\\.");
        String currentDomain = split[split.length - 2] + "." + split[split.length - 1];
        List<AuditIssue> auditIssues = new ArrayList<>();

        //根据server头判断
        Type typeByServer = getTypeByServer(baseRequestResponse);
        if (typeByServer == AliYun){
            auditIssues.addAll(new COS(baseRequestResponse).checkVul());
        }
        else if (typeByServer == Tencent){
            auditIssues.addAll(new OSS(baseRequestResponse).checkVul());
        }
        else if (typeByServer == HauWeiCloud){
            auditIssues.addAll(new OBS(baseRequestResponse).checkVul());
        }
        //如果无法通过server判断则使用域名
        else {
            if (currentDomain.equals(Tencent.getDomain())){
                auditIssues.addAll(new COS(baseRequestResponse).checkVul());
            }
            if (currentDomain.equals(AliYun.getDomain())){
                auditIssues.addAll(new OSS(baseRequestResponse).checkVul());
            }
            if (currentDomain.equals(HauWeiCloud.getDomain())){
                auditIssues.addAll(new OBS(baseRequestResponse).checkVul());
            }
        }

        return auditIssues;
    }

    public static Map parse(String url,String args) {
        Map map = new HashMap();
        //1.创建DocumentBuilderFactory对象
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING,true);
        } catch (ParserConfigurationException e) {
            return null;
        }
        //2.创建DocumentBuilder对象
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document d = builder.parse(url);
            NodeList sList = d.getElementsByTagName(args);
            //element(sList);
            for (int i = 0; i <sList.getLength() ; i++) {
                Node node = sList.item(i);
                NodeList childNodes = node.getChildNodes();
                for (int j = 0; j <childNodes.getLength() ; j++) {
                    if (childNodes.item(j).getNodeType()==Node.ELEMENT_NODE) {
                        map.put(childNodes.item(j).getNodeName(),childNodes.item(j).getFirstChild().getNodeValue());
                        System.out.print(childNodes.item(j).getNodeName() + ":");
                        System.out.println(childNodes.item(j).getFirstChild().getNodeValue());
                    }
                }
            }
            return map;
        } catch (Exception e) {
            return null;
        }
    }
}
