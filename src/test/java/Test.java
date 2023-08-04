import burp.Main;
import burp.http.RequestHandler;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class Test {

    public static void main(String[] args) {
        String ak = "ACCESSKEYID:sdhaiohklnvnlkaujklqwlqksdaaaaaaaaaaaaaaaaaaaaaaaagdsggggggggggggggggggoiyhjkfsba,mcklajsd;lsajdl;sakl.cm.,xnz.jdl;abndflksbfvkldnsk.,mxzm.ajdklabkjdba.ko;wfbn,mvsaaaaaaaaaaaaaaaaaaaaaaaaaaafsdgggggggggg";
        int accesskeyid = ak.indexOf("ACCESSKEYID");
        String res = null;
        if ((accesskeyid + 50) >= ak.length()){
            res = ak.substring(accesskeyid);
        }
        else {
            res = ak.substring(accesskeyid,50);
        }
        System.out.println(res);

    }
}
