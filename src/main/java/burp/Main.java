package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.ui.menu.Menu;
import burp.task.IScanCheck;
import burp.ui.UI;

import javax.swing.*;
import java.awt.*;

public class Main implements BurpExtension {
    public static MontoyaApi api = null;
    @Override
    public void initialize(MontoyaApi api) {
        Main.api = api;
        api.extension().setName("ex");
        api.userInterface().registerSuiteTab("AkSkPane", UI.getUI(
                api.userInterface().createHttpRequestEditor(),
                api.userInterface().createHttpResponseEditor())
        );
        api.scanner().registerScanCheck(new IScanCheck());
    }
}
