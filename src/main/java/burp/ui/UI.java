package burp.ui;

import burp.Main;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class UI {
    private static JTable currentTable;
    private static JPanel tableJPanel;
    private static HttpRequestEditor requestEditor;
    private static HttpResponseEditor httpResponseEditor;
    private static int num = 0;
    private static Component createTable(){
        String[] tableTitle = new String[]{"行数","url","匹配参数"};
        currentTable = new JTable(){
            public boolean isCellEditable(int row,int col){
                return col == 2;
            }
        };
        currentTable.getTableHeader().setReorderingAllowed(false);
        DefaultTableModel model = (DefaultTableModel) currentTable.getModel();
        model.setColumnIdentifiers(tableTitle);
        currentTable.setModel(model);
        currentTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int r = currentTable.getSelectedRow();
                ListsModule valueAt = (ListsModule) currentTable.getValueAt(r, 1);
                requestEditor.setRequest(valueAt.getRequestResponse().request());
                httpResponseEditor.setResponse(valueAt.getRequestResponse().response());
                httpResponseEditor.setSearchExpression(currentTable.getValueAt(r, 2).toString());
            }
        });
        return new JScrollPane(currentTable);
    }

    private static Component createLayout(HttpRequestEditor reqEdit, HttpResponseEditor respEdit){
        requestEditor = reqEdit;
        httpResponseEditor = respEdit;
        tableJPanel = new JPanel();
        tableJPanel.setLayout(new GridLayout(1,2));
        JScrollPane jScrollPane = new JScrollPane(createTable());
        tableJPanel.add(jScrollPane);
        JPanel reqRespEdit = new JPanel();
        reqRespEdit.setLayout(new GridLayout(1,2));
        reqRespEdit.add(reqEdit.uiComponent());
        reqRespEdit.add(respEdit.uiComponent());
        JPanel mainPane = new JPanel();
        mainPane.setLayout(new GridLayout(2,1));
        mainPane.add(tableJPanel);
        mainPane.add(reqRespEdit);
        mainPane.setVisible(true);
        return mainPane;
    }

    public static Component getUI(HttpRequestEditor reqEdit,HttpResponseEditor respEdit){
        return createLayout(reqEdit,respEdit);
    }
    private static void setModeData(ListsModule listsModule,String key){
        DefaultTableModel model = (DefaultTableModel) currentTable.getModel();
        model.addRow(new Object[]{num++,listsModule,key});
        currentTable.setModel(model);
//        Main.api.logging().logToOutput(listsModule.toString());
    }

//    public static void createConfigUI(){
//        JPanel jPanel = new JPanel(new BorderLayout());
//        jPanel.add(new ConfigUI(),BorderLayout.CENTER);
//        tableJPanel.add(jPanel);
//    }

    public static void updateUIData(ListsModule listsModule,String key){
        setModeData(listsModule,key);
    }

}
