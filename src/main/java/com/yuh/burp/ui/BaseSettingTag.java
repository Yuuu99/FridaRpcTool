package com.yuh.burp.ui;

import burp.IBurpExtenderCallbacks;
import com.yuh.burp.BurpExtender;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Document;
import java.awt.*;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

public class BaseSettingTag {
    public JRadioButton buttonReq = new JRadioButton("请求信息");
    public JRadioButton buttonResp = new JRadioButton("响应信息");
    public JRadioButton buttonReqResp = new JRadioButton("请求和响应信息");
    public JRadioButton buttonStatusStart = new JRadioButton("启用");
    public JRadioButton buttonStatusStop = new JRadioButton("暂停");
    public JRadioButton buttonUrlDecodeStart = new JRadioButton("启用");
    public JRadioButton buttonUrlDecodeStop = new JRadioButton("暂停");
    public JRadioButton buttonRespBodyStart = new JRadioButton("启用");
    public JRadioButton buttonRespBodyStop = new JRadioButton("暂停");
    public JPanel baseSettingPanel = new JPanel();
    public JPanel urlPanel;
    public JPanel hostPanel;
    public JPanel modePanel;
    public JPanel statusPanel;
    public JPanel urlDecodePanel;
    public JPanel reqParamPanel;
    public JPanel reqHeadersPanel;
    public JPanel respParamPanel;
    public JPanel respHeadersPanel;
    public JPanel respBodyPanel;

    public BaseSettingTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs) {
        baseSettingPanel.setLayout(new BoxLayout(baseSettingPanel, BoxLayout.Y_AXIS));
        baseSettingPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        statusPanel = addStatusJRBPanel("状态：");
        hostPanel = addHostJTFPanel();
        urlPanel = addUrlJTFPanel();
        modePanel = addModeJRBPanel("模式：");
        urlDecodePanel = addUrlDecodeJRBPanel("自动URL解码：");

        reqParamPanel = addReqParamJTFPanel();
        reqHeadersPanel = addReqHeadersJTFPanel();
        respParamPanel = addRespParamJTFPanel();
        respHeadersPanel = addRespHeadersJTFPanel();
        respBodyPanel = addRespBodyJRBPanel("响应体解密：");

        tabs.addTab("基本设置", baseSettingPanel);
    }

    public JPanel addHostJTFPanel(){
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel("过滤域名：");
        baseSettingPanel.add(label);
        JTextField jt = new JTextField(200);
        jt.setMaximumSize(jt.getPreferredSize());
        jt.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpHost = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpHost = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void changedUpdate(DocumentEvent e) {

            }
        });
        baseSettingPanel.add(jt);
        panel.add(label);
        panel.add(jt);
        baseSettingPanel.add(panel);
        return panel;
    }

    public JPanel addUrlJTFPanel(){
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel("RPC接口地址：");
        baseSettingPanel.add(label);
        JTextField jt = new JTextField(200);
        jt.setMaximumSize(jt.getPreferredSize());
        jt.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpRpcUrl = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpRpcUrl = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void changedUpdate(DocumentEvent e) {

            }
        });
        baseSettingPanel.add(jt);
        panel.add(label);
        panel.add(jt);
        baseSettingPanel.add(panel);
        return panel;
    }

    public JPanel addReqParamJTFPanel(){
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel("请求参数解密：");
        baseSettingPanel.add(label);
        JTextField jt = new JTextField(200);
        jt.setMaximumSize(jt.getPreferredSize());
        jt.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpReqParam = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpReqParam = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void changedUpdate(DocumentEvent e) {

            }
        });
        baseSettingPanel.add(jt);
        panel.add(label);
        panel.add(jt);
        baseSettingPanel.add(panel);
        return panel;
    }

    public JPanel addReqHeadersJTFPanel(){
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel("请求头解密：");
        baseSettingPanel.add(label);
        JTextField jt = new JTextField(200);
        jt.setMaximumSize(jt.getPreferredSize());
        jt.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpReqHeaders = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpReqHeaders = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void changedUpdate(DocumentEvent e) {

            }
        });
        baseSettingPanel.add(jt);
        panel.add(label);
        panel.add(jt);
        baseSettingPanel.add(panel);
        return panel;
    }

    public JPanel addRespParamJTFPanel(){
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel("响应JSON参数解密：");
        baseSettingPanel.add(label);
        JTextField jt = new JTextField(200);
        jt.setMaximumSize(jt.getPreferredSize());
        jt.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpRespParam = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpRespParam = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void changedUpdate(DocumentEvent e) {

            }
        });
        baseSettingPanel.add(jt);
        panel.add(label);
        panel.add(jt);
        baseSettingPanel.add(panel);
        return panel;
    }

    public JPanel addRespHeadersJTFPanel(){
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel("响应头解密：");
        baseSettingPanel.add(label);
        JTextField jt = new JTextField(200);
        jt.setMaximumSize(jt.getPreferredSize());
        jt.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpRespHeaders = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                Document doc = e.getDocument();
                try {
                    BurpExtender.burpRespHeaders = doc.getText(0, doc.getLength()); //返回文本框输入的内容
                } catch (BadLocationException ex) {
                    BurpExtender.stderr.println(ex.getMessage());
                }
            }

            @Override
            public void changedUpdate(DocumentEvent e) {

            }
        });
        baseSettingPanel.add(jt);
        panel.add(label);
        panel.add(jt);
        baseSettingPanel.add(panel);
        return panel;
    }

    public JPanel addModeJRBPanel(String text){
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel(text);
        baseSettingPanel.add(label);
        buttonReq.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                BurpExtender.burpMode = "ReqParam";
            }
        });
        buttonResp.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                BurpExtender.burpMode = "RespParam";
            }
        });
        buttonReqResp.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                BurpExtender.burpMode = "ReqRespParam";
            }
        });
        ButtonGroup group = new ButtonGroup();
        group.add(buttonReq);
        group.add(buttonResp);
        group.add(buttonReqResp);
        panel.add(label);
        panel.add(buttonReq);
        panel.add(buttonResp);
        panel.add(buttonReqResp);
        baseSettingPanel.add(panel);
        return panel;
    }

    public JPanel addStatusJRBPanel(String text){
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel(text);
        baseSettingPanel.add(label);
        buttonStatusStart.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                HttpProxyTag.burpStatus = true;
            }
        });
        buttonStatusStop.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                HttpProxyTag.burpStatus = false;
            }
        });
        ButtonGroup group = new ButtonGroup();
        group.add(buttonStatusStart);
        group.add(buttonStatusStop);
        panel.add(label);
        panel.add(buttonStatusStart);
        panel.add(buttonStatusStop);
        baseSettingPanel.add(panel);
        return panel;
    }

    public JPanel addUrlDecodeJRBPanel(String text){
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel(text);
        baseSettingPanel.add(label);
        buttonUrlDecodeStart.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                HttpProxyTag.burpUrlDecode = true;
            }
        });
        buttonUrlDecodeStop.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                HttpProxyTag.burpUrlDecode = false;
            }
        });
        ButtonGroup group = new ButtonGroup();
        group.add(buttonUrlDecodeStart);
        group.add(buttonUrlDecodeStop);
        panel.add(label);
        panel.add(buttonUrlDecodeStart);
        panel.add(buttonUrlDecodeStop);
        baseSettingPanel.add(panel);
        return panel;
    }

    public JPanel addRespBodyJRBPanel(String text){
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel label = new JLabel(text);
        baseSettingPanel.add(label);
        buttonRespBodyStart.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                HttpProxyTag.burpRespBody = true;
            }
        });
        buttonRespBodyStop.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                HttpProxyTag.burpRespBody = false;
            }
        });
        ButtonGroup group = new ButtonGroup();
        group.add(buttonRespBodyStart);
        group.add(buttonRespBodyStop);
        panel.add(label);
        panel.add(buttonRespBodyStart);
        panel.add(buttonRespBodyStop);
        baseSettingPanel.add(panel);
        return panel;
    }

}