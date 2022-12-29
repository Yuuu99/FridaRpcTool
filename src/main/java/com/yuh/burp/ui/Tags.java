package com.yuh.burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;

import javax.swing.*;
import java.awt.*;

public class Tags implements ITab {
    private final JTabbedPane tabs;
    private String tagName;
    private BaseSettingTag baseSettingTag;
    private HttpQueueTag httpQueueTag;

    public Tags(IBurpExtenderCallbacks callbacks, String name) {
        this.tagName = name;
        tabs = new JTabbedPane();
        // 请求队列-窗口
        HttpQueueTag scanQueueTag = new HttpQueueTag(callbacks, tabs);
        this.httpQueueTag = scanQueueTag;
        // 基本设置-窗口
        this.baseSettingTag = new BaseSettingTag(callbacks, tabs);
        // 自定义组件-导入
        callbacks.customizeUiComponent(tabs);
        // 将自定义选项卡添加到Burp的UI
        callbacks.addSuiteTab(Tags.this);
    }

    public HttpQueueTag getHttpQueueTagClass() {
        return this.httpQueueTag;
    }

    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }
}