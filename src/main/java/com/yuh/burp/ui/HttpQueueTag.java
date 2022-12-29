package com.yuh.burp.ui;

import burp.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class HttpQueueTag extends AbstractTableModel implements IMessageEditorController {
    private JSplitPane mjSplitPane;
    private List<TablesData> Udatas = new ArrayList<TablesData>();
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    private ITextEditor iTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private URLTable Utable;
    private JScrollPane UscrollPane;
    private JSplitPane HjSplitPane;
    private JTabbedPane Ltable;
    private JTabbedPane Rtable;

    public HttpQueueTag(IBurpExtenderCallbacks callbacks, JTabbedPane tabs) {
        JPanel scanQueue = new JPanel(new BorderLayout());

        // 主分隔面板
        mjSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 任务栏面板
        Utable = new URLTable(HttpQueueTag.this);
        UscrollPane = new JScrollPane(Utable);

        // 请求与响应界面的分隔面板规则
        HjSplitPane = new JSplitPane();
        HjSplitPane.setResizeWeight(0.5);

        // 请求面板
        Ltable = new JTabbedPane();
        HRequestTextEditor = callbacks.createMessageEditor(HttpQueueTag.this, false);
        Ltable.addTab("Request", HRequestTextEditor.getComponent());

        // 响应面板
        Rtable = new JTabbedPane();
        HResponseTextEditor = callbacks.createMessageEditor(HttpQueueTag.this, false);
        Rtable.addTab("Response", HResponseTextEditor.getComponent());

        // 自定义程序UI组件
        HjSplitPane.add(Ltable, "left");
        HjSplitPane.add(Rtable, "right");

        mjSplitPane.add(UscrollPane, "left");
        mjSplitPane.add(HjSplitPane, "right");

        scanQueue.add(mjSplitPane);
        tabs.addTab("请求队列", scanQueue);
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public int getRowCount() {
        return this.Udatas.size();
    }

    @Override
    public int getColumnCount() {
        return 9;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return "#";
            case 1:
                return "Host";
            case 2:
                return "Method";
            case 3:
                return "Path";
            case 4:
                return "Status";
            case 5:
                return "Length";
            case 6:
                return "Time";
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        TablesData datas = this.Udatas.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return datas.id;
            case 1:
                return datas.host;
            case 2:
                return datas.method;
            case 3:
                return datas.url;
            case 4:
                return datas.status;
            case 5:
                return datas.length;
            case 6:
                return datas.time;
        }
        return null;
    }

    public int add(String host, String method, String url, String status, String length, IHttpRequestResponse requestResponse) {
        synchronized (this.Udatas) {
            Date d = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String time = sdf.format(d);

            int id = this.Udatas.size();
            this.Udatas.add(
                new TablesData(id, host, method, url, status, length, time, requestResponse)
            );
            fireTableRowsInserted(id, id);
            return id;
        }
    }

    private class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            TablesData dataEntry = HttpQueueTag.this.Udatas.get(convertRowIndexToModel(row));
            HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    private static class TablesData {
        final int id;
        final String host;
        final String method;
        final String url;
        final String status;
        final String length;
        final String time;
        final IHttpRequestResponse requestResponse;

        public TablesData(int id, String host, String method,String url, String status, String length, String time, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.host = host;
            this.method = method;
            this.url = url;
            this.status = status;
            this.length = length;
            this.time = time;
            this.requestResponse = requestResponse;
        }
    }
}