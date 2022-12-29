package com.yuh.burp.ui;

import burp.*;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import static com.yuh.burp.BurpExtender.helpers;
import static com.yuh.burp.utils.HttpUtil.decryptString;
import static com.yuh.burp.utils.HttpUtil.encryptString;

public class FridaRpcToolMenu implements IContextMenuFactory {
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList();
        JMenu chunkedMenu = new JMenu("FridaRpcTool");
        JMenuItem encryptData = new JMenuItem("Encrypt Data");
        JMenuItem decryptData = new JMenuItem("Decrypt Data");
        chunkedMenu.add(encryptData);
        chunkedMenu.add(decryptData);

        //若数据包无法编辑，则将编码解码菜单项设置为禁用
        if(invocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST){
            encryptData.setEnabled(false);
            decryptData.setEnabled(false);
        }

        encryptData.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent arg0) {
                // 获取用户选择的明文数据并返回密文数据
                getSelectionEncryptData(invocation);
            }
        });

        decryptData.addActionListener(new ActionListener(){
            public void actionPerformed(ActionEvent arg0) {
                // 获取用户选择的密文数据并返回明文数据
                getSelectionDecryptData(invocation);
            }
        });

        menus.add(chunkedMenu);
        return menus;
    }

    // 获取用户选择的密文数据并返回明文数据
    public void getSelectionDecryptData(final IContextMenuInvocation invocation) {
        int[] selectionBounds = invocation.getSelectionBounds();
        int start = selectionBounds[0];
        int stop = selectionBounds[1];

        IHttpRequestResponse requestResponse = invocation.getSelectedMessages()[0];
        byte[] request = requestResponse.getRequest();

        String requestData = helpers.bytesToString(request);
        int length = requestData.length();
        String requestSelectedData = requestData.substring(start, stop);

        // 判断是否需要进行 URL 解码
        if (HttpProxyTag.burpUrlDecode) {
            requestSelectedData = helpers.urlDecode(requestSelectedData);
        }

        // 明文数据
        String decryptData = decryptString(requestSelectedData);

        // 替换密文信息
        String decryptRequest = requestData.substring(0, start) + decryptData + requestData.substring(stop, length);
        byte[] decryptRequestBytes = helpers.stringToBytes(decryptRequest);
        requestResponse.setRequest(decryptRequestBytes);
    }

    // 获取用户选择的明文数据并返回密文数据
    public void getSelectionEncryptData(final IContextMenuInvocation invocation) {
        int[] selectionBounds = invocation.getSelectionBounds();
        int start = selectionBounds[0];
        int stop = selectionBounds[1];

        IHttpRequestResponse requestResponse = invocation.getSelectedMessages()[0];
        byte[] request = requestResponse.getRequest();

        String requestData = helpers.bytesToString(request);
        int length = requestData.length();
        String requestSelectedData = requestData.substring(start, stop);

        // 判断是否需要进行 URL 解码
        if (HttpProxyTag.burpUrlDecode) {
            requestSelectedData = helpers.urlDecode(requestSelectedData);
        }

        // 密文数据
        String encryptData = encryptString(requestSelectedData);

        // 替换密文信息
        String decryptRequest = requestData.substring(0, start) + encryptData + requestData.substring(stop, length);
        byte[] decryptRequestBytes = helpers.stringToBytes(decryptRequest);
        requestResponse.setRequest(decryptRequestBytes);
    }
}