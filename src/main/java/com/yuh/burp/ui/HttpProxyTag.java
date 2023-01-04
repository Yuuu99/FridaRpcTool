package com.yuh.burp.ui;

import burp.*;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.yuh.burp.BurpExtender;

import java.awt.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static com.yuh.burp.BurpExtender.*;
import static com.yuh.burp.utils.HttpUtil.decryptString;
import static com.yuh.burp.utils.JsonUtil.*;

public class HttpProxyTag implements IMessageEditorTab {
    private ITextEditor iTextEditor;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    public JSONObject jsonObject;
    public static boolean burpStatus;
    public static boolean burpUrlDecode;
    public static boolean burpReqBody;
    public static boolean burpRespBody;

    public HttpProxyTag(IBurpExtenderCallbacks callbacks) {
        this.iTextEditor = callbacks.createTextEditor();
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
    }

    @Override
    public String getTabCaption() {
        return "FridaRpcTool";
    }

    @Override
    public Component getUiComponent() {
        return iTextEditor.getComponent();
    }

    @Override
    public boolean isEnabled(byte[] content, boolean isRequest) {
        return burpStatus;
    }

    @Override
    public void setMessage(byte[] content, boolean isRequest) {
        StringBuffer stringBuffer = new StringBuffer("");
        // 清空内容
        iTextEditor.setText("".getBytes(StandardCharsets.UTF_8));
        jsonObject = new JSONObject();

        if (isRequest && burpMode == "ReqParam") { // 请求信息包含密文
            stringBuffer = reqParamMode(content);
            iTextEditor.setText(stringBuffer.toString().getBytes(StandardCharsets.UTF_8));
        } else if (!isRequest && burpMode == "RespParam") { // 响应信息包含密文
            stringBuffer = respParamMode(content);
            iTextEditor.setText(stringBuffer.toString().getBytes(StandardCharsets.UTF_8));
        } else if (burpMode == "ReqRespParam") { // 请求和响应信息包含密文
            if (isRequest) {
                stringBuffer = reqParamMode(content);
                iTextEditor.setText(stringBuffer.toString().getBytes(StandardCharsets.UTF_8));
            } else {
                stringBuffer = respParamMode(content);
                iTextEditor.setText(stringBuffer.toString().getBytes(StandardCharsets.UTF_8));
            }
        }

    }

    @Override
    public byte[] getMessage() {
        return new byte[0];
    }

    @Override
    public boolean isModified() {
        return false;
    }

    @Override
    public byte[] getSelectedData() {
        return new byte[0];
    }

    // 请求信息解密
    public StringBuffer reqParamMode(byte[] content){
        int start = 0;
        int stop = 0;
        StringBuffer httpParam = new StringBuffer("");
        StringBuffer httpHeaders = new StringBuffer("");
        StringBuffer httpReqText = new StringBuffer("");
        StringBuffer httpCipherText = new StringBuffer("");

        IRequestInfo iRequestInfo = helpers.analyzeRequest(content);

        // 请求参数解密
        if (burpReqParam.length() != 0) {
            String paramData = "";
            List<IParameter> parameters = iRequestInfo.getParameters();
            for (IParameter parameter : parameters) {
                httpParam.append(parameter.getName() + ": " + parameter.getValue() + "\n");
            }
            start = httpParam.indexOf(burpReqParam);
            if (start != -1){
                stop = httpParam.indexOf("\n", start);
                paramData = httpParam.substring(start, stop);
                httpCipherText.append(paramData + "\n\n");
            }

            // 获取密文
            String sourceData =  paramData.substring(burpReqParam.length() + 2);
            // 判断是否需要进行 URL 解码
            if (HttpProxyTag.burpUrlDecode) {
                sourceData = helpers.urlDecode(sourceData);
            }
            // 解密
            httpCipherText.append(decryptString(sourceData));
        } else if (HttpProxyTag.burpReqBody) { // 请求体解密
            start = iRequestInfo.getBodyOffset();

            // HTTP 请求体
            String requestText = null;
            try {
                requestText = new String(content,"UTF-8");
            } catch (UnsupportedEncodingException e) {
                BurpExtender.stderr.println(e.getMessage());
            }

            httpReqText.append(requestText);

            if (start != 0) {
                // 请求体数据
                String httpReqBodyText = httpReqText.substring(start);

                httpCipherText.append(httpReqBodyText + "\n\n");

                // 判断是否需要进行 URL 解码
                if (HttpProxyTag.burpUrlDecode) {
                    httpReqBodyText = helpers.urlDecode(httpReqBodyText);
                }

                // 解密
                httpCipherText.append(decryptString(httpReqBodyText));
            }
        }

        // 请求头解密
        if (burpReqHeaders.length() != 0) {
            String headerData = "";
            List<String> headers = iRequestInfo.getHeaders();
            for (String header : headers) {
                httpHeaders.append(header + "\n");
            }
            start = httpHeaders.indexOf(burpReqHeaders);
            if (start != -1){
                stop = httpHeaders.indexOf("\n", start);
                headerData = httpHeaders.substring(start, stop);
                httpCipherText.append(headerData + "\n\n");
            }

            // 获取密文
            String sourceData =  headerData.substring(burpReqHeaders.length() + 2);
            // 判断是否需要进行 URL 解码
            if (HttpProxyTag.burpUrlDecode) {
                sourceData = helpers.urlDecode(sourceData);
            }
            // 解密
            httpCipherText.append(decryptString(sourceData));
        }
        return httpCipherText;
    }

    // 响应信息解密
    public StringBuffer respParamMode(byte[] content){
        int start = 0;
        int stop = 0;
        StringBuffer httpRespText = new StringBuffer("");
        StringBuffer httpHeaders = new StringBuffer("");
        StringBuffer httpCipherText = new StringBuffer("");

        IResponseInfo iResponseInfo = helpers.analyzeResponse(content);

        // 响应 JSON 参数解密
        if (burpRespParam.length() != 0) {
            start = iResponseInfo.getBodyOffset();

            // HTTP 响应信息
            String responseText = null;
            try {
                responseText = new String(content,"UTF-8");
            } catch (UnsupportedEncodingException e) {
                BurpExtender.stderr.println(e.getMessage());
            }

            httpRespText.append(responseText);

            // HTTP 响应体信息
            if (start != 0){
                String httpRespBodyText = httpRespText.substring(start);

                //  判断响应数据是否为 JSON
                if (isJson(httpRespBodyText)) {
                    JSONObject jsonObject = JSON.parseObject(httpRespBodyText);
                    //递归解析 JSON
                    Map<String, Object> analysis = analysis(jsonObject);

                    for (Map.Entry<String, Object> stringObjectEntry : analysis.entrySet()) {
                        if (burpRespParam.equals(stringObjectEntry.getKey())){
                            httpCipherText.append(stringObjectEntry.getKey() + ": " + stringObjectEntry.getValue() + "\n\n");
                            // 获取密文
                            String sourceData = stringObjectEntry.getValue().toString();
                            // 判断是否需要进行 URL 解码
                            if (HttpProxyTag.burpUrlDecode) {
                                sourceData = helpers.urlDecode(sourceData);
                            }
                            // 解密
                            httpCipherText.append(decryptString(sourceData));
                        }
                    }
                }
            }
        } else if (HttpProxyTag.burpRespBody) { // 响应体解密
            start = iResponseInfo.getBodyOffset();

            // HTTP 响应信息
            String responseText = null;
            try {
                responseText = new String(content,"UTF-8");
            } catch (UnsupportedEncodingException e) {
                BurpExtender.stderr.println(e.getMessage());
            }

            httpRespText.append(responseText);

            if (start != 0) {
                // 响应体数据
                String httpRespBodyText = httpRespText.substring(start);

                httpCipherText.append(httpRespBodyText + "\n\n");

                // 判断是否需要进行 URL 解码
                if (HttpProxyTag.burpUrlDecode) {
                    httpRespBodyText = helpers.urlDecode(httpRespBodyText);
                }
                // 解密
                httpCipherText.append(decryptString(httpRespBodyText));
            }

        }

        // 响应头解密
        if (burpRespHeaders.length() != 0) {
            String headerData = "";
            List<String> headers = iResponseInfo.getHeaders();

            for (String header : headers) {
                httpHeaders.append(header + "\n");
            }

            start = httpHeaders.indexOf(burpRespHeaders);
            if (start != -1){
                stop = httpHeaders.indexOf("\n", start);
                headerData = httpHeaders.substring(start, stop);
                httpCipherText.append(headerData + "\n\n");
            }

            // 获取密文
            String sourceData =  headerData.substring(burpRespHeaders.length() + 2);
            // 判断是否需要进行 URL 解码
            if (HttpProxyTag.burpUrlDecode) {
                sourceData = helpers.urlDecode(sourceData);
            }
            // 解密
            httpCipherText.append(decryptString(sourceData));
        }

        return httpCipherText;
    }
}
