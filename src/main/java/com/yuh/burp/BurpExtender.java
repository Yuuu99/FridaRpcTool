package com.yuh.burp;

import burp.*;
import com.yuh.burp.ui.HttpProxyTag;
import com.yuh.burp.ui.FridaRpcToolMenu;
import com.yuh.burp.ui.Tags;
import java.io.*;
import java.net.URL;

public class BurpExtender implements IBurpExtender, IHttpListener, IMessageEditorTabFactory {
    private String name = "FridaRpcTool";
    private String version ="1.0";
    private IBurpExtenderCallbacks callbacks;
    private Tags tags;

    public String httpHost = "";
    public IHttpService httpService;

    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static String burpHost = "";
    public static String burpRpcUrl = "";
    public static String burpMode = "";
    public static String burpReqParam = "";
    public static String burpReqHeaders = "";
    public static String burpRespParam = "";
    public static String burpRespHeaders = "";

    // implement IBurpExtender
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // 设置扩展名
        callbacks.setExtensionName("FridaRpcTool");
        // 注册 HTTP 消息监听器
        callbacks.registerHttpListener(this);
        // 注册标签页工厂
        callbacks.registerMessageEditorTabFactory(this);
        // 注册右键工具栏菜单
        callbacks.registerContextMenuFactory(new FridaRpcToolMenu());

        stdout = new PrintWriter(callbacks.getStdout(),true);
        stderr = new PrintWriter(callbacks.getStderr(),true);
        stdout.println(getBanner());

        // 标签界面
        this.tags = new Tags(callbacks, name);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(toolFlag != IBurpExtenderCallbacks.TOOL_PROXY && toolFlag != IBurpExtenderCallbacks.TOOL_REPEATER) {
            return;
        }

        httpService = messageInfo.getHttpService();
        httpHost = httpService.getHost();

        // 域名匹配
        if (burpHost.equals(httpHost)){
            IRequestInfo iRequestInfo = helpers.analyzeRequest(messageInfo);
            // 方法
            String method = iRequestInfo.getMethod();
            // URL
            URL url = iRequestInfo.getUrl();
            // 响应信息
            byte[] responseByte = messageInfo.getResponse();
            IResponseInfo iResponseInfo = helpers.analyzeResponse(responseByte);
            // 状态码
            short statusCode = iResponseInfo.getStatusCode();

            tags.getHttpQueueTagClass().add(httpHost, method, url.getPath(), statusCode + "", responseByte.length + "", messageInfo);
        }

    }

    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new HttpProxyTag(this.callbacks);
    }

    public String getBanner(){
        String bannerInfo =
            "[+] ##############################################\n"
            + "[+]    " + name + " v" + version +"\n"
            + "[+]    anthor: Yuh\n"
            + "[+]    github: https://github.com/Yuuu99\n"
            + "[+] ##############################################";
        return bannerInfo;
    }
}