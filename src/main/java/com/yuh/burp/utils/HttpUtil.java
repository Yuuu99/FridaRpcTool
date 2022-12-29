package com.yuh.burp.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import static com.yuh.burp.BurpExtender.burpRpcUrl;
import static com.yuh.burp.utils.JsonUtil.doJson;

public class HttpUtil {
    // 字符串加密
    public static String encryptString(String sourceData){
        JSONObject jsonObject = new JSONObject();

        // 加密
        jsonObject.put("item_mode", 0);
        jsonObject.put("item_data", sourceData);
        String resultJson = doJson(burpRpcUrl, jsonObject);

        // 解析 JSON 数据
        JSONObject encryptJson = JSON.parseObject(resultJson);
        String encryptData = encryptJson.get("item_data").toString();
        return encryptData;
    }

    // 字符串解密
    public static String decryptString(String sourceData){
        JSONObject jsonObject = new JSONObject();

        // 解密
        jsonObject.put("item_mode", 1);
        jsonObject.put("item_data", sourceData);
        String resultJson = doJson(burpRpcUrl, jsonObject);

        // 解析 JSON 数据
        JSONObject decryptJson = JSON.parseObject(resultJson);
        String decryptData = decryptJson.get("item_data").toString();
        return decryptData;
    }
}
