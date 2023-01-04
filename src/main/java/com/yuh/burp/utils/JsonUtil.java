package com.yuh.burp.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.yuh.burp.BurpExtender;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static com.yuh.burp.utils.HttpUtil.decryptString;

public class JsonUtil {
    // 递归解析 JSONObject 转换成 Map
    public static Map<String, Object> analysis(JSONObject jsonObject) {
        Map<String, Object> result = new HashMap<>();
        Set<String> keys = jsonObject.keySet();

        keys.parallelStream().forEach(key -> {
            Object value = jsonObject.get(key);
            if (value instanceof JSONObject) {
                JSONObject valueJsonObject = (JSONObject) value;
                result.putAll(analysis(valueJsonObject));
            } else if (value instanceof JSONArray) {
                JSONArray jsonArray = (JSONArray) value;

                if (jsonArray.size() == 0) {
                    return;
                }

                if (jsonArray.size() > 0) {
                    if (jsonArray.get(0) instanceof JSONArray || jsonArray.get(0) instanceof JSONObject) {
                        analysisJSONArray(jsonArray, result);
                    } else {
                        result.put(key, value);
                    }
                }
            } else {
                result.put(key, value);
            }
        });
        return result;
    }

    // 递归解析 JSONArray
    private static void analysisJSONArray(JSONArray jsonArray, Map<String, Object> map) {
        jsonArray.parallelStream().forEach(json -> {
            if (json instanceof JSONObject) {
                JSONObject valueJsonObject = (JSONObject) json;
                map.putAll(analysis(valueJsonObject));
            } else if (json instanceof JSONArray) {
                JSONArray tmpJsonArray = (JSONArray) json;
                if (tmpJsonArray.size() == 0) {
                    return;
                }
                analysisJSONArray(tmpJsonArray, map);
            }
        });
    }

    // 发送 JSON 请求
    public static String doJson(String httpUrl, JSONObject jsonParam){
        StringBuffer sbf = new StringBuffer();

        String query = jsonParam.toString();
        try {
            URL url = new URL(httpUrl);

            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setDoInput(true);
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");
            connection.setUseCaches(false);
            connection.setInstanceFollowRedirects(true);
            connection.setRequestProperty("Content-Type","application/json");
            connection.connect();

            try (OutputStream os = connection.getOutputStream()) {
                os.write(query.getBytes("UTF-8"));
            }

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
                String lines;
                while ((lines = reader.readLine()) != null) {
                    lines = new String(lines.getBytes(), "utf-8");
                    sbf.append(lines);
                }
                connection.disconnect();
            }

        } catch (Exception e) {
            BurpExtender.stderr.println(e.getMessage());
        }
        return sbf.toString();
    }

    // 判断是否为 JSON 数据
    public static boolean isJson(String str) {
        boolean result = false;
        if (str != null && !str.isEmpty()) {
            str = str.trim();
            if (str.startsWith("{") && str.endsWith("}")) {
                result = true;
            } else if (str.startsWith("[") && str.endsWith("]")) {
                result = true;
            }
        }
        return result;
    }

}