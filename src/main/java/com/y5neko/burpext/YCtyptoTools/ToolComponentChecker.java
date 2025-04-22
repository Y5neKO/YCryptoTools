package com.y5neko.burpext.YCtyptoTools;

import com.alibaba.fastjson2.JSONArray;

public class ToolComponentChecker {

    // Burp 工具标志位常量
    public static final int TOOL_SUITE     = 1;
    public static final int TOOL_TARGET    = 2;
    public static final int TOOL_PROXY     = 4;
    public static final int TOOL_SPIDER    = 8;
    public static final int TOOL_SCANNER   = 16;
    public static final int TOOL_INTRUDER  = 32;
    public static final int TOOL_REPEATER  = 64;
    public static final int TOOL_SEQUENCER = 128;
    public static final int TOOL_DECODER   = 256;
    public static final int TOOL_COMPARER  = 512;
    public static final int TOOL_EXTENDER  = 1024;

    // 判断toolFlag是否匹配enabledComponents
    public static boolean checkToolFlag(JSONArray enabledComponents, int toolFlag) {
        // 过滤 "是否启用插件" 并检查其他组件
        for (Object obj : enabledComponents) {
            String component = obj.toString();

            if ("是否启用插件".equals(component)) {
                continue; // 忽略该项
            }

            // 如果toolFlag匹配一个有效组件
            switch (component) {
                case "Target":
                    if (toolFlag == TOOL_TARGET) return true;
                    break;
                case "Proxy":
                    if (toolFlag == TOOL_PROXY) return true;
                    break;
                case "Spider":
                    if (toolFlag == TOOL_SPIDER) return true;
                    break;
                case "Scanner":
                    if (toolFlag == TOOL_SCANNER) return true;
                    break;
                case "Intruder":
                    if (toolFlag == TOOL_INTRUDER) return true;
                    break;
                case "Repeater":
                    if (toolFlag == TOOL_REPEATER) return true;
                    break;
                case "Sequencer":
                    if (toolFlag == TOOL_SEQUENCER) return true;
                    break;
                case "Decoder":
                    if (toolFlag == TOOL_DECODER) return true;
                    break;
                case "Comparer":
                    if (toolFlag == TOOL_COMPARER) return true;
                    break;
                case "Extender":
                    if (toolFlag == TOOL_EXTENDER) return true;
                    break;
                case "Suite":
                    if (toolFlag == TOOL_SUITE) return true;
                    break;
            }
        }
        return false; // 如果没有匹配则返回false
    }
}