package com.lingqiong.buddy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * [v83] 抓包记录存储 —— 重写版。
 *
 * 与旧版的关键差别（旧版是「看不懂」的根源）：
 *   旧版 Entry 只有 log 字符串数组（30 行 × 500 字符），没有任何报文结构字段，
 *   请求头/响应头/正文压根没被保存过。
 *   本版新增 reqHead / respHead / 解码后的正文文本 / 正文类型 / 压缩说明 / 错误分类，
 *   并把「列表」与「详情」拆成两个出口：
 *     - toListJson()  只返回摘要，前端列表用，几百条也不卡
 *     - detailJson()  返回单条完整报文（含图片 base64），点开才取
 */
public class CaptureStore {

    public static class Entry {
        public long id;
        public long time;
        public String proto = "";
        public String src = "";
        public String dst = "";
        public String host = "";      // SNI / DNS / Host
        public String method = "";    // 请求行
        public String url = "";       // 请求目标
        public String status = "";    // 状态行
        public long up = 0;
        public long down = 0;
        public List<String> log = new ArrayList<>();

        // ---- [v83] 报文实体 ----
        public String reqHead = "";
        public String respHead = "";
        public String reqBodyText = "";
        public String respBodyText = "";
        public String reqBodyB64 = "";
        public String respBodyB64 = "";
        public String reqType = "";
        public String respType = "";
        public String reqNote = "";
        public String respNote = "";
        public long reqLen = 0;       // 原始 body 长度（解压前）
        public long respLen = 0;

        // ---- [v83] 归类 ----
        public String error = "";     // 错误分类（空=正常）
        public String appName = "";   // 触发流量的应用
        public int uid = -1;
        public boolean ws = false;    // 是否 WebSocket
    }

    private static final int MAX = 600;              // 最多保留多少条连接
    private static final int MAX_LOG_LINES = 40;
    private static final int MAX_LOG_CHARS = 500;
    private static final int MAX_HEAD_SAVE = 12 * 1024;   // 单条头最多存多少
    private static final Object LOCK = new Object();
    private static final ArrayList<Entry> LIST = new ArrayList<>();
    private static long SEQ = 0;
    private static volatile boolean capturing = false;

    // ---- [v83] 抓包会话参数（第5条：AI 指定时间/数量/种类/IP，到点自动停） ----
    public static volatile long autoStopAt = 0;      // 到期时间戳（0=不限）
    public static volatile int autoStopCount = 0;    // 最多抓多少条（0=不限）
    public static volatile String autoTypes = "";    // 只收这些类型（逗号分隔，空=全部）
    public static volatile String autoIps = "";      // 只收这些 IP/域名（逗号分隔，空=全部）
    public static volatile Runnable onAutoStop = null;
    private static volatile boolean autoStopFired = false;

    public static boolean isCapturing() { return capturing; }
    public static void setCapturing(boolean b) { capturing = b; }

    public static Entry add(String proto, String src, String dst) {
        Entry e = new Entry();
        synchronized (LOCK) {
            e.id = ++SEQ;
            e.time = System.currentTimeMillis();
            e.proto = proto;
            e.src = src;
            e.dst = dst;
            LIST.add(e);
            while (LIST.size() > MAX) LIST.remove(0);
        }
        checkAutoStop();
        return e;
    }

    /** 是否该收这条（按 AI 指定的类型/IP 过滤） */
    public static boolean accept(String host, String ip) {
        String types = autoTypes;
        String ips = autoIps;
        if (ips != null && !ips.trim().isEmpty()) {
            boolean hit = false;
            for (String p : ips.split(",")) {
                p = p.trim().toLowerCase();
                if (p.isEmpty()) continue;
                if ((host != null && host.toLowerCase().contains(p))
                        || (ip != null && ip.toLowerCase().contains(p))) { hit = true; break; }
            }
            if (!hit) return false;
        }
        if (types != null && !types.trim().isEmpty()) {
            // 类型要等解析出 Content-Type 才知道，这里先放行，由上层在 onHttp 里二次判断
            return true;
        }
        return true;
    }

    /** 类型过滤（在解析出报文类型后调用） */
    public static boolean acceptType(String type) {
        String types = autoTypes;
        if (types == null || types.trim().isEmpty()) return true;
        if (type == null) return true;
        for (String p : types.split(",")) {
            if (p.trim().equalsIgnoreCase(type)) return true;
        }
        return false;
    }

    public static void addLog(Entry e, String line) {
        if (e == null || line == null) return;
        synchronized (LOCK) {
            if (e.log.size() >= MAX_LOG_LINES) return;
            String s = line;
            if (s.length() > MAX_LOG_CHARS) s = s.substring(0, MAX_LOG_CHARS) + " …";
            e.log.add(s);
        }
    }

    /** 设置错误分类（同一连接多次报错只保留第一个最具体的） */
    public static void setError(Entry e, String err) {
        if (e == null || err == null || err.isEmpty()) return;
        synchronized (LOCK) {
            if (e.error == null || e.error.isEmpty()) e.error = err;
        }
    }

    public static void clear() {
        synchronized (LOCK) {
            LIST.clear();
            SEQ = 0;
        }
        autoStopFired = false;
    }

    public static int size() { synchronized (LOCK) { return LIST.size(); } }

    // ==================== 自动停止判定 ====================
    private static void checkAutoStop() {
        if (autoStopFired) return;
        boolean fire = false;
        if (autoStopAt > 0 && System.currentTimeMillis() >= autoStopAt) fire = true;
        if (autoStopCount > 0) {
            int n;
            synchronized (LOCK) { n = LIST.size(); }
            if (n >= autoStopCount) fire = true;
        }
        if (fire) {
            autoStopFired = true;
            Runnable r = onAutoStop;
            if (r != null) {
                try { r.run(); } catch (Throwable ignore) {}
            }
        }
    }

    /** 由外部定时器调用，保证「时间到」即使没有任何流量也能停 */
    public static void tickAutoStop() { checkAutoStop(); }

    public static void setAutoStop(int seconds, int count, String types, String ips, Runnable cb) {
        autoStopFired = false;
        autoStopAt = seconds > 0 ? System.currentTimeMillis() + seconds * 1000L : 0;
        autoStopCount = Math.max(0, count);
        autoTypes = types == null ? "" : types;
        autoIps = ips == null ? "" : ips;
        onAutoStop = cb;
    }

    public static void clearAutoStop() {
        autoStopAt = 0;
        autoStopCount = 0;
        autoTypes = "";
        autoIps = "";
        onAutoStop = null;
        autoStopFired = false;
    }

    public static String autoStopInfo() {
        StringBuilder sb = new StringBuilder();
        if (autoStopAt > 0) {
            long left = Math.max(0, (autoStopAt - System.currentTimeMillis()) / 1000);
            sb.append("剩余 ").append(left).append(" 秒");
        }
        if (autoStopCount > 0) {
            if (sb.length() > 0) sb.append(" · ");
            sb.append("上限 ").append(autoStopCount).append(" 条");
        }
        if (autoTypes != null && !autoTypes.isEmpty()) {
            if (sb.length() > 0) sb.append(" · ");
            sb.append("类型 ").append(autoTypes);
        }
        if (autoIps != null && !autoIps.isEmpty()) {
            if (sb.length() > 0) sb.append(" · ");
            sb.append("过滤 ").append(autoIps);
        }
        return sb.toString();
    }

    // ==================== 出口 1：列表（轻量） ====================
    public static String toListJson(int limit, String filter) {
        JSONArray arr = new JSONArray();
        String f = filter == null ? "" : filter.toLowerCase().trim();
        synchronized (LOCK) {
            int n = 0;
            for (int i = LIST.size() - 1; i >= 0; i--) {
                if (limit > 0 && n >= limit) break;
                Entry e = LIST.get(i);
                if (!f.isEmpty()) {
                    boolean hit = contains(e.host, f) || contains(e.dst, f) || contains(e.method, f)
                            || contains(e.url, f) || contains(e.status, f) || contains(e.error, f)
                            || contains(e.reqType, f) || contains(e.respType, f)
                            || contains(e.appName, f);
                    if (!hit) continue;
                }
                try {
                    JSONObject o = new JSONObject();
                    o.put("id", e.id);
                    o.put("time", e.time);
                    o.put("proto", e.proto);
                    o.put("src", e.src);
                    o.put("dst", e.dst);
                    o.put("host", e.host);
                    o.put("method", e.method);
                    o.put("url", e.url);
                    o.put("status", e.status);
                    o.put("up", e.up);
                    o.put("down", e.down);
                    o.put("error", e.error);
                    o.put("appName", e.appName);
                    o.put("uid", e.uid);
                    o.put("ws", e.ws);
                    o.put("reqType", e.reqType);
                    o.put("respType", e.respType);
                    o.put("reqLen", e.reqLen);
                    o.put("respLen", e.respLen);
                    o.put("hasReq", e.reqHead != null && !e.reqHead.isEmpty());
                    o.put("hasResp", e.respHead != null && !e.respHead.isEmpty());
                    o.put("log", new JSONArray(e.log));
                    arr.put(o);
                    n++;
                } catch (Throwable ignore) {}
            }
        }
        return arr.toString();
    }

    private static boolean contains(String s, String f) {
        return s != null && s.toLowerCase().contains(f);
    }

    // ==================== 出口 2：单条详情（含图片 base64） ====================
    public static String detailJson(long id) {
        synchronized (LOCK) {
            for (Entry e : LIST) {
                if (e.id != id) continue;
                try {
                    JSONObject o = new JSONObject();
                    o.put("id", e.id);
                    o.put("time", e.time);
                    o.put("proto", e.proto);
                    o.put("src", e.src);
                    o.put("dst", e.dst);
                    o.put("host", e.host);
                    o.put("method", e.method);
                    o.put("url", e.url);
                    o.put("status", e.status);
                    o.put("up", e.up);
                    o.put("down", e.down);
                    o.put("error", e.error);
                    o.put("appName", e.appName);
                    o.put("ws", e.ws);
                    o.put("log", new JSONArray(e.log));

                    o.put("reqHead", cut(e.reqHead, MAX_HEAD_SAVE));
                    o.put("respHead", cut(e.respHead, MAX_HEAD_SAVE));
                    o.put("reqHeadFull", e.reqHead == null ? "" : e.reqHead);
                    o.put("respHeadFull", e.respHead == null ? "" : e.respHead);
                    o.put("reqBody", cut(e.reqBodyText, 64 * 1024));
                    o.put("respBody", cut(e.respBodyText, 64 * 1024));
                    o.put("reqBodyB64", e.reqBodyB64);
                    o.put("respBodyB64", e.respBodyB64);
                    o.put("reqType", e.reqType);
                    o.put("respType", e.respType);
                    o.put("reqNote", e.reqNote);
                    o.put("respNote", e.respNote);
                    o.put("reqLen", e.reqLen);
                    o.put("respLen", e.respLen);
                    return o.toString();
                } catch (Throwable t) {
                    return "{\"error\":\"序列化失败\"}";
                }
            }
        }
        return "{\"error\":\"记录不存在（可能已被新记录挤出）\"}";
    }

    private static String cut(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "\n… 已截断，共 " + s.length() + " 字符";
    }

    /** 兼容旧接口：返回列表 JSON（不含正文） */
    public static String toJson() { return toListJson(0, ""); }

    // ==================== 供上层写入解码结果 ====================
    public static void fillRequest(Entry e, String head, byte[] body, int bodyLen) {
        if (e == null) return;
        HttpCodec.Decoded d = HttpCodec.decode(body, bodyLen, head, e.url);
        // 类型过滤（AI 指定了类型时）
        boolean typeOk = acceptType(d.type);
        synchronized (LOCK) {
            if (e.reqHead == null || e.reqHead.isEmpty()) e.reqHead = cut(head, MAX_HEAD_SAVE);
            e.reqType = d.type;
            e.reqLen = bodyLen;
            e.reqNote = d.note;
            if (typeOk) {
                e.reqBodyText = d.text;
                if (d.raw != null && "image".equals(d.type)) {
                    try { e.reqBodyB64 = Base64.getEncoder().encodeToString(d.raw); } catch (Throwable ignore) {}
                }
            }
            // 请求行 / Host 补全
            if (e.method == null || e.method.isEmpty()) {
                int nl = head.indexOf("\r\n");
                e.method = nl > 0 ? head.substring(0, nl) : head;
            }
            if (e.host == null || e.host.isEmpty()) {
                String h = HttpCodec.header(head, "Host");
                if (h != null && !h.isEmpty()) e.host = h;
            }
        }
    }

    public static void fillResponse(Entry e, String head, byte[] body, int bodyLen) {
        if (e == null) return;
        HttpCodec.Decoded d = HttpCodec.decode(body, bodyLen, head, null);
        boolean typeOk = acceptType(d.type);
        synchronized (LOCK) {
            if (e.respHead == null || e.respHead.isEmpty()) e.respHead = cut(head, MAX_HEAD_SAVE);
            e.respType = d.type;
            e.respLen = bodyLen;
            e.respNote = d.note;
            if (typeOk) {
                e.respBodyText = d.text;
                if (d.raw != null && "image".equals(d.type)) {
                    try { e.respBodyB64 = Base64.getEncoder().encodeToString(d.raw); } catch (Throwable ignore) {}
                }
            }
            if (e.status == null || e.status.isEmpty()) {
                int nl = head.indexOf("\r\n");
                e.status = nl > 0 ? head.substring(0, nl) : head;
            }
        }
    }

    public static void fillWs(Entry e, boolean isClient, int opcode, byte[] payload, int len) {
        if (e == null) return;
        e.ws = true;
        String name;
        switch (opcode) {
            case 0x0: name = "续帧"; break;
            case 0x1: name = "文本"; break;
            case 0x2: name = "二进制"; break;
            case 0x8: name = "关闭"; break;
            case 0x9: name = "Ping"; break;
            case 0xA: name = "Pong"; break;
            default: name = "op" + opcode;
        }
        String text;
        if (opcode == 0x1) {
            String[] cs = new String[]{""};
            text = HttpCodec.decodeText(payload, len, "", cs);
            if (text.length() > 2000) text = text.substring(0, 2000) + " …";
        } else if (opcode == 0x2) {
            text = HttpCodec.hexDump(payload, len, 128);
        } else {
            text = HttpCodec.humanSize(len);
        }
        addLog(e, (isClient ? "→ " : "← ") + "[WS " + name + " " + HttpCodec.humanSize(len) + "] " + text);
    }
}
