package com.lingqiong.buddy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * [v27] 抓包记录的全局存储（内存态，供前端通过 JS 桥查询）。
 * 只保留最近 MAX 条，避免长时间抓包撑爆内存。
 */
public class CaptureStore {

    public static class Entry {
        public long id;
        public long time;
        public String proto = "";
        public String src = "";
        public String dst = "";
        public String host = "";    // SNI / DNS 域名
        public String method = "";  // HTTP 请求行 / 方法
        public String url = "";     // HTTP 目标
        public String status = "";  // HTTP 状态行
        public long up = 0;         // 上行字节
        public long down = 0;       // 下行字节
        public List<String> log = new ArrayList<>();
    }

    private static final int MAX = 800;
    private static final int MAX_LOG_LINES = 30;
    private static final int MAX_LOG_CHARS = 500;
    private static final Object LOCK = new Object();
    private static final ArrayList<Entry> LIST = new ArrayList<>();
    private static long SEQ = 0;
    private static volatile boolean capturing = false;

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
        return e;
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

    public static void clear() {
        synchronized (LOCK) { LIST.clear(); SEQ = 0; }
    }

    public static int size() { synchronized (LOCK) { return LIST.size(); } }

    /** 导出为 JSON（新的在前），供前端渲染。 */
    public static String toJson() {
        JSONArray arr = new JSONArray();
        synchronized (LOCK) {
            for (int i = LIST.size() - 1; i >= 0; i--) {
                Entry e = LIST.get(i);
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
                    o.put("log", new JSONArray(e.log));
                    arr.put(o);
                } catch (Throwable ignore) {}
            }
        }
        return arr.toString();
    }
}
