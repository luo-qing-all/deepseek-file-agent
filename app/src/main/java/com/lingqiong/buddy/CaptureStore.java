package com.lingqiong.buddy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

/**
 * [v27] 抓包记录的全局存储（内存态，供前端通过 JS 桥查询）。
 *
 * [v71] 重大升级 —— 旧版「看不到具体内容」的真凶在这里：
 *   1. 旧版每条只存 30 行 log、每行 500 字        → 正文被截成碎片
 *   2. 旧版【根本没有响应体字段】，onServerData 只取了状态行
 *   3. proto 只有 "TCP"/"UDP"                     → DNS/QUIC/HTTP/HTTPS 全糊在一起
 *
 * 新版：
 *   · 逐条保存 reqHead / respHead / reqBody / respBody / alpn / kind
 *   · log 上限 400 行 × 8192 字
 *   · list() 只带正文摘要（前 2KB），完整正文用 detail(id) 单独取（避免桥调用序列化爆炸）
 *   · 二进制（图片/视频/字体…）不存字节，只记长度和 Content-Type，避免 JSON 被控制字符污染
 */
public class CaptureStore {

    public static class Entry {
        public long id;
        public long time;
        public String proto = "";      // 传输层：TCP / UDP
        public String kind = "";       // [v71] 应用层：DNS / QUIC / HTTP / HTTPS / WebSocket / TCP / UDP
        public String src = "";
        public String dst = "";
        public String host = "";       // SNI / DNS 域名 / HTTP Host
        public String method = "";     // HTTP 请求行
        public String url = "";        // HTTP 目标
        public String status = "";     // HTTP 状态行
        public String alpn = "";       // [v71] TLS ALPN（h2 / http/1.1）
        public long up = 0;
        public long down = 0;
        public List<String> log = new ArrayList<>();

        // [v71] 新增：内容明细
        public String reqHead = "";
        public String respHead = "";
        public String reqBody = "";
        public String respBody = "";
        public int reqBodyLen = 0;
        public int respBodyLen = 0;
        public boolean truncated = false;

        // 采集缓冲（不参与 JSON）
        public ByteArrayOutputStream reqRaw;
        public ByteArrayOutputStream respRaw;
        public String ctype = "";      // 响应 Content-Type
    }

    private static final int MAX = 300;
    private static final int MAX_LOG_LINES = 400;
    private static final int MAX_LOG_CHARS = 8192;
    private static final int CAP_RAW = 256 * 1024;       // 单方向最多缓冲 256KB（文本响应通常够；超出会明确标注）
    private static final int HEAD_MAX = 8192;            // 头部最多存 8KB
    private static final int BODY_LIST_MAX = 2048;       // list() 里带的正文摘要
    private static final int BODY_FULL_MAX = 200 * 1024; // detail() 里带的正文上限
    private static final Charset LATIN1 = Charset.forName("ISO-8859-1");
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
            while (LIST.size() > MAX) {
                Entry dead = LIST.remove(0);
                if (dead != null) { dead.reqRaw = null; dead.respRaw = null; }
            }
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
        synchronized (LOCK) {
            for (int i = 0; i < LIST.size(); i++) {
                Entry e = LIST.get(i);
                if (e != null) { e.reqRaw = null; e.respRaw = null; }
            }
            LIST.clear();
            SEQ = 0;
        }
    }

    public static int size() { synchronized (LOCK) { return LIST.size(); } }

    /* ==================== [v71] 内容采集 ==================== */

    /** 上行（客户端 → 服务器）字节。只在确认为文本协议时缓冲，避免白占内存。 */
    public static void feedReq(Entry e, byte[] p, int off, int len) {
        if (e == null || p == null || len <= 0) return;
        synchronized (LOCK) {
            if (e.reqRaw == null) {
                // 前几个字节就能判断是不是明文 HTTP / TLS，不是就不缓冲
                if (!looksWorthBuffering(p, off, len)) return;
                e.reqRaw = new ByteArrayOutputStream(Math.min(len, 4096));
            }
            int room = CAP_RAW - e.reqRaw.size();
            if (room <= 0) { e.truncated = true; return; }
            int n = Math.min(len, room);
            e.reqRaw.write(p, off, n);
            if (n < len) e.truncated = true;
        }
    }

    /** 下行（服务器 → 客户端）字节。 */
    public static void feedResp(Entry e, byte[] p, int off, int len) {
        if (e == null || p == null || len <= 0) return;
        synchronized (LOCK) {
            if (e.respRaw == null) {
                if (!looksWorthBufferingResp(p, off, len)) return;
                e.respRaw = new ByteArrayOutputStream(Math.min(len, 4096));
            }
            int room = CAP_RAW - e.respRaw.size();
            if (room <= 0) { e.truncated = true; return; }
            int n = Math.min(len, room);
            e.respRaw.write(p, off, n);
            if (n < len) e.truncated = true;
        }
    }

    private static boolean looksWorthBuffering(byte[] p, int off, int len) {
        try {
            if (len < 3) return false;
            int c0 = p[off] & 0xff, c1 = p[off + 1] & 0xff;
            // TLS ClientHello
            if (c0 == 0x16 && c1 == 0x03) return false;
            // 明文 HTTP 方法开头
            int c2 = p[off + 2] & 0xff;
            if (c0 >= 'A' && c0 <= 'Z' && c1 >= 'A' && c1 <= 'Z' && c2 >= 'A' && c2 <= 'Z') return true;
            return false;
        } catch (Throwable t) { return false; }
    }

    private static boolean looksWorthBufferingResp(byte[] p, int off, int len) {
        try {
            if (len < 5) return false;
            return (p[off] & 0xff) == 'H' && (p[off + 1] & 0xff) == 'T'
                    && (p[off + 2] & 0xff) == 'T' && (p[off + 3] & 0xff) == 'P';
        } catch (Throwable t) { return false; }
    }

    /** 连接结束：把缓冲切分成「头 / 正文」并落库，随后释放缓冲。 */
    public static void finish(Entry e) {
        if (e == null) return;
        byte[] rq = null, rs = null;
        int rqLen = 0, rsLen = 0;
        synchronized (LOCK) {
            try {
                if (e.reqRaw != null) { rq = e.reqRaw.toByteArray(); rqLen = rq.length; }
                if (e.respRaw != null) { rs = e.respRaw.toByteArray(); rsLen = rs.length; }
                e.reqRaw = null; e.respRaw = null;
            } catch (Throwable t) { return; }
        }
        if (rq != null && rqLen > 0) splitInto(e, true, rq, rqLen);
        if (rs != null && rsLen > 0) splitInto(e, false, rs, rsLen);
        // [v71] 采集被上限截断时，明确写进正文，别让用户以为「内容就这么点」
        if (e.truncated) {
            String tip = "\n…（已达采集上限 " + (CAP_RAW / 1024) + "KB，后续内容未记录）";
            if (e.respBody != null && !e.respBody.startsWith("[二进制")) e.respBody = e.respBody + tip;
            if (e.reqBody != null && !e.reqBody.startsWith("[二进制")) e.reqBody = e.reqBody + tip;
        }
        if (!e.reqHead.isEmpty() && (e.reqBody.isEmpty())) {
            // 没有 body 但也把请求行/头补进 log，方便详情页直接看
        }
    }

    private static void splitInto(Entry e, boolean isReq, byte[] data, int len) {
        try {
            String txt = new String(data, 0, len, LATIN1);
            int hdrEnd = txt.indexOf("\r\n\r\n");
            String head, body;
            if (hdrEnd >= 0) {
                head = txt.substring(0, hdrEnd);
                body = txt.substring(hdrEnd + 4);
            } else {
                if (txt.startsWith("HTTP/") || looksLikeReqLine(txt)) { head = txt; body = ""; }
                else { head = ""; body = txt; }
            }
            String ct = headerValue(head, "content-type");
            boolean isText = looksText(ct, body);
            String headOut = clip(sanitize(head), HEAD_MAX);
            int blen = body.length();
            String bodyOut;
            if (blen == 0) {
                bodyOut = "";
            } else if (isText) {
                bodyOut = clip(sanitize(body), BODY_FULL_MAX);
            } else {
                bodyOut = "[二进制内容 " + blen + " 字节" + (ct != null && ct.length() > 0 ? " · " + ct : "") + "]";
            }
            if (isReq) {
                e.reqHead = headOut;
                e.reqBody = bodyOut;
                e.reqBodyLen = blen;
            } else {
                e.respHead = headOut;
                e.respBody = bodyOut;
                e.respBodyLen = blen;
                if (ct != null) e.ctype = ct;
            }
            // [v71] 协议自动细分（Engine 没判断出来时兜底）
            if (e.kind == null || e.kind.length() == 0) {
                if (!isReq && head.startsWith("HTTP/")) e.kind = "HTTP";
                else if (isReq && looksLikeReqLine(head)) e.kind = "HTTP";
            }
            if (head.toLowerCase().contains("upgrade: websocket")) e.kind = "WebSocket";
        } catch (Throwable ignore) {}
    }

    private static boolean looksLikeReqLine(String s) {
        if (s == null) return false;
        return s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("PUT ")
                || s.startsWith("DELETE ") || s.startsWith("HEAD ") || s.startsWith("PATCH ")
                || s.startsWith("OPTIONS ") || s.startsWith("TRACE ");
    }

    private static String headerValue(String head, String name) {
        if (head == null || head.length() == 0) return null;
        try {
            String[] lines = head.split("\r\n");
            for (int i = 0; i < lines.length; i++) {
                String ln = lines[i];
                int c = ln.indexOf(':');
                if (c > 0 && ln.substring(0, c).trim().equalsIgnoreCase(name)) {
                    return ln.substring(c + 1).trim();
                }
            }
        } catch (Throwable ignore) {}
        return null;
    }

    /** 文本 / 二进制判定：先看 Content-Type，再看控制字符比例。 */
    private static boolean looksText(String ct, String body) {
        try {
            if (ct != null && ct.length() > 0) {
                String c = ct.toLowerCase();
                if (c.startsWith("image/") || c.startsWith("video/") || c.startsWith("audio/")
                        || c.contains("octet-stream") || c.contains("font")
                        || c.contains("protobuf") || c.contains("zip") || c.contains("gzip")
                        || c.contains("mpeg") || c.contains("webp") || c.contains("avif")) {
                    return false;
                }
            }
            if (body == null || body.length() == 0) return true;
            int n = Math.min(body.length(), 4096);
            int bad = 0;
            for (int i = 0; i < n; i++) {
                char ch = body.charAt(i);
                if (ch < 9 || (ch > 13 && ch < 32) || ch == 127) bad++;
            }
            return n == 0 || bad * 10 < n;
        } catch (Throwable t) { return true; }
    }

    /** 去掉会在 JSON 里惹麻烦的控制字符（§38 的教训）。 */
    private static String sanitize(String s) {
        if (s == null || s.length() == 0) return "";
        StringBuilder sb = new StringBuilder(s.length());
        int n = s.length();
        for (int i = 0; i < n; i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\r' || c == '\t') sb.append(c);
            else if (c < 32 || c == 127) sb.append('.');
            else sb.append(c);
        }
        return sb.toString();
    }

    private static String clip(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "\n…（已截断，原始长度 " + s.length() + "）";
    }

    /* ==================== 输出 JSON ==================== */

    public static String toJson() {
        JSONArray arr = new JSONArray();
        synchronized (LOCK) {
            for (int i = LIST.size() - 1; i >= 0; i--) {
                Entry e = LIST.get(i);
                try {
                    arr.put(pack(e, BODY_LIST_MAX));
                } catch (Throwable ignore) {}
            }
        }
        return arr.toString();
    }

    /** [v71] 单条完整内容（正文最多 200KB），给「详情页」和 AI 用。 */
    public static String detailJson(long id) {
        synchronized (LOCK) {
            for (int i = 0; i < LIST.size(); i++) {
                Entry e = LIST.get(i);
                if (e != null && e.id == id) {
                    try { return pack(e, BODY_FULL_MAX).toString(); } catch (Throwable t) { return "{}"; }
                }
            }
        }
        return "{}";
    }

    private static JSONObject pack(Entry e, int bodyMax) throws Exception {
        JSONObject o = new JSONObject();
        o.put("id", e.id);
        o.put("time", e.time);
        o.put("proto", e.proto);
        o.put("kind", e.kind == null ? "" : e.kind);
        o.put("src", e.src);
        o.put("dst", e.dst);
        o.put("host", e.host);
        o.put("method", e.method);
        o.put("url", e.url);
        o.put("status", e.status);
        o.put("alpn", e.alpn == null ? "" : e.alpn);
        o.put("up", e.up);
        o.put("down", e.down);
        o.put("log", new JSONArray(e.log));
        o.put("reqHead", clip(e.reqHead == null ? "" : e.reqHead, 4096));
        o.put("respHead", clip(e.respHead == null ? "" : e.respHead, 4096));
        o.put("reqBody", clip(e.reqBody == null ? "" : e.reqBody, bodyMax));
        o.put("respBody", clip(e.respBody == null ? "" : e.respBody, bodyMax));
        o.put("reqBodyLen", e.reqBodyLen);
        o.put("respBodyLen", e.respBodyLen);
        o.put("ctype", e.ctype == null ? "" : e.ctype);
        o.put("truncated", e.truncated);
        return o;
    }
}
