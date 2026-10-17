package com.lingqiong.buddy;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

/**
 * [v27] 抓包记录的全局存储（内存态，供前端通过 JS 桥查询）。
 *
 * [v71] 第一次升级：加了 reqHead/respHead/reqBody/respBody 字段。
 *
 * [v77] 第二次升级 —— 用户反馈「还是看不到请求头/请求体」的真凶在这里：
 *   1. ★ MITM 解密后的明文完全没进采集缓冲
 *      Engine 里写的是 `if (!c.mitmReady) feedResp(...)`、`if (!c.mitmPending && !c.mitmReady) feedReq(...)`，
 *      而 MitmTerminator.pump() 只把明文截 2048 字、取第一行 + trim(400) 塞进 log。
 *      结果：HTTPS 解密后 reqHead/respHead/reqBody/respBody 全是空字符串。
 *      → 现在 MitmTerminator 里直接 feedReq/feedResp，并把数据完整缓冲。
 *   2. ★ 只在「连接关闭」时才切分头/体
 *      HTTP/1.1 keep-alive 长连接可以挂几十秒甚至几分钟，期间详情页一片空白。
 *      → 新增 flushPartial()：每收到数据就尝试切分，内容即时可见。
 *   3. ★ 响应体 gzip/deflate 没解压
 *      绝大多数站点的响应都是压缩的，旧版一律判成「[二进制内容]」。
 *      → 新增 decompress()，按 Content-Encoding 解压后再展示。
 *   4. ★ 头只有一坨文本，前端没法做表格
 *      → 新增 reqHeaderList/respHeaderList（结构化 k/v）+ 查询参数解析。
 *   5. ★ 二进制没内容
 *      → 新增 hex dump（前 1KB），至少能看到文件头魔数判断真实类型。
 *
 * 设计原则：
 *   · list() 只带摘要（前 2KB），完整内容走 detail(id) —— 否则每次轮询序列化几十 MB 必卡死
 *   · 二进制不塞进 JSON（控制字符会污染），改存 hex + 类型 + 长度
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

        // [v71] 内容明细
        public String reqHead = "";
        public String respHead = "";
        public String reqBody = "";
        public String respBody = "";
        public int reqBodyLen = 0;
        public int respBodyLen = 0;
        public boolean truncated = false;

        // [v77] 结构化明细
        public String reqHeaderList = "";   // JSONArray 字符串 [{k,v}]
        public String respHeaderList = "";  // JSONArray 字符串 [{k,v}]
        public String reqBodyKind = "";     // text / json / form / image / binary / empty
        public String respBodyKind = "";
        public String reqHex = "";          // 二进制时的十六进制（前 1KB）
        public String respHex = "";
        public String contentEncoding = ""; // gzip / deflate / br
        public long reqMs = 0;              // 首次收到请求的时刻
        public long respMs = 0;             // 首次收到响应的时刻
        public int httpVersion = 0;         // 11 / 20 / 30
        public String query = "";           // URL 里的查询串

        // 采集缓冲（不参与 JSON）
        public ByteArrayOutputStream reqRaw;
        public ByteArrayOutputStream respRaw;
        public String ctype = "";      // 响应 Content-Type
    }

    private static final int MAX = 300;
    private static final int MAX_LOG_LINES = 400;
    private static final int MAX_LOG_CHARS = 8192;
    private static final int CAP_RAW = 512 * 1024;       // [v77] 单方向最多缓冲 512KB（大页面也够看）
    private static final int HEAD_MAX = 16384;           // [v77] 头部最多存 16KB（含 Cookie 的长头也够）
    private static final int BODY_LIST_MAX = 2048;       // list() 里带的正文摘要
    private static final int BODY_FULL_MAX = 256 * 1024; // detail() 里带的正文上限
    private static final int HEX_MAX = 1024;             // hex dump 取前 1KB
    private static final Charset LATIN1 = Charset.forName("ISO-8859-1");
    private static final Charset UTF8 = Charset.forName("UTF-8");
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
                if (e.reqMs == 0) e.reqMs = System.currentTimeMillis();
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
                if (e.respMs == 0) e.respMs = System.currentTimeMillis();
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

    /**
     * [v77] 实时切分：每收到一批数据就尝试把头/体切开并落库。
     *
     * 为什么需要它：finish() 只在连接关闭时调用，而 HTTP/1.1 默认 keep-alive，
     * 一条连接可能挂很久 —— 期间用户点开详情页看到的是空白。
     * 这里不释放缓冲（后面可能还有数据），只把当前已有内容切分出来。
     */
    public static void flushPartial(Entry e) {
        if (e == null) return;
        byte[] rq = null, rs = null;
        int rqLen = 0, rsLen = 0;
        synchronized (LOCK) {
            try {
                if (e.reqRaw != null && e.reqRaw.size() > 0) {
                    rq = e.reqRaw.toByteArray(); rqLen = rq.length;
                }
                if (e.respRaw != null && e.respRaw.size() > 0) {
                    rs = e.respRaw.toByteArray(); rsLen = rs.length;
                }
            } catch (Throwable t) { return; }
        }
        if (rq != null && rqLen > 0) splitInto(e, true, rq, rqLen);
        if (rs != null && rsLen > 0) splitInto(e, false, rs, rsLen);
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
    }

    /* ==================== [v77] 头 / 体 切分 ==================== */

    private static void splitInto(Entry e, boolean isReq, byte[] data, int len) {
        try {
            String txt = new String(data, 0, len, LATIN1);
            int hdrEnd = txt.indexOf("\r\n\r\n");
            int hdrEndLen = 4;
            if (hdrEnd < 0) {
                // 有些服务器用裸 \n\n
                hdrEnd = txt.indexOf("\n\n");
                hdrEndLen = 2;
            }
            String head, body;
            if (hdrEnd >= 0) {
                head = txt.substring(0, hdrEnd);
                body = txt.substring(hdrEnd + hdrEndLen);
            } else {
                if (txt.startsWith("HTTP/") || looksLikeReqLine(txt)) { head = txt; body = ""; }
                else { head = ""; body = txt; }
            }

            String ct = headerValue(head, "content-type");
            String ce = headerValue(head, "content-encoding");
            byte[] bodyBytes = body.getBytes(LATIN1);

            // [v77] 压缩体先解压，否则永远显示「二进制」
            if (ce != null && bodyBytes.length > 0) {
                byte[] dec = decompress(bodyBytes, ce);
                if (dec != null) bodyBytes = dec;
            }

            String kind = classifyBody(ct, bodyBytes);
            String headOut = clip(sanitize(head), HEAD_MAX);
            int blen = bodyBytes.length;
            String bodyOut;
            String hexOut = "";

            if (blen == 0) {
                bodyOut = "";
            } else if ("text".equals(kind) || "json".equals(kind) || "form".equals(kind)) {
                // 文本类：按 UTF-8 解（比 LATIN1 正确），失败再退回 LATIN1
                String decoded;
                try {
                    decoded = new String(bodyBytes, UTF8);
                    // UTF-8 解出大量替换字符 → 其实不是 UTF-8，退回 LATIN1
                    int bad = 0;
                    for (int i = 0; i < decoded.length(); i++) if (decoded.charAt(i) == '\uFFFD') bad++;
                    if (bad > 0 && bad * 20 > decoded.length()) decoded = new String(bodyBytes, LATIN1);
                } catch (Throwable t) {
                    decoded = new String(bodyBytes, LATIN1);
                }
                bodyOut = clip(sanitize(decoded), BODY_FULL_MAX);
                if ("json".equals(kind)) bodyOut = prettyJson(bodyOut);
            } else {
                // 二进制：给长度 + 类型 + hex（至少能看魔数）
                bodyOut = "[二进制内容 " + blen + " 字节" + (ct != null && ct.length() > 0 ? " · " + ct : "") + "]";
                hexOut = hexDump(bodyBytes, HEX_MAX);
            }

            String headerList = parseHeaderList(head);

            if (isReq) {
                e.reqHead = headOut;
                e.reqBody = bodyOut;
                e.reqBodyLen = blen;
                e.reqBodyKind = kind;
                e.reqHex = hexOut;
                e.reqHeaderList = headerList;
                // 请求行 → method / url
                try {
                    String firstLine = head;
                    int nl = firstLine.indexOf('\n');
                    if (nl > 0) firstLine = firstLine.substring(0, nl);
                    firstLine = firstLine.replace("\r", "").trim();
                    if (looksLikeReqLine(firstLine)) {
                        String[] pr = firstLine.split(" ");
                        if (pr.length >= 2) {
                            e.method = pr[0];
                            e.url = pr[1];
                            int q = pr[1].indexOf('?');
                            if (q >= 0 && q + 1 < pr[1].length()) e.query = pr[1].substring(q + 1);
                            if (e.host == null || e.host.length() == 0) {
                                String h = headerValue(head, "host");
                                if (h != null) e.host = h;
                            }
                        }
                        if (firstLine.endsWith("HTTP/1.0")) e.httpVersion = 10;
                        else if (firstLine.endsWith("HTTP/1.1")) e.httpVersion = 11;
                        else if (firstLine.endsWith("HTTP/2")) e.httpVersion = 20;
                        else if (firstLine.endsWith("HTTP/3")) e.httpVersion = 30;
                    }
                } catch (Throwable ignore) {}
            } else {
                e.respHead = headOut;
                e.respBody = bodyOut;
                e.respBodyLen = blen;
                e.respBodyKind = kind;
                e.respHex = hexOut;
                e.respHeaderList = headerList;
                if (ct != null) e.ctype = ct;
                if (ce != null) e.contentEncoding = ce;
                // 状态行
                try {
                    if (head.startsWith("HTTP/")) {
                        String firstLine = head;
                        int nl = firstLine.indexOf('\n');
                        if (nl > 0) firstLine = firstLine.substring(0, nl);
                        e.status = firstLine.replace("\r", "").trim();
                        if (firstLine.contains("HTTP/2")) e.httpVersion = 20;
                        else if (firstLine.contains("HTTP/3")) e.httpVersion = 30;
                        else if (firstLine.contains("HTTP/1.1")) e.httpVersion = 11;
                        else if (firstLine.contains("HTTP/1.0")) e.httpVersion = 10;
                    }
                } catch (Throwable ignore) {}
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
                || s.startsWith("OPTIONS ") || s.startsWith("TRACE ") || s.startsWith("CONNECT ");
    }

    private static String headerValue(String head, String name) {
        if (head == null || head.length() == 0) return null;
        try {
            String[] lines = head.split("\r?\n");
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

    /** [v77] 把头部文本解析成结构化 [{k,v}]，前端可直接渲染成表格。 */
    private static String parseHeaderList(String head) {
        if (head == null || head.length() == 0) return "";
        try {
            JSONArray arr = new JSONArray();
            String[] lines = head.split("\r?\n");
            boolean first = true;
            for (int i = 0; i < lines.length; i++) {
                String ln = lines[i];
                if (ln == null) continue;
                ln = ln.replace("\r", "");
                if (ln.length() == 0) continue;
                if (first) { first = false; continue; } // 首行是请求行/状态行，不是头
                int c = ln.indexOf(':');
                if (c <= 0) continue;
                JSONObject o = new JSONObject();
                o.put("k", ln.substring(0, c).trim());
                o.put("v", ln.substring(c + 1).trim());
                arr.put(o);
            }
            return arr.toString();
        } catch (Throwable t) { return ""; }
    }

    /** [v77] 按 Content-Encoding 解压。br 没有标准库，返回 null（前端会提示）。 */
    private static byte[] decompress(byte[] in, String enc) {
        if (in == null || in.length == 0 || enc == null) return null;
        String e = enc.toLowerCase().trim();
        try {
            if (e.indexOf("gzip") >= 0) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream(in.length * 4);
                GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(in));
                byte[] buf = new byte[8192];
                int n, total = 0;
                while ((n = gz.read(buf)) > 0) {
                    total += n;
                    if (total > CAP_RAW * 2) break;  // 防解压炸弹
                    bos.write(buf, 0, n);
                }
                gz.close();
                return bos.toByteArray();
            }
            if (e.indexOf("deflate") >= 0) {
                Inflater inf = new Inflater(false);
                inf.setInput(in);
                ByteArrayOutputStream bos = new ByteArrayOutputStream(in.length * 4);
                byte[] buf = new byte[8192];
                int total = 0;
                while (!inf.finished()) {
                    int n = inf.inflate(buf);
                    if (n <= 0) break;
                    total += n;
                    if (total > CAP_RAW * 2) break;
                    bos.write(buf, 0, n);
                }
                inf.end();
                return bos.toByteArray();
            }
        } catch (Throwable ignore) {}
        return null;
    }

    /** [v77] 正文类型分类。 */
    private static String classifyBody(String ct, byte[] body) {
        if (body == null || body.length == 0) return "empty";
        String c = ct == null ? "" : ct.toLowerCase();
        if (c.indexOf("json") >= 0) return "json";
        if (c.indexOf("x-www-form-urlencoded") >= 0) return "form";
        if (c.indexOf("image/") >= 0) return "image";
        if (c.indexOf("text/") >= 0 || c.indexOf("xml") >= 0
                || c.indexOf("javascript") >= 0 || c.indexOf("xhtml") >= 0) return "text";
        // 没有 Content-Type 时靠内容判断
        if (looksText(ct, new String(body, LATIN1))) return "text";
        return "binary";
    }

    /** [v77] 十六进制 + ASCII 对照（前 max 字节）。 */
    private static String hexDump(byte[] b, int max) {
        if (b == null || b.length == 0) return "";
        int n = Math.min(b.length, max);
        StringBuilder sb = new StringBuilder(n * 4 + 64);
        for (int i = 0; i < n; i += 16) {
            sb.append(String.format("%08x  ", i));
            StringBuilder asc = new StringBuilder();
            for (int j = 0; j < 16; j++) {
                if (i + j < n) {
                    int v = b[i + j] & 0xff;
                    sb.append(String.format("%02x ", v));
                    asc.append(v >= 32 && v < 127 ? (char) v : '.');
                } else {
                    sb.append("   ");
                    asc.append(' ');
                }
                if (j == 7) sb.append(' ');
            }
            sb.append(" |").append(asc).append("|\n");
        }
        if (b.length > n) sb.append("…（共 ").append(b.length).append(" 字节，只显示前 ").append(n).append(" 字节）");
        return sb.toString();
    }

    /** [v77] JSON 美化（解析失败就原样返回，不破坏内容）。 */
    private static String prettyJson(String s) {
        if (s == null || s.length() == 0) return s;
        String t = s.trim();
        if (!(t.startsWith("{") || t.startsWith("["))) return s;
        try {
            Object o = t.startsWith("{") ? (Object) new JSONObject(t) : (Object) new JSONArray(t);
            return o instanceof JSONObject ? ((JSONObject) o).toString(2) : ((JSONArray) o).toString(2);
        } catch (Throwable ignore) { return s; }
    }

    /** 文本 / 二进制判定：先看 Content-Type，再看控制字符比例。 */
    private static boolean looksText(String ct, String body) {
        if (ct != null) {
            String c = ct.toLowerCase();
            if (c.indexOf("text/") >= 0 || c.indexOf("json") >= 0 || c.indexOf("xml") >= 0
                    || c.indexOf("javascript") >= 0 || c.indexOf("x-www-form-urlencoded") >= 0) return true;
            if (c.indexOf("image/") >= 0 || c.indexOf("video/") >= 0 || c.indexOf("audio/") >= 0
                    || c.indexOf("font") >= 0 || c.indexOf("octet-stream") >= 0 || c.indexOf("zip") >= 0
                    || c.indexOf("pdf") >= 0) return false;
        }
        if (body == null || body.length() == 0) return true;
        int n = Math.min(body.length(), 4096), ctrl = 0;
        for (int i = 0; i < n; i++) {
            char ch = body.charAt(i);
            if (ch == 0) { ctrl += 10; continue; }
            if (ch < 9 || (ch > 13 && ch < 32)) ctrl++;
        }
        return ctrl * 100 / Math.max(n, 1) < 5;
    }

    private static String sanitize(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\n' || c == '\t') sb.append(c);
            else if (c == '\r') { /* 丢掉 \r，前端按 \n 分行 */ }
            else if (c < 32 || c == 127) sb.append(' ');
            else sb.append(c);
        }
        return sb.toString();
    }

    private static String clip(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "\n…（已截断，共 " + s.length() + " 字符）";
    }

    /* ==================== JSON 输出 ==================== */

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

    /** [v71] 单条完整内容（正文最多 256KB），给「详情页」和 AI 用。 */
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
        o.put("reqHead", clip(e.reqHead == null ? "" : e.reqHead, HEAD_MAX));
        o.put("respHead", clip(e.respHead == null ? "" : e.respHead, HEAD_MAX));
        o.put("reqBody", clip(e.reqBody == null ? "" : e.reqBody, bodyMax));
        o.put("respBody", clip(e.respBody == null ? "" : e.respBody, bodyMax));
        o.put("reqBodyLen", e.reqBodyLen);
        o.put("respBodyLen", e.respBodyLen);
        o.put("ctype", e.ctype == null ? "" : e.ctype);
        o.put("truncated", e.truncated);

        // [v77] 结构化明细（list 时不带，省流量；detail 时全给）
        boolean full = bodyMax > BODY_LIST_MAX;
        if (full) {
            o.put("reqHeaderList", e.reqHeaderList == null ? "" : e.reqHeaderList);
            o.put("respHeaderList", e.respHeaderList == null ? "" : e.respHeaderList);
            o.put("reqHex", e.reqHex == null ? "" : e.reqHex);
            o.put("respHex", e.respHex == null ? "" : e.respHex);
            o.put("query", e.query == null ? "" : e.query);
            o.put("contentEncoding", e.contentEncoding == null ? "" : e.contentEncoding);
            o.put("reqMs", e.reqMs);
            o.put("respMs", e.respMs);
            o.put("httpVersion", e.httpVersion);
        }
        o.put("reqBodyKind", e.reqBodyKind == null ? "" : e.reqBodyKind);
        o.put("respBodyKind", e.respBodyKind == null ? "" : e.respBodyKind);
        return o;
    }
}
