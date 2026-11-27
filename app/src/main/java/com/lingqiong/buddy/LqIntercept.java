package com.lingqiong.buddy;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * [v141] 抓包增强：重写规则 + 断点拦截 + 挂起队列。
 *
 * ── 为什么要这一层 ──
 * 原来的 MitmTerminator.pump() 是纯字节管道：读多少转发多少，只旁路解析用于记录。
 * 想「改包」就必须知道一条消息到哪里结束，所以 pump 改成按【完整 HTTP 消息】转发，
 * 转发前先把消息交给这里处理：跑重写规则 → 命中断点就挂起等用户决定 → 返回最终字节。
 *
 * ── 设计原则 ──
 * 1. 失败放行：本类任何异常都必须让原始消息照常发出去，绝不能因为改包把用户网络弄断。
 * 2. 不改就不复制：没命中任何规则时直接返回原数组，零拷贝。
 * 3. 流式不阻塞：SSE / 大文件 / chunked 未结束时立刻切直通，不做缓冲。
 *
 * ── 规则类型 ──
 *   req       改请求（头 / 体）
 *   resp      改响应（头 / 体 / 状态行）
 *   redirect  重定向到另一个 URL（改写请求行，目标由本机直连）
 *   mock      用固定内容替换响应体
 *   block     丢弃请求（连接关闭）
 */
public class LqIntercept {

    public static final String PREF_FILE = "lq_intercept.json";

    /* ==================== 数据结构 ==================== */

    public static class Rule {
        public String id = "";
        public String name = "";
        public String type = "req";      // req / resp / redirect / mock / block
        public boolean enabled = true;
        public String urlMatch = "";     // 空=全部；含 * 通配；/xxx/ 正则；否则子串
        public String methodMatch = "";  // 空=全部；可写 GET,POST
        public String statusMatch = "";  // resp 用，空=全部；可写 200,404,5xx
        public String setHeaders = "";   // 每行 "K: V"
        public String removeHeaders = "";// 逗号或换行分隔的 K
        public String setBody = "";      // 新 body（文本）
        public String setStatus = "";    // resp 用，如 "200 OK"
        public String redirectTo = "";   // redirect 用
        public String mockBody = "";     // mock 用（文本）
        public String mockStatus = "200 OK";

        JSONObject toJson() {
            JSONObject o = new JSONObject();
            try {
                o.put("id", id); o.put("name", name); o.put("type", type);
                o.put("enabled", enabled); o.put("urlMatch", urlMatch);
                o.put("methodMatch", methodMatch); o.put("statusMatch", statusMatch);
                o.put("setHeaders", setHeaders); o.put("removeHeaders", removeHeaders);
                o.put("setBody", setBody); o.put("setStatus", setStatus);
                o.put("redirectTo", redirectTo); o.put("mockBody", mockBody);
                o.put("mockStatus", mockStatus);
            } catch (Throwable ignore) {}
            return o;
        }

        static Rule from(JSONObject o) {
            Rule r = new Rule();
            r.id = o.optString("id", "");
            r.name = o.optString("name", "");
            r.type = o.optString("type", "req");
            r.enabled = o.optBoolean("enabled", true);
            r.urlMatch = o.optString("urlMatch", "");
            r.methodMatch = o.optString("methodMatch", "");
            r.statusMatch = o.optString("statusMatch", "");
            r.setHeaders = o.optString("setHeaders", "");
            r.removeHeaders = o.optString("removeHeaders", "");
            r.setBody = o.optString("setBody", "");
            r.setStatus = o.optString("setStatus", "");
            r.redirectTo = o.optString("redirectTo", "");
            r.mockBody = o.optString("mockBody", "");
            r.mockStatus = o.optString("mockStatus", "200 OK");
            return r;
        }
    }

    public static class Bp {
        public String id = "";
        public String name = "";
        public boolean enabled = true;
        public String urlMatch = "";
        public String methodMatch = "";
        public boolean onRequest = true;
        public boolean onResponse = false;

        JSONObject toJson() {
            JSONObject o = new JSONObject();
            try {
                o.put("id", id); o.put("name", name); o.put("enabled", enabled);
                o.put("urlMatch", urlMatch); o.put("methodMatch", methodMatch);
                o.put("onRequest", onRequest); o.put("onResponse", onResponse);
            } catch (Throwable ignore) {}
            return o;
        }

        static Bp from(JSONObject o) {
            Bp b = new Bp();
            b.id = o.optString("id", "");
            b.name = o.optString("name", "");
            b.enabled = o.optBoolean("enabled", true);
            b.urlMatch = o.optString("urlMatch", "");
            b.methodMatch = o.optString("methodMatch", "");
            b.onRequest = o.optBoolean("onRequest", true);
            b.onResponse = o.optBoolean("onResponse", false);
            return b;
        }
    }

    /** 一个被断点拦下的消息，等前端决定。 */
    public static class Pending {
        public long pid;
        public long recId;
        public boolean isResponse;
        public String url = "";
        public String method = "";
        public String head = "";
        public byte[] body = new byte[0];
        public long at;

        volatile int decision = 0;          // 0=等待 1=放行 2=丢弃
        volatile String newHead = null;     // 用户改过的头
        volatile byte[] newBody = null;     // 用户改过的体

        JSONObject toJson() {
            JSONObject o = new JSONObject();
            try {
                o.put("pid", pid);
                o.put("recId", recId);
                o.put("isResponse", isResponse);
                o.put("url", url);
                o.put("method", method);
                o.put("head", head);
                o.put("bodyLen", body.length);
                o.put("body", body.length <= 262144
                        ? new String(body, StandardCharsets.UTF_8) : "");
                o.put("bodyB64", body.length <= 262144 ? b64(body) : "");
                o.put("bodyTruncated", body.length > 262144);
                o.put("at", at);
            } catch (Throwable ignore) {}
            return o;
        }
    }

    private static final List<Rule> RULES = new ArrayList<>();
    private static final List<Bp> BPS = new ArrayList<>();
    private static final List<Pending> PEND = new ArrayList<>();
    private static long PID_SEQ = 1;
    private static final Object LOCK = new Object();
    private static volatile Context APP = null;

    /** 断点等待上限：超时自动放行，避免用户走开导致连接永久挂住。 */
    private static final int BP_TIMEOUT_MS = 120000;

    public static void init(Context c) {
        APP = c;
        load();
    }

    /* ==================== 规则 CRUD ==================== */

    public static String listRulesJson() {
        JSONArray a = new JSONArray();
        synchronized (LOCK) {
            for (Rule r : RULES) a.put(r.toJson());
        }
        return a.toString();
    }

    public static String saveRule(String json) {
        try {
            JSONObject o = new JSONObject(json);
            Rule r = Rule.from(o);
            if (r.id == null || r.id.isEmpty()) r.id = "r" + System.currentTimeMillis();
            if (r.name == null || r.name.isEmpty()) r.name = r.type + " 规则";
            synchronized (LOCK) {
                boolean replaced = false;
                for (int i = 0; i < RULES.size(); i++) {
                    if (RULES.get(i).id.equals(r.id)) { RULES.set(i, r); replaced = true; break; }
                }
                if (!replaced) RULES.add(r);
            }
            save();
            return r.id;
        } catch (Throwable t) {
            return "";
        }
    }

    public static boolean delRule(String id) {
        synchronized (LOCK) {
            for (int i = 0; i < RULES.size(); i++) {
                if (RULES.get(i).id.equals(id)) { RULES.remove(i); save(); return true; }
            }
        }
        return false;
    }

    public static boolean setRuleEnabled(String id, boolean en) {
        synchronized (LOCK) {
            for (Rule r : RULES) {
                if (r.id.equals(id)) { r.enabled = en; save(); return true; }
            }
        }
        return false;
    }

    public static int ruleCount() { synchronized (LOCK) { return RULES.size(); } }

    /* ==================== 断点 CRUD ==================== */

    public static String listBpsJson() {
        JSONArray a = new JSONArray();
        synchronized (LOCK) {
            for (Bp b : BPS) a.put(b.toJson());
        }
        return a.toString();
    }

    public static String saveBp(String json) {
        try {
            JSONObject o = new JSONObject(json);
            Bp b = Bp.from(o);
            if (b.id == null || b.id.isEmpty()) b.id = "b" + System.currentTimeMillis();
            if (b.name == null || b.name.isEmpty()) b.name = "断点";
            synchronized (LOCK) {
                boolean replaced = false;
                for (int i = 0; i < BPS.size(); i++) {
                    if (BPS.get(i).id.equals(b.id)) { BPS.set(i, b); replaced = true; break; }
                }
                if (!replaced) BPS.add(b);
            }
            save();
            return b.id;
        } catch (Throwable t) {
            return "";
        }
    }

    public static boolean delBp(String id) {
        synchronized (LOCK) {
            for (int i = 0; i < BPS.size(); i++) {
                if (BPS.get(i).id.equals(id)) { BPS.remove(i); save(); return true; }
            }
        }
        return false;
    }

    public static boolean setBpEnabled(String id, boolean en) {
        synchronized (LOCK) {
            for (Bp b : BPS) {
                if (b.id.equals(id)) { b.enabled = en; save(); return true; }
            }
        }
        return false;
    }

    /* ==================== 挂起队列 ==================== */

    public static String listPendingJson() {
        JSONArray a = new JSONArray();
        synchronized (PEND) {
            for (Pending p : PEND) a.put(p.toJson());
        }
        return a.toString();
    }

    public static int pendingCount() { synchronized (PEND) { return PEND.size(); } }

    /**
     * 前端对某个挂起消息做决定。
     * @param action 1=放行 2=丢弃
     * @param newHead 改过的头（空=用原头）
     * @param newBodyB64 改过的体 base64（空=用原体）
     */
    public static boolean decide(long pid, int action, String newHead, String newBodyB64) {
        Pending hit = null;
        synchronized (PEND) {
            for (Pending p : PEND) {
                if (p.pid == pid) { hit = p; break; }
            }
        }
        if (hit == null) return false;
        try {
            if (newHead != null && !newHead.isEmpty()) hit.newHead = newHead;
            if (newBodyB64 != null && !newBodyB64.isEmpty()) hit.newBody = unb64(newBodyB64);
        } catch (Throwable ignore) {}
        hit.decision = action == 2 ? 2 : 1;
        synchronized (hit) { try { hit.notifyAll(); } catch (Throwable ignore) {} }
        return true;
    }

    public static boolean releaseAll() {
        boolean any = false;
        synchronized (PEND) {
            for (Pending p : PEND) {
                p.decision = 1;
                synchronized (p) { try { p.notifyAll(); } catch (Throwable ignore) {} }
                any = true;
            }
        }
        return any;
    }

    /* ==================== 消息处理入口 ==================== */

    /** 请求方向：跑规则 → 断点 → 返回最终字节。异常一律返回原消息。 */
    public static byte[] passRequest(String url, String method, byte[] msg, long recId) {
        byte[] out = msg;
        try {
            out = applyRules(url, method, "", out, false);
        } catch (Throwable ignore) { out = msg; }
        try {
            if (shouldBreak(url, method, false)) {
                out = awaitBreak(url, method, out, false, recId);
            }
        } catch (Throwable ignore) {}
        return out == null ? new byte[0] : out;
    }

    /** 响应方向。 */
    public static byte[] passResponse(String url, String method, byte[] msg, long recId) {
        byte[] out = msg;
        try {
            String status = "";
            try { status = statusCode(out); } catch (Throwable ignore) {}
            out = applyRules(url, method, status, out, true);
        } catch (Throwable ignore) { out = msg; }
        try {
            if (shouldBreak(url, method, true)) {
                out = awaitBreak(url, method, out, true, recId);
            }
        } catch (Throwable ignore) {}
        return out == null ? new byte[0] : out;
    }

    /* ==================== 规则执行 ==================== */

    private static byte[] applyRules(String url, String method, String status, byte[] msg, boolean isResp) {
        List<Rule> snapshot;
        synchronized (LOCK) {
            if (RULES.isEmpty()) return msg;
            snapshot = new ArrayList<>(RULES);
        }
        byte[] cur = msg;
        boolean changed = false;
        for (Rule r : snapshot) {
            if (!r.enabled) continue;
            if (!urlMatch(r.urlMatch, url)) continue;
            if (!methodMatch(r.methodMatch, method)) continue;
            if (isResp && !statusMatch(r.statusMatch, status)) continue;

            String t = r.type == null ? "" : r.type;
            if (!isResp) {
                if ("req".equals(t)) {
                    byte[] n = modify(r, cur, false);
                    if (n != null) { cur = n; changed = true; }
                } else if ("redirect".equals(t)) {
                    byte[] n = redirect(r, cur);
                    if (n != null) { cur = n; changed = true; }
                } else if ("block".equals(t)) {
                    return new byte[0];   // 丢弃：pump 不写，连接随后关闭
                }
            } else {
                if ("resp".equals(t)) {
                    byte[] n = modify(r, cur, true);
                    if (n != null) { cur = n; changed = true; }
                } else if ("mock".equals(t)) {
                    byte[] n = mock(r, cur);
                    if (n != null) { cur = n; changed = true; }
                }
            }
        }
        return changed ? cur : msg;
    }

    private static byte[] modify(Rule r, byte[] msg, boolean isResp) {
        try {
            int he = headEnd(msg);
            if (he < 0) return null;
            String head = new String(msg, 0, he, StandardCharsets.ISO_8859_1);
            byte[] body = slice(msg, he);
            boolean touched = false;

            // 状态行
            if (isResp && r.setStatus != null && !r.setStatus.isEmpty()) {
                int nl = head.indexOf("\r\n");
                String rest = nl >= 0 ? head.substring(nl) : "";
                String v = head.startsWith("HTTP/") ? head.substring(0, head.indexOf(' ')) : "HTTP/1.1";
                head = v + " " + r.setStatus.trim() + rest;
                touched = true;
            }
            // 删头
            if (r.removeHeaders != null && !r.removeHeaders.isEmpty()) {
                for (String k : r.removeHeaders.split("[,\\n]")) {
                    k = k.trim();
                    if (k.isEmpty()) continue;
                    String nh = removeHeader(head, k);
                    if (!nh.equals(head)) { head = nh; touched = true; }
                }
            }
            // 设头
            if (r.setHeaders != null && !r.setHeaders.isEmpty()) {
                for (String line : r.setHeaders.split("\\n")) {
                    line = line.trim();
                    if (line.isEmpty()) continue;
                    int c = line.indexOf(':');
                    if (c <= 0) continue;
                    String k = line.substring(0, c).trim();
                    String v = line.substring(c + 1).trim();
                    head = setHeader(head, k, v);
                    touched = true;
                }
            }
            // 换体
            if (r.setBody != null && !r.setBody.isEmpty()) {
                body = r.setBody.getBytes(StandardCharsets.UTF_8);
                head = setHeader(head, "Content-Length", String.valueOf(body.length));
                // 体变了，原来的压缩/分块声明不再成立
                head = removeHeader(head, "Content-Encoding");
                head = removeHeader(head, "Transfer-Encoding");
                touched = true;
            }
            if (!touched) return null;
            return rebuild(head, body);
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] redirect(Rule r, byte[] msg) {
        try {
            if (r.redirectTo == null || r.redirectTo.isEmpty()) return null;
            int he = headEnd(msg);
            if (he < 0) return null;
            String head = new String(msg, 0, he, StandardCharsets.ISO_8859_1);
            int nl = head.indexOf("\r\n");
            if (nl < 0) return null;
            String first = head.substring(0, nl);
            String rest = head.substring(nl);
            String[] parts = first.split(" ");
            if (parts.length < 2) return null;
            String target = r.redirectTo.trim();
            // 允许用 $url 占位保留原路径
            if (target.contains("$url")) target = target.replace("$url", parts[1]);
            String newFirst = parts[0] + " " + target + " " + (parts.length > 2 ? parts[2] : "HTTP/1.1");
            return rebuild(newFirst + rest, slice(msg, he));
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] mock(Rule r, byte[] msg) {
        try {
            int he = headEnd(msg);
            if (he < 0) return null;
            String head = new String(msg, 0, he, StandardCharsets.ISO_8859_1);
            String ver = head.startsWith("HTTP/") ? head.substring(0, head.indexOf(' ')) : "HTTP/1.1";
            String st = (r.mockStatus == null || r.mockStatus.isEmpty()) ? "200 OK" : r.mockStatus.trim();
            String bodyStr = r.mockBody == null ? "" : r.mockBody;
            byte[] body = bodyStr.getBytes(StandardCharsets.UTF_8);

            StringBuilder sb = new StringBuilder();
            sb.append(ver).append(' ').append(st).append("\r\n");
            sb.append("Content-Type: application/json; charset=utf-8\r\n");
            sb.append("Content-Length: ").append(body.length).append("\r\n");
            sb.append("Connection: close\r\n");
            sb.append("X-LQ-Mock: 1\r\n");
            sb.append("\r\n");
            return rebuild(sb.toString(), body);
        } catch (Throwable t) {
            return null;
        }
    }

    /* ==================== 断点 ==================== */

    private static boolean shouldBreak(String url, String method, boolean isResp) {
        synchronized (LOCK) {
            for (Bp b : BPS) {
                if (!b.enabled) continue;
                if (isResp && !b.onResponse) continue;
                if (!isResp && !b.onRequest) continue;
                if (!urlMatch(b.urlMatch, url)) continue;
                if (!methodMatch(b.methodMatch, method)) continue;
                return true;
            }
        }
        return false;
    }

    private static byte[] awaitBreak(String url, String method, byte[] msg, boolean isResp, long recId) {
        Pending p = new Pending();
        synchronized (PEND) {
            p.pid = PID_SEQ++;
            p.recId = recId;
            p.isResponse = isResp;
            p.url = url == null ? "" : url;
            p.method = method == null ? "" : method;
            p.at = System.currentTimeMillis();
            try {
                int he = headEnd(msg);
                p.head = he > 0 ? new String(msg, 0, he, StandardCharsets.ISO_8859_1) : "";
                p.body = he > 0 ? slice(msg, he) : msg;
            } catch (Throwable ignore) {}
            PEND.add(p);
        }
        // 阻塞等待（有上限）
        long deadline = System.currentTimeMillis() + BP_TIMEOUT_MS;
        synchronized (p) {
            while (p.decision == 0) {
                long left = deadline - System.currentTimeMillis();
                if (left <= 0) break;
                try { p.wait(Math.min(left, 500)); } catch (Throwable ignore) {}
            }
        }
        synchronized (PEND) { PEND.remove(p); }

        if (p.decision == 2) return new byte[0];           // 丢弃
        try {
            if (p.newHead != null && !p.newHead.isEmpty()) {
                byte[] body = p.newBody != null ? p.newBody : p.body;
                String h = p.newHead;
                if (p.newBody != null) h = setHeader(h, "Content-Length", String.valueOf(body.length));
                return rebuild(h, body);
            }
            if (p.newBody != null) {
                String h = p.head;
                h = setHeader(h, "Content-Length", String.valueOf(p.newBody.length));
                return rebuild(h, p.newBody);
            }
        } catch (Throwable ignore) {}
        return msg;                                         // 放行原样
    }

    /* ==================== HTTP 消息边界 ==================== */

    public static final int NOT_HTTP = -2;
    public static final int INCOMPLETE = -1;
    public static final int STREAM_THROUGH = -3;

    private static final int MAX_MSG = 8 * 1024 * 1024;   // 单条消息缓冲上限

    /**
     * 判断 b[0..len) 里是否已有一条完整的 HTTP 消息。
     * @return >=0 完整消息长度；INCOMPLETE 还不全；NOT_HTTP 不是 HTTP；STREAM_THROUGH 应直通
     */
    public static int completeLen(byte[] b, int len, boolean isResp) {
        if (b == null || len <= 0) return INCOMPLETE;
        if (len < 5) {
            // 先做前缀判断，避免把二进制流当 HTTP 缓冲
            String p = new String(b, 0, len, StandardCharsets.ISO_8859_1);
            if (isResp ? !"HTTP/".startsWith(p) && !p.startsWith("HTTP/")
                       : !looksLikeMethodPrefix(p)) return NOT_HTTP;
            return INCOMPLETE;
        }
        String head5 = new String(b, 0, 5, StandardCharsets.ISO_8859_1);
        if (isResp) {
            if (!head5.startsWith("HTTP/")) return NOT_HTTP;
        } else {
            if (!looksLikeMethodPrefix(head5)) return NOT_HTTP;
        }
        int he = headEnd(b, len);
        if (he < 0) {
            if (len > MAX_MSG) return STREAM_THROUGH;
            return INCOMPLETE;
        }
        String head = new String(b, 0, he, StandardCharsets.ISO_8859_1);
        // 101 升级（WebSocket）：头之后就是二进制帧，直接切直通
        String firstLine = head;
        int nl = head.indexOf("\r\n");
        if (nl > 0) firstLine = head.substring(0, nl);
        if (isResp && firstLine.contains(" 101")) return he;

        boolean chunked = containsIgnoreCase(head, "Transfer-Encoding:") && containsIgnoreCase(head, "chunked");
        if (chunked) {
            int end = chunkedEnd(b, he, len);
            if (end > 0) return end;
            if (len > 65536) return STREAM_THROUGH;   // SSE / 无限流 → 直通
            if (len > MAX_MSG) return STREAM_THROUGH;
            return INCOMPLETE;
        }
        long cl = contentLength(head);
        if (cl >= 0) {
            long total = he + cl;
            if (total > MAX_MSG) return STREAM_THROUGH;
            if (len >= total) return (int) total;
            return INCOMPLETE;
        }
        // 没有 Content-Length 也没有 chunked：只有头
        return he;
    }

    private static boolean looksLikeMethodPrefix(String p) {
        if (p == null || p.isEmpty()) return false;
        String[] ms = {"GET ", "POST", "PUT ", "HEAD", "DELE", "OPTI", "PATC", "CONN", "TRAC"};
        for (String m : ms) {
            if (p.length() <= m.length()) {
                if (m.startsWith(p)) return true;
            } else if (p.startsWith(m)) return true;
        }
        return false;
    }

    /** 返回 \r\n\r\n 之后的位置（头长），没有则 -1。 */
    public static int headEnd(byte[] b) { return headEnd(b, b == null ? 0 : b.length); }

    public static int headEnd(byte[] b, int len) {
        if (b == null) return -1;
        for (int i = 0; i + 3 < len; i++) {
            if (b[i] == '\r' && b[i + 1] == '\n' && b[i + 2] == '\r' && b[i + 3] == '\n') return i + 4;
        }
        return -1;
    }

    private static int chunkedEnd(byte[] b, int from, int len) {
        int i = from;
        while (i < len) {
            int nl = -1;
            for (int j = i; j + 1 < len; j++) {
                if (b[j] == '\r' && b[j + 1] == '\n') { nl = j; break; }
            }
            if (nl < 0) return -1;
            String line = new String(b, i, nl - i, StandardCharsets.ISO_8859_1).trim();
            int semi = line.indexOf(';');
            if (semi >= 0) line = line.substring(0, semi);
            int size;
            try { size = Integer.parseInt(line.trim(), 16); } catch (Throwable t) { return -1; }
            i = nl + 2;
            if (size == 0) {
                // 结尾可能是 "\r\n" 或 "trailer\r\n\r\n"
                if (i + 1 < len && b[i] == '\r' && b[i + 1] == '\n') return i + 2;
                for (int j = i; j + 3 < len; j++) {
                    if (b[j] == '\r' && b[j + 1] == '\n' && b[j + 2] == '\r' && b[j + 3] == '\n') return j + 4;
                }
                return -1;
            }
            i += size;
            if (i + 1 < len && b[i] == '\r' && b[i + 1] == '\n') i += 2;
            else return -1;
        }
        return -1;
    }

    private static long contentLength(String head) {
        String[] lines = head.split("\r\n");
        for (String ln : lines) {
            int c = ln.indexOf(':');
            if (c <= 0) continue;
            String k = ln.substring(0, c).trim();
            if (!k.equalsIgnoreCase("Content-Length")) continue;
            try { return Long.parseLong(ln.substring(c + 1).trim()); } catch (Throwable t) { return -1; }
        }
        return -1;
    }

    public static String[] requestLine(byte[] msg) {
        try {
            int he = headEnd(msg);
            int end = he > 0 ? he : msg.length;
            int nl = -1;
            for (int i = 0; i < end; i++) if (msg[i] == '\r') { nl = i; break; }
            if (nl < 0) return new String[]{"", ""};
            String first = new String(msg, 0, nl, StandardCharsets.ISO_8859_1);
            String[] p = first.split(" ");
            String m = p.length > 0 ? p[0] : "";
            String u = p.length > 1 ? p[1] : "";
            return new String[]{m, u};
        } catch (Throwable t) {
            return new String[]{"", ""};
        }
    }

    public static String statusCode(byte[] msg) {
        try {
            int nl = -1;
            for (int i = 0; i < msg.length && i < 64; i++) if (msg[i] == '\r') { nl = i; break; }
            if (nl < 0) return "";
            String first = new String(msg, 0, nl, StandardCharsets.ISO_8859_1);
            String[] p = first.split(" ");
            return p.length > 1 ? p[1] : "";
        } catch (Throwable t) {
            return "";
        }
    }

    /* ==================== 头操作 ==================== */

    public static String setHeader(String head, String name, String value) {
        try {
            String[] lines = head.split("\r\n", -1);
            StringBuilder sb = new StringBuilder();
            boolean done = false;
            for (int i = 0; i < lines.length; i++) {
                String ln = lines[i];
                if (ln.isEmpty()) continue;
                int c = ln.indexOf(':');
                boolean isTarget = c > 0 && ln.substring(0, c).trim().equalsIgnoreCase(name);
                if (isTarget) {
                    if (!done) { sb.append(name).append(": ").append(value).append("\r\n"); done = true; }
                    continue;
                }
                sb.append(ln).append("\r\n");
            }
            if (!done) sb.append(name).append(": ").append(value).append("\r\n");
            sb.append("\r\n");
            return sb.toString();
        } catch (Throwable t) {
            return head;
        }
    }

    public static String removeHeader(String head, String name) {
        try {
            String[] lines = head.split("\r\n", -1);
            StringBuilder sb = new StringBuilder();
            for (String ln : lines) {
                if (ln.isEmpty()) continue;
                int c = ln.indexOf(':');
                if (c > 0 && ln.substring(0, c).trim().equalsIgnoreCase(name)) continue;
                sb.append(ln).append("\r\n");
            }
            sb.append("\r\n");
            return sb.toString();
        } catch (Throwable t) {
            return head;
        }
    }

    public static byte[] rebuild(String head, byte[] body) {
        byte[] h = head.getBytes(StandardCharsets.ISO_8859_1);
        if (body == null || body.length == 0) return h;
        byte[] out = new byte[h.length + body.length];
        System.arraycopy(h, 0, out, 0, h.length);
        System.arraycopy(body, 0, out, h.length, body.length);
        return out;
    }

    private static byte[] slice(byte[] b, int from) {
        if (from >= b.length) return new byte[0];
        byte[] o = new byte[b.length - from];
        System.arraycopy(b, from, o, 0, o.length);
        return o;
    }

    private static boolean containsIgnoreCase(String s, String sub) {
        return s != null && s.toLowerCase().contains(sub.toLowerCase());
    }

    /* ==================== 匹配 ==================== */

    public static boolean urlMatch(String pattern, String url) {
        try {
            if (pattern == null) return true;
            pattern = pattern.trim();
            if (pattern.isEmpty()) return true;
            String u = url == null ? "" : url;
            if (pattern.length() > 2 && pattern.startsWith("/") && pattern.endsWith("/")) {
                return Pattern.compile(pattern.substring(1, pattern.length() - 1)).matcher(u).find();
            }
            if (pattern.indexOf('*') >= 0) {
                StringBuilder re = new StringBuilder();
                for (char c : pattern.toCharArray()) {
                    if (c == '*') re.append(".*");
                    else re.append(Pattern.quote(String.valueOf(c)));
                }
                return Pattern.compile(re.toString(), Pattern.CASE_INSENSITIVE).matcher(u).find();
            }
            return u.toLowerCase().contains(pattern.toLowerCase());
        } catch (Throwable t) {
            return false;
        }
    }

    public static boolean methodMatch(String pattern, String method) {
        try {
            if (pattern == null) return true;
            pattern = pattern.trim();
            if (pattern.isEmpty()) return true;
            String m = method == null ? "" : method.trim();
            for (String p : pattern.split("[,\\s]+")) {
                p = p.trim();
                if (p.isEmpty()) continue;
                if (p.equalsIgnoreCase(m)) return true;
            }
            return false;
        } catch (Throwable t) {
            return false;
        }
    }

    public static boolean statusMatch(String pattern, String status) {
        try {
            if (pattern == null) return true;
            pattern = pattern.trim();
            if (pattern.isEmpty()) return true;
            String s = status == null ? "" : status.trim();
            for (String p : pattern.split("[,\\s]+")) {
                p = p.trim();
                if (p.isEmpty()) continue;
                if (p.endsWith("xx") && p.length() == 3) {
                    if (s.startsWith(p.substring(0, 1))) return true;
                } else if (p.equals(s)) return true;
            }
            return false;
        } catch (Throwable t) {
            return false;
        }
    }

    /* ==================== 持久化 ==================== */

    public static void save() {
        Context c = APP;
        if (c == null) return;
        try {
            JSONObject o = new JSONObject();
            JSONArray ra = new JSONArray();
            synchronized (LOCK) { for (Rule r : RULES) ra.put(r.toJson()); }
            JSONArray ba = new JSONArray();
            synchronized (LOCK) { for (Bp b : BPS) ba.put(b.toJson()); }
            o.put("rules", ra);
            o.put("bps", ba);
            File f = new File(c.getFilesDir(), PREF_FILE);
            FileOutputStream fo = new FileOutputStream(f);
            fo.write(o.toString().getBytes(StandardCharsets.UTF_8));
            fo.close();
        } catch (Throwable ignore) {}
    }

    public static void load() {
        Context c = APP;
        if (c == null) return;
        try {
            File f = new File(c.getFilesDir(), PREF_FILE);
            if (!f.exists()) return;
            byte[] b = new byte[(int) f.length()];
            FileInputStream fi = new FileInputStream(f);
            int n = fi.read(b);
            fi.close();
            if (n <= 0) return;
            JSONObject o = new JSONObject(new String(b, 0, n, StandardCharsets.UTF_8));
            JSONArray ra = o.optJSONArray("rules");
            JSONArray ba = o.optJSONArray("bps");
            synchronized (LOCK) {
                RULES.clear();
                BPS.clear();
                if (ra != null) for (int i = 0; i < ra.length(); i++) RULES.add(Rule.from(ra.getJSONObject(i)));
                if (ba != null) for (int i = 0; i < ba.length(); i++) BPS.add(Bp.from(ba.getJSONObject(i)));
            }
        } catch (Throwable ignore) {}
    }

    /* ==================== base64 ==================== */

    public static String b64(byte[] d) {
        try {
            return android.util.Base64.encodeToString(d, android.util.Base64.NO_WRAP);
        } catch (Throwable t) {
            return "";
        }
    }

    public static byte[] unb64(String s) {
        try {
            return android.util.Base64.decode(s, android.util.Base64.NO_WRAP);
        } catch (Throwable t) {
            return new byte[0];
        }
    }
}
