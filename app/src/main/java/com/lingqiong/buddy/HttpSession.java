package com.lingqiong.buddy;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;

/**
 * [v83] 单条 TCP 连接上的 HTTP / WebSocket 会话状态机。
 *
 * 为什么必须有它：
 *   旧版 onClientData / onServerData 是「每收到一个 TCP 段就独立解析」。
 *   但 HTTP 正文（尤其 JSON、HTML、图片）几乎一定跨多个段，
 *   于是旧版永远只看得到第一段 —— 这就是「正文被切碎、看不懂」的机制性原因。
 *   本类按 Content-Length / chunked 边界把字节流重新拼成完整消息。
 *
 * WebSocket：
 *   握手成功（HTTP 101 + Upgrade: websocket）后同一连接变成帧结构，
 *   自动切到帧解析，解出 opcode 与载荷。
 */
public class HttpSession {

    public interface Sink {
        void onHttp(boolean isRequest, String head, byte[] body, int bodyLen);
        void onWs(boolean isRequest, int opcode, byte[] payload, int len);
        void onNote(String note);
    }

    private static final int MAX_HEAD = 48 * 1024;
    private static final int MAX_ACC = 2 * 1024 * 1024;   // 单条消息累积上限
    private static final int MAX_WS = 512 * 1024;

    private final Sink sink;
    private final Stream req = new Stream();
    private final Stream resp = new Stream();
    private volatile boolean wsMode = false;

    public HttpSession(Sink sink) { this.sink = sink; }
    public boolean isWebSocket() { return wsMode; }

    // ==================== 入口 ====================
    public void onClient(byte[] data, int off, int len) {
        if (wsMode) { feedWs(true, data, off, len); return; }
        feed(false, data, off, len);
    }

    public void onServer(byte[] data, int off, int len) {
        if (wsMode) { feedWs(false, data, off, len); return; }
        feed(true, data, off, len);
    }

    /** 连接关闭：把「靠关闭界定长度」的残留消息交出去 */
    public void finish() {
        flushTail(false);
        flushTail(true);
    }

    // ==================== 流状态 ====================
    private static class Stream {
        final ByteArrayOutputStream buf = new ByteArrayOutputStream(8192);
        String headText = null;   // 已解析但正文未齐的头
        int contentLen = -1;
        boolean chunked = false;
        boolean noBody = false;

        void clearMsg() {
            headText = null;
            contentLen = -1;
            chunked = false;
            noBody = false;
        }
    }

    private void feed(boolean isResponse, byte[] data, int off, int len) {
        Stream s = isResponse ? resp : req;

        if (len > 0) {
            if (s.buf.size() + len > MAX_ACC) {
                if (sink != null) sink.onNote("单条消息超过 " + HttpCodec.humanSize(MAX_ACC) + "，已放弃");
                s.buf.reset();
                s.clearMsg();
                return;
            }
            s.buf.write(data, off, len);
        }

        byte[] all = s.buf.toByteArray();
        int pos = 0;

        while (true) {
            // ---- 阶段一：拿头 ----
            if (s.headText == null) {
                int he = indexOfAll(all, pos, CRLFCRLF);
                if (he < 0) {
                    if (all.length - pos > MAX_HEAD) {
                        s.buf.reset();
                        s.clearMsg();
                        return;
                    }
                    break;   // 头未收全
                }
                String head = new String(all, pos, he + 4 - pos, Charset.forName("ISO-8859-1"));
                if (!looksHttp(head, isResponse)) {
                    s.buf.reset();
                    s.clearMsg();
                    return;
                }
                s.headText = head;
                s.contentLen = parseLen(head);
                String te = HttpCodec.header(head, "Transfer-Encoding");
                s.chunked = te != null && te.toLowerCase().contains("chunked");
                s.noBody = s.contentLen < 0 && !s.chunked;
                pos = he + 4;

                if (isResponse && head.startsWith("HTTP/")) {
                    String up = HttpCodec.header(head, "Upgrade");
                    if (head.contains(" 101") && up != null && up.toLowerCase().contains("websocket")) {
                        wsMode = true;
                    }
                }
            }

            // ---- 阶段二：拿体 ----
            if (s.noBody) {
                if (sink != null) sink.onHttp(isResponse, s.headText, new byte[0], 0);
                s.clearMsg();
                if (pos >= all.length) { s.buf.reset(); return; }
                continue;
            }
            if (s.chunked) {
                int end = chunkedEnd(all, pos);
                if (end < 0) break;
                byte[] body = slice(all, pos, end);
                if (sink != null) sink.onHttp(isResponse, s.headText, body, body.length);
                pos = end;
                s.clearMsg();
                if (pos >= all.length) { s.buf.reset(); return; }
                continue;
            }
            int need = Math.max(0, s.contentLen);
            if (all.length - pos < need) break;
            byte[] body = new byte[need];
            System.arraycopy(all, pos, body, 0, need);
            if (sink != null) sink.onHttp(isResponse, s.headText, body, need);
            pos += need;
            s.clearMsg();
            if (pos >= all.length) { s.buf.reset(); return; }
            continue;
        }

        // 未消费的字节写回
        byte[] remain = new byte[Math.max(0, all.length - pos)];
        if (remain.length > 0) System.arraycopy(all, pos, remain, 0, remain.length);
        s.buf.reset();
        if (remain.length > 0) s.buf.write(remain, 0, remain.length);
    }

    private void flushTail(boolean isResponse) {
        Stream s = isResponse ? resp : req;
        if (s.headText == null) return;
        byte[] all = s.buf.toByteArray();
        int pos = 0;
        int he = indexOfAll(all, 0, CRLFCRLF);
        if (he >= 0) pos = he + 4;
        byte[] body = slice(all, pos, all.length);
        if (body.length > 0 && sink != null) sink.onHttp(isResponse, s.headText, body, body.length);
        s.buf.reset();
        s.clearMsg();
    }

    private static byte[] slice(byte[] a, int from, int to) {
        int n = Math.max(0, Math.min(to, a.length) - from);
        byte[] r = new byte[n];
        if (n > 0) System.arraycopy(a, from, r, 0, n);
        return r;
    }

    private static final byte[] CRLFCRLF = {'\r', '\n', '\r', '\n'};
    private static final byte[] CRLF = {'\r', '\n'};

    private static boolean looksHttp(String s, boolean isResponse) {
        if (s == null || s.length() < 5) return false;
        if (!isResponse) {
            return s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("PUT ")
                    || s.startsWith("DELETE ") || s.startsWith("HEAD ") || s.startsWith("PATCH ")
                    || s.startsWith("OPTIONS ") || s.startsWith("TRACE ") || s.startsWith("CONNECT ");
        }
        return s.startsWith("HTTP/");
    }

    private static int parseLen(String head) {
        String cl = HttpCodec.header(head, "Content-Length");
        if (cl == null || cl.isEmpty()) return -1;
        try { return Integer.parseInt(cl.trim()); } catch (Throwable t) { return -1; }
    }

    private static int indexOfAll(byte[] b, int from, byte[] pat) {
        outer:
        for (int i = Math.max(0, from); i + pat.length <= b.length; i++) {
            for (int k = 0; k < pat.length; k++) if (b[i + k] != pat[k]) continue outer;
            return i;
        }
        return -1;
    }

    /** chunked 结束的下标 */
    private static int chunkedEnd(byte[] b, int from) {
        int i = from;
        while (i < b.length) {
            int le = indexOfAll(b, i, CRLF);
            if (le < 0) return -1;
            String line = new String(b, i, le - i, Charset.forName("ISO-8859-1")).trim();
            int sc = line.indexOf(';');
            if (sc >= 0) line = line.substring(0, sc);
            int size;
            try { size = Integer.parseInt(line.trim(), 16); } catch (Throwable t) { return -1; }
            int start = le + 2;
            if (size == 0) {
                int crlf = indexOfAll(b, start, CRLF);
                if (crlf < 0) return -1;
                if (crlf == start) return start + 2;
                int end = indexOfAll(b, crlf + 2, CRLFCRLF);
                return end < 0 ? -1 : end + 4;
            }
            int next = start + size + 2;
            if (next > b.length) return -1;
            i = next;
        }
        return -1;
    }

    // ==================== WebSocket ====================
    private final ByteArrayOutputStream wsClient = new ByteArrayOutputStream(4096);
    private final ByteArrayOutputStream wsServer = new ByteArrayOutputStream(4096);

    private void feedWs(boolean isClient, byte[] data, int off, int len) {
        ByteArrayOutputStream buf = isClient ? wsClient : wsServer;
        if (buf.size() + len > MAX_WS * 8) buf.reset();
        buf.write(data, off, len);
        byte[] all = buf.toByteArray();
        int pos = 0;
        while (pos + 2 <= all.length) {
            int b0 = all[pos] & 0xff;
            int b1 = all[pos + 1] & 0xff;
            int opcode = b0 & 0x0f;
            boolean masked = (b1 & 0x80) != 0;
            long plen = b1 & 0x7f;
            int p = pos + 2;
            if (plen == 126) {
                if (p + 2 > all.length) break;
                plen = ((all[p] & 0xff) << 8) | (all[p + 1] & 0xff);
                p += 2;
            } else if (plen == 127) {
                if (p + 8 > all.length) break;
                plen = 0;
                for (int k = 0; k < 8; k++) plen = (plen << 8) | (all[p + k] & 0xff);
                p += 8;
            }
            byte[] mask = new byte[4];
            if (masked) {
                if (p + 4 > all.length) break;
                System.arraycopy(all, p, mask, 0, 4);
                p += 4;
            }
            if (plen > MAX_WS) {
                buf.reset();
                if (sink != null) sink.onNote("WebSocket 帧超过 " + HttpCodec.humanSize(MAX_WS) + "，已跳过");
                return;
            }
            if (p + plen > all.length) break;
            byte[] payload = new byte[(int) plen];
            System.arraycopy(all, p, payload, 0, (int) plen);
            if (masked) for (int k = 0; k < payload.length; k++) payload[k] ^= mask[k & 3];
            if (sink != null) sink.onWs(isClient, opcode, payload, payload.length);
            pos = p + (int) plen;
        }
        byte[] remain = new byte[Math.max(0, all.length - pos)];
        if (remain.length > 0) System.arraycopy(all, pos, remain, 0, remain.length);
        buf.reset();
        if (remain.length > 0) buf.write(remain, 0, remain.length);
    }
}
