package com.lingqiong.buddy;

import android.net.VpnService;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * [v141] 改包重发：把用户编辑过的请求头 / 请求体真正发出去，并把响应带回来。
 *
 * 和原来的「重放」区别：
 *   原来 —— GET 丢给浏览器，其它拼一条 curl 让人自己去终端粘，等于没做。
 *   现在 —— 本机直接发请求，头、体、方法、路径都能改，发完立刻看响应头和响应体。
 *
 * 两个关键点：
 *   ① service.protect(socket)：不 protect 的话请求会被自己的 VPN 抓走，形成死循环。
 *   ② 信任所有证书：重发是调试自己的流量，目标站点证书链未必装在本机，
 *      这里刻意放宽。只用于本地回显，不做任何校验决策。
 */
public class CaptureReplay {

    private static final int MAX_RESP = 16 * 1024 * 1024;

    /** 信任所有证书的 TrustManager（仅用于重发调试）。 */
    private static TrustManager[] trustAll() {
        return new TrustManager[]{new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
    }

    /**
     * 发一条 HTTP(S) 请求。
     *
     * @param hostHint  目标主机（head 里没有 Host 头时用；可为空）
     * @param head      完整请求头（第一行 METHOD PATH HTTP/1.1，以空行结束）
     * @param bodyB64   请求体 base64，可为空
     * @param timeoutMs 超时
     * @return JSON：{ok, status, head, body, bodyB64, len, ms, error, reqBytes}
     */
    public static String send(String hostHint, String head, String bodyB64, int timeoutMs) {
        JSONObject out = new JSONObject();
        long t0 = System.currentTimeMillis();
        Socket sock = null;
        try {
            if (head == null || head.trim().isEmpty()) {
                out.put("ok", false); out.put("error", "请求头是空的");
                return out.toString();
            }
            if (timeoutMs <= 0) timeoutMs = 20000;

            // ① 规整请求头：保证以 \r\n 结尾并带一个空行
            String h = head.replace("\r\n", "\n").replace("\n", "\r\n");
            if (!h.endsWith("\r\n\r\n")) {
                if (!h.endsWith("\r\n")) h += "\r\n";
                h += "\r\n";
            }

            // ② 解析请求行
            int nl = h.indexOf("\r\n");
            String firstLine = nl > 0 ? h.substring(0, nl) : h;
            String[] parts = firstLine.split(" ");
            if (parts.length < 2) {
                out.put("ok", false); out.put("error", "请求行解析失败：" + firstLine);
                return out.toString();
            }
            String method = parts[0];
            String target = parts[1];

            // ③ 目标主机与端口
            String host = headerValue(h, "Host");
            if (host == null || host.trim().isEmpty()) host = hostHint;
            if (host == null || host.trim().isEmpty()) {
                out.put("ok", false); out.put("error", "缺少 Host，无法确定目标主机");
                return out.toString();
            }
            host = host.trim();
            boolean tls = true;
            int port = 443;
            int c = host.lastIndexOf(':');
            if (c > 0 && host.indexOf(']') < c) {
                try { port = Integer.parseInt(host.substring(c + 1)); } catch (Throwable ignore) {}
                host = host.substring(0, c);
            }
            // 绝对 URL 形式（http://host/path）
            String path = target;
            if (target.startsWith("http://")) { tls = false; port = 80; path = stripScheme(target); }
            else if (target.startsWith("https://")) { tls = true; path = stripScheme(target); }
            if (port == 80) tls = false;

            byte[] body = (bodyB64 == null || bodyB64.isEmpty())
                    ? new byte[0] : LqIntercept.unb64(bodyB64);

            // ④ 建连接
            sock = new Socket();
            VpnService vpn = CaptureVpnService.vpn();
            try { if (vpn != null) vpn.protect(sock); } catch (Throwable ignore) {}
            sock.setTcpNoDelay(true);
            sock.connect(new InetSocketAddress(host, port), timeoutMs);
            sock.setSoTimeout(timeoutMs);

            Socket io = sock;
            if (tls) {
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(null, trustAll(), new java.security.SecureRandom());
                SSLSocket ss = (SSLSocket) ctx.getSocketFactory().createSocket(sock, host, port, true);
                try {
                    SSLParameters p = ss.getSSLParameters();
                    p.setServerNames(java.util.Collections.singletonList(new SNIHostName(host)));
                    try { p.setApplicationProtocols(new String[]{"http/1.1"}); } catch (Throwable ignore) {}
                    ss.setSSLParameters(p);
                } catch (Throwable ignore) {}
                ss.startHandshake();
                io = ss;
            }

            // ⑤ 写请求（头 + 体）
            OutputStream os = io.getOutputStream();
            os.write(h.getBytes(StandardCharsets.ISO_8859_1));
            if (body.length > 0) os.write(body);
            os.flush();

            // ⑥ 读响应（按完整 HTTP 消息边界）
            InputStream in = io.getInputStream();
            ByteArrayOutputStream acc = new ByteArrayOutputStream(8192);
            byte[] buf = new byte[16384];
            int total = 0;
            String respHead = null;
            byte[] respBody = new byte[0];
            long deadline = System.currentTimeMillis() + timeoutMs;
            while (System.currentTimeMillis() < deadline) {
                int n;
                try { n = in.read(buf); } catch (Throwable t) { break; }
                if (n <= 0) break;
                total += n;
                if (total > MAX_RESP) break;
                acc.write(buf, 0, n);
                byte[] a = acc.toByteArray();
                int cl = LqIntercept.completeLen(a, a.length, true);
                if (cl >= 0) {
                    int he = LqIntercept.headEnd(a);
                    if (he > 0) {
                        respHead = new String(a, 0, he, StandardCharsets.ISO_8859_1);
                        int blen = Math.min(cl, a.length) - he;
                        if (blen > 0) {
                            respBody = new byte[blen];
                            System.arraycopy(a, he, respBody, 0, blen);
                        }
                    }
                    break;
                }
                if (cl == LqIntercept.NOT_HTTP || cl == LqIntercept.STREAM_THROUGH) break;
            }
            if (respHead == null) {
                byte[] a = acc.toByteArray();
                int he = LqIntercept.headEnd(a);
                if (he > 0) {
                    respHead = new String(a, 0, he, StandardCharsets.ISO_8859_1);
                    int blen = a.length - he;
                    if (blen > 0) { respBody = new byte[blen]; System.arraycopy(a, he, respBody, 0, blen); }
                } else if (a.length > 0) {
                    respHead = new String(a, 0, Math.min(a.length, 2048), StandardCharsets.ISO_8859_1);
                }
            }

            String status = "";
            if (respHead != null) {
                int sp = respHead.indexOf(' ');
                if (sp > 0) {
                    int sp2 = respHead.indexOf(' ', sp + 1);
                    status = sp2 > 0 ? respHead.substring(sp + 1, sp2) : respHead.substring(sp + 1).trim();
                }
            }

            out.put("ok", respHead != null);
            out.put("status", status);
            out.put("head", respHead == null ? "" : respHead);
            out.put("len", respBody.length);
            out.put("body", new String(respBody, StandardCharsets.UTF_8));
            out.put("bodyB64", LqIntercept.b64(respBody));
            out.put("reqBytes", h.getBytes(StandardCharsets.ISO_8859_1).length + body.length);
            out.put("ms", System.currentTimeMillis() - t0);
            out.put("target", (tls ? "https://" : "http://") + host + (port == 443 || port == 80 ? "" : ":" + port) + path);
            if (respHead == null) out.put("error", "没收到响应（超时或被拒绝）");
            return out.toString();
        } catch (Throwable t) {
            try {
                out.put("ok", false);
                out.put("error", t.getClass().getSimpleName() + " · " + t.getMessage());
                out.put("ms", System.currentTimeMillis() - t0);
            } catch (Throwable ignore) {}
            return out.toString();
        } finally {
            try { if (sock != null) sock.close(); } catch (Throwable ignore) {}
        }
    }

    private static String stripScheme(String url) {
        int i = url.indexOf("://");
        if (i < 0) return url;
        String rest = url.substring(i + 3);
        int slash = rest.indexOf('/');
        return slash < 0 ? "/" : rest.substring(slash);
    }

    private static String headerValue(String head, String name) {
        try {
            for (String ln : head.split("\r\n")) {
                int c = ln.indexOf(':');
                if (c <= 0) continue;
                if (ln.substring(0, c).trim().equalsIgnoreCase(name)) return ln.substring(c + 1).trim();
            }
        } catch (Throwable ignore) {}
        return null;
    }
}
