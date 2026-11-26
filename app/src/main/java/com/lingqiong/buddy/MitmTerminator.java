package com.lingqiong.buddy;

import android.net.VpnService;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * [v28] 单个 HTTPS 连接的 TLS 中间人终结器。
 *
 * 原理：
 *   客户端 <--TLS--> 本终结器(冒充服务器, 用本机 CA 签发的证书) <--TLS--> 真实服务器
 *   两段 TLS 都在此终结，中间明文 HTTP 被完整记录 —— 这就是「解密 HTTPS」。
 *
 * 实现：用标准库 SSLServerSocket / SSLSocket（而非手写 SSLEngine 状态机），
 *       把复杂的 TLS 握手交给 JDK，稳定可靠。
 *
 * 数据流：
 *   CaptureEngine 把客户端密文写进本地端口 → clientSide 解密为明文 →
 *   记录 → serverSide 加密发往真实服务器；反向同理。
 */
public class MitmTerminator {

    private final MitmCa ca;
    private final String host;
    private final byte[] realIp;
    private final int realPort;
    private final CaptureStore.Entry record;
    private final VpnService service;
    private final HttpSession hs;      // [v83] 明文交给它拼包解码

    private SSLServerSocket serverSocket;
    private SSLSocket clientSide;   // 与客户端（服务端角色）
    private SSLSocket serverSide;   // 与真实服务器（客户端角色）
    private volatile boolean closed = false;
    private volatile boolean sniffed = false;   // [v128] 明文类型只嗅探一次

    public MitmTerminator(MitmCa ca, String host, byte[] realIp, int realPort,
                          CaptureStore.Entry record, VpnService service, HttpSession hs) {
        this.ca = ca;
        this.host = host;
        this.realIp = realIp;
        this.realPort = realPort;
        this.record = record;
        this.service = service;
        this.hs = hs;
    }

    /** 启动本地 TLS 监听，返回端口号，供上层把客户端密文转过来。 */
    public int start() throws Exception {
        SSLServerSocket ss = (SSLServerSocket) ca.serverContext(host).getServerSocketFactory()
                .createServerSocket(0, 4, InetAddress.getByName("127.0.0.1"));
        ss.setNeedClientAuth(false);
        /* [v128] 强制 ALPN = http/1.1。
           不设的话客户端会挑 h2，之后传的是 HTTP/2 二进制帧，
           HttpSession 的 HTTP/1.x 文本解析会全部失败 —— 这就是
           「TLS 解密成功但正文一片空白」的真正原因。 */
        try { applyAlpn(ss); } catch (Throwable ignore) {}
        serverSocket = ss;
        Thread t = new Thread(new Runnable() { public void run() { acceptLoop(); } }, "mitm-accept");
        t.setDaemon(true);
        t.start();
        return ss.getLocalPort();
    }

    private void acceptLoop() {
        try {
            clientSide = (SSLSocket) serverSocket.accept();
            /* [v129] 与客户端握手失败时，把原因说清楚 ——
               绝大多数情况是目标 App 启用了证书固定（微信/银行/部分游戏），
               系统信任库里有本机 CA 也没用。 */
            try { clientSide.startHandshake(); }
            catch (Throwable th) {
                /* [v131] 记录【完整】异常：类名 + message。
                   原来只按关键字归类，把「证书链构建失败（trust anchor not found）」
                   这种真 bug 也说成「App 启用了证书固定」，把排查方向带偏。 */
                String cls = th.getClass().getName();
                String msg2 = String.valueOf(th.getMessage() == null ? "" : th.getMessage());
                String full = cls + (msg2.isEmpty() ? "" : " · " + msg2);
                String why;
                if (msg2.contains("Trust anchor") || msg2.contains("trust anchor")
                        || msg2.contains("CertPathValidator") || msg2.contains("PKIX")) {
                    /* 这是我们自己签发的证书链有问题，不是对方证书固定 */
                    why = "证书链不被信任（trust anchor 找不到）→ " + full;
                } else if (msg2.contains("certificate") || msg2.contains("Certificate")
                        || msg2.contains("trust") || msg2.contains("Trust")) {
                    why = "目标 App 拒绝本机 CA（多为证书固定）→ " + full;
                } else if (msg2.contains("protocol") || msg2.contains("Protocol")) {
                    why = "TLS 协议版本不匹配 → " + full;
                } else {
                    why = full;
                }
                try { CaptureStore.addLog(record, "✗ 与客户端 TLS 握手失败：" + why); } catch (Throwable ig) {}
                /* [v131] 把 host 加入黑名单：后续同 host 直连透传，不再重复失败、不再让 App 断网 */
                try { CaptureEngine.markMitmFailed(host); } catch (Throwable ig) {}
                close();
                return;
            }
            clientSide.setUseClientMode(false);

            // 连接真实服务器（再套一层 TLS）
            Socket raw = new Socket();
            raw.setTcpNoDelay(true);
            try { if (service != null) service.protect(raw); } catch (Throwable ignore) {}
            raw.connect(new InetSocketAddress(InetAddress.getByAddress(realIp), realPort), 15000);
            SSLSocketFactory f = ca.clientContext().getSocketFactory();
            serverSide = (SSLSocket) f.createSocket(raw, host, realPort, true);
            serverSide.setUseClientMode(true);
            try { applyAlpn(serverSide); } catch (Throwable ignore) {}
            try { serverSide.startHandshake(); }
            catch (Throwable t) {
                /* [v129] 不再静默：连真实服务器失败要说明白 */
                String m = t.getClass().getName() + (t.getMessage() == null ? "" : " · " + t.getMessage());
                try { CaptureStore.addLog(record, "✗ 连真实服务器失败：" + m); } catch (Throwable ig) {}
                try { CaptureEngine.markMitmFailed(host); } catch (Throwable ig) {}
            }

            if (record != null) CaptureStore.addLog(record, "🔓 HTTPS 已解密（" + host + "）");

            Thread t1 = new Thread(new Runnable() { public void run() { pump(clientSide, serverSide, true); } }, "mitm-c2s");
            Thread t2 = new Thread(new Runnable() { public void run() { pump(serverSide, clientSide, false); } }, "mitm-s2c");
            t1.setDaemon(true); t2.setDaemon(true);
            t1.start(); t2.start();
        } catch (Throwable t) {
            String err = CaptureEngine.classifyErr(t, "解密");
            if (record != null) {
                CaptureStore.setError(record, err);
                CaptureStore.addLog(record, "✗ " + err);
            }
            close();
        }
    }

    /**
     * [v128] 只协商 http/1.1。
     * API 29+ 才有可用的 ALPN setter；更低版本直接跳过（保持旧行为）。
     */
    private static void applyAlpn(SSLSocket sock) {
        try {
            if (android.os.Build.VERSION.SDK_INT < 29) return;
            SSLParameters sp = sock.getSSLParameters();
            sp.setApplicationProtocols(new String[]{"http/1.1"});
            sock.setSSLParameters(sp);
        } catch (Throwable ignore) {}
    }

    /** SSLServerSocket 与 SSLSocket 没有共同父接口，只能各写一个重载。 */
    private static void applyAlpn(SSLServerSocket sock) {
        try {
            if (android.os.Build.VERSION.SDK_INT < 29) return;
            SSLParameters sp = sock.getSSLParameters();
            sp.setApplicationProtocols(new String[]{"http/1.1"});
            sock.setSSLParameters(sp);
        } catch (Throwable ignore) {}
    }

    /**
     * [v128] 明文嗅探：判断解密后第一段数据到底是哪种协议。
     * 结果写进日志，用户能立刻看出「解没解开、卡在哪一步」，
     * 而不是只看到一条「已解密」然后一片空白。
     */
    private void sniffPlain(byte[] buf, int n, boolean isRequest) {
        if (record == null || n <= 0) return;
        if (sniffed) return;
        sniffed = true;
        String kind;
        if (startsWith(buf, n, "PRI * HTTP/2.0")) {
            kind = "HTTP/2（二进制帧）";
            if (record != null) record.httpVersion = 20;
        } else if (startsWith(buf, n, "GET ") || startsWith(buf, n, "POST ")
                || startsWith(buf, n, "PUT ") || startsWith(buf, n, "HEAD ")
                || startsWith(buf, n, "DELETE ") || startsWith(buf, n, "OPTIONS ")
                || startsWith(buf, n, "PATCH ") || startsWith(buf, n, "HTTP/")) {
            kind = "HTTP/1.x（文本）";
            if (record != null && record.httpVersion == 0) record.httpVersion = 11;
        } else if ((buf[0] & 0xff) == 0x16 || (buf[0] & 0xff) == 0x17) {
            kind = "仍是 TLS 密文（握手没在本机终结）";
        } else {
            kind = "无法识别的协议（首字节 0x" + String.format("%02X", buf[0] & 0xff) + "）";
        }
        CaptureStore.addLog(record, "🔍 明文协议：" + kind);
        if (kind.startsWith("HTTP/2")) {
            CaptureStore.addLog(record, "⚠ 这条走了 HTTP/2，正文是二进制帧。"
                    + "已尝试降级到 HTTP/1.1；若仍为空，说明该 App 强制 h2，换用其他接口或 App 内关闭 HTTP/2 后再试。");
        }
    }

    private static boolean startsWith(byte[] b, int n, String s) {
        byte[] t = s.getBytes(StandardCharsets.ISO_8859_1);
        if (n < t.length) return false;
        for (int i = 0; i < t.length; i++) if (b[i] != t[i]) return false;
        return true;
    }

    private void pump(SSLSocket from, SSLSocket to, boolean isRequest) {
        byte[] buf = new byte[16384];
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            int n;
            while (!closed && (n = in.read(buf)) > 0) {
                try { sniffPlain(buf, n, isRequest); } catch (Throwable ignore) {}
                // [v83] 明文完整交给拼包层解码（旧版只截前 2KB 转字符串就丢）
                if (hs != null) {
                    try {
                        if (isRequest) hs.onClient(buf, 0, n);
                        else hs.onServer(buf, 0, n);
                    } catch (Throwable ignore) {}
                }
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (Throwable ignore) {}
        close();
    }

    private void logPlain(byte[] buf, int n, boolean isRequest) {
        if (record == null) return;
        try {
            int cap = Math.min(n, 2048);
            String s = new String(buf, 0, cap, StandardCharsets.UTF_8);
            int nl = s.indexOf("\r\n");
            String first = nl > 0 ? s.substring(0, nl) : s;
            int bi = s.indexOf("\r\n\r\n");
            if (isRequest) {
                CaptureStore.addLog(record, "→ [明文] " + first);
                if (bi >= 0 && bi + 4 < s.length()) {
                    String body = s.substring(bi + 4);
                    if (!body.isEmpty()) CaptureStore.addLog(record, "   请求体: " + trim(body));
                }
            } else {
                if (first.startsWith("HTTP/")) CaptureStore.addLog(record, "← [明文] " + first);
                if (bi >= 0 && bi + 4 < s.length()) {
                    String body = s.substring(bi + 4);
                    if (!body.isEmpty()) CaptureStore.addLog(record, "   响应体: " + trim(body));
                }
            }
        } catch (Throwable ignore) {}
    }

    private static String trim(String s) {
        s = s.replace("\r", "").replace("\n", "\\n");
        return s.length() > 400 ? s.substring(0, 400) + " …" : s;
    }

    public void close() {
        closed = true;
        try { if (clientSide != null) clientSide.close(); } catch (Throwable ignore) {}
        try { if (serverSide != null) serverSide.close(); } catch (Throwable ignore) {}
        try { if (serverSocket != null) serverSocket.close(); } catch (Throwable ignore) {}
    }
}
