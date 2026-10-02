package com.lingqiong.buddy;

import android.net.VpnService;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

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

    private SSLServerSocket serverSocket;
    private SSLSocket clientSide;   // 与客户端（服务端角色）
    private SSLSocket serverSide;   // 与真实服务器（客户端角色）
    private volatile boolean closed = false;

    public MitmTerminator(MitmCa ca, String host, byte[] realIp, int realPort,
                          CaptureStore.Entry record, VpnService service) {
        this.ca = ca;
        this.host = host;
        this.realIp = realIp;
        this.realPort = realPort;
        this.record = record;
        this.service = service;
    }

    /** 启动本地 TLS 监听，返回端口号，供上层把客户端密文转过来。 */
    public int start() throws Exception {
        SSLServerSocket ss = (SSLServerSocket) ca.serverContext(host).getServerSocketFactory()
                .createServerSocket(0, 4, InetAddress.getByName("127.0.0.1"));
        ss.setNeedClientAuth(false);
        serverSocket = ss;
        Thread t = new Thread(new Runnable() { public void run() { acceptLoop(); } }, "mitm-accept");
        t.setDaemon(true);
        t.start();
        return ss.getLocalPort();
    }

    private void acceptLoop() {
        try {
            clientSide = (SSLSocket) serverSocket.accept();
            clientSide.setUseClientMode(false);

            // 连接真实服务器（再套一层 TLS）
            Socket raw = new Socket();
            raw.setTcpNoDelay(true);
            try { if (service != null) service.protect(raw); } catch (Throwable ignore) {}
            raw.connect(new InetSocketAddress(InetAddress.getByAddress(realIp), realPort), 15000);
            SSLSocketFactory f = ca.clientContext().getSocketFactory();
            serverSide = (SSLSocket) f.createSocket(raw, host, realPort, true);
            serverSide.setUseClientMode(true);
            try { serverSide.startHandshake(); } catch (Throwable ignore) {}

            if (record != null) CaptureStore.addLog(record, "🔓 HTTPS 已解密（" + host + "）");

            Thread t1 = new Thread(new Runnable() { public void run() { pump(clientSide, serverSide, true); } }, "mitm-c2s");
            Thread t2 = new Thread(new Runnable() { public void run() { pump(serverSide, clientSide, false); } }, "mitm-s2c");
            t1.setDaemon(true); t2.setDaemon(true);
            t1.start(); t2.start();
        } catch (Throwable t) {
            if (record != null) CaptureStore.addLog(record, "✗ 解密失败: " + t.getClass().getSimpleName()
                    + (t.getMessage() != null ? " " + t.getMessage() : ""));
            close();
        }
    }

    private void pump(SSLSocket from, SSLSocket to, boolean isRequest) {
        byte[] buf = new byte[16384];
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            int n;
            while (!closed && (n = in.read(buf)) > 0) {
                logPlain(buf, n, isRequest);
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
