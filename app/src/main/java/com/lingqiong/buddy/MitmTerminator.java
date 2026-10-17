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

    /* [v78] 解密失败的域名黑名单：命中后该域名不再尝试 MITM，直接直连透传。
       这是「解密失败就断网」的根治办法 —— App 至少能正常上网，只是看不到明文。 */
    private static final java.util.Set<String> FAILED_HOSTS =
            java.util.Collections.synchronizedSet(new java.util.HashSet<String>());

    public static boolean isBlacklisted(String host) {
        if (host == null || host.isEmpty()) return false;
        return FAILED_HOSTS.contains(host);
    }

    public static void blacklist(String host) {
        if (host != null && !host.isEmpty()) FAILED_HOSTS.add(host);
    }

    public static void clearBlacklist() { FAILED_HOSTS.clear(); }

    /* [v78] pump 引用计数：两个方向都结束才真正 close。
       旧版任一方结束就 close 全部，另一线程正在 write 已关闭的 socket → SocketException 刷屏。 */
    private final java.util.concurrent.atomic.AtomicInteger pumpAlive =
            new java.util.concurrent.atomic.AtomicInteger(2);

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

            /* [v78] 服务器握手不再 try{}catch(ignore){} —— 吞掉它会让后续所有 write 抛
               SocketException，表现为「解密转发失败: SocketException」刷屏。 */
            try {
                serverSide.startHandshake();
            } catch (Throwable hs) {
                String why = (hs.getMessage() != null ? hs.getMessage() : hs.getClass().getSimpleName());
                if (record != null) {
                    CaptureStore.addLog(record, "✗ 与真实服务器 TLS 握手失败：" + why);
                }
                blacklist(host);   // 该域名以后直接直连，不再折腾
                close();
                return;
            }

            if (record != null) CaptureStore.addLog(record, "🔓 HTTPS 已解密（" + host + "）");

            Thread t1 = new Thread(new Runnable() { public void run() { pump(clientSide, serverSide, true); } }, "mitm-c2s");
            Thread t2 = new Thread(new Runnable() { public void run() { pump(serverSide, clientSide, false); } }, "mitm-s2c");
            t1.setDaemon(true); t2.setDaemon(true);
            t1.start(); t2.start();
        } catch (Throwable t) {
            if (record != null) {
                String why = (t.getMessage() != null ? t.getMessage() : "");
                /* 客户端握手失败 = 对方不认我们的 CA（证书固定 / App 没重开） */
                boolean clientReject = (t instanceof javax.net.ssl.SSLException)
                        || t.getClass().getName().contains("SSL")
                        || why.toLowerCase().contains("certificate")
                        || why.toLowerCase().contains("handshake");
                if (clientReject) {
                    CaptureStore.addLog(record, "✗ 客户端拒绝我们的证书（该 App 可能启用了证书固定，或装完证书后没重开它）");
                    blacklist(host);
                } else {
                    CaptureStore.addLog(record, "✗ 解密失败: " + t.getClass().getSimpleName()
                            + (why.isEmpty() ? "" : " " + why));
                }
            }
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
                /* [v77] 关键修复：解密后的明文必须真正进采集缓冲。
                   旧版只在这里 logPlain（截 2048 字、取首行 + trim 400），
                   导致 reqHead/respHead/reqBody/respBody 永远为空 —— 这就是
                   「根本看不到请求头/请求体」的直接原因。 */
                try {
                    if (isRequest) CaptureStore.feedReq(record, buf, 0, n);
                    else CaptureStore.feedResp(record, buf, 0, n);
                } catch (Throwable ignore) {}
                logPlain(buf, n, isRequest);
                out.write(buf, 0, n);
                out.flush();
                /* [v77] 实时切分：keep-alive 长连接不关闭也能立刻看到内容 */
                try { CaptureStore.flushPartial(record); } catch (Throwable ignore) {}
            }
        } catch (Throwable e) {
            /* [v78] 区分「正常收尾」和「真出错」，不再一律静默。
               只有真异常才记一笔，且写明方向，方便判断是客户端断还是服务器断。 */
            String m = (e.getMessage() != null ? e.getMessage() : "");
            boolean benign = (e instanceof java.net.SocketException)
                    && (m.contains("Socket closed") || m.contains("Broken pipe")
                        || m.contains("Connection reset") || m.contains("EOF"));
            if (!benign && record != null) {
                try {
                    CaptureStore.addLog(record, "✗ " + (isRequest ? "上行" : "下行") + "转发中断: "
                            + e.getClass().getSimpleName() + (m.isEmpty() ? "" : " " + m));
                } catch (Throwable ignore2) {}
            }
        } finally {
            /* [v78] 引用计数：只有两个方向都结束才真正 close，
               否则另一线程正在 write 已关闭的 socket 会刷 SocketException。 */
            if (pumpAlive.decrementAndGet() <= 0) close();
        }
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
        if (closed) return;
        closed = true;
        /* [v77] 连接结束：把缓冲里剩余内容最终切分落库 */
        try { CaptureStore.finish(record); } catch (Throwable ignore) {}
        try { if (clientSide != null) clientSide.close(); } catch (Throwable ignore) {}
        try { if (serverSide != null) serverSide.close(); } catch (Throwable ignore) {}
        try { if (serverSocket != null) serverSocket.close(); } catch (Throwable ignore) {}
    }
}
