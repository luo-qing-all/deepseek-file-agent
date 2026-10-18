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
        /* [v80] 明确启用 TLS1.2/1.3：不同 ROM 默认协议集不一致，
           不显式设置时可能只启用 1.2 或包含被废弃的版本。 */
        try {
            java.util.List<String> ok = new java.util.ArrayList<String>();
            for (String pr : ss.getSupportedProtocols()) {
                if ("TLSv1.2".equals(pr) || "TLSv1.3".equals(pr)) ok.add(pr);
            }
            if (!ok.isEmpty()) ss.setEnabledProtocols(ok.toArray(new String[0]));
        } catch (Throwable ignoreTls) {}
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
            /* [v79] 给客户端握手设超时，避免 App 不握手时线程永久阻塞 */
            try { clientSide.setSoTimeout(15000); } catch (Throwable ignore0) {}
            applyTls(clientSide);

            /* ===== [v80] 核心修复：并行建连 =====
               旧版是串行：accept → connect 真实服务器(最长 15s) → 服务器握手 → 才回客户端 ServerHello。
               真实服务器一慢（或跨境/被限速），客户端 1 秒内等不到 ServerHello 就【重传 ClientHello】，
               重传的 ClientHello 再被喂进已经握手的 SSLSocket → UNEXPECTED_MESSAGE；
               某些情况下客户端还会收到错位数据 → WRONG_VERSION_NUMBER。

               现在改成：连真实服务器放到后台线程，本线程【立刻】跟客户端握手。
               客户端马上拿到 ServerHello，就不会重传了。 */
            final Throwable[] srvErr = new Throwable[1];
            Thread tConn = new Thread(new Runnable() {
                public void run() {
                    try {
                        Socket raw = new Socket();
                        raw.setTcpNoDelay(true);
                        try { if (service != null) service.protect(raw); } catch (Throwable ignore) {}
                        raw.connect(new InetSocketAddress(InetAddress.getByAddress(realIp), realPort), 12000);
                        SSLSocketFactory f = ca.clientContext().getSocketFactory();
                        SSLSocket ss2 = (SSLSocket) f.createSocket(raw, host, realPort, true);
                        ss2.setUseClientMode(true);
                        applyTls(ss2);
                        ss2.startHandshake();
                        serverSide = ss2;
                    } catch (Throwable e) {
                        srvErr[0] = e;
                    }
                }
            }, "mitm-conn");
            tConn.setDaemon(true);
            tConn.start();

            /* ---- 客户端这一段握手：不等真实服务器，立刻做 ---- */
            try {
                clientSide.startHandshake();
            } catch (Throwable chs) {
                String why = (chs.getMessage() != null ? chs.getMessage() : chs.getClass().getSimpleName());
                boolean certReject = why.contains("CERTIFICATE_UNKNOWN")
                        || why.contains("certificate_unknown")
                        || why.contains("ALERT_CERTIFICATE")
                        || why.toLowerCase().contains("certificate unknown")
                        || why.contains("bad_certificate")
                        || why.contains("unknown_ca");
                boolean dupHello = why.contains("UNEXPECTED_MESSAGE") || why.contains("WRONG_VERSION_NUMBER");
                if (record != null) {
                    if (certReject) {
                        CaptureStore.addLog(record,
                                "✗ 该 App 拒绝我们的证书 —— 多半启用了证书固定（pinning），"
                                + "或装完证书后没把它从后台彻底划掉重开");
                        blacklist(host);   /* 证书固定是无解的，拉黑避免反复折腾 */
                    } else if (dupHello) {
                        /* [v80] 这类错误几乎都是「客户端重传了 ClientHello」，
                           不是证书问题，绝不能拉黑（否则这个域名永远看不了明文）。 */
                        CaptureStore.addLog(record, "✗ 客户端握手异常（多为 ClientHello 重传）：" + why);
                    } else {
                        CaptureStore.addLog(record, "✗ 客户端 TLS 握手失败：" + why);
                    }
                }
                close();
                return;
            }

            /* [v80] 握手已完成 → 关掉 15 秒超时。
               否则 keep-alive 连接空闲 15s 后 read 抛 SocketTimeoutException，
               pump 退出 → 连接被误杀（长连接/长轮询必踩）。 */
            try { clientSide.setSoTimeout(0); } catch (Throwable ignore1) {}

            /* ---- 等真实服务器那一段 ---- */
            try { tConn.join(13000); } catch (Throwable ignore2) {}
            if (serverSide == null) {
                Throwable e = srvErr[0];
                String why = (e == null) ? "连接超时"
                        : ((e.getMessage() != null) ? e.getMessage() : e.getClass().getSimpleName());
                if (record != null) {
                    CaptureStore.addLog(record, "✗ 连不上真实服务器：" + why
                            + "（本次未解密；不是证书问题，下次可能成功）");
                }
                /* [v80] 这里【不拉黑】：连不上是网络/服务器临时问题，
                   拉黑会让这个域名以后永远无法解密。 */
                close();
                return;
            }

            /* 两段握手都成功 → 这次是真的能解密，才可以说「已解密」 */
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

    /** [v80] 统一 TLS 参数：只启用 TLS1.2 / TLS1.3，让握手行为可预测。 */
    private static void applyTls(SSLSocket s) {
        try {
            java.util.List<String> ok = new java.util.ArrayList<String>();
            for (String pr : s.getSupportedProtocols()) {
                if ("TLSv1.2".equals(pr) || "TLSv1.3".equals(pr)) ok.add(pr);
            }
            if (!ok.isEmpty()) s.setEnabledProtocols(ok.toArray(new String[0]));
        } catch (Throwable ignore) {}
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
                    boolean certReject = m.contains("CERTIFICATE_UNKNOWN")
                            || m.contains("certificate_unknown")
                            || m.contains("ALERT_CERTIFICATE")
                            || m.contains("bad_certificate")
                            || m.contains("unknown_ca");
                    if (certReject) {
                        /* 长连接跑到一半被 App 拒绝（有些 App 只对特定请求做校验） */
                        CaptureStore.addLog(record,
                                "✗ 该 App 拒绝我们的证书（证书固定 / 装完没重开）—— 后续该域名改为直连");
                        blacklist(host);
                    } else {
                        CaptureStore.addLog(record, "✗ " + (isRequest ? "上行" : "下行") + "转发中断: "
                                + e.getClass().getSimpleName() + (m.isEmpty() ? "" : " " + m));
                    }
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
