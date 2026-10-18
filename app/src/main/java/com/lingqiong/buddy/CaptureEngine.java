package com.lingqiong.buddy;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

/**
 * [v27] 抓包引擎（纯 Java 用户态转发）。
 *
 * 流程：从 TUN 读原始 IPv4 包 → 解析 TCP/UDP → 用真实 socket 转发到目标 →
 *       把响应重新封装成 IP 包写回 TUN；同时记录连接 / HTTP / 域名(SNI/DNS) 信息。
 *
 * 说明：只处理 IPv4；HTTPS 正文为密文，仅能提取 SNI 域名（正文解密见后续阶段）。
 */
public class CaptureEngine implements Runnable {

    private final ParcelFileDescriptor tun;
    private final VpnService service;
    private final FileInputStream in;
    private final FileOutputStream out;
    private volatile boolean running = true;
    private final Object writeLock = new Object();

    private final ConcurrentHashMap<String, TcpConn> tcpConns = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, UdpConn> udpConns = new ConcurrentHashMap<>();

    // [v28] HTTPS 解密（MITM）
    private volatile MitmCa mitm = null;
    private volatile boolean decryptHttps = false;

    public void setMitm(MitmCa ca, boolean decrypt) { this.mitm = ca; this.decryptHttps = decrypt; }

    public CaptureEngine(ParcelFileDescriptor tun, VpnService service) {
        this.tun = tun;
        this.service = service;
        this.in = new FileInputStream(tun.getFileDescriptor());
        this.out = new FileOutputStream(tun.getFileDescriptor());
    }

    public void stop() { running = false; }

    @Override
    public void run() {
        byte[] buf = new byte[32767];
        while (running) {
            int len;
            try {
                len = in.read(buf);
            } catch (Throwable t) {
                break;
            }
            if (len <= 0) continue;
            try {
                handleIp(buf, len);
            } catch (Throwable ignore) {}
        }
        closeAll();
    }

    private void closeAll() {
        for (TcpConn c : tcpConns.values()) {
            try { c.closed = true; if (c.sock != null) c.sock.close(); } catch (Throwable ignore) {}
        }
        for (UdpConn c : udpConns.values()) {
            try { if (c.sock != null) c.sock.close(); } catch (Throwable ignore) {}
        }
        tcpConns.clear();
        udpConns.clear();
    }

    // ============================ IP 层 ============================
    private void handleIp(byte[] p, int len) {
        if (len < 20) return;
        int vihl = p[0] & 0xff;
        if ((vihl >> 4) != 4) return;              // 仅 IPv4
        int ihl = (vihl & 0x0f) * 4;
        if (ihl < 20 || len < ihl) return;
        int proto = p[9] & 0xff;
        byte[] srcIp = new byte[]{p[12], p[13], p[14], p[15]};
        byte[] dstIp = new byte[]{p[16], p[17], p[18], p[19]};
        if (proto == 6) handleTcp(p, len, ihl, srcIp, dstIp);
        else if (proto == 17) handleUdp(p, len, ihl, srcIp, dstIp);
    }

    // ============================ TCP ============================
    private void handleTcp(byte[] p, int len, int ihl, byte[] srcIp, byte[] dstIp) {
        if (len < ihl + 20) return;
        int t = ihl;
        int srcPort = ((p[t] & 0xff) << 8) | (p[t + 1] & 0xff);
        int dstPort = ((p[t + 2] & 0xff) << 8) | (p[t + 3] & 0xff);
        long seq = readU32(p, t + 4);
        int dataOff = ((p[t + 12] & 0xff) >> 4) * 4;
        if (dataOff < 20) dataOff = 20;
        int flags = p[t + 13] & 0xff;
        int payloadOff = t + dataOff;
        int payloadLen = len - payloadOff;
        if (payloadLen < 0) payloadLen = 0;

        boolean syn = (flags & 0x02) != 0;
        boolean ack = (flags & 0x10) != 0;
        boolean fin = (flags & 0x01) != 0;
        boolean rst = (flags & 0x04) != 0;

        String key = ipStr(srcIp) + ":" + srcPort + "->" + ipStr(dstIp) + ":" + dstPort;

        if (syn && !ack) {
            if (tcpConns.containsKey(key)) return;
            if (tcpConns.size() >= 1200) { // 防御：连接过多时直接 RST，避免内存/线程爆炸
                sendTcp(dstIp, srcIp, dstPort, srcPort, 0, (seq + 1) & 0xffffffffL, 0x14, null, 0);
                return;
            }
            final TcpConn c = new TcpConn(key, srcIp, dstIp, srcPort, dstPort);
            c.clientSeq = (seq + 1) & 0xffffffffL;
            c.mySeq = (long) (Math.random() * 1000000000L) + 1;
            c.record = CaptureStore.add("TCP", ipStr(srcIp) + ":" + srcPort, ipStr(dstIp) + ":" + dstPort);
            /* ===== [v80] 关键：在 SYN 这一层【同步】判定是否 MITM =====
               旧版把 mitmPending=true 放在 connectServer（新线程）里，
               而 SYN|ACK 也在那个线程里才发。于是：
                 · 客户端要等线程调度才收到 SYN|ACK
                 · ClientHello 若先到，mitmPending 还是 false → 走普通路径
                   → c.sout 为 null → ClientHello 被静默丢弃 → 握手必失败
               现在改为：这里就判定、这里就回 SYN|ACK，只有「直连」才交给线程。 */
            boolean doMitm = (mitm != null && decryptHttps && dstPort == 443);
            if (doMitm && c.record != null && c.record.host != null
                    && !c.record.host.isEmpty() && MitmTerminator.isBlacklisted(c.record.host)) {
                doMitm = false;
            }
            if (doMitm) c.mitmPending = true;
            tcpConns.put(key, c);
            sendTcp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, c.mySeq, c.clientSeq, 0x12, null, 0); // SYN|ACK
            c.mySeq = (c.mySeq + 1) & 0xffffffffL;
            if (!doMitm) {
                new Thread(new Runnable() { public void run() { connectServer(c); } }, "cap-tcp-conn").start();
            }
            return;
        }

        final TcpConn c = tcpConns.get(key);
        if (c == null) {
            // 未知连接：回 RST，避免客户端苦等
            sendTcp(dstIp, srcIp, dstPort, srcPort, 0, (seq + 1) & 0xffffffffL, 0x14, null, 0);
            return;
        }

        if (rst) { closeTcp(c); return; }

        if (payloadLen > 0) {
            c.clientSeq = (seq + payloadLen) & 0xffffffffL;
            onClientData(c, p, payloadOff, payloadLen);
            try {
                if (c.sout != null) { c.sout.write(p, payloadOff, payloadLen); c.sout.flush(); }
            } catch (Throwable ignore) {}
            if (c.record != null) c.record.up += payloadLen;
            sendTcp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, c.mySeq, c.clientSeq, 0x10, null, 0); // ACK
        }

        if (fin) {
            c.clientSeq = (c.clientSeq + 1) & 0xffffffffL;
            sendTcp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, c.mySeq, c.clientSeq, 0x11, null, 0); // FIN|ACK
            closeTcp(c);
        }
    }

    /** [v80] 只负责「直连真实服务器」；是否 MITM 已在 handleTcp 的 SYN 分支同步判定。 */
    private void connectServer(final TcpConn c) {
        try {
            Socket s = new Socket();
            s.setTcpNoDelay(true);
            try { if (service != null) service.protect(s); } catch (Throwable ignore) {}  // 关键：绕过 VPN，避免死循环
            s.connect(new InetSocketAddress(InetAddress.getByAddress(c.dstIp), c.dstPort), 15000);
            c.sock = s;
            c.sin = s.getInputStream();
            c.sout = s.getOutputStream();
            sendTcp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, c.mySeq, c.clientSeq, 0x12, null, 0); // SYN|ACK
            c.mySeq = (c.mySeq + 1) & 0xffffffffL;
            new Thread(new Runnable() { public void run() { readServer(c); } }, "cap-tcp-read").start();
        } catch (Throwable e) {
            sendTcp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, 0, c.clientSeq, 0x14, null, 0); // RST|ACK
            if (c.record != null) CaptureStore.addLog(c.record, "✗ 连接失败: " + e.getClass().getSimpleName());
            tcpConns.remove(c.key);
        }
    }

    private void readServer(final TcpConn c) {
        byte[] buf = new byte[16384];
        try {
            while (running && !c.closed) {
                int n = c.sin.read(buf);
                if (n < 0) break;
                onServerData(c, buf, 0, n);
                sendTcp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, c.mySeq, c.clientSeq, 0x18, buf, n); // PSH|ACK
                c.mySeq = (c.mySeq + n) & 0xffffffffL;
                if (c.record != null) c.record.down += n;
            }
        } catch (Throwable ignore) {}
        try {
            sendTcp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, c.mySeq, c.clientSeq, 0x11, null, 0); // FIN|ACK
            c.mySeq = (c.mySeq + 1) & 0xffffffffL;
        } catch (Throwable ignore) {}
        closeTcp(c);
    }

    private void closeTcp(TcpConn c) {
        if (c == null) return;
        c.closed = true;
        // [v71] 连接结束 → 把头/正文切分落库（这是「能看到具体内容」的关键一步）
        try { CaptureStore.finish(c.record); } catch (Throwable ignore) {}
        try { if (c.sock != null) c.sock.close(); } catch (Throwable ignore) {}
        try { if (c.mitmT != null) c.mitmT.close(); } catch (Throwable ignore) {}
        try { if (c.localSock != null) c.localSock.close(); } catch (Throwable ignore) {}
        tcpConns.remove(c.key);
    }

    // ============================ [v28] MITM 解密 ============================

    /** [v78] 纯 TCP 透传：不做 MITM，直接把密文原样转发。用于「解密失败过的域名」。 */
    private boolean directTunnel(TcpConn c, byte[] p, int off, int len) {
        try {
            Socket s = new Socket();
            s.setTcpNoDelay(true);
            try { if (service != null) service.protect(s); } catch (Throwable ignore) {}
            s.connect(new InetSocketAddress(InetAddress.getByAddress(c.dstIp), c.dstPort), 15000);
            c.sock = s;
            c.sin = s.getInputStream();
            c.sout = s.getOutputStream();
            c.mitmPending = false;
            c.mitmReady = false;
            sendTcp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, c.mySeq, c.clientSeq, 0x12, null, 0);
            c.mySeq = (c.mySeq + 1) & 0xffffffffL;
            new Thread(new Runnable() { public void run() { readServer(c); } }, "cap-tcp-read").start();
            if (len > 0 && c.sout != null) {
                c.sout.write(p, off, len);
                c.sout.flush();
                if (c.record != null) c.record.up += len;
            }
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    private void handleMitmClientData(TcpConn c, byte[] p, int off, int len) {
        try {
            if (c.mitmPending) {
                /* ===== [v80] 先缓冲到「完整的第一条 TLS record」再建 MITM =====
                   TLS1.3 的 ClientHello 常 1000+ 字节（带 PQ key_share 的更多），
                   会跨多个 TCP 段。旧版第一段到了就建 MITM：
                     · parseSni 在不完整数据上失败 → SNI 为空 → 用 IP 签证书
                     · 客户端随后报证书错误 / 握手异常
                   现在收全再建。 */
                if (c.hsBuf == null) c.hsBuf = new java.io.ByteArrayOutputStream(Math.max(len, 2048));
                if (c.hsBuf.size() + len <= 16384) {
                    c.hsBuf.write(p, off, len);
                }
                byte[] hsAll = c.hsBuf.toByteArray();
                int hsNeed = tlsRecordTotal(hsAll);
                if (hsNeed <= 0) {
                    /* 不是 TLS 记录开头（可能不是 HTTPS），放弃 MITM，原样透传 */
                    c.mitmPending = false;
                    c.hsBuf = null;
                    if (c.localOut != null) { c.localOut.write(p, off, len); c.localOut.flush(); }
                    return;
                }
                if (hsAll.length < hsNeed) {
                    return;   /* 还没收全，继续等下一段 */
                }
                c.hsBuf = null;
                p = hsAll;
                off = 0;
                len = hsNeed;   /* 只把完整 ClientHello 交给 MITM */

                String sni = parseSni(p, off, Math.min(len, 4096));
                if (sni == null || sni.isEmpty()) sni = (c.record != null && c.record.host != null && !c.record.host.isEmpty()) ? c.record.host : ipStr(c.dstIp);

                /* [v78] 这个域名以前解密失败过 → 本次直接纯 TCP 透传。
                   好处：App 能正常上网，只是这条看不到明文（总比断网强）。 */
                if (MitmTerminator.isBlacklisted(sni)) {
                    if (directTunnel(c, p, off, len)) {
                        if (c.record != null) CaptureStore.addLog(c.record,
                                "↪ " + sni + " 解密失败过，本次直连（App 正常上网，看不到明文）");
                        return;
                    }
                }

                c.mitmT = new MitmTerminator(mitm, sni, c.dstIp, c.dstPort, c.record, service);
                int port = c.mitmT.start();
                Socket ls = new Socket("127.0.0.1", port);
                ls.setTcpNoDelay(true);
                c.localSock = ls;
                c.localOut = ls.getOutputStream();
                c.mitmPending = false;
                c.mitmReady = true;
                new Thread(new Runnable() { public void run() { readLocal(c); } }, "cap-mitm-read").start();
            }
            if (c.localOut != null) {
                /* [v80] 丢弃「重传的 ClientHello」。
                   客户端等不到 ServerHello 时会重发 ClientHello；
                   已握手的 SSLSocket 再收到一个 ClientHello 会报
                   UNEXPECTED_MESSAGE / WRONG_VERSION_NUMBER。
                   只认 handshake type 0x01（ClientHello），
                   post-handshake 的 KeyUpdate(0x18) 等不能误伤。 */
                if (len >= 6 && (p[off] & 0xff) == 0x16 && (p[off + 1] & 0xff) == 0x03
                        && (p[off + 5] & 0xff) == 0x01) {
                    if (c.record != null) CaptureStore.addLog(c.record, "· 已丢弃重复的 ClientHello（客户端重传）");
                    return;
                }
                c.localOut.write(p, off, len);
                c.localOut.flush();
            }
        } catch (Throwable e) {
            /* [v78] 转发失败 → 记清楚 + 把该域名拉黑，下次直接直连，不再反复失败 */
            String hn = (c.record != null && c.record.host != null) ? c.record.host : "";
            if (hn.isEmpty() && c.record != null) hn = ipStr(c.dstIp);
            /* [v80] 旧版这里【无条件】拉黑：任何异常（端口占用、临时 IO 错、客户端提前断开）
               都会让该域名以后永远只能直连。现在只有「客户端拒绝证书」才拉黑。 */
            String em = (e.getMessage() != null ? e.getMessage() : "");
            boolean certReject = em.contains("CERTIFICATE_UNKNOWN") || em.contains("certificate_unknown")
                    || em.contains("bad_certificate") || em.contains("unknown_ca")
                    || em.contains("ALERT_CERTIFICATE");
            if (certReject) MitmTerminator.blacklist(hn);
            if (c.record != null) {
                String m = (e.getMessage() != null ? e.getMessage() : "");
                CaptureStore.addLog(c.record, "✗ 解密转发失败: " + e.getClass().getSimpleName()
                        + (m.isEmpty() ? "" : " " + m) + "（该域名后续将直连）");
            }
            closeTcp(c);
        }
    }

    private void readLocal(TcpConn c) {
        byte[] buf = new byte[16384];
        try {
            InputStream in2 = c.localSock.getInputStream();
            int n;
            while (running && !c.closed && (n = in2.read(buf)) > 0) {
                sendTcp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, c.mySeq, c.clientSeq, 0x18, buf, n);
                c.mySeq = (c.mySeq + n) & 0xffffffffL;
                if (c.record != null) c.record.down += n;
            }
        } catch (Throwable ignore) {}
        try {
            sendTcp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, c.mySeq, c.clientSeq, 0x11, null, 0);
            c.mySeq = (c.mySeq + 1) & 0xffffffffL;
        } catch (Throwable ignore) {}
        closeTcp(c);
    }

    // ============================ UDP ============================
    private void handleUdp(byte[] p, int len, int ihl, byte[] srcIp, byte[] dstIp) {
        if (len < ihl + 8) return;
        int t = ihl;
        int srcPort = ((p[t] & 0xff) << 8) | (p[t + 1] & 0xff);
        int dstPort = ((p[t + 2] & 0xff) << 8) | (p[t + 3] & 0xff);
        int udpLen = ((p[t + 4] & 0xff) << 8) | (p[t + 5] & 0xff);
        int payloadOff = t + 8;
        int payloadLen = udpLen - 8;
        if (payloadLen < 0) payloadLen = 0;
        if (payloadOff + payloadLen > len) payloadLen = len - payloadOff;
        if (payloadLen < 0) payloadLen = 0;

        String key = ipStr(srcIp) + ":" + srcPort + "->" + ipStr(dstIp) + ":" + dstPort;
        UdpConn c = udpConns.get(key);
        if (c == null) {
            if (udpConns.size() >= 1200) return; // 防御：UDP 连接过多时丢弃
            c = new UdpConn(key, srcIp, dstIp, srcPort, dstPort);
            c.record = CaptureStore.add("UDP", ipStr(srcIp) + ":" + srcPort, ipStr(dstIp) + ":" + dstPort);
            if (dstPort == 53) {
                c.record.kind = "DNS";
                String d = parseDnsName(p, payloadOff, payloadLen);
                if (d != null && !d.isEmpty()) {
                    c.record.host = d;
                    CaptureStore.addLog(c.record, "DNS 查询: " + d);
                }
            } else if (dstPort == 443 || dstPort == 80) {
                c.record.kind = "QUIC";   // UDP 443/80 基本都是 QUIC（HTTP/3）
                CaptureStore.addLog(c.record, "⚡ 疑似 QUIC（HTTP/3）流量");
            } else {
                c.record.kind = "UDP";
            }
            try {
                DatagramSocket ds = new DatagramSocket();
                try { if (service != null) service.protect(ds); } catch (Throwable ignore) {}  // 关键：绕过 VPN
                ds.connect(InetAddress.getByAddress(dstIp), dstPort);
                ds.setSoTimeout(30000);
                c.sock = ds;
            } catch (Throwable e) {
                udpConns.remove(key);
                return;
            }
            final UdpConn cc = c;
            udpConns.put(key, cc);
            new Thread(new Runnable() { public void run() { readUdp(cc); } }, "cap-udp-read").start();
        }
        try {
            c.sock.send(new DatagramPacket(p, payloadOff, payloadLen));
            if (c.record != null) c.record.up += payloadLen;
            c.lastActive = System.currentTimeMillis();
        } catch (Throwable ignore) {}
    }

    private void readUdp(final UdpConn c) {
        byte[] buf = new byte[65535];
        while (running) {
            try {
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                c.sock.receive(dp);
                c.lastActive = System.currentTimeMillis();
                int n = dp.getLength();
                if (n > 0) {
                    if (c.record != null) c.record.down += n;
                    sendUdp(c.dstIp, c.srcIp, c.dstPort, c.srcPort, dp.getData(), n);
                }
            } catch (Throwable e) {
                break; // 超时 / 关闭
            }
        }
        udpConns.remove(c.key);
        try { c.sock.close(); } catch (Throwable ignore) {}
    }

    // ============================ 写 TUN ============================
    private void writeTun(byte[] pkt, int len) {
        synchronized (writeLock) {
            try { out.write(pkt, 0, len); out.flush(); } catch (Throwable ignore) {}
        }
    }

    private void sendTcp(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort,
                         long seq, long ack, int flags, byte[] payload, int payloadLen) {
        int tcpHdr = 20;
        int total = 20 + tcpHdr + payloadLen;
        byte[] pkt = new byte[total];
        // ---- IPv4 头 ----
        pkt[0] = (byte) 0x45;
        pkt[1] = 0;
        pkt[2] = (byte) ((total >> 8) & 0xff);
        pkt[3] = (byte) (total & 0xff);
        pkt[4] = 0; pkt[5] = 0;
        pkt[6] = (byte) 0x40; pkt[7] = 0;      // Don't Fragment
        pkt[8] = 64;                            // TTL
        pkt[9] = 6;                             // TCP
        pkt[10] = 0; pkt[11] = 0;
        System.arraycopy(srcIp, 0, pkt, 12, 4);
        System.arraycopy(dstIp, 0, pkt, 16, 4);
        int ipSum = checksum(pkt, 0, 20);
        pkt[10] = (byte) ((ipSum >> 8) & 0xff);
        pkt[11] = (byte) (ipSum & 0xff);
        // ---- TCP 头 ----
        int t = 20;
        pkt[t] = (byte) ((srcPort >> 8) & 0xff);     pkt[t + 1] = (byte) (srcPort & 0xff);
        pkt[t + 2] = (byte) ((dstPort >> 8) & 0xff); pkt[t + 3] = (byte) (dstPort & 0xff);
        writeU32(pkt, t + 4, seq);
        writeU32(pkt, t + 8, ack);
        pkt[t + 12] = (byte) ((tcpHdr / 4) << 4);
        pkt[t + 13] = (byte) flags;
        pkt[t + 14] = (byte) 0xff; pkt[t + 15] = (byte) 0xff;  // window 65535
        pkt[t + 16] = 0; pkt[t + 17] = 0;
        pkt[t + 18] = 0; pkt[t + 19] = 0;
        if (payload != null && payloadLen > 0) System.arraycopy(payload, 0, pkt, t + 20, payloadLen);
        int tcpSum = tcpChecksum(srcIp, dstIp, pkt, t, tcpHdr + payloadLen);
        pkt[t + 16] = (byte) ((tcpSum >> 8) & 0xff);
        pkt[t + 17] = (byte) (tcpSum & 0xff);
        writeTun(pkt, total);
    }

    private void sendUdp(byte[] srcIp, byte[] dstIp, int srcPort, int dstPort, byte[] payload, int payloadLen) {
        int udpHdr = 8;
        int total = 20 + udpHdr + payloadLen;
        byte[] pkt = new byte[total];
        pkt[0] = (byte) 0x45;
        pkt[1] = 0;
        pkt[2] = (byte) ((total >> 8) & 0xff);
        pkt[3] = (byte) (total & 0xff);
        pkt[6] = (byte) 0x40; pkt[7] = 0;
        pkt[8] = 64;
        pkt[9] = 17;                            // UDP
        System.arraycopy(srcIp, 0, pkt, 12, 4);
        System.arraycopy(dstIp, 0, pkt, 16, 4);
        int ipSum = checksum(pkt, 0, 20);
        pkt[10] = (byte) ((ipSum >> 8) & 0xff);
        pkt[11] = (byte) (ipSum & 0xff);
        int t = 20;
        pkt[t] = (byte) ((srcPort >> 8) & 0xff);     pkt[t + 1] = (byte) (srcPort & 0xff);
        pkt[t + 2] = (byte) ((dstPort >> 8) & 0xff); pkt[t + 3] = (byte) (dstPort & 0xff);
        int ulen = udpHdr + payloadLen;
        pkt[t + 4] = (byte) ((ulen >> 8) & 0xff); pkt[t + 5] = (byte) (ulen & 0xff);
        pkt[t + 6] = 0; pkt[t + 7] = 0;          // 校验和 0（IPv4 允许）
        if (payload != null && payloadLen > 0) System.arraycopy(payload, 0, pkt, t + 8, payloadLen);
        writeTun(pkt, total);
    }

    // ============================ 解析：HTTP / TLS / DNS ============================
    private void onClientData(TcpConn c, byte[] p, int off, int len) {
        // [v71] 采集上行字节（请求头 / 请求体）。加密流量会在 looksWorthBuffering 里被挡住。
        try {
            if (c.record != null && !c.mitmPending && !c.mitmReady) {
                CaptureStore.feedReq(c.record, p, off, len);
                /* [v77] 实时切分：HTTP/1.1 keep-alive 长连接不关闭也能立刻看到请求头/体 */
                CaptureStore.flushPartial(c.record);
            }
        } catch (Throwable ignore) {}
        if (c.mitmPending || c.mitmReady) { handleMitmClientData(c, p, off, len); return; }
        try {
            int cap = Math.min(len, 4096);
            String s = new String(p, off, cap, StandardCharsets.ISO_8859_1);
            if (s.startsWith("GET ") || s.startsWith("POST ") || s.startsWith("PUT ")
                    || s.startsWith("DELETE ") || s.startsWith("HEAD ") || s.startsWith("PATCH ")
                    || s.startsWith("OPTIONS ") || s.startsWith("TRACE ") || s.startsWith("CONNECT ")) {
                int nl = s.indexOf("\r\n");
                String reqLine = nl > 0 ? s.substring(0, nl) : s;
                if (c.record != null) {
                    c.record.method = reqLine;
                    // [v71] 协议细分 + 抽出请求路径
                    try {
                        if (reqLine.indexOf("GET ", 0) == 0 || reqLine.indexOf("POST ", 0) == 0
                                || reqLine.indexOf("PUT ", 0) == 0 || reqLine.indexOf("DELETE ", 0) == 0
                                || reqLine.indexOf("PATCH ", 0) == 0 || reqLine.indexOf("HEAD ", 0) == 0
                                || reqLine.indexOf("OPTIONS ", 0) == 0) {
                            String[] pr = reqLine.split(" ");
                            if (pr.length >= 2 && pr[1] != null) c.record.url = pr[1];
                            if (c.record.kind == null || c.record.kind.length() == 0) c.record.kind = "HTTP";
                        }
                    } catch (Throwable ignore2) {}
                    int hi = s.indexOf("\r\nHost:");
                    if (hi < 0) hi = s.indexOf("\r\nhost:");
                    if (hi >= 0) {
                        int he = s.indexOf("\r\n", hi + 2);
                        if (he > hi) c.record.host = s.substring(hi + 7, he).trim();
                    }
                    CaptureStore.addLog(c.record, "→ " + reqLine);
                    int bodyIdx = s.indexOf("\r\n\r\n");
                    if (bodyIdx >= 0 && bodyIdx + 4 < s.length()) {
                        String body = s.substring(bodyIdx + 4);
                        if (!body.isEmpty()) CaptureStore.addLog(c.record, "  请求体: " + body);
                    }
                }
            } else if (cap > 5 && (p[off] & 0xff) == 0x16 && (p[off + 1] & 0xff) == 0x03) {
                // TLS ClientHello → 提取 SNI
                String sni = parseSni(p, off, cap);
                if (c.record != null) {
                    if (c.record.kind == null || c.record.kind.length() == 0) c.record.kind = "HTTPS";
                    if (sni != null && !sni.isEmpty() && c.record.host.isEmpty()) {
                        c.record.host = sni;
                        CaptureStore.addLog(c.record, "🔒 TLS 目标域名: " + sni);
                    }
                    // [v71] 顺手取 ALPN（h2 / http/1.1），详情页能显示
                    try {
                        String alp = parseAlpn(p, off, cap);
                        if (alp != null && alp.length() > 0) {
                            c.record.alpn = alp;
                            CaptureStore.addLog(c.record, "  ALPN: " + alp);
                        }
                    } catch (Throwable ignore3) {}
                }
            }
        } catch (Throwable ignore) {}
    }

    private void onServerData(TcpConn c, byte[] p, int off, int len) {
        // [v71] 采集下行字节（响应头 / 响应体）—— 旧版完全没有这一步，所以「看不到内容」
        try {
            if (c.record != null && !c.mitmReady) {
                CaptureStore.feedResp(c.record, p, off, len);
                /* [v77] 实时切分：响应边到边可见，不用等连接关闭 */
                CaptureStore.flushPartial(c.record);
            }
        } catch (Throwable ignore) {}
        try {
            int cap = Math.min(len, 4096);
            String s = new String(p, off, cap, StandardCharsets.ISO_8859_1);
            if (s.startsWith("HTTP/")) {
                int nl = s.indexOf("\r\n");
                String statusLine = nl > 0 ? s.substring(0, nl) : s;
                if (c.record != null) {
                    c.record.status = statusLine;
                    if (c.record.kind == null || c.record.kind.length() == 0) c.record.kind = "HTTP";
                    CaptureStore.addLog(c.record, "← " + statusLine);
                    // [v71] 记录 Content-Type，详情页据此决定「按文本显示」还是「按二进制提示」
                    try {
                        int ci = s.toLowerCase().indexOf("\r\ncontent-type:");
                        if (ci >= 0) {
                            int ce = s.indexOf("\r\n", ci + 2);
                            if (ce > ci) c.record.ctype = s.substring(ci + 15, ce).trim();
                        }
                        int uw = s.toLowerCase().indexOf("\r\nupgrade: websocket");
                        if (uw >= 0) c.record.kind = "WebSocket";
                    } catch (Throwable ignore4) {}
                }
            }
        } catch (Throwable ignore) {}
    }

    /** 从 DNS 报文里取第一个查询域名。 */
    private static String parseDnsName(byte[] p, int off, int len) {
        try {
            if (len < 12) return "";
            int qd = ((p[off + 4] & 0xff) << 8) | (p[off + 5] & 0xff);
            if (qd < 1) return "";
            int i = off + 12;
            int end = off + len;
            StringBuilder sb = new StringBuilder();
            while (i < end) {
                int l = p[i] & 0xff;
                if (l == 0) break;
                if ((l & 0xc0) != 0) break;
                i++;
                if (i + l > end) break;
                if (sb.length() > 0) sb.append('.');
                sb.append(new String(p, i, l, StandardCharsets.US_ASCII));
                i += l;
            }
            return sb.toString();
        } catch (Throwable t) { return ""; }
    }

    /** 从 TLS ClientHello 里提取 SNI。 */
    /** [v71] 从 TLS ClientHello 的扩展里取 ALPN（h2 / http/1.1）。取不到返回 ""。 */
    private static String parseAlpn(byte[] p, int off, int len) {
        try {
            if (len < 50) return "";
            int base = off + 43;                       // TLS record(5) + handshake(4) + version(2) + random(32)
            if (base >= off + len) return "";
            int sidLen = p[base] & 0xff;
            int pos = base + 1 + sidLen;
            if (pos + 2 > off + len) return "";
            int csLen = ((p[pos] & 0xff) << 8) | (p[pos + 1] & 0xff);
            pos += 2 + csLen;
            if (pos >= off + len) return "";
            int compLen = p[pos] & 0xff;
            pos += 1 + compLen;
            if (pos + 2 > off + len) return "";
            int extTotal = ((p[pos] & 0xff) << 8) | (p[pos + 1] & 0xff);
            pos += 2;
            int extEnd = Math.min(pos + extTotal, off + len);
            while (pos + 4 <= extEnd) {
                int type = ((p[pos] & 0xff) << 8) | (p[pos + 1] & 0xff);
                int elen = ((p[pos + 2] & 0xff) << 8) | (p[pos + 3] & 0xff);
                pos += 4;
                if (pos + elen > extEnd) break;
                if (type == 16) {   // ALPN
                    int q = pos + 2;
                    StringBuilder sb = new StringBuilder();
                    while (q < pos + elen) {
                        int l = p[q] & 0xff;
                        q++;
                        if (q + l > pos + elen) break;
                        if (sb.length() > 0) sb.append(", ");
                        sb.append(new String(p, q, l, StandardCharsets.ISO_8859_1));
                        q += l;
                    }
                    return sb.toString();
                }
                pos += elen;
            }
        } catch (Throwable ignore) {}
        return "";
    }

    private static String parseSni(byte[] p, int off, int len) {
        try {
            int end = off + len;
            int i = off + 5;                       // 跳过 TLS record 头
            if (i + 4 > end) return "";
            if ((p[i] & 0xff) != 0x01) return "";  // 只认 ClientHello
            i += 4;                                // handshake 头
            i += 34;                               // client version(2) + random(32)
            if (i >= end) return "";
            int sidLen = p[i] & 0xff; i += 1 + sidLen;
            if (i + 2 > end) return "";
            int csLen = ((p[i] & 0xff) << 8) | (p[i + 1] & 0xff); i += 2 + csLen;
            if (i >= end) return "";
            int compLen = p[i] & 0xff; i += 1 + compLen;
            if (i + 2 > end) return "";
            int extLen = ((p[i] & 0xff) << 8) | (p[i + 1] & 0xff); i += 2;
            int extEnd = Math.min(i + extLen, end);
            while (i + 4 <= extEnd) {
                int type = ((p[i] & 0xff) << 8) | (p[i + 1] & 0xff);
                int eLen = ((p[i + 2] & 0xff) << 8) | (p[i + 3] & 0xff);
                i += 4;
                if (type == 0x00) {                // server_name
                    int ni = i + 2;
                    if (ni + 3 > end) break;
                    int nameLen = ((p[ni + 1] & 0xff) << 8) | (p[ni + 2] & 0xff);
                    ni += 3;
                    if (ni + nameLen > end) break;
                    return new String(p, ni, nameLen, StandardCharsets.US_ASCII);
                }
                i += eLen;
            }
        } catch (Throwable t) {}
        return "";
    }

    /** [v80] 返回第一条 TLS record 的总长度（5 字节头 + 声明长度）；不是 TLS 返回 -1。 */
    private static int tlsRecordTotal(byte[] b) {
        try {
            if (b == null || b.length < 5) return -1;
            if ((b[0] & 0xff) != 0x16) return -1;          // handshake
            int len = ((b[3] & 0xff) << 8) | (b[4] & 0xff);
            if (len <= 0 || len > 16384) return -1;
            return 5 + len;
        } catch (Throwable t) {
            return -1;
        }
    }

    // ============================ 工具 ============================
    private static long readU32(byte[] p, int off) {
        return ((long) (p[off] & 0xff) << 24) | ((p[off + 1] & 0xff) << 16)
                | ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
    }

    private static void writeU32(byte[] p, int off, long v) {
        p[off] = (byte) ((v >> 24) & 0xff);
        p[off + 1] = (byte) ((v >> 16) & 0xff);
        p[off + 2] = (byte) ((v >> 8) & 0xff);
        p[off + 3] = (byte) (v & 0xff);
    }

    private static String ipStr(byte[] ip) {
        return (ip[0] & 0xff) + "." + (ip[1] & 0xff) + "." + (ip[2] & 0xff) + "." + (ip[3] & 0xff);
    }

    private static int checksum(byte[] data, int off, int len) {
        long sum = 0;
        int i = off, end = off + len;
        while (i + 1 < end) {
            sum += ((data[i] & 0xff) << 8) | (data[i + 1] & 0xff);
            i += 2;
        }
        if (i < end) sum += (data[i] & 0xff) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return (int) (~sum) & 0xffff;
    }

    private static int tcpChecksum(byte[] srcIp, byte[] dstIp, byte[] tcp, int tcpOff, int tcpLen) {
        long sum = 0;
        sum += ((srcIp[0] & 0xff) << 8) | (srcIp[1] & 0xff);
        sum += ((srcIp[2] & 0xff) << 8) | (srcIp[3] & 0xff);
        sum += ((dstIp[0] & 0xff) << 8) | (dstIp[1] & 0xff);
        sum += ((dstIp[2] & 0xff) << 8) | (dstIp[3] & 0xff);
        sum += 6;
        sum += tcpLen;
        int i = tcpOff, end = tcpOff + tcpLen;
        while (i + 1 < end) {
            sum += ((tcp[i] & 0xff) << 8) | (tcp[i + 1] & 0xff);
            i += 2;
        }
        if (i < end) sum += (tcp[i] & 0xff) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return (int) (~sum) & 0xffff;
    }

    // ============================ 连接对象 ============================
    static class TcpConn {
        final String key;
        final byte[] srcIp;
        final byte[] dstIp;
        final int srcPort;
        final int dstPort;
        Socket sock;
        java.io.InputStream sin;
        java.io.OutputStream sout;
        long mySeq;
        long clientSeq;
        volatile boolean closed = false;
        CaptureStore.Entry record;
        // [v28] MITM 状态
        volatile boolean mitmPending = false;
        volatile boolean mitmReady = false;
        /* [v80] ClientHello 分片缓冲：TLS1.3 的 ClientHello 常 1000+ 字节，
           会跨多个 TCP 段。必须收全再交给 MITM，否则 parseSni 失败 → 用 IP 签证书。 */
        java.io.ByteArrayOutputStream hsBuf;
        MitmTerminator mitmT;
        Socket localSock;
        java.io.OutputStream localOut;

        TcpConn(String key, byte[] srcIp, byte[] dstIp, int srcPort, int dstPort) {
            this.key = key;
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
        }
    }

    static class UdpConn {
        final String key;
        final byte[] srcIp;
        final byte[] dstIp;
        final int srcPort;
        final int dstPort;
        DatagramSocket sock;
        long lastActive;
        CaptureStore.Entry record;

        UdpConn(String key, byte[] srcIp, byte[] dstIp, int srcPort, int dstPort) {
            this.key = key;
            this.srcIp = srcIp;
            this.dstIp = dstIp;
            this.srcPort = srcPort;
            this.dstPort = dstPort;
        }
    }
}
