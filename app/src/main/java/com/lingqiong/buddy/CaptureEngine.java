package com.lingqiong.buddy;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
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
            tcpConns.put(key, c);
            new Thread(new Runnable() { public void run() { connectServer(c); } }, "cap-tcp-conn").start();
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
        try { if (c.sock != null) c.sock.close(); } catch (Throwable ignore) {}
        tcpConns.remove(c.key);
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
                String d = parseDnsName(p, payloadOff, payloadLen);
                if (d != null && !d.isEmpty()) {
                    c.record.host = d;
                    CaptureStore.addLog(c.record, "DNS 查询: " + d);
                }
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
                if (c.record != null && sni != null && !sni.isEmpty() && c.record.host.isEmpty()) {
                    c.record.host = sni;
                    CaptureStore.addLog(c.record, "🔒 TLS 目标域名: " + sni);
                }
            }
        } catch (Throwable ignore) {}
    }

    private void onServerData(TcpConn c, byte[] p, int off, int len) {
        try {
            int cap = Math.min(len, 4096);
            String s = new String(p, off, cap, StandardCharsets.ISO_8859_1);
            if (s.startsWith("HTTP/")) {
                int nl = s.indexOf("\r\n");
                String statusLine = nl > 0 ? s.substring(0, nl) : s;
                if (c.record != null) {
                    c.record.status = statusLine;
                    CaptureStore.addLog(c.record, "← " + statusLine);
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
