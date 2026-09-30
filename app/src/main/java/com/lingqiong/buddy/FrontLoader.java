package com.lingqiong.buddy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * FrontLoader —— 客户端前端资源加载器（纯 JDK：java.* + java.net.*）。
 *
 * 流程：
 *   ① 联网下载 front_pack.json  → FrontCrypto.decode(验签+解密) → HTML，并缓存【加密态】
 *   ② 联网失败 → 读取本地缓存（也是加密态）→ 验签+解密 → HTML
 *   ③ 都失败 → 返回 null（由 MainActivity 提示"无法获取前端资源"）
 *
 * 关键：APK 内【不含】任何能解密的 AES 密钥；只有一个【公钥】（公开信息，泄露无碍）。
 *       密文与密钥由服务器下发，且服务器私钥签名可防篡改。
 *
 * [2.5.5] 新增：版本号对比（远端更高才下载）+ 不限时下载 + 进度回调。
 */
public class FrontLoader {

    /** 前端加密包地址（服务器只需把这个静态文件放上来，无需任何密码学依赖）。 */
    public static final String PACK_URL = "https://lingqiong.top/front_pack.json";

    /** 内置验签公钥（RSA-2048，与服务器私钥配对）。 */
    public static final String PUB_PEM =
        "-----BEGIN PUBLIC KEY-----\n"
        + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApDc66OJRZxtpbdDKjiUU\n"
        + "RnMXautL21DCvObD3IXc1wOr3ZFl22f7TBpc8Y29/JG9FJIkGiFtN8tsR18UTy0+\n"
        + "C2bpAV6aVkWT7zQyYabMd1tmgpqElYZSlLIb5kZ0gJ5SJpRQhWnXp14c5FCWucei\n"
        + "lGW4Zatali3430chMwlcxsGGUupnjfNIjbNFQuxgxYkDiH+4QswmIIR96LTIbkib\n"
        + "QtcvREfZ/NktjUsb+ZBp3BI+lFmtTeSwknUfMM7fp+CvqQ+Ahk4WCG5Cw0jRcALH\n"
        + "OY9bPFISnCxMun/74cDQjDIczc3Q49Rfd/6eLa7mOTKd9iMk7fpmX8CbchKQFIGM\n"
        + "kwIDAQAB\n"
        + "-----END PUBLIC KEY-----\n";

    /** [2.5.5] 进度回调：MainActivity 用它更新进度条。 */
    public interface Progress {
        /** 文字状态（如"正在检查更新…"）。 */
        void onStatus(String msg);
        /** 下载进度：downloaded 已下载字节；total 总字节（&lt;=0 表示未知）；bytesPerSec 瞬时速度。 */
        void onProgress(long downloaded, long total, long bytesPerSec);
    }

    /**
     * 取前端 HTML（旧签名，保持向后兼容：无版本对比、固定超时）。
     * @param packUrl   加密包地址
     * @param cachePath 本地缓存文件路径（存加密态，可离线兜底）
     * @param timeoutMs 连接/读取超时
     * @return 解密后的 HTML；失败返回 null。
     */
    public static String load(String packUrl, String cachePath, int timeoutMs) {
        // ① 联网取最新
        try {
            String json = httpGet(packUrl, timeoutMs);
            String html = FrontCrypto.decode(json, PUB_PEM);   // 验签/解密任一失败即抛异常
            try { Files.write(Paths.get(cachePath), json.getBytes("UTF-8")); } catch (Throwable ignore) {}
            return html;
        } catch (Throwable netErr) {
            // ② 回退本地缓存
            try {
                if (Files.exists(Paths.get(cachePath))) {
                    String json = new String(Files.readAllBytes(Paths.get(cachePath)), "UTF-8");
                    return FrontCrypto.decode(json, PUB_PEM);
                }
            } catch (Throwable ignore) {}
            return null;
        }
    }

    static String httpGet(String urlStr, int timeoutMs) throws IOException {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setInstanceFollowRedirects(true);
            int code = conn.getResponseCode();
            if (code != 200) throw new IOException("HTTP " + code);
            InputStream in = conn.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            in.close();
            return new String(bos.toByteArray(), "UTF-8");
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ==================== [2.5.5] 新增：版本对比 + 不限时 + 进度 ====================

    /** 从包头部明文解析版本号（形如 {"v":15,...}）。解析失败返回 -1。 */
    public static int parseVersion(String json) {
        if (json == null) return -1;
        try {
            Matcher m = Pattern.compile("\"v\"\\s*:\\s*(\\d+)").matcher(json);
            if (m.find()) return Integer.parseInt(m.group(1));
        } catch (Throwable ignore) {}
        return -1;
    }

    /** 只读远端包头（Range 前 256 字节）取版本号；网络失败返回 -1。 */
    static int fetchRemoteVersion(String urlStr, int timeoutMs) {
        HttpURLConnection conn = null;
        InputStream in = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(timeoutMs);
            conn.setReadTimeout(timeoutMs);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Range", "bytes=0-255");
            conn.setRequestProperty("Accept", "application/json");
            conn.setInstanceFollowRedirects(true);
            int code = conn.getResponseCode();
            if (code != 200 && code != 206) return -1;
            in = conn.getInputStream();
            byte[] buf = new byte[256];
            int total = 0, n;
            while (total < buf.length && (n = in.read(buf, total, buf.length - total)) > 0) total += n;
            return parseVersion(new String(buf, 0, total, "UTF-8"));
        } catch (Throwable t) {
            return -1;
        } finally {
            try { if (in != null) in.close(); } catch (Throwable ignore) {}
            if (conn != null) conn.disconnect();
        }
    }

    /** 读本地缓存包头版本号（缓存是加密态 json，头部同样有明文 v）。无缓存/损坏返回 -1。 */
    static int localVersion(String cachePath) {
        try {
            if (!Files.exists(Paths.get(cachePath))) return -1;
            byte[] all = Files.readAllBytes(Paths.get(cachePath));
            int n = Math.min(all.length, 256);
            return parseVersion(new String(all, 0, n, "UTF-8"));
        } catch (Throwable t) {
            return -1;
        }
    }

    /**
     * [2.5.5] 带进度回调的加载：
     *   ① 取远端版本号；本地有缓存且远端不更高 → 直接用缓存（秒进，不再重复下载）
     *   ② 远端更高（或本地无缓存）→ 下载完整包（【不限时】）→ 缓存 → 验签解密
     *   ③ 网络异常 → 回退本地缓存
     */
    public static String load(String packUrl, String cachePath, int timeoutMs, Progress cb) {
        int localV = localVersion(cachePath);
        if (cb != null) cb.onStatus("正在检查更新…");
        int remoteV = fetchRemoteVersion(packUrl, timeoutMs);

        boolean needDownload;
        if (remoteV < 0) {
            // 版本检查失败（网络问题）：有缓存就直接进，无缓存才尝试下载
            needDownload = (localV < 0);
            if (!needDownload && cb != null) cb.onStatus("使用本地版本启动…");
        } else if (localV < 0) {
            needDownload = true;
        } else {
            needDownload = (remoteV > localV);
            if (!needDownload && cb != null) cb.onStatus("已是最新版本，正在启动…");
        }

        if (!needDownload) {
            try {
                String json = new String(Files.readAllBytes(Paths.get(cachePath)), "UTF-8");
                return FrontCrypto.decode(json, PUB_PEM);
            } catch (Throwable ignore) {
                // 缓存损坏 → 强制走下载
            }
        }

        try {
            if (cb != null) cb.onStatus(remoteV > 0 ? ("发现新版本 v" + remoteV + "，开始下载…") : "正在下载…");
            String json = httpGetWithProgress(packUrl, cb);
            String html = FrontCrypto.decode(json, PUB_PEM);
            try { Files.write(Paths.get(cachePath), json.getBytes("UTF-8")); } catch (Throwable ignore) {}
            return html;
        } catch (Throwable netErr) {
            if (cb != null) cb.onStatus("下载失败，尝试使用本地缓存…");
            try {
                if (Files.exists(Paths.get(cachePath))) {
                    String json = new String(Files.readAllBytes(Paths.get(cachePath)), "UTF-8");
                    return FrontCrypto.decode(json, PUB_PEM);
                }
            } catch (Throwable ignore) {}
            return null;
        }
    }

    /** [2.5.5] 带进度的 GET：【读超时=0 即不限时】，按 Content-Length 报百分比/速度。 */
    static String httpGetWithProgress(String urlStr, Progress cb) throws IOException {
        HttpURLConnection conn = null;
        InputStream in = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(20000);
            conn.setReadTimeout(0);   // ★ 0 = 不限时（慢速网络可一直下完，不再 8 秒放弃）
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setInstanceFollowRedirects(true);
            int code = conn.getResponseCode();
            if (code != 200) throw new IOException("HTTP " + code);
            long total = conn.getContentLengthLong();
            in = conn.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream(
                    (total > 0 && total < Integer.MAX_VALUE) ? (int) total : 8192);
            byte[] buf = new byte[16384];
            long got = 0, tLast = System.currentTimeMillis(), gotLast = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
                got += n;
                long now = System.currentTimeMillis();
                if (cb != null && (now - tLast >= 250 || (total > 0 && got >= total))) {
                    long dt = now - tLast;
                    long bps = dt > 0 ? (got - gotLast) * 1000L / dt : 0;
                    cb.onProgress(got, total, bps);
                    tLast = now; gotLast = got;
                }
            }
            if (cb != null) cb.onProgress(got, total > 0 ? total : got, 0);
            return new String(bos.toByteArray(), "UTF-8");
        } finally {
            try { if (in != null) in.close(); } catch (Throwable ignore) {}
            if (conn != null) conn.disconnect();
        }
    }
}
