package com.lingqiong.buddy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

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

    /**
     * 取前端 HTML。
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
}
