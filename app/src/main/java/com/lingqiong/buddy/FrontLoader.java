package com.lingqiong.buddy;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
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

    /**
     * [加固 v2] 新格式前端包地址：AES 密钥以 ekey 形式下发（由 native 私钥解包），
     * 因此即使该文件被公开下载，也无法还原出前端源码。
     * 旧格式 PACK_URL 保留，用于：① 新包不可用时的降级；② 兼容旧版 App。
     */
    public static final String PACK_URL_V2 = "https://lingqiong.top/front_pack2.json";

    /**
     * [v83] 增量包清单地址：只有约 2KB，含「每块 sha256」。
     * 客户端按 sha 本地缓存块 → 只下载缺失的块 → 真增量 + 断点续传。
     */
    public static final String PACK_URL_V3 = "https://lingqiong.top/front_pack3.json";

    /** [v83] 内容寻址的块下载前缀（拼上 sha256 即可取块）。 */
    public static final String CHUNK_URL_BASE = "https://lingqiong.top/front_chunk/";

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
            writeText(cachePath, json);
            return html;
        } catch (Throwable netErr) {
            // ② 回退本地缓存
            try {
                if (new File(cachePath).exists()) {
                    String json = readText(cachePath);
                    return FrontCrypto.decode(json, PUB_PEM);
                }
            } catch (Throwable ignore) {}
            return null;
        }
    }

    // ═══════════════ [minSdk 24 兼容] java.io 读写 ═══════════════
    // 原来用的是 java.nio.file.Files/Paths，但那是 Android API 26 才有的类，
    // 降到 minSdk 24 后会在运行期 NoClassDefFoundError，故改为纯 java.io 实现。

    /** 覆盖写入文本（UTF-8）。失败静默——与原 Files.write 外裹 try/catch 的语义一致。 */
    private static void writeText(String path, String text) {
        try {
            FileOutputStream o = new FileOutputStream(path);
            try { o.write(text.getBytes("UTF-8")); } finally { o.close(); }
        } catch (Throwable ignore) {}
    }

    /** 读取整个文件的字节。 */
    static byte[] readBytes(String path) throws IOException {
        File f = new File(path);
        FileInputStream in = new FileInputStream(f);
        try {
            int len = (int) Math.min(f.length(), (long) Integer.MAX_VALUE);
            byte[] b = new byte[len > 0 ? len : 0];
            int off = 0, n;
            while (off < b.length && (n = in.read(b, off, b.length - off)) > 0) off += n;
            if (off < b.length) {
                byte[] t = new byte[off];
                System.arraycopy(b, 0, t, 0, off);
                return t;
            }
            return b;
        } finally {
            in.close();
        }
    }

    /** 读取整个文件的文本（UTF-8）。 */
    static String readText(String path) throws IOException {
        return new String(readBytes(path), "UTF-8");
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
            if (!new File(cachePath).exists()) return -1;
            byte[] all = readBytes(cachePath);
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
                String json = readText(cachePath);
                return FrontCrypto.decode(json, PUB_PEM);
            } catch (Throwable ignore) {
                // 缓存损坏 → 强制走下载
            }
        }

        try {
            if (cb != null) cb.onStatus(remoteV > 0 ? ("发现新版本 v" + remoteV + "，开始下载…") : "正在下载…");
            String json = httpGetWithProgress(packUrl, cb);
            String html = FrontCrypto.decode(json, PUB_PEM);
            writeText(cachePath, json);
            return html;
        } catch (Throwable netErr) {
            if (cb != null) cb.onStatus("下载失败，尝试使用本地缓存…");
            try {
                if (new File(cachePath).exists()) {
                    String json = readText(cachePath);
                    return FrontCrypto.decode(json, PUB_PEM);
                }
            } catch (Throwable ignore) {}
            return null;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  [加固 v2] 新加载入口：v2 优先 → v1 回退 → 缓存兜底
    //  设计要点：任何一步失败都只"降级"，绝不把异常抛到调用方（绝不闪退）。
    // ═══════════════════════════════════════════════════════════

    /**
     * 新加载入口。
     * @param v2Url  新格式包地址（可为 null/空 = 跳过）
     * @param v2Cache v2 本地缓存路径（存加密态）
     * @param v1Url  旧格式包地址（可为 null/空 = 跳过）
     * @param v1Cache v1 本地缓存路径
     * @return 解密后的 HTML；全部失败返回 null。
     */
    public static String load(String v2Url, String v2Cache, String v1Url, String v1Cache,
                              int timeoutMs, Progress cb) {
        // ① 优先 v2
        if (v2Url != null && v2Url.length() > 0) {
            try {
                String h = loadOne(v2Url, v2Cache, timeoutMs, cb);
                if (h != null) return h;
            } catch (Throwable ignore) { /* 降级 */ }
        }
        // ② 回退 v1
        if (v1Url != null && v1Url.length() > 0) {
            try {
                String h = loadOne(v1Url, v1Cache, timeoutMs, cb);
                if (h != null) return h;
            } catch (Throwable ignore) { /* 降级 */ }
        }
        // ③ 缓存兜底
        String h = tryCache(v2Cache);
        if (h != null) return h;
        return tryCache(v1Cache);
    }

    /** 单来源加载：版本对比 → 下载/用缓存 → 解码 → 落缓存。失败返回 null。 */
    private static String loadOne(String url, String cachePath, int timeoutMs, Progress cb) {
        int localV = localVersion(cachePath);
        if (cb != null) cb.onStatus("正在检查更新…");
        int remoteV = fetchRemoteVersion(url, timeoutMs);

        boolean needDownload;
        if (remoteV < 0) {
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
                return decodeAny(readText(cachePath));
            } catch (Throwable ignore) { /* 缓存坏了 → 强制下载 */ }
        }

        try {
            if (cb != null) cb.onStatus(remoteV > 0 ? ("发现新版本 v" + remoteV + "，开始下载…") : "正在下载…");
            String json = httpGetWithProgress(url, cb);
            String html = decodeAny(json);      // 先解码；失败则抛，不写入坏缓存
            writeText(cachePath, json);
            return html;
        } catch (Throwable netErr) {
            if (cb != null) cb.onStatus("下载失败，尝试使用本地缓存…");
            try {
                if (new File(cachePath).exists()) return decodeAny(readText(cachePath));
            } catch (Throwable ignore) {}
            return null;
        }
    }

    /** 按内容自动识别格式解码：含 ekey → v2（native 解包）；否则 v1（旧明文 key）。 */
    private static String decodeAny(String json) throws Exception {
        if (json != null && json.indexOf("\"ekey\"") >= 0) {
            return FrontCrypto.decodeV2(json, PUB_PEM);
        }
        return FrontCrypto.decode(json, PUB_PEM);
    }

    /** 读缓存并解码；任何失败返回 null。 */
    private static String tryCache(String cachePath) {
        try {
            if (cachePath == null || !new File(cachePath).exists()) return null;
            return decodeAny(readText(cachePath));
        } catch (Throwable t) {
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

    // ═══════════════════════════════════════════════════════════
    //  [v83] v3 增量加载：清单 → 只补缺失块 → 拼装 → 解密
    //
    //  解决的问题：
    //   ① 以前版本一变就整包重下（1MB）。现在只下发生变化的块（通常 1~2 个 = 64~128KB）
    //   ② 以前下到 99% 闪退，重进从头再来。现在已下完的块按 sha 落盘，永久复用
    //   ③ 块按内容寻址 + 服务端长缓存，配合 manifest 签名，防篡改
    // ═══════════════════════════════════════════════════════════

    /**
     * @param manifestUrl 清单地址
     * @param chunkBase   块地址前缀（末尾带 /）
     * @param chunkDir    块缓存目录（文件名 = sha256）
     * @param binCache    完整密文缓存文件路径（命中同版本可秒启）
     * @param metaPath    记录上次成功版本号的小文件
     * @return 解密后的 HTML；失败返回 null（调用方回退 v2）
     */
    public static String loadV3(String manifestUrl, String chunkBase, File chunkDir,
                                String manifestCache, int timeoutMs, Progress cb,
                                android.content.res.AssetManager am) {
        try {
            if (cb != null) cb.onStatus("正在检查更新…");

            // ---- ① 清单：远端 → 本地缓存 → APK 内置（三级兜底，保证一定能启动）----
            // ★ 清单只有 ~4KB，正常网络瞬间完成；这里把超时压到 4 秒，
            //   避免断网/弱网时让用户干等 15 秒。超时后立刻改用内置资源启动。
            String manifest = null;
            boolean fromRemote = false;
            try {
                manifest = httpGet(manifestUrl, Math.min(timeoutMs, 4000));
                if (manifest != null && manifest.length() > 0) fromRemote = true;
            } catch (Throwable ig) {}
            if (!fromRemote && manifestCache != null) {
                try { manifest = readText(manifestCache); } catch (Throwable ig) {}
            }
            if ((manifest == null || manifest.length() == 0) && am != null) {
                byte[] mz = readAsset(am, "seed/manifest.json");
                if (mz != null) {
                    manifest = new String(mz, "UTF-8");
                    if (cb != null) cb.onStatus("使用内置版本启动…");
                }
            }
            if (manifest == null || manifest.length() == 0) return null;

            org.json.JSONObject m = new org.json.JSONObject(manifest);
            int v = m.optInt("v", -1);
            long totalLen = m.optLong("len", -1);
            org.json.JSONArray arr = m.optJSONArray("blocks");
            if (v < 0 || totalLen <= 0 || arr == null || arr.length() == 0) return null;
            int n = arr.length();

            if (chunkDir != null && !chunkDir.exists()) chunkDir.mkdirs();

            // ---- ② 逐块确认：本地已有 → 用；没有 → 先从 APK 内置块取（秒开，不走网络）----
            String[] ids = new String[n];
            boolean[] have = new boolean[n];
            int fromSeed = 0;
            for (int i = 0; i < n; i++) {
                ids[i] = arr.getString(i);
                File f = new File(chunkDir, ids[i]);
                have[i] = f.exists() && f.length() > 16;
                if (!have[i] && am != null) {
                    byte[] seed = readAsset(am, "seed/chunks/" + ids[i]);
                    if (seed != null && seed.length > 16) {
                        try {
                            FileOutputStream o = new FileOutputStream(f);
                            try { o.write(seed); } finally { try { o.close(); } catch (Throwable ig) {} }
                            have[i] = true;
                            fromSeed++;
                        } catch (Throwable ig) {}
                    }
                }
            }
            if (fromSeed > 0 && cb != null) cb.onStatus("从内置资源准备前端（" + fromSeed + " 块）…");

            int miss = 0;
            for (int i = 0; i < n; i++) if (!have[i]) miss++;

            // ---- ③ 只下载真正缺的块（已下载/内置的永久复用 = 断点续传 + 增量）----
            if (miss > 0) {
                if (cb != null) cb.onStatus("更新 " + miss + "/" + n + " 个文件块…");
                long got = 0, tLast = System.currentTimeMillis();
                for (int i = 0; i < n; i++) {
                    if (have[i]) continue;
                    byte[] blk = httpGetBytes(chunkBase + ids[i], 20000, 0);
                    if (blk == null || blk.length <= 16) {
                        blk = httpGetBytes(chunkBase + ids[i], 20000, 0);   // 重试一次
                    }
                    if (blk == null || blk.length <= 16) {
                        if (cb != null) cb.onStatus("缺少文件块，尝试其他通道…");
                        return null;
                    }
                    File f = new File(chunkDir, ids[i]);
                    File tmp = new File(f.getAbsolutePath() + ".tmp");
                    FileOutputStream o = new FileOutputStream(tmp);
                    try { o.write(blk); } finally { try { o.close(); } catch (Throwable ig) {} }
                    if (!tmp.renameTo(f)) { try { f.delete(); } catch (Throwable ig) {} tmp.renameTo(f); }
                    got += blk.length;
                    long now = System.currentTimeMillis();
                    if (cb != null && (now - tLast >= 200)) {
                        long dt = now - tLast;
                        long bps = dt > 0 ? got * 1000L / dt : 0;
                        cb.onProgress(got, got, bps);
                        tLast = now;
                    }
                }
            } else if (cb != null) {
                cb.onStatus("准备就绪，正在启动…");
            }

            // ---- ④ 按清单顺序取块 ----
            byte[][] blocks = new byte[n][];
            for (int i = 0; i < n; i++) {
                File f = new File(chunkDir, ids[i]);
                if (!f.exists()) return null;
                blocks[i] = readBytes(f.getAbsolutePath());
            }

            // ---- ⑤ 验签 + 逐块解密 ----
            String html = FrontCrypto.decodeV3Blocks(manifest, blocks, PUB_PEM);
            if (html == null || html.length() == 0) return null;

            if (fromRemote && manifestCache != null) writeText(manifestCache, manifest);

            // ---- ⑥ 清理不属于本清单的旧块 ----
            try {
                java.util.HashSet<String> keep = new java.util.HashSet<String>();
                for (int i = 0; i < n; i++) keep.add(ids[i]);
                File[] olds = chunkDir.listFiles();
                if (olds != null) for (File f : olds) {
                    String nm = f.getName();
                    if (nm.endsWith(".tmp")) { f.delete(); continue; }
                    if (!keep.contains(nm)) f.delete();
                }
            } catch (Throwable ignore) {}

            return html;
        } catch (Throwable t) {
            if (cb != null) cb.onStatus("增量更新失败，尝试其他通道…");
            return null;
        }
    }

    /** [v83] 从 APK assets 读一个小文件；失败返回 null。 */
    static byte[] readAsset(android.content.res.AssetManager am, String path) {
        if (am == null) return null;
        java.io.InputStream in = null;
        try {
            in = am.open(path);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[16384];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            return bos.toByteArray();
        } catch (Throwable t) {
            return null;
        } finally {
            try { if (in != null) in.close(); } catch (Throwable ignore) {}
        }
    }

    /** 读小文件里的整数；不存在/损坏返回 -1。 */
    static int readIntFile(String path) {
        try {
            if (path == null) return -1;
            String t = readText(path).trim();
            return Integer.parseInt(t);
        } catch (Throwable t) {
            return -1;
        }
    }

    /** 写小文件里的整数。 */
    static void writeIntFile(String path, int v) {
        try {
            if (path == null) return;
            writeText(path, String.valueOf(v));
        } catch (Throwable ignore) {}
    }

    /** GET 二进制（connectTimeout / readTimeout；readTimeout=0 表示不限时）。 */
    static byte[] httpGetBytes(String urlStr, int connectTimeout, int readTimeout) {
        HttpURLConnection conn = null;
        InputStream in = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "*/*");
            conn.setInstanceFollowRedirects(true);
            int code = conn.getResponseCode();
            if (code != 200) throw new IOException("HTTP " + code);
            long len = conn.getContentLengthLong();
            in = conn.getInputStream();
            ByteArrayOutputStream bos = new ByteArrayOutputStream(
                    (len > 0 && len < Integer.MAX_VALUE) ? (int) len : 8192);
            byte[] buf = new byte[16384];
            int r;
            while ((r = in.read(buf)) > 0) bos.write(buf, 0, r);
            return bos.toByteArray();
        } catch (Throwable t) {
            return null;
        } finally {
            try { if (in != null) in.close(); } catch (Throwable ignore) {}
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * [v83] 统一入口：v3 增量 → v2 → v1 → 本地缓存兜底。
     * 任何一步失败都只降级，绝不抛异常（避免启动闪退）。
     */
    public static String loadBest(File filesDir, int timeoutMs, Progress cb,
                                  android.content.res.AssetManager am) {
        String v2Cache = new File(filesDir, "front_pack2.json").getAbsolutePath();
        String v1Cache = new File(filesDir, "front_pack.json").getAbsolutePath();

        // ① v3 增量（APK 内置块 → 本地缓存 → 只下缺的块）
        try {
            String h = loadV3(PACK_URL_V3, CHUNK_URL_BASE,
                    new File(filesDir, "chunks"),
                    new File(filesDir, "front_v3_manifest.json").getAbsolutePath(),
                    timeoutMs, cb, am);
            if (h != null && h.length() > 0) return h;
        } catch (Throwable ignore) { /* 降级 */ }

        // ② 旧通道 v2 → v1 → 本地缓存
        return load(PACK_URL_V2, v2Cache, PACK_URL, v1Cache, timeoutMs, cb);
    }

}
