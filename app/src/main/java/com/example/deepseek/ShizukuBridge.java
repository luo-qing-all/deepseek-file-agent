package com.example.deepseek;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Base64;
import android.webkit.JavascriptInterface;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import rikka.shizuku.Shizuku;
import rikka.shizuku.ShizukuRemoteProcess;

public class ShizukuBridge {
    private static final int REQUEST_CODE = 1001;
    private final Context context;

    public ShizukuBridge(Context context) { this.context = context; }

    private boolean isAvailable() {
        try {
            return Shizuku.pingBinder() &&
                   Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED;
        } catch (Throwable t) { return false; }
    }

    @JavascriptInterface
    public boolean isReady() { return isAvailable(); }

    @JavascriptInterface
    public String requestPermission() {
        try {
            if (!Shizuku.pingBinder()) return "Shizuku 服务未运行";
            if (!Shizuku.isPreV11() && Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) return "已授权";
            Shizuku.requestPermission(REQUEST_CODE);
            return "已发送授权请求，请在弹窗中允许";
        } catch (Throwable t) { return "请求失败：" + t.getMessage(); }
    }

    /* ==================== 文件操作（走 shell） ==================== */

    @JavascriptInterface
    public String readFile(String path) {
        Result r = run("cat " + q(path));
        if (r.code != 0 && !r.err.isEmpty()) return "读取失败：" + r.err;
        return r.out;
    }

    @JavascriptInterface
    public String writeFile(String path, String content) {
        String b64 = Base64.encodeToString(content.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
        return execShell("mkdir -p " + q(parentOf(path)) + " && echo " + q(b64) + " | base64 -d > " + q(path));
    }

    @JavascriptInterface
    public String readFileBase64(String path) {
        Result r = run("base64 " + q(path));
        if (r.code != 0 && !r.err.isEmpty()) return "读取失败：" + r.err;
        // 去掉 base64 输出里的换行/空白，返回纯净 base64
        return r.out.replaceAll("\\s", "");
    }

    @JavascriptInterface
    public String writeFileBase64(String path, String base64) {
        String clean = base64 == null ? "" : base64.replaceAll("\\s", "");
        return execShell("mkdir -p " + q(parentOf(path)) + " && echo " + q(clean) + " | base64 -d > " + q(path));
    }

    @JavascriptInterface
    public String copyFile(String src, String dest) {
        // 若 dest 是已存在目录，则复制进该目录（保持原名）
        String cmd = "if [ -d " + q(dest) + " ]; then cp -r " + q(src) + " " + q(dest) + "/; " +
                     "else mkdir -p " + q(parentOf(dest)) + " && cp -r " + q(src) + " " + q(dest) + "; fi";
        return execShell(cmd);
    }

    @JavascriptInterface
    public String moveFile(String src, String dest) {
        String cmd = "if [ -d " + q(dest) + " ]; then mkdir -p " + q(dest) + " && mv " + q(src) + " " + q(dest) + "/; " +
                     "else mkdir -p " + q(parentOf(dest)) + " && mv " + q(src) + " " + q(dest) + "; fi";
        return execShell(cmd);
    }

    @JavascriptInterface
    public String mkdirs(String path) { return execShell("mkdir -p " + q(path)); }

    @JavascriptInterface
    public String deleteFile(String path) { return execShell("rm -rf " + q(path)); }

    @JavascriptInterface
    public String listDir(String path) { return execShell("ls -la " + q(path)); }

    @JavascriptInterface
    public String listDirDetailed(String path) {
        return execShell("ls -la --full-time " + q(path) + " 2>/dev/null || ls -la " + q(path));
    }

    @JavascriptInterface
    public String fileInfo(String path) {
        return execShell(
            "if [ -e " + q(path) + " ]; then " +
            "  echo \"路径: " + escDouble(path) + "\"; " +
            "  if [ -d " + q(path) + " ]; then echo '类型: 目录'; else echo '类型: 文件'; fi; " +
            "  stat -c '大小: %s 字节' " + q(path) + " 2>/dev/null; " +
            "  stat -c '权限: %A' " + q(path) + " 2>/dev/null; " +
            "  stat -c '修改时间: %y' " + q(path) + " 2>/dev/null; " +
            "  ls -ld " + q(path) + "; " +
            "else echo '文件不存在：" + escDouble(path) + "'; fi"
        );
    }

    /* ==================== 任意 shell ==================== */

    @JavascriptInterface
    public String exec(String cmd) {
        if (cmd == null || cmd.trim().isEmpty()) return "命令为空";
        return execShell(cmd);
    }

    /* ==================== 内部工具 ==================== */

    /** 单引号安全转义，用于包住路径/参数 */
    private static String q(String s) {
        if (s == null) return "''";
        return "'" + s.replace("'", "'\\''") + "'";
    }

    /** 双引号内转义，用于 echo 里回显路径 */
    private static String escDouble(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$").replace("`", "\\`");
    }

    private static String parentOf(String path) {
        if (path == null) return "/";
        File f = new File(path);
        String p = f.getParent();
        return p == null ? "/" : p;
    }

    private static final class Result {
        String out = "";
        String err = "";
        int code = 0;
    }

    private Result run(String cmd) {
        Result r = new Result();
        if (!isAvailable()) { r.err = "Shizuku 未授权"; r.code = -1; return r; }
        try {
            Method m = Shizuku.class.getDeclaredMethod(
                    "newProcess", String[].class, String[].class, String.class);
            m.setAccessible(true);
            ShizukuRemoteProcess process = (ShizukuRemoteProcess)
                    m.invoke(null, new String[]{"sh", "-c", cmd}, null, null);

            // stderr 单独线程读取，避免大输出时管道堵塞导致死锁
            final StringBuilder errSb = new StringBuilder();
            Thread errThread = new Thread(new Runnable() {
                @Override public void run() {
                    try {
                        BufferedReader er = new BufferedReader(
                                new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8));
                        String line;
                        while ((line = er.readLine()) != null) errSb.append(line).append("\n");
                    } catch (Exception ignore) {}
                }
            });
            errThread.start();

            String out = readStream(process.getInputStream());
            r.code = process.waitFor();
            try { errThread.join(2000); } catch (InterruptedException ignore) {}

            r.out = out;
            r.err = errSb.toString().trim();
        } catch (Throwable t) {
            r.err = "Shizuku 执行失败：" + t.getMessage();
            r.code = -1;
        }
        return r;
    }

    private static String readStream(InputStream in) throws Exception {
        BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        char[] buf = new char[8192];
        int n;
        while ((n = br.read(buf)) != -1) sb.append(buf, 0, n);
        return sb.toString();
    }

    private String execShell(String cmd) {
        Result r = run(cmd);
        StringBuilder sb = new StringBuilder();
        if (r.out != null && !r.out.isEmpty()) sb.append(r.out);
        if (r.err != null && !r.err.isEmpty()) {
            if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n') sb.append("\n");
            sb.append("[stderr] ").append(r.err);
        }
        if (sb.length() == 0) {
            if (r.code != 0) return "命令执行失败（exit " + r.code + "）";
            return "(OK, 无输出)";
        }
        if (r.code != 0 && (r.err == null || r.err.isEmpty())) {
            sb.append("\n[exit ").append(r.code).append("]");
        }
        return sb.toString().trim();
    }
}
