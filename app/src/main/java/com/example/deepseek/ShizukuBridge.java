package com.example.deepseek;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Base64;
import android.webkit.JavascriptInterface;

import java.io.BufferedReader;
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
            if (Shizuku.isPreV11()) return "Shizuku 版本过低";
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) return "已授权";
            Shizuku.requestPermission(REQUEST_CODE);
            return "已发送授权请求，请在弹窗中允许";
        } catch (Throwable t) { return "请求失败：" + t.getMessage(); }
    }

    // ============ 文本读写 ============
    @JavascriptInterface
    public String readFile(String path) { return execShell("cat '" + escape(path) + "'"); }

    @JavascriptInterface
    public String writeFile(String path, String content) {
        String b64 = Base64.encodeToString(content.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
        return execShell("echo '" + b64 + "' | base64 -d > '" + escape(path) + "'");
    }

    @JavascriptInterface
    public String listDir(String path) { return execShell("ls -la '" + escape(path) + "'"); }

    // ============ 二进制读写 ============
    @JavascriptInterface
    public String readFileBase64(String path) {
        return execShell("base64 -w0 '" + escape(path) + "'");
    }

    @JavascriptInterface
    public String writeFileBase64(String path, String base64) {
        String clean = base64.replaceAll("\\s+", "");
        return execShell("echo '" + clean + "' | base64 -d > '" + escape(path) + "'");
    }

    // ============ 文件操作 ============
    @JavascriptInterface
    public String copyFile(String src, String dest) {
        return execShell("cp -r '" + escape(src) + "' '" + escape(dest) + "' && echo '复制成功'");
    }

    @JavascriptInterface
    public String moveFile(String src, String dest) {
        return execShell("mv '" + escape(src) + "' '" + escape(dest) + "' && echo '移动成功'");
    }

    @JavascriptInterface
    public String deleteFile(String path) {
        return execShell("rm -rf '" + escape(path) + "' && echo '删除成功'");
    }

    @JavascriptInterface
    public String mkdirs(String path) {
        return execShell("mkdir -p '" + escape(path) + "' && echo '创建成功'");
    }

    @JavascriptInterface
    public String fileInfo(String path) {
        return execShell("ls -la '" + escape(path) + "' && file '" + escape(path) + "'");
    }

    @JavascriptInterface
    public String listDirDetailed(String path) {
        return execShell("ls -la '" + escape(path) + "'");
    }

    // ============ 关键：执行任意 shell 命令（反编译靠这个） ============
    @JavascriptInterface
    public String exec(String cmd) {
        return execShell(cmd);
    }

    private String escape(String s) { return s.replace("'", "'\\''"); }

    private String execShell(String cmd) {
        if (!isAvailable()) return "错误：Shizuku 未授权";
        try {
            Method m = Shizuku.class.getDeclaredMethod("newProcess",
                    String[].class, String[].class, String.class);
            m.setAccessible(true);
            ShizukuRemoteProcess process = (ShizukuRemoteProcess)
                    m.invoke(null, new String[]{"sh", "-c", cmd}, null, null);

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            BufferedReader er = new BufferedReader(
                    new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) out.append(line).append("\n");
            while ((line = er.readLine()) != null) out.append("[stderr] ").append(line).append("\n");
            process.waitFor();
            String result = out.toString().trim();
            return result.isEmpty() ? "(OK, no output)" : result;
        } catch (Throwable t) { return "Shizuku 执行失败：" + t.getMessage(); }
    }
}
