package com.example.deepseek;

import android.content.Context;
import android.content.pm.PackageManager;
import android.util.Base64;
import android.webkit.JavascriptInterface;
import java.io.BufferedReader;
import java.io.InputStreamReader;
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
            if (Shizuku.isPreV11()) return "Shizuku version too old";
            if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) return "Already granted";
            Shizuku.requestPermission(REQUEST_CODE);
            return "Permission requested, please allow in popup";
        } catch (Throwable t) { return "Request failed: " + t.getMessage(); }
    }

    @JavascriptInterface
    public String readFile(String path) { return execShell("cat '" + escape(path) + "'"); }

    @JavascriptInterface
    public String writeFile(String path, String content) {
        String b64 = Base64.encodeToString(content.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
        return execShell("echo '" + b64 + "' | base64 -d > '" + escape(path) + "'");
    }

    @JavascriptInterface
    public String listDir(String path) { return execShell("ls -la '" + escape(path) + "'"); }

    @JavascriptInterface
    public String deleteFile(String path) { return execShell("rm -f '" + escape(path) + "'"); }

    private String escape(String s) { return s.replace("'", "'\\''"); }

    private String execShell(String cmd) {
        if (!isAvailable()) return "Shizuku not authorized";
        try {
            ShizukuRemoteProcess process = Shizuku.newProcess(new String[]{"sh", "-c", cmd}, null, null);
            BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            BufferedReader er = new BufferedReader(new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) out.append(line).append("\n");
            while ((line = er.readLine()) != null) out.append("[stderr] ").append(line).append("\n");
            process.waitFor();
            String result = out.toString().trim();
            return result.isEmpty() ? "(OK, no output)" : result;
        } catch (Throwable t) { return "Shizuku exec failed: " + t.getMessage(); }
    }
}
