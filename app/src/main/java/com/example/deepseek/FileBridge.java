package com.example.deepseek;

import android.content.Context;
import android.webkit.JavascriptInterface;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class FileBridge {
    private final Context context;
    public FileBridge(Context context) { this.context = context; }

    @JavascriptInterface
    public String readFile(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "File not found: " + path;
            if (!f.canRead()) return "No read permission";
            StringBuilder sb = new StringBuilder();
            BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
            br.close();
            return sb.toString();
        } catch (Exception e) { return "Read failed: " + e.getMessage(); }
    }

    @JavascriptInterface
    public String writeFile(String path, String content) {
        try {
            File f = new File(path);
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) { parent.mkdirs(); }
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(content.getBytes(StandardCharsets.UTF_8));
            fos.close();
            return "Write OK: " + path;
        } catch (Exception e) { return "Write failed: " + e.getMessage(); }
    }

    @JavascriptInterface
    public String listDir(String path) {
        try {
            File dir = new File(path);
            if (!dir.exists()) return "Directory not found";
            if (!dir.isDirectory()) return "Not a directory";
            File[] files = dir.listFiles();
            if (files == null) return "Cannot list directory";
            StringBuilder sb = new StringBuilder();
            for (File f : files) {
                sb.append(f.isDirectory() ? "[DIR] " : "[FILE] ").append(f.getName());
                if (!f.isDirectory()) sb.append(" (").append(f.length()).append(" B)");
                sb.append("\n");
            }
            return sb.length() > 0 ? sb.toString() : "(empty)";
        } catch (Exception e) { return "List failed: " + e.getMessage(); }
    }

    @JavascriptInterface
    public String deleteFile(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "File not found";
            if (f.delete()) return "Deleted: " + path;
            return "Delete failed";
        } catch (Exception e) { return "Delete failed: " + e.getMessage(); }
    }

    @JavascriptInterface
    public boolean exists(String path) { return new File(path).exists(); }
}
