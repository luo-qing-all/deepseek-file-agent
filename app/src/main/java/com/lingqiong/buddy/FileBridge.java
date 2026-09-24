package com.lingqiong.buddy;

import android.content.Context;
import android.util.Base64;
import android.webkit.JavascriptInterface;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * 普通权限文件桥接（java.io）。所有方法都是给 JS 调的。
 * 注意：只有标注 @JavascriptInterface 的方法才能被网页调用。
 */
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
            if (parent != null && !parent.exists()) parent.mkdirs();
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(content.getBytes(StandardCharsets.UTF_8));
            fos.close();
            return "Write OK: " + path;
        } catch (Exception e) { return "Write failed: " + e.getMessage(); }
    }

    @JavascriptInterface
    public String readFileBase64(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "";
            InputStream in = new FileInputStream(f);
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
            in.close();
            return Base64.encodeToString(bos.toByteArray(), Base64.NO_WRAP);
        } catch (Exception e) { return ""; }
    }

    @JavascriptInterface
    public String writeFileBase64(String path, String base64) {
        try {
            File f = new File(path);
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            byte[] data = Base64.decode(base64, Base64.DEFAULT);
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(data);
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

    /** 返回 JSON 数组，便于 JS 直接解析：[{name,isDir,size,mtime}] */
    @JavascriptInterface
    public String listDirJson(String path) {
        try {
            File dir = new File(path);
            if (!dir.exists() || !dir.isDirectory()) return "[]";
            File[] files = dir.listFiles();
            if (files == null) return "[]";
            JSONArray arr = new JSONArray();
            for (File f : files) {
                JSONObject o = new JSONObject();
                o.put("name", f.getName());
                o.put("isDir", f.isDirectory());
                o.put("size", f.isDirectory() ? 0 : f.length());
                o.put("mtime", f.lastModified());
                arr.put(o);
            }
            return arr.toString();
        } catch (Exception e) { return "[]"; }
    }

    @JavascriptInterface
    public String mkdirs(String path) {
        try {
            File f = new File(path);
            if (f.exists() && f.isDirectory()) return "OK: " + path;
            return f.mkdirs() ? "OK: " + path : "Mkdir failed";
        } catch (Exception e) { return "Mkdir failed: " + e.getMessage(); }
    }

    @JavascriptInterface
    public String copyFile(String src, String dest) {
        try {
            File s = new File(src);
            if (!s.exists()) return "Source not found: " + src;
            File d = new File(dest);
            if (d.isDirectory()) d = new File(d, s.getName());
            File parent = d.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            copyRecursive(s, d);
            return "Copy OK: " + d.getAbsolutePath();
        } catch (Exception e) { return "Copy failed: " + e.getMessage(); }
    }

    @JavascriptInterface
    public String moveFile(String src, String dest) {
        try {
            File s = new File(src);
            if (!s.exists()) return "Source not found: " + src;
            File d = new File(dest);
            if (d.isDirectory()) d = new File(d, s.getName());
            File parent = d.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            if (s.renameTo(d)) return "Move OK: " + d.getAbsolutePath();
            // 跨挂载点 rename 失败 → 复制后删源
            copyRecursive(s, d);
            deleteRecursive(s);
            return "Move OK(副本): " + d.getAbsolutePath();
        } catch (Exception e) { return "Move failed: " + e.getMessage(); }
    }

    @JavascriptInterface
    public String deleteFile(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "File not found";
            boolean ok = deleteRecursive(f);
            return ok ? "Deleted: " + path : "Delete failed";
        } catch (Exception e) { return "Delete failed: " + e.getMessage(); }
    }

    @JavascriptInterface
    public boolean exists(String path) { return new File(path).exists(); }

    @JavascriptInterface
    public boolean isDirectory(String path) { return new File(path).isDirectory(); }

    /* ==================== 内部工具 ==================== */

    private static void copyRecursive(File src, File dst) throws Exception {
        if (src.isDirectory()) {
            if (!dst.exists()) dst.mkdirs();
            File[] children = src.listFiles();
            if (children != null) for (File c : children) copyRecursive(c, new File(dst, c.getName()));
        } else {
            File parent = dst.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            FileInputStream in = new FileInputStream(src);
            FileOutputStream out = new FileOutputStream(dst);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            in.close();
            out.close();
        }
    }

    private static boolean deleteRecursive(File f) {
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) for (File c : children) deleteRecursive(c);
        }
        return f.delete();
    }
}
