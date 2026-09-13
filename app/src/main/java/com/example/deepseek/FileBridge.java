package com.example.deepseek;

import android.content.Context;
import android.util.Base64;
import android.webkit.JavascriptInterface;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class FileBridge {
    private final Context context;
    public FileBridge(Context context) { this.context = context; }

    // ============ 文本读写 ============
    @JavascriptInterface
    public String readFile(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "错误：文件不存在 " + path;
            if (!f.canRead()) return "错误：无读取权限";
            StringBuilder sb = new StringBuilder();
            java.io.BufferedReader br = new java.io.BufferedReader(
                    new java.io.InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8));
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append("\n");
            br.close();
            return sb.toString();
        } catch (Exception e) { return "读取失败：" + e.getMessage(); }
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
            return "写入成功：" + path;
        } catch (Exception e) { return "写入失败：" + e.getMessage(); }
    }

    // ============ 二进制读写（base64） ============
    @JavascriptInterface
    public String readFileBase64(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "错误：文件不存在 " + path;
            if (!f.canRead()) return "错误：无读取权限";
            long len = f.length();
            if (len > 50L * 1024 * 1024) return "错误：文件超过 50MB，不建议 base64 读取";
            FileInputStream fis = new FileInputStream(f);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = fis.read(buf)) > 0) bos.write(buf, 0, n);
            fis.close();
            return Base64.encodeToString(bos.toByteArray(), Base64.NO_WRAP);
        } catch (Exception e) { return "读取失败：" + e.getMessage(); }
    }

    @JavascriptInterface
    public String writeFileBase64(String path, String base64) {
        try {
            File f = new File(path);
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            String clean = base64.replaceAll("\\s+", "");
            byte[] data = Base64.decode(clean, Base64.DEFAULT);
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(data);
            fos.close();
            return "写入成功：" + path + "（" + data.length + " 字节）";
        } catch (Exception e) { return "写入失败：" + e.getMessage(); }
    }

    // ============ 文件操作 ============
    @JavascriptInterface
    public String copyFile(String src, String dest) {
        try {
            File s = new File(src);
            File d = new File(dest);
            if (!s.exists()) return "错误：源不存在 " + src;
            if (s.isDirectory()) {
                if (!copyDir(s, d)) return "复制目录失败";
                return "复制成功：" + src + " → " + dest;
            }
            File parent = d.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            FileInputStream in = new FileInputStream(s);
            FileOutputStream out = new FileOutputStream(d);
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            in.close(); out.close();
            return "复制成功：" + src + " → " + dest;
        } catch (Exception e) { return "复制失败：" + e.getMessage(); }
    }

    private boolean copyDir(File src, File dest) {
        if (!dest.exists()) dest.mkdirs();
        File[] files = src.listFiles();
        if (files == null) return false;
        for (File f : files) {
            File target = new File(dest, f.getName());
            if (f.isDirectory()) { if (!copyDir(f, target)) return false; }
            else {
                try {
                    FileInputStream in = new FileInputStream(f);
                    FileOutputStream out = new FileOutputStream(target);
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
                    in.close(); out.close();
                } catch (Exception e) { return false; }
            }
        }
        return true;
    }

    @JavascriptInterface
    public String moveFile(String src, String dest) {
        try {
            File s = new File(src);
            File d = new File(dest);
            if (!s.exists()) return "错误：源不存在";
            File parent = d.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            if (s.renameTo(d)) return "移动成功：" + src + " → " + dest;
            String r = copyFile(src, dest);
            if (r.startsWith("复制成功")) {
                deleteRecursive(s);
                return "移动成功（跨分区）：" + src + " → " + dest;
            }
            return "移动失败：" + r;
        } catch (Exception e) { return "移动失败：" + e.getMessage(); }
    }

    @JavascriptInterface
    public String deleteFile(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "错误：不存在";
            if (deleteRecursive(f)) return "删除成功：" + path;
            return "删除失败";
        } catch (Exception e) { return "删除失败：" + e.getMessage(); }
    }

    private boolean deleteRecursive(File f) {
        if (f.isDirectory()) {
            File[] files = f.listFiles();
            if (files != null) for (File c : files) deleteRecursive(c);
        }
        return f.delete();
    }

    @JavascriptInterface
    public String mkdirs(String path) {
        try {
            File f = new File(path);
            if (f.exists()) return "已存在：" + path;
            if (f.mkdirs()) return "创建成功：" + path;
            return "创建失败";
        } catch (Exception e) { return "创建失败：" + e.getMessage(); }
    }

    // ============ 文件信息 ============
    @JavascriptInterface
    public String fileInfo(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "错误：文件不存在";
            StringBuilder sb = new StringBuilder();
            sb.append("路径: ").append(f.getAbsolutePath()).append("\n");
            sb.append("类型: ").append(f.isDirectory() ? "目录" : "文件").append("\n");
            sb.append("大小: ").append(f.length()).append(" 字节\n");
            sb.append("可读: ").append(f.canRead() ? "是" : "否").append("\n");
            sb.append("可写: ").append(f.canWrite() ? "是" : "否").append("\n");
            sb.append("修改时间: ").append(new java.util.Date(f.lastModified())).append("\n");
            if (f.isFile()) {
                String n = f.getName().toLowerCase();
                String type = "未知";
                if (n.endsWith(".txt") || n.endsWith(".md") || n.endsWith(".log")) type = "文本";
                else if (n.endsWith(".jpg") || n.endsWith(".jpeg")) type = "JPEG 图片";
                else if (n.endsWith(".png")) type = "PNG 图片";
                else if (n.endsWith(".gif")) type = "GIF 图片";
                else if (n.endsWith(".webp")) type = "WebP 图片";
                else if (n.endsWith(".mp4") || n.endsWith(".mkv")) type = "视频";
                else if (n.endsWith(".mp3") || n.endsWith(".m4a")) type = "音频";
                else if (n.endsWith(".apk")) type = "APK 安装包";
                else if (n.endsWith(".zip")) type = "ZIP";
                else if (n.endsWith(".dex")) type = "DEX 字节码";
                else if (n.endsWith(".so")) type = "原生库";
                else if (n.endsWith(".json")) type = "JSON";
                else if (n.endsWith(".xml")) type = "XML";
                else if (n.endsWith(".html") || n.endsWith(".htm")) type = "HTML";
                sb.append("推测类型: ").append(type).append("\n");
            }
            return sb.toString();
        } catch (Exception e) { return "获取信息失败：" + e.getMessage(); }
    }

    @JavascriptInterface
    public String listDirDetailed(String path) {
        try {
            File dir = new File(path);
            if (!dir.exists()) return "错误：目录不存在";
            if (!dir.isDirectory()) return "错误：不是目录";
            File[] files = dir.listFiles();
            if (files == null) return "错误：无法读取";
            Arrays.sort(files, (a, b) -> a.getName().compareToIgnoreCase(b.getName()));
            StringBuilder sb = new StringBuilder();
            long total = 0; int fc = 0, dc = 0;
            for (File f : files) {
                if (f.isDirectory()) {
                    dc++;
                    sb.append("[DIR]  ").append(f.getName()).append("/\n");
                } else {
                    fc++; total += f.length();
                    sb.append("[FILE] ").append(f.getName())
                      .append("  (").append(f.length()).append(" B)  ")
                      .append(new java.util.Date(f.lastModified())).append("\n");
                }
            }
            sb.append("\n共 ").append(dc).append(" 个目录，").append(fc).append(" 个文件，").append(total).append(" 字节\n");
            return sb.toString();
        } catch (Exception e) { return "读取失败：" + e.getMessage(); }
    }

    @JavascriptInterface
    public String listDir(String path) {
        try {
            File dir = new File(path);
            if (!dir.exists()) return "错误：目录不存在";
            if (!dir.isDirectory()) return "错误：不是目录";
            File[] files = dir.listFiles();
            if (files == null) return "错误：无法读取";
            StringBuilder sb = new StringBuilder();
            for (File f : files) {
                sb.append(f.isDirectory() ? "[目录] " : "[文件] ").append(f.getName());
                if (!f.isDirectory()) sb.append(" (").append(f.length()).append(" B)");
                sb.append("\n");
            }
            return sb.length() > 0 ? sb.toString() : "（空目录）";
        } catch (Exception e) { return "读取目录失败：" + e.getMessage(); }
    }

    @JavascriptInterface
    public boolean exists(String path) { return new File(path).exists(); }
}
