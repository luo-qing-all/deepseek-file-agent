package com.example.deepseek;

import android.content.Context;
import android.util.Base64;
import android.webkit.JavascriptInterface;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class FileBridge {

    private final Context context;
    private static final int BUF = 8192;

    public FileBridge(Context context) { this.context = context; }

    /* ==================== 文本读写 ==================== */

    @JavascriptInterface
    public String readFile(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "文件不存在：" + path;
            if (f.isDirectory()) return "这是一个目录，请改用 list_dir：" + path;
            if (!f.canRead()) return "无读取权限：" + path;
            byte[] data = readAll(f);
            return new String(data, StandardCharsets.UTF_8);
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
            return "写入成功：" + path + "（" + f.length() + " 字节）";
        } catch (Exception e) { return "写入失败：" + e.getMessage(); }
    }

    /* ==================== Base64 二进制读写 ==================== */

    @JavascriptInterface
    public String readFileBase64(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "文件不存在：" + path;
            if (f.isDirectory()) return "这是一个目录，无法按文件读取：" + path;
            if (!f.canRead()) return "无读取权限：" + path;
            byte[] data = readAll(f);
            return Base64.encodeToString(data, Base64.NO_WRAP);
        } catch (Exception e) { return "读取失败：" + e.getMessage(); }
    }

    @JavascriptInterface
    public String writeFileBase64(String path, String base64) {
        try {
            File f = new File(path);
            File parent = f.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            // 去掉可能存在的空白字符，避免解码失败
            String clean = base64 == null ? "" : base64.replaceAll("\\s", "");
            byte[] data = Base64.decode(clean, Base64.DEFAULT);
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(data);
            fos.close();
            return "写入成功：" + path + "（" + data.length + " 字节）";
        } catch (Exception e) { return "写入失败：" + e.getMessage(); }
    }

    /* ==================== 复制 / 移动 ==================== */

    @JavascriptInterface
    public String copyFile(String src, String dest) {
        try {
            File srcF = new File(src);
            if (!srcF.exists()) return "源不存在：" + src;
            File destF = new File(dest);
            // 目标若是一个已存在的目录，则把源复制进该目录（保持原名）
            if (destF.exists() && destF.isDirectory()) destF = new File(destF, srcF.getName());

            if (destF.exists()) {
                if (destF.isDirectory()) deleteRecursive(destF);
                else if (!destF.delete()) return "复制失败：目标已存在且无法覆盖：" + destF.getAbsolutePath();
            }

            copyRecursive(srcF, destF);
            return "复制成功：" + srcF.getAbsolutePath() + " -> " + destF.getAbsolutePath();
        } catch (Exception e) { return "复制失败：" + e.getMessage(); }
    }

    @JavascriptInterface
    public String moveFile(String src, String dest) {
        try {
            File srcF = new File(src);
            if (!srcF.exists()) return "源不存在：" + src;
            File destF = new File(dest);
            if (destF.exists() && destF.isDirectory()) destF = new File(destF, srcF.getName());

            if (srcF.getAbsolutePath().equals(destF.getAbsolutePath())) return "移动成功（源与目标同一路径）：" + destF.getAbsolutePath();

            File parent = destF.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();

            // 优先尝试原子重命名
            if (srcF.renameTo(destF)) {
                return "移动成功：" + srcF.getAbsolutePath() + " -> " + destF.getAbsolutePath();
            }

            // 跨分区等场景：复制后删除
            if (destF.exists()) {
                if (destF.isDirectory()) deleteRecursive(destF);
                else destF.delete();
            }
            copyRecursive(srcF, destF);
            deleteRecursive(srcF);
            return "移动成功（复制后删除）：" + srcF.getAbsolutePath() + " -> " + destF.getAbsolutePath();
        } catch (Exception e) { return "移动失败：" + e.getMessage(); }
    }

    /* ==================== 目录 ==================== */

    @JavascriptInterface
    public String mkdirs(String path) {
        try {
            File dir = new File(path);
            if (dir.exists()) {
                if (dir.isDirectory()) return "目录已存在：" + path;
                return "创建失败：同名文件已存在：" + path;
            }
            if (dir.mkdirs()) return "创建成功：" + path;
            return "创建失败：" + path;
        } catch (Exception e) { return "创建失败：" + e.getMessage(); }
    }

    @JavascriptInterface
    public String listDir(String path) {
        try {
            File dir = new File(path);
            if (!dir.exists()) return "目录不存在：" + path;
            if (!dir.isDirectory()) return "不是目录：" + path;
            File[] files = dir.listFiles();
            if (files == null) return "无法列出目录（权限不足）：" + path;
            StringBuilder sb = new StringBuilder();
            for (File f : files) {
                sb.append(f.isDirectory() ? "[DIR] " : "[FILE] ").append(f.getName());
                if (!f.isDirectory()) sb.append(" (").append(f.length()).append(" B)");
                sb.append("\n");
            }
            return sb.length() > 0 ? sb.toString() : "(空目录)";
        } catch (Exception e) { return "列目录失败：" + e.getMessage(); }
    }

    @JavascriptInterface
    public String listDirDetailed(String path) {
        try {
            File dir = new File(path);
            if (!dir.exists()) return "目录不存在：" + path;
            if (!dir.isDirectory()) return "不是目录：" + path;
            File[] files = dir.listFiles();
            if (files == null) return "无法列出目录（权限不足）：" + path;
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
            StringBuilder sb = new StringBuilder();
            for (File f : files) {
                sb.append(f.isDirectory() ? "[DIR]  " : "[FILE] ");
                sb.append(f.isDirectory() ? pad(f.getName(), 28) : pad(f.getName(), 28));
                sb.append("  ");
                sb.append(f.isDirectory() ? "-" : humanSize(f.length()));
                sb.append("  ");
                sb.append(sdf.format(new Date(f.lastModified())));
                sb.append("\n");
            }
            return sb.length() > 0 ? sb.toString() : "(空目录)";
        } catch (Exception e) { return "列目录失败：" + e.getMessage(); }
    }

    /* ==================== 删除 ==================== */

    @JavascriptInterface
    public String deleteFile(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "文件不存在：" + path;
            boolean ok = deleteRecursive(f);
            return ok ? ("已删除：" + path) : ("删除失败：" + path);
        } catch (Exception e) { return "删除失败：" + e.getMessage(); }
    }

    /* ==================== 详情 ==================== */

    @JavascriptInterface
    public String fileInfo(String path) {
        try {
            File f = new File(path);
            if (!f.exists()) return "文件不存在：" + path;
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
            StringBuilder sb = new StringBuilder();
            sb.append("路径: ").append(f.getAbsolutePath()).append("\n");
            sb.append("类型: ").append(f.isDirectory() ? "目录" : "文件").append("\n");
            sb.append("大小: ").append(humanSize(f.length())).append(" (").append(f.length()).append(" 字节)").append("\n");
            sb.append("修改时间: ").append(sdf.format(new Date(f.lastModified()))).append("\n");
            sb.append("可读: ").append(f.canRead() ? "是" : "否").append("\n");
            sb.append("可写: ").append(f.canWrite() ? "是" : "否").append("\n");
            sb.append("可执行: ").append(f.canExecute() ? "是" : "否");
            return sb.toString();
        } catch (Exception e) { return "获取失败：" + e.getMessage(); }
    }

    @JavascriptInterface
    public boolean exists(String path) { return new File(path).exists(); }

    /* ==================== 内部工具 ==================== */

    private static byte[] readAll(File f) throws Exception {
        InputStream in = new FileInputStream(f);
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.max(BUF, (int) Math.min(f.length(), 1 << 20)));
            byte[] buf = new byte[BUF];
            int n;
            while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        } finally { in.close(); }
    }

    private static void copyRecursive(File src, File dest) throws Exception {
        if (src.isDirectory()) {
            if (!dest.exists() && !dest.mkdirs()) throw new Exception("无法创建目录：" + dest.getAbsolutePath());
            File[] children = src.listFiles();
            if (children != null) {
                for (File c : children) copyRecursive(c, new File(dest, c.getName()));
            }
        } else {
            File parent = dest.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            InputStream in = new FileInputStream(src);
            OutputStream out = new FileOutputStream(dest);
            try {
                byte[] buf = new byte[BUF];
                int n;
                while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
            } finally {
                try { in.close(); } catch (Exception ignore) {}
                try { out.close(); } catch (Exception ignore) {}
            }
        }
    }

    private static boolean deleteRecursive(File f) {
        if (f.isDirectory()) {
            File[] children = f.listFiles();
            if (children != null) {
                for (File c : children) deleteRecursive(c);
            }
        }
        return f.delete();
    }

    private static String humanSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format(Locale.US, "%.1f KB", bytes / 1024.0);
        if (bytes < 1024L * 1024 * 1024) return String.format(Locale.US, "%.1f MB", bytes / 1024.0 / 1024.0);
        return String.format(Locale.US, "%.2f GB", bytes / 1024.0 / 1024.0 / 1024.0);
    }

    private static String pad(String s, int len) {
        if (s == null) s = "";
        if (s.length() >= len) return s;
        StringBuilder sb = new StringBuilder(s);
        while (sb.length() < len) sb.append(' ');
        return sb.toString();
    }
}
