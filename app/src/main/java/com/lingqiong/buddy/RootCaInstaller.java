package com.lingqiong.buddy;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * [v28] 把本机 MITM 根证书装进系统信任库（需 root）。
 *
 * 为什么必须装系统：Android 7+ 起，App 默认只信任「系统 CA」，用户自装证书
 * 不被信任。要让被抓的 App 接受我们签发的证书，只能把根证书放进系统信任库。
 *
 * 目录差异：
 *   · Android < 14 ：/system/etc/security/cacerts/
 *   · Android 14+ ：/apex/com.android.conscrypt/cacerts/（只读 apex，需 bind-mount 或 Magisk）
 *
 * 本类先用 su 直接尝试写入；失败则返回提示，让用户改用导出的证书手动安装。
 */
public class RootCaInstaller {

    public static class Result {
        public boolean ok;
        public boolean hasRoot;
        public String message = "";
    }

    private static final String FILE_NAME_HINT = "%s.0";

    /** 检测是否有 root（su 可用且能拿到 uid=0）。 */
    public static boolean hasRoot() {
        try {
            Process p = new ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line;
            StringBuilder sb = new StringBuilder();
            while ((line = br.readLine()) != null) sb.append(line);
            p.waitFor();
            return sb.toString().contains("uid=0");
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * 安装根证书到系统信任库。
     * @param ca 已生成的 MITM CA
     */
    public static Result install(Context ctx, MitmCa ca) {
        Result r = new Result();
        try {
            if (!hasRoot()) {
                r.ok = false;
                r.hasRoot = false;
                r.message = "未检测到 root 权限（su 不可用）";
                return r;
            }
            r.hasRoot = true;

            String pem = ca.caPem();
            String hash = ca.caHashName();
            String fileName = String.format(FILE_NAME_HINT, hash);

            // 1) 写到临时文件（su 可读）
            File tmp = new File(ctx.getCacheDir(), fileName);
            OutputStream os = new FileOutputStream(tmp);
            os.write(pem.getBytes(StandardCharsets.UTF_8));
            os.close();
            String src = tmp.getAbsolutePath();

            // 2) 生成安装脚本
            String script =
                "SRC='" + src + "'\n" +
                "FILE='" + fileName + "'\n" +
                "OK=0\n" +
                "mount -o rw,remount /system 2>/dev/null\n" +
                "mount -o rw,remount / 2>/dev/null\n" +
                "for D in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts; do\n" +
                "  if [ -d \"$D\" ]; then\n" +
                "    cp \"$SRC\" \"$D/$FILE\" 2>/dev/null && chmod 644 \"$D/$FILE\" 2>/dev/null && OK=1\n" +
                "  fi\n" +
                "done\n" +
                // Android 14+：apex 只读，尝试 bind mount 覆盖（部分环境可行）
                "if [ $OK -eq 0 ]; then\n" +
                "  if [ -d /apex/com.android.conscrypt/cacerts ]; then\n" +
                "    TMPD=/data/local/tmp/cacerts_mitm\n" +
                "    rm -rf \"$TMPD\"; mkdir -p \"$TMPD\"\n" +
                "    cp /apex/com.android.conscrypt/cacerts/* \"$TMPD/\" 2>/dev/null\n" +
                "    cp \"$SRC\" \"$TMPD/$FILE\" 2>/dev/null\n" +
                "    chmod 644 \"$TMPD/$FILE\" 2>/dev/null\n" +
                "    mount --bind \"$TMPD\" /apex/com.android.conscrypt/cacerts 2>/dev/null && OK=2\n" +
                "  fi\n" +
                "fi\n" +
                "echo \"RESULT=$OK\"\n";

            File sh = new File(ctx.getCacheDir(), "install_ca.sh");
            OutputStream so = new FileOutputStream(sh);
            so.write(script.getBytes(StandardCharsets.UTF_8));
            so.close();

            Process p = new ProcessBuilder("su", "-c", "sh " + sh.getAbsolutePath())
                    .redirectErrorStream(true).start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) out.append(line).append('\n');
            p.waitFor();

            String o = out.toString();
            if (o.contains("RESULT=1") || o.contains("RESULT=2")) {
                r.ok = true;
                r.message = "根证书已安装到系统信任库" + (o.contains("RESULT=2") ? "（bind-mount）" : "");
            } else {
                r.ok = false;
                r.message = "写入系统证书目录失败（系统分区只读）。已导出证书，可用 Magisk 模块或手动安装。\n" + o.trim();
            }
            return r;
        } catch (Throwable t) {
            r.ok = false;
            r.message = "安装异常：" + t;
            return r;
        }
    }

    /** 检测根证书是否已装进系统信任库（需 root）。 */
    public static boolean isInstalled(MitmCa ca) {
        try {
            String fileName = ca.caHashName() + ".0";
            String cmd = "[ -f /system/etc/security/cacerts/" + fileName + " ] && echo YES || "
                    + "( [ -f /apex/com.android.conscrypt/cacerts/" + fileName + " ] && echo YES || echo NO )";
            Process p = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line; StringBuilder sb = new StringBuilder();
            while ((line = br.readLine()) != null) sb.append(line);
            p.waitFor();
            return sb.toString().contains("YES");
        } catch (Throwable t) { return false; }
    }

    /** 导出根证书 PEM 到 /sdcard/LingQiongBuddy/mitm_ca.crt，便于手动安装。 */
    public static String exportPem(MitmCa ca) {
        try {
            File dir = new File("/sdcard/LingQiongBuddy");
            if (!dir.exists()) dir.mkdirs();
            File f = new File(dir, "mitm_ca.crt");
            OutputStream os = new FileOutputStream(f);
            os.write(ca.caPem().getBytes(StandardCharsets.UTF_8));
            os.close();
            return f.getAbsolutePath();
        } catch (Throwable t) {
            return null;
        }
    }
}
