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

            /* [v132] 关键修复：Java TrustManager 读的是 /system/etc/security/cacerts，
               而该目录只读（remount 也失败）。可行路径是：
                 ① 证书写 /apex/com.android.conscrypt/cacerts（可写）
                 ② bind-mount /apex → /system（当前 namespace）
                 ③ 遍历所有进程 namespace 逐个 bind-mount（目标 App 才看得到）
               注意：已在运行的 App 的 TrustManager 已缓存 CA，必须重启该 App 才生效。 */
            String script =
                "SRC='" + src + "'\n" +
                "FILE='" + fileName + "'\n" +
                "APEX=/apex/com.android.conscrypt/cacerts\n" +
                "SYSD=/system/etc/security/cacerts\n" +
                "WROTE=0; BOUND=0; TOTAL=0\n" +
                "if [ -d \"$APEX\" ]; then\n" +
                "  cp \"$SRC\" \"$APEX/$FILE\" 2>/dev/null && chmod 644 \"$APEX/$FILE\" 2>/dev/null && WROTE=1\n" +
                "fi\n" +
                "if [ -d \"$SYSD\" ] && [ $WROTE -eq 1 ]; then\n" +
                "  cp \"$SRC\" \"$SYSD/$FILE\" 2>/dev/null && chmod 644 \"$SYSD/$FILE\" 2>/dev/null && WROTE=2\n" +
                "fi\n" +
                "if [ $WROTE -eq 1 ]; then\n" +
                "  mount --bind \"$APEX\" \"$SYSD\" 2>/dev/null && BOUND=$((BOUND+1))\n" +
                "  for pid in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do\n" +
                "    [ -d \"/proc/$pid/ns/mnt\" ] || continue\n" +
                "    TOTAL=$((TOTAL+1))\n" +
                "    nsenter -t $pid -m -- mount --bind \"$APEX\" \"$SYSD\" 2>/dev/null && BOUND=$((BOUND+1))\n" +
                "  done\n" +
                "fi\n" +
                "echo \"RESULT=$WROTE BOUND=$BOUND TOTAL=$TOTAL\"\n";

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
            /* 解析 RESULT=<写入方式> BOUND=<绑定成功数> TOTAL=<尝试数> */
            int wrote = 0, bound = 0;
            try {
                java.util.regex.Matcher m = java.util.regex.Pattern
                        .compile("RESULT=(\\d+) BOUND=(\\d+)").matcher(o);
                if (m.find()) { wrote = Integer.parseInt(m.group(1)); bound = Integer.parseInt(m.group(2)); }
            } catch (Throwable ig) {}
            if (wrote > 0 && bound > 0) {
                r.ok = true;
                r.message = "根证书已生效（绑定 " + bound + " 个进程）\n"
                        + "⚠ 已经在跑的 App 必须从后台彻底划掉再重开，否则它仍用旧的信任库缓存。";
            } else if (wrote > 0) {
                r.ok = true;
                r.message = "证书已写入，但 bind-mount 未成功（部分系统限制）。\n"
                        + "如仍解不出明文，请重启手机后再开一次「解密 HTTPS」。\n" + o.trim();
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
