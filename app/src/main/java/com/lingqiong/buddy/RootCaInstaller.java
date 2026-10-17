package com.lingqiong.buddy;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * [v71] 把本机 MITM 根证书装进系统信任库（需 root）。
 *
 * 为什么必须装系统：Android 7+ 起，App 默认只信任「系统 CA」，用户自装证书
 * 不被信任。要让被抓的 App 接受我们签发的证书，只能把根证书放进系统信任库。
 *
 * 目录差异：
 *   · Android < 14 ：/system/etc/security/cacerts/          （remount 后可写）
 *   · Android 14+  ：/apex/com.android.conscrypt/cacerts/   （只读 apex）
 *
 * ★ Android 14+ 的关键（v71 修正，之前是错的）：
 *   apex 是只读挂载，`cp` 一定失败；`mount --bind` 在 su 自己的 mount namespace 里
 *   做也没用 —— 系统和其它 App 各自在别的 namespace，根本看不到。
 *   正确做法是把证书目录做成 tmpfs 副本，然后**对 zygote 以及所有进程的
 *   mount namespace 逐个 bind-mount**。zygote 是关键：新启动的 App 都从它 fork，
 *   继承了 bind-mount，于是新开的 App 就能信任我们的 CA。
 *
 * 三种兜底（按成功率从高到低自动尝试）：
 *   A. 直接写（Android <14，或已 remount 的 ROM）
 *   B. tmpfs + 全 namespace bind-mount（Android 14+，临时生效，重启即还原）
 *   C. 写入 Magisk 模块目录（重启后仍生效，需用户重刷/重启加载）
 *
 * 注意：bind-mount 是**临时**的，重启后自动消失 —— 对「临时 root」正合适，不会留垃圾。
 */
public class RootCaInstaller {

    public static class Result {
        public boolean ok;
        public boolean hasRoot;
        public int mode;            // 0=失败 1=直接写 2=bind-mount 3=Magisk模块
        public String message = "";
        public String detail = "";
    }

    private static final String APEX_DIR = "/apex/com.android.conscrypt/cacerts";
    private static final String SYS_DIR  = "/system/etc/security/cacerts";
    private static final String TMP_DIR  = "/data/local/tmp/lq_cacerts";
    private static final String MAGISK_MOD = "/data/adb/modules/lq_mitm_ca";

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

    /** 安装根证书到系统信任库。 */
    public static Result install(Context ctx, MitmCa ca) {
        Result r = new Result();
        try {
            if (!hasRoot()) {
                r.ok = false;
                r.hasRoot = false;
                r.message = "未检测到 root 权限（su 不可用）。已导出证书，可用「设置 → 安全 → 安装证书」手动装（系统级仍需 root）。";
                return r;
            }
            r.hasRoot = true;

            String pem  = ca.caPem();
            String hash = ca.caHashName();
            String fileName = hash + ".0";

            // 证书放到 su 可读的位置
            File tmp = new File(ctx.getCacheDir(), fileName);
            OutputStream os = new FileOutputStream(tmp);
            os.write(pem.getBytes(StandardCharsets.UTF_8));
            os.close();
            String src = tmp.getAbsolutePath();

            String script = buildScript(src, fileName);
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
            r.detail = o.trim();
            if (o.contains("RESULT=1")) {
                r.ok = true; r.mode = 1;
                r.message = "根证书已写入系统证书目录（永久）。如需撤销，删除该文件后重启。";
            } else if (o.contains("RESULT=2")) {
                r.ok = true; r.mode = 2;
                r.message = "根证书已生效（bind-mount，临时）。"
                        + "★ 请把要抓的 App 从后台彻底划掉再重新打开，否则它还用着旧证书缓存。"
                        + "重启手机后失效，重装 APK 后需重新点一次。";
            } else if (o.contains("RESULT=3")) {
                r.ok = true; r.mode = 3;
                r.message = "已写入 Magisk 模块（" + MAGISK_MOD + "）。重启手机后生效。";
            } else {
                r.ok = false;
                r.message = "自动安装失败（系统限制）。已导出证书，可改用 Magisk 模块或手动安装。\n" + o.trim();
            }
            return r;
        } catch (Throwable t) {
            r.ok = false;
            r.message = "安装异常：" + t;
            return r;
        }
    }

    /** 生成安装脚本（严格按 A→B→C 顺序兜底）。 */
    private static String buildScript(String src, String fileName) {
        StringBuilder s = new StringBuilder();
        s.append("SRC='").append(src).append("'\n");
        s.append("FILE='").append(fileName).append("'\n");
        s.append("APEX=").append(APEX_DIR).append("\n");
        s.append("SYS=").append(SYS_DIR).append("\n");
        s.append("TMP=").append(TMP_DIR).append("\n");
        s.append("MOD=").append(MAGISK_MOD).append("\n");
        s.append("DETAIL=''\n");
        s.append("OK=0\n");
        // ---- A: 直接写 ----
        s.append("mount -o rw,remount /system 2>/dev/null\n");
        s.append("mount -o rw,remount / 2>/dev/null\n");
        s.append("for D in \"$SYS\" \"$APEX\"; do\n");
        s.append("  [ -d \"$D\" ] || continue\n");
        s.append("  if cp -f \"$SRC\" \"$D/$FILE\" 2>/dev/null; then\n");
        s.append("    chmod 644 \"$D/$FILE\" 2>/dev/null\n");
        s.append("    chown root:root \"$D/$FILE\" 2>/dev/null\n");
        s.append("    chcon u:object_r:system_file:s0 \"$D/$FILE\" 2>/dev/null\n");
        s.append("    OK=1; DETAIL=\"$DETAIL 直接写入 $D;\"\n");
        s.append("  fi\n");
        s.append("done\n");
        // ---- B: Android 14+ tmpfs + 全 namespace bind-mount ----
        s.append("if [ \"$OK\" -eq 0 ] && [ -d \"$APEX\" ]; then\n");
        s.append("  umount \"$TMP\" 2>/dev/null\n");
        s.append("  rm -rf \"$TMP\"; mkdir -p \"$TMP\" 2>/dev/null\n");
        s.append("  if mount -t tmpfs -o mode=755 tmpfs \"$TMP\" 2>/dev/null; then\n");
        s.append("    cp -f \"$APEX\"/* \"$TMP\"/ 2>/dev/null\n");
        s.append("    cp -f \"$SRC\" \"$TMP/$FILE\" 2>/dev/null\n");
        s.append("    chmod 644 \"$TMP\"/* 2>/dev/null\n");
        s.append("    chown root:root \"$TMP\"/* 2>/dev/null\n");
        s.append("    chcon -R u:object_r:system_file:s0 \"$TMP\" 2>/dev/null\n");
        s.append("    N=$(ls \"$TMP\" 2>/dev/null | wc -l)\n");
        s.append("    DETAIL=\"$DETAIL tmpfs 内证书 $N 个;\"\n");
        // zygote 优先（新 App 从这里 fork）
        s.append("    ZN=0\n");
        s.append("    for z in $(ps -A -o PID,NAME 2>/dev/null | grep -E 'zygote' | awk '{print $1}'); do\n");
        s.append("      if nsenter -t \"$z\" -m -- mount --bind \"$TMP\" \"$APEX\" 2>/dev/null; then ZN=$((ZN+1)); fi\n");
        s.append("    done\n");
        s.append("    DETAIL=\"$DETAIL zygote 已绑 $ZN 个;\"\n");
        // 全量进程
        s.append("    CNT=0\n");
        s.append("    for pd in /proc/[0-9]*; do\n");
        s.append("      pid=${pd#/proc/}\n");
        s.append("      if nsenter -t \"$pid\" -m -- mount --bind \"$TMP\" \"$APEX\" 2>/dev/null; then CNT=$((CNT+1)); fi\n");
        s.append("    done\n");
        s.append("    DETAIL=\"$DETAIL 共绑定 $CNT 个进程命名空间;\"\n");
        s.append("    if [ $((ZN+CNT)) -gt 0 ]; then OK=2; fi\n");
        s.append("  else\n");
        s.append("    DETAIL=\"$DETAIL tmpfs 挂载失败;\"\n");
        s.append("  fi\n");
        s.append("fi\n");
        // ---- C: Magisk 模块 ----
        s.append("if [ \"$OK\" -eq 0 ] && [ -d /data/adb/modules ]; then\n");
        s.append("  mkdir -p \"$MOD/system/etc/security/cacerts\" 2>/dev/null\n");
        s.append("  cp -f \"$SRC\" \"$MOD/system/etc/security/cacerts/$FILE\" 2>/dev/null && OK=3\n");
        s.append("  chmod 644 \"$MOD/system/etc/security/cacerts/$FILE\" 2>/dev/null\n");
        s.append("  printf 'id=lq_mitm_ca\\nname=LQ MITM CA\\nversion=1\\nversionCode=1\\nauthor=LingQiongBuddy\\ndescription=Trust LingQiongBuddy MITM root CA\\n' > \"$MOD/module.prop\" 2>/dev/null\n");
        s.append("  DETAIL=\"$DETAIL Magisk 模块已写入（需重启生效）;\"\n");
        s.append("fi\n");
        s.append("echo \"RESULT=$OK\"\n");
        s.append("echo \"DETAIL=$DETAIL\"\n");
        return s.toString();
    }

    /** 检测根证书当前是否已在系统信任库中可见。 */
    public static boolean isInstalled(MitmCa ca) {
        try {
            String fileName = ca.caHashName() + ".0";
            String cmd = "[ -f " + SYS_DIR + "/" + fileName + " ] && echo YES || "
                    + "( [ -f " + APEX_DIR + "/" + fileName + " ] && echo YES || "
                    + "( [ -f " + MAGISK_MOD + "/system/etc/security/cacerts/" + fileName + " ] && echo YES || echo NO ) )";
            Process p = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line; StringBuilder sb = new StringBuilder();
            while ((line = br.readLine()) != null) sb.append(line);
            p.waitFor();
            return sb.toString().contains("YES");
        } catch (Throwable t) { return false; }
    }

    /** 撤销临时 bind-mount（重启也会自动还原）。 */
    public static boolean uninstall() {
        try {
            String cmd = "umount " + APEX_DIR + " 2>/dev/null; umount " + TMP_DIR + " 2>/dev/null; "
                    + "rm -f " + MAGISK_MOD + "/system/etc/security/cacerts/*.0 2>/dev/null; "
                    + "rm -rf " + MAGISK_MOD + " 2>/dev/null; echo DONE";
            Process p = new ProcessBuilder("su", "-c", cmd).redirectErrorStream(true).start();
            p.waitFor();
            return true;
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
