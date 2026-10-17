package com.lingqiong.buddy;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/**
 * [v72] 把本机 MITM 根证书装进系统信任库（需 root）。
 *
 * 为什么必须装系统：Android 7+ 起，App 默认只信任「系统 CA」，用户自装证书不被信任。
 * 要让被抓的 App 接受我们签发的证书，只能把根证书放进系统信任库。
 *
 * 目录差异：
 * · Android < 14 ：/system/etc/security/cacerts/ （remount 后可写）
 * · Android 14+ ：/apex/com.android.conscrypt/cacerts/ （只读 apex，`cp` 必失败）
 *
 * ============================================================================
 * ★ v72 修的两个致命问题（用户实测「点了安装就卡住、黑屏」的真凶）
 * ============================================================================
 * 问题 1：su 调用【没有超时】
 *   旧版 hasRoot()/isInstalled() = new ProcessBuilder("su","-c","id") + p.waitFor()。
 *   KernelSU / Magisk / APatch 首次授权会弹确认框并等用户点；用户没点、或 su 在
 *   当前 App 的 namespace 里被隐藏，waitFor() 就【永久阻塞】。
 *   这个调用发生在 @JavascriptInterface 里 → 阻塞 WebView 的 JS 线程 → 整个界面
 *   卡死（这就是「点了直接卡住，动不了」）。
 *   修：① 多路径探测 su 绝对路径（KernelSU 是 /system/bin/su，APatch 是
 *        /data/adb/ap/bin/su，Magisk 可能是 /debug_ramdisk/su）；
 *       ② 统一走 suRun(cmd, timeoutMs)，waitFor 带超时，超时 destroyForcibly；
 *       ③ 结果缓存，避免每次 caStatus() 都去 fork 一次 su。
 *
 * 问题 2：装证书对【全量进程】逐个 bind-mount
 *   旧脚本 `for pd in /proc/[0-9]*; do nsenter -t $pid -m -- mount --bind ...`。
 *   本机实测 1404 个进程 → fork 出 2800+ 个 nsenter/mount 进程，而且每次 mount 都要
 *   拿内核 mount 锁 → 整机 CPU 与锁竞争饱和 → 卡死、掉帧、甚至黑屏。
 *   修：只绑 zygote（zygote64 / zygote / webview_zygote）——新启动的 App 都从 zygote
 *   fork，会继承 bind-mount；再加当前 App 自己。最多 20 个目标，每个 `timeout 3`。
 *   正在运行的 App 需要「从后台划掉再打开」才生效，这一点在返回文案里已说明。
 *
 * 注意：bind-mount 是**临时**的，重启后自动消失 —— 对「临时 root」正合适。
 */
public class RootCaInstaller {

    public static class Result {
        public boolean ok;
        public boolean hasRoot;
        public int mode; // 0=失败 1=直接写 2=bind-mount 3=Magisk模块
        public String message = "";
        public String detail = "";
    }

    private static final String APEX_DIR = "/apex/com.android.conscrypt/cacerts";
    private static final String SYS_DIR = "/system/etc/security/cacerts";
    private static final String TMP_DIR = "/data/local/tmp/lq_cacerts";
    private static final String MAGISK_MOD = "/data/adb/modules/lq_mitm_ca";

    /** su 的常见位置，按「本机实际优先」排序。最后一项交给 PATH 兜底。 */
    private static final String[] SU_CANDIDATES = {
            "/system/bin/su",            // KernelSU / 多数 ROM
            "/debug_ramdisk/su",         // Magisk
            "/data/adb/ksu/bin/su",      // KernelSU（老版本）
            "/data/adb/ap/bin/su",       // APatch
            "/data/adb/magisk/su",       // Magisk（老）
            "/system/xbin/su",
            "/sbin/su",
            "su"                         // 交给 PATH
    };

    private static volatile String suPathCache = null;
    private static volatile boolean rootCache = false;
    private static volatile long rootCacheAt = 0L;
    private static final long ROOT_CACHE_MS = 60_000L; // hasRoot 结果缓存 60 秒

    /** 探测可用的 su 绝对路径（缓存）。找不到返回 null。 */
    public static String suPath() {
        String c = suPathCache;
        if (c != null) return c.isEmpty() ? null : c;
        for (String p : SU_CANDIDATES) {
            try {
                if (!p.startsWith("/")) { // "su"：交给 PATH，先放着，最后再试
                    continue;
                }
                if (new File(p).exists()) {
                    suPathCache = p;
                    return p;
                }
            } catch (Throwable ignored) {
            }
        }
        // 绝对路径都没找到：退回 PATH 里的 su（Termux 自带的占位 su 也会命中，
        // 但下面 suRun 会因为它返回非 uid=0 而正确判定为「无 root」）
        suPathCache = "su";
        return "su";
    }

    /**
     * 统一执行 su 命令。【带超时，绝不永久阻塞】。
     *
     * ★ API 24 兼容：不能直接用 Process.waitFor(timeout, TimeUnit) 与 destroyForcibly()
     *   —— 这两个都是 API 26 才加入的，在 Android 7.x 上会抛 NoSuchMethodError。
     *   这里改成「后台线程读输出 + 主循环轮询 exitValue()」的经典写法，
     *   只用 Process.exitValue() / Process.destroy() / Thread.sleep()，API 1 就有。
     *
     * @return 合并后的 stdout+stderr；超时会在末尾追加 [TIMEOUT xxxms]。
     */
    public static String suRun(String cmd, int timeoutMs) {
        Process p = null;
        final StringBuilder sb = new StringBuilder();
        Thread reader = null;
        try {
            String su = suPath();
            p = new ProcessBuilder(su, "-c", cmd).redirectErrorStream(true).start();
            final Process fp = p;
            // 必须在后台线程读，否则管道写满 4KB 后子进程会阻塞 → 假死
            reader = new Thread(new Runnable() {
                public void run() {
                    BufferedReader br = null;
                    try {
                        br = new BufferedReader(new InputStreamReader(fp.getInputStream()));
                        String line;
                        while ((line = br.readLine()) != null) {
                            synchronized (sb) {
                                sb.append(line).append('\n');
                                if (sb.length() > 200_000) break; // 防异常输出撑爆内存
                            }
                        }
                    } catch (Throwable ignored) {
                    } finally {
                        try { if (br != null) br.close(); } catch (Throwable ignored) {}
                    }
                }
            }, "lq-su-reader");
            reader.setDaemon(true);
            reader.start();

            // 轮询退出（API 24 兼容的超时等待）
            long deadline = System.currentTimeMillis() + Math.max(500, timeoutMs);
            boolean done = false;
            while (System.currentTimeMillis() < deadline) {
                try {
                    p.exitValue(); // 进程已退出 → 返回退出码
                    done = true;
                    break;
                } catch (IllegalThreadStateException stillRunning) {
                    try { Thread.sleep(50); } catch (Throwable ignored) {}
                }
            }
            if (!done) {
                try { p.destroy(); } catch (Throwable ignored) {}
                try { reader.join(300); } catch (Throwable ignored) {}
                synchronized (sb) {
                    return sb.toString() + "\n[TIMEOUT " + timeoutMs + "ms]";
                }
            }
            try { reader.join(400); } catch (Throwable ignored) {} // 收尾读完剩余输出
            synchronized (sb) {
                return sb.toString();
            }
        } catch (Throwable t) {
            try { if (p != null) p.destroy(); } catch (Throwable ignored) {}
            return "";
        }
    }

    /** 检测是否有 root（su 可用且能拿到 uid=0）。【带超时 + 60 秒缓存】。 */
    public static boolean hasRoot() {
        long now = System.currentTimeMillis();
        if (now - rootCacheAt < ROOT_CACHE_MS && rootCacheAt > 0) return rootCache;
        boolean ok = false;
        try {
            // 3 秒足够：超时说明「su 在等授权」或「没有 su」，两种情况都按不可用处理，
            // 绝不能像旧版那样无限等下去。
            String out = suRun("id", 3000);
            ok = out.contains("uid=0");
            if (!ok && out.contains("[TIMEOUT")) {
                // su 存在但等授权：仍视为「有 root，只是没授权」，交给上层提示用户去授权
                ok = false;
            }
        } catch (Throwable ignored) {
            ok = false;
        }
        rootCache = ok;
        rootCacheAt = now;
        return ok;
    }

    /** 强制刷新 root 缓存（用户去授权后点「重新检测」时用）。 */
    public static void resetRootCache() {
        rootCacheAt = 0L;
        suPathCache = null;
    }

    /** 安装根证书到系统信任库。 */
    public static Result install(Context ctx, MitmCa ca) {
        Result r = new Result();
        try {
            if (!hasRoot()) {
                r.ok = false;
                r.hasRoot = false;
                String su = suPath();
                r.message = "未检测到 root 权限（su 不可用或未授权）。"
                        + "\n· 若你已 root（KernelSU/Magisk/APatch），请到 root 管理器里"
                        + "把「凌穹伙伴」加入允许列表，回来点「重新检测」。"
                        + "\n· 可用「导出证书」后到 设置 → 安全 → 安装证书 手动装（系统级仍需 root）。"
                        + "\n（探测路径：" + (su == null ? "无" : su) + "）";
                return r;
            }
            r.hasRoot = true;

            String pem = ca.caPem();
            String hash = ca.caHashName();
            String fileName = hash + ".0";

            // 证书放到 App 私有缓存（root 可读），再把脚本也放这里
            File tmp = new File(ctx.getCacheDir(), fileName);
            OutputStream os = new FileOutputStream(tmp);
            os.write(pem.getBytes(StandardCharsets.UTF_8));
            os.close();
            String src = tmp.getAbsolutePath();

            // 脚本同样需要 root 可读
            String script = buildScript(src, fileName);
            File sh = new File(ctx.getCacheDir(), "install_ca.sh");
            OutputStream so = new FileOutputStream(sh);
            so.write(script.getBytes(StandardCharsets.UTF_8));
            so.close();

            // ★ 45 秒上限：旧版这里是无限等待，装 1404 个进程时会卡到天荒地老
            String o = suRun("sh " + sh.getAbsolutePath(), 45000);
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
            } else if (o.contains("[TIMEOUT")) {
                r.ok = false;
                r.message = "安装超时（45 秒）。可能 su 授权未点，或系统繁忙。"
                        + "\n请到 root 管理器确认已授权，再重试一次。\n" + o.trim();
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

        // ---- A: 直接写（Android <14，或已 remount 的 ROM）----
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

        // ---- B: Android 14+ tmpfs + 【只绑 zygote 与自身】bind-mount ----
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
        // ★ 关键改动：只挑 zygote 系列 + 本 App，绝不全量遍历 /proc
        s.append("    TP=$(ps -A -o PID,NAME 2>/dev/null | grep -E 'zygote|com.lq.app' | awk '{print $1}' | head -20)\n");
        s.append("    ZN=0\n");
        s.append("    for z in $TP; do\n");
        s.append("      timeout 3 nsenter -t \"$z\" -m -- mount --bind \"$TMP\" \"$APEX\" 2>/dev/null && ZN=$((ZN+1))\n");
        s.append("    done\n");
        s.append("    DETAIL=\"$DETAIL 已绑定 $ZN 个目标命名空间（zygote/自身）;\"\n");
        s.append("    if [ \"$ZN\" -gt 0 ]; then OK=2; fi\n");
        s.append("  else\n");
        s.append("    DETAIL=\"$DETAIL tmpfs 挂载失败;\"\n");
        s.append("  fi\n");
        s.append("fi\n");

        // ---- C: Magisk 模块（重启后仍生效）----
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

    /** 检测根证书当前是否已在系统信任库中可见。【带超时 + 缓存】。 */
    public static boolean isInstalled(MitmCa ca) {
        try {
            String fileName = ca.caHashName() + ".0";
            String cmd = "[ -f " + SYS_DIR + "/" + fileName + " ] && echo YES || "
                    + "( [ -f " + APEX_DIR + "/" + fileName + " ] && echo YES || "
                    + "( [ -f " + MAGISK_MOD + "/system/etc/security/cacerts/" + fileName + " ] && echo YES || echo NO ) )";
            return suRun(cmd, 4000).contains("YES");
        } catch (Throwable t) {
            return false;
        }
    }

    /** 撤销临时 bind-mount（重启也会自动还原）。 */
    public static boolean uninstall() {
        try {
            String cmd = "umount " + APEX_DIR + " 2>/dev/null; umount " + TMP_DIR + " 2>/dev/null; "
                    + "rm -f " + MAGISK_MOD + "/system/etc/security/cacerts/*.0 2>/dev/null; "
                    + "rm -rf " + MAGISK_MOD + " 2>/dev/null; echo DONE";
            suRun(cmd, 8000);
            return true;
        } catch (Throwable t) {
            return false;
        }
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
