package com.lingqiong.buddy;

import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.system.Os;
import android.system.OsConstants;
import android.webkit.JavascriptInterface;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 自包含的 Termux 终端环境（不依赖外部 Termux App，且可与官方 Termux 共存）。
 *
 * ── 为什么能"删掉 Termux 也能用" && "与官方 Termux 共存" ──────────
 * Termux bootstrap 里每个二进制的库搜索路径(RUNPATH)都被编译期硬编码成
 *     /data/data/com.termux/files/usr/lib
 * 因此在 CI 打包阶段，会把 bootstrap 里所有 "com.termux" 等长替换成本 App 的
 * applicationId（例如 com.lq.app，两者同为 10 字节，ELF 字符串偏移不变）。
 * 于是本 App 的 getFilesDir() == /data/data/<applicationId>/files 就是这套
 * 环境的真实位置：
 *     · 环境完全属于本 App，删掉官方 Termux 也不影响；
 *     · applicationId ≠ com.termux，因此与官方 Termux 可以并存，互不干扰。
 *
 * ── 为什么 targetSdk 必须是 28 ────────────────────────────────
 * Android 10(Q) 起，只对 targetSdk >= 29 的应用禁止"从 App 私有目录执行二进制"
 * (W^X 策略)。targetSdk 28 可豁免，Termux 官方同样如此。
 *
 * ── 多环境（完全隔离）────────────────────────────────────────
 * 硬编码的库路径只有一份 /data/data/<pkg>/files/usr，因此这里用"软链激活"实现
 * 多个互相独立的软件库：
 *     files/envs/<id>/usr     每个环境一套完整 bootstrap（独立软件包）
 *     files/envs/<id>/home    每个环境独立 HOME
 *     files/usr               指向"当前激活环境"usr 的符号链接
 * 执行命令前把软链指向目标环境，二进制便自然加载该环境自己的库，
 * 于是各环境可以 pkg install 出不同版本的软件（如不同 Python）。
 * 同一时刻只有一个环境被"激活"（AI 单对话场景足够）。
 *
 * ── 为什么要"异步执行"───────────────────────────────────────
 * WebView 的 @JavascriptInterface 方法运行在 JS 线程上。若在这里同步
 * waitFor()，一旦命令长时间不返回（pkg install / 交互式 / 卡死），整个网页
 * 线程会被冻结：按钮失灵、无法滚动（但原生输入框光标仍在闪）。
 * 因此这里改成 execStart(返回任务号) + execPoll(轮询) 的异步模型，并带超时兜底。
 */
public class TermuxBridge {

    private final Context context;

    private static final AtomicBoolean INSTALLING = new AtomicBoolean(false);
    private static volatile String installLog = "尚未安装";
    private static volatile int installPercent = 0;

    /** 软链切换 / 进程启动的互斥锁，避免两个环境同时激活。 */
    private static final Object LOCK = new Object();

    private static final ConcurrentHashMap<String, Task> TASKS = new ConcurrentHashMap<>();
    private static long TASK_SEQ = 0;

    /** 单条命令默认超时（毫秒）。超时后强制结束，避免无限挂起。 */
    private static final long DEFAULT_TIMEOUT_MS = 600_000L;
    /** 单次执行保留的最大输出字符数，防止超大输出撑爆内存。 */
    private static final int MAX_OUT = 400_000;

    public TermuxBridge(Context context) { this.context = context; }

    /* ==================== 路径 ==================== */

    private File filesDir() { return context.getFilesDir(); }
    private File envsDir() { return new File(filesDir(), "envs"); }
    private File envUsr(String id) { return new File(envsDir(), id + "/usr"); }
    private File envHomeDir(String id) { return new File(envsDir(), id + "/home"); }
    /** files/usr —— 指向当前激活环境 usr 的软链（也是二进制硬编码的那条路径）。 */
    private File activeLink() { return new File(filesDir(), "usr"); }
    private String prefix() { return activeLink().getAbsolutePath(); }

    /** 只允许安全字符，避免路径穿越。 */
    private static String safeId(String id) {
        if (id == null) return "default";
        String s = id.trim().replaceAll("[^a-zA-Z0-9_.-]", "_");
        return s.isEmpty() ? "default" : s;
    }

    public boolean isReady() { return new File(activeLink(), "bin/sh").exists(); }

    private static boolean isSymlink(File f) {
        try { return OsConstants.S_ISLNK(Os.lstat(f.getAbsolutePath()).st_mode); }
        catch (Throwable t) { return false; }
    }

    private static String readLink(File f) {
        try { return Os.readlink(f.getAbsolutePath()); } catch (Throwable t) { return null; }
    }

    private static String archName() {
        String abi = (Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0)
                ? Build.SUPPORTED_ABIS[0] : "arm64-v8a";
        if (abi.contains("arm64")) return "aarch64";
        if (abi.contains("armeabi")) return "arm";
        if (abi.contains("x86_64")) return "x86_64";
        if (abi.contains("x86")) return "i686";
        return "aarch64";
    }

    /* ==================== 激活某个环境（改软链） ==================== */

    /**
     * 让 files/usr 软链指向 envUsr(id)。
     * 若发现 files/usr 还是旧版的"真实目录"，会先把它迁移成 default 环境。
     */
    private void activate(String envId) throws Exception {
        String id = safeId(envId);
        File link = activeLink();
        File target = envUsr(id);

        // 旧版兼容：files/usr 是真实目录 → 迁移为 default 环境
        if (link.exists() && !isSymlink(link)) {
            File def = envUsr("default");
            File defParent = def.getParentFile();
            if (defParent != null && !defParent.exists()) defParent.mkdirs();
            if (def.exists()) {
                deleteRecursive(link);
            } else if (!link.renameTo(def)) {
                deleteRecursive(link);
            }
        }

        String cur = readLink(link);
        if (cur != null && cur.equals(target.getAbsolutePath())) return; // 已指向目标

        if (isSymlink(link) || link.exists()) {
            try { link.delete(); } catch (Throwable ignore) {}
        }
        File parent = target.getParentFile();
        if (parent != null && !parent.exists()) parent.mkdirs();
        if (!target.exists()) target.mkdirs();
        Os.symlink(target.getAbsolutePath(), link.getAbsolutePath());
    }

    /* ==================== 状态查询（JS 轮询） ==================== */

    @JavascriptInterface
    public String getStatus() {
        String active = readLink(activeLink());
        String activeId = "";
        if (active != null) {
            int i = active.lastIndexOf("/usr");
            if (i > 0) {
                String dir = active.substring(0, i);
                int j = dir.lastIndexOf('/');
                activeId = j >= 0 ? dir.substring(j + 1) : dir;
            }
        }
        StringBuilder sb = new StringBuilder(220);
        sb.append("{\"ready\":").append(isReady());
        sb.append(",\"installing\":").append(INSTALLING.get());
        sb.append(",\"percent\":").append(installPercent);
        sb.append(",\"arch\":\"").append(archName()).append("\"");
        sb.append(",\"prefix\":\"").append(esc(prefix())).append("\"");
        sb.append(",\"envsDir\":\"").append(esc(envsDir().getAbsolutePath())).append("\"");
        sb.append(",\"home\":\"").append(esc(new File(envsDir(), "default/home").getAbsolutePath())).append("\"");
        sb.append(",\"active\":\"").append(esc(activeId)).append("\"");
        sb.append(",\"pkg\":\"").append(esc(context.getPackageName())).append("\"");
        sb.append(",\"log\":\"").append(esc(installLog)).append("\"}");
        return sb.toString();
    }

    /* ==================== 安装 / 重装 / 环境管理 ==================== */

    @JavascriptInterface
    public String install() {
        if (INSTALLING.get()) return "正在安装中…";
        if (isReady()) { installLog = "已安装"; installPercent = 100; return "已安装"; }
        if (!INSTALLING.compareAndSet(false, true)) return "正在安装中…";
        installLog = "准备解压…"; installPercent = 0;
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    createEnv("default");
                    activate("default");
                    installPercent = 100;
                    installLog = "安装完成";
                } catch (Throwable t) {
                    installLog = "安装失败：" + t; installPercent = 0;
                } finally { INSTALLING.set(false); }
            }
        }, "lqb-termux-install").start();
        return "已开始安装";
    }

    @JavascriptInterface
    public String reinstall() {
        if (INSTALLING.get()) return "正在安装中…";
        installLog = "清理旧环境…"; installPercent = 0;
        if (!INSTALLING.compareAndSet(false, true)) return "正在安装中…";
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    File link = activeLink();
                    if (isSymlink(link)) { try { link.delete(); } catch (Throwable ignore) {} }
                    deleteRecursive(envsDir());
                    createEnv("default");
                    activate("default");
                    installPercent = 100; installLog = "重装完成";
                } catch (Throwable t) {
                    installLog = "重装失败：" + t; installPercent = 0;
                } finally { INSTALLING.set(false); }
            }
        }, "lqb-termux-reinstall").start();
        return "已开始重装";
    }

    /** 新建一个完全独立的环境（独立 bootstrap + 独立 home）。 */
    @JavascriptInterface
    public String envCreate(String envId) {
        String id = safeId(envId);
        if (new File(envUsr(id), "bin/sh").exists()) return "该环境已存在";
        if (INSTALLING.get()) return "正在安装中，请稍后再试";
        if (!INSTALLING.compareAndSet(false, true)) return "正在安装中，请稍后再试";
        installLog = "正在创建环境 " + id + " …"; installPercent = 0;
        new Thread(new Runnable() {
            @Override public void run() {
                try {
                    createEnv(id);
                    installPercent = 100; installLog = "环境 " + id + " 已创建";
                } catch (Throwable t) {
                    installLog = "创建环境失败：" + t; installPercent = 0;
                } finally { INSTALLING.set(false); }
            }
        }, "lqb-env-create").start();
        return "已开始创建环境";
    }

    @JavascriptInterface
    public String envDelete(String envId) {
        String id = safeId(envId);
        if ("default".equals(id)) return "默认环境不可删除";
        File dir = new File(envsDir(), id);
        if (!dir.exists()) return "环境不存在";
        String active = readLink(activeLink());
        if (active != null && active.startsWith(dir.getAbsolutePath() + "/")) {
            try { activate("default"); } catch (Throwable ignore) {}
        }
        deleteRecursive(dir);
        return "已删除环境 " + id;
    }

    @JavascriptInterface
    public boolean envExists(String envId) {
        return new File(envUsr(safeId(envId)), "bin/sh").exists();
    }

    /** 估算环境占用（字节），用于 UI 显示。 */
    @JavascriptInterface
    public long envSize(String envId) {
        return sizeOf(new File(envsDir(), safeId(envId)));
    }

    private void createEnv(String id) throws Exception {
        File usr = envUsr(id);
        if (new File(usr, "bin/sh").exists()) return;
        usr.mkdirs();
        unzipBootstrap(usr);
        chmodTree(usr);
        File home = envHomeDir(id);
        if (!home.exists()) home.mkdirs();
        new File(usr, "tmp").mkdirs();
        new File(usr, "var").mkdirs();
        try { Os.chmod(new File(usr, "tmp").getAbsolutePath(), 0777); } catch (Throwable ignore) {}
    }

    private void unzipBootstrap(File usr) throws Exception {
        String asset = "bootstrap-" + archName() + ".zip";
        InputStream raw;
        try { raw = context.getAssets().open(asset); }
        catch (Exception e) {
            throw new Exception("APK 里没有内置 " + asset + "（打包时必须把它放进 assets/）");
        }
        installLog = "解压 bootstrap（" + archName() + "）…";
        ZipInputStream zis = new ZipInputStream(new BufferedInputStream(raw, 1 << 16), StandardCharsets.UTF_8);
        ZipEntry e;
        byte[] buf = new byte[1 << 16];
        int count = 0;
        String symlinks = null;
        while ((e = zis.getNextEntry()) != null) {
            String name = e.getName();
            if (name == null || name.contains("..")) continue;
            if (name.equals("SYMLINKS.txt") || name.equals("HARDLINKS.txt")) {
                BufferedReader r = new BufferedReader(new InputStreamReader(zis, StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = r.readLine()) != null) sb.append(line).append('\n');
                if (name.equals("SYMLINKS.txt")) symlinks = sb.toString();
                continue;
            }
            File out = new File(usr, name);
            if (name.endsWith("/")) { out.mkdirs(); continue; }
            File parent = out.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            OutputStream os = new FileOutputStream(out);
            int n;
            while ((n = zis.read(buf)) != -1) os.write(buf, 0, n);
            os.close();
            if ((++count & 0x3FF) == 0) installPercent = Math.min(70, count / 40);
        }
        zis.close();

        installPercent = 78;
        installLog = "重建符号链接…";
        if (symlinks != null) {
            for (String line : symlinks.split("\n")) {
                int idx = line.indexOf('\u2190');
                if (idx <= 0) continue;
                String target = line.substring(0, idx).trim();
                String linkName = line.substring(idx + 1).trim();
                if (linkName.isEmpty()) continue;
                File link = new File(usr, linkName);
                File parent = link.getParentFile();
                if (parent != null && !parent.exists()) parent.mkdirs();
                try {
                    if (link.exists()) link.delete();
                    Os.symlink(target, link.getAbsolutePath());
                } catch (Throwable ignore) {}
            }
        }
        installPercent = 88;
        installLog = "设置文件权限…";
    }

    /* ==================== 异步执行命令 ==================== */

    private static final class Task {
        volatile boolean done = false;
        volatile int code = -1;
        volatile boolean timedOut = false;
        volatile long cost = 0;
        final long start = System.currentTimeMillis();
        final StringBuilder out = new StringBuilder();
        volatile Process proc;
        Task() {}
    }

    /**
     * 启动一条命令，立即返回任务号（形如 "ok:t123"）。
     * 真正的执行在线程里进行，JS 通过 execPoll 轮询结果，绝不阻塞网页线程。
     */
    @JavascriptInterface
    public String execStart(String cmd, String cwd, String envId) {
        if (cmd == null || cmd.trim().isEmpty()) return "err:命令为空";
        if (!isReady()) return "err:内置 Termux 环境尚未安装，请先到「总设置 → Termux 环境」点安装。";
        String id = "t" + (++TASK_SEQ);
        Task t = new Task();
        TASKS.put(id, t);
        final String fcmd = cmd, fcwd = cwd, fenv = envId;
        new Thread(new Runnable() {
            @Override public void run() { runTask(t, fcmd, fcwd, fenv); }
        }, "lqb-exec-" + id).start();
        return "ok:" + id;
    }

    private void runTask(Task t, String cmd, String cwd, String envId) {
        Process proc = null;
        try {
            synchronized (LOCK) {
                activate(envId);
                ProcessBuilder pb = buildProcess(cmd, cwd, envId);
                proc = pb.start();
                t.proc = proc;
            }
            try { proc.getOutputStream().close(); } catch (Throwable ignore) {}

            final InputStream in = proc.getInputStream();
            Thread reader = new Thread(new Runnable() {
                @Override public void run() {
                    Reader rd = new InputStreamReader(in, StandardCharsets.UTF_8);
                    char[] cbuf = new char[4096];
                    int n;
                    try {
                        while ((n = rd.read(cbuf)) != -1) {
                            synchronized (t.out) {
                                if (t.out.length() < MAX_OUT) t.out.append(cbuf, 0, n);
                            }
                        }
                    } catch (Throwable ignore) {}
                }
            }, "lqb-exec-read");
            reader.start();

            boolean finished;
            try {
                finished = proc.waitFor(DEFAULT_TIMEOUT_MS, TimeUnit.MILLISECONDS);
            } catch (Throwable ex) {
                finished = false;
            }
            if (!finished) {
                t.timedOut = true;
                try { proc.destroyForcibly(); } catch (Throwable ignore) {}
                try { proc.waitFor(3, TimeUnit.SECONDS); } catch (Throwable ignore) {}
            }
            try { reader.join(1500); } catch (Throwable ignore) {}
            t.code = finished ? safeExit(proc) : -9;
        } catch (Throwable e) {
            synchronized (t.out) { if (t.out.length() == 0) t.out.append(String.valueOf(e)); }
            t.code = -1;
        } finally {
            t.cost = System.currentTimeMillis() - t.start;
            t.done = true;
        }
    }

    /** 轮询任务结果。running 时也会带上"到目前为止"的输出，便于终端实时显示。 */
    @JavascriptInterface
    public String execPoll(String taskId) {
        Task t = TASKS.get(taskId);
        if (t == null) return "{\"state\":\"missing\"}";
        String out;
        synchronized (t.out) { out = t.out.toString(); }
        if (!t.done) {
            return "{\"state\":\"running\",\"out\":\"" + esc(out) + "\"}";
        }
        TASKS.remove(taskId);
        return "{\"state\":\"done\",\"code\":" + t.code + ",\"cost\":" + t.cost
                + ",\"timedOut\":" + t.timedOut + ",\"out\":\"" + esc(out) + "\"}";
    }

    @JavascriptInterface
    public String execKill(String taskId) {
        Task t = TASKS.get(taskId);
        if (t == null) return "无此任务";
        try { if (t.proc != null) t.proc.destroyForcibly(); } catch (Throwable ignore) {}
        return "已中止";
    }

    private ProcessBuilder buildProcess(String cmd, String cwd, String envId) throws Exception {
        String p = prefix();
        File home = envHomeDir(safeId(envId));
        if (!home.exists()) home.mkdirs();
        File cwdF = (cwd != null && !cwd.trim().isEmpty()) ? new File(cwd) : home;
        if (!cwdF.exists()) cwdF.mkdirs();

        ProcessBuilder pb = new ProcessBuilder(p + "/bin/bash", "-c", cmd);
        Map<String, String> env = pb.environment();
        env.clear();
        env.put("PATH", p + "/bin:" + p + "/bin/applets:/system/bin:/system/xbin");
        env.put("HOME", home.getAbsolutePath());
        env.put("PREFIX", p);
        env.put("TERM", "xterm-256color");
        env.put("TMPDIR", p + "/tmp");
        env.put("LANG", "zh_CN.UTF-8");
        env.put("LC_ALL", "zh_CN.UTF-8");
        env.put("LD_LIBRARY_PATH", p + "/lib");
        env.put("ANDROID_DATA", "/data");
        env.put("ANDROID_ROOT", "/system");
        env.put("EXTERNAL_STORAGE", Environment.getExternalStorageDirectory().getAbsolutePath());
        env.put("COLORTERM", "truecolor");
        pb.directory(cwdF);
        pb.redirectErrorStream(true);
        return pb;
    }

    /** 同步执行（仅供内部/备份等短任务使用，带超时）。返回纯文本输出。 */
    private String execSync(String cmd, String cwd, String envId) {
        Task t = new Task();
        runTask(t, cmd, cwd, envId);
        synchronized (t.out) { return t.out.toString(); }
    }

    /* ==================== 备份 / 还原整个环境（含已安装软件包） ==================== */

    /**
     * 把全部环境（envs 目录，含每个环境 pkg 安装出来的软件包）打包成 tar.gz。
     * 体积可能很大（每个环境几百 MB），请确认外部存储有足够空间。
     * 异步执行：立即返回 "ok:任务号"，用 execPoll 轮询进度/结果。
     */
    @JavascriptInterface
    public String exportEnvTar(String outPath) {
        if (outPath == null || outPath.trim().isEmpty()) return "err:输出路径为空";
        String id = "e" + (++TASK_SEQ);
        Task t = new Task();
        TASKS.put(id, t);
        final String fout = outPath;
        new Thread(new Runnable() {
            @Override public void run() { doExport(t, fout); }
        }, "lqb-env-export").start();
        return "ok:" + id;
    }

    private void doExport(Task t, String outPath) {
        try {
            File parent = new File(outPath).getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();
            String base = filesDir().getAbsolutePath();
            String pick =
                "if command -v tar >/dev/null 2>&1; then TAR='tar'; " +
                "elif [ -x /system/bin/toybox ]; then TAR='/system/bin/toybox tar'; " +
                "else echo \"__NO_TAR__\"; exit 127; fi; ";
            String cmd = pick
                + "if [ -d " + q(base + "/envs") + " ]; then "
                + "  $TAR -czf " + q(outPath) + " -C " + q(base) + " envs 2>&1; "
                + "else "
                + "  $TAR -czf " + q(outPath) + " -C " + q(base) + " usr home 2>&1; "
                + "fi";
            String out = isReady() ? execSync(cmd, null, null) : execSystem(cmd);
            synchronized (t.out) { t.out.append(out == null ? "" : out); }
            File f = new File(outPath);
            t.code = (f.exists() && f.length() > 0) ? 0 : -1;
        } catch (Throwable e) {
            synchronized (t.out) { t.out.append(String.valueOf(e)); }
            t.code = -1;
        } finally {
            t.cost = System.currentTimeMillis() - t.start;
            t.done = true;
        }
    }

    /** 从 tar.gz 还原全部环境（覆盖 envs）。异步执行，返回 "ok:任务号"。 */
    @JavascriptInterface
    public String importEnvTar(String inPath) {
        if (inPath == null || !new File(inPath).exists()) return "err:找不到备份文件：" + inPath;
        String id = "i" + (++TASK_SEQ);
        Task t = new Task();
        TASKS.put(id, t);
        final String fin = inPath;
        new Thread(new Runnable() {
            @Override public void run() { doImport(t, fin); }
        }, "lqb-env-import").start();
        return "ok:" + id;
    }

    private void doImport(Task t, String inPath) {
        try {
            String base = filesDir().getAbsolutePath();
            String pick =
                "if command -v tar >/dev/null 2>&1; then TAR='tar'; " +
                "elif [ -x /system/bin/toybox ]; then TAR='/system/bin/toybox tar'; " +
                "else echo \"__NO_TAR__\"; exit 127; fi; ";
            String cmd = pick
                + "$TAR -xzf " + q(inPath) + " -C " + q(base) + " 2>&1 && echo __ENV_OK__";
            String out = isReady() ? execSync(cmd, null, null) : execSystem(cmd);
            synchronized (t.out) { t.out.append(out == null ? "" : out); }
            if (out != null && out.contains("__ENV_OK__")) {
                try { chmodTree(envsDir()); } catch (Throwable ignore) {}
                try { activate("default"); } catch (Throwable ignore) {}
                t.code = 0;
            } else {
                t.code = -1;
            }
        } catch (Throwable e) {
            synchronized (t.out) { t.out.append(String.valueOf(e)); }
            t.code = -1;
        } finally {
            t.cost = System.currentTimeMillis() - t.start;
            t.done = true;
        }
    }

    /* ==================== 工具 ==================== */

    /** 用系统 shell 执行（不依赖内置 Termux），用于解压等基础操作。 */
    private String execSystem(String cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try { p.getOutputStream().close(); } catch (Throwable ignore) {}
            String out = readAll(p.getInputStream());
            try { p.waitFor(120, TimeUnit.SECONDS); } catch (Throwable ignore) {}
            return out;
        } catch (Throwable t) { return String.valueOf(t); }
    }

    /** 单引号安全转义，防止路径里的特殊字符造成命令注入。 */
    private static String q(String s) {
        if (s == null) return "''";
        return "'" + s.replace("'", "'\\''") + "'";
    }

    private static String readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
        in.close();
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void chmodTree(File f) {
        if (isSymlink(f)) return;                 // 符号链接不跟随
        String path = f.getAbsolutePath();
        try { Os.chmod(path, 0755); } catch (Throwable ignore) {}
        if (f.isDirectory()) {
            File[] cs = f.listFiles();
            if (cs != null) for (File c : cs) chmodTree(c);
        }
    }

    private static void deleteRecursive(File f) {
        if (isSymlink(f)) { try { f.delete(); } catch (Throwable ignore) {} return; }
        if (f.isDirectory()) {
            File[] cs = f.listFiles();
            if (cs != null) for (File c : cs) deleteRecursive(c);
        }
        try { f.delete(); } catch (Throwable ignore) {}
    }

    private static long sizeOf(File f) {
        if (isSymlink(f)) return 0;
        if (f.isFile()) return f.length();
        long sum = 0;
        File[] cs = f.listFiles();
        if (cs != null) for (File c : cs) sum += sizeOf(c);
        return sum;
    }

    private static int safeExit(Process p) {
        try { return p.exitValue(); } catch (Throwable t) { return -1; }
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "");
    }
}
