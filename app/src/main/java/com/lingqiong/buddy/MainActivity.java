package com.lingqiong.buddy;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.webkit.JavascriptInterface;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import org.json.JSONArray;

import java.security.MessageDigest;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 宿主 Activity：WebView 装载 index.html，并用 addJavascriptInterface 把
 * FileBridge / ShizukuBridge / TermuxBridge / SystemBridge 暴露成 JS 里的 window 对象。
 *
 * 这就是"AI 能操作文件 / 终端"的物理接口——JS 只是喊一声，真正的执行在这里。
 */
public class MainActivity extends Activity {
    /** 正式签名（lq-release.jks）证书 SHA-256；与打包签名不一致 → 判定为改包。 */
    private static final String EXPECTED_SIG = "b7b78c6ffed16fb9e59174e109590f7c47edefa50e4cd844ed57e8d15af7e359";
    /** 前端资源由服务器动态下发（AES-256-GCM + RSA 验签），APK 内不含可解密密钥。 */
    private WebView webView;
    private ValueCallback<Uri[]> filePathCallback;
    private static final int FILE_CHOOSER_REQ = 1001;
    private static final int PERM_REQ = 2001;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        setContentView(webView);

        WebSettings ws = webView.getSettings();
        ws.setJavaScriptEnabled(true);
        ws.setDomStorageEnabled(true);
        ws.setAllowFileAccess(true);
        ws.setAllowContentAccess(true);
        ws.setAllowFileAccessFromFileURLs(true);
        ws.setAllowUniversalAccessFromFileURLs(true);
        ws.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);

        // ===== 桥接：把 Java 对象挂到 window 上 =====
        webView.addJavascriptInterface(new FileBridge(this), "AndroidFile");
        webView.addJavascriptInterface(new ShizukuBridge(this), "AndroidShizuku");
        webView.addJavascriptInterface(new TermuxBridge(this), "AndroidTermux");
        webView.addJavascriptInterface(new SystemBridge(), "AndroidSystem");

        webView.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                view.loadUrl(url);
                return true;
            }
        });

        // 处理 <input type="file"> 弹窗
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback,
                                             FileChooserParams params) {
                if (filePathCallback != null) {
                    filePathCallback.onReceiveValue(null);
                }
                filePathCallback = callback;

                Intent intent = params.createIntent();
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                try {
                    startActivityForResult(intent, FILE_CHOOSER_REQ);
                } catch (Exception e) {
                    filePathCallback = null;
                    return false;
                }
                return true;
            }
        });

        // ===== 安全加固①：签名校验（换签 / 改包 → 直接退出）=====
        if (!checkSignature()) { die("应用完整性校验失败，已停止运行"); return; }

        // ===== 安全加固②：前端资源【动态下发 + 验签解密】=====
        // APK 内不含可解密钥匙；密文与 AES 密钥由服务器下发，服务器私钥签名防篡改。
        // 首次需联网；之后可用本地缓存（加密态）离线兜底。
        webView.loadDataWithBaseURL("file:///android_asset/", LOADING_HTML, "text/html", "utf-8", null);
        final String cachePath = new File(getFilesDir(), "front_pack.json").getAbsolutePath();
        new Thread(new Runnable() {
            @Override public void run() {
                // [2.5.5] 版本对比 + 不限时下载 + 进度回调（进度条实时更新）
                final String html = FrontLoader.load(FrontLoader.PACK_URL, cachePath, 15000, new FrontLoader.Progress() {
                    @Override public void onStatus(final String msg) {
                        webView.post(new Runnable() { @Override public void run() {
                            webView.evaluateJavascript("window.__lqStatus&&window.__lqStatus(" + jsStr(msg) + ")", null);
                        }});
                    }
                    @Override public void onProgress(final long d, final long total, final long bps) {
                        webView.post(new Runnable() { @Override public void run() {
                            webView.evaluateJavascript("window.__lqLoad&&window.__lqLoad(" + d + "," + total + "," + bps + ")", null);
                        }});
                    }
                });
                webView.post(new Runnable() {
                    @Override public void run() {
                        if (html == null) { die("无法获取前端资源，请检查网络后重试"); return; }
                        webView.loadDataWithBaseURL("file:///android_asset/", html, "text/html", "utf-8", null);
                    }
                });
            }
        }, "lqb-front-load").start();

        // 注意：此处不再自动申请存储权限。改由用户在「总设置 → 文件系统权限」手动授权。
    }

    /** Android 11+ 用「所有文件访问权限」；更低版本用传统运行时权限。 */
    private void requestStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                try {
                    Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivity(intent);
                } catch (Exception e) {
                    try {
                        Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                        startActivity(intent);
                    } catch (Exception ex) {}
                }
            }
        } else {
            boolean need = checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED
                    || checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED;
            if (need) {
                requestPermissions(new String[]{
                        Manifest.permission.READ_EXTERNAL_STORAGE,
                        Manifest.permission.WRITE_EXTERNAL_STORAGE
                }, PERM_REQ);
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == FILE_CHOOSER_REQ) {
            if (filePathCallback == null) return;
            Uri[] results = null;
            if (resultCode == Activity.RESULT_OK && data != null) {
                if (data.getClipData() != null) {
                    int count = data.getClipData().getItemCount();
                    results = new Uri[count];
                    for (int i = 0; i < count; i++) {
                        results[i] = data.getClipData().getItemAt(i).getUri();
                    }
                } else if (data.getData() != null) {
                    results = new Uri[]{ data.getData() };
                }
            }
            filePathCallback.onReceiveValue(results);
            filePathCallback = null;

            // 把"可被 ffmpeg 直接读取的真实文件路径"推给前端。
            // 关键修复：系统文件选择器返回的是 content:// URI（DocumentsProvider），
            // 它没有 _data 列，且内置 ffmpeg 作为独立进程无法解析 content://
            // （会报 "No Java virtual machine has been registered / Invalid argument"）。
            // 因此这里把 URI 的内容复制进 App 私有目录，得到真正的文件路径再交出去。
            if (results != null && results.length > 0) {
                final Uri[] uris = results;
                new Thread(new Runnable() {
                    @Override public void run() {
                        JSONArray arr = new JSONArray();
                        for (Uri u : uris) {
                            JSONObject o = new JSONObject();
                            try {
                                o.put("p", localizeForFfmpeg(u));
                                o.put("n", displayName(u));
                            } catch (Throwable ignore) {}
                            arr.put(o);
                        }
                        final String js = "window.__onNativePicker&&window.__onNativePicker(" + arr.toString() + ")";
                        webView.post(new Runnable() {
                            @Override public void run() { webView.evaluateJavascript(js, null); }
                        });
                    }
                }, "lqb-picker").start();
            }
        }
    }

    /**
     * 把选择到的 Uri 变成 ffmpeg 能直接读取的「真实文件路径」：
    * 1. file:// → 直接用其路径；
    * 2. content:// 若 _data 列能取到且文件确实可读 → 用真实路径；
    * 3. 其余情况（DocumentsProvider / FileProvider 等无 _data 的 URI）→
     *    通过 ContentResolver 读取内容并复制进 App 私有目录 files/tmp/，返回该路径。
     */
    private String localizeForFfmpeg(Uri uri) {
        if (uri == null) return "";
        try {
            String scheme = uri.getScheme();
            if (scheme != null && scheme.equalsIgnoreCase("file")) {
                String p = uri.getPath();
                if (p != null && !p.isEmpty()) return p;
            }
            String direct = queryDataColumn(uri);
            // [2.5.11] 排除相册选择器(PhotoPicker)返回的虚拟合成路径：
            // 形如 /sdcard/.transforms/synthetic/picker_get_content/... ，
            // 主进程 File.exists() 为真但内容是合成的，独立进程 ffmpeg 读不到有效数据。
            // 这类路径强制走下方 copyUriToPrivate 复制出真实文件。
            if (direct != null && direct.indexOf(".transforms/synthetic") < 0 && direct.indexOf("picker_get_content") < 0) {
                File f = new File(direct);
                if (f.exists() && f.canRead()) return direct;
            }
            String copied = copyUriToPrivate(uri);
            if (copied != null && !copied.isEmpty()) return copied;
        } catch (Throwable ignore) {}
        // 最后的兜底：至少把原始字符串交出去（前端会显示路径，便于排错）
        return uri.toString();
    }

    /** 尝试读取 content:// 的 _data 列；不可用时返回 null（不抛异常）。 */
    private String queryDataColumn(Uri uri) {
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, new String[]{"_data"}, null, null, null);
            if (c != null && c.moveToFirst()) {
                int idx = c.getColumnIndex("_data");
                if (idx >= 0) {
                    String p = c.getString(idx);
                    if (p != null && !p.isEmpty()) return p;
                }
            }
        } catch (Throwable ignore) {
            // DocumentsProvider 没有 _data 列，query 会抛异常，这里静默
        } finally {
            try { if (c != null) c.close(); } catch (Throwable ignore) {}
        }
        return null;
    }

    /** 把 content:// 的内容复制到 files/tmp/import_<时间>_<文件名>，返回绝对路径。 */
    private String copyUriToPrivate(Uri uri) {
        InputStream in = null;
        OutputStream out = null;
        try {
            File dir = new File(getFilesDir(), "tmp");
            if (!dir.exists()) dir.mkdirs();
            cleanupOldImports(dir);

            String base = displayName(uri);
            if (base == null || base.isEmpty()) base = "video.mp4";
            base = base.replaceAll("[^0-9A-Za-z._\\-\\u4e00-\\u9fff]", "_");
            File dst = new File(dir, "import_" + System.currentTimeMillis() + "_" + base);

            in = getContentResolver().openInputStream(uri);
            if (in == null) return "";
            out = new FileOutputStream(dst);
            byte[] buf = new byte[1 << 16];
            int n;
            while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
            out.flush();
            return dst.getAbsolutePath();
        } catch (Throwable t) {
            return "";
        } finally {
            try { if (in != null) in.close(); } catch (Throwable ignore) {}
            try { if (out != null) out.close(); } catch (Throwable ignore) {}
        }
    }

    /** 清理超过 24 小时的旧导入临时文件，避免反复发大视频撑爆私有目录。 */
    private void cleanupOldImports(File dir) {
        try {
            File[] fs = dir.listFiles();
            if (fs == null) return;
            long now = System.currentTimeMillis();
            for (File f : fs) {
                if (f.isFile() && f.getName().startsWith("import_")
                        && now - f.lastModified() > 24L * 3600L * 1000L) {
                    //noinspection ResultOfMethodCallIgnored
                    f.delete();
                }
            }
        } catch (Throwable ignore) {}
    }

    /** 取 Uri 的显示文件名（用于给复制出的临时文件起个好名字）。 */
    private String displayName(Uri uri) {
        if (uri == null) return "";
        Cursor c = null;
        try {
            c = getContentResolver().query(uri, new String[]{"_display_name"}, null, null, null);
            if (c != null && c.moveToFirst()) {
                int i = c.getColumnIndex("_display_name");
                if (i >= 0) {
                    String s = c.getString(i);
                    if (s != null && !s.isEmpty()) return s;
                }
            }
        } catch (Throwable ignore) {
        } finally {
            try { if (c != null) c.close(); } catch (Throwable ignore) {}
        }
        String last = uri.getLastPathSegment();
        if (last != null) {
            int idx = last.lastIndexOf('/');
            if (idx >= 0) last = last.substring(idx + 1);
            try { last = Uri.decode(last); } catch (Throwable ignore) {}
            return last;
        }
        return "";
    }

    /** SHA-256 → 小写 hex。 */
    private static String sha256hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] h = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Throwable t) { return ""; }
    }

    /** 校验当前 APK 签名是否为本应用正式签名；被换签 / 改包 → false。 */
    private boolean checkSignature() {
        try {
            PackageInfo pi = getPackageManager().getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
            if (pi == null || pi.signatures == null) return false;
            for (Signature sg : pi.signatures) {
                if (EXPECTED_SIG.equalsIgnoreCase(sha256hex(sg.toByteArray()))) return true;
            }
        } catch (Throwable ignore) {}
        return false;
    }

    /** [2.5.5] 启动加载页：进度条 + 百分比 + 速度 + 预计剩余时间（前端 HTML 取回后替换）。 */
    private static final String LOADING_HTML =
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        + "<style>"
        + "html,body{height:100%;margin:0;display:flex;align-items:center;justify-content:center;"
        + "background:#fff;font-family:-apple-system,'PingFang SC','Microsoft YaHei',sans-serif;color:#222}"
        + ".box{width:80%;max-width:360px}"
        + ".tt{font-size:15px;font-weight:600;text-align:center;margin-bottom:14px}"
        + ".bar{height:8px;border-radius:5px;background:#eceef3;overflow:hidden}"
        + ".fill{height:100%;width:0;border-radius:5px;background:linear-gradient(90deg,#4c7dff,#7aa2ff);transition:width .2s ease}"
        + ".ind{width:38%;animation:sl 1.1s ease-in-out infinite}"
        + "@keyframes sl{0%{margin-left:-38%}100%{margin-left:100%}}"
        + ".pct{font-size:13px;font-weight:600;text-align:center;color:#4c7dff;margin-top:10px;min-height:18px}"
        + ".meta{font-size:12px;text-align:center;color:#8a8f99;margin-top:6px;line-height:1.6;min-height:16px}"
        + "</style></head><body>"
        + "<div class='box'>"
        + "<div class='tt' id='tt'>正在连接服务器…</div>"
        + "<div class='bar'><div class='fill ind' id='fl'></div></div>"
        + "<div class='pct' id='pc'></div>"
        + "<div class='meta' id='mt'></div>"
        + "</div>"
        + "<script>"
        + "function _fmt(b){if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(1)+' KB';return (b/1048576).toFixed(2)+' MB';}"
        + "function _ft(s){if(s<60)return s+' 秒';var m=Math.floor(s/60),x=s%60;return m+' 分 '+x+' 秒';}"
        + "function _draw(d,t,b){var f=document.getElementById('fl'),p=document.getElementById('pc'),m=document.getElementById('mt');"
        + "if(!f)return;"
        + "if(t>0){f.className='fill';var pc=Math.floor(d*100/t);if(pc>100)pc=100;f.style.width=pc+'%';p.textContent=pc+'%';}"
        + "else{f.className='fill ind';p.textContent='';}"
        + "var s='';"
        + "if(t>0){s=_fmt(d)+' / '+_fmt(t);}else{s=_fmt(d);}"
        + "if(b>0){s+='  ·  '+_fmt(b)+'/s';}"
        + "if(b>0&&t>0&&d<t){s+='  ·  剩余约 '+_ft(Math.ceil((t-d)/b));}"
        + "m.textContent=s;}"
        + "window.__lqLoad=function(d,t,b){_draw(d,t,b);};"
        + "window.__lqStatus=function(s){var e=document.getElementById('tt');if(e)e.textContent=s;};"
        + "</script></body></html>";

    /** 校验失败：提示后退出（不给任何可用界面）。 */
    private void die(final String msg) {
        try { Toast.makeText(this, msg, Toast.LENGTH_LONG).show(); } catch (Throwable ignore) {}
        new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(new Runnable() {
            public void run() {
                try { finish(); } catch (Throwable ignore) {}
                System.exit(0);
            }
        }, 900);
    }

    /** [2.5.5] 把字符串转成安全的 JS 字面量（用于 evaluateJavascript 传参）。 */
    private static String jsStr(String s) {
        if (s == null) return "''";
        StringBuilder sb = new StringBuilder("'");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') sb.append("\\\\");
            else if (c == '\'') sb.append("\\'");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\r') sb.append("\\r");
            else if (c == '<') sb.append("\\u003c");
            else sb.append(c);
        }
        return sb.append("'").toString();
    }

    @Override
    protected void onResume() {
        super.onResume();
        // 用户从系统设置返回时，通知前端刷新权限状态
        if (webView != null) {
            webView.post(new Runnable() {
                public void run() {
                    webView.evaluateJavascript("window.__onPermChanged&&window.__onPermChanged()", null);
                }
            });
        }
    }

    public class SystemBridge {
        @JavascriptInterface
        public String getSdkVersion() {
            return String.valueOf(Build.VERSION.SDK_INT);
        }

        @JavascriptInterface
        public boolean hasAllFilesAccess() {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                return Environment.isExternalStorageManager();
            }
            return checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    == PackageManager.PERMISSION_GRANTED;
        }

        @JavascriptInterface
        public String getVersionName() {
            try {
                return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
            } catch (PackageManager.NameNotFoundException e) { return "2.3.4"; }
        }

        @JavascriptInterface
        public int getVersionCode() {
            try {
                return getPackageManager().getPackageInfo(getPackageName(), 0).versionCode;
            } catch (PackageManager.NameNotFoundException e) { return 0; }
        }

        /** 用系统浏览器/下载器打开链接（用于「检查更新」跳转下载 APK）。 */
        @JavascriptInterface
        public void openUrl(final String url) {
            if (url == null || url.trim().isEmpty()) return;
            runOnUiThread(new Runnable() {
                public void run() {
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
                    } catch (Exception e) {
                        Toast.makeText(MainActivity.this, "无法打开链接", Toast.LENGTH_SHORT).show();
                    }
                }
            });
        }

        /** 宿主包名（com.lq.app，与官方 com.termux 等长，故可共存）。 */
        @JavascriptInterface
        public String getHostPackageName() { return getPackageName(); }

        /** 由「总设置 → 文件系统权限」按钮调用：主动发起存储授权（不再启动即弹）。 */
        /** 前端探活失败 / 需强制退出时调用。 */
        @JavascriptInterface
        public void exitApp() {
            runOnUiThread(new Runnable() {
                public void run() { die("无法连接服务器"); }
            });
        }

        @JavascriptInterface
        public void requestStoragePermission() {
            runOnUiThread(new Runnable() {
                public void run() { MainActivity.this.requestStoragePermission(); }
            });
        }

        @JavascriptInterface
        public void toast(final String msg) {
            runOnUiThread(new Runnable() {
                public void run() {
                    Toast.makeText(MainActivity.this, msg, Toast.LENGTH_SHORT).show();
                }
            });
        }
    }
}
