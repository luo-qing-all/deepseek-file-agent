package com.lingqiong.buddy;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
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

/**
 * 宿主 Activity：WebView 装载 index.html，并用 addJavascriptInterface 把
 * FileBridge / ShizukuBridge / TermuxBridge / SystemBridge 暴露成 JS 里的 window 对象。
 *
 * 这就是"AI 能操作文件 / 终端"的物理接口——JS 只是喊一声，真正的执行在这里。
 */
public class MainActivity extends Activity {
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

        webView.loadUrl("file:///android_asset/index.html");

        requestStoragePermission();
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

            // 把真实文件路径推给前端：视频不读进内存，只靠这条路径交给 AI 处理
            if (results != null && results.length > 0) {
                JSONArray arr = new JSONArray();
                for (Uri u : results) arr.put(resolvePath(u));
                final String js = "window.__onNativePicker&&window.__onNativePicker(" + arr.toString() + ")";
                webView.post(new Runnable() {
                    @Override public void run() { webView.evaluateJavascript(js, null); }
                });
            }
        }
    }

    /** 尽力把 content:// 或 file:// 的 Uri 还原成真实文件路径。 */
    private String resolvePath(Uri uri) {
        if (uri == null) return "";
        try {
            String scheme = uri.getScheme();
            if (scheme == null) return uri.toString();
            if (scheme.equalsIgnoreCase("file")) {
                String p = uri.getPath();
                return p == null ? "" : p;
            }
            if (scheme.equalsIgnoreCase("content")) {
                Cursor c = getContentResolver().query(uri, new String[]{"_data"}, null, null, null);
                if (c != null) {
                    try {
                        if (c.moveToFirst()) {
                            int idx = c.getColumnIndex("_data");
                            if (idx >= 0) {
                                String p = c.getString(idx);
                                if (p != null && !p.isEmpty()) return p;
                            }
                        }
                    } finally { c.close(); }
                }
            }
        } catch (Throwable ignore) {}
        return uri.toString();
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
            } catch (PackageManager.NameNotFoundException e) { return "2.3.0"; }
        }

        /** 宿主包名（com.lq.app，与官方 com.termux 等长，故可共存）。 */
        @JavascriptInterface
        public String getHostPackageName() { return getPackageName(); }

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
