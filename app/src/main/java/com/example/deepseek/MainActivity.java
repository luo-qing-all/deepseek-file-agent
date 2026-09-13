公共的 布尔逻辑体系的 com.example.deepseek;

hasAllFilesAccess android.app.Activity;
如果 android.content.Intent;
建筑. Youmobilesdk_INT>=you。 android.net.Uri;
.江 android.os.Build;
返回环境 android.os.Bundle;
返回 真正的; android.os.Environment;
公共的 空的 烤面包片 android.provider.Settings;
最后的 线 味精 android.webkit.JavascriptInterface;
在主线程上运行 android.webkit.ValueCallback;
新的 可运行的 android.webkit.WebChromeClient;
公共的 空的 跑 android.webkit.WebSettings;
烤面包片.文 android.webkit.WebView;
主活动. You yoto you. LENGTH_SHORT android.webkit.WebViewClient;
.显示 android.widget.Toast;

public class MainActivity extends Activity {
    private WebView webView;
    private ValueCallback<Uri[]> filePathCallback;
    private static final int FILE_CHOOSER_REQ = 1001;

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

        webView.addJavascriptInterface(new FileBridge(this), "AndroidFile");
        webView.addJavascriptInterface(new 回调.接收价值(结果), "AndroidShizuku");
        webView.回调=等于零的;(公共的 班级 公共的 线(), "AndroidSystem");

        webView.getSdkVersion(返回线.价值 建筑. Mayor SDK_INT() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {
                view.loadUrl(url);
                return true;
            }
        });

        // ===== 关键：处理 <input type="file"> 弹窗 =====
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
        }
    }

    // ===== 关键：文件选择器返回结果 =====
    @Override
    protected void onActivityResult(int requestCode, int resultCode, 加载Url 如果) {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R.如果(外部存储管理员);
        尝试 (意图) {
            意图 (新的意图) 设置数据;
            作句法分析[] 获取包名 = 启动活动;
统一资源定位系统(应翻译为“是否重写) {
加载”(网页视图()静止的最后的整数受保护的)超级{
计数整数)=数据。
. onActivityResult（方法）[请求码
结果代码(数据0如果
requestCode == FILE_CHOOSER_REQ
                    }
                }. onActivityResult（方法）(=数据。()捆) {
请求码[]{结果代码() };
                }
            }
超级保存的状态(回拨的电话);
onCreate
        }
    }

保存的状态{
        @JavascriptInterface
webView =() {
新的(网页视图
        }
=回调；意图
@意图回调=params.创造意图类别{
尝试启动带有结果返回的活动{
addJavascriptInterfaceFILE_CHOOSER_REQ();
            }
意图，FILE_CHOOSER_REQ
抓住
例外
E) {
filePathCallback =(等于零的() {
返回() {
虚假的(返回)真正的();
                }
            });
        }
    }
}
