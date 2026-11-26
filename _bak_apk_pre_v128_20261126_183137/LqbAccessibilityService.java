package com.lingqiong.buddy;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.GestureDescription;
import android.content.Intent;
import android.graphics.Path;
import android.graphics.Rect;
import android.os.Build;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PixelFormat;
import android.graphics.drawable.GradientDrawable;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewConfiguration;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * [v43] AI 操作手机：无障碍服务。
 *
 * 提供 读屏 / 点击 / 长按 / 滑动 / 系统按键 能力，由 MainActivity 的 A11yBridge
 * 暴露成前端 JS 的 window.AndroidA11y，供 AI 工具调用。
 *
 * 设计约束：
 *  1. 用户必须在「总设置 → AI 操作手机」手动开启系统无障碍权限；未开启时
 *     INSTANCE 为 null，所有能力返回失败，绝不静默尝试。
 *  2. 服务本身不联网、不后台常驻、不主动录制；只有 AI 明确调用对应工具时
 *     才执行一次动作（点击/读屏等）。
 *  3. 只在服务已连接（onServiceConnected）后才允许派发手势。
 */
public class LqbAccessibilityService extends AccessibilityService {

    private static volatile LqbAccessibilityService INSTANCE = null;

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        INSTANCE = this;
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        // 本服务不需要监听事件流，事件类型仅用于满足系统要求。
    }

    @Override
    public void onInterrupt() {
    }

    @Override
    public boolean onUnbind(Intent intent) {
        try { doStopPick(false); } catch (Throwable t) { }   // [v116] 无障碍被关掉时立刻移除取点浮窗
        INSTANCE = null;
        return super.onUnbind(intent);
    }

    @Override
    public void onDestroy() {
        try { doStopPick(false); } catch (Throwable t) { }   // [v116] 服务销毁兜底，防窗口残留卡屏
        INSTANCE = null;
        super.onDestroy();
    }

    /** 无障碍权限是否已开启（服务是否已连接）。 */
    public static boolean isEnabled() {
        return INSTANCE != null;
    }

    /**
     * [v83] 截屏并返回 JPEG 的 base64（不含 data: 前缀）。失败返回 null。
     *
     * 为什么用无障碍而不是 screencap：
     *   screencap 要 shell/root 身份，普通 App 直接调用会被拒；
     *   AccessibilityService.takeScreenshot（API 30+）是系统许可的正规通道，
     *   不需要 root，也不需要录屏权限弹窗。
     */
    public static String screenshotBase64(int timeoutMs) {
        final LqbAccessibilityService s = INSTANCE;
        if (s == null) return null;
        if (android.os.Build.VERSION.SDK_INT < 30) return null;
        final java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(1);
        final String[] holder = new String[]{null};
        final String[] errHolder = new String[]{null};
        try {
            s.takeScreenshot(android.view.Display.DEFAULT_DISPLAY,
                    java.util.concurrent.Executors.newSingleThreadExecutor(),
                    new TakeScreenshotCallback() {
                        @Override
                        public void onSuccess(ScreenshotResult result) {
                            android.graphics.Bitmap bmp = null;
                            try {
                                bmp = android.graphics.Bitmap.wrapHardwareBuffer(
                                        result.getHardwareBuffer(), result.getColorSpace());
                                if (bmp != null) {
                                    java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                                    bmp.compress(android.graphics.Bitmap.CompressFormat.JPEG, 82, bos);
                                    holder[0] = android.util.Base64.encodeToString(
                                            bos.toByteArray(), android.util.Base64.NO_WRAP);
                                } else {
                                    errHolder[0] = "Bitmap 为空";
                                }
                            } catch (Throwable t) {
                                errHolder[0] = t.getClass().getSimpleName();
                            } finally {
                                try { if (bmp != null) bmp.recycle(); } catch (Throwable ignore) {}
                                try { result.getHardwareBuffer().close(); } catch (Throwable ignore) {}
                                latch.countDown();
                            }
                        }

                        @Override
                        public void onFailure(int errorCode) {
                            errHolder[0] = "系统拒绝截图(code=" + errorCode + ")";
                            latch.countDown();
                        }
                    });
            latch.await(Math.max(1000, timeoutMs), java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (Throwable t) {
            return null;
        }
        return holder[0];
    }

    /** 截图失败原因（给上层拼提示用） */
    public static String lastShotError = "";

    private static boolean dispatch(Path path, long duration) {
        final LqbAccessibilityService s = INSTANCE;
        if (s == null || Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return false;
        try {
            GestureDescription.Builder b = new GestureDescription.Builder();
            b.addStroke(new GestureDescription.StrokeDescription(path, 0, duration));
            final CountDownLatch latch = new CountDownLatch(1);
            final AtomicBoolean ok = new AtomicBoolean(false);
            boolean dispatched = s.dispatchGesture(b.build(),
                    new AccessibilityService.GestureResultCallback() {
                        @Override public void onCompleted(GestureDescription g) { ok.set(true); latch.countDown(); }
                        @Override public void onCancelled(GestureDescription g) { ok.set(false); latch.countDown(); }
                    }, null);
            if (!dispatched) return false;
            long waitMs = duration + 1200;
            latch.await(waitMs, TimeUnit.MILLISECONDS);
            return ok.get();
        } catch (Throwable t) {
            return false;
        }
    }

    public static boolean tap(float x, float y) {
        Path p = new Path();
        p.moveTo(x, y);
        return dispatch(p, 60);
    }

    public static boolean longPress(float x, float y, long dur) {
        Path p = new Path();
        p.moveTo(x, y);
        long d = dur <= 0 ? 600 : dur;
        if (d > 5000) d = 5000;
        return dispatch(p, d);
    }

    public static boolean swipe(float x1, float y1, float x2, float y2, long dur) {
        Path p = new Path();
        p.moveTo(x1, y1);
        p.lineTo(x2, y2);
        long d = dur <= 0 ? 300 : dur;
        if (d > 5000) d = 5000;
        return dispatch(p, d);
    }

    public static boolean globalAction(String name) {
        final LqbAccessibilityService s = INSTANCE;
        if (s == null || name == null) return false;
        int code;
        if ("back".equals(name)) code = GLOBAL_ACTION_BACK;
        else if ("home".equals(name)) code = GLOBAL_ACTION_HOME;
        else if ("recents".equals(name)) code = GLOBAL_ACTION_RECENTS;
        else if ("notifications".equals(name)) code = GLOBAL_ACTION_NOTIFICATIONS;
        else if ("quick_settings".equals(name)) code = GLOBAL_ACTION_QUICK_SETTINGS;
        else return false;
        try { return s.performGlobalAction(code); } catch (Throwable t) { return false; }
    }

    /** 读取当前窗口可见文本，每行形如：文本  @[x,y] 点击 */
    public static String readScreen() {
        final LqbAccessibilityService s = INSTANCE;
        if (s == null) return "";
        AccessibilityNodeInfo root = null;
        try { root = s.getRootInActiveWindow(); } catch (Throwable t) { root = null; }
        if (root == null) return "";
        StringBuilder sb = new StringBuilder();
        try { walk(root, sb, 0); } catch (Throwable ignore) { }
        try { root.recycle(); } catch (Throwable ignore) { }
        return sb.toString();
    }

    private static void walk(AccessibilityNodeInfo node, StringBuilder sb, int depth) {
        if (node == null || depth > 24 || sb.length() > 12000) return;
        CharSequence text = node.getText();
        CharSequence desc = node.getContentDescription();
        boolean clickable = node.isClickable();
        String label = null;
        if (text != null && text.length() > 0) label = text.toString();
        else if (desc != null && desc.length() > 0) label = desc.toString();
        if (label != null) {
            label = label.replace("\n", " ").trim();
            if (label.length() > 60) label = label.substring(0, 60);
            if (label.length() > 0) {
                Rect r = new Rect();
                try { node.getBoundsInScreen(r); } catch (Throwable ignore) { }
                sb.append(label).append("  @[").append(r.centerX()).append(",").append(r.centerY()).append("]");
                if (clickable) sb.append(" 点击");
                sb.append('\n');
            }
        }
        int n;
        try { n = node.getChildCount(); } catch (Throwable t) { return; }
        for (int i = 0; i < n; i++) {
            AccessibilityNodeInfo c = null;
            try { c = node.getChild(i); } catch (Throwable t) { c = null; }
            if (c != null) {
                try { walk(c, sb, depth + 1); } catch (Throwable ignore) { }
                try { c.recycle(); } catch (Throwable ignore) { }
            }
        }
    }

    /* ============ [v116] 屏幕取点：无障碍悬浮窗（TYPE_ACCESSIBILITY_OVERLAY） ============
       用途：用户像用自动点击器一样，在【任意 App 之上】直接点屏幕取点。
       不需要 SYSTEM_ALERT_WINDOW，坐标天然是屏幕物理像素（与 dispatchGesture 同坐标系）。

       窗口分两层（同一 WindowManager）：
         1) PickView 全屏透明层：接收触摸、绘制标记；点「穿透」后设 FLAG_NOT_TOUCHABLE
            让触摸落到下层 App，方便用户切 App / 导航到目标界面再点回来取点。
         2) 底部控制条：撤销 / 穿透 / 完成 / 取消，永远可点（在下层之上，先加全屏层后加控制条）。

       生命周期：onUnbind / onDestroy / 再次 startPick 都会先 clearPickViews()，
       绝不残留窗口卡屏。
    */

    /** 取点回调：json 形如 {"evt":"start|add|undo|done|cancel","steps":[{...}]} */
    public interface PickCallback { void onEvent(String json); }

    private static volatile boolean sPicking = false;
    private static PickCallback sPickCb = null;
    private static LqbAccessibilityService sPickCtx = null;
    private static WindowManager sPickWm = null;
    private static View sPickView = null;
    private static View sPickBar = null;
    private static org.json.JSONArray sPickSteps = new org.json.JSONArray();
    private static boolean sPassThrough = false;
    private static TextView sPickCount = null;
    private static LinearLayout sPickTipBar = null;   // [v124] 顶部说明条
    private static TextView sPickPassBtn = null;

    public static boolean isPicking() { return sPicking; }

    private static int dpix(float v) {
        float d = 2f;
        try { if (sPickCtx != null) d = sPickCtx.getResources().getDisplayMetrics().density; } catch (Throwable t) { }
        return Math.round(v * d);
    }

    private static void runOnMain(Runnable r) {
        if (Looper.myLooper() == Looper.getMainLooper()) r.run();
        else new Handler(Looper.getMainLooper()).post(r);
    }

    /** 开始取点。返回 false = 无障碍服务没开或系统不支持 overlay。 */
    public static boolean startPick(final PickCallback cb) {
        final LqbAccessibilityService s = INSTANCE;
        if (s == null) return false;
        final CountDownLatch latch = new CountDownLatch(1);
        final AtomicBoolean ok = new AtomicBoolean(false);
        Runnable r = new Runnable() {
            public void run() {
                try { ok.set(doStartPick(s, cb)); } catch (Throwable t) { ok.set(false); clearPickViews(); }
                latch.countDown();
            }
        };
        if (Looper.myLooper() == Looper.getMainLooper()) r.run();
        else {
            new Handler(Looper.getMainLooper()).post(r);
            try { latch.await(2000, TimeUnit.MILLISECONDS); } catch (InterruptedException ie) { }
        }
        return ok.get();
    }

    private static boolean doStartPick(LqbAccessibilityService s, PickCallback cb) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return false;
        if (sPicking) clearPickViews();
        sPickCtx = s;
        WindowManager wm = (WindowManager) s.getSystemService(Context.WINDOW_SERVICE);
        if (wm == null) return false;
        sPickWm = wm;
        sPickSteps = new org.json.JSONArray();
        sPickCb = cb;
        sPassThrough = false;

        PickView v = new PickView(s);
        WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT, WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                        | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
                        | WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
                PixelFormat.TRANSLUCENT);
        lp.gravity = Gravity.TOP | Gravity.LEFT;
        lp.x = 0; lp.y = 0;
        /* [v127] API 30+：不裁剪任何系统栏区域，真正盖满整块屏幕
           （否则部分机型只盖住 App 内容区，状态栏和导航栏区域点不到） */
        if (Build.VERSION.SDK_INT >= 30) {
            try { lp.setFitInsetsTypes(0); } catch (Throwable ignore) {}
            try { lp.layoutInDisplayCutoutMode =
                    WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS; } catch (Throwable ignore) {}
        }
        try { lp.screenBrightness = WindowManager.LayoutParams.BRIGHTNESS_OVERRIDE_NONE; } catch (Throwable ignore) {}
        wm.addView(v, lp);
        sPickView = v;

        LinearLayout bar = buildPickBar(s);
        WindowManager.LayoutParams blp = new WindowManager.LayoutParams(
                WindowManager.LayoutParams.WRAP_CONTENT, WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.TRANSLUCENT);
        blp.gravity = Gravity.BOTTOM | Gravity.CENTER_HORIZONTAL;
        blp.y = dpix(30);
        wm.addView(bar, blp);
        sPickBar = bar;

        /* [v124] 顶部说明条：告诉用户怎么操作，不然只有底部一排按钮没人看得懂 */
        LinearLayout tip = buildPickTipBar(s);
        WindowManager.LayoutParams tlp = new WindowManager.LayoutParams(
                WindowManager.LayoutParams.WRAP_CONTENT, WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                        | WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE
                        | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                PixelFormat.TRANSLUCENT);
        tlp.gravity = Gravity.TOP | Gravity.CENTER_HORIZONTAL;
        tlp.y = dpix(46);
        try { wm.addView(tip, tlp); sPickTipBar = tip; } catch (Throwable ignore) {}

        sPicking = true;
        refreshPickBar();
        emitPick("start");
        return true;
    }

    /** 结束取点：commit=true 视为「完成」，false 视为「取消」。主线程安全。 */
    public static void stopPick(final boolean commit) {
        runOnMain(new Runnable() {
            public void run() { doStopPick(commit); }
        });
    }

    private static void doStopPick(boolean commit) {
        boolean was = sPicking;
        clearPickViews();
        if (was || commit) emitPick(commit ? "done" : "cancel");
        sPickCb = null;
        sPickCtx = null;
    }

    /** 撤销最近一个取点步骤。 */
    public static boolean undoPick() {
        if (!sPicking) return false;
        final AtomicBoolean ok = new AtomicBoolean(false);
        final CountDownLatch latch = new CountDownLatch(1);
        Runnable r = new Runnable() {
            public void run() {
                try {
                    int n = sPickSteps.length();
                    if (n > 0) { sPickSteps.remove(n - 1); ok.set(true); }
                } catch (Throwable t) { }
                try { if (sPickView != null) sPickView.invalidate(); } catch (Throwable t) { }
                refreshPickBar();
                if (ok.get()) emitPick("undo");
                latch.countDown();
            }
        };
        if (Looper.myLooper() == Looper.getMainLooper()) r.run();
        else {
            new Handler(Looper.getMainLooper()).post(r);
            try { latch.await(1000, TimeUnit.MILLISECONDS); } catch (InterruptedException ie) { }
        }
        return ok.get();
    }

    private static void clearPickViews() {
        try {
            if (sPickView != null && sPickWm != null) sPickWm.removeViewImmediate(sPickView);
        } catch (Throwable t) { }
        try {
            if (sPickBar != null && sPickWm != null) sPickWm.removeViewImmediate(sPickBar);
        } catch (Throwable t) { }
        sPickView = null;
        sPickBar = null;
        sPickCount = null;
        try { if (sPickTipBar != null && sPickWm != null) sPickWm.removeViewImmediate(sPickTipBar); } catch (Throwable ignore) {}
        sPickTipBar = null;
        sPickPassBtn = null;
        sPassThrough = false;
        sPicking = false;
    }

    private static void emitPick(String evt) {
        final PickCallback cb = sPickCb;
        if (cb == null) return;
        try {
            org.json.JSONObject o = new org.json.JSONObject();
            o.put("evt", evt);
            o.put("steps", new org.json.JSONArray(sPickSteps.toString()));
            cb.onEvent(o.toString());
        } catch (Throwable t) { }
    }

    private static void togglePassThrough() {
        if (sPickView == null || sPickWm == null) return;
        try {
            WindowManager.LayoutParams lp = (WindowManager.LayoutParams) sPickView.getLayoutParams();
            if (lp == null) return;
            sPassThrough = !sPassThrough;
            if (sPassThrough) lp.flags |= WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE;
            else lp.flags &= ~WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE;
            sPickWm.updateViewLayout(sPickView, lp);
        } catch (Throwable t) { }
        refreshPickBar();
    }

    private static void refreshPickBar() {
        try {
            if (sPickCount != null) sPickCount.setText("已取 " + sPickSteps.length() + " 点");
            if (sPickPassBtn != null) sPickPassBtn.setText(sPassThrough ? "取点" : "穿透");
        } catch (Throwable t) { }
    }

    private static TextView mkPickBtn(Context c, String text) {
        TextView t = new TextView(c);
        t.setText(text);
        t.setTextColor(0xFFFFFFFF);
        t.setTextSize(13f);
        t.setGravity(Gravity.CENTER);
        t.setPadding(dpix(12), dpix(7), dpix(12), dpix(7));
        t.setClickable(true);
        return t;
    }

    /** [v124] 顶部说明条：短按取点击、拖动取滑动，并提示可穿透回 App 操作。 */
    private static LinearLayout buildPickTipBar(Context c) {
        LinearLayout bar = new LinearLayout(c);
        bar.setOrientation(LinearLayout.VERTICAL);
        bar.setGravity(Gravity.CENTER_HORIZONTAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xF21B1F2A);
        bg.setCornerRadius(dpix(16));
        bg.setStroke(Math.max(1, dpix(1)), 0x66FFFFFF);
        bar.setBackground(bg);
        bar.setPadding(dpix(14), dpix(9), dpix(14), dpix(9));

        TextView t1 = new TextView(c);
        t1.setText("取点模式 · 全屏");
        t1.setTextColor(0xFF9FB6FF);
        t1.setTextSize(12f);
        t1.setGravity(Gravity.CENTER);
        t1.getPaint().setFakeBoldText(true);
        bar.addView(t1);

        TextView t2 = new TextView(c);
        t2.setText("点一下 = 点击　划一下 = 滑动");
        t2.setTextColor(0xFFFFFFFF);
        t2.setTextSize(12f);
        t2.setGravity(Gravity.CENTER);
        t2.setPadding(0, dpix(3), 0, 0);
        bar.addView(t2);

        TextView t3 = new TextView(c);
        t3.setText("取完点「完成」回 App 保存 · 想操作底层界面点「穿透」");
        t3.setTextColor(0xFFB9C0CF);
        t3.setTextSize(11f);
        t3.setGravity(Gravity.CENTER);
        t3.setPadding(0, dpix(2), 0, 0);
        bar.addView(t3);
        return bar;
    }

    private static LinearLayout buildPickBar(Context c) {
        LinearLayout bar = new LinearLayout(c);
        bar.setOrientation(LinearLayout.HORIZONTAL);
        bar.setGravity(Gravity.CENTER_VERTICAL);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xF21B1F2A);
        bg.setCornerRadius(dpix(24));
        bg.setStroke(Math.max(1, dpix(1)), 0x66FFFFFF);
        bar.setBackground(bg);
        bar.setPadding(dpix(4), dpix(4), dpix(4), dpix(4));

        sPickCount = mkPickBtn(c, "已取 0 点");
        sPickCount.setTextColor(0xFF9FB6FF);
        bar.addView(sPickCount);

        TextView bUndo = mkPickBtn(c, "撤销");
        bUndo.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { undoPick(); }
        });
        bar.addView(bUndo);

        sPickPassBtn = mkPickBtn(c, "穿透");
        sPickPassBtn.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { togglePassThrough(); }
        });
        bar.addView(sPickPassBtn);

        TextView bDone = mkPickBtn(c, "完成");
        bDone.setTextColor(0xFF6FE39B);
        bDone.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { doStopPick(true); }
        });
        bar.addView(bDone);

        TextView bCancel = mkPickBtn(c, "取消");
        bCancel.setTextColor(0xFFFF8B8B);
        bCancel.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { doStopPick(false); }
        });
        bar.addView(bCancel);
        return bar;
    }

    /** 全屏透明取点层：短按=点击点，按住拖动=滑动（记起点/终点/时长）。 */
    static class PickView extends View {
        private final Paint pRing = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint pFill = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint pLine = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint pTxt = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint pTxtB = new Paint(Paint.ANTI_ALIAS_FLAG);
        /* [v127] 取点层可见性用的画笔 */
        private final Paint pEdge = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint pTag = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint pTagBg = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final int[] loc = new int[2];
        private float d = 2f;
        private float slop = 24f;
        private float downX, downY, curX, curY;
        private long downT = 0;
        private boolean dragging = false;

        PickView(Context c) {
            super(c);
            d = c.getResources().getDisplayMetrics().density;
            try { slop = ViewConfiguration.get(c).getScaledTouchSlop() * 1.4f; } catch (Throwable t) { }
            pRing.setStyle(Paint.Style.STROKE);
            pRing.setStrokeWidth(3f * d);
            pRing.setColor(0xFF4DA3FF);
            pFill.setStyle(Paint.Style.FILL);
            pFill.setColor(0x554DA3FF);
            pLine.setStyle(Paint.Style.STROKE);
            pLine.setStrokeWidth(3f * d);
            pLine.setStrokeCap(Paint.Cap.ROUND);
            pLine.setColor(0xFF4DA3FF);
            pTxt.setTextSize(13f * d);
            pTxt.setTextAlign(Paint.Align.CENTER);
            pTxt.setColor(0xFFFFFFFF);
            pTxt.setFakeBoldText(true);
            pTxtB.setTextSize(13f * d);
            pTxtB.setTextAlign(Paint.Align.CENTER);
            pTxtB.setStyle(Paint.Style.STROKE);
            pTag.setTextSize(11.5f * d);
            pTag.setColor(0xFFFFFFFF);
            pTag.setFakeBoldText(true);
            pTag.setAntiAlias(true);
            pTagBg.setStyle(Paint.Style.FILL);
            pTagBg.setAntiAlias(true);
            pTxtB.setStrokeWidth(4f * d);
            pTxtB.setColor(0xFF000000);
            pTxtB.setFakeBoldText(true);
        }

        @Override
        public boolean onTouchEvent(MotionEvent e) {
            switch (e.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    downX = e.getX(); downY = e.getY();
                    curX = downX; curY = downY;
                    downT = System.currentTimeMillis();
                    dragging = false;
                    invalidate();
                    return true;
                case MotionEvent.ACTION_MOVE:
                    curX = e.getX(); curY = e.getY();
                    if (!dragging) {
                        float dx = curX - downX, dy = curY - downY;
                        if (Math.sqrt(dx * dx + dy * dy) > slop) {
                            dragging = true;
                            downT = System.currentTimeMillis();
                        }
                    }
                    if (dragging) invalidate();
                    return true;
                case MotionEvent.ACTION_UP:
                    long dur = System.currentTimeMillis() - downT;
                    if (dur < 120) dur = 120;
                    if (dur > 3000) dur = 3000;
                    getLocationOnScreen(loc);
                    float sx1 = downX + loc[0], sy1 = downY + loc[1];
                    float sx2 = e.getX() + loc[0], sy2 = e.getY() + loc[1];
                    if (dragging) recordSwipe(sx1, sy1, sx2, sy2, dur);
                    else recordTap(sx1, sy1);
                    dragging = false;
                    invalidate();
                    return true;
                case MotionEvent.ACTION_CANCEL:
                    dragging = false;
                    invalidate();
                    return true;
                default:
                    return true;
            }
        }

        @Override
        protected void onDraw(Canvas c) {
            getLocationOnScreen(loc);
            /* [v127] 让取点层「看得见」：极淡遮罩 + 四边描边 + 左上角状态标签。
               原来这层是全透明的，用户根本不知道自己在取点模式。 */
            int vw = getWidth(), vh = getHeight();
            c.drawColor(0x0A000000);                    /* 4% 黑，压一下底层但不挡内容 */
            pEdge.setStyle(Paint.Style.STROKE);
            pEdge.setStrokeWidth(Math.max(2f, 2f * d));
            pEdge.setColor(0xCC4DA3FF);
            float inset = Math.max(2f, 2f * d);
            c.drawRect(inset, inset, vw - inset, vh - inset, pEdge);
            /* 左上角标签 */
            String tag = "取点中 " + sPickSteps.length();
            float tw = pTag.measureText(tag);
            float pad = 9f * d, th = 15f * d;
            float ty0 = 14f * d;
            pTagBg.setColor(0xE61B1F2A);
            c.drawRoundRect(12f * d, ty0, 12f * d + tw + pad * 2, ty0 + th + pad, 7f * d, 7f * d, pTagBg);
            c.drawText(tag, 12f * d + pad, ty0 + th, pTag);
            int n = sPickSteps.length();
            for (int i = 0; i < n; i++) {
                org.json.JSONObject o = sPickSteps.optJSONObject(i);
                if (o == null) continue;
                if ("swipe".equals(o.optString("type"))) {
                    drawSwipe(c, (float) o.optDouble("x1"), (float) o.optDouble("y1"),
                            (float) o.optDouble("x2"), (float) o.optDouble("y2"), i + 1);
                } else {
                    drawDot(c, (float) o.optDouble("x"), (float) o.optDouble("y"), i + 1);
                }
            }
            if (dragging) {
                drawSwipe(c, downX + loc[0], downY + loc[1], curX + loc[0], curY + loc[1], -1);
            }
        }

        private void drawDot(Canvas c, float sx, float sy, int idx) {
            float x = sx - loc[0], y = sy - loc[1];
            float r = 20f * d;
            c.drawCircle(x, y, r, pFill);
            c.drawCircle(x, y, r, pRing);
            if (idx > 0) {
                String s = String.valueOf(idx);
                float ty = y + 4.6f * d;
                c.drawText(s, x, ty, pTxtB);
                c.drawText(s, x, ty, pTxt);
            }
        }

        private void drawSwipe(Canvas c, float sx1, float sy1, float sx2, float sy2, int idx) {
            float x1 = sx1 - loc[0], y1 = sy1 - loc[1], x2 = sx2 - loc[0], y2 = sy2 - loc[1];
            c.drawLine(x1, y1, x2, y2, pLine);
            double ang = Math.atan2(y2 - y1, x2 - x1);
            float ah = 15f * d;
            for (int k = -1; k <= 1; k += 2) {
                double a = ang + k * 0.45;
                c.drawLine(x2, y2, x2 - (float) (Math.cos(a) * ah), y2 - (float) (Math.sin(a) * ah), pLine);
            }
            drawDot(c, sx1, sy1, idx);
            c.drawCircle(x2, y2, 12f * d, pRing);
        }

        private void recordTap(float sx, float sy) {
            try {
                org.json.JSONObject o = new org.json.JSONObject();
                o.put("type", "tap");
                o.put("x", Math.round(sx));
                o.put("y", Math.round(sy));
                sPickSteps.put(o);
            } catch (Throwable t) { return; }
            refreshPickBar();
            emitPick("add");
        }

        private void recordSwipe(float sx1, float sy1, float sx2, float sy2, long dur) {
            try {
                org.json.JSONObject o = new org.json.JSONObject();
                o.put("type", "swipe");
                o.put("x1", Math.round(sx1));
                o.put("y1", Math.round(sy1));
                o.put("x2", Math.round(sx2));
                o.put("y2", Math.round(sy2));
                o.put("dur", (int) dur);
                sPickSteps.put(o);
            } catch (Throwable t) { return; }
            refreshPickBar();
            emitPick("add");
        }
    }

}
