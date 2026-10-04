package com.lingqiong.buddy;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.GestureDescription;
import android.content.Intent;
import android.graphics.Path;
import android.graphics.Rect;
import android.os.Build;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

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
        INSTANCE = null;
        return super.onUnbind(intent);
    }

    /** 无障碍权限是否已开启（服务是否已连接）。 */
    public static boolean isEnabled() {
        return INSTANCE != null;
    }

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
}
