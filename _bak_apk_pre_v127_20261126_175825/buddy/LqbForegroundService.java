package com.lingqiong.buddy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;

/**
 * [2.6.0] AI 后台持续运行的前台服务。
 *
 * 为什么需要它：
 *   Android 8+ 对后台进程限制很严，App 一旦退到后台 / 熄屏，普通后台进程会被
 *   快速冻结甚至回收，导致 WebView 里正在进行的 AI 流式输出被掐断。
 *   以前台服务（带常驻通知）形式运行则不受此限制，配合 MainActivity 持有的
 *   PARTIAL_WAKE_LOCK（熄屏时 CPU 不休眠），可实现「熄屏 / 退到桌面后 AI 继续输出」。
 *
 * 生命周期：
 *   仅在「AI 生成期间」存在——生成开始由 MainActivity.workBegin() 调起，
 *   生成结束由 workEnd() 通过 stopService() 停止，前台通知随之消失，
 *   不会长期占用通知栏。
 */
public class LqbForegroundService extends Service {

    public static final String ACTION_START = "com.lq.app.WORK_START";
    public static final String ACTION_STOP  = "com.lq.app.WORK_STOP";
    public static final String EXTRA_TITLE  = "title";

    private static final String CH_ID = "lq_ai_work";
    private static final int NOTI_ID = 20001;

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = (intent == null) ? null : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopForegroundCompat();
            stopSelf();
            return START_NOT_STICKY;
        }
        String title = (intent == null) ? null : intent.getStringExtra(EXTRA_TITLE);
        ensureChannel();
        Notification n = buildNoti(title);
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                startForeground(NOTI_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
            } else {
                startForeground(NOTI_ID, n);
            }
        } catch (Throwable t) {
            try { startForeground(NOTI_ID, n); } catch (Throwable ignore) {}
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy() {
        stopForegroundCompat();
        super.onDestroy();
    }

    private void stopForegroundCompat() {
        try { stopForeground(true); } catch (Throwable ignore) {}
    }

    private void ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return;
        try {
            NotificationManager m = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (m == null || m.getNotificationChannel(CH_ID) != null) return;
            // LOW：静默显示在通知栏，不弹横幅、不响铃
            NotificationChannel ch = new NotificationChannel(CH_ID, "AI 后台运行中", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            m.createNotificationChannel(ch);
        } catch (Throwable ignore) {}
    }

    private Notification buildNoti(String title) {
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        int piFlag = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                ? (PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE)
                : PendingIntent.FLAG_UPDATE_CURRENT;
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, piFlag);
        Notification.Builder b = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                ? new Notification.Builder(this, CH_ID)
                : new Notification.Builder(this);
        String txt = (title == null || title.length() == 0) ? "AI 正在生成回复…" : ("「" + title + "」正在生成…");
        b.setContentTitle("LingQiongBuddy")
         .setContentText(txt)
         .setSmallIcon(getApplicationInfo().icon)
         .setOngoing(true)
         .setContentIntent(pi);
        return b.build();
    }
}
