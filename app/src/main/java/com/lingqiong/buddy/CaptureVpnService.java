package com.lingqiong.buddy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

/**
 * [v27] 抓包用 VpnService：建立本地 VPN(TUN)，把系统流量交给 CaptureEngine 转发 + 记录。
 * 无 root 设备上，这是唯一能捕获其它 App 流量的合法途径。
 *
 * [v27.1 加固] Android 8.0 起，普通后台服务在 App 退到后台约 1 分钟后会被系统回收，
 * 抓包会因此中断；必须走 startForeground（前台服务 + 常驻通知）才能持续。
 * 这里所有系统调用都包了 try/catch，保证即使通知/前台化失败也绝不拖垮 App。
 */
public class CaptureVpnService extends VpnService {

    public static final String ACTION_START = "com.lingqiong.buddy.CAPTURE_START";
    public static final String ACTION_STOP = "com.lingqiong.buddy.CAPTURE_STOP";

    private static final String CH_ID = "lq_capture";
    private static final int NOTI_ID = 0x4C71; // 'LQ'

    private static volatile CaptureVpnService instance;
    private ParcelFileDescriptor tun;
    private Thread engineThread;
    private CaptureEngine engine;
    private volatile boolean running = false;

    public static boolean isRunning() {
        CaptureVpnService s = instance;
        return s != null && s.running;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_STOP.equals(action)) {
            stopCapture();
            return START_NOT_STICKY;
        }
        startCapture();
        return START_STICKY;
    }

    /** 前台服务通知：保证抓包在后台持续运行。全部 try/catch，绝不影响启动。 */
    private void goForeground() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
                if (nm != null && nm.getNotificationChannel(CH_ID) == null) {
                    NotificationChannel ch = new NotificationChannel(
                            CH_ID, "网络抓包", NotificationManager.IMPORTANCE_LOW);
                    ch.setShowBadge(false);
                    nm.createNotificationChannel(ch);
                }
            }
            Intent open = new Intent(this, MainActivity.class);
            open.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            int piFlags = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
                    ? PendingIntent.FLAG_IMMUTABLE : 0;
            PendingIntent pi = PendingIntent.getActivity(this, 0, open, piFlags);
            Notification.Builder nb = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                    ? new Notification.Builder(this, CH_ID)
                    : new Notification.Builder(this);
            nb.setContentTitle("LingQiongBuddy 抓包中")
                    .setContentText("正在记录网络请求 · 点此返回应用")
                    .setSmallIcon(android.R.drawable.stat_sys_download)
                    .setOngoing(true)
                    .setContentIntent(pi);
            startForeground(NOTI_ID, nb.build());
        } catch (Throwable ignore) {
            // 前台化失败不影响抓包本身
        }
    }

    public void startCapture() {
        if (running) return;
        try {
            goForeground();
            Builder b = new Builder();
            b.setSession("LingQiongBuddy 抓包");
            b.setMtu(1500);
            b.addAddress("10.8.0.2", 32);
            b.addDnsServer("223.5.5.5");
            b.addDnsServer("119.29.29.29");
            b.addRoute("0.0.0.0", 0);

            tun = b.establish();
            if (tun == null) {
                running = false;
                CaptureStore.setCapturing(false);
                return;
            }
            engine = new CaptureEngine(tun, this);
            engineThread = new Thread(engine, "cap-engine");
            engineThread.start();
            running = true;
            instance = this;
            CaptureStore.setCapturing(true);
        } catch (Throwable t) {
            running = false;
            CaptureStore.setCapturing(false);
        }
    }

    public void stopCapture() {
        running = false;
        CaptureStore.setCapturing(false);
        try { if (engine != null) engine.stop(); } catch (Throwable ignore) {}
        try { if (engineThread != null) engineThread.interrupt(); } catch (Throwable ignore) {}
        try { if (tun != null) tun.close(); } catch (Throwable ignore) {}
        tun = null;
        engine = null;
        engineThread = null;
        instance = null;
        try { stopForeground(true); } catch (Throwable ignore) {}
        try { stopSelf(); } catch (Throwable ignore) {}
    }

    @Override
    public void onRevoke() {
        stopCapture();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        stopCapture();
        super.onDestroy();
    }
}
