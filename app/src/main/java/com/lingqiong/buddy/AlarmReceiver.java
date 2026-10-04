package com.lingqiong.buddy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/**
 * [v43] 定时任务触发广播：系统闹钟到点时被唤醒。
 *  1) 把任务写入「待执行」队列（下次打开 App 时由前端取走并自动发送）；
 *  2) 发一条通知提醒用户；
 *  3) 重新排下一天（每天型）。
 */
public class AlarmReceiver extends BroadcastReceiver {

    public static final String ACTION_FIRE = "com.lq.app.SCHEDULE_FIRE";
    private static final String CH_ID = "lqb_sched";

    @Override
    public void onReceive(Context ctx, Intent it) {
        if (it == null || !ACTION_FIRE.equals(it.getAction())) return;
        String convId = it.getStringExtra("convId");
        String prompt = it.getStringExtra("prompt");
        if (prompt == null || prompt.trim().isEmpty()) return;

        ScheduleStore.addPending(ctx, convId == null ? "" : convId, prompt);
        notifyUser(ctx, prompt);
        // 重新排程：每天型顺延到明天，仅一次型自然过期
        try { ScheduleManager.rescheduleAll(ctx); } catch (Throwable ignore) {}
    }

    private void notifyUser(Context ctx, String prompt) {
        try {
            NotificationManager nm = (NotificationManager) ctx.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm == null) return;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm.getNotificationChannel(CH_ID) == null) {
                NotificationChannel ch = new NotificationChannel(CH_ID, "定时任务", NotificationManager.IMPORTANCE_DEFAULT);
                ch.setDescription("LingQiongBuddy 定时任务到点提醒");
                nm.createNotificationChannel(ch);
            }
            Intent open = new Intent(ctx, MainActivity.class);
            open.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            int flags = PendingIntent.FLAG_UPDATE_CURRENT;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) flags |= PendingIntent.FLAG_IMMUTABLE;
            int id = (int) (System.currentTimeMillis() & 0x7fffffff);
            PendingIntent pi = PendingIntent.getActivity(ctx, id, open, flags);
            String txt = prompt.length() > 40 ? prompt.substring(0, 40) + "…" : prompt;
            Notification.Builder b = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                    ? new Notification.Builder(ctx, CH_ID)
                    : new Notification.Builder(ctx);
            b.setSmallIcon(android.R.drawable.ic_popup_reminder)
                    .setContentTitle("定时任务已到点")
                    .setContentText(txt)
                    .setAutoCancel(true)
                    .setContentIntent(pi);
            nm.notify(id, b.build());
        } catch (Throwable ignore) {
        }
    }
}
