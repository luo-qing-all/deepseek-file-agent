package com.lingqiong.buddy;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * [v43] 开机重排定时任务：手机重启后 AlarmManager 排程会清空，这里重新排上。
 */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context ctx, Intent it) {
        if (it == null) return;
        String a = it.getAction();
        if (Intent.ACTION_BOOT_COMPLETED.equals(a) || "android.intent.action.QUICKBOOT_POWERON".equals(a)) {
            try { ScheduleManager.rescheduleAll(ctx); } catch (Throwable ignore) {}
        }
    }
}
