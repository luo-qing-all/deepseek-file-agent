package com.lingqiong.buddy;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Calendar;

/**
 * [v43] 定时任务调度：把前端同步来的任务排进系统 AlarmManager。
 *
 * 策略：
 *  - 每条任务按其「每天 / 仅一次」计算下一次触发时刻，用 setExactAndAllowWhileIdle 精确排程；
 *  - 无精确闹钟权限时自动降级为 set()（可能略有延迟，但不崩）；
 *  - 到点由 AlarmReceiver 接收 → 写入待执行队列 + 发通知 → 重新排下一天。
 *  - 开机由 BootReceiver 重新排程，避免重启后丢失。
 */
public class ScheduleManager {

    public static void apply(Context ctx, String json) {
        ScheduleStore.saveAll(ctx, json);
        rescheduleAll(ctx);
    }

    public static void rescheduleAll(Context ctx) {
        try {
            AlarmManager am = (AlarmManager) ctx.getSystemService(Context.ALARM_SERVICE);
            if (am == null) return;
            JSONArray arr = new JSONArray(ScheduleStore.loadAll(ctx));
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.optJSONObject(i);
                if (o == null) continue;
                if (!o.optBoolean("enabled", true)) continue;
                String time = o.optString("time", "");
                String prompt = o.optString("prompt", "");
                String convId = o.optString("convId", "");
                boolean once = "once".equals(o.optString("repeat", "daily"));
                if (time.isEmpty() || prompt.isEmpty()) continue;

                long trigger = nextTrigger(time, once);
                if (once && trigger < System.currentTimeMillis()) continue;

                Intent it = new Intent(ctx, AlarmReceiver.class);
                it.setAction(AlarmReceiver.ACTION_FIRE);
                it.putExtra("convId", convId);
                it.putExtra("prompt", prompt);
                int reqCode = (convId + "|" + time + "|" + i).hashCode();
                int flags = PendingIntent.FLAG_UPDATE_CURRENT;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) flags |= PendingIntent.FLAG_IMMUTABLE;
                PendingIntent pi = PendingIntent.getBroadcast(ctx, reqCode, it, flags);

                try {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        am.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, trigger, pi);
                    } else {
                        am.setExact(AlarmManager.RTC_WAKEUP, trigger, pi);
                    }
                } catch (SecurityException se) {
                    am.set(AlarmManager.RTC_WAKEUP, trigger, pi);
                }
            }
        } catch (Throwable ignore) {
        }
    }

    /** 计算下一次触发时间戳（毫秒）。每天：若今天已过则顺延到明天；仅一次：今天该时刻。 */
    private static long nextTrigger(String hhmm, boolean once) {
        String[] p = hhmm.split(":");
        int h = 0, m = 0;
        try {
            h = Integer.parseInt(p[0]);
            m = Integer.parseInt(p[1]);
        } catch (Exception ignore) {
        }
        Calendar c = Calendar.getInstance();
        c.set(Calendar.HOUR_OF_DAY, h);
        c.set(Calendar.MINUTE, m);
        c.set(Calendar.SECOND, 0);
        c.set(Calendar.MILLISECOND, 0);
        long t = c.getTimeInMillis();
        if (!once && t <= System.currentTimeMillis()) {
            t += 24L * 60 * 60 * 1000;
        }
        return t;
    }
}
