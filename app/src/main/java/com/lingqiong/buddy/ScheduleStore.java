package com.lingqiong.buddy;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * [v43] 定时任务存储：持久化「全部任务」与「已到点待执行」队列。
 * 用 SharedPreferences，无需额外文件权限，开机/重启后仍在。
 */
public class ScheduleStore {

    private static final String SP = "lqb_sched";

    private static SharedPreferences sp(Context c) {
        return c.getSharedPreferences(SP, Context.MODE_PRIVATE);
    }

    /** 前端同步过来的全部任务（JSON 数组字符串）。 */
    public static void saveAll(Context c, String json) {
        sp(c).edit().putString("list", json == null ? "[]" : json).apply();
    }

    public static String loadAll(Context c) {
        return sp(c).getString("list", "[]");
    }

    /** 闹钟到点：把该任务压入「待执行」队列（页面上一次执行）。 */
    public static synchronized void addPending(Context c, String convId, String prompt) {
        try {
            JSONArray arr = new JSONArray(sp(c).getString("pending", "[]"));
            JSONObject o = new JSONObject();
            o.put("convId", convId == null ? "" : convId);
            o.put("prompt", prompt == null ? "" : prompt);
            o.put("ts", System.currentTimeMillis());
            arr.put(o);
            while (arr.length() > 20) arr.remove(0);
            sp(c).edit().putString("pending", arr.toString()).apply();
        } catch (Exception ignore) {
        }
    }

    /** 前端启动时取走待执行队列，并清空。 */
    public static synchronized String takePending(Context c) {
        String v = sp(c).getString("pending", "[]");
        sp(c).edit().putString("pending", "[]").apply();
        return v;
    }
}
