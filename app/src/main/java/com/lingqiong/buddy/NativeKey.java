package com.lingqiong.buddy;

/**
 * NativeKey —— 从 native 层取得「包密钥解包私钥」（PKCS#8 DER）。
 *
 * 【设计原则：绝不闪退】
 *   · System.loadLibrary 全程包 try-catch —— 任何加载失败（ABI 不匹配、.so 缺失、
 *     平台限制）都只把 available() 置为 false，绝不向上抛异常、绝不崩溃；
 *   · 所有 native 调用再包一层 try-catch，失败一律返回 null；
 *   · 上层（FrontCrypto/FrontLoader）拿到 null 后走"降级路径"（回退旧格式），
 *     因此即使 native 完全不可用，App 仍能正常启动。
 *
 * 私钥以滚动异或形式内嵌于 liblqkey.so，反编译 Java 层拿不到。
 */
public final class NativeKey {

    /** native 库是否可用。 */
    private static final boolean OK;

    static {
        boolean ok;
        try {
            System.loadLibrary("lqkey");
            ok = true;
        } catch (Throwable t) {
            // 不打印、不抛出：静默降级即可（避免在启动路径上产生任何风险）
            ok = false;
        }
        OK = ok;
    }

    private NativeKey() {}

    /** native 是否可用。不可用时上层应直接走降级路径。 */
    public static boolean available() {
        return OK;
    }

    /**
     * 返回私钥 PKCS#8 DER 的副本。
     * @return DER 字节；native 不可用 / 返回异常 / 长度非法时一律返回 null。
     */
    public static byte[] privateDer() {
        if (!OK) return null;
        try {
            byte[] d = privateDerNative();
            if (d == null || d.length <= 0) return null;
            return d;
        } catch (Throwable t) {
            return null;
        }
    }

    /** 返回内嵌材料长度（健全性检查用）；异常返回 -1。 */
    public static int derLen() {
        if (!OK) return -1;
        try {
            return derLenNative();
        } catch (Throwable t) {
            return -1;
        }
    }

    // ── native 实现（见 app/src/main/cpp/lqkey.c）──
    private static native byte[] privateDerNative();
    private static native int    derLenNative();
}
