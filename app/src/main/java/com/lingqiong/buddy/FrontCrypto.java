package com.lingqiong.buddy;

import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * FrontCrypto —— 客户端解密核心（纯 JDK，可脱离 Android 单独编译验证）。
 * 与 FrontPack.pack 完全对称：
 *   1) 用内置公钥验签 (key|iv|cipher)  —— 防篡改
 *   2) 用 AES-256-GCM 解密            —— 取回明文 HTML
 * 验签失败抛 SecurityException("SIG_FAIL")；GCM 认证失败会抛 AEADBadTagException。
 * Android 端 MainActivity 将调用 decode()，故此处验证通过 = 端上可解。
 */
public class FrontCrypto {
    /**
     * [minSdk 24 兼容] 内置 Base64 编解码。
     *
     * 为什么不用 java.util.Base64：它在 Android 上是 API 26 才有的类，
     * 而 desugar_jdk_libs 并不提供它的 backport；本类的 decode() 在 App
     * 启动路径上（解密前端包），一旦缺类就是闪退，故自带一份纯 JDK 实现。
     * 行为与 java.util.Base64 一致：解码忽略换行/空白/多余的 '='。
     */
    static final class B64 {
        private static final char[] ENC =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
        private static final int[] DEC = new int[256];
        static {
            for (int i = 0; i < DEC.length; i++) DEC[i] = -1;
            for (int i = 0; i < ENC.length; i++) DEC[ENC[i]] = i;
        }
        static byte[] decode(String s) {
            byte[] out = new byte[s.length() / 4 * 3 + 3];
            int o = 0, buf = 0, bits = 0;
            for (int i = 0; i < s.length(); i++) {
                char ch = s.charAt(i);
                if (ch >= 256) continue;
                int v = DEC[ch];
                if (v < 0) continue;                 // 空白 / '=' / 非法字符一律跳过
                buf = (buf << 6) | v;
                bits += 6;
                if (bits >= 8) { bits -= 8; out[o++] = (byte) ((buf >> bits) & 0xFF); }
            }
            byte[] r = new byte[o];
            System.arraycopy(out, 0, r, 0, o);
            return r;
        }
        static String encode(byte[] b) {
            StringBuilder sb = new StringBuilder((b.length + 2) / 3 * 4);
            for (int i = 0; i < b.length; i += 3) {
                int rem = b.length - i;
                int n = (b[i] & 0xFF) << 16;
                if (rem > 1) n |= (b[i + 1] & 0xFF) << 8;
                if (rem > 2) n |= (b[i + 2] & 0xFF);
                sb.append(ENC[(n >> 18) & 63]).append(ENC[(n >> 12) & 63]);
                sb.append(rem > 1 ? ENC[(n >> 6) & 63] : '=');
                sb.append(rem > 2 ? ENC[n & 63] : '=');
            }
            return sb.toString();
        }
    }

    public static String decode(String json, String pubPem) throws Exception {
        String keyB = grab(json, "key");
        String ivB = grab(json, "iv");
        String cipherB = grab(json, "cipher");
        String sigB = grab(json, "sig");

        byte[] toSign = (keyB + "|" + ivB + "|" + cipherB).getBytes("UTF-8");
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pubFromPem(pubPem));
        s.update(toSign);
        if (!s.verify(B64.decode(sigB))) throw new SecurityException("SIG_FAIL");

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(B64.decode(keyB), "AES"),
                new GCMParameterSpec(128, B64.decode(ivB)));
        return new String(c.doFinal(B64.decode(cipherB)), "UTF-8");
    }

    static PublicKey pubFromPem(String pem) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (String line : pem.split("\n")) {
            line = line.trim();
            if (line.startsWith("-----") || line.isEmpty()) continue;
            sb.append(line);
        }
        return KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(B64.decode(sb.toString())));
    }

    static String grab(String json, String f) {
        String pat = "\"" + f + "\":\"";
        int i = json.indexOf(pat);
        if (i < 0) return "";
        i += pat.length();
        int j = json.indexOf('"', i);
        return (j < 0) ? "" : json.substring(i, j);
    }

    public static void main(String[] a) throws Exception {
        String json = readText(a[0]);
        String pem = readText(a[1]);
        String html = decode(json, pem);
        System.out.println("decoded chars: " + html.length());
        if (a.length > 2) {
            FileOutputStream o = new FileOutputStream(a[2]);
            try { o.write(html.getBytes("UTF-8")); } finally { o.close(); }
        }
    }

    /** [minSdk 24 兼容] 读整个文件为文本（java.io 版）。 */
    static String readText(String path) throws Exception {
        File f = new File(path);
        byte[] b = new byte[(int) f.length()];
        FileInputStream in = new FileInputStream(f);
        try {
            int off = 0, n;
            while (off < b.length && (n = in.read(b, off, b.length - off)) > 0) off += n;
            if (off < b.length) {
                byte[] t = new byte[off];
                System.arraycopy(b, 0, t, 0, off);
                return new String(t, "UTF-8");
            }
            return new String(b, "UTF-8");
        } finally {
            in.close();
        }
    }
}
