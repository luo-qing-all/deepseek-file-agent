package com.lingqiong.buddy;

import java.io.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

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

    /**
     * [加固 v2] 解包流程（密钥不落地）：
     *   ① 验签 (2|ekey|iv|cipher)                —— 防篡改
     *   ② 用 native 私钥做 RSA-OAEP 解出 AES 密钥  —— 下载者也拿不到明文密钥
     *   ③ AES-256-GCM 解密正文
     * 任何一步失败都会抛异常，由 FrontLoader 捕获并降级（绝不闪退）。
     */
    public static String decodeV2(String json, String pubPem) throws Exception {
        String ekeyB = grab(json, "ekey");
        String ivB = grab(json, "iv");
        String cipherB = grab(json, "cipher");
        String sigB = grab(json, "sig");
        if (ekeyB.length() == 0 || ivB.length() == 0 || cipherB.length() == 0 || sigB.length() == 0) {
            throw new SecurityException("V2_MISSING_FIELDS");
        }

        // ① 验签
        byte[] toSign = ("2|" + ekeyB + "|" + ivB + "|" + cipherB).getBytes("UTF-8");
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pubFromPem(pubPem));
        s.update(toSign);
        if (!s.verify(B64.decode(sigB))) throw new SecurityException("SIG_FAIL");

        // ② 取 native 私钥并解包 ekey
        byte[] der = NativeKey.privateDer();
        if (der == null) throw new IllegalStateException("NATIVE_KEY_UNAVAILABLE");
        PrivateKey priv = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(der));

        byte[] ek = B64.decode(ekeyB);
        byte[] aesKey;
        try {
            // 标准：SHA-256 摘要 + MGF1(SHA-256)
            aesKey = rsaUnwrap(priv, ek, "SHA-256");
        } catch (Throwable t1) {
            // 兼容：部分 Android 实现会忽略 OAEPParameterSpec 的 MGF1 参数而固定用 SHA-1，
            // 此时上面会失败，这里用 MGF1(SHA-1) 再试一次（hash 仍是 SHA-256）。
            aesKey = rsaUnwrap(priv, ek, "SHA-1");
        }
        if (aesKey == null || aesKey.length != 32) throw new SecurityException("EKEY_UNWRAP_FAIL");

        // ③ AES-GCM 解密
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                new GCMParameterSpec(128, B64.decode(ivB)));
        return new String(c.doFinal(B64.decode(cipherB)), "UTF-8");
    }

    /** RSA-OAEP 解包：hash=SHA-256，MGF1 摘要由参数指定（兼容不同 Android 实现）。 */
    private static byte[] rsaUnwrap(PrivateKey priv, byte[] ek, String mgf1) throws Exception {
        Cipher rc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaep = new OAEPParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec(mgf1), PSource.PSpecified.DEFAULT);
        rc.init(Cipher.DECRYPT_MODE, priv, oaep);
        return rc.doFinal(ek);
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

    /**
     * [v83] 解码 v3 包：manifest（清单）+ 已按 sha 拼装好的完整密文 → HTML。
     *
     * manifest 结构：
     *   {"v":91,"fmt":"v3","ekey":"..","iv":"..","len":769021,"chunk":65536,
     *    "n":12,"chunks":["sha256hex",...],"html":"明文sha256","sig":".."}
     *
     * 安全性：签名覆盖 版本|ekey|iv|长度|块大小|块sha列表|明文sha，
     *        任何块被替换/删改都会导致签名不匹配或解密失败。
     */
    /**
     * [v83] 解码 v3 包：清单 + 按顺序的块密文 → HTML。
     *
     * 块设计（必须与服务器 _pack_v3.py 完全一致）：
     *   块 id = sha256(明文块)                    —— 内容寻址
     *   块 iv = sha256("lq3iv|" + id) 前 12 字节  —— 由内容确定性派生（无 IV 复用）
     *   每块独立 AES-256-GCM，末尾 16 字节是 tag
     * 签名覆盖：版本|ekey|明文总长|块id列表|明文sha
     *
     * @param blocks 与 manifest 的 blocks 数组**顺序一致**的块密文
     */
    public static String decodeV3Blocks(String manifestJson, byte[][] blocks, String pubPem) throws Exception {
        org.json.JSONObject m = new org.json.JSONObject(manifestJson);
        String ekeyB = m.optString("ekey", "");
        String sigB = m.optString("sig", "");
        String htmlSha = m.optString("html", "");
        int v = m.optInt("v", -1);
        long len = m.optLong("len", -1);
        org.json.JSONArray arr = m.optJSONArray("blocks");
        if (ekeyB.length() == 0 || sigB.length() == 0 || htmlSha.length() == 0
                || v < 0 || len <= 0 || arr == null || arr.length() == 0) {
            throw new SecurityException("V3_MISSING_FIELDS");
        }
        if (blocks == null || blocks.length != arr.length()) {
            throw new SecurityException("V3_BLOCK_COUNT");
        }

        // ① 验签（拼法与 _pack_v3.py 的 sign_src 严格一致）
        StringBuilder idsb = new StringBuilder();
        for (int i = 0; i < arr.length(); i++) {
            if (i > 0) idsb.append(',');
            idsb.append(arr.getString(i));
        }
        String signSrc = "3|" + v + "|" + ekeyB + "|" + len + "|" + idsb.toString() + "|" + htmlSha;
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pubFromPem(pubPem));
        s.update(signSrc.getBytes("UTF-8"));
        if (!s.verify(B64.decode(sigB))) throw new SecurityException("SIG_FAIL");

        // ② 解包 ekey
        byte[] der = NativeKey.privateDer();
        if (der == null) throw new IllegalStateException("NATIVE_KEY_UNAVAILABLE");
        PrivateKey priv = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(der));
        byte[] ek = B64.decode(ekeyB);
        byte[] aesKey;
        try {
            aesKey = rsaUnwrap(priv, ek, "SHA-256");
        } catch (Throwable t1) {
            aesKey = rsaUnwrap(priv, ek, "SHA-1");
        }
        if (aesKey == null || aesKey.length != 32) throw new SecurityException("EKEY_UNWRAP_FAIL");

        // ③ 逐块解密并拼接
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream((int) len);
        for (int i = 0; i < arr.length(); i++) {
            String bid = arr.getString(i);
            byte[] cblk = blocks[i];
            if (cblk == null || cblk.length <= 16) throw new SecurityException("V3_BLOCK_EMPTY:" + bid);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"),
                    new GCMParameterSpec(128, blockIv(bid)));
            byte[] plain = c.doFinal(cblk);
            if (!sha256Hex(plain).equalsIgnoreCase(bid)) {
                throw new SecurityException("BLOCK_SHA_MISMATCH:" + bid);
            }
            bos.write(plain, 0, plain.length);
        }
        byte[] all = bos.toByteArray();
        if (all.length != len) throw new SecurityException("V3_LEN_MISMATCH");
        if (!sha256Hex(all).equalsIgnoreCase(htmlSha)) throw new SecurityException("HTML_SHA_MISMATCH");
        return new String(all, "UTF-8");
    }

    /** [v83] 块 IV = sha256("lq3iv|"+块id) 前 12 字节（与打包脚本一致）。 */
    static byte[] blockIv(String bid) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(("lq3iv|" + bid).getBytes("US-ASCII"));
        byte[] iv = new byte[12];
        System.arraycopy(d, 0, iv, 0, 12);
        return iv;
    }

    /** [v83] 字节数组的 sha256 小写十六进制。 */
    static String sha256Hex(byte[] b) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(b);
            StringBuilder sb = new StringBuilder(64);
            for (byte x : d) {
                int n = x & 0xFF;
                if (n < 16) sb.append('0');
                sb.append(Integer.toHexString(n));
            }
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
    }

}
