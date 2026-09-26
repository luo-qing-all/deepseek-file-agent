package com.lingqiong.buddy;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
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
    static final Base64.Decoder B64D = Base64.getDecoder();

    public static String decode(String json, String pubPem) throws Exception {
        String keyB = grab(json, "key");
        String ivB = grab(json, "iv");
        String cipherB = grab(json, "cipher");
        String sigB = grab(json, "sig");

        byte[] toSign = (keyB + "|" + ivB + "|" + cipherB).getBytes("UTF-8");
        Signature s = Signature.getInstance("SHA256withRSA");
        s.initVerify(pubFromPem(pubPem));
        s.update(toSign);
        if (!s.verify(B64D.decode(sigB))) throw new SecurityException("SIG_FAIL");

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(B64D.decode(keyB), "AES"),
                new GCMParameterSpec(128, B64D.decode(ivB)));
        return new String(c.doFinal(B64D.decode(cipherB)), "UTF-8");
    }

    static PublicKey pubFromPem(String pem) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (String line : pem.split("\n")) {
            line = line.trim();
            if (line.startsWith("-----") || line.isEmpty()) continue;
            sb.append(line);
        }
        return KeyFactory.getInstance("RSA").generatePublic(
                new X509EncodedKeySpec(B64D.decode(sb.toString())));
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
        String json = new String(Files.readAllBytes(Paths.get(a[0])), "UTF-8");
        String pem = new String(Files.readAllBytes(Paths.get(a[1])), "UTF-8");
        String html = decode(json, pem);
        System.out.println("decoded chars: " + html.length());
        if (a.length > 2) Files.write(Paths.get(a[2]), html.getBytes("UTF-8"));
    }
}
