package com.lingqiong.buddy;

import android.content.Context;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * [v28] HTTPS 解密（MITM）所用的本地 CA。
 *
 * 首次开启「解密 HTTPS」时，在本机生成一对 RSA 根证书（私钥永不出设备），
 * 存到 files/mitm/ca.crt + ca.key；之后每个被解密的域名都用它动态签发一张
 * 服务器证书（含 SAN），交给 TLS 中间人引擎冒充目标服务器。
 *
 * 使用者需把 ca.crt 装进系统信任库（需 root），客户端才会信任我们签发的证书。
 */
public class MitmCa {

    private static final long DAY = 24L * 3600 * 1000;
    private final File dir;
    private final SecureRandom rnd = new SecureRandom();
    private X509Certificate caCert;
    private PrivateKey caKey;
    /** [v132] 当前 CA 的 SHA-256 指纹（十六进制），用于和系统信任库比对 */
    public volatile String caFingerprint = "";

    /** [v132] 计算证书 SHA-256 指纹。 */
    public static String fpOf(X509Certificate c) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(c.getEncoded());
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02X", b));
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    /** host -> {PrivateKey, X509Certificate[]{leaf, ca}} */
    private final ConcurrentHashMap<String, Object[]> hostCache = new ConcurrentHashMap<>();
    /** host -> SSLContext(服务端) */
    private final ConcurrentHashMap<String, SSLContext> serverCtxCache = new ConcurrentHashMap<>();
    private volatile SSLContext clientCtx;

    public MitmCa(Context ctx) throws Exception {
        dir = new File(ctx.getFilesDir(), "mitm");
        if (!dir.exists()) dir.mkdirs();
        File cf = new File(dir, "ca.crt");
        File kf = new File(dir, "ca.key");
        boolean ok = false;
        String why = "";
        if (cf.exists() && kf.exists()) {
            try {
                loadCa(cf, kf);
                ok = caCert != null && caKey != null;
                if (!ok) why = "加载后 caCert/caKey 为空";
            } catch (Throwable t) {
                /* [v132] 绝不静默：CA 加载失败会导致每次启动换新 CA，必须留下证据 */
                why = t.getClass().getSimpleName() + ": " + t.getMessage();
                try { android.util.Log.w("LQ-MITM", "CA 加载失败：" + why); } catch (Throwable ig) {}
            }
        }
        if (!ok) {
            if (!why.isEmpty()) {
                try { android.util.Log.w("LQ-MITM", "重新生成 CA，原因：" + why); } catch (Throwable ig) {}
            }
            genCa();
            saveCa(cf, kf);
        }
        /* [v132] 记录当前 CA 指纹，便于自检「系统里装的是不是这一张」 */
        try { caFingerprint = fpOf(caCert); } catch (Throwable ig) {}
    }

    public X509Certificate caCert() { return caCert; }

    /**
     * [v132] 把当前 CA 指纹写到 files/mitm/ca.fp。
     * 下次启动比对：如果变了，说明 CA 被重新生成过，系统信任库里装的必然失效，
     * 必须重新安装 —— 这是「重启后突然全部解不出明文」的唯一可靠判据。
     * @return true 表示检测到 CA 被更换
     */
    public boolean persistFingerprint() {
        try {
            File f = new File(dir, "ca.fp");
            String old = "";
            if (f.exists()) {
                byte[] b = new byte[(int) f.length()];
                java.io.FileInputStream in = new java.io.FileInputStream(f);
                int n = in.read(b);
                in.close();
                old = n > 0 ? new String(b, 0, n, "UTF-8").trim() : "";
            }
            boolean changed = !old.isEmpty() && !old.equals(caFingerprint);
            java.io.FileOutputStream out = new java.io.FileOutputStream(f);
            out.write(caFingerprint.getBytes("UTF-8"));
            out.close();
            return changed;
        } catch (Throwable t) {
            return false;
        }
    }

    public String caPem() throws Exception {
        StringWriter sw = new StringWriter();
        JcaPEMWriter w = new JcaPEMWriter(sw);
        w.writeObject(caCert);
        w.close();
        return sw.toString();
    }

    // ---------------- CA 生成 / 读写 ----------------

    private void genCa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, rnd);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name("CN=LingQiongBuddy Root CA,O=LingQiongBuddy,OU=HTTPS Decryption");
        Date nb = new Date(System.currentTimeMillis() - DAY);
        Date na = new Date(System.currentTimeMillis() + 3650L * DAY);
        BigInteger serial = new BigInteger(64, rnd).abs();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(name, serial, nb, na, name, kp.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        /* [v131] CA 也带 SKI，方便 leaf 的 AKI 指向它 */
        try {
            b.addExtension(Extension.subjectKeyIdentifier, false,
                    new SubjectKeyIdentifier(MessageDigest.getInstance("SHA-1").digest(kp.getPublic().getEncoded())));
        } catch (Throwable ignore) {}
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        caCert = new JcaX509CertificateConverter().getCertificate(b.build(signer));
        caKey = kp.getPrivate();
        hostCache.clear();
        serverCtxCache.clear();
    }

    private void saveCa(File cf, File kf) throws Exception {
        JcaPEMWriter w = new JcaPEMWriter(new FileWriter(cf));
        w.writeObject(caCert);
        w.close();
        w = new JcaPEMWriter(new FileWriter(kf));
        w.writeObject(caKey);
        w.close();
    }

    private void loadCa(File cf, File kf) throws Exception {
        PEMParser p = new PEMParser(new FileReader(cf));
        Object o = p.readObject();
        p.close();
        caCert = new JcaX509CertificateConverter().getCertificate((X509CertificateHolder) o);
        p = new PEMParser(new FileReader(kf));
        Object ko = p.readObject();
        p.close();
        /* [v132] 关键修复：ca.key 由 JcaPEMWriter 写出时是 PKCS#1（BEGIN RSA PRIVATE KEY），
           PEMParser 返回 PEMKeyPair；旧代码强转 PrivateKeyInfo 会抛 ClassCastException，
           被构造函数静默吞掉后重新生成 CA —— 于是每次启动都换一对新 CA，
           系统信任库里的旧 CA 对不上，客户端一律 CERTIFICATE_UNKNOWN。
           这里两种格式都认。 */
        JcaPEMKeyConverter conv = new JcaPEMKeyConverter();
        if (ko instanceof org.bouncycastle.openssl.PEMKeyPair) {
            caKey = conv.getKeyPair((org.bouncycastle.openssl.PEMKeyPair) ko).getPrivate();
        } else if (ko instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo) {
            caKey = conv.getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) ko);
        } else {
            throw new IllegalStateException("ca.key 格式无法识别："
                    + (ko == null ? "null" : ko.getClass().getName()));
        }
    }

    /** 重新生成 CA（换证书时用）。 */
    public void reset() throws Exception {
        genCa();
        saveCa(new File(dir, "ca.crt"), new File(dir, "ca.key"));
    }

    /** [v132] 判断字符串是不是 IPv4 / IPv6 字面量。 */
    static boolean isIpLiteral(String s) {
        if (s == null || s.isEmpty()) return false;
        /* IPv4：四段 0-255 */
        if (s.matches("^\\d{1,3}(\\.\\d{1,3}){3}$")) {
            for (String p : s.split("\\.")) {
                try { if (Integer.parseInt(p) > 255) return false; } catch (Throwable t) { return false; }
            }
            return true;
        }
        /* IPv6：含冒号即认为是（够用，不需要严格校验） */
        return s.indexOf(':') >= 0;
    }

    // ---------------- 动态签发 ----------------

    private Object[] hostKeyCert(String host) throws Exception {
        Object[] c = hostCache.get(host);
        if (c != null) return c;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, rnd);
        KeyPair kp = kpg.generateKeyPair();
        X500Name subject = new X500Name("CN=" + host);
        /* [v131] 必须用 getEncoded()，不能用 getName() 再 new X500Name(String)。
           getName() 返回 RFC2253 字符串，重新解析会改变 ASN.1 字符串类型，
           导致 issuer 的 DER 与 CA subject 的 DER 不一致 —— Android 建链时
           逐字节比较，不一致就直接判「找不到信任锚点」，握手全部失败。
           实测：旧做法 DER 相同长度但内容不同；新做法完全一致。 */
        X500Name issuer = X500Name.getInstance(caCert.getSubjectX500Principal().getEncoded());
        Date nb = new Date(System.currentTimeMillis() - DAY);
        Date na = new Date(System.currentTimeMillis() + 825L * DAY);
        BigInteger serial = new BigInteger(64, rnd).abs();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer, serial, nb, na, subject, kp.getPublic());
        /* [v132] IP 必须用 iPAddress 类型。原来一律用 dNSName，
           遇到「SNI 解析失败 → host 是 IP」时会签出 DNS:1.2.3.4，
           客户端按 IP 验证时找不到匹配的 SAN，直接 CERTIFICATE_UNKNOWN。 */
        GeneralName gn;
        if (isIpLiteral(host)) {
            gn = new GeneralName(GeneralName.iPAddress, host);
        } else {
            gn = new GeneralName(GeneralName.dNSName, host);
        }
        GeneralNames sans = new GeneralNames(gn);
        b.addExtension(Extension.subjectAlternativeName, false, sans);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
        /* [v131] 补 SKI / AKI：部分 Android 版本的链构建器会要求这两个扩展，
           缺失时即便 issuer DER 一致也可能建链失败。 */
        try {
            SubjectKeyIdentifier caSki = new SubjectKeyIdentifier(
                    MessageDigest.getInstance("SHA-1").digest(caCert.getPublicKey().getEncoded()));
            b.addExtension(Extension.subjectKeyIdentifier, false,
                    new SubjectKeyIdentifier(MessageDigest.getInstance("SHA-1").digest(kp.getPublic().getEncoded())));
            b.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(caSki.getKeyIdentifier()));
        } catch (Throwable ignore) {}
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKey);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(b.build(signer));
        Object[] arr = new Object[]{kp.getPrivate(), new X509Certificate[]{cert, caCert}};
        hostCache.put(host, arr);
        return arr;
    }

    /** 为 host 建服务端 SSLContext（用动态签发的证书）。 */
    public SSLContext serverContext(String host) throws Exception {
        SSLContext c = serverCtxCache.get(host);
        if (c != null) return c;
        Object[] kc = hostKeyCert(host);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        char[] pw = "mitmpass".toCharArray();
        ks.setKeyEntry("srv", (PrivateKey) kc[0], pw, (X509Certificate[]) kc[1]);
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pw);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), null, rnd);
        serverCtxCache.put(host, ctx);
        return ctx;
    }

    /** 客户端 SSLContext：信任系统根证书，用于连真实服务器。 */
    public SSLContext clientContext() throws Exception {
        SSLContext c = clientCtx;
        if (c != null) return c;
        SSLContext ctx = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        ctx.init(null, tmf.getTrustManagers(), rnd);
        clientCtx = ctx;
        return ctx;
    }

    /**
     * OpenSSL subject_hash_old（8 位小写十六进制），即系统证书目录下的文件名前缀。
     * 算法：对 subject 的 DER 编码做 MD5，取前 4 字节按小端拼成 32 位整数。
     */
    public String caHashName() {
        try {
            byte[] dn = caCert.getSubjectX500Principal().getEncoded();
            byte[] d = MessageDigest.getInstance("MD5").digest(dn);
            long v = (d[0] & 0xffL) | ((d[1] & 0xffL) << 8) | ((d[2] & 0xffL) << 16) | ((d[3] & 0xffL) << 24);
            return String.format("%08x", v);
        } catch (Throwable t) {
            return "00000000";
        }
    }
}
