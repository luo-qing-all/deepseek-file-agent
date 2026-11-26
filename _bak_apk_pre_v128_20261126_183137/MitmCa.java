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
        if (cf.exists() && kf.exists()) {
            try { loadCa(cf, kf); ok = caCert != null && caKey != null; } catch (Throwable ignore) {}
        }
        if (!ok) { genCa(); saveCa(cf, kf); }
    }

    public X509Certificate caCert() { return caCert; }

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
        caKey = new JcaPEMKeyConverter().getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) ko);
    }

    /** 重新生成 CA（换证书时用）。 */
    public void reset() throws Exception {
        genCa();
        saveCa(new File(dir, "ca.crt"), new File(dir, "ca.key"));
    }

    // ---------------- 动态签发 ----------------

    private Object[] hostKeyCert(String host) throws Exception {
        Object[] c = hostCache.get(host);
        if (c != null) return c;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048, rnd);
        KeyPair kp = kpg.generateKeyPair();
        X500Name subject = new X500Name("CN=" + host);
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        Date nb = new Date(System.currentTimeMillis() - DAY);
        Date na = new Date(System.currentTimeMillis() + 825L * DAY);
        BigInteger serial = new BigInteger(64, rnd).abs();
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuer, serial, nb, na, subject, kp.getPublic());
        GeneralNames sans = new GeneralNames(new GeneralName(GeneralName.dNSName, host));
        b.addExtension(Extension.subjectAlternativeName, false, sans);
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
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
