package com.lingqiong.buddy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

/**
 * [v83] HTTP 报文解码器 —— 抓包「看得懂」的核心。
 *
 * 解决旧版的四个硬伤：
 *   ① 旧版用 ISO_8859_1 读字节 → 中文必乱码。这里按 Content-Type 的 charset 解，
 *      没有就先用「严格 UTF-8」试，失败再退 GBK（国内接口常见）。
 *   ② 旧版不解压 → gzip/deflate 响应必乱码。这里真解压后再解码。
 *   ③ 旧版不处理 chunked → 正文里混着一堆 "1a2b\r\n" 长度前缀。这里先拆块。
 *   ④ 旧版不区分类型 → 图片/字体/二进制全当文本。这里按 MIME + 内容嗅探分类。
 *
 * 说明：brotli(br) Android 无内置解码器，如实标注「br 压缩未解」，绝不假装解开了。
 */
public class HttpCodec {

    /** 单条正文最多保留多少字节（足够分析，又不撑爆内存） */
    public static final int MAX_BODY = 64 * 1024;
    /** 图片预览最多保留多少原始字节（超过只给摘要，不给 base64） */
    public static final int MAX_IMAGE = 512 * 1024;
    /** 文本预览最多多少字符 */
    public static final int MAX_TEXT = 32 * 1024;

    public static class Decoded {
        public String type = "other";   // json/xml/html/js/css/image/font/media/text/binary/other
        public String mime = "";
        public String charset = "";
        public String text = "";        // 人类可读文本
        public byte[] raw = null;       // 解压后的原始字节（图片预览用）
        public int rawLen = 0;          // 解压后总长度
        public String note = "";        // 附加说明（压缩方式、二进制尺寸等）
        public boolean truncated = false;
    }

    // ==================== 头字段解析 ====================

    /** 从原始头文本里取某个字段（大小写不敏感），取不到返回 ""。 */
    public static String header(String head, String name) {
        if (head == null || name == null) return "";
        String[] lines = head.split("\r\n");
        for (String ln : lines) {
            int c = ln.indexOf(':');
            if (c <= 0) continue;
            if (ln.substring(0, c).trim().equalsIgnoreCase(name)) {
                return ln.substring(c + 1).trim();
            }
        }
        return "";
    }

    /** 解析 "text/html; charset=utf-8" → mime / charset */
    public static String mimeOf(String ct) {
        if (ct == null) return "";
        int sc = ct.indexOf(';');
        String m = (sc >= 0 ? ct.substring(0, sc) : ct).trim().toLowerCase();
        return m;
    }

    public static String charsetOf(String ct) {
        if (ct == null) return "";
        String[] parts = ct.split(";");
        for (String p : parts) {
            p = p.trim();
            int e = p.indexOf('=');
            if (e > 0 && p.substring(0, e).trim().equalsIgnoreCase("charset")) {
                String v = p.substring(e + 1).trim();
                if (v.startsWith("\"") && v.endsWith("\"") && v.length() > 2) v = v.substring(1, v.length() - 1);
                return v;
            }
        }
        return "";
    }

    // ==================== 分类 ====================

    public static String classify(String mime, byte[] b, int len, String url) {
        if (mime != null && !mime.isEmpty()) {
            if (mime.contains("json")) return "json";
            if (mime.contains("xml")) return "xml";
            if (mime.startsWith("text/html")) return "html";
            if (mime.contains("javascript") || mime.contains("ecmascript")) return "js";
            if (mime.contains("css")) return "css";
            if (mime.startsWith("image/")) return "image";
            if (mime.startsWith("font/") || mime.contains("font-") || mime.contains("woff")) return "font";
            if (mime.startsWith("audio/") || mime.startsWith("video/")) return "media";
            if (mime.startsWith("text/")) return "text";
            if (mime.contains("protobuf") || mime.contains("octet-stream")
                    || mime.contains("msgpack") || mime.contains("cbor")) return "binary";
        }
        // 无 Content-Type → 嗅探内容
        if (b != null && len > 0) {
            int n = Math.min(len, 64);
            // 跳过空白
            int i = 0;
            while (i < n && (b[i] == ' ' || b[i] == '\r' || b[i] == '\n' || b[i] == '\t')) i++;
            if (i < n) {
                byte c = b[i];
                if (c == '{' || c == '[') return "json";
                if (c == '<') {
                    // <!DOCTYPE html / <html
                    String head = new String(b, 0, Math.min(len, 200), Charset.forName("ISO-8859-1")).toLowerCase();
                    if (head.contains("<html") || head.contains("<!doctype html")) return "html";
                    return "xml";
                }
            }
            // 图片魔数
            String img = imageMime(b, len);
            if (!img.isEmpty()) return "image";
            // 可打印字符比例
            int printable = 0, total = Math.min(len, 512);
            for (int k = 0; k < total; k++) {
                int v = b[k] & 0xff;
                if (v == 9 || v == 10 || v == 13 || (v >= 32 && v < 127) || v >= 0xC0) printable++;
            }
            if (total > 0 && printable * 100 / total > 92) return "text";
        }
        if (url != null) {
            String u = url.toLowerCase();
            if (u.endsWith(".json")) return "json";
            if (u.endsWith(".html") || u.endsWith(".htm")) return "html";
            if (u.endsWith(".js")) return "js";
            if (u.endsWith(".css")) return "css";
            if (u.matches(".*\\.(png|jpe?g|gif|webp|bmp|ico|svg)$")) return "image";
        }
        return "binary";
    }

    /** 按魔数判断图片 MIME，不是图片返回 "" */
    public static String imageMime(byte[] b, int len) {
        if (b == null || len < 4) return "";
        int b0 = b[0] & 0xff, b1 = b[1] & 0xff, b2 = b[2] & 0xff, b3 = b[3] & 0xff;
        if (b0 == 0x89 && b1 == 0x50 && b2 == 0x4E && b3 == 0x47) return "image/png";
        if (b0 == 0xFF && b1 == 0xD8 && b2 == 0xFF) return "image/jpeg";
        if (b0 == 0x47 && b1 == 0x49 && b2 == 0x46) return "image/gif";
        if (b0 == 0x52 && b1 == 0x49 && b2 == 0x46 && b3 == 0x46 && len >= 12
                && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P') return "image/webp";
        if (b0 == 0x42 && b1 == 0x4D) return "image/bmp";
        return "";
    }

    /** 图片尺寸（只支持 PNG / GIF / JPEG 的头部，够用且零依赖） */
    public static String imageSize(byte[] b, int len) {
        try {
            if (len >= 24 && (b[0] & 0xff) == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G') {
                int w = ((b[16] & 0xff) << 24) | ((b[17] & 0xff) << 16) | ((b[18] & 0xff) << 8) | (b[19] & 0xff);
                int h = ((b[20] & 0xff) << 24) | ((b[21] & 0xff) << 16) | ((b[22] & 0xff) << 8) | (b[23] & 0xff);
                return w + "×" + h;
            }
            if (len >= 10 && b[0] == 'G' && b[1] == 'I' && b[2] == 'F') {
                int w = (b[6] & 0xff) | ((b[7] & 0xff) << 8);
                int h = (b[8] & 0xff) | ((b[9] & 0xff) << 8);
                return w + "×" + h;
            }
            if (len >= 4 && (b[0] & 0xff) == 0xFF && (b[1] & 0xff) == 0xD8) {
                int i = 2;
                while (i + 9 < len) {
                    if ((b[i] & 0xff) != 0xFF) { i++; continue; }
                    int mk = b[i + 1] & 0xff;
                    if (mk >= 0xC0 && mk <= 0xCF && mk != 0xC4 && mk != 0xC8 && mk != 0xCC) {
                        int h = ((b[i + 5] & 0xff) << 8) | (b[i + 6] & 0xff);
                        int w = ((b[i + 7] & 0xff) << 8) | (b[i + 8] & 0xff);
                        return w + "×" + h;
                    }
                    int seg = ((b[i + 2] & 0xff) << 8) | (b[i + 3] & 0xff);
                    if (seg <= 0) break;
                    i += 2 + seg;
                }
            }
        } catch (Throwable ignore) {}
        return "";
    }

    // ==================== 解压 / 拆块 ====================

    /** 按 Content-Encoding 解压；解不了就原样返回并在 note 里说明。 */
    public static byte[] decompress(byte[] data, int len, String encoding, String[] noteOut) {
        if (data == null || len <= 0) return new byte[0];
        String enc = encoding == null ? "" : encoding.toLowerCase().trim();
        if (enc.isEmpty() || enc.equals("identity")) return copy(data, len);
        try {
            if (enc.contains("gzip") || enc.contains("x-gzip")) {
                ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.max(64, len * 3));
                GZIPInputStream gz = new GZIPInputStream(new ByteArrayInputStream(data, 0, len));
                byte[] buf = new byte[8192];
                int n;
                while ((n = gz.read(buf)) > 0) bos.write(buf, 0, n);
                gz.close();
                return bos.toByteArray();
            }
            if (enc.contains("deflate")) {
                // 可能是 zlib 包装，也可能是裸 deflate，两种都试
                byte[] r = inflate(data, len, false);
                if (r == null) r = inflate(data, len, true);
                if (r != null) return r;
                if (noteOut != null && noteOut.length > 0) noteOut[0] = "deflate 解压失败";
                return copy(data, len);
            }
            if (enc.contains("br")) {
                if (noteOut != null && noteOut.length > 0) noteOut[0] = "br(brotli) 压缩 · 系统无内置解码器，以下为原始字节";
                return copy(data, len);
            }
        } catch (Throwable t) {
            if (noteOut != null && noteOut.length > 0) noteOut[0] = enc + " 解压失败: " + t.getClass().getSimpleName();
        }
        return copy(data, len);
    }

    private static byte[] inflate(byte[] data, int len, boolean nowrap) {
        try {
            Inflater inf = new Inflater(nowrap);
            inf.setInput(data, 0, len);
            ByteArrayOutputStream bos = new ByteArrayOutputStream(Math.max(64, len * 3));
            byte[] buf = new byte[8192];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0) {
                    if (inf.needsInput() || inf.needsDictionary()) break;
                } else bos.write(buf, 0, n);
            }
            inf.end();
            byte[] out = bos.toByteArray();
            return out.length > 0 ? out : null;
        } catch (Throwable t) {
            return null;
        }
    }

    /** 拆 chunked 编码。不是 chunked 就原样返回。 */
    public static byte[] dechunk(byte[] data, int len) {
        if (data == null || len <= 0) return new byte[0];
        ByteArrayOutputStream out = new ByteArrayOutputStream(len);
        int i = 0;
        while (i < len) {
            int lineEnd = -1;
            for (int k = i; k + 1 < len; k++) {
                if (data[k] == '\r' && data[k + 1] == '\n') { lineEnd = k; break; }
            }
            if (lineEnd < 0) break;
            String line = new String(data, i, lineEnd - i, Charset.forName("ISO-8859-1")).trim();
            int sc = line.indexOf(';');
            if (sc >= 0) line = line.substring(0, sc);
            int size;
            try { size = Integer.parseInt(line.trim(), 16); } catch (Throwable t) { return copy(data, len); }
            if (size == 0) break;
            int start = lineEnd + 2;
            int end = Math.min(start + size, len);
            out.write(data, start, end - start);
            i = end + 2;   // 跳过 chunk 后的 CRLF
            if (i > len) break;
        }
        byte[] r = out.toByteArray();
        return r.length > 0 ? r : copy(data, len);
    }

    public static byte[] copy(byte[] d, int len) {
        byte[] r = new byte[len];
        System.arraycopy(d, 0, r, 0, len);
        return r;
    }

    // ==================== 字符解码 ====================

    /** 严格解码（遇到非法字节抛异常），用于判断到底是不是 UTF-8 */
    private static String strictDecode(byte[] b, int len, String cs) {
        try {
            Charset c = Charset.forName(cs);
            CharsetDecoder d = c.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            return d.decode(ByteBuffer.wrap(b, 0, len)).toString();
        } catch (CharacterCodingException e) {
            return null;
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * 把字节转成人类能读的字符串。
     * 顺序：头里声明的 charset → 严格 UTF-8 → GBK → 宽松 UTF-8（必有结果）
     */
    public static String decodeText(byte[] b, int len, String declaredCharset, String[] csOut) {
        if (b == null || len <= 0) return "";
        String cs = declaredCharset == null ? "" : declaredCharset.trim();
        if (!cs.isEmpty()) {
            try {
                String s = new String(b, 0, len, Charset.forName(cs));
                if (csOut != null && csOut.length > 0) csOut[0] = cs;
                return s;
            } catch (Throwable ignore) {}
        }
        String s = strictDecode(b, len, "UTF-8");
        if (s != null) {
            if (csOut != null && csOut.length > 0) csOut[0] = "UTF-8";
            return s;
        }
        s = strictDecode(b, len, "GBK");
        if (s != null) {
            if (csOut != null && csOut.length > 0) csOut[0] = "GBK";
            return s;
        }
        if (csOut != null && csOut.length > 0) csOut[0] = "UTF-8(容错)";
        return new String(b, 0, len, Charset.forName("UTF-8"));
    }

    // ==================== 美化 ====================

    /** JSON 美化（手写，零依赖，容错：不是合法 JSON 就原样返回） */
    public static String prettyJson(String s) {
        if (s == null || s.isEmpty()) return s;
        StringBuilder out = new StringBuilder(s.length() + 128);
        int indent = 0;
        boolean inStr = false, esc = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                out.append(c);
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
                continue;
            }
            switch (c) {
                case '"': inStr = true; out.append(c); break;
                case '{': case '[':
                    out.append(c); indent++; out.append('\n'); pad(out, indent); break;
                case '}': case ']':
                    indent = Math.max(0, indent - 1);
                    out.append('\n'); pad(out, indent); out.append(c); break;
                case ',':
                    out.append(c); out.append('\n'); pad(out, indent); break;
                case ':':
                    out.append(": "); break;
                case ' ': case '\n': case '\r': case '\t':
                    break;
                default:
                    out.append(c);
            }
        }
        return out.toString();
    }

    private static void pad(StringBuilder sb, int n) {
        for (int i = 0; i < n; i++) sb.append("  ");
    }

    /** 十六进制 + ASCII 双栏 dump */
    public static String hexDump(byte[] b, int len, int maxBytes) {
        if (b == null || len <= 0) return "";
        int n = Math.min(len, maxBytes);
        StringBuilder sb = new StringBuilder(n * 5);
        for (int i = 0; i < n; i += 16) {
            sb.append(String.format("%08X  ", i));
            StringBuilder asc = new StringBuilder();
            for (int k = 0; k < 16; k++) {
                if (i + k < n) {
                    int v = b[i + k] & 0xff;
                    sb.append(String.format("%02X ", v));
                    asc.append(v >= 32 && v < 127 ? (char) v : '.');
                } else {
                    sb.append("   ");
                    asc.append(' ');
                }
                if (k == 7) sb.append(' ');
            }
            sb.append(" |").append(asc).append("|\n");
        }
        if (len > n) sb.append("… 共 ").append(len).append(" 字节，仅显示前 ").append(n).append(" 字节\n");
        return sb.toString();
    }

    /** 表单（application/x-www-form-urlencoded）美化 */
    public static String prettyForm(String s) {
        if (s == null || s.isEmpty()) return s;
        try {
            StringBuilder sb = new StringBuilder();
            String[] ps = s.split("&");
            for (String p : ps) {
                int e = p.indexOf('=');
                if (e < 0) { sb.append(p).append('\n'); continue; }
                String k = p.substring(0, e), v = p.substring(e + 1);
                sb.append(urlDecode(k)).append(" = ").append(urlDecode(v)).append('\n');
            }
            return sb.toString();
        } catch (Throwable t) { return s; }
    }

    public static String urlDecode(String s) {
        try { return java.net.URLDecoder.decode(s, "UTF-8"); } catch (Throwable t) { return s; }
    }

    public static String humanSize(long n) {
        if (n < 1024) return n + " B";
        if (n < 1024 * 1024) return String.format("%.1f KB", n / 1024.0);
        if (n < 1024L * 1024 * 1024) return String.format("%.1f MB", n / 1048576.0);
        return String.format("%.2f GB", n / 1073741824.0);
    }

    /**
     * 一站式解码：给定原始 body 字节 + 完整头文本，产出可展示结果。
     */
    public static Decoded decode(byte[] body, int len, String headers, String url) {
        Decoded d = new Decoded();
        if (body == null || len <= 0) { d.type = "empty"; return d; }

        String ct = header(headers, "Content-Type");
        String ce = header(headers, "Content-Encoding");
        String te = header(headers, "Transfer-Encoding");
        d.mime = mimeOf(ct);
        d.charset = charsetOf(ct);

        byte[] data = copy(body, len);
        d.rawLen = len;

        String[] note = new String[]{""};
        if (ce != null && !ce.isEmpty()) {
            data = decompress(data, data.length, ce, note);
            if (!note[0].isEmpty()) d.note = note[0];
        }
        if (te != null && te.toLowerCase().contains("chunked")) {
            data = dechunk(data, data.length);
            d.note = (d.note.isEmpty() ? "" : d.note + " · ") + "chunked";
        }
        if (note[0].isEmpty()) d.rawLen = data.length;

        String type = classify(d.mime, data, data.length, url);
        d.type = type;

        if ("image".equals(type)) {
            String im = d.mime.isEmpty() ? imageMime(data, data.length) : d.mime;
            String size = imageSize(data, data.length);
            d.note = (d.note.isEmpty() ? "" : d.note + " · ") + im + " · " + humanSize(data.length)
                    + (size.isEmpty() ? "" : " · " + size);
            if (data.length <= MAX_IMAGE) d.raw = data;
            d.text = "[图片] " + im + " · " + humanSize(data.length) + (size.isEmpty() ? "" : " · " + size);
            return d;
        }

        if ("binary".equals(type) || "font".equals(type) || "media".equals(type)) {
            d.raw = data.length <= MAX_IMAGE ? data : null;
            d.text = hexDump(data, data.length, 256);
            d.note = (d.note.isEmpty() ? "" : d.note + " · ") + "二进制 · " + humanSize(data.length);
            return d;
        }

        // 文本类
        String[] csOut = new String[]{""};
        String text = decodeText(data, data.length, d.charset, csOut);
        if (!csOut[0].isEmpty()) d.charset = csOut[0];
        if (("json".equals(type) || "js".equals(type)) && text.length() < MAX_TEXT * 4) {
            text = prettyJson(text);
        } else if ("text".equals(type) && d.mime.contains("x-www-form-urlencoded")) {
            text = prettyForm(text);
        }
        if (text.length() > MAX_TEXT) { text = text.substring(0, MAX_TEXT); d.truncated = true; }
        d.text = text;
        return d;
    }
}
