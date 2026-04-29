package com.apiiro.avigtest.sast;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.Statement;
import java.util.Random;

/**
 * Intentional vulnerable patterns for SAST pipelines and AI triage (Semgrep true-positive training).
 * Each method maps to a common Semgrep Java rule family; user-controlled values flow directly into sinks.
 */
public class AiSastTriageSemgrepTruePositives {

    /** java.lang.security.audit.sql-injection — concatenated SQL */
    public void sqlInjectionStatement(Connection conn, String userId) throws Exception {
        String sql = "DELETE FROM sessions WHERE user_id = '" + userId + "'";
        try (Statement st = conn.createStatement()) {
            st.execute(sql);
        }
    }

    /** java.lang.security.audit.command-injection — shell command built from input */
    public int commandInjection(String userHost) throws Exception {
        return Runtime.getRuntime().exec("nslookup " + userHost).waitFor();
    }

    /** java.lang.security.audit.path-traversal — path built from input */
    public byte[] pathTraversalRead(String relativePath) throws Exception {
        String base = "/data/exports/";
        try (FileInputStream in = new FileInputStream(base + relativePath)) {
            return in.readAllBytes();
        }
    }

    /** java.lang.security.audit.path-traversal — java.nio path concatenation */
    public String pathTraversalNio(String userSubpath) throws Exception {
        return Files.readString(Paths.get("/var/reports", userSubpath));
    }

    /** java.lang.security.audit.ssrf — URL from caller */
    public byte[] ssrfOpenStream(String targetUrl) throws Exception {
        return new URL(targetUrl).openStream().readAllBytes();
    }

    /** java.lang.security.audit.object-deserialization — untrusted bytes */
    public Object unsafeDeserialize(byte[] blob) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(blob))) {
            return ois.readObject();
        }
    }

    /** java.lang.security.audit.crypto.weak-hash — MD5 for “integrity” of secret material */
    public byte[] weakHashMd5(String material) throws Exception {
        return MessageDigest.getInstance("MD5").digest(material.getBytes());
    }

    /** java.lang.security.audit.crypto.insecure-random — token from java.util.Random */
    public String predictableSessionToken() {
        return "sess-" + new Random().nextLong();
    }

    /** java.lang.security.audit.crypto.weak-cipher — DES */
    public byte[] weakCipherDes(String plaintext) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        kg.init(56, new SecureRandom());
        SecretKey key = kg.generateKey();
        Cipher c = Cipher.getInstance("DES");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(plaintext.getBytes());
    }

    /** java.lang.security.audit.ssl.disabled-cert-validation — trust-all TLS for HTTPS */
    public void trustAllTlsBeforeFetch() throws Exception {
        TrustManager[] trustAll = new TrustManager[]{
            new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(ctx.getSocketFactory());
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
    }
}
