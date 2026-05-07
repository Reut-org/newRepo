package com.apiiro.avigtest.sast;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Random;

/**
 * SAST sample without common critical-class sinks (no SQLi, RCE, unsafe deserialization, SSRF).
 * For PR comment testing when critical bucket should stay empty or minimal per Apiiro rules.
 */
public class AiSastTriageSemgrepTruePositives {

    // --- High-class (typical) ---
    public byte[] pathTraversalRead(String relativePath) throws Exception {
        String base = "/data/exports/";
        try (FileInputStream in = new FileInputStream(base + relativePath)) {
            return in.readAllBytes();
        }
    }

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

    // --- Medium-class (typical) ---
    public byte[] weakHashMd5(String material) throws Exception {
        return MessageDigest.getInstance("MD5").digest(material.getBytes());
    }

    public String predictableSessionToken() {
        return "sess-" + new Random().nextLong();
    }

    public byte[] weakCipherDes(String plaintext) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("DES");
        kg.init(56, new SecureRandom());
        SecretKey key = kg.generateKey();
        Cipher c = Cipher.getInstance("DES");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(plaintext.getBytes());
    }
}
