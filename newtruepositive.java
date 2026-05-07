package com.apiiro.avigtest.sast;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

/**
 * Minimal SAST sample: weak cryptography only (no I/O, TLS, injection, SSRF).
 * Intended to avoid high/critical buckets; severity still depends on Apiiro rules.
 */
public class AiSastTriageSemgrepTruePositives {

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
