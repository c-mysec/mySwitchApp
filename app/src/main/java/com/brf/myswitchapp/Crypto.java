package com.brf.myswitchapp;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
public class Crypto {
    private final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public byte[] hmacKey;
    public byte[] aesKey;
    public byte[] iv;
    public Activity activity;
    public Crypto(Activity activity) {
        this.activity = activity;
    }
    public void genkeys(String msg) {
        byte[] key2 = { 0x1C,0x3E,0x4B, (byte)0xAF, 0x13,0x4A, (byte)0x89, (byte)0xC3,
                (byte)0xF3, (byte)0x87, 0x4F, (byte)0xBC, (byte)0xD7, (byte)0xF3, 0x31,
                0x31 };
        MessageDigest md = null;
        SecureRandom secureRandom = new SecureRandom();

        try {
            byte[] key = msg.getBytes("ASCII");
            for (int i = 0; i < key.length && i < key2.length; i++) {
                key2[i] = key[i];
            }
            printByteArray("passkey: ", key2);
            md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(key2);
            printByteArray("keyHash: ", digest);
            aesKey = new byte[16];
            hmacKey = new byte[16];
            for (int i = 0; i < aesKey.length; i++) {
                aesKey[i] = digest[i];
            }
            for (int i = 0; i < hmacKey.length; i++) {
                hmacKey[i] = digest[i + aesKey.length];
            }
            iv = new byte[16];
            secureRandom.nextBytes(iv);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
    public static byte[] decrypt(byte[] cipherText, SecretKey key, byte[] IV) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");
            IvParameterSpec ivSpec = new IvParameterSpec(IV);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] decryptedText = cipher.doFinal(cipherText);
            return decryptedText;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    public int minimumSize() {
        return 76;
    }
    public byte[] openMsg(byte[] m) {
        if (aesKey == null) {
            SharedPreferences sharedPref = activity.getPreferences(Context.MODE_PRIVATE);
            String passwd = sharedPref.getString("pass", "12345678");
            genkeys(passwd);
        }
        try {
            SecretKey secretKey = new SecretKeySpec(
                    hmacKey, "HmacSHA256");
            Mac mac = Mac.getInstance(secretKey.getAlgorithm());
            mac.init(secretKey);
            byte[] buffer2 = new byte[m.length - mac.getMacLength()];
            for(int i = 0; i < buffer2.length; i++) buffer2[i] = m[i];
            byte[] calcHmac = mac.doFinal(buffer2);
            for (int i = 0; i < calcHmac.length; i++) {
                if (calcHmac[i] != m[i + buffer2.length]) return null;
            }
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //actually uses PKCS#7
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
            byte[] receivedIv = new byte[iv.length];
            for (int i = 0; i < iv.length; i++) receivedIv[i] = buffer2[i];
            IvParameterSpec ivSpec = new IvParameterSpec(receivedIv);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            byte[] encrypted = new byte[buffer2.length - iv.length];
            for (int i = 0; i < encrypted.length; i++) encrypted[i] = buffer2[i + iv.length];

            byte[] decrypted = cipher.doFinal(encrypted);

            printByteArray("received decrypted: ", decrypted);
            return decrypted;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    public void printByteArray(String tag, byte[] decrypted) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < decrypted.length; i++) {
            int v = decrypted[i] & 0xFF;
            sb.append(HEX_ARRAY[v >>> 4]);
            sb.append(HEX_ARRAY[v & 0x0F]);
        }
        Log.e(tag, sb.toString());
    }

    public byte[] signMsg(byte[] m) {
        if (aesKey == null) {
            SharedPreferences sharedPref = activity.getPreferences(Context.MODE_PRIVATE);
            String passwd = sharedPref.getString("pass", "12345678");
            genkeys(passwd);
        }
        try {
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); //actually uses PKCS#7
            printByteArray("IV", iv);
            SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES/CBC/PKCS5Padding");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

            byte[] encrypted = cipher.doFinal(m);
            SecretKey secretKey = new SecretKeySpec(
                    hmacKey, "HmacSHA256");

            byte[] buffer1 = new byte[encrypted.length + 16];
            byte[] iv = cipher.getIV();
            for (int i = 0; i < 16; i++) buffer1[i] = iv[i];
            for (int i = 0; i < encrypted.length; i++) buffer1[i + 16] = encrypted[i];

            Mac mac = Mac.getInstance(secretKey.getAlgorithm());
            mac.init(secretKey);
            byte[] hmac = mac.doFinal(buffer1);
            byte[] buffer = new byte[buffer1.length + hmac.length];
            for(int i = 0; i < buffer1.length; i++) buffer[i] = buffer1[i];
            for(int i = 0; i < hmac.length; i++) buffer[i + buffer1.length] = hmac[i];
            return buffer;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }
}
