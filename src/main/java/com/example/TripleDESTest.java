package com.example;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

public class TripleDESTest {
    public static void main(String[] args) {
        try {
            String text = "kyle boon";
            String codedtext = new TripleDESTest().encrypt(text);
            String decodedtext = new TripleDESTest().decrypt(codedtext);

            System.out.println("Ciphertext: " + codedtext);
            System.out.println("Decoded text: " + decodedtext);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String message) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("md5");
        final byte[] digestOfPassword = md.digest("HG58YZ3CR9".getBytes("utf-8"));
        final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0, k = 16; j < 8; ) {
            keyBytes[k++] = keyBytes[j++];
        }

        SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        
        byte[] plainTextBytes = message.getBytes("utf-8");
        byte[] cipherText = cipher.doFinal(plainTextBytes);
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public String decrypt(String message) throws Exception {
        final MessageDigest md = MessageDigest.getInstance("md5");
        final byte[] digestOfPassword = md.digest("HG58YZ3CR9".getBytes("utf-8"));
        final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
        for (int j = 0, k = 16; j < 8; ) {
            keyBytes[k++] = keyBytes[j++];
        }

        SecretKey key = new SecretKeySpec(keyBytes, "DESede");
        IvParameterSpec iv = new IvParameterSpec(new byte[8]);
        Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, key, iv);
        
        byte[] encData = Base64.getDecoder().decode(message);
        byte[] plainText = decipher.doFinal(encData);
        return new String(plainText, "utf-8");
    }
}
