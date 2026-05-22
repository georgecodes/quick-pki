package com.elevenware.quickpki.certapi;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

/**
 * Encrypts the issuing CA's private key for storage at rest. The AES-256-GCM
 * key is derived per-record from {@code CERT_API_CA_KEY_PASSWORD} with PBKDF2,
 * so the database never holds a usable key without the configured password.
 */
final class KeyEncryptor {

    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 12;
    private static final int KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int PBKDF2_ITERATIONS = 210_000;

    private final char[] password;
    private final SecureRandom random = new SecureRandom();

    KeyEncryptor(String password) {
        this.password = password.toCharArray();
    }

    EncryptedBytes encrypt(byte[] plaintext) {
        try {
            byte[] salt = new byte[SALT_BYTES];
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(salt);
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key(salt), new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new EncryptedBytes(cipher.doFinal(plaintext), salt, iv);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt CA private key", e);
        }
    }

    byte[] decrypt(EncryptedBytes encrypted) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key(encrypted.salt()), new GCMParameterSpec(GCM_TAG_BITS, encrypted.iv()));
            return cipher.doFinal(encrypted.ciphertext());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt CA private key", e);
        }
    }

    private SecretKeySpec key(byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_BITS);
        byte[] encoded = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec)
                .getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }
}
