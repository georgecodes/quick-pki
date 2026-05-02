package com.elevenware.quickpki.acme;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class KeyEncryptorTest {

    @Test
    void encryptsAndDecryptsKeyMaterial() {
        KeyEncryptor encryptor = new KeyEncryptor("change-this-development-password");
        byte[] plaintext = "private-key-material".getBytes(StandardCharsets.UTF_8);

        EncryptedBytes encrypted = encryptor.encrypt(plaintext);

        assertFalse(java.util.Arrays.equals(plaintext, encrypted.ciphertext()));
        assertArrayEquals(plaintext, encryptor.decrypt(encrypted));
    }

    @Test
    void wrongPasswordCannotDecrypt() {
        byte[] plaintext = "private-key-material".getBytes(StandardCharsets.UTF_8);
        EncryptedBytes encrypted = new KeyEncryptor("change-this-development-password").encrypt(plaintext);

        assertThrows(IllegalStateException.class,
                () -> new KeyEncryptor("another-development-password").decrypt(encrypted));
    }
}
