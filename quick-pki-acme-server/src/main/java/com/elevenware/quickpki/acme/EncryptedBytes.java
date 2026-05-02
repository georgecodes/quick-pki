package com.elevenware.quickpki.acme;

record EncryptedBytes(byte[] ciphertext, byte[] salt, byte[] iv) {
}
