package com.elevenware.quickpki.certapi;

record EncryptedBytes(byte[] ciphertext, byte[] salt, byte[] iv) {
}
