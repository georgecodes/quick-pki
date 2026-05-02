package com.elevenware.quickpki.acme;

import java.security.SecureRandom;

final class Ids {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Ids() {
    }

    static String randomUrlToken(int bytes) {
        byte[] token = new byte[bytes];
        RANDOM.nextBytes(token);
        return Base64Url.encode(token);
    }
}
