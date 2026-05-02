package com.elevenware.quickpki.acme;

import java.util.Base64;

final class Base64Url {

    private Base64Url() {
    }

    static String encode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static byte[] decode(String value) {
        return Base64.getUrlDecoder().decode(value);
    }
}
