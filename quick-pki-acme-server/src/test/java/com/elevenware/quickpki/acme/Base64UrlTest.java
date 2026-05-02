package com.elevenware.quickpki.acme;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class Base64UrlTest {

    @Test
    void encodesWithoutPaddingAndRoundTrips() {
        byte[] original = "quick-pki?".getBytes(StandardCharsets.UTF_8);

        String encoded = Base64Url.encode(original);

        assertEquals("cXVpY2stcGtpPw", encoded);
        assertArrayEquals(original, Base64Url.decode(encoded));
    }
}
