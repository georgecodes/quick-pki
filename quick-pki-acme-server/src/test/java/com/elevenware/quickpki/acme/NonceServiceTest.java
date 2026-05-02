package com.elevenware.quickpki.acme;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class NonceServiceTest {

    @Test
    void nonceCanOnlyBeConsumedOnce() {
        NonceService service = new NonceService();
        String nonce = service.create();

        assertDoesNotThrow(() -> service.consume(nonce));
        AcmeException reused = assertThrows(AcmeException.class, () -> service.consume(nonce));

        assertEquals(400, reused.status());
        assertEquals("badNonce", reused.type());
    }

    @Test
    void missingNonceIsRejected() {
        NonceService service = new NonceService();

        AcmeException exception = assertThrows(AcmeException.class, () -> service.consume(null));

        assertEquals(400, exception.status());
        assertEquals("badNonce", exception.type());
    }
}
