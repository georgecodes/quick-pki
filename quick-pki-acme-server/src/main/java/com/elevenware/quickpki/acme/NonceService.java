package com.elevenware.quickpki.acme;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

final class NonceService {

    private final Set<String> nonces = ConcurrentHashMap.newKeySet();

    String create() {
        String nonce = Ids.randomUrlToken(24);
        nonces.add(nonce);
        return nonce;
    }

    void consume(String nonce) {
        if (nonce == null || !nonces.remove(nonce)) {
            throw new AcmeException(400, "badNonce", "JWS nonce is missing, expired, or already used");
        }
    }
}
