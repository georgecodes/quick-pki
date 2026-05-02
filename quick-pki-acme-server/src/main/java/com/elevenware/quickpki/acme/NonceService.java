package com.elevenware.quickpki.acme;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

final class NonceService {

    // Defaults: ACME nonces are single-use replay protection. RFC 8555 doesn't
    // mandate a TTL, but a short window is fine - clients fetch a fresh nonce
    // on every request - and prevents an unbounded nonce set being grown by a
    // client that asks for new-nonce repeatedly without consuming them.
    private static final Duration DEFAULT_TTL = Duration.ofMinutes(15);
    private static final int DEFAULT_MAX_SIZE = 100_000;

    private final Clock clock;
    private final Duration ttl;
    private final int maxSize;
    private final ConcurrentMap<String, Instant> nonces = new ConcurrentHashMap<>();

    NonceService() {
        this(Clock.systemUTC(), DEFAULT_TTL, DEFAULT_MAX_SIZE);
    }

    NonceService(Clock clock, Duration ttl, int maxSize) {
        if (maxSize < 1) {
            throw new IllegalArgumentException("maxSize must be positive");
        }
        this.clock = clock;
        this.ttl = ttl;
        this.maxSize = maxSize;
    }

    String create() {
        purgeExpired();
        enforceCapacity();
        String nonce = Ids.randomUrlToken(24);
        nonces.put(nonce, clock.instant().plus(ttl));
        return nonce;
    }

    void consume(String nonce) {
        purgeExpired();
        if (nonce == null) {
            throw badNonce();
        }
        Instant expiresAt = nonces.remove(nonce);
        if (expiresAt == null || expiresAt.isBefore(clock.instant())) {
            throw badNonce();
        }
    }

    int size() {
        return nonces.size();
    }

    private void purgeExpired() {
        Instant now = clock.instant();
        nonces.values().removeIf(expiresAt -> expiresAt.isBefore(now));
    }

    // Belt-and-braces: if a misbehaving client manages to fill the map within
    // the TTL window, evict oldest entries until we're back under the cap.
    // Safe: dropping unconsumed nonces just forces those clients to re-fetch.
    private void enforceCapacity() {
        if (nonces.size() < maxSize) {
            return;
        }
        Iterator<Map.Entry<String, Instant>> it = nonces.entrySet()
                .stream()
                .sorted(Map.Entry.comparingByValue())
                .iterator();
        while (nonces.size() >= maxSize && it.hasNext()) {
            nonces.remove(it.next().getKey());
        }
    }

    private static AcmeException badNonce() {
        return new AcmeException(400, "badNonce", "JWS nonce is missing, expired, or already used");
    }
}
