package com.elevenware.quickpki.acme;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

record Identifier(String type, String value) {
}

record Account(UUID id, String keyThumbprint, String jwkJson, String contactJson, String status, boolean termsAgreed) {
}

record Order(
        UUID id,
        UUID accountId,
        String status,
        Instant expiresAt,
        String identifiersJson,
        byte[] csrDer,
        String certificatePem,
        String chainPem,
        List<Authorization> authorizations
) {
}

record Authorization(
        UUID id,
        UUID orderId,
        String identifierType,
        String identifierValue,
        boolean wildcard,
        String status,
        Instant expiresAt,
        List<Challenge> challenges
) {

    Identifier identifier() {
        return new Identifier(identifierType, identifierValue);
    }
}

record Challenge(
        UUID id,
        UUID authorizationId,
        String type,
        String token,
        String status,
        Instant validatedAt,
        String errorJson
) {
}

record CaMaterial(
        String issuerInfoJson,
        String certificatePem,
        byte[] privateKeyCiphertext,
        byte[] privateKeySalt,
        byte[] privateKeyIv
) {
}
