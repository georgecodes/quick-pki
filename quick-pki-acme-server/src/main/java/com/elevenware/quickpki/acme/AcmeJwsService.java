package com.elevenware.quickpki.acme;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

final class AcmeJwsService {

    private static final TypeReference<Map<String, Object>> MAP = new TypeReference<>() {
    };

    private final AcmeRepository repository;
    private final NonceService nonceService;

    AcmeJwsService(AcmeRepository repository, NonceService nonceService) {
        this.repository = repository;
        this.nonceService = nonceService;
    }

    AcmeRequest read(String body, boolean accountRequired) {
        try {
            JsonNode json = Json.MAPPER.readTree(body);
            String protectedPart = required(json, "protected");
            String payloadPart = json.path("payload").asText("");
            String signaturePart = required(json, "signature");
            JsonNode protectedJson = Json.MAPPER.readTree(Base64Url.decode(protectedPart));

            nonceService.consume(protectedJson.path("nonce").asText(null));
            JWK key = keyFor(protectedJson, accountRequired);
            JWSObject jws = new JWSObject(
                    Base64URL.from(protectedPart),
                    Base64URL.from(payloadPart),
                    Base64URL.from(signaturePart));
            if (!jws.verify(verifierFor(key))) {
                throw new AcmeException(400, "malformed", "JWS signature verification failed");
            }

            Account account = null;
            if (protectedJson.hasNonNull("kid")) {
                account = accountFromKid(protectedJson.get("kid").asText());
            }
            String payloadJson = payloadPart == null || payloadPart.isEmpty()
                    ? "{}"
                    : new String(Base64Url.decode(payloadPart), StandardCharsets.UTF_8);
            Map<String, Object> payload = Json.MAPPER.readValue(payloadJson, MAP);
            return new AcmeRequest(payload, key, account, protectedJson.path("url").asText(null));
        } catch (AcmeException e) {
            throw e;
        } catch (Exception e) {
            throw new AcmeException(400, "malformed", "Malformed ACME JWS request: " + e.getMessage());
        }
    }

    String thumbprint(JWK key) {
        try {
            return key.computeThumbprint().toString();
        } catch (Exception e) {
            throw new AcmeException(400, "malformed", "Unable to compute account key thumbprint");
        }
    }

    private JWK keyFor(JsonNode protectedJson, boolean accountRequired) throws Exception {
        if (protectedJson.hasNonNull("jwk")) {
            return JWK.parse(Json.MAPPER.convertValue(protectedJson.get("jwk"), MAP));
        }
        if (protectedJson.hasNonNull("kid")) {
            return JWK.parse(accountFromKid(protectedJson.get("kid").asText()).jwkJson());
        }
        if (accountRequired) {
            throw new AcmeException(401, "accountDoesNotExist", "Request must identify an ACME account");
        }
        throw new AcmeException(400, "malformed", "Request must contain jwk or kid in protected header");
    }

    private Account accountFromKid(String kid) {
        String id = kid.substring(kid.lastIndexOf('/') + 1);
        try {
            return repository.findAccount(UUID.fromString(id))
                    .orElseThrow(() -> new AcmeException(401, "accountDoesNotExist", "ACME account not found"));
        } catch (IllegalArgumentException e) {
            throw new AcmeException(401, "accountDoesNotExist", "ACME account not found");
        }
    }

    private com.nimbusds.jose.JWSVerifier verifierFor(JWK key) throws Exception {
        if (KeyType.RSA.equals(key.getKeyType())) {
            return new RSASSAVerifier(key.toRSAKey().toRSAPublicKey());
        }
        if (KeyType.EC.equals(key.getKeyType())) {
            return new ECDSAVerifier(key.toECKey().toECPublicKey());
        }
        throw new AcmeException(400, "badPublicKey", "Unsupported account key type");
    }

    private String required(JsonNode json, String field) {
        if (!json.hasNonNull(field)) {
            throw new AcmeException(400, "malformed", "JWS missing " + field);
        }
        return json.get(field).asText();
    }

    record AcmeRequest(Map<String, Object> payload, JWK jwk, Account account, String url) {

        Optional<String> string(String name) {
            Object value = payload.get(name);
            return value instanceof String s ? Optional.of(s) : Optional.empty();
        }
    }
}
