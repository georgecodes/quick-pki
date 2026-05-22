package com.elevenware.quickpki.certapi;

import java.time.Instant;
import java.util.UUID;

/**
 * The issuing CA's persisted material: its self-signed certificate plus its
 * private key encrypted at rest. A single row keeps the issuer identity stable
 * across restarts.
 */
record CaMaterial(
        String issuerInfoJson,
        String certificatePem,
        byte[] privateKeyCiphertext,
        byte[] privateKeySalt,
        byte[] privateKeyIv
) {
}

/**
 * A certificate that has been signed and persisted, together with the metadata
 * needed to serve it back to a caller.
 *
 * @param clientId the OAuth client (from token introspection) that requested it
 */
record IssuedCertificate(
        UUID id,
        String serialNumber,
        String subjectDn,
        String certificatePem,
        String chainPem,
        Instant notBefore,
        Instant notAfter,
        String clientId,
        Instant createdAt
) {
}

/**
 * Inbound JSON request body for {@code POST /v1/certificates}.
 *
 * @param csr     a base64-encoded PKCS#10 certificate request
 * @param profile the certificate profile name to issue under (eg. {@code
 *                BRCAC}); optional, {@code null} means the DEFAULT profile
 */
record CertificateRequest(String csr, String profile) {
}
