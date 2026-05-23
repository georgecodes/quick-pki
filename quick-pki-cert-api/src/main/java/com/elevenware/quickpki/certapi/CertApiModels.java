package com.elevenware.quickpki.certapi;

import java.time.Instant;
import java.util.List;
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
 * @param csrPem   the PKCS#10 the certificate was issued from, persisted for
 *                 audit. For the convenience /brcac and /brseal endpoints this
 *                 is a synthetic CSR built server-side around the consumer's
 *                 public key, signed by an ephemeral key, so its signature
 *                 deliberately will not verify. Nullable for rows persisted
 *                 before changeset 002.
 */
record IssuedCertificate(
        UUID id,
        String serialNumber,
        String subjectDn,
        String certificatePem,
        String chainPem,
        String csrPem,
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

/**
 * Inbound JSON request body for {@code POST /v1/certificates/brcac}. The
 * consumer supplies the subject attributes plus a PEM-encoded
 * SubjectPublicKeyInfo public key; the server constructs a synthetic PKCS#10
 * around it, issues the BRCAC certificate, and returns both. Country defaults
 * to {@code BR} and jurisdictionCountry to {@code BR} when omitted.
 */
record BrcacCertificateRequest(
        String publicKey,
        String commonName,
        String businessCategory,
        String serialNumber,
        String organization,
        String stateOrProvince,
        String locality,
        String organizationIdentifier,
        String userId,
        String country,
        String jurisdictionCountry,
        List<String> dnsNames
) {
}

/**
 * Inbound JSON request body for {@code POST /v1/certificates/brseal}. The
 * consumer supplies the subject attributes, the four ICP-Brasil otherName
 * SAN values, plus a PEM-encoded SubjectPublicKeyInfo public key. Country
 * defaults to {@code BR} and organization to {@code ICP-Brasil} when omitted.
 */
record BrsealCertificateRequest(
        String publicKey,
        String commonName,
        String userId,
        String country,
        String organization,
        List<String> organizationUnits,
        String responsiblePersonName,
        String companyCnpj,
        String responsiblePersonData,
        String companyCei
) {
}
