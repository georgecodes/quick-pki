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
 * Inbound JSON request body for {@code POST /v1/openssl-configs/brcac}. The
 * caller supplies the BRCAC subject attributes; the server returns an
 * openssl {@code req} config that bakes them in, so the caller can produce
 * a compliant CSR with their own private key via
 * {@code openssl req -new -config brcac.cnf -key key.pem -out csr.pem}.
 * Country and jurisdictionCountry default to {@code BR} when omitted.
 */
record BrcacOpensslConfigRequest(
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
 * Inbound JSON request body for {@code POST /v1/openssl-configs/brseal}.
 * Same idea as {@link BrcacOpensslConfigRequest}, with the BRSEAL subject
 * attributes and the four ICP-Brasil otherName SAN values that go into the
 * generated config. Country defaults to {@code BR}, organization to
 * {@code ICP-Brasil} when omitted.
 */
record BrsealOpensslConfigRequest(
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

/**
 * Inbound JSON request body for {@code POST /v1/openssl-configs/qwac}.
 * Collects the QWAC subject attributes and PSD2 metadata the server bakes
 * into the openssl {@code req} config. The config emits the standard ETSI
 * QC statements (QcCompliance + QcType=web) and, when {@code psd2Roles} is
 * populated, the PSD2 qcStatement listing the PSP's roles and NCA.
 *
 * <p>Field reference: ETSI EN 319 412-1 §5.1 for the subject DN attributes,
 * ETSI TS 119 495 §5 for the PSD2 organizationIdentifier and qcStatement
 * payload.
 */
record QwacOpensslConfigRequest(
        String commonName,
        String country,
        String stateOrProvince,
        String locality,
        String organization,
        String organizationIdentifier,
        String serialNumber,
        List<String> dnsNames,
        List<String> psd2Roles,
        String ncaName,
        String ncaId,
        List<PdsLocationRequest> pdsLocations
) {
}

/**
 * Inbound JSON request body for {@code POST /v1/openssl-configs/qseal}.
 * Same shape as {@link QwacOpensslConfigRequest} but produces a config for
 * the QSEAL profile - no DNS SANs, QcType set to {@code id-etsi-qct-eseal},
 * optional {@code QcSSCD} qcStatement when {@code onQscd} is {@code true}.
 */
record QsealOpensslConfigRequest(
        String commonName,
        String country,
        String stateOrProvince,
        String locality,
        String organization,
        String organizationIdentifier,
        String serialNumber,
        List<String> psd2Roles,
        String ncaName,
        String ncaId,
        List<PdsLocationRequest> pdsLocations,
        boolean onQscd
) {
}

/**
 * A single PDS URL / language pair carried in the {@code QcPDS} qcStatement
 * payload. Language must be an ISO 639-1 two-letter code (eg. {@code "en"}).
 */
record PdsLocationRequest(String url, String language) {
}

/**
 * Response body for {@code POST /v1/openssl-configs/{brcac,brseal}}: the
 * generated openssl {@code req} config, base64-encoded (consistent with how
 * CSRs and certs travel on this API), plus a suggested filename for callers
 * that want to save the config to disk before invoking openssl.
 */
record OpensslConfigResponse(String filename, String config) {
}
