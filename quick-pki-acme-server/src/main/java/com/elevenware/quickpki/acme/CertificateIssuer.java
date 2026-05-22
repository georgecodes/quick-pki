package com.elevenware.quickpki.acme;

import java.util.List;

/**
 * Source of signed certificates for finalized ACME orders.
 * <p>
 * The ACME server either mints certificates from a CA it holds locally
 * ({@link CertificateAuthorityService}) or delegates issuance to a deployed
 * certificate API ({@link RemoteCertificateIssuer}). Which one is used is
 * decided at startup from configuration, so the rest of the server depends
 * only on this interface.
 */
interface CertificateIssuer {

    /**
     * Issues a certificate for the given PKCS#10 CSR. Implementations must only
     * issue subjectAltName entries covered by {@code validatedIdentifiers};
     * see {@link CsrValidation}.
     */
    IssuedCertificate issue(byte[] csrDer, List<Identifier> validatedIdentifiers);

    /** PEM of the certificate that anchors the chain returned by {@link #issue}. */
    String issuerPem();

    record IssuedCertificate(String certificatePem, String chainPem) {
    }
}
