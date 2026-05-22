package com.elevenware.quickpki.certapi;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Decodes the base64-encoded CSR carried in an API request into a parsed
 * {@link PKCS10CertificationRequest}. After base64-decoding the body accepts
 * either a raw DER request or a PEM-wrapped one, so callers can send whatever
 * {@code openssl req} produced without re-encoding it.
 */
final class Csrs {

    private Csrs() {
    }

    static PKCS10CertificationRequest parse(String base64Csr) {
        if (base64Csr == null || base64Csr.isBlank()) {
            throw new CertApiException(400, "invalid_request",
                    "request body must contain a non-empty base64-encoded 'csr' field");
        }
        byte[] decoded;
        try {
            decoded = Base64.getMimeDecoder().decode(base64Csr.trim());
        } catch (IllegalArgumentException e) {
            throw new CertApiException(400, "invalid_request", "'csr' is not valid base64");
        }
        try {
            String asText = new String(decoded, StandardCharsets.US_ASCII);
            if (asText.contains("-----BEGIN")) {
                try (PEMParser parser = new PEMParser(new StringReader(asText))) {
                    Object object = parser.readObject();
                    if (object instanceof PKCS10CertificationRequest request) {
                        return request;
                    }
                }
                throw new CertApiException(400, "bad_csr",
                        "decoded PEM does not contain a PKCS#10 certificate request");
            }
            return new PKCS10CertificationRequest(decoded);
        } catch (CertApiException e) {
            throw e;
        } catch (Exception e) {
            throw new CertApiException(400, "bad_csr",
                    "could not parse PKCS#10 certificate request: " + e.getMessage());
        }
    }
}
