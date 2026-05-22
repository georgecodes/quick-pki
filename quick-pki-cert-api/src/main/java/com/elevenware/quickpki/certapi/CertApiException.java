package com.elevenware.quickpki.certapi;

/**
 * Carries an HTTP status and a machine-readable error code so handlers can be
 * translated uniformly into a JSON error body. The {@code error} code follows
 * OAuth 2.0 conventions for the 401/403 cases ({@code invalid_token},
 * {@code insufficient_scope}) so it can also be echoed in a
 * {@code WWW-Authenticate} header.
 */
final class CertApiException extends RuntimeException {

    private final int status;
    private final String error;

    CertApiException(int status, String error, String message) {
        super(message);
        this.status = status;
        this.error = error;
    }

    int status() {
        return status;
    }

    String error() {
        return error;
    }
}
