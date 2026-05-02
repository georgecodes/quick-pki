package com.elevenware.quickpki.acme;

final class AcmeException extends RuntimeException {

    private final int status;
    private final String type;

    AcmeException(int status, String type, String message) {
        super(message);
        this.status = status;
        this.type = type;
    }

    int status() {
        return status;
    }

    String type() {
        return type;
    }
}
