package com.elevenware.quickpki;

public class QuickPkiException extends RuntimeException {

    public QuickPkiException(String message, Throwable cause) {
        super(message, cause);
    }

    public QuickPkiException(String message) {
        super(message);
    }
}
