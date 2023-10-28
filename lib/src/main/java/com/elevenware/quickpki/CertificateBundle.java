package com.elevenware.quickpki;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

public class CertificateBundle {

    private X509Certificate x509Certificate;
    private KeyPair keyPair;

    public CertificateBundle(X509Certificate certificate, KeyPair keyPair) {
        this.x509Certificate = certificate;
        this.keyPair = keyPair;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }
}
