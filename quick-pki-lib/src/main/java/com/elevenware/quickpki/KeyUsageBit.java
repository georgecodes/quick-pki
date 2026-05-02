package com.elevenware.quickpki;

import org.bouncycastle.asn1.x509.KeyUsage;

// The nine standard X.509 KeyUsage bits (RFC 5280 §4.2.1.3). Pass these to
// CertInfo.Builder.keyUsage(...) to override the default leaf KeyUsage that
// QuickPki picks based on the leaf's key algorithm.
public enum KeyUsageBit {

    DIGITAL_SIGNATURE(KeyUsage.digitalSignature),
    NON_REPUDIATION(KeyUsage.nonRepudiation),
    KEY_ENCIPHERMENT(KeyUsage.keyEncipherment),
    DATA_ENCIPHERMENT(KeyUsage.dataEncipherment),
    KEY_AGREEMENT(KeyUsage.keyAgreement),
    KEY_CERT_SIGN(KeyUsage.keyCertSign),
    CRL_SIGN(KeyUsage.cRLSign),
    ENCIPHER_ONLY(KeyUsage.encipherOnly),
    DECIPHER_ONLY(KeyUsage.decipherOnly);

    private final int bit;

    KeyUsageBit(int bit) {
        this.bit = bit;
    }

    int bit() {
        return bit;
    }
}
