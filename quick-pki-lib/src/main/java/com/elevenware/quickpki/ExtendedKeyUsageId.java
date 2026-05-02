package com.elevenware.quickpki;

import org.bouncycastle.asn1.x509.KeyPurposeId;

// The six standard ExtendedKeyUsage purposes from RFC 5280 §4.2.1.12. Pass
// these to CertInfo.Builder.extendedKeyUsage(...) to override the default
// leaf EKU (serverAuth + clientAuth).
public enum ExtendedKeyUsageId {

    SERVER_AUTH(KeyPurposeId.id_kp_serverAuth),
    CLIENT_AUTH(KeyPurposeId.id_kp_clientAuth),
    CODE_SIGNING(KeyPurposeId.id_kp_codeSigning),
    EMAIL_PROTECTION(KeyPurposeId.id_kp_emailProtection),
    TIME_STAMPING(KeyPurposeId.id_kp_timeStamping),
    OCSP_SIGNING(KeyPurposeId.id_kp_OCSPSigning);

    private final KeyPurposeId keyPurposeId;

    ExtendedKeyUsageId(KeyPurposeId keyPurposeId) {
        this.keyPurposeId = keyPurposeId;
    }

    KeyPurposeId keyPurposeId() {
        return keyPurposeId;
    }
}
