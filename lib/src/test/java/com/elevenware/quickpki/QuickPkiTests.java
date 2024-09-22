package com.elevenware.quickpki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class QuickPkiTests {

    @Test
    void rootIssuerOnly() {

        QuickPki pki = QuickPki.builder()
                .withProvider(new BouncyCastleProvider())
                .withIssuer(CertInfo.builder()
                        .commonName("My Root Issuer")
                        .build())
                .build();

        CertificateBundle bundle = pki.issue(CertInfo.builder()
                .commonName("My Leaf")
                .build());

        CertificateBundle root = pki.getRoot();

        assertEquals(bundle.getCertificate().getIssuerDN().getName(), root.getCertificate().getSubjectDN().getName());
        assertTrue(bundle.isIssuedBy(root));
    }

}
