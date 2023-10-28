package com.elevenware.quickpki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class PkiTests {

    @Test
    void canCreatePkiWithRootOnly() {

        QuickPki quickPki = QuickPki.builder()
            .withProvider(new BouncyCastleProvider())
            .withIssuer("My Issuer")
            .build();

        X509Certificate[] chain = quickPki.getCertificateChain();

        assertEquals(1, chain.length);
        X509Certificate root = chain[0];
        assertNotNull(root);

        assertEquals("CN=My Issuer", root.getIssuerDN().getName());

    }

}
