package com.elevenware.quickpki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateChainTests {

    @Test
    void canIssueLeafCertFromRoot() {

        CertificateAuthority certificateAuthority = CertificateAuthority.builder()
                .withProvider(new BouncyCastleProvider())
                .withIssuer("My Root")
                .endDate(LocalDateTime.now().plusMinutes(1L))
                .build();

        CertificateChain chain = certificateAuthority.getChains().get("My Root");
        CertificateBundle leaf = chain.issue(CertInfo.builder()
                .commonName("My Leaf")
                .endDate(LocalDateTime.now().plusMinutes(1L))
                .build());

        assertNotNull(leaf);
        assertTrue(leaf.isIssuedBy(certificateAuthority.getRoot()));

    }

    @Test
    void canIssueLeafCertFromIssuer() {

        CertificateAuthority certificateAuthority = CertificateAuthority.builder()
                .withProvider(new BouncyCastleProvider())
                .withIssuer("My Root")
                .endDate(LocalDateTime.now().plusMinutes(1L))
                .withIntermediate(CertInfo.builder()
                        .commonName("My Intermediate")
                        .endDate(LocalDateTime.now().plusMinutes(1L))
                        .build())
                .build();

        CertificateChain chain = certificateAuthority.getChains().get("My Intermediate");
        CertificateBundle leaf = chain.issue(CertInfo.builder()
                .commonName("My Leaf")
                .endDate(LocalDateTime.now().plusMinutes(1L))
                .build());

        assertNotNull(leaf);
        assertFalse(leaf.isIssuedBy(certificateAuthority.getRoot()));
        assertTrue(leaf.isIssuedBy(chain.getTrustChain().get(1)));

    }

    @Test
    void canAddAnIntermediate() {

        CertificateAuthority certificateAuthority = CertificateAuthority.builder()
                .withProvider(new BouncyCastleProvider())
                .withIssuer("My Root")
                .endDate(LocalDateTime.now().plusMinutes(1L))
                .withIntermediate(CertInfo.builder()
                        .commonName("My Intermediate")
                        .endDate(LocalDateTime.now().plusMinutes(1L))
                        .build())
                .build();

        CertificateChain chain = certificateAuthority.getChain("My Intermediate");
        CertificateBundle newIntermediate = chain.addIntermediate(CertInfo.builder()
                .commonName("My Other Intermediate")
                .build());


        CertificateBundle leaf = chain.issue(CertInfo.builder()
                .commonName("My Leaf")
                .endDate(LocalDateTime.now().plusMinutes(1L))
                .build());

        assertNotNull(leaf);
        assertTrue(leaf.isIssuedBy(newIntermediate));

    }

}
