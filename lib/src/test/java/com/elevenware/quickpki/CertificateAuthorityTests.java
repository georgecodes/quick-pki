package com.elevenware.quickpki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateAuthorityTests {

    @Test
    void canCreateAuthorityWithRootOnly() {

        CertificateAuthority certificateAuthority = CertificateAuthority.builder()
            .withProvider(new BouncyCastleProvider())
            .withIssuer("My Root")
            .endDate(LocalDateTime.now().plusMinutes(1L))
            .build();

        CertificateBundle root = certificateAuthority.getRoot();

        assertEquals("CN=My Root", root.getCertificate().getIssuerDN().getName());
        assertTrue(root.isIssuedBy(root));

    }

    @Test
    void canCreateAuthorityWithIntermediates() {

        CertificateAuthority certificateAuthority = CertificateAuthority.builder()
                .withProvider(new BouncyCastleProvider())
                .withIssuer("My Root Issuer")
                .endDate(LocalDateTime.now().plusMinutes(1L))
                .withIntermediate(CertInfo.builder()
                        .commonName("My Intermediate Issuer 1")
                        .endDate(LocalDateTime.now().plusMinutes(1L))
                        .build())
                .withIntermediate(CertInfo.builder()
                        .commonName("My Intermediate Issuer 2")
                        .endDate(LocalDateTime.now().plusMinutes(1L))
                        .build())
                .build();

        Collection<CertificateChain> chains = certificateAuthority.getChains().values();

        assertEquals(2, chains.size());
        for(CertificateChain chain: chains) {
            List<CertificateBundle> certs = chain.getTrustChain();
            Iterator<CertificateBundle> iterator = certs.iterator();
            CertificateBundle current = iterator.next();
            while(iterator.hasNext()) {
                CertificateBundle next = iterator.next();
                assertTrue(next.isIssuedBy(current));
                current = next;
            }
        }

    }

}
