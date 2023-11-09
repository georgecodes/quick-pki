package com.elevenware.quickpki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import static com.elevenware.quickpki.Utils.dateToLocalDateTime;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class CertGeneratorTests {

    @Test
    void generateSelfSigned() throws Exception {

        CertGenerator generator = new CertGenerator(new BouncyCastleProvider());
        LocalDateTime startTime = LocalDateTime.now();
        LocalDateTime endTime = startTime.plusMinutes(1L);

        CertInfo info = CertInfo.builder()
                .commonName("My Cert")
                .startDate(startTime)
                .endDate(endTime)
                .isCa(true)
                .build();

        CertificateBundle bundle = generator.issue(info);
        X509Certificate certificate  = bundle.getCertificate();;

        assertEquals("CN=My Cert", certificate.getSubjectDN().getName());
        assertEquals("CN=My Cert", certificate.getIssuerDN().getName());
        assertThat(startTime).isEqualToIgnoringNanos(dateToLocalDateTime(certificate.getNotBefore()));
        assertThat(endTime).isEqualToIgnoringNanos(dateToLocalDateTime(certificate.getNotAfter()));

        PublicKey key = certificate.getPublicKey();
        try {
            certificate.verify(key);
        } catch (SignatureException signatureException) {
            fail("Not self-signed");
        }

    }

    @Test
    void generateSigned() throws Exception {

        CertGenerator generator = new CertGenerator(new BouncyCastleProvider());
        LocalDateTime startTime = LocalDateTime.now();
        LocalDateTime endTime = startTime.plusMinutes(1L);

        CertInfo info = CertInfo.builder()
                .commonName("My Root Cert")
                .startDate(startTime)
                .endDate(endTime)
                .build();

        CertificateBundle rootBundle = generator.issue(info);
        X509Certificate rootCert  = rootBundle.getCertificate();

        info = CertInfo.builder()
                .commonName("My Cert")
                .startDate(startTime)
                .endDate(endTime)
                .issuer(rootBundle)
                .build();

        CertificateBundle bundle = generator.issue(info);
        X509Certificate certificate = bundle.getCertificate();

        assertEquals("CN=My Cert", certificate.getSubjectDN().getName());
        assertEquals("CN=My Root Cert", certificate.getIssuerDN().getName());
        assertThat(startTime).isEqualToIgnoringNanos(dateToLocalDateTime(certificate.getNotBefore()));
        assertThat(endTime).isEqualToIgnoringNanos(dateToLocalDateTime(certificate.getNotAfter()));

        PublicKey key = certificate.getPublicKey();
        try {
            certificate.verify(key);
            fail("Self-signed");
        } catch (SignatureException signatureException) {
        }

        key = rootCert.getPublicKey();
        try {
            certificate.verify(key);
        } catch (SignatureException signatureException) {
            fail("Not issued by issuer");
        }

        X500Principal issuerX500Principal = certificate.getIssuerX500Principal();

        Utils.dumpCert(certificate);

    }




}
