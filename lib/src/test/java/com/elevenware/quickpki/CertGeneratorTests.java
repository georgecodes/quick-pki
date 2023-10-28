package com.elevenware.quickpki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

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
                .build();

        CertificateBundle bundle = generator.generate(info);
        X509Certificate certificate  = bundle.getCertificate();;

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
                .commonName("My Cert")
                .startDate(startTime)
                .endDate(endTime)
                .build();

        CertificateBundle bundle = generator.generate(info);
        X509Certificate certificate  = bundle.getCertificate();;

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

    public LocalDateTime dateToLocalDateTime(Date dateToConvert) {
        return dateToConvert.toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime();
    }

}
