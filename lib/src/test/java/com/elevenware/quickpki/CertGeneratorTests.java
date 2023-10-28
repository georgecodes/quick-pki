package com.elevenware.quickpki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CertGeneratorTests {

    @Test
    void generateSelfSigned() throws Exception {

        CertGenerator generator = new CertGenerator(new BouncyCastleProvider());
        LocalDateTime startTime = LocalDateTime.now();
        LocalDateTime endTime = startTime.plusYears(1L);

        CertInfo info = CertInfo.builder()
                .commonName("My Cert")
                .startDate(startTime)
                .endDate(endTime)
                .build();

        CertificateBundle bundle = generator.generate(info);

        assertEquals("CN=My Cert", bundle.getX509Certificate().getIssuerDN().getName());

    }

}
