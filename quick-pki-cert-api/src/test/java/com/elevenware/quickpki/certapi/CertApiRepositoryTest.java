package com.elevenware.quickpki.certapi;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class CertApiRepositoryTest {

    @Test
    void saveCaMaterialUpsertsTheSingleRow() throws Exception {
        CertApiRepository repository = new CertApiRepository(CertApiTestSupport.dataSource());

        repository.saveCaMaterial(new CaMaterial("{}", "first", new byte[]{1}, new byte[]{2}, new byte[]{3}));
        repository.saveCaMaterial(new CaMaterial("{}", "second", new byte[]{4}, new byte[]{5}, new byte[]{6}));

        CaMaterial loaded = repository.loadCaMaterial().orElseThrow();
        assertThat(loaded.certificatePem()).isEqualTo("second");
        assertThat(loaded.privateKeyCiphertext()).containsExactly(4);
    }

    @Test
    void savesAndLoadsAnIssuedCertificate() throws Exception {
        CertApiRepository repository = new CertApiRepository(CertApiTestSupport.dataSource());
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        UUID id = UUID.randomUUID();
        IssuedCertificate certificate = new IssuedCertificate(
                id,
                "1a2b3c",
                "CN=service.example.com",
                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE REQUEST-----\ncsr\n-----END CERTIFICATE REQUEST-----\n",
                now,
                now.plus(90, ChronoUnit.DAYS),
                "client-42",
                now);

        repository.saveCertificate(certificate);

        IssuedCertificate loaded = repository.loadCertificate(id).orElseThrow();
        assertThat(loaded.serialNumber()).isEqualTo("1a2b3c");
        assertThat(loaded.subjectDn()).isEqualTo("CN=service.example.com");
        assertThat(loaded.certificatePem()).contains("leaf");
        assertThat(loaded.chainPem()).contains("chain");
        assertThat(loaded.csrPem()).contains("csr");
        assertThat(loaded.clientId()).isEqualTo("client-42");
        assertThat(loaded.notAfter()).isEqualTo(now.plus(90, ChronoUnit.DAYS));
    }

    @Test
    void rowsWithoutACsrLoadCleanly() throws Exception {
        CertApiRepository repository = new CertApiRepository(CertApiTestSupport.dataSource());
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        UUID id = UUID.randomUUID();
        IssuedCertificate certificate = new IssuedCertificate(
                id,
                "deadbeef",
                "CN=legacy.example.com",
                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----\n",
                null,
                now,
                now.plus(90, ChronoUnit.DAYS),
                "client-42",
                now);

        repository.saveCertificate(certificate);

        IssuedCertificate loaded = repository.loadCertificate(id).orElseThrow();
        assertThat(loaded.csrPem()).isNull();
    }

    @Test
    void loadingAnUnknownCertificateReturnsEmpty() throws Exception {
        CertApiRepository repository = new CertApiRepository(CertApiTestSupport.dataSource());

        assertThat(repository.loadCertificate(UUID.randomUUID())).isEmpty();
    }
}
