package com.elevenware.quickpki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PkiTests {

    @Test
    void canCreateDefaultPki() {

        QuickPki pki = QuickPki.createDefault();

        assertNotNull(pki);

        CertificateBundle issuer = pki.getIssuer();
        assertNotNull(issuer);

        assertTrue(issuer.issuedBy(issuer));
        assertEquals("Default Root Issuer", issuer.getCommonName());

    }

    @Test
    void canIssueCertificate() {

        QuickPki pki = QuickPki.createDefault();
        CertificateBundle issuer = pki.getIssuer();
        CertificateBundle bundle = pki.issueCertificate(CertInfo.builder()
                        .subjectName(SubjectName.builder()
                                .commonName("My First Certificate")
                                .build())
                .build());

        assertNotNull(bundle);
        assertEquals("My First Certificate", bundle.getCommonName());

        assertTrue(bundle.issuedBy(issuer));
        assertFalse(bundle.issuedBy(bundle));
        assertFalse(issuer.issuedBy(bundle));

    }

    @Test
    void issuesCertificateWithDefaults() {

        QuickPki pki = QuickPki.createDefault();
        CertificateBundle bundle = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder()
                        .commonName("My First Certificate").build())
                .build());

        X509Certificate certificate = bundle.getCertificate();
        assertDoesNotThrow(() -> certificate.checkValidity());
        Instant exp = Instant.now().plus(1, ChronoUnit.DAYS);
        assertDoesNotThrow(() -> certificate.checkValidity(Date.from(exp.minus(2, ChronoUnit.SECONDS))));
        assertThrows(CertificateExpiredException.class, () -> certificate.checkValidity(Date.from(exp)));
        assertThrows(CertificateNotYetValidException.class, () -> certificate.checkValidity(Date.from(Instant.now().minus(1, ChronoUnit.MINUTES))));

    }

    @Test
    void createCertificateWithCustomExpiry() {
        QuickPki pki = QuickPki.createDefault();

        CertificateBundle certificate = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder()
                        .commonName("My First Certificate").build())
                .validFrom(Instant.now().minus(2, ChronoUnit.HOURS))
                .validUntil(Instant.now().minus(1, ChronoUnit.HOURS))
                .build());
        assertThrows(CertificateExpiredException.class, () -> certificate.getCertificate().checkValidity());
    }

    @Test
    void canCustomiseIssuer() {

        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant start = now.minus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        Instant end = now.plus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        QuickPki pki = QuickPki.create(IssuerInfo.builder()
                .subjectName(SubjectName.builder()
                        .commonName("My Custom Issuer").build())
                .validFrom(start)
                .validUntil(end)
                .defaultLifespan(Duration.ofMinutes(1L))
                .build());

        CertificateBundle issuerBundle = pki.getIssuer();
        assertEquals("My Custom Issuer", issuerBundle.getCommonName());
        X509Certificate issuerCert = issuerBundle.getCertificate();
        Date notBefore = issuerCert.getNotBefore();
        assertEquals(start, notBefore.toInstant());

        Date notAfter = issuerCert.getNotAfter();
        assertEquals(end, notAfter.toInstant());

        now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        CertificateBundle leaf = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder()
                        .commonName("My First Certificate").build())
                .build());

        X509Certificate leafCert = leaf.getCertificate();
        Date leafNotAfter = leafCert.getNotAfter();
        assertEquals(now.plus(1, ChronoUnit.MINUTES), leafNotAfter.toInstant());

    }

    @Test
    void issuesCertificateWithFullerSubject() throws IOException, CertificateEncodingException {

        QuickPki pki = QuickPki.createDefault();
        CertificateBundle bundle = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder()
                        .commonName("My First Certificate")
                        .country("GB")
                        .organization("Elevenware")
                        .organizationUnit("Development")
                        .dnQualifier("12345")
                        .locality("London")
                        .stateOrProvince("London").build())

                .build());

        X509Certificate certificate = bundle.getCertificate();
        JcaX509CertificateHolder holder = new JcaX509CertificateHolder(certificate);
        X500Name x500Name = holder.getSubject();
        String commonName = x500Name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
        String country = x500Name.getRDNs(BCStyle.C)[0].getFirst().getValue().toString();
        String organization = x500Name.getRDNs(BCStyle.O)[0].getFirst().getValue().toString();
        String organizationUnit = x500Name.getRDNs(BCStyle.OU)[0].getFirst().getValue().toString();
        String dnQualifier = x500Name.getRDNs(BCStyle.DN_QUALIFIER)[0].getFirst().getValue().toString();
        String locality = x500Name.getRDNs(BCStyle.L)[0].getFirst().getValue().toString();
        String stateOrProvince = x500Name.getRDNs(BCStyle.ST)[0].getFirst().getValue().toString();
        assertEquals("My First Certificate", commonName);
        assertEquals("GB", country);
        assertEquals("Elevenware", organization);
        assertEquals("Development", organizationUnit);
        assertEquals("12345", dnQualifier);
        assertEquals("London", locality);
        assertEquals("London", stateOrProvince);
    }

    // Regression: defaulted SubjectName was discarded; calling issueCertificate
    // with an empty CertInfo NPE'd because the raw info.getSubjectName() was
    // passed to the DN builder rather than the local default.
    @Test
    void issueCertificateWithoutSubjectNameUsesDefault() {
        QuickPki pki = QuickPki.createDefault();
        CertificateBundle bundle = pki.issueCertificate(CertInfo.builder().build());
        assertEquals("Default Subject", bundle.getCommonName());
    }

    // Regression: issued leaves were marked basicConstraints CA:TRUE.
    // X509Certificate.getBasicConstraints() returns -1 for non-CA, otherwise
    // the path-length constraint (Integer.MAX_VALUE if none).
    @Test
    void issuedLeafIsNotMarkedAsCa() {
        QuickPki pki = QuickPki.createDefault();
        CertificateBundle leaf = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Leaf").build())
                .build());

        assertEquals(-1, leaf.getCertificate().getBasicConstraints(),
                "leaf must not be a CA");
        assertNotEquals(-1, pki.getIssuer().getCertificate().getBasicConstraints(),
                "root must remain a CA");
    }

    // Regression: serial numbers were built from BigInteger(Long.toString(SecureRandom.nextLong())),
    // which yields negative values ~50% of the time. RFC 5280 §4.1.2.2 requires
    // positive serials and caps them at 20 octets (159 bits unsigned).
    @Test
    void serialNumbersArePositiveAndWithinRfcBounds() {
        QuickPki pki = QuickPki.createDefault();
        BigInteger rootSerial = pki.getIssuer().getCertificate().getSerialNumber();
        assertEquals(1, rootSerial.signum(), "root serial must be positive");
        assertTrue(rootSerial.bitLength() <= 159, "root serial exceeds RFC 5280 bounds");

        for (int i = 0; i < 16; i++) {
            BigInteger serial = pki.issueCertificate(CertInfo.builder()
                    .subjectName(SubjectName.builder().commonName("Leaf " + i).build())
                    .build())
                    .getCertificate().getSerialNumber();
            assertEquals(1, serial.signum(), "leaf serial must be positive");
            assertTrue(serial.bitLength() <= 159, "leaf serial exceeds RFC 5280 bounds");
        }
    }

    // Regression: createDefault() fetched Security.getProvider("BC") and
    // silently passed null to BC builders if the caller hadn't pre-registered
    // BouncyCastle. The factory must self-register when missing.
    @Test
    void createDefaultRegistersBouncyCastleWhenMissing() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        try {
            assertNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME),
                    "precondition: BC must be unregistered for this test");

            QuickPki pki = QuickPki.createDefault();

            assertNotNull(pki.getIssuer());
            assertNotNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME),
                    "createDefault should have registered BC");
        } finally {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        }
    }

    // Regression: subject DNs were assembled by string concatenation with ", "
    // separators and re-parsed via new X500Name(...). A common name containing
    // a comma could inject extra RDNs ('Innocent, O=Evil' became CN=Innocent + O=Evil).
    @Test
    void commonNameWithCommaIsNotInjectedAsAdditionalRdn() throws CertificateEncodingException {
        QuickPki pki = QuickPki.createDefault();
        String adversarialCn = "Innocent, O=Evil";

        CertificateBundle bundle = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName(adversarialCn).build())
                .build());

        X500Name subject = new JcaX509CertificateHolder(bundle.getCertificate()).getSubject();
        assertEquals(1, subject.getRDNs(BCStyle.CN).length, "subject must have exactly one CN");
        assertEquals(adversarialCn,
                subject.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString(),
                "the comma must remain part of the CN value, not introduce a new RDN");
        assertEquals(0, subject.getRDNs(BCStyle.O).length,
                "no Organization RDN should have been injected");
    }

    // Regression: KeyPairGenerator was a shared mutable field, so concurrent
    // issueCertificate calls could race on internal state. Issuing a batch of
    // certs from many threads should produce N distinct, valid bundles.
    @Test
    void canIssueCertificatesFromMultipleThreadsConcurrently() throws Exception {
        QuickPki pki = QuickPki.createDefault();
        CertificateBundle issuer = pki.getIssuer();

        int threads = 8;
        int perThread = 4;
        int total = threads * perThread;
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        try {
            List<Future<CertificateBundle>> futures = new ArrayList<>(total);
            for (int i = 0; i < total; i++) {
                final int idx = i;
                futures.add(executor.submit(() -> pki.issueCertificate(CertInfo.builder()
                        .subjectName(SubjectName.builder().commonName("Concurrent " + idx).build())
                        .build())));
            }

            Set<BigInteger> serials = new HashSet<>();
            for (Future<CertificateBundle> f : futures) {
                CertificateBundle bundle = f.get(30, TimeUnit.SECONDS);
                assertNotNull(bundle);
                assertTrue(bundle.issuedBy(issuer));
                assertTrue(serials.add(bundle.getCertificate().getSerialNumber()),
                        "duplicate serial under concurrent issuance");
            }
            assertEquals(total, serials.size());
        } finally {
            executor.shutdownNow();
        }
    }

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

}
