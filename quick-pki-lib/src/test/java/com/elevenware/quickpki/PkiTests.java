package com.elevenware.quickpki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
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
        Provider originalBc = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        int originalPosition = -1;
        if (originalBc != null) {
            Provider[] providers = Security.getProviders();
            for (int i = 0; i < providers.length; i++) {
                if (providers[i] == originalBc) {
                    // Security.insertProviderAt is 1-based.
                    originalPosition = i + 1;
                    break;
                }
            }
        }
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        try {
            assertNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME),
                    "precondition: BC must be unregistered for this test");

            QuickPki pki = QuickPki.createDefault();

            assertNotNull(pki.getIssuer());
            assertNotNull(Security.getProvider(BouncyCastleProvider.PROVIDER_NAME),
                    "createDefault should have registered BC");
        } finally {
            // Restore the exact original instance at its original index so
            // provider-ordering-sensitive algorithm selection is unchanged
            // for any test that runs after this one.
            if (originalBc != null) {
                Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
                Security.insertProviderAt(originalBc, originalPosition);
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

    // RFC 5280 §4.2.1.3: a CA MUST have keyCertSign asserted; cRLSign is
    // standard for the same. KeyUsage bit positions: digitalSignature=0,
    // nonRepudiation=1, keyEncipherment=2, dataEncipherment=3,
    // keyAgreement=4, keyCertSign=5, cRLSign=6.
    @Test
    void rootCertificateHasCaKeyUsage() {
        QuickPki pki = QuickPki.createDefault();

        boolean[] keyUsage = pki.getIssuer().getCertificate().getKeyUsage();
        assertNotNull(keyUsage, "root must have a KeyUsage extension");
        assertTrue(keyUsage[5], "root must assert keyCertSign");
        assertTrue(keyUsage[6], "root must assert cRLSign");
        assertFalse(keyUsage[0], "root should not assert digitalSignature");
    }

    @Test
    void leafCertificateHasEndEntityKeyUsage() {
        QuickPki pki = QuickPki.createDefault();

        boolean[] keyUsage = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Leaf").build())
                .build())
                .getCertificate().getKeyUsage();

        assertNotNull(keyUsage, "leaf must have a KeyUsage extension");
        assertTrue(keyUsage[0], "leaf must assert digitalSignature");
        assertTrue(keyUsage[2], "leaf must assert keyEncipherment");
        assertFalse(keyUsage[5], "leaf must NOT assert keyCertSign");
    }

    @Test
    void leafCertificateHasServerAndClientExtendedKeyUsage() throws Exception {
        QuickPki pki = QuickPki.createDefault();

        List<String> eku = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Leaf").build())
                .build())
                .getCertificate().getExtendedKeyUsage();

        assertNotNull(eku, "leaf must have an ExtendedKeyUsage extension");
        assertTrue(eku.contains(KeyPurposeId.id_kp_serverAuth.getId()),
                "leaf must include serverAuth EKU");
        assertTrue(eku.contains(KeyPurposeId.id_kp_clientAuth.getId()),
                "leaf must include clientAuth EKU");
    }

    // Path-building tools (PKIX, openssl, browsers) match the leaf's
    // AuthorityKeyIdentifier against the issuer's SubjectKeyIdentifier.
    @Test
    void leafAuthorityKeyIdentifierMatchesIssuerSubjectKeyIdentifier() throws Exception {
        QuickPki pki = QuickPki.createDefault();
        X509Certificate root = pki.getIssuer().getCertificate();
        X509Certificate leaf = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Leaf").build())
                .build())
                .getCertificate();

        X509CertificateHolder rootHolder = new X509CertificateHolder(root.getEncoded());
        X509CertificateHolder leafHolder = new X509CertificateHolder(leaf.getEncoded());
        SubjectKeyIdentifier ski = SubjectKeyIdentifier.fromExtensions(rootHolder.getExtensions());
        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.fromExtensions(leafHolder.getExtensions());

        assertNotNull(ski, "root must have a SubjectKeyIdentifier");
        assertNotNull(aki, "leaf must have an AuthorityKeyIdentifier");
        assertArrayEquals(ski.getKeyIdentifier(), aki.getKeyIdentifier(),
                "leaf's AKI must match root's SKI for path building");
    }

    // Modern TLS verifiers (browsers, OkHttp, JDK >=11) ignore CN entirely
    // and require the hostname to match a SubjectAlternativeName entry.
    @Test
    void leafIncludesDnsNamesInSubjectAlternativeName() throws Exception {
        QuickPki pki = QuickPki.createDefault();

        X509Certificate leaf = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Leaf").build())
                .dnsName("example.com")
                .dnsName("www.example.com")
                .build())
                .getCertificate();

        Set<String> dnsNames = new HashSet<>();
        Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
        assertNotNull(sans, "leaf with dnsName entries must have a SAN extension");
        for (List<?> entry : sans) {
            if (((Integer) entry.get(0)) == GeneralName.dNSName) {
                dnsNames.add((String) entry.get(1));
            }
        }
        assertTrue(dnsNames.contains("example.com"));
        assertTrue(dnsNames.contains("www.example.com"));
    }

    @Test
    void leafIncludesIpAddressesInSubjectAlternativeName() throws Exception {
        QuickPki pki = QuickPki.createDefault();

        X509Certificate leaf = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Leaf").build())
                .ipAddress("127.0.0.1")
                .build())
                .getCertificate();

        Collection<List<?>> sans = leaf.getSubjectAlternativeNames();
        assertNotNull(sans, "leaf with ipAddress entries must have a SAN extension");
        boolean foundIp = false;
        for (List<?> entry : sans) {
            if (((Integer) entry.get(0)) == GeneralName.iPAddress
                    && "127.0.0.1".equals(entry.get(1))) {
                foundIp = true;
            }
        }
        assertTrue(foundIp, "expected SAN entry for IP 127.0.0.1");
    }

    @Test
    void leafWithoutSanFieldsHasNoSanExtension() throws Exception {
        QuickPki pki = QuickPki.createDefault();

        X509Certificate leaf = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Leaf").build())
                .build())
                .getCertificate();

        assertNull(leaf.getSubjectAlternativeNames(),
                "no dnsName/ipAddress provided should mean no SAN extension");
    }

    // Verifies bug #9: failures inside issueCertificate must be wrapped in
    // QuickPkiException with both a meaningful message and the original cause
    // preserved, instead of an opaque RuntimeException.
    @Test
    void issueCertificateWrapsUnderlyingFailuresInQuickPkiException() {
        QuickPki pki = QuickPki.createDefault();

        QuickPkiException ex = assertThrows(QuickPkiException.class, () ->
                pki.issueCertificate(CertInfo.builder()
                        .subjectName(SubjectName.builder().commonName(null).build())
                        .build()));

        assertNotNull(ex.getMessage(), "wrapped exception must carry a message");
        assertNotNull(ex.getCause(), "wrapped exception must preserve the underlying cause");
    }

    @Test
    void dnsNameRejectsNullWithClearMessage() {
        NullPointerException ex = assertThrows(NullPointerException.class,
                () -> CertInfo.builder().dnsName(null));
        assertTrue(ex.getMessage() != null && ex.getMessage().contains("dnsName"),
                "NPE message must name the rejected parameter, got: " + ex.getMessage());
    }

    @Test
    void ipAddressRejectsNullWithClearMessage() {
        NullPointerException ex = assertThrows(NullPointerException.class,
                () -> CertInfo.builder().ipAddress(null));
        assertTrue(ex.getMessage() != null && ex.getMessage().contains("ipAddress"),
                "NPE message must name the rejected parameter, got: " + ex.getMessage());
    }

    @Test
    void defaultPkiUsesRsa2048AndSha256() {
        QuickPki pki = QuickPki.createDefault();

        X509Certificate root = pki.getIssuer().getCertificate();
        assertEquals("RSA", root.getPublicKey().getAlgorithm());
        java.security.interfaces.RSAPublicKey rsaKey =
                (java.security.interfaces.RSAPublicKey) root.getPublicKey();
        assertEquals(2048, rsaKey.getModulus().bitLength(),
                "default key size must be 2048");
        assertTrue("SHA256withRSA".equalsIgnoreCase(root.getSigAlgName()),
                "expected SHA256withRSA, got " + root.getSigAlgName());
    }

    @Test
    void canOverrideRsaKeySize() {
        QuickPki pki = QuickPki.create(IssuerInfo.builder()
                .keyAlgorithm(KeyAlgorithm.rsa(3072))
                .build());

        X509Certificate root = pki.getIssuer().getCertificate();
        java.security.interfaces.RSAPublicKey rsaKey =
                (java.security.interfaces.RSAPublicKey) root.getPublicKey();
        assertEquals(3072, rsaKey.getModulus().bitLength());

        CertificateBundle leaf = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Leaf").build())
                .build());
        assertTrue(leaf.issuedBy(pki.getIssuer()));
        assertEquals(3072, ((java.security.interfaces.RSAPublicKey)
                leaf.getCertificate().getPublicKey()).getModulus().bitLength());
    }

    @Test
    void canIssueWithEcKeysAndDefaultEcdsaSignature() {
        QuickPki pki = QuickPki.create(IssuerInfo.builder()
                .keyAlgorithm(KeyAlgorithm.ec("secp256r1"))
                .build());

        X509Certificate root = pki.getIssuer().getCertificate();
        assertEquals("EC", root.getPublicKey().getAlgorithm());
        assertEquals("SHA256WITHECDSA", root.getSigAlgName().toUpperCase());

        CertificateBundle leaf = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("EC Leaf").build())
                .build());
        assertEquals("EC", leaf.getCertificate().getPublicKey().getAlgorithm());
        assertTrue(leaf.issuedBy(pki.getIssuer()),
                "EC-issued leaf must verify against its EC issuer");
    }

    @Test
    void canOverrideSignatureAlgorithmIndependently() {
        QuickPki pki = QuickPki.create(IssuerInfo.builder()
                .keyAlgorithm(KeyAlgorithm.rsa(2048))
                .signatureAlgorithm("SHA384withRSA")
                .build());

        String rootSigAlg = pki.getIssuer().getCertificate().getSigAlgName();
        assertTrue("SHA384withRSA".equalsIgnoreCase(rootSigAlg),
                "expected SHA384withRSA, got " + rootSigAlg);

        CertificateBundle leaf = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Leaf").build())
                .build());
        String leafSigAlg = leaf.getCertificate().getSigAlgName();
        assertTrue("SHA384withRSA".equalsIgnoreCase(leafSigAlg),
                "expected SHA384withRSA, got " + leafSigAlg);
    }

    @Test
    void rsaKeyAlgorithmRejectsTooSmallKeySize() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> KeyAlgorithm.rsa(1024));
        assertTrue(ex.getMessage().contains("2048"),
                "rejection should mention the minimum, got: " + ex.getMessage());
    }

    // keyEncipherment is RSA key-transport; for EC keys it's meaningless and
    // some validators reject it. EC leaves should get keyAgreement instead.
    @Test
    void ecLeafHasKeyAgreementNotKeyEncipherment() {
        QuickPki pki = QuickPki.create(IssuerInfo.builder()
                .keyAlgorithm(KeyAlgorithm.ec("secp256r1"))
                .build());

        boolean[] keyUsage = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("EC Leaf").build())
                .build())
                .getCertificate().getKeyUsage();

        assertNotNull(keyUsage);
        assertTrue(keyUsage[0], "EC leaf must assert digitalSignature");
        assertTrue(keyUsage[4], "EC leaf must assert keyAgreement");
        assertFalse(keyUsage[2], "EC leaf must NOT assert keyEncipherment");
    }

    @Test
    void rsaLeafKeepsKeyEncipherment() {
        QuickPki pki = QuickPki.createDefault();

        boolean[] keyUsage = pki.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("RSA Leaf").build())
                .build())
                .getCertificate().getKeyUsage();

        assertTrue(keyUsage[0], "RSA leaf must assert digitalSignature");
        assertTrue(keyUsage[2], "RSA leaf must assert keyEncipherment");
        assertFalse(keyUsage[4], "RSA leaf must NOT assert keyAgreement");
    }

    @Test
    void blankSignatureAlgorithmIsRejected() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> IssuerInfo.builder().signatureAlgorithm(""));
        assertTrue(ex.getMessage().contains("signatureAlgorithm"),
                "rejection should name the parameter, got: " + ex.getMessage());
    }

    @Test
    void blankEcCurveIsRejected() {
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> KeyAlgorithm.ec("   "));
        assertTrue(ex.getMessage().contains("curve"),
                "rejection should name the parameter, got: " + ex.getMessage());
    }

    @Test
    void issuedIntermediateIsACaWithKeyCertSign() {
        QuickPki root = QuickPki.createDefault();
        QuickPki intermediate = root.issueIntermediate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Intermediate CA").build())
                .build());

        X509Certificate intCert = intermediate.getIssuer().getCertificate();
        assertNotEquals(-1, intCert.getBasicConstraints(),
                "intermediate must be a CA");
        boolean[] keyUsage = intCert.getKeyUsage();
        assertNotNull(keyUsage);
        assertTrue(keyUsage[5], "intermediate must assert keyCertSign");
        assertTrue(keyUsage[6], "intermediate must assert cRLSign");
        assertTrue(intermediate.getIssuer().issuedBy(root.getIssuer()),
                "intermediate must be signed by root");
    }

    @Test
    void leafIssuedByIntermediateIsNotIssuedByRootDirectly() {
        QuickPki root = QuickPki.createDefault();
        QuickPki intermediate = root.issueIntermediate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Issuing CA").build())
                .build());

        CertificateBundle leaf = intermediate.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("End entity").build())
                .build());

        assertTrue(leaf.issuedBy(intermediate.getIssuer()),
                "leaf must verify against the intermediate that signed it");
        assertFalse(leaf.issuedBy(root.getIssuer()),
                "leaf must NOT verify against the root directly");
    }

    // The decisive test: build root -> intermediate -> leaf, then ask the JDK's
    // standard PKIX validator (the same code that browsers and JDK TLS use)
    // to walk the chain. If this passes, the certs are wired up correctly:
    // AKI/SKI links, BasicConstraints, KeyUsage on each level, and signatures.
    @Test
    void fullRootIntermediateLeafChainValidatesUnderPkix() throws Exception {
        QuickPki root = QuickPki.createDefault();
        QuickPki intermediate = root.issueIntermediate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Issuing CA").build())
                .build());
        CertificateBundle leaf = intermediate.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("End entity").build())
                .dnsName("example.com")
                .build());

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        java.security.cert.CertPath path = cf.generateCertPath(List.of(
                leaf.getCertificate(),
                intermediate.getIssuer().getCertificate()));

        java.security.cert.TrustAnchor anchor =
                new java.security.cert.TrustAnchor(root.getIssuer().getCertificate(), null);
        java.security.cert.PKIXParameters params =
                new java.security.cert.PKIXParameters(Set.of(anchor));
        params.setRevocationEnabled(false);

        java.security.cert.CertPathValidator validator =
                java.security.cert.CertPathValidator.getInstance("PKIX");

        // Throws CertPathValidatorException on failure; the assertion is the
        // absence of a thrown exception.
        validator.validate(path, params);
    }

    @Test
    void chainsOfArbitraryDepthValidate() throws Exception {
        QuickPki root = QuickPki.createDefault();
        QuickPki int1 = root.issueIntermediate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Intermediate 1").build())
                .build());
        QuickPki int2 = int1.issueIntermediate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Intermediate 2").build())
                .build());
        CertificateBundle leaf = int2.issueCertificate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("End entity").build())
                .build());

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        java.security.cert.CertPath path = cf.generateCertPath(List.of(
                leaf.getCertificate(),
                int2.getIssuer().getCertificate(),
                int1.getIssuer().getCertificate()));

        java.security.cert.PKIXParameters params = new java.security.cert.PKIXParameters(
                Set.of(new java.security.cert.TrustAnchor(root.getIssuer().getCertificate(), null)));
        params.setRevocationEnabled(false);

        java.security.cert.CertPathValidator.getInstance("PKIX").validate(path, params);
    }

    @Test
    void rootIsRootIntermediateIsNot() {
        QuickPki root = QuickPki.createDefault();
        QuickPki intermediate = root.issueIntermediate(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("Intermediate").build())
                .build());

        assertTrue(root.isRoot());
        assertNull(root.getParent());
        assertFalse(intermediate.isRoot());
        assertSame(root, intermediate.getParent());
    }

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

}
