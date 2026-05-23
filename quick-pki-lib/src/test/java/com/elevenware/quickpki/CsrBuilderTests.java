package com.elevenware.quickpki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CsrBuilderTests {

    private static final ASN1ObjectIdentifier JURISDICTION_COUNTRY =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3");

    @BeforeAll
    static void setup() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void csrCreateProducesVerifiableCsrWithSubjectAndSans() throws Exception {
        KeyPair keys = generateRsaKeyPair();
        CertInfo info = CertInfo.builder()
                .subjectName(SubjectName.builder()
                        .commonName("example.com")
                        .organization("Example Co")
                        .country("GB")
                        .build())
                .dnsName("example.com")
                .dnsName("www.example.com")
                .ipAddress("10.0.0.1")
                .build();

        PKCS10CertificationRequest csr = Csr.create(info, keys);

        assertEquals(keys.getPublic(), Csr.publicKey(csr));
        assertDoesNotThrow(() -> Csr.verifySignature(csr));
        assertEquals(List.of("example.com", "www.example.com"), Csr.dnsSubjectAlternativeNames(csr));
        assertEquals(List.of("10.0.0.1"), Csr.ipSubjectAlternativeNames(csr));

        X500Name subject = csr.getSubject();
        assertEquals("example.com", subject.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString());
        assertEquals("Example Co", subject.getRDNs(BCStyle.O)[0].getFirst().getValue().toString());
        assertEquals("GB", subject.getRDNs(BCStyle.C)[0].getFirst().getValue().toString());
    }

    @Test
    void csrCreateRejectsCertInfoWithoutSubject() {
        KeyPair keys = assertDoesNotThrow(CsrBuilderTests::generateRsaKeyPair);
        CertInfo info = CertInfo.builder().dnsName("example.com").build();

        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> Csr.create(info, keys));
        assertTrue(ex.getMessage().toLowerCase().contains("subjectname"),
                "message should explain the missing SubjectName, got: " + ex.getMessage());
    }

    @Test
    void csrCreateSupportsEcKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        KeyPair keys = generator.generateKeyPair();

        PKCS10CertificationRequest csr = Csr.create(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("ec.example.com").build())
                .dnsName("ec.example.com")
                .build(), keys);

        assertDoesNotThrow(() -> Csr.verifySignature(csr));
    }

    @Test
    void toPemAndFromPemRoundTripsCsr() throws Exception {
        KeyPair keys = generateRsaKeyPair();
        PKCS10CertificationRequest csr = Csr.create(CertInfo.builder()
                .subjectName(SubjectName.builder().commonName("pem.example.com").build())
                .dnsName("pem.example.com")
                .build(), keys);

        String pem = Csr.toPem(csr);
        assertTrue(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"),
                "PEM should carry the CERTIFICATE REQUEST header, got: " + pem);
        assertTrue(pem.contains("-----END CERTIFICATE REQUEST-----"),
                "PEM should carry the CERTIFICATE REQUEST footer, got: " + pem);

        PKCS10CertificationRequest decoded = Csr.fromPem(pem);
        assertEquals(csr.getSubject(), decoded.getSubject());
        assertEquals(keys.getPublic(), Csr.publicKey(decoded));
        assertDoesNotThrow(() -> Csr.verifySignature(decoded));
    }

    @Test
    void fromPemRejectsNonCsrPemContent() {
        // A PEM-encoded private key isn't a CSR. The parser should refuse it
        // rather than returning a wrong-typed object up the call chain.
        String notACsr = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        QuickPkiException ex = assertThrows(QuickPkiException.class, () -> Csr.fromPem(notACsr));
        assertTrue(ex.getMessage().toLowerCase().contains("csr")
                || ex.getMessage().toLowerCase().contains("parse"),
                "message should explain the failure, got: " + ex.getMessage());
    }

    @Test
    void openFinanceBrcacBuilderProducesCsrInOpenFinanceRdnOrder() throws Exception {
        KeyPair keys = generateRsaKeyPair();

        PKCS10CertificationRequest csr = OpenFinanceBrasil.brcac()
                .commonName("transport.example.com")
                .businessCategory("Private Organization")
                .serialNumber("12345678000199")
                .organization("Example Participant Ltda")
                .stateOrProvince("SP")
                .locality("Sao Paulo")
                .organizationIdentifier("OFBBR-12345678")
                .userId("software-statement-uuid")
                .dnsName("transport.example.com")
                .buildCsr(keys);

        assertDoesNotThrow(() -> Csr.verifySignature(csr));

        RDN[] rdns = csr.getSubject().getRDNs();
        assertEquals(BCStyle.BUSINESS_CATEGORY, rdns[0].getFirst().getType());
        assertEquals(JURISDICTION_COUNTRY, rdns[1].getFirst().getType());
        assertEquals(BCStyle.SERIALNUMBER, rdns[2].getFirst().getType());
        assertEquals(BCStyle.C, rdns[3].getFirst().getType());
        assertEquals(BCStyle.O, rdns[4].getFirst().getType());
        assertEquals(BCStyle.ST, rdns[5].getFirst().getType());
        assertEquals(BCStyle.L, rdns[6].getFirst().getType());
        assertEquals(BCStyle.ORGANIZATION_IDENTIFIER, rdns[7].getFirst().getType());
        assertEquals(BCStyle.UID, rdns[8].getFirst().getType());
        assertEquals(BCStyle.CN, rdns[9].getFirst().getType());

        assertEquals(List.of("transport.example.com"), Csr.dnsSubjectAlternativeNames(csr));
    }

    @Test
    void openFinanceBrcacBuilderCsrCanBeIssuedAsBrcacCertificate() throws Exception {
        QuickPki pki = QuickPki.createDefault();
        KeyPair keys = generateRsaKeyPair();

        PKCS10CertificationRequest csr = OpenFinanceBrasil.brcac()
                .commonName("transport.example.com")
                .businessCategory("Private Organization")
                .serialNumber("12345678000199")
                .organization("Example Participant Ltda")
                .stateOrProvince("SP")
                .locality("Sao Paulo")
                .organizationIdentifier("OFBBR-12345678")
                .userId("software-statement-uuid")
                .dnsName("transport.example.com")
                .buildCsr(keys);

        CertificateBundle bundle = pki.issueCertificate(csr,
                CertInfo.fromCsr(csr).profile(CertificateProfile.BRCAC).build());

        X500Name subject = new JcaX509CertificateHolder(bundle.getCertificate()).getSubject();
        assertEquals("OFBBR-12345678",
                subject.getRDNs(BCStyle.ORGANIZATION_IDENTIFIER)[0].getFirst().getValue().toString());
        assertEquals("transport.example.com",
                subject.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString());
    }

    @Test
    void openFinanceBrsealBuilderProducesCsrInOpenFinanceRdnOrder() throws Exception {
        KeyPair keys = generateRsaKeyPair();

        PKCS10CertificationRequest csr = OpenFinanceBrasil.brseal()
                .userId("OFBBR-12345678")
                .organizationUnit("Example CA")
                .organizationUnit("12345678000199")
                .organizationUnit("Validacao por certificado digital")
                .commonName("Seal Co")
                .responsiblePersonName("Responsible Person")
                .companyCnpj("12345678000199")
                .responsiblePersonData("197001010000000000000")
                .companyCei("123456789012")
                .buildCsr(keys);

        assertDoesNotThrow(() -> Csr.verifySignature(csr));

        RDN[] rdns = csr.getSubject().getRDNs();
        assertEquals(BCStyle.UID, rdns[0].getFirst().getType());
        assertEquals(BCStyle.C, rdns[1].getFirst().getType());
        assertEquals(BCStyle.O, rdns[2].getFirst().getType());
        assertEquals(BCStyle.OU, rdns[3].getFirst().getType());
        assertEquals(BCStyle.OU, rdns[4].getFirst().getType());
        assertEquals(BCStyle.OU, rdns[5].getFirst().getType());
        assertEquals(BCStyle.CN, rdns[6].getFirst().getType());

        Extensions extensions = csr.getRequestedExtensions();
        GeneralNames sans = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        assertNotNull(sans, "BRSEAL CSR should carry an extensionRequest with otherName entries");
        Set<String> otherNameOids = new HashSet<>();
        for (GeneralName name : sans.getNames()) {
            if (name.getTagNo() == GeneralName.otherName) {
                org.bouncycastle.asn1.ASN1Sequence seq =
                        org.bouncycastle.asn1.ASN1Sequence.getInstance(name.getName().toASN1Primitive());
                otherNameOids.add(ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0)).getId());
            }
        }
        assertEquals(Set.of("2.16.76.1.3.2", "2.16.76.1.3.3", "2.16.76.1.3.4", "2.16.76.1.3.7"),
                otherNameOids);
    }

    @Test
    void openFinanceBrsealBuilderCsrCanBeIssuedAsBrsealCertificate() throws Exception {
        QuickPki pki = QuickPki.createDefault();
        KeyPair keys = generateRsaKeyPair();

        PKCS10CertificationRequest csr = OpenFinanceBrasil.brseal()
                .userId("OFBBR-12345678")
                .organizationUnit("Example CA")
                .organizationUnit("12345678000199")
                .organizationUnit("Validacao por certificado digital")
                .commonName("Seal Co")
                .responsiblePersonName("Responsible Person")
                .companyCnpj("12345678000199")
                .responsiblePersonData("197001010000000000000")
                .companyCei("123456789012")
                .buildCsr(keys);

        CertificateBundle bundle = pki.issueCertificate(csr,
                CertInfo.fromCsr(csr).profile(CertificateProfile.BRSEAL).build());

        X500Name subject = new JcaX509CertificateHolder(bundle.getCertificate()).getSubject();
        assertEquals("Seal Co", subject.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString());
        assertEquals("OFBBR-12345678", subject.getRDNs(BCStyle.UID)[0].getFirst().getValue().toString());
        // BRSEAL forbids ExtendedKeyUsage and requires nonRepudiation
        assertTrue(bundle.getCertificate().getKeyUsage()[1], "BRSEAL must assert nonRepudiation");
    }

    @Test
    void brcacCertInfoFactoryAttachesProfileAndSubject() {
        SubjectName subject = SubjectName.builder().commonName("x.example.com").build();
        CertInfo info = OpenFinanceBrasil.brcacCertInfo(subject)
                .dnsName("x.example.com")
                .build();
        assertEquals(CertificateProfile.BRCAC, info.getProfile());
        assertEquals(subject, info.getSubjectName());
        assertEquals(List.of("x.example.com"), info.getDnsNames());
    }

    @Test
    void brsealCertInfoFactoryAttachesProfileAndSubject() {
        SubjectName subject = SubjectName.builder().commonName("Seal Co").build();
        CertInfo info = OpenFinanceBrasil.brsealCertInfo(subject).build();
        assertEquals(CertificateProfile.BRSEAL, info.getProfile());
        assertEquals(subject, info.getSubjectName());
    }

    @Test
    void euQualifiedQwacBuilderProducesCsrInEtsiRdnOrder() throws Exception {
        KeyPair keys = generateRsaKeyPair();

        PKCS10CertificationRequest csr = EuQualified.qwac()
                .country("GB")
                .organization("Example PSP plc")
                .organizationIdentifier(EuQualified.psd2OrganizationIdentifier("GB", "FCA", "123456"))
                .commonName("psp.example.com")
                .dnsName("psp.example.com")
                .buildCsr(keys);

        assertDoesNotThrow(() -> Csr.verifySignature(csr));

        RDN[] rdns = csr.getSubject().getRDNs();
        assertEquals(BCStyle.C, rdns[0].getFirst().getType());
        assertEquals(BCStyle.O, rdns[1].getFirst().getType());
        assertEquals(BCStyle.ORGANIZATION_IDENTIFIER, rdns[2].getFirst().getType());
        assertEquals(BCStyle.CN, rdns[3].getFirst().getType());

        assertEquals(List.of("psp.example.com"), Csr.dnsSubjectAlternativeNames(csr));
        // The two mandatory ETSI qcStatements ride in the CSR's
        // extensionRequest so the issuer can carry them through.
        java.util.List<QcStatement> qcStatements = Csr.qcStatements(csr);
        assertEquals(2, qcStatements.size());
        assertEquals(EuQualified.OID_QC_COMPLIANCE, qcStatements.get(0).statementId().getId());
        assertEquals(EuQualified.OID_QC_TYPE, qcStatements.get(1).statementId().getId());
    }

    @Test
    void euQualifiedQwacBuilderCsrCanBeIssuedAsQwacCertificate() throws Exception {
        QuickPki pki = QuickPki.createDefault();
        KeyPair keys = generateRsaKeyPair();

        PKCS10CertificationRequest csr = EuQualified.qwac()
                .country("GB")
                .organization("Example PSP plc")
                .organizationIdentifier(EuQualified.psd2OrganizationIdentifier("GB", "FCA", "123456"))
                .commonName("psp.example.com")
                .dnsName("psp.example.com")
                .psd2(Set.of(EuQualified.Psd2Role.PSP_AS), "Financial Conduct Authority", "GB-FCA")
                .buildCsr(keys);

        CertificateBundle bundle = pki.issueCertificate(csr,
                CertInfo.fromCsr(csr).profile(CertificateProfile.QWAC).build());

        X500Name subject = new JcaX509CertificateHolder(bundle.getCertificate()).getSubject();
        assertEquals("PSDGB-FCA-123456",
                subject.getRDNs(BCStyle.ORGANIZATION_IDENTIFIER)[0].getFirst().getValue().toString());
        assertEquals("psp.example.com",
                subject.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString());
        // QC statements (including the PSD2 one) survived the CSR round trip.
        assertNotNull(bundle.getCertificate()
                .getExtensionValue(EuQualified.OID_QC_STATEMENTS_EXTENSION));
    }

    @Test
    void euQualifiedQsealBuilderCsrCanBeIssuedAsQsealCertificate() throws Exception {
        QuickPki pki = QuickPki.createDefault();
        KeyPair keys = generateRsaKeyPair();

        PKCS10CertificationRequest csr = EuQualified.qseal()
                .country("GB")
                .organization("Example PSP plc")
                .organizationIdentifier(EuQualified.psd2OrganizationIdentifier("GB", "FCA", "123456"))
                .commonName("PSP Seal")
                .onQscd()
                .buildCsr(keys);

        CertificateBundle bundle = pki.issueCertificate(csr,
                CertInfo.fromCsr(csr).profile(CertificateProfile.QSEAL).build());

        // QSEAL forbids ExtendedKeyUsage and requires nonRepudiation.
        assertTrue(bundle.getCertificate().getKeyUsage()[1], "QSEAL must assert nonRepudiation");
        assertNotNull(bundle.getCertificate()
                .getExtensionValue(EuQualified.OID_QC_STATEMENTS_EXTENSION));
    }

    @Test
    void qwacCertInfoFactoryAttachesProfileSubjectAndDefaultQcStatements() {
        SubjectName subject = SubjectName.builder()
                .country("GB").organization("Example PSP plc")
                .organizationIdentifier("PSDGB-FCA-123456")
                .commonName("psp.example.com").build();

        CertInfo info = EuQualified.qwacCertInfo(subject).dnsName("psp.example.com").build();

        assertEquals(CertificateProfile.QWAC, info.getProfile());
        assertEquals(subject, info.getSubjectName());
        assertEquals(2, info.getQcStatements().size());
    }

    @Test
    void qsealCertInfoFactoryAttachesProfileSubjectAndDefaultQcStatements() {
        SubjectName subject = SubjectName.builder()
                .country("GB").organization("Example PSP plc")
                .organizationIdentifier("PSDGB-FCA-123456")
                .commonName("PSP Seal").build();

        CertInfo info = EuQualified.qsealCertInfo(subject).build();

        assertEquals(CertificateProfile.QSEAL, info.getProfile());
        assertEquals(2, info.getQcStatements().size());
    }

    @Test
    void sesameOsTransportBuilderCsrCanBeIssuedAsTransportCertificate() throws Exception {
        QuickPki pki = QuickPki.createDefault();
        KeyPair keys = generateRsaKeyPair();

        PKCS10CertificationRequest csr = Sesame.osTransport()
                .country("GB")
                .organization("Example Organisation Ltd")
                .organizationUnit("Example Software Product")
                .commonName("transport.example.org")
                .dnsName("transport.example.org")
                .uri("urn:odtf:finance:gb:fca:participant:123456")
                .uri("urn:odtf:finance:gb:fca:software:9f1c2a3b4c5d")
                .buildCsr(keys);

        assertDoesNotThrow(() -> Csr.verifySignature(csr));
        assertEquals(List.of("transport.example.org"), Csr.dnsSubjectAlternativeNames(csr));
        assertEquals(List.of("urn:odtf:finance:gb:fca:participant:123456",
                        "urn:odtf:finance:gb:fca:software:9f1c2a3b4c5d"),
                Csr.uriSubjectAlternativeNames(csr));
        assertEquals(List.of(Sesame.OID_OS_TRANSPORT_POLICY), Csr.certificatePolicies(csr));

        CertificateBundle bundle = pki.issueCertificate(csr,
                CertInfo.fromCsr(csr).profile(CertificateProfile.OS_TRANSPORT).build());
        List<String> eku = bundle.getCertificate().getExtendedKeyUsage();
        assertNotNull(eku);
        assertTrue(eku.contains("1.3.6.1.5.5.7.3.2"), "OS_TRANSPORT EKU must include clientAuth");
    }

    @Test
    void sesameOsSigningBuilderCsrCanBeIssuedAsSigningCertificate() throws Exception {
        QuickPki pki = QuickPki.createDefault();
        KeyPair keys = generateRsaKeyPair();
        String ekuOid = "1.3.6.1.4.1.55555.2.1";

        PKCS10CertificationRequest csr = Sesame.osSigning()
                .country("GB")
                .organization("Example Organisation Ltd")
                .organizationUnit("Example Software Product")
                .commonName("signing.example.org")
                .uri("urn:odtf:finance:gb:fca:participant:123456")
                .uri("urn:odtf:finance:gb:fca:software:9f1c2a3b4c5d")
                .extendedKeyUsageOid(ekuOid)
                .buildCsr(keys);

        assertDoesNotThrow(() -> Csr.verifySignature(csr));
        assertEquals(List.of("urn:odtf:finance:gb:fca:participant:123456",
                        "urn:odtf:finance:gb:fca:software:9f1c2a3b4c5d"),
                Csr.uriSubjectAlternativeNames(csr));
        assertEquals(List.of(Sesame.OID_OS_SIGNING_POLICY), Csr.certificatePolicies(csr));

        CertInfo info = CertInfo.fromCsr(csr)
                .profile(CertificateProfile.OS_SIGNING)
                .extendedKeyUsageOid(ekuOid)
                .build();
        CertificateBundle bundle = pki.issueCertificate(csr, info);
        assertEquals(List.of(ekuOid), bundle.getCertificate().getExtendedKeyUsage(),
                "OS_SIGNING EKU must carry the ecosystem-specific OID");
    }

    @Test
    void sesameOsTransportCertInfoFactoryAttachesProfileSubjectAndPolicy() {
        SubjectName subject = SubjectName.builder()
                .country("GB").organization("Example Organisation Ltd")
                .commonName("transport.example.org").build();

        CertInfo info = Sesame.osTransportCertInfo(subject)
                .dnsName("transport.example.org")
                .uri("urn:odtf:finance:gb:fca:participant:123456")
                .build();

        assertEquals(CertificateProfile.OS_TRANSPORT, info.getProfile());
        assertEquals(subject, info.getSubjectName());
        assertEquals(List.of(Sesame.OID_OS_TRANSPORT_POLICY), info.getCertificatePolicies());
    }

    @Test
    void sesameOsSigningCertInfoFactoryAttachesProfileSubjectAndPolicy() {
        SubjectName subject = SubjectName.builder()
                .country("GB").organization("Example Organisation Ltd")
                .commonName("signing.example.org").build();

        CertInfo info = Sesame.osSigningCertInfo(subject).build();

        assertEquals(CertificateProfile.OS_SIGNING, info.getProfile());
        assertEquals(List.of(Sesame.OID_OS_SIGNING_POLICY), info.getCertificatePolicies());
    }

    @Test
    void brcacBuilderCsrPemEncodesAsCertificateRequest() throws Exception {
        KeyPair keys = generateRsaKeyPair();
        String pem = OpenFinanceBrasil.brcac()
                .commonName("transport.example.com")
                .businessCategory("Private Organization")
                .serialNumber("12345678000199")
                .organization("Example Participant Ltda")
                .stateOrProvince("SP")
                .locality("Sao Paulo")
                .organizationIdentifier("OFBBR-12345678")
                .userId("software-statement-uuid")
                .dnsName("transport.example.com")
                .buildCsrPem(keys);

        assertTrue(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        assertDoesNotThrow(() -> Csr.verifySignature(Csr.fromPem(pem)));
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
