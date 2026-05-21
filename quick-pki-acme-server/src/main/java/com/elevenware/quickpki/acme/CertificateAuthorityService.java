package com.elevenware.quickpki.acme;

import com.elevenware.quickpki.CertInfo;
import com.elevenware.quickpki.CertificateBundle;
import com.elevenware.quickpki.Csr;
import com.elevenware.quickpki.ExtendedKeyUsageId;
import com.elevenware.quickpki.IssuerInfo;
import com.elevenware.quickpki.QuickPki;
import com.elevenware.quickpki.SubjectName;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class CertificateAuthorityService {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateAuthorityService.class);

    private final QuickPki pki;
    private final CertificateBundle issuer;
    private final AcmeConfig config;

    private CertificateAuthorityService(QuickPki pki, AcmeConfig config) {
        this.pki = pki;
        this.issuer = pki.getIssuer();
        this.config = config;
    }

    static CertificateAuthorityService loadOrCreate(AcmeConfig config, AcmeRepository repository) {
        Security.addProvider(new BouncyCastleProvider());
        IssuerInfo issuerInfo = issuerInfo(config);
        KeyEncryptor encryptor = new KeyEncryptor(config.caKeyPassword());
        return repository.loadCaMaterial()
                .map(material -> load(config, issuerInfo, encryptor, material))
                .orElseGet(() -> create(config, issuerInfo, encryptor, repository));
    }

    static CertificateAuthorityService rotate(AcmeConfig config, AcmeRepository repository) {
        Security.addProvider(new BouncyCastleProvider());
        LOG.warn("Rotating Quick-PKI ACME root CA material");
        return create(config, issuerInfo(config), new KeyEncryptor(config.caKeyPassword()), repository);
    }

    CertificateBundle issuer() {
        return issuer;
    }

    IssuedCertificate issue(byte[] csrDer, List<Identifier> validatedIdentifiers) {
        try {
            PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrDer);

            // Filter per-type: a validated "dns:example.com" identifier
            // authorises a dNSName SAN, not an iPAddress SAN of the same
            // string. Carrying the tag through avoids issuing a cert whose
            // SAN type disagrees with what was actually validated.
            Set<String> allowedDns = identifierValuesOfType(validatedIdentifiers, "dns");
            Set<String> allowedIp = identifierValuesOfType(validatedIdentifiers, "ip");

            List<String> csrDnsNames = Csr.dnsSubjectAlternativeNames(csr);
            List<String> csrIpNames = Csr.ipSubjectAlternativeNames(csr);

            if (!csrDnsNames.stream().allMatch(allowedDns::contains)
                    || !csrIpNames.stream().allMatch(allowedIp::contains)) {
                throw new AcmeException(400, "badCSR",
                        "CSR contains subjectAltName entries that were not validated");
            }

            List<String> dnsNames = csrDnsNames.stream().distinct().toList();
            List<String> ipNames = csrIpNames.stream().distinct().toList();
            if (dnsNames.isEmpty() && ipNames.isEmpty()) {
                throw new AcmeException(400, "badCSR",
                        "CSR must contain at least one validated subjectAltName");
            }

            // CN is just a label - take the first SAN in CSR source order so
            // it stays stable across re-issuance.
            String commonName = Csr.subjectAlternativeNames(csr).get(0);

            Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
            CertInfo.Builder cert = CertInfo.builder()
                    .subjectName(SubjectName.builder().commonName(commonName).build())
                    .validFrom(now.minus(5, ChronoUnit.MINUTES))
                    .validUntil(now.plus(config.certificateLifetime()))
                    .extendedKeyUsage(ExtendedKeyUsageId.SERVER_AUTH);
            for (String dns : dnsNames) {
                cert.dnsName(dns);
            }
            for (String ip : ipNames) {
                cert.ipAddress(ip);
            }
            CertificateBundle bundle = pki.issueCertificate(csr, cert.build());
            return new IssuedCertificate(bundle.toCertificatePem(), bundle.toCertificateChainPem());
        } catch (AcmeException e) {
            throw e;
        } catch (Exception e) {
            throw new AcmeException(400, "badCSR", "Failed to issue certificate from CSR: " + e.getMessage());
        }
    }

    private static Set<String> identifierValuesOfType(List<Identifier> identifiers, String type) {
        return identifiers.stream()
                .filter(id -> type.equalsIgnoreCase(id.type()))
                .map(Identifier::value)
                .collect(java.util.stream.Collectors.toCollection(HashSet::new));
    }

    private static CertificateAuthorityService load(
            AcmeConfig config,
            IssuerInfo issuerInfo,
            KeyEncryptor encryptor,
            CaMaterial material) {
        try {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(material.certificatePem().getBytes()));
            byte[] privateKeyDer = encryptor.decrypt(new EncryptedBytes(
                    material.privateKeyCiphertext(),
                    material.privateKeySalt(),
                    material.privateKeyIv()));
            PrivateKey privateKey = KeyFactory.getInstance(certificate.getPublicKey().getAlgorithm())
                    .generatePrivate(new PKCS8EncodedKeySpec(privateKeyDer));
            CertificateBundle issuer = new CertificateBundle(null, certificate, new KeyPair(certificate.getPublicKey(), privateKey));
            LOG.info("Loaded persisted Quick-PKI ACME CA subject={} notAfter={}",
                    certificate.getSubjectX500Principal().getName(), certificate.getNotAfter().toInstant());
            return new CertificateAuthorityService(QuickPki.fromIssuer(issuerInfo, issuer), config);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load persisted CA material", e);
        }
    }

    private static CertificateAuthorityService create(
            AcmeConfig config,
            IssuerInfo issuerInfo,
            KeyEncryptor encryptor,
            AcmeRepository repository) {
        QuickPki pki = QuickPki.create(issuerInfo);
        CertificateBundle issuer = pki.getIssuer();
        EncryptedBytes encrypted = encryptor.encrypt(issuer.getKeyPair().getPrivate().getEncoded());
        try {
            repository.saveCaMaterial(new CaMaterial(
                    "{\"defaultLifespanDays\":" + config.certificateLifetime().toDays() + "}",
                    issuer.toCertificatePem(),
                    encrypted.ciphertext(),
                    encrypted.salt(),
                    encrypted.iv()));
            LOG.info("Created and persisted Quick-PKI ACME CA subject={} notAfter={}",
                    issuer.getCertificate().getSubjectX500Principal().getName(),
                    issuer.getCertificate().getNotAfter().toInstant());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to persist new CA material", e);
        }
        return new CertificateAuthorityService(pki, config);
    }

    private static IssuerInfo issuerInfo(AcmeConfig config) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return IssuerInfo.builder()
                .subjectName(SubjectName.builder().commonName("Quick-PKI ACME Root").build())
                .validFrom(now.minus(1, ChronoUnit.HOURS))
                .validUntil(now.plus(3650, ChronoUnit.DAYS))
                .defaultLifespan(config.certificateLifetime())
                .build();
    }

    String issuerPem() {
        return issuer.toCertificatePem();
    }

    String issuerName() {
        try {
            return new JcaX509CertificateHolder(issuer.getCertificate()).getSubject().toString();
        } catch (Exception e) {
            return "Quick-PKI ACME Root";
        }
    }

    private static String pem(Object value) {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(value);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode PEM", e);
        }
        return sw.toString();
    }

    record IssuedCertificate(String certificatePem, String chainPem) {
    }
}
