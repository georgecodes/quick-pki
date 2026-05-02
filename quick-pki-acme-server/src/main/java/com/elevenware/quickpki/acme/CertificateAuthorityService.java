package com.elevenware.quickpki.acme;

import com.elevenware.quickpki.CertInfo;
import com.elevenware.quickpki.CertificateBundle;
import com.elevenware.quickpki.ExtendedKeyUsageId;
import com.elevenware.quickpki.IssuerInfo;
import com.elevenware.quickpki.QuickPki;
import com.elevenware.quickpki.SubjectName;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
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
            if (!csr.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(csr.getSubjectPublicKeyInfo()))) {
                throw new AcmeException(400, "badCSR", "CSR signature is invalid");
            }

            JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            List<String> csrNames = csrSubjectAlternativeNames(csr);
            Set<String> allowed = new HashSet<>(validatedIdentifiers.stream().map(Identifier::value).toList());
            List<String> names = csrNames.stream()
                    .filter(allowed::contains)
                    .distinct()
                    .toList();
            if (names.isEmpty()) {
                throw new AcmeException(400, "badCSR", "CSR must contain at least one validated subjectAltName");
            }
            if (names.size() != csrNames.stream().distinct().count()) {
                throw new AcmeException(400, "badCSR", "CSR contains subjectAltName entries that were not validated");
            }

            Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
            CertInfo.Builder cert = CertInfo.builder()
                    .subjectName(SubjectName.builder().commonName(names.get(0)).build())
                    .validFrom(now.minus(5, ChronoUnit.MINUTES))
                    .validUntil(now.plus(config.certificateLifetime()))
                    .extendedKeyUsage(ExtendedKeyUsageId.SERVER_AUTH);
            for (String name : names) {
                if (isIpAddress(name)) {
                    cert.ipAddress(name);
                } else {
                    cert.dnsName(name);
                }
            }
            CertificateBundle bundle = pki.issueCertificate(cert.build(), jcaCsr.getPublicKey());
            return new IssuedCertificate(bundle.toCertificatePem(), bundle.toCertificateChainPem());
        } catch (AcmeException e) {
            throw e;
        } catch (Exception e) {
            throw new AcmeException(400, "badCSR", "Failed to issue certificate from CSR: " + e.getMessage());
        }
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

    private static List<String> csrSubjectAlternativeNames(PKCS10CertificationRequest csr) throws Exception {
        Extensions extensions = csr.getRequestedExtensions();
        if (extensions == null) {
            return List.of();
        }
        GeneralNames generalNames = GeneralNames.fromExtensions(extensions, Extension.subjectAlternativeName);
        if (generalNames == null) {
            return List.of();
        }
        return List.of(generalNames.getNames()).stream()
                .filter(name -> name.getTagNo() == GeneralName.dNSName || name.getTagNo() == GeneralName.iPAddress)
                .map(CertificateAuthorityService::generalNameToString)
                .toList();
    }

    private static String generalNameToString(GeneralName name) {
        if (name.getTagNo() == GeneralName.dNSName) {
            return name.getName().toString();
        }
        try {
            byte[] octets = ASN1OctetString.getInstance(name.getName()).getOctets();
            return InetAddress.getByAddress(octets).getHostAddress();
        } catch (Exception e) {
            throw new AcmeException(400, "badCSR", "CSR contains an invalid IP subjectAltName");
        }
    }

    private static boolean isIpAddress(String value) {
        try {
            InetAddress.getByName(value);
            return value.indexOf(':') >= 0 || value.chars().allMatch(c -> Character.isDigit(c) || c == '.');
        } catch (Exception e) {
            return false;
        }
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
