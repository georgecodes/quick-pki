package com.elevenware.quickpki.certapi;

import com.elevenware.quickpki.CertInfo;
import com.elevenware.quickpki.CertificateBundle;
import com.elevenware.quickpki.CertificateProfile;
import com.elevenware.quickpki.Csr;
import com.elevenware.quickpki.IssuerInfo;
import com.elevenware.quickpki.QuickPki;
import com.elevenware.quickpki.QuickPkiException;
import com.elevenware.quickpki.SubjectName;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * Wraps the Quick-PKI library as the API's issuing CA. The CA key pair is
 * generated once and persisted (encrypted) so the issuer identity survives
 * restarts; every request then signs a leaf certificate against it.
 */
final class CertificateAuthorityService {

    private static final Logger LOG = LoggerFactory.getLogger(CertificateAuthorityService.class);

    private final QuickPki pki;
    private final CertificateBundle issuer;

    private CertificateAuthorityService(QuickPki pki) {
        this.pki = pki;
        this.issuer = pki.getIssuer();
    }

    static CertificateAuthorityService loadOrCreate(CertApiConfig config, CertApiRepository repository) {
        Security.addProvider(new BouncyCastleProvider());
        IssuerInfo issuerInfo = issuerInfo(config);
        KeyEncryptor encryptor = new KeyEncryptor(config.caKeyPassword());
        return repository.loadCaMaterial()
                .map(material -> load(issuerInfo, encryptor, material))
                .orElseGet(() -> create(config, issuerInfo, encryptor, repository));
    }

    /**
     * Signs a leaf certificate from {@code csr} under {@code profile}. The
     * CSR's self-signature is verified before anything is signed; subject DN
     * and subjectAltName entries are copied from the CSR, and validity defaults
     * to the configured lifetime. The profile supplies the leaf's KeyUsage /
     * ExtendedKeyUsage shape. The CSR PEM is returned alongside the cert so
     * the API layer can persist it for audit.
     */
    Issued issue(PKCS10CertificationRequest csr, CertificateProfile profile) {
        try {
            CertificateBundle bundle = pki.issueCertificate(csr,
                    CertInfo.fromCsr(csr).profile(profile).build());
            return new Issued(
                    bundle.getCertificate(),
                    bundle.toCertificatePem(),
                    bundle.toCertificateChainPem(),
                    Csr.toPem(csr));
        } catch (IllegalArgumentException e) {
            throw new CertApiException(400, "bad_csr",
                    "could not issue a " + profile + " certificate from the supplied CSR: "
                            + e.getMessage());
        } catch (QuickPkiException e) {
            throw new CertApiException(400, "bad_csr",
                    "could not issue a " + profile + " certificate from the supplied CSR: "
                            + rootMessage(e));
        }
    }

    String issuerPem() {
        return issuer.toCertificatePem();
    }

    private static String rootMessage(Throwable t) {
        Throwable cause = t;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return cause.getMessage() != null ? cause.getMessage() : cause.getClass().getSimpleName();
    }

    private static CertificateAuthorityService load(
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
            CertificateBundle issuer = new CertificateBundle(
                    null, certificate, new KeyPair(certificate.getPublicKey(), privateKey));
            LOG.info("Loaded persisted Quick-PKI issuing CA subject={} notAfter={}",
                    certificate.getSubjectX500Principal().getName(), certificate.getNotAfter().toInstant());
            return new CertificateAuthorityService(QuickPki.fromIssuer(issuerInfo, issuer));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load persisted CA material", e);
        }
    }

    private static CertificateAuthorityService create(
            CertApiConfig config,
            IssuerInfo issuerInfo,
            KeyEncryptor encryptor,
            CertApiRepository repository) {
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
            LOG.info("Created and persisted Quick-PKI issuing CA subject={} notAfter={}",
                    issuer.getCertificate().getSubjectX500Principal().getName(),
                    issuer.getCertificate().getNotAfter().toInstant());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to persist new CA material", e);
        }
        return new CertificateAuthorityService(pki);
    }

    private static IssuerInfo issuerInfo(CertApiConfig config) {
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return IssuerInfo.builder()
                .subjectName(SubjectName.builder().commonName("Quick-PKI Issuing CA").build())
                .validFrom(now.minus(1, ChronoUnit.HOURS))
                .validUntil(now.plus(3650, ChronoUnit.DAYS))
                .defaultLifespan(config.certificateLifetime())
                .build();
    }

    /**
     * A freshly signed leaf certificate plus its PEM encodings and the CSR
     * it was issued from.
     */
    record Issued(X509Certificate certificate, String certificatePem, String chainPem, String csrPem) {
    }
}
