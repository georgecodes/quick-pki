package com.elevenware.quickpki.certapi;

import com.elevenware.quickpki.CertInfo;
import com.elevenware.quickpki.CertificateBundle;
import com.elevenware.quickpki.CertificateProfile;
import com.elevenware.quickpki.Csr;
import com.elevenware.quickpki.IssuerInfo;
import com.elevenware.quickpki.OpenFinanceBrasil;
import com.elevenware.quickpki.QuickPki;
import com.elevenware.quickpki.QuickPkiException;
import com.elevenware.quickpki.SubjectName;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

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
     * ExtendedKeyUsage shape.
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

    /**
     * Convenience flow for {@code POST /v1/certificates/brcac}: takes the
     * consumer's structured request plus their public key, builds an Open
     * Finance Brasil BRCAC subject + SANs server-side, persists a synthetic
     * CSR for audit, and returns the signed leaf.
     *
     * <p>The synthetic CSR carries the consumer's public key and the assembled
     * subject + SAN extension, but is signed with an ephemeral server key. Its
     * signature deliberately will not verify against the embedded public key
     * — it is an audit artifact, not a proof-of-possession PKCS#10 the
     * consumer can re-submit elsewhere.
     */
    Issued issueBrcac(BrcacCertificateRequest request, PublicKey publicKey) {
        CertInfo certInfo = brcacCertInfo(request);
        return issueFromCertInfo(certInfo, publicKey, CertificateProfile.BRCAC);
    }

    /** BRSEAL counterpart to {@link #issueBrcac}; see that method for the contract. */
    Issued issueBrseal(BrsealCertificateRequest request, PublicKey publicKey) {
        CertInfo certInfo = brsealCertInfo(request);
        return issueFromCertInfo(certInfo, publicKey, CertificateProfile.BRSEAL);
    }

    String issuerPem() {
        return issuer.toCertificatePem();
    }

    private Issued issueFromCertInfo(CertInfo info, PublicKey publicKey, CertificateProfile profile) {
        try {
            String csrPem = Csr.toPem(buildSyntheticCsr(info, publicKey));
            CertificateBundle bundle = pki.issueCertificate(info, publicKey);
            return new Issued(
                    bundle.getCertificate(),
                    bundle.toCertificatePem(),
                    bundle.toCertificateChainPem(),
                    csrPem);
        } catch (CertApiException e) {
            throw e;
        } catch (IllegalArgumentException e) {
            throw new CertApiException(400, "invalid_request",
                    "could not issue a " + profile + " certificate: " + e.getMessage());
        } catch (QuickPkiException e) {
            throw new CertApiException(400, "invalid_request",
                    "could not issue a " + profile + " certificate: " + rootMessage(e));
        }
    }

    // Builds a PKCS#10 envelope around the consumer's public key, signed by an
    // ephemeral server key. The signature won't verify against the embedded
    // public key - that's deliberate: this CSR exists as an audit record of
    // what was submitted, not as proof of possession.
    private PKCS10CertificationRequest buildSyntheticCsr(CertInfo info, PublicKey subscriberPublicKey) {
        X500Name subject = Csr.x500Name(info.getSubjectName(), info.getProfile());
        PKCS10CertificationRequestBuilder builder =
                new JcaPKCS10CertificationRequestBuilder(subject, subscriberPublicKey);

        List<GeneralName> sans = new ArrayList<>();
        for (String dnsName : info.getDnsNames()) {
            sans.add(new GeneralName(GeneralName.dNSName, dnsName));
        }
        for (String ipAddress : info.getIpAddresses()) {
            sans.add(new GeneralName(GeneralName.iPAddress, ipAddress));
        }
        sans.addAll(info.getOtherSubjectAlternativeNames());
        if (!sans.isEmpty()) {
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            try {
                extGen.addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(sans.toArray(new GeneralName[0])));
            } catch (Exception e) {
                throw new IllegalStateException("failed to build synthetic CSR SAN extension", e);
            }
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        }

        try {
            KeyPair ephemeral = newRsaKeyPair();
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(ephemeral.getPrivate());
            return builder.build(signer);
        } catch (Exception e) {
            throw new IllegalStateException("failed to build synthetic CSR", e);
        }
    }

    private static KeyPair newRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static CertInfo brcacCertInfo(BrcacCertificateRequest request) {
        OpenFinanceBrasil.BrcacBuilder builder = OpenFinanceBrasil.brcac()
                .commonName(request.commonName())
                .businessCategory(request.businessCategory())
                .serialNumber(request.serialNumber())
                .organization(request.organization())
                .stateOrProvince(request.stateOrProvince())
                .locality(request.locality())
                .organizationIdentifier(request.organizationIdentifier())
                .userId(request.userId());
        if (request.country() != null) {
            builder.country(request.country());
        }
        if (request.jurisdictionCountry() != null) {
            builder.jurisdictionCountry(request.jurisdictionCountry());
        }
        if (request.dnsNames() != null) {
            for (String dnsName : request.dnsNames()) {
                builder.dnsName(dnsName);
            }
        }
        return builder.toCertInfo().build();
    }

    private static CertInfo brsealCertInfo(BrsealCertificateRequest request) {
        OpenFinanceBrasil.BrsealBuilder builder = OpenFinanceBrasil.brseal()
                .commonName(request.commonName())
                .userId(request.userId())
                .responsiblePersonName(request.responsiblePersonName())
                .companyCnpj(request.companyCnpj())
                .responsiblePersonData(request.responsiblePersonData())
                .companyCei(request.companyCei());
        if (request.country() != null) {
            builder.country(request.country());
        }
        if (request.organization() != null) {
            builder.organization(request.organization());
        }
        if (request.organizationUnits() != null) {
            for (String ou : request.organizationUnits()) {
                builder.organizationUnit(ou);
            }
        }
        return builder.toCertInfo().build();
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
     * (real, or synthetic for the convenience endpoints) the cert was issued
     * from.
     */
    record Issued(X509Certificate certificate, String certificatePem, String chainPem, String csrPem) {
    }
}
