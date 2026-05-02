package com.elevenware.quickpki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A very small library for generating certs for tests. It isn't in any way a viable PKI
 * @see CertificateBundle
 */
public class QuickPki {

    private final QuickPki parent;
    private final IssuerInfo issuerInfo;
    private final Provider provider;
    private final SecureRandom secureRandom = new SecureRandom();
    private final CertificateBundle issuer;

    // Root-PKI constructor: generates a self-signed issuer.
    private QuickPki(Provider provider, IssuerInfo info) {
        this.parent = null;
        this.provider = provider;
        this.issuerInfo = info;
        try {
            issuer = createIssuer();
        } catch (Exception e) {
            throw new QuickPkiException("Failed to build issuer certificate", e);
        }
    }

    // Intermediate-PKI constructor: takes a pre-built issuer bundle (already
    // signed by the parent), so we don't regenerate one.
    private QuickPki(QuickPki parent, IssuerInfo info, CertificateBundle issuerBundle) {
        this.parent = parent;
        this.provider = parent.provider;
        this.issuerInfo = info;
        this.issuer = issuerBundle;
    }

    private KeyPair newKeyPair() throws GeneralSecurityException {
        KeyAlgorithm algorithm = issuerInfo.getKeyAlgorithm();
        KeyPairGenerator generator;
        if (algorithm instanceof KeyAlgorithm.Rsa rsa) {
            generator = KeyPairGenerator.getInstance("RSA", provider);
            generator.initialize(rsa.bits(), secureRandom);
        } else if (algorithm instanceof KeyAlgorithm.Ec ec) {
            generator = KeyPairGenerator.getInstance("EC", provider);
            generator.initialize(new ECGenParameterSpec(ec.curve()), secureRandom);
        } else {
            throw new IllegalStateException("Unsupported KeyAlgorithm: " + algorithm);
        }
        return generator.generateKeyPair();
    }

    // Resolves a CertInfo's start/end Instants, defaulting to now() and
    // start+issuerInfo.defaultLifespan respectively when omitted. Catches
    // the case where the caller pinned only one bound to a value that
    // would invert the resolved range (eg. validUntil in the past with no
    // explicit validFrom).
    private Validity resolveValidity(CertInfo info) {
        Instant start = info.getValidFrom() != null ? info.getValidFrom() : Instant.now();
        Instant end = info.getValidUntil() != null ? info.getValidUntil()
                : start.plus(issuerInfo.getDefaultLifespan());
        if (start.isAfter(end)) {
            throw new IllegalArgumentException(
                    "validFrom (" + start + ") must not be after validUntil (" + end + ")");
        }
        return new Validity(start, end);
    }

    private record Validity(Instant start, Instant end) {}

    // RFC 5280 §4.1.2.2 requires the serial to be a positive integer (1..2^159-1).
    // BigInteger(159, random) draws uniformly over [0, 2^159), so we reject 0.
    private BigInteger newSerialNumber() {
        BigInteger serial;
        do {
            serial = new BigInteger(159, secureRandom);
        } while (serial.signum() == 0);
        return serial;
    }

    // KeyUsage.keyEncipherment is RSA key-transport semantics; for EC keys it is
    // meaningless and some strict validators reject it. Use keyAgreement (ECDH)
    // for EC, matching the convention that Let's Encrypt etc. follow.
    private KeyUsage leafKeyUsageFor(KeyPair keyPair) {
        String algo = keyPair.getPublic().getAlgorithm();
        if ("EC".equalsIgnoreCase(algo)) {
            return new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement);
        }
        return new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
    }


    public static QuickPki createDefault() {
        return new QuickPki(ensureBouncyCastleProvider(), IssuerInfo.builder().build());
    }

    public static QuickPki create(IssuerInfo issuerInfo) {
        return new QuickPki(ensureBouncyCastleProvider(), issuerInfo);
    }

    private static Provider ensureBouncyCastleProvider() {
        Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (provider == null) {
            provider = new BouncyCastleProvider();
            Security.addProvider(provider);
        }
        return provider;
    }

    // Null for a root PKI; otherwise the PKI that issued this intermediate.
    public QuickPki getParent() {
        return parent;
    }

    public boolean isRoot() {
        return parent == null;
    }

    public CertificateBundle getIssuer() {
        return issuer;
    }

    // PKCS12 truststore containing the chain's root cert as a
    // TrustedCertificateEntry under `alias`. Suitable for handing to
    // SSLContext as a trust source on the client side.
    public KeyStore toTrustStore(String alias) {
        Objects.requireNonNull(alias, "alias must not be null");
        try {
            KeyStore ts = KeyStore.getInstance("PKCS12");
            ts.load(null, null);
            List<X509Certificate> chain = issuer.getCertificateChain();
            X509Certificate root = chain.get(chain.size() - 1);
            ts.setCertificateEntry(alias, root);
            return ts;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new QuickPkiException("Failed to build PKCS12 TrustStore", e);
        }
    }

    // JWK Set containing the public key (with x5c) of every cert in the chain
    // from this PKI's issuer up to the root, leaf-first. Useful for serving as
    // the JWKS endpoint of a mock OIDC issuer in tests.
    public JWKSet toJwkSet() {
        List<JWK> keys = new ArrayList<>();
        CertificateBundle current = issuer;
        for (int depth = 0; depth < MAX_CHAIN_DEPTH; depth++) {
            keys.add(current.toJwk());
            if (current.getIssuer() == current) {
                return new JWKSet(keys);
            }
            current = current.getIssuer();
        }
        throw new QuickPkiException(
                "Certificate chain exceeds " + MAX_CHAIN_DEPTH + " levels (possible cycle)");
    }

    private static final int MAX_CHAIN_DEPTH = 64;

    private CertificateBundle createIssuer() throws Exception {
        Date startDate = Date
                .from(issuerInfo.getValidFrom());

        Date endDate = Date
                .from(issuerInfo.getValidUntil());

        KeyPair rootKeyPair = newKeyPair();
        BigInteger rootSerialNum = newSerialNumber();

        SubjectName subjectName = Optional.ofNullable(issuerInfo.getSubjectName())
                .orElse(SubjectName.builder()
                        .commonName("Default Root Issuer")
                        .build());

        X500Name rootCertIssuer = buildX500Name(subjectName);
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(issuerInfo.getEffectiveSignatureAlgorithm())
                .setProvider(provider).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder =
                new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum,
                        startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert = new JcaX509CertificateConverter().setProvider(provider).getCertificate(rootCertHolder);
        return new CertificateBundle(null, rootCert, rootKeyPair);
    }

    public CertificateBundle issueCertificate(CertInfo info) {
        try {
            return intIssueCertificate(info);
        } catch (IllegalArgumentException e) {
            // Bad caller input (eg. inverted validity range): bubble directly
            // so the message reaches the caller without 'Failed to issue
            // certificate' framing it as a library-internal failure.
            throw e;
        } catch (Exception e) {
            throw new QuickPkiException("Failed to issue certificate", e);
        }
    }

    // Issues a subordinate CA certificate, signed by this PKI, and returns it
    // wrapped as a new QuickPki that can itself issue further certificates.
    // The intermediate inherits this PKI's algorithm and signature settings.
    public QuickPki issueIntermediate(CertInfo info) {
        if (!info.getDnsNames().isEmpty() || !info.getIpAddresses().isEmpty()) {
            throw new IllegalArgumentException(
                    "Subject Alternative Names (dnsName/ipAddress) are not supported on "
                            + "intermediate CA certificates; put them on the end-entity cert instead");
        }
        try {
            return intIssueIntermediate(info);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new QuickPkiException("Failed to issue intermediate CA", e);
        }
    }

    private QuickPki intIssueIntermediate(CertInfo info) throws Exception {
        Validity validity = resolveValidity(info);

        KeyPair keyPair = newKeyPair();
        BigInteger serialNum = newSerialNumber();

        X500Name issuerSubject = new JcaX509CertificateHolder(issuer.getCertificate()).getSubject();
        SubjectName subjectName = info.getSubjectName();
        if (subjectName == null) {
            subjectName = SubjectName.builder().commonName("Default Intermediate CA").build();
        }
        X500Name subject = buildX500Name(subjectName);

        ContentSigner signer = new JcaContentSignerBuilder(issuerInfo.getEffectiveSignatureAlgorithm())
                .setProvider(provider).build(issuer.getKeyPair().getPrivate());
        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuerSubject, serialNum,
                        Date.from(validity.start()), Date.from(validity.end()), subject, keyPair.getPublic());

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(issuer.getCertificate()));

        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(provider).getCertificate(holder);
        CertificateBundle intermediateBundle = new CertificateBundle(this.issuer, cert, keyPair);

        return new QuickPki(this, this.issuerInfo, intermediateBundle);
    }

    private CertificateBundle intIssueCertificate(CertInfo info) throws Exception {

        Validity validity = resolveValidity(info);
        Date startDate = Date.from(validity.start());
        Date endDate = Date.from(validity.end());

        KeyPair keyPair = newKeyPair();
        BigInteger serialNum = newSerialNumber();

        X500Name issuerSubject = new JcaX509CertificateHolder(issuer.getCertificate()).getSubject();

        SubjectName subjectName = info.getSubjectName();
        if(subjectName == null) {
            subjectName = SubjectName.builder().commonName("Default Subject").build();
        }
        X500Name subject = buildX500Name(subjectName);
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(issuerInfo.getEffectiveSignatureAlgorithm())
                .setProvider(provider).build(this.issuer.getKeyPair().getPrivate());
        X509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(issuerSubject, serialNum,
                        startDate, endDate, subject, keyPair.getPublic());

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certificateBuilder.addExtension(Extension.keyUsage, true, leafKeyUsageFor(keyPair));
        certificateBuilder.addExtension(Extension.extendedKeyUsage, false,
                new ExtendedKeyUsage(new KeyPurposeId[] {
                        KeyPurposeId.id_kp_serverAuth,
                        KeyPurposeId.id_kp_clientAuth
                }));
        certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
        certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                extUtils.createAuthorityKeyIdentifier(issuer.getCertificate()));

        GeneralNames sans = buildSubjectAlternativeNames(info);
        if (sans != null) {
            certificateBuilder.addExtension(Extension.subjectAlternativeName, false, sans);
        }

        X509CertificateHolder rootCertHolder = certificateBuilder.build(rootCertContentSigner);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(provider).getCertificate(rootCertHolder);
        return new CertificateBundle(this.issuer, cert, keyPair);
    }

    private GeneralNames buildSubjectAlternativeNames(CertInfo info) {
        List<GeneralName> names = new ArrayList<>();
        for (String dnsName : info.getDnsNames()) {
            names.add(new GeneralName(GeneralName.dNSName, dnsName));
        }
        for (String ipAddress : info.getIpAddresses()) {
            names.add(new GeneralName(GeneralName.iPAddress, ipAddress));
        }
        if (names.isEmpty()) {
            return null;
        }
        return new GeneralNames(names.toArray(new GeneralName[0]));
    }

    private X500Name buildX500Name(SubjectName info) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, info.getCommonName());
        if(info.getCountry() != null) {
            builder.addRDN(BCStyle.C, info.getCountry());
        }
        if(info.getOrganization() != null) {
            builder.addRDN(BCStyle.O, info.getOrganization());
        }
        if(info.getOrganizationUnit() != null) {
            builder.addRDN(BCStyle.OU, info.getOrganizationUnit());
        }
        if(info.getDnQualifier() != null) {
            builder.addRDN(BCStyle.DN_QUALIFIER, info.getDnQualifier());
        }
        if(info.getLocality() != null) {
            builder.addRDN(BCStyle.L, info.getLocality());
        }
        if(info.getStateOrProvince() != null) {
            builder.addRDN(BCStyle.ST, info.getStateOrProvince());
        }
        return builder.build();
    }
}
