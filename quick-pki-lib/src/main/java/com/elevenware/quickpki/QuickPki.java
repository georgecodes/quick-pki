package com.elevenware.quickpki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
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
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

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
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

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

    // Rehydrates a PKI around an already-created issuer bundle. This is useful
    // for services that persist their CA material and need stable issuer
    // identity across process restarts.
    private QuickPki(Provider provider, IssuerInfo info, CertificateBundle issuerBundle) {
        this.parent = null;
        this.provider = provider;
        this.issuerInfo = info;
        this.issuer = Objects.requireNonNull(issuerBundle, "issuerBundle must not be null");
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

    // Resolves the leaf KeyUsage. Precedence: explicit CertInfo bits win;
    // otherwise the selected profile's bits; otherwise default by key
    // algorithm - RSA gets digitalSignature|keyEncipherment, EC gets
    // digitalSignature|keyAgreement because keyEncipherment is RSA
    // key-transport semantics and some strict validators reject it on EC.
    private KeyUsage leafKeyUsageFor(PublicKey publicKey, CertInfo info) {
        Set<KeyUsageBit> usages = info.getKeyUsages();
        if (usages == null) {
            usages = info.getProfile().keyUsages();
        }
        if (usages != null) {
            int bits = 0;
            for (KeyUsageBit b : usages) {
                bits |= b.bit();
            }
            return new KeyUsage(bits);
        }
        String algo = publicKey.getAlgorithm();
        if ("EC".equalsIgnoreCase(algo)) {
            return new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyAgreement);
        }
        return new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
    }

    // Resolves the leaf ExtendedKeyUsage. Precedence: explicit CertInfo
    // purposes win; otherwise the selected profile's purposes; otherwise
    // default to serverAuth + clientAuth. Returns null when no EKU extension
    // should be emitted at all - the profile can request this with an empty
    // purpose set (eg. CertificateProfile.BRSEAL).
    private ExtendedKeyUsage leafEkuFor(CertInfo info) {
        Set<ExtendedKeyUsageId> eku = info.getExtendedKeyUsages();
        if (eku == null) {
            eku = info.getProfile().extendedKeyUsages();
        }
        if (eku != null) {
            if (eku.isEmpty()) {
                return null;
            }
            KeyPurposeId[] purposes = eku.stream()
                    .map(ExtendedKeyUsageId::keyPurposeId)
                    .toArray(KeyPurposeId[]::new);
            return new ExtendedKeyUsage(purposes);
        }
        return new ExtendedKeyUsage(new KeyPurposeId[] {
                KeyPurposeId.id_kp_serverAuth,
                KeyPurposeId.id_kp_clientAuth
        });
    }


    public static QuickPki createDefault() {
        return new QuickPki(ensureBouncyCastleProvider(), IssuerInfo.builder().build());
    }

    public static QuickPki create(IssuerInfo issuerInfo) {
        return new QuickPki(ensureBouncyCastleProvider(), issuerInfo);
    }

    /**
     * Rehydrates a {@link QuickPki} around an already-built issuer bundle so a
     * service can keep its CA identity stable across restarts. The bundle must
     * carry the issuer's signing key: this PKI will use {@code
     * issuerBundle.getKeyPair().getPrivate()} on every issuance, and we'd
     * rather fail fast here than NPE deep inside BouncyCastle later.
     *
     * @throws NullPointerException     if {@code issuerInfo} or {@code issuerBundle} is null
     * @throws IllegalArgumentException if the bundle has no key pair / private key,
     *                                  or its certificate is not a CA
     */
    public static QuickPki fromIssuer(IssuerInfo issuerInfo, CertificateBundle issuerBundle) {
        Objects.requireNonNull(issuerInfo, "issuerInfo must not be null");
        Objects.requireNonNull(issuerBundle, "issuerBundle must not be null");
        KeyPair keyPair = issuerBundle.getKeyPair();
        if (keyPair == null || keyPair.getPrivate() == null) {
            throw new IllegalArgumentException(
                    "issuerBundle must carry a private key; cannot sign certificates without one");
        }
        X509Certificate cert = issuerBundle.getCertificate();
        if (cert.getBasicConstraints() < 0) {
            throw new IllegalArgumentException(
                    "issuerBundle certificate is not a CA (basicConstraints cA=false or absent)");
        }
        return new QuickPki(ensureBouncyCastleProvider(), issuerInfo, issuerBundle);
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
            KeyPair keyPair = newKeyPair();
            return intIssueCertificate(info, keyPair.getPublic(), keyPair);
        } catch (IllegalArgumentException e) {
            // Bad caller input (eg. inverted validity range): bubble directly
            // so the message reaches the caller without 'Failed to issue
            // certificate' framing it as a library-internal failure.
            throw e;
        } catch (Exception e) {
            throw new QuickPkiException("Failed to issue certificate", e);
        }
    }

    /**
     * Issues a leaf certificate that binds {@code publicKey} to the subject in
     * {@code info}. Intended for CSR-style flows (eg. ACME) where the subscriber
     * generated the key pair and only the public half ever leaves their host.
     * <p>
     * The returned {@link CertificateBundle} therefore has a {@code KeyPair}
     * whose private half is {@code null}. Helpers that need the private key
     * ({@link CertificateBundle#toPrivateKeyPem()}, {@link
     * CertificateBundle#toKeyStore(String, char[])}) will throw
     * {@link QuickPkiException} on such a bundle - serve the cert/chain PEM
     * back to the subscriber and let them pair it with the key they retained.
     */
    public CertificateBundle issueCertificate(CertInfo info, PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        try {
            return intIssueCertificate(info, publicKey, new KeyPair(publicKey, null));
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new QuickPkiException("Failed to issue certificate", e);
        }
    }

    /**
     * Issues a leaf certificate from a PKCS#10 CSR, drawing the subject DN,
     * SANs, and public key from the CSR. The dNSName / iPAddress tag on each
     * SAN is preserved from the CSR (a CSR dNSName that happens to look like
     * an IP literal stays a DNS SAN). The subject DN is copied via
     * {@link CertInfo#fromCsr(PKCS10CertificationRequest)}, which models the
     * common RDNs (CN, C, O, OU, dnQualifier, L, ST) - other RDNs in the CSR
     * are dropped. The CSR's self-signature is verified before anything is
     * signed; a CSR with a bad signature never produces a cert.
     * <p>
     * The returned bundle carries no private key (the subscriber kept it); see
     * {@link #issueCertificate(CertInfo, PublicKey)} for the caveats around
     * such bundles.
     *
     * @throws QuickPkiException if the CSR signature is invalid or issuance fails
     */
    public CertificateBundle issueCertificate(PKCS10CertificationRequest csr) {
        Objects.requireNonNull(csr, "csr must not be null");
        return issueCertificate(csr, CertInfo.fromCsr(csr).build());
    }

    /**
     * Issues a leaf certificate from a PKCS#10 CSR, but with {@code info}
     * overriding the CSR's subject/SANs/validity/usages. The CSR contributes
     * only the public key (and the signature that proves the subscriber
     * possesses the matching private key). Intended for callers that apply
     * their own policy on top of CSR contents - eg. ACME servers that
     * restrict SANs to validated identifiers.
     *
     * @throws QuickPkiException if the CSR signature is invalid or issuance fails
     */
    public CertificateBundle issueCertificate(PKCS10CertificationRequest csr, CertInfo info) {
        Objects.requireNonNull(csr, "csr must not be null");
        Objects.requireNonNull(info, "info must not be null");
        Csr.verifySignature(csr);
        return issueCertificate(info, Csr.publicKey(csr));
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

    private CertificateBundle intIssueCertificate(CertInfo info, PublicKey publicKey, KeyPair keyPair) throws Exception {

        validateProfileCompliance(info, publicKey);
        Validity validity = resolveValidity(info);
        Date startDate = Date.from(validity.start());
        Date endDate = Date.from(validity.end());

        BigInteger serialNum = newSerialNumber();

        X500Name issuerSubject = new JcaX509CertificateHolder(issuer.getCertificate()).getSubject();

        SubjectName subjectName = info.getSubjectName();
        if(subjectName == null) {
            subjectName = SubjectName.builder().commonName("Default Subject").build();
        }
        X500Name subject = buildX500Name(subjectName, info.getProfile());
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder(issuerInfo.getEffectiveSignatureAlgorithm())
                .setProvider(provider).build(this.issuer.getKeyPair().getPrivate());
        X509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(issuerSubject, serialNum,
                        startDate, endDate, subject, publicKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certificateBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));
        certificateBuilder.addExtension(Extension.keyUsage, true, leafKeyUsageFor(publicKey, info));
        ExtendedKeyUsage eku = leafEkuFor(info);
        if (eku != null) {
            certificateBuilder.addExtension(Extension.extendedKeyUsage, false, eku);
        }
        certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                extUtils.createSubjectKeyIdentifier(publicKey));
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
        names.addAll(info.getOtherSubjectAlternativeNames());
        if (names.isEmpty()) {
            return null;
        }
        return new GeneralNames(names.toArray(new GeneralName[0]));
    }

    private X500Name buildX500Name(SubjectName info) {
        return buildX500Name(info, CertificateProfile.DEFAULT);
    }

    private X500Name buildX500Name(SubjectName info, CertificateProfile profile) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        if (profile == CertificateProfile.BRCAC) {
            addOpenFinanceTransportRdns(builder, info);
            return builder.build();
        }
        if (profile == CertificateProfile.BRSEAL) {
            addOpenFinanceSigningRdns(builder, info);
            return builder.build();
        }
        builder.addRDN(BCStyle.CN, info.getCommonName());
        if(info.getCountry() != null) {
            builder.addRDN(BCStyle.C, info.getCountry());
        }
        if(info.getOrganization() != null) {
            builder.addRDN(BCStyle.O, info.getOrganization());
        }
        for (String organizationUnit : info.getOrganizationUnits()) {
            builder.addRDN(BCStyle.OU, organizationUnit);
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
        if(info.getOrganizationIdentifier() != null) {
            builder.addRDN(BCStyle.ORGANIZATION_IDENTIFIER, info.getOrganizationIdentifier());
        }
        if(info.getBusinessCategory() != null) {
            builder.addRDN(BCStyle.BUSINESS_CATEGORY, info.getBusinessCategory());
        }
        if(info.getJurisdictionCountry() != null) {
            builder.addRDN(JURISDICTION_COUNTRY_NAME, info.getJurisdictionCountry());
        }
        if(info.getSerialNumber() != null) {
            builder.addRDN(BCStyle.SERIALNUMBER, info.getSerialNumber());
        }
        if(info.getUserId() != null) {
            builder.addRDN(BCStyle.UID, info.getUserId());
        }
        return builder.build();
    }

    private void validateProfileCompliance(CertInfo info, PublicKey publicKey) {
        CertificateProfile profile = info.getProfile();
        if (profile != CertificateProfile.BRCAC && profile != CertificateProfile.BRSEAL) {
            return;
        }
        validateOpenFinanceAlgorithm(publicKey);
        SubjectName subjectName = info.getSubjectName();
        if (subjectName == null) {
            throw new IllegalArgumentException(profile + " certificates require an Open Finance subject DN");
        }
        if (profile == CertificateProfile.BRCAC) {
            validateBrcac(info, subjectName);
        } else {
            validateBrseal(info, subjectName);
        }
    }

    private void validateOpenFinanceAlgorithm(PublicKey publicKey) {
        if (!(publicKey instanceof RSAPublicKey rsaPublicKey)) {
            throw new IllegalArgumentException(
                    "Open Finance Brasil BRCAC/BRSEAL certificates require an RSA public key");
        }
        if (rsaPublicKey.getModulus().bitLength() != 2048) {
            throw new IllegalArgumentException(
                    "Open Finance Brasil BRCAC/BRSEAL certificates require a 2048-bit RSA public key");
        }
        if (!"SHA256withRSA".equalsIgnoreCase(issuerInfo.getEffectiveSignatureAlgorithm())) {
            throw new IllegalArgumentException(
                    "Open Finance Brasil BRCAC/BRSEAL certificates require SHA256withRSA signatures");
        }
        if (!"RSA".equalsIgnoreCase(issuer.getCertificate().getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException(
                    "Open Finance Brasil BRCAC/BRSEAL certificates require an RSA issuing CA");
        }
    }

    private void validateBrcac(CertInfo info, SubjectName subjectName) {
        requireOneOf(subjectName.getBusinessCategory(), "businessCategory",
                Set.of("Private Organization", "Government Entity", "Business Entity", "Non-Commercial Entity"));
        requireEquals(subjectName.getJurisdictionCountry(), "jurisdictionCountry", "BR");
        requireNonBlank(subjectName.getSerialNumber(), "serialNumber");
        requireEquals(subjectName.getCountry(), "country", "BR");
        requireNonBlank(subjectName.getOrganization(), "organization");
        requireNonBlank(subjectName.getStateOrProvince(), "stateOrProvince");
        requireNonBlank(subjectName.getLocality(), "locality");
        requireNonBlank(subjectName.getOrganizationIdentifier(), "organizationIdentifier");
        if (!subjectName.getOrganizationIdentifier().startsWith("OFBBR-")) {
            throw new IllegalArgumentException("BRCAC organizationIdentifier must start with OFBBR-");
        }
        requireNonBlank(subjectName.getUserId(), "userId");
        requireNonBlank(subjectName.getCommonName(), "commonName");
        if (info.getDnsNames().isEmpty()) {
            throw new IllegalArgumentException("BRCAC certificates require at least one DNS subjectAltName");
        }
        if (!info.getIpAddresses().isEmpty() || !info.getOtherSubjectAlternativeNames().isEmpty()) {
            throw new IllegalArgumentException("BRCAC certificates support DNS subjectAltName entries only");
        }
    }

    private void validateBrseal(CertInfo info, SubjectName subjectName) {
        requireNonBlank(subjectName.getUserId(), "userId");
        requireEquals(subjectName.getCountry(), "country", "BR");
        requireEquals(subjectName.getOrganization(), "organization", "ICP-Brasil");
        if (subjectName.getOrganizationUnits().size() < 3) {
            throw new IllegalArgumentException(
                    "BRSEAL certificates require three organizationUnit values");
        }
        requireNonBlank(subjectName.getCommonName(), "commonName");
        if (!info.getDnsNames().isEmpty() || !info.getIpAddresses().isEmpty()) {
            throw new IllegalArgumentException("BRSEAL certificates support ICP-Brasil otherName SAN entries only");
        }
        requireOtherName(info, "2.16.76.1.3.2");
        requireOtherName(info, "2.16.76.1.3.3");
        requireOtherName(info, "2.16.76.1.3.4");
        requireOtherName(info, "2.16.76.1.3.7");
    }

    private void requireOtherName(CertInfo info, String oid) {
        boolean found = info.getOtherSubjectAlternativeNames().stream()
                .anyMatch(name -> oid.equals(otherNameOid(name)));
        if (!found) {
            throw new IllegalArgumentException("BRSEAL certificates require otherName " + oid);
        }
    }

    private String otherNameOid(GeneralName name) {
        try {
            ASN1Sequence sequence = ASN1Sequence.getInstance(name.getName().toASN1Primitive());
            return ASN1ObjectIdentifier.getInstance(sequence.getObjectAt(0)).getId();
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid otherName subjectAltName", e);
        }
    }

    private void requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
    }

    private void requireEquals(String value, String field, String expected) {
        requireNonBlank(value, field);
        if (!expected.equals(value)) {
            throw new IllegalArgumentException(field + " must be " + expected);
        }
    }

    private void requireOneOf(String value, String field, Set<String> expected) {
        requireNonBlank(value, field);
        if (!expected.contains(value)) {
            throw new IllegalArgumentException(field + " must be one of " + expected);
        }
    }

    private void addOpenFinanceTransportRdns(X500NameBuilder builder, SubjectName info) {
        builder.addRDN(BCStyle.BUSINESS_CATEGORY, info.getBusinessCategory());
        builder.addRDN(JURISDICTION_COUNTRY_NAME, info.getJurisdictionCountry());
        builder.addRDN(BCStyle.SERIALNUMBER, info.getSerialNumber());
        builder.addRDN(BCStyle.C, info.getCountry());
        builder.addRDN(BCStyle.O, info.getOrganization());
        builder.addRDN(BCStyle.ST, info.getStateOrProvince());
        builder.addRDN(BCStyle.L, info.getLocality());
        builder.addRDN(BCStyle.ORGANIZATION_IDENTIFIER, info.getOrganizationIdentifier());
        builder.addRDN(BCStyle.UID, info.getUserId());
        builder.addRDN(BCStyle.CN, info.getCommonName());
    }

    private void addOpenFinanceSigningRdns(X500NameBuilder builder, SubjectName info) {
        builder.addRDN(BCStyle.UID, info.getUserId());
        builder.addRDN(BCStyle.C, info.getCountry());
        builder.addRDN(BCStyle.O, info.getOrganization());
        for (String organizationUnit : info.getOrganizationUnits()) {
            builder.addRDN(BCStyle.OU, organizationUnit);
        }
        builder.addRDN(BCStyle.CN, info.getCommonName());
    }

    // jurisdictionCountryName, the EV-style jurisdiction-of-incorporation
    // country. BCStyle has no constant for it, so we name the OID directly.
    private static final ASN1ObjectIdentifier JURISDICTION_COUNTRY_NAME =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3");
}
