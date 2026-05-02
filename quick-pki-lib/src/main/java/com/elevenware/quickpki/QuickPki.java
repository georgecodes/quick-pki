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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

/**
 * A very small library for generating certs for tests. It isn't in any way a viable PKI
 * @see CertificateBundle
 */
public class QuickPki {

    private final IssuerInfo issuerInfo;
    private final Provider provider;
    private final SecureRandom secureRandom = new SecureRandom();
    private final CertificateBundle issuer;

    private QuickPki(Provider provider, IssuerInfo info) {
        this.provider = provider;
        this.issuerInfo = info;
        try {
            issuer = createIssuer(info);
        } catch (Exception e) {
            throw new QuickPkiException("Failed to build issuer certificate", e);
        }
    }

    private KeyPair newKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", provider);
        generator.initialize(2048, secureRandom);
        return generator.generateKeyPair();
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

    public CertificateBundle getIssuer() {
        return issuer;
    }

    private CertificateBundle createIssuer(IssuerInfo info) throws Exception {
        Date startDate = Date
                .from(info.getValidFrom());

        Date endDate = Date
                .from(info.getValidUntil());

        KeyPair rootKeyPair = newKeyPair();
        BigInteger rootSerialNum = new BigInteger(159, secureRandom);

        SubjectName subjectName = Optional.ofNullable(info.getSubjectName())
                .orElse(SubjectName.builder()
                        .commonName("Default Root Issuer")
                        .build());

        X500Name rootCertIssuer = buildX500Name(subjectName);
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder("SHA256withRSA")
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
        } catch (Exception e) {
            throw new QuickPkiException("Failed to issue certificate", e);
        }
    }

    private CertificateBundle intIssueCertificate(CertInfo info) throws Exception {

        Instant start = info.getValidFrom();
        Instant end = info.getValidUntil();
        if(start == null) {
            start = Instant.now();
        }
        if(end == null) {
           Duration lifespan = issuerInfo.getDefaultLifespan();
           if(lifespan == null) {
               lifespan = Duration.ofDays(1L);
           }
           end = start.plus(lifespan);
        }
        Date startDate = Date
                .from(start);

        Date endDate = Date
                .from(end);

        KeyPair keyPair = newKeyPair();
        BigInteger serialNum = new BigInteger(159, secureRandom);

        X500Name issuerSubject = new JcaX509CertificateHolder(issuer.getCertificate()).getSubject();

        SubjectName subjectName = info.getSubjectName();
        if(subjectName == null) {
            subjectName = SubjectName.builder().commonName("Default Subject").build();
        }
        X500Name subject = buildX500Name(subjectName);
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(provider).build(this.issuer.getKeyPair().getPrivate());
        X509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(issuerSubject, serialNum,
                        startDate, endDate, subject, keyPair.getPublic());

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certificateBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
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
