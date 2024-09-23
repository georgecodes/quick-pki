package com.elevenware.quickpki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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
import java.util.Date;
import java.util.Optional;

/**
 * A very small library for generating certs for tests. It isn't in any way a viable PKI
 * @see CertificateBundle
 */
public class QuickPki {

    private final IssuerInfo issuerInfo;
    private KeyPairGenerator keyPairGenerator;
    private Provider provider;
    private CertificateBundle issuer;

    private QuickPki(Provider provider, IssuerInfo info) {
        this.provider = provider;
        this.issuerInfo = info;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
            keyPairGenerator.initialize(2048);
            issuer = createIssuer(info);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }


    public static QuickPki createDefault() {
        Provider provider = Security.getProvider("BC");
        IssuerInfo issuerInfo = IssuerInfo.builder().build();
        return new QuickPki(provider, issuerInfo);
    }

    public static QuickPki create(IssuerInfo issuerInfo) {
        Provider provider = Security.getProvider("BC");
        return new QuickPki(provider, issuerInfo);
    }

    public CertificateBundle getIssuer() {
        return issuer;
    }

    private CertificateBundle createIssuer(IssuerInfo info) throws Exception {
        Date startDate = Date
                .from(info.getValidFrom());

        Date endDate = Date
                .from(info.getValidUntil());

        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        SubjectName subjectName = Optional.ofNullable(info.getSubjectName())
                .orElse(SubjectName.builder()
                        .commonName("Default Root Issuer")
                        .build());

        String rootSubjectName = buildSubjectName(subjectName);

        X500Name rootCertIssuer = new X500Name(rootSubjectName);
        X500Name rootCertSubject = rootCertIssuer;
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(provider).build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder rootCertBuilder =
                new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum,
                        startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
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
            throw new RuntimeException(e);
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

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        BigInteger serialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        X500Name issuerSubject = new JcaX509CertificateHolder(issuer.getCertificate()).getSubject();

        SubjectName subjectName = info.getSubjectName();
        if(subjectName == null) {
            subjectName = SubjectName.builder().commonName("My Root Issuer").build();
        }
        String subjectNameString = buildSubjectName(info.getSubjectName());

        X500Name subject = new X500Name(subjectNameString);
        ContentSigner rootCertContentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(provider).build(this.issuer.getKeyPair().getPrivate());
        X509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(issuerSubject, serialNum,
                        startDate, endDate, subject, keyPair.getPublic());

        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certificateBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                rootCertExtUtils.createSubjectKeyIdentifier(keyPair.getPublic()));



        X509CertificateHolder rootCertHolder = certificateBuilder.build(rootCertContentSigner);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(provider).getCertificate(rootCertHolder);
        return new CertificateBundle(this.issuer, cert, keyPair);
    }

    private String buildSubjectName(SubjectName info) {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("CN=").append(info.getCommonName());
        if(info.getCountry() != null) {
            stringBuilder.append(", C=").append(info.getCountry());
        }
        if(info.getOrganization() != null) {
            stringBuilder.append(", O=").append(info.getOrganization());
        }
        if(info.getOrganizationUnit() != null) {
            stringBuilder.append(", OU=").append(info.getOrganizationUnit());
        }
        if(info.getDnQualifier() != null) {
            stringBuilder.append(", DN=").append(info.getDnQualifier());
        }
        if(info.getLocality() != null) {
            stringBuilder.append(", L=").append(info.getLocality());
        }
        if(info.getStateOrProvince() != null) {
            stringBuilder.append(", ST=").append(info.getStateOrProvince());
        }

        return stringBuilder.toString();
    }
}
