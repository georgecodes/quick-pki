package com.elevenware.quickpki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class CertGenerator {
    private final Provider provider;

    public CertGenerator(Provider provider) {
        this.provider = provider;
    }

    public CertificateBundle issue(CertInfo info) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
        keyPairGenerator.initialize(2048);

        LocalDateTime sd = info.getStartDate();
        LocalDateTime ed = info.getEndDate();
        if(sd == null) {
            sd = LocalDateTime.now();
        }
        if(ed == null) {
            ed = LocalDateTime.now().plusYears(1L);
        }
        Date startDate = Date
                .from(sd.atZone(ZoneId.systemDefault())
                        .toInstant());

        Date endDate = Date
                .from(ed.atZone(ZoneId.systemDefault())
                        .toInstant());

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        KeyPair signingKeyPair = keyPair;
        X500Name issuerName = new X500Name("CN=" + info.getCommonName());
        X500Name subject = issuerName;
        CertificateBundle issuer = info.getIssuer();
        if(issuer != null) {
            signingKeyPair = issuer.getKeyPair();
            issuerName = new X500Name(issuer.getCertificate().getSubjectDN().getName());
        }
        BigInteger serialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        ContentSigner certSigner = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(provider).build(signingKeyPair.getPrivate());
        X509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(issuerName, serialNum,
                        startDate, endDate, subject, keyPair.getPublic());

        JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(info.isCa()));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                extensionUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

        X509CertificateHolder certHolder = certBuilder.build(certSigner);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider(provider).getCertificate(certHolder);
        return new CertificateBundle(cert, keyPair);
    }
}
