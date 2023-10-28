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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class QuickPki {

    private List<X509Certificate> issuerChain = new ArrayList<>();

    public static Builder builder() {
        return new Builder();
    }

    public X509Certificate[] getCertificateChain() {
        return issuerChain.toArray(new X509Certificate[0]);
    }

    public static class Builder {

        private String issuer;
        private Provider provider;
        private KeyPair rootKeyPair;
        private X500Name rootCertIssuer;
        private X509CertificateHolder rootCertHolder;
        private X509Certificate rootCert;

        public Builder withIssuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder withProvider(Provider provider) {
            this.provider = provider;
            return this;
        }

        public QuickPki build() {
            QuickPki quickPki = new QuickPki();
            try {
                generateRootCert(issuer);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            quickPki.issuerChain.add(rootCert);
            return quickPki;
        }

        public void generateRootCert(String issuerName) throws Exception {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", provider);
            keyPairGenerator.initialize(2048);

            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.DATE, -1);
            Date startDate = calendar.getTime();

            calendar.add(Calendar.DATE, 1);
            Date endDate = calendar.getTime();

            rootKeyPair = keyPairGenerator.generateKeyPair();
            BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

            rootCertIssuer = new X500Name("CN=" + issuerName);
            X500Name rootCertSubject = rootCertIssuer;
            ContentSigner rootCertContentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider(provider).build(rootKeyPair.getPrivate());
            X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject, rootKeyPair.getPublic());

            JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
            rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false, rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

            rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
            rootCert = new JcaX509CertificateConverter().setProvider(provider).getCertificate(rootCertHolder);
        }

    }

}
