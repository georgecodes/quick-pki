package com.elevenware.quickpki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class CertificateBundle {


    private CertificateBundle issuer;
    private final X509Certificate certificate;
    private final JcaX509CertificateHolder holder;
    private final KeyPair keyPair;

    public CertificateBundle(CertificateBundle issuer, X509Certificate certificate, KeyPair keyPair) {
        this.issuer = issuer;
        this.certificate = certificate;
        try {
            this.holder = new JcaX509CertificateHolder(certificate);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
        this.keyPair = keyPair;
        if(issuer == null) {
            this.issuer = this;
        }
    }


    public boolean issuedBy(CertificateBundle issuer) {
        X509Certificate issuerCert = issuer.getCertificate();
        try {
            certificate.verify(issuerCert.getPublicKey());
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            return false;
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            return false;
        }
        return true;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String getCommonName() {
        X500Name x500Name = holder.getSubject();
        return x500Name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }
}
