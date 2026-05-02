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


    private final CertificateBundle issuer;
    private final X509Certificate certificate;
    private final JcaX509CertificateHolder holder;
    private final KeyPair keyPair;

    public CertificateBundle(CertificateBundle issuer, X509Certificate certificate, KeyPair keyPair) {
        this.issuer = (issuer != null) ? issuer : this;
        this.certificate = certificate;
        try {
            this.holder = new JcaX509CertificateHolder(certificate);
        } catch (CertificateEncodingException e) {
            throw new QuickPkiException("Failed to parse certificate", e);
        }
        this.keyPair = keyPair;
    }


    // Predicate: returns true iff `issuer` actually signed this certificate.
    // Verification negatives (key doesn't match scheme, signature mismatch)
    // return false. Infrastructure failures (missing algorithm/provider,
    // malformed encoding) cannot answer the question and so throw.
    public boolean issuedBy(CertificateBundle issuer) {
        try {
            certificate.verify(issuer.getCertificate().getPublicKey());
            return true;
        } catch (InvalidKeyException | SignatureException e) {
            return false;
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new QuickPkiException("Failed to verify certificate signature", e);
        }
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
