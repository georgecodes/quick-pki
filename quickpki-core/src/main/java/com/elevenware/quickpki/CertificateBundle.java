package com.elevenware.quickpki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @CertificateBundle
 *
 * This class packages a certificate with its keypair and issuer, if any.
 * It adds convenience methods for checking if a certificate was issued by another certificate.
 */
public class CertificateBundle {

    private CertificateBundle issuer;
    private final X509Certificate certificate;
    private final JcaX509CertificateHolder holder;
    private final KeyPair keyPair;

    /**
     * Constructor for a CertificateBundle
     * @param issuer The issuer of the certificate
     * @param certificate The certificate
     * @param keyPair The keypair associated with the certificate
     */
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

    /**
     * Checks if the certificate was issued by the provided issuer
     * @param issuer
     * @return
     */
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

    /**
     * Returns the issuer of the certificate
     * @return
     */
    public CertificateBundle getIssuer() {
        return issuer;
    }

    /**
     * Returns the x.509 certificate
     * @return
     */
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

    public KeyManager[] keyManagers() {
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(certificate);
        if (issuer != null) {
            chain.add(issuer.getCertificate());
        }

        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance("JKS");
            keystore.load(null);
            keystore.setCertificateEntry("cert-alias", certificate);
            keystore.setKeyEntry("key-alias", keyPair.getPrivate(), "changeit".toCharArray(), chain.toArray(new Certificate[chain.size()]));

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keystore, "changeit".toCharArray());

            return keyManagerFactory.getKeyManagers();
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

    }

    public TrustManager[] trustStore() {
        if(this == issuer) {
            // root certificate
            X509TrustManager x509TrustManager =	new X509TrustManager() {

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[] {certificate};
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    System.out.println("Server check in " + certificate.getSubjectX500Principal());
                }

                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    System.out.println("Client check in " + certificate.getSubjectX500Principal());
                }
            };
            return new TrustManager[] {x509TrustManager};
        }
        return issuer.trustStore();
    }
}
