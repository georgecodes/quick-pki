package com.elevenware.quickpki;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;

import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class CertificateBundle {

    // Hard cap on chain walks. Real PKI chains are 2-5 levels deep; 64 is far
    // beyond anything legitimate and ensures we fail fast rather than hang if
    // a caller ever constructs a pathological bundle graph (today the final
    // issuer field plus Java's evaluation order make cycles unconstructible
    // through the normal API, but reflection or future API changes could).
    private static final int MAX_CHAIN_DEPTH = 64;

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

    // The bundle that signed this one. For a self-signed root, returns this.
    public CertificateBundle getIssuer() {
        return issuer;
    }

    public String getCommonName() {
        X500Name x500Name = holder.getSubject();
        return x500Name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    // The certificate chain from this bundle's cert up to and including the
    // root, leaf-first - the order Java's TLS stack and most other consumers
    // expect.
    public List<X509Certificate> getCertificateChain() {
        List<X509Certificate> chain = new ArrayList<>();
        CertificateBundle current = this;
        for (int depth = 0; depth < MAX_CHAIN_DEPTH; depth++) {
            chain.add(current.certificate);
            if (current.issuer == current) {
                return List.copyOf(chain);
            }
            current = current.issuer;
        }
        throw new QuickPkiException(
                "Certificate chain exceeds " + MAX_CHAIN_DEPTH + " levels (possible cycle)");
    }

    public String toCertificatePem() {
        return writePem(certificate);
    }

    // PKCS#8 PEM (BEGIN PRIVATE KEY) - the modern, algorithm-neutral form;
    // OpenSSL >= 1.1 and modern Java tools expect this rather than the legacy
    // BEGIN RSA PRIVATE KEY block.
    public String toPrivateKeyPem() {
        requirePrivateKey("export PKCS#8 private key PEM");
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            // null encryptor = unencrypted PKCS#8.
            pemWriter.writeObject(new JcaPKCS8Generator(keyPair.getPrivate(), null));
        } catch (IOException e) {
            throw new QuickPkiException("Failed to write PKCS#8 private key PEM", e);
        }
        return sw.toString();
    }

    // Concatenated PEM of the full chain, leaf-first. Drop-in for nginx /
    // Tomcat / curl style "fullchain.pem" configurations.
    public String toCertificateChainPem() {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            for (X509Certificate cert : getCertificateChain()) {
                pemWriter.writeObject(cert);
            }
        } catch (IOException e) {
            throw new QuickPkiException("Failed to write chain PEM", e);
        }
        return sw.toString();
    }

    // PKCS12 KeyStore with this bundle's private key + full chain stored under
    // `alias`. Returned in-memory; callers store(OutputStream, password) to
    // serialise.
    public KeyStore toKeyStore(String alias, char[] password) {
        Objects.requireNonNull(alias, "alias must not be null");
        Objects.requireNonNull(password, "password must not be null");
        requirePrivateKey("build PKCS12 KeyStore");
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            X509Certificate[] chain = getCertificateChain().toArray(new X509Certificate[0]);
            ks.setKeyEntry(alias, keyPair.getPrivate(), password, chain);
            return ks;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new QuickPkiException("Failed to build PKCS12 KeyStore", e);
        }
    }

    // The bundle's public key as a JWK, with x5c populated from the full
    // chain. The private key is not embedded - if you need it, export PEM /
    // PKCS12 via the dedicated methods.
    public JWK toJwk() {
        try {
            List<Base64> x5c = new ArrayList<>();
            for (X509Certificate cert : getCertificateChain()) {
                x5c.add(Base64.encode(cert.getEncoded()));
            }
            String publicAlgorithm = certificate.getPublicKey().getAlgorithm();
            if ("RSA".equalsIgnoreCase(publicAlgorithm)) {
                return new RSAKey.Builder((RSAPublicKey) certificate.getPublicKey())
                        .keyUse(KeyUse.SIGNATURE)
                        .x509CertChain(x5c)
                        .build();
            }
            if ("EC".equalsIgnoreCase(publicAlgorithm)) {
                ECPublicKey ecKey = (ECPublicKey) certificate.getPublicKey();
                Curve curve = Curve.forECParameterSpec(ecKey.getParams());
                if (curve == null) {
                    throw new QuickPkiException(
                            "Unsupported EC curve for JWK export: " + ecKey.getParams());
                }
                return new ECKey.Builder(curve, ecKey)
                        .keyUse(KeyUse.SIGNATURE)
                        .x509CertChain(x5c)
                        .build();
            }
            throw new QuickPkiException(
                    "Unsupported public key algorithm for JWK export: " + publicAlgorithm);
        } catch (CertificateEncodingException e) {
            throw new QuickPkiException("Failed to encode certificate for JWK x5c", e);
        }
    }

    // Bundles produced by QuickPki.issueCertificate(info, PublicKey) carry a
    // KeyPair with no private half (the subscriber kept it). Anything that
    // needs to sign or export the private key must fail fast with a clear
    // message rather than NPE inside BouncyCastle.
    private void requirePrivateKey(String operation) {
        if (keyPair == null || keyPair.getPrivate() == null) {
            throw new QuickPkiException(
                    "Cannot " + operation + ": this CertificateBundle has no private key "
                            + "(it was issued from a caller-supplied public key)");
        }
    }

    private static String writePem(Object jcaObject) {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(jcaObject);
        } catch (IOException e) {
            throw new QuickPkiException("Failed to write PEM", e);
        }
        return sw.toString();
    }
}
