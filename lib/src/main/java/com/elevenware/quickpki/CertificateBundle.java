package com.elevenware.quickpki;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import org.checkerframework.checker.units.qual.C;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

public class CertificateBundle {

    private X509Certificate x509Certificate;
    private KeyPair keyPair;

    public CertificateBundle(X509Certificate certificate, KeyPair keyPair) {
        this.x509Certificate = certificate;
        this.keyPair = keyPair;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public X509Certificate getCertificate() {
        return x509Certificate;
    }

    public boolean isIssuedBy(CertificateBundle issuer) {
        X509Certificate issuerCert = issuer.getCertificate();
        try {
            x509Certificate.verify(issuerCert.getPublicKey());
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    public String getName() {
        return x509Certificate.getSubjectDN().getName();
    }

    public JsonObject toJson() {
        try {
            JWK jwk = JWK.parse(x509Certificate);
            String s = jwk.toJSONString();
            return JsonParser.parseString(s).getAsJsonObject();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    public KeyManager[] keyManagers() {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null);
            keyStore.setKeyEntry("client", keyPair.getPrivate().getEncoded(), new Certificate[] {x509Certificate});
            keyStore.setCertificateEntry("client", x509Certificate);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
            kmf.init(keyStore, new char[0]);
            return kmf.getKeyManagers();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
