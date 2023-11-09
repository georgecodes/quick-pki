package com.elevenware.quickpki;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.security.Provider;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CertificateChain {

    private List<CertificateBundle> trustChain = new ArrayList<>();
    private List<CertificateBundle> issuedCerts = new ArrayList<>();
    private CertGenerator generator;

    public CertificateChain(Provider provider) {
        this.generator = new CertGenerator(provider);
    }

    public List<CertificateBundle> getTrustChain() {
        return Collections.unmodifiableList(trustChain);
    }

    public void addIntermediate(CertificateBundle cert) {
        trustChain.add(cert);
    }

    public CertificateBundle issue(CertInfo info) {
        info.setCa(false);
        info.setIssuer(trustChain.get(trustChain.size() - 1));
        try {
            CertificateBundle leaf = generator.issue(info);
            issuedCerts.add(leaf);
            return leaf;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public CertificateBundle addIntermediate(CertInfo info) {
        info.setCa(true);
        info.setIssuer(trustChain.get(trustChain.size() - 1));
        try {
            CertificateBundle intermediate = generator.issue(info);
            trustChain.add(intermediate);
            return intermediate;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public JsonObject toJson() {
        JsonObject jsonObject = new JsonObject();
        JsonArray trustChainJson = new JsonArray();
        JsonArray issuedCertsJson = new JsonArray();
        for(CertificateBundle bundle : trustChain) {
            trustChainJson.add(bundle.toJson());
        }
        for(CertificateBundle bundle : issuedCerts) {
            issuedCertsJson.add(bundle.toJson());
        }
        jsonObject.add("trustChain", trustChainJson);
        jsonObject.add("issuedCerts", issuedCertsJson);
        return jsonObject;
    }
}
