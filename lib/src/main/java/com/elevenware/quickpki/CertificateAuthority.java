package com.elevenware.quickpki;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;

import java.security.KeyPair;
import java.security.Provider;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CertificateAuthority {

    private Provider provider;
    private Map<String, CertificateChain> issuerChain = new HashMap<>();
    private CertificateBundle root;

    public CertificateAuthority(Provider provider) {
        this.provider = provider;
    }

    public static Builder builder() {
        return new Builder();
    }

    public CertificateBundle getRoot() {
        return root;
    }

    public Map<String, CertificateChain> getChains() {
        return Collections.unmodifiableMap(issuerChain);
    }

    public CertificateChain getChain(String name) {
        return issuerChain.get(name);
    }

    public String getName() {
        return root.getName();
    }

    public JsonObject toJson() {
        JsonObject json = new JsonObject();
        for(Map.Entry<String, CertificateChain> entry : issuerChain.entrySet()) {
            json.add(entry.getKey(), entry.getValue().toJson());
        }
        return json;
    }

    public static class Builder {

        private String issuer;
        private Provider provider;
        private KeyPair rootKeyPair;
        private X500Name rootCertIssuer;
        private X509CertificateHolder rootCertHolder;
        private CertificateBundle rootCert;
        private LocalDateTime rootEndDate;
        private List<CertInfo> intermediates = new ArrayList<>();

        public Builder withIssuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder withProvider(Provider provider) {
            this.provider = provider;
            return this;
        }

        public Builder withIntermediate(CertInfo info) {
            info.setCa(true);
            intermediates.add(info);
            return this;
        }

        public Builder endDate(LocalDateTime endDate) {
            rootEndDate = endDate;
            return this;
        }

        public CertificateAuthority build() {
            CertificateAuthority certificateAuthority = new CertificateAuthority(provider);
            CertGenerator certGenerator = new CertGenerator(provider);
            CertInfo rootCertInfo = CertInfo.builder()
                    .isCa(true)
                    .commonName(issuer)
                    .startDate(LocalDateTime.now())
                    .endDate(rootEndDate)
                    .build();
            try {
                rootCert = certGenerator.issue(rootCertInfo);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            for (CertInfo info : intermediates) {
                CertificateChain chain = new CertificateChain(provider);
                chain.addIntermediate(rootCert);
                try {
                    info.setIssuer(rootCert);
                    info.setStartDate(LocalDateTime.now());
                    CertificateBundle intermediate = certGenerator.issue(info);
                    chain.addIntermediate(intermediate);
                    certificateAuthority.issuerChain.put(info.getCommonName(), chain);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            certificateAuthority.root = rootCert;
            if(intermediates.isEmpty()) {
                CertificateChain chain = new CertificateChain(provider);
                chain.addIntermediate(rootCert);
                certificateAuthority.issuerChain.put(issuer, chain);
            }
            return certificateAuthority;
        }


    }

}
