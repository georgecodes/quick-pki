package com.elevenware.quickpki;

import com.google.gson.JsonObject;

import java.util.HashMap;
import java.util.Map;

public class QuickPki {
    private Map<String, CertificateAuthority> authorities = new HashMap<>();

    public CertificateAuthority addCertificateAuthority(CertificateAuthority authority) {
        authorities.put(authority.getName(), authority);
        return authority;
    }

    public String serialise() {
        JsonObject json = new JsonObject();
        for(Map.Entry<String, CertificateAuthority> entry : authorities.entrySet()) {
            json.add(entry.getKey(), entry.getValue().toJson());
        }
        return json.toString();
    }
}
