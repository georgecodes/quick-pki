package com.elevenware.quickpki;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

public class PkiTests {

    @Test
    void canSerialise() {

        QuickPki pki = new QuickPki();
        CertificateAuthority first = pki.addCertificateAuthority(CertificateAuthority.builder()
                .withIssuer("My Root")
                .withProvider(new BouncyCastleProvider())
                        .withIntermediate(CertInfo.builder()
                                .commonName("My Intermediate 1")
                                .build())
                        .withIntermediate(CertInfo.builder()
                                .commonName("My Intermediate 2").build())
                        .withIntermediate(CertInfo.builder()
                                .commonName("My Intermediate 3")
                                .build())
                .build());

        first.getChain("My Intermediate 1").issue(CertInfo.builder()
                .commonName("My Leaf")
                .endDate(LocalDateTime.now().plusMinutes(1L))
                .build());

        JsonObject json = JsonParser.parseString(pki.serialise()).getAsJsonObject();

        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        System.out.println(gson.toJson(json));

    }

}
