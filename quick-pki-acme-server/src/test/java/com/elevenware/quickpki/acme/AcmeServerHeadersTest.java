package com.elevenware.quickpki.acme;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import io.javalin.Javalin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AcmeServerHeadersTest {

    private final HttpClient http = HttpClient.newHttpClient();
    private Javalin app;

    @AfterEach
    void stopApp() {
        if (app != null) {
            app.stop();
        }
    }

    @Test
    void challengeResponseLinksUpToAuthorization() throws Exception {
        Fixture fixture = startServerWithOrder();
        Challenge challenge = fixture.order().authorizations().get(0).challenges().get(0);
        Authorization authorization = fixture.order().authorizations().get(0);
        fixture.repository().markChallengeValid(challenge.id());

        HttpResponse<String> response = post(fixture, "/acme/challenge/" + challenge.id(), Map.of());

        assertEquals(200, response.statusCode());
        assertEquals("<http://acme.test/acme/authz/" + authorization.id() + ">;rel=\"up\"",
                response.headers().firstValue("Link").orElseThrow());
    }

    @Test
    void certificateResponseLinksUpToIssuer() throws Exception {
        Fixture fixture = startServerWithOrder();
        repositoryFinalizeOrder(fixture.repository(), fixture.order());

        HttpResponse<String> response = post(fixture, "/acme/cert/" + fixture.order().id(), Map.of());

        assertEquals(200, response.statusCode());
        assertEquals("<http://acme.test/issuer/root.pem>;rel=\"up\"",
                response.headers().firstValue("Link").orElseThrow());
        assertTrue(response.body().contains("BEGIN CERTIFICATE"));
    }

    private Fixture startServerWithOrder() throws Exception {
        DataSource dataSource = AcmeTestSupport.dataSource();
        AcmeConfig config = AcmeTestSupport.config();
        AcmeRepository repository = new AcmeRepository(dataSource);
        NonceService nonceService = new NonceService();
        AcmeJwsService jwsService = new AcmeJwsService(repository, nonceService);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        java.security.KeyPair keyPair = generator.generateKeyPair();
        RSAKey key = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID("test-key")
                .build();
        Account account = repository.createAccount(
                key.computeThumbprint().toString(),
                key.toPublicJWK().toJSONString(),
                "[]",
                true);
        Order order = repository.createOrder(account, List.of(new Identifier("dns", "example.test")), config);
        CertificateAuthorityService caService = CertificateAuthorityService.loadOrCreate(config, repository);
        AcmeServer server = new AcmeServer(
                config,
                repository,
                caService,
                nonceService,
                jwsService,
                new ChallengeValidationService(config));
        app = server.app().start(0);
        return new Fixture(repository, nonceService, key, account, order, app.port());
    }

    private HttpResponse<String> post(Fixture fixture, String path, Map<String, Object> payload) throws Exception {
        String url = "http://acme.test" + path;
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + fixture.port() + path))
                .header("Content-Type", "application/jose+json")
                .POST(HttpRequest.BodyPublishers.ofString(jws(fixture, url, payload)))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private String jws(Fixture fixture, String url, Map<String, Object> payload) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JOSE_JSON)
                .keyID("http://acme.test/acme/account/" + fixture.account().id())
                .customParam("nonce", fixture.nonceService().create())
                .customParam("url", url)
                .build();
        JWSObject object = new JWSObject(header, new Payload(Json.MAPPER.writeValueAsString(payload)));
        object.sign(new RSASSASigner(fixture.key()));
        String[] parts = object.serialize().split("\\.");
        return Json.MAPPER.writeValueAsString(Map.of(
                "protected", parts[0],
                "payload", parts[1],
                "signature", parts[2]));
    }

    private void repositoryFinalizeOrder(AcmeRepository repository, Order order) {
        repository.finalizeOrder(order.id(), new byte[]{1, 2, 3},
                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n");
    }

    private record Fixture(
            AcmeRepository repository,
            NonceService nonceService,
            RSAKey key,
            Account account,
            Order order,
            int port) {
    }
}
