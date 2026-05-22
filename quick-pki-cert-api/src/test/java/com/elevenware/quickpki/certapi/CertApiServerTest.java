package com.elevenware.quickpki.certapi;

import com.fasterxml.jackson.databind.JsonNode;
import io.javalin.Javalin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CertApiServerTest {

    private final HttpClient http = HttpClient.newHttpClient();

    private Javalin authServer;
    private Javalin api;

    @BeforeEach
    void startAuthServer() {
        authServer = Javalin.create(cfg -> cfg.routes.post("/introspect", ctx -> {
            String token = ctx.formParam("token");
            if ("active-token".equals(token)) {
                ctx.json(Map.of("active", true,
                        "scope", "certificates:issue profile",
                        "client_id", "issuing-client"));
            } else if ("no-scope-token".equals(token)) {
                ctx.json(Map.of("active", true,
                        "scope", "profile",
                        "client_id", "issuing-client"));
            } else {
                ctx.json(Map.of("active", false));
            }
        })).start(0);
    }

    @AfterEach
    void stopServers() {
        if (api != null) {
            api.stop();
        }
        if (authServer != null) {
            authServer.stop();
        }
    }

    @Test
    void issuesACertificateForAValidTokenAndPersistsIt() throws Exception {
        start("certificates:issue");
        String csr = CertApiTestSupport.base64Csr("service.example.com");

        HttpResponse<String> response = post("/v1/certificates", "active-token",
                "{\"csr\":\"" + csr + "\"}");

        assertThat(response.statusCode()).isEqualTo(201);
        JsonNode body = Json.MAPPER.readTree(response.body());
        assertThat(body.get("subject").asText()).contains("service.example.com");
        String certificatePem = new String(Base64.getDecoder().decode(body.get("certificate").asText()),
                StandardCharsets.UTF_8);
        assertThat(certificatePem).contains("BEGIN CERTIFICATE");

        // The Location header points at the persisted resource: fetch it back.
        HttpResponse<String> fetched = get("/v1/certificates/" + body.get("id").asText(), "active-token");
        assertThat(fetched.statusCode()).isEqualTo(200);
        assertThat(Json.MAPPER.readTree(fetched.body()).get("serialNumber").asText())
                .isEqualTo(body.get("serialNumber").asText());
    }

    @Test
    void rejectsRequestsWithoutABearerToken() throws Exception {
        start("certificates:issue");

        HttpResponse<String> response = http.send(
                HttpRequest.newBuilder(uri("/v1/certificates"))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString("{\"csr\":\"x\"}"))
                        .build(),
                HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.headers().firstValue("WWW-Authenticate")).isPresent();
        assertThat(Json.MAPPER.readTree(response.body()).get("error").asText()).isEqualTo("invalid_token");
    }

    @Test
    void rejectsInactiveTokens() throws Exception {
        start("certificates:issue");

        HttpResponse<String> response = post("/v1/certificates", "expired-token", "{\"csr\":\"x\"}");

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(Json.MAPPER.readTree(response.body()).get("error").asText()).isEqualTo("invalid_token");
    }

    @Test
    void rejectsTokensMissingTheRequiredScope() throws Exception {
        start("certificates:issue");
        String csr = CertApiTestSupport.base64Csr("service.example.com");

        HttpResponse<String> response = post("/v1/certificates", "no-scope-token",
                "{\"csr\":\"" + csr + "\"}");

        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(Json.MAPPER.readTree(response.body()).get("error").asText()).isEqualTo("insufficient_scope");
    }

    @Test
    void rejectsAMalformedCsr() throws Exception {
        start("certificates:issue");

        HttpResponse<String> response = post("/v1/certificates", "active-token",
                "{\"csr\":\"bm90LWEtY3Ny\"}");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(Json.MAPPER.readTree(response.body()).get("error").asText()).isEqualTo("bad_csr");
    }

    @Test
    void servesTheIssuerCertificateWithoutAuthentication() throws Exception {
        start(null);

        HttpResponse<String> response = get("/issuer/root.pem", null);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("BEGIN CERTIFICATE");
    }

    private void start(String requiredScope) throws Exception {
        DataSource dataSource = CertApiTestSupport.dataSource();
        String introspectionUrl = "http://localhost:" + authServer.port() + "/introspect";
        CertApiConfig config = CertApiTestSupport.config(introspectionUrl, requiredScope);
        CertApiRepository repository = new CertApiRepository(dataSource);
        CertificateAuthorityService caService = CertificateAuthorityService.loadOrCreate(config, repository);
        TokenIntrospector introspector = TokenIntrospector.fromConfig(config);
        api = new CertApiServer(config, repository, caService, introspector).app().start(0);
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + api.port() + path);
    }

    private HttpResponse<String> post(String path, String token, String body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri(path))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String path, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri(path)).GET();
        if (token != null) {
            request.header("Authorization", "Bearer " + token);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
}
