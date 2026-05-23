package com.elevenware.quickpki.certapi;

import com.fasterxml.jackson.databind.JsonNode;
import io.javalin.Javalin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Map;
import java.util.logging.Logger;

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
    void issuesACertificateUnderTheRequestedProfile() throws Exception {
        start("certificates:issue");
        String csr = CertApiTestSupport.base64BrsealCsr("Seal Co");

        HttpResponse<String> response = post("/v1/certificates", "active-token",
                "{\"csr\":\"" + csr + "\",\"profile\":\"BRSEAL\"}");

        assertThat(response.statusCode()).isEqualTo(201);
        X509Certificate cert = parseCertificate(Json.MAPPER.readTree(response.body()));
        // BRSEAL: digitalSignature + nonRepudiation, and no EKU extension.
        assertThat(cert.getKeyUsage()[0]).as("digitalSignature").isTrue();
        assertThat(cert.getKeyUsage()[1]).as("nonRepudiation").isTrue();
        assertThat(cert.getExtendedKeyUsage()).as("BRSEAL carries no EKU").isNull();
    }

    @Test
    void rejectsNonCompliantProfileCsrAsBadRequest() throws Exception {
        start("certificates:issue");
        String csr = CertApiTestSupport.base64Csr("seal.example.com");

        HttpResponse<String> response = post("/v1/certificates", "active-token",
                "{\"csr\":\"" + csr + "\",\"profile\":\"BRSEAL\"}");

        assertThat(response.statusCode()).isEqualTo(400);
        JsonNode body = Json.MAPPER.readTree(response.body());
        assertThat(body.get("error").asText()).isEqualTo("bad_csr");
        assertThat(body.get("error_description").asText()).contains("BRSEAL");
    }

    @Test
    void rejectsAnUnknownProfile() throws Exception {
        start("certificates:issue");
        String csr = CertApiTestSupport.base64Csr("service.example.com");

        HttpResponse<String> response = post("/v1/certificates", "active-token",
                "{\"csr\":\"" + csr + "\",\"profile\":\"NONSENSE\"}");

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(Json.MAPPER.readTree(response.body()).get("error").asText()).isEqualTo("invalid_request");
    }

    private static X509Certificate parseCertificate(JsonNode body) throws Exception {
        byte[] pem = Base64.getDecoder().decode(body.get("certificate").asText());
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
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

    @Test
    void servesTheOpenApiDocumentWithoutAuthentication() throws Exception {
        start(null);

        HttpResponse<String> response = get("/openapi.yaml", null);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type")).get().asString()
                .startsWith("application/yaml");
        assertThat(response.body()).contains("openapi: 3.0.3");
        assertThat(response.body()).contains("/v1/certificates");
        // The placeholder is substituted with the configured external URL.
        assertThat(response.body()).doesNotContain("__SERVER_URL__");
    }

    @Test
    void reportsLivenessWithoutAuthentication() throws Exception {
        start(null);

        HttpResponse<String> response = get("/healthz", null);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(Json.MAPPER.readTree(response.body()).get("status").asText()).isEqualTo("alive");
    }

    @Test
    void reportsReadinessWhenTheDatabaseIsReachable() throws Exception {
        start(null);

        HttpResponse<String> response = get("/readyz", null);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(Json.MAPPER.readTree(response.body()).get("status").asText()).isEqualTo("ready");
    }

    @Test
    void reportsNotReadyWhenTheDatabaseIsUnreachable() throws Exception {
        // The service starts against a healthy database, then loses it: the
        // liveness probe stays green while readiness flips to 503.
        ToggleableDataSource dataSource = new ToggleableDataSource(CertApiTestSupport.dataSource());
        start(null, dataSource);
        dataSource.fail();

        HttpResponse<String> readiness = get("/readyz", null);
        assertThat(readiness.statusCode()).isEqualTo(503);
        assertThat(Json.MAPPER.readTree(readiness.body()).get("status").asText()).isEqualTo("unavailable");

        assertThat(get("/healthz", null).statusCode()).isEqualTo(200);
    }

    @Test
    void servesTheApiReferencePage() throws Exception {
        start(null);

        HttpResponse<String> response = get("/docs", null);

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("spec-url=\"openapi.yaml\"");
    }

    private void start(String requiredScope) throws Exception {
        start(requiredScope, CertApiTestSupport.dataSource());
    }

    private void start(String requiredScope, DataSource dataSource) throws Exception {
        String introspectionUrl = "http://localhost:" + authServer.port() + "/introspect";
        CertApiConfig config = CertApiTestSupport.config(introspectionUrl, requiredScope);
        CertApiRepository repository = new CertApiRepository(dataSource);
        CertificateAuthorityService caService = CertificateAuthorityService.loadOrCreate(config, repository);
        TokenIntrospector introspector = TokenIntrospector.fromConfig(config);
        api = new CertApiServer(config, repository, caService, introspector, dataSource).app().start(0);
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

    /**
     * A {@link DataSource} that delegates normally until {@link #fail()} is
     * called, after which every {@code getConnection} throws — standing in for
     * a database that has become unreachable after the service started.
     */
    private static final class ToggleableDataSource implements DataSource {

        private final DataSource delegate;
        private volatile boolean failing;

        ToggleableDataSource(DataSource delegate) {
            this.delegate = delegate;
        }

        void fail() {
            this.failing = true;
        }

        @Override
        public Connection getConnection() throws SQLException {
            if (failing) {
                throw new SQLException("database is unreachable");
            }
            return delegate.getConnection();
        }

        @Override
        public Connection getConnection(String username, String password) throws SQLException {
            return getConnection();
        }

        @Override
        public PrintWriter getLogWriter() throws SQLException {
            return delegate.getLogWriter();
        }

        @Override
        public void setLogWriter(PrintWriter out) throws SQLException {
            delegate.setLogWriter(out);
        }

        @Override
        public void setLoginTimeout(int seconds) throws SQLException {
            delegate.setLoginTimeout(seconds);
        }

        @Override
        public int getLoginTimeout() throws SQLException {
            return delegate.getLoginTimeout();
        }

        @Override
        public Logger getParentLogger() {
            return Logger.getGlobal();
        }

        @Override
        public <T> T unwrap(Class<T> iface) throws SQLException {
            return delegate.unwrap(iface);
        }

        @Override
        public boolean isWrapperFor(Class<?> iface) throws SQLException {
            return delegate.isWrapperFor(iface);
        }
    }
}
