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
import java.security.KeyPair;
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
    void issuesABrcacCertificateFromStructuredFields() throws Exception {
        start("certificates:issue");
        KeyPair subscriberKeys = CertApiTestSupport.rsaKeyPair();
        String publicKey = CertApiTestSupport.base64PublicKey(subscriberKeys.getPublic());
        String body = """
                {
                  "publicKey": "%s",
                  "commonName": "transport.example.com",
                  "businessCategory": "Private Organization",
                  "serialNumber": "12345678000199",
                  "organization": "Example Participant Ltda",
                  "stateOrProvince": "SP",
                  "locality": "Sao Paulo",
                  "organizationIdentifier": "OFBBR-12345678",
                  "userId": "software-statement-uuid",
                  "dnsNames": ["transport.example.com"]
                }
                """.formatted(publicKey);

        HttpResponse<String> response = post("/v1/certificates/brcac", "active-token", body);

        assertThat(response.statusCode()).isEqualTo(201);
        JsonNode jsonBody = Json.MAPPER.readTree(response.body());
        // Cert binds the subscriber's public key, even though they never sent a CSR.
        X509Certificate cert = parseCertificate(jsonBody);
        assertThat(cert.getPublicKey()).isEqualTo(subscriberKeys.getPublic());
        // BRCAC: digitalSignature + keyEncipherment, EKU clientAuth only.
        assertThat(cert.getKeyUsage()[0]).as("digitalSignature").isTrue();
        assertThat(cert.getKeyUsage()[2]).as("keyEncipherment").isTrue();
        assertThat(cert.getExtendedKeyUsage())
                .containsExactly("1.3.6.1.5.5.7.3.2"); // clientAuth
        assertThat(jsonBody.get("subject").asText()).contains("CN=transport.example.com");
        // The synthetic CSR is returned and points at the same public key.
        String csrPem = new String(Base64.getDecoder().decode(jsonBody.get("csr").asText()),
                StandardCharsets.UTF_8);
        assertThat(csrPem).contains("BEGIN CERTIFICATE REQUEST");

        // It's persisted: GET returns the same CSR.
        HttpResponse<String> fetched = get("/v1/certificates/" + jsonBody.get("id").asText(),
                "active-token");
        assertThat(fetched.statusCode()).isEqualTo(200);
        assertThat(Json.MAPPER.readTree(fetched.body()).get("csr").asText())
                .isEqualTo(jsonBody.get("csr").asText());
    }

    @Test
    void issuesABrsealCertificateFromStructuredFields() throws Exception {
        start("certificates:issue");
        KeyPair subscriberKeys = CertApiTestSupport.rsaKeyPair();
        String publicKey = CertApiTestSupport.base64PublicKey(subscriberKeys.getPublic());
        String body = """
                {
                  "publicKey": "%s",
                  "commonName": "Seal Co",
                  "userId": "OFBBR-12345678",
                  "organizationUnits": ["Example CA", "12345678000199",
                                        "Validacao por certificado digital"],
                  "responsiblePersonName": "Responsible Person",
                  "companyCnpj": "12345678000199",
                  "responsiblePersonData": "197001010000000000000",
                  "companyCei": "123456789012"
                }
                """.formatted(publicKey);

        HttpResponse<String> response = post("/v1/certificates/brseal", "active-token", body);

        assertThat(response.statusCode()).isEqualTo(201);
        X509Certificate cert = parseCertificate(Json.MAPPER.readTree(response.body()));
        assertThat(cert.getPublicKey()).isEqualTo(subscriberKeys.getPublic());
        // BRSEAL: digitalSignature + nonRepudiation, no EKU.
        assertThat(cert.getKeyUsage()[1]).as("nonRepudiation").isTrue();
        assertThat(cert.getExtendedKeyUsage()).isNull();
    }

    @Test
    void rejectsBrcacRequestMissingThePublicKey() throws Exception {
        start("certificates:issue");

        HttpResponse<String> response = post("/v1/certificates/brcac", "active-token",
                "{\"commonName\":\"transport.example.com\"}");

        assertThat(response.statusCode()).isEqualTo(400);
        JsonNode bodyJson = Json.MAPPER.readTree(response.body());
        assertThat(bodyJson.get("error").asText()).isEqualTo("invalid_request");
        assertThat(bodyJson.get("error_description").asText().toLowerCase()).contains("publickey");
    }

    @Test
    void rejectsBrcacRequestWithMalformedPublicKey() throws Exception {
        start("certificates:issue");
        String body = """
                {
                  "publicKey": "bm90LXBlbQ==",
                  "commonName": "transport.example.com"
                }
                """;

        HttpResponse<String> response = post("/v1/certificates/brcac", "active-token", body);

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(Json.MAPPER.readTree(response.body()).get("error").asText())
                .isEqualTo("invalid_request");
    }

    @Test
    void rejectsBrcacRequestMissingOpenFinanceFields() throws Exception {
        // No businessCategory, no serialNumber: validation inside QuickPki fires.
        start("certificates:issue");
        KeyPair subscriberKeys = CertApiTestSupport.rsaKeyPair();
        String publicKey = CertApiTestSupport.base64PublicKey(subscriberKeys.getPublic());
        String body = """
                {
                  "publicKey": "%s",
                  "commonName": "transport.example.com",
                  "dnsNames": ["transport.example.com"]
                }
                """.formatted(publicKey);

        HttpResponse<String> response = post("/v1/certificates/brcac", "active-token", body);

        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(Json.MAPPER.readTree(response.body()).get("error").asText())
                .isEqualTo("invalid_request");
    }

    @Test
    void brcacAndBrsealEndpointsAreAuthenticated() throws Exception {
        start("certificates:issue");

        HttpResponse<String> brcac = post("/v1/certificates/brcac", "expired-token", "{}");
        assertThat(brcac.statusCode()).isEqualTo(401);

        HttpResponse<String> brseal = post("/v1/certificates/brseal", "expired-token", "{}");
        assertThat(brseal.statusCode()).isEqualTo(401);
    }

    @Test
    void issuedCertificatesEndpointReturnsTheCsrAlongsideTheCert() throws Exception {
        // Round-trip through the existing CSR endpoint: the CSR a caller
        // submitted is now persisted and served back via GET.
        start("certificates:issue");
        String csr = CertApiTestSupport.base64Csr("service.example.com");

        HttpResponse<String> issued = post("/v1/certificates", "active-token",
                "{\"csr\":\"" + csr + "\"}");
        String id = Json.MAPPER.readTree(issued.body()).get("id").asText();

        HttpResponse<String> fetched = get("/v1/certificates/" + id, "active-token");
        assertThat(fetched.statusCode()).isEqualTo(200);
        String csrPem = new String(Base64.getDecoder().decode(
                Json.MAPPER.readTree(fetched.body()).get("csr").asText()),
                StandardCharsets.UTF_8);
        assertThat(csrPem).contains("BEGIN CERTIFICATE REQUEST");
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
