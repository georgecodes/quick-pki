package com.elevenware.quickpki.acme;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class RemoteCertificateIssuerTest {

    private static final String CERT_PEM =
            "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n";
    private static final String CHAIN_PEM = CERT_PEM
            + "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n";
    private static final String ISSUER_PEM =
            "-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----\n";

    private HttpServer server;
    private String baseUrl;
    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicInteger issueRequests = new AtomicInteger();
    private final AtomicReference<String> lastBearer = new AtomicReference<>();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/token", exchange -> {
            tokenRequests.incrementAndGet();
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (auth == null || !auth.startsWith("Basic ")) {
                respond(exchange, 401, "{\"error\":\"invalid_client\"}");
                return;
            }
            respond(exchange, 200, "{\"access_token\":\"tok-" + tokenRequests.get()
                    + "\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
        });
        server.createContext("/v1/certificates", exchange -> {
            issueRequests.incrementAndGet();
            lastBearer.set(exchange.getRequestHeaders().getFirst("Authorization"));
            respond(exchange, 201, "{\"id\":\"" + UUID.randomUUID()
                    + "\",\"certificate\":\"" + base64(CERT_PEM)
                    + "\",\"chain\":\"" + base64(CHAIN_PEM) + "\"}");
        });
        server.createContext("/issuer/root.pem", exchange -> respond(exchange, 200, ISSUER_PEM));
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void issuesCertificateThroughRemoteApi() throws Exception {
        RemoteCertificateIssuer issuer = RemoteCertificateIssuer.fromConfig(remoteConfig());
        byte[] csr = AcmeTestSupport.csrWithDnsSan("example.test");

        CertificateIssuer.IssuedCertificate issued =
                issuer.issue(csr, List.of(new Identifier("dns", "example.test")));

        assertThat(issued.certificatePem()).isEqualTo(CERT_PEM);
        assertThat(issued.chainPem()).isEqualTo(CHAIN_PEM);
        assertThat(lastBearer.get()).startsWith("Bearer tok-");
        assertThat(issueRequests.get()).isEqualTo(1);
    }

    @Test
    void reusesCachedAccessTokenAcrossCalls() throws Exception {
        RemoteCertificateIssuer issuer = RemoteCertificateIssuer.fromConfig(remoteConfig());
        byte[] csr = AcmeTestSupport.csrWithDnsSan("example.test");
        List<Identifier> identifiers = List.of(new Identifier("dns", "example.test"));

        issuer.issue(csr, identifiers);
        issuer.issue(csr, identifiers);

        assertThat(issueRequests.get()).isEqualTo(2);
        assertThat(tokenRequests.get()).isEqualTo(1);
    }

    @Test
    void rejectsUnvalidatedSanWithoutCallingApi() throws Exception {
        RemoteCertificateIssuer issuer = RemoteCertificateIssuer.fromConfig(remoteConfig());
        byte[] csr = AcmeTestSupport.csrWithDnsSan("evil.test");

        AcmeException error = catchThrowableOfType(
                () -> issuer.issue(csr, List.of(new Identifier("dns", "example.test"))),
                AcmeException.class);

        assertThat(error).isNotNull();
        assertThat(error.status()).isEqualTo(400);
        assertThat(error.type()).isEqualTo("badCSR");
        assertThat(issueRequests.get()).isZero();
    }

    @Test
    void fetchesAndCachesIssuerCertificate() {
        RemoteCertificateIssuer issuer = RemoteCertificateIssuer.fromConfig(remoteConfig());

        assertThat(issuer.issuerPem()).isEqualTo(ISSUER_PEM);
        assertThat(issuer.issuerPem()).isEqualTo(ISSUER_PEM);
    }

    private AcmeConfig.RemoteIssuerConfig remoteConfig() {
        return new AcmeConfig.RemoteIssuerConfig(
                baseUrl,
                baseUrl + "/token",
                "acme-client",
                "s3cr3t",
                "certificates:issue",
                Duration.ofSeconds(5));
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String base64(String value) {
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
