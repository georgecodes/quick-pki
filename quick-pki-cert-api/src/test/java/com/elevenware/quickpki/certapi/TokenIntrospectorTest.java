package com.elevenware.quickpki.certapi;

import io.javalin.Javalin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenIntrospectorTest {

    private Javalin server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop();
        }
    }

    @Test
    void parsesActiveResponseAndAuthenticatesAsConfidentialClient() {
        AtomicReference<String> capturedToken = new AtomicReference<>();
        AtomicReference<String> capturedAuth = new AtomicReference<>();
        server = Javalin.create(cfg -> cfg.routes.post("/introspect", ctx -> {
            capturedToken.set(ctx.formParam("token"));
            capturedAuth.set(ctx.header("Authorization"));
            ctx.json(Map.of(
                    "active", true,
                    "scope", "certificates:issue profile",
                    "client_id", "calling-client"));
        })).start(0);

        TokenIntrospector introspector = new TokenIntrospector(
                "http://localhost:" + server.port() + "/introspect",
                "resource-id", "resource-secret", Duration.ofSeconds(5));

        TokenIntrospector.Introspection result = introspector.introspect("the-token");

        assertThat(result.active()).isTrue();
        assertThat(result.clientId()).isEqualTo("calling-client");
        assertThat(result.scopes()).containsExactlyInAnyOrder("certificates:issue", "profile");
        assertThat(capturedToken.get()).isEqualTo("the-token");
        assertThat(capturedAuth.get()).isEqualTo("Basic " + Base64.getEncoder()
                .encodeToString("resource-id:resource-secret".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void reportsInactiveTokens() {
        server = Javalin.create(cfg -> cfg.routes.post("/introspect",
                ctx -> ctx.json(Map.of("active", false)))).start(0);

        TokenIntrospector introspector = new TokenIntrospector(
                "http://localhost:" + server.port() + "/introspect",
                "resource-id", "resource-secret", Duration.ofSeconds(5));

        TokenIntrospector.Introspection result = introspector.introspect("revoked");

        assertThat(result.active()).isFalse();
        assertThat(result.scopes()).isEmpty();
    }

    @Test
    void unreachableEndpointSurfacesAsServiceUnavailable() {
        TokenIntrospector introspector = new TokenIntrospector(
                "http://localhost:1/introspect", "resource-id", "resource-secret", Duration.ofMillis(500));

        assertThatThrownBy(() -> introspector.introspect("any"))
                .isInstanceOf(CertApiException.class)
                .satisfies(e -> assertThat(((CertApiException) e).status()).isEqualTo(503));
    }
}
