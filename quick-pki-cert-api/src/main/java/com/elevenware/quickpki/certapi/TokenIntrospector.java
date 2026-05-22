package com.elevenware.quickpki.certapi;

import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Validates incoming bearer tokens against an external OAuth 2.0 authorization
 * server using RFC 7662 token introspection.
 * <p>
 * The API is a protected resource: callers obtain tokens elsewhere (typically
 * via the client credentials grant) and present them here. This service does
 * not issue or verify tokens itself - it asks the authorization server whether
 * a token is currently active. It authenticates to the introspection endpoint
 * as a confidential client using HTTP Basic credentials.
 */
final class TokenIntrospector {

    private static final Logger LOG = LoggerFactory.getLogger(TokenIntrospector.class);

    private final URI endpoint;
    private final String basicAuth;
    private final Duration timeout;
    private final HttpClient http;

    TokenIntrospector(String endpoint, String clientId, String clientSecret, Duration timeout) {
        this.endpoint = URI.create(endpoint);
        this.basicAuth = "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        this.timeout = timeout;
        this.http = HttpClient.newBuilder()
                .connectTimeout(timeout)
                .build();
    }

    static TokenIntrospector fromConfig(CertApiConfig config) {
        return new TokenIntrospector(
                config.introspectionUrl(),
                config.introspectionClientId(),
                config.introspectionClientSecret(),
                config.introspectionTimeout());
    }

    Introspection introspect(String token) {
        String form = "token=" + URLEncoder.encode(token, StandardCharsets.UTF_8)
                + "&token_type_hint=access_token";
        HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Authorization", basicAuth)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();

        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw unavailable("token introspection request was interrupted");
        } catch (IOException e) {
            LOG.warn("Token introspection endpoint unreachable url={} detail={}", endpoint, e.toString());
            throw unavailable("the token introspection endpoint is unreachable");
        }

        if (response.statusCode() != 200) {
            LOG.warn("Token introspection endpoint returned status={} url={}", response.statusCode(), endpoint);
            throw unavailable("the token introspection endpoint returned HTTP " + response.statusCode());
        }

        try {
            JsonNode body = Json.MAPPER.readTree(response.body());
            return new Introspection(
                    body.path("active").asBoolean(false),
                    body.path("scope").isMissingNode() ? null : body.path("scope").asText(null),
                    body.path("client_id").isMissingNode() ? null : body.path("client_id").asText(null));
        } catch (Exception e) {
            LOG.warn("Token introspection response could not be parsed url={} detail={}", endpoint, e.toString());
            throw unavailable("the token introspection response could not be parsed");
        }
    }

    private static CertApiException unavailable(String detail) {
        return new CertApiException(503, "introspection_unavailable", detail);
    }

    /**
     * The subset of an RFC 7662 introspection response this API acts on.
     */
    record Introspection(boolean active, String scope, String clientId) {

        Set<String> scopes() {
            if (scope == null || scope.isBlank()) {
                return Set.of();
            }
            return new LinkedHashSet<>(Arrays.asList(scope.trim().split("\\s+")));
        }
    }
}
