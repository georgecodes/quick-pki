package com.elevenware.quickpki.certapi;

import java.net.URI;
import java.time.Duration;

/**
 * Runtime configuration, sourced entirely from environment variables so the
 * service can be configured the same way in Docker and Kubernetes.
 *
 * @param requiredScope the OAuth scope a bearer token must carry to issue
 *                       certificates, or {@code null} to accept any active token
 */
record CertApiConfig(
        int port,
        String externalUrl,
        String databaseUrl,
        String databaseUser,
        String databasePassword,
        String caKeyPassword,
        Duration certificateLifetime,
        String introspectionUrl,
        String introspectionClientId,
        String introspectionClientSecret,
        String requiredScope,
        Duration introspectionTimeout
) {

    static CertApiConfig fromEnv() {
        int port = intEnv("PORT", 8080);
        String externalUrl = trimTrailingSlash(env("CERT_API_EXTERNAL_URL", "http://localhost:" + port));
        URI.create(externalUrl);

        String caKeyPassword = env("CERT_API_CA_KEY_PASSWORD", null);
        if (caKeyPassword == null || caKeyPassword.length() < 12) {
            throw new IllegalArgumentException(
                    "CERT_API_CA_KEY_PASSWORD must be set and at least 12 characters");
        }

        String introspectionUrl = env("OAUTH_INTROSPECTION_URL", null);
        if (introspectionUrl == null) {
            throw new IllegalArgumentException(
                    "OAUTH_INTROSPECTION_URL must be set to the OAuth 2.0 token introspection endpoint");
        }
        URI.create(introspectionUrl);

        String clientId = env("OAUTH_CLIENT_ID", null);
        String clientSecret = env("OAUTH_CLIENT_SECRET", null);
        if (clientId == null || clientSecret == null) {
            throw new IllegalArgumentException(
                    "OAUTH_CLIENT_ID and OAUTH_CLIENT_SECRET must be set; the API authenticates "
                            + "to the introspection endpoint as a confidential client");
        }

        return new CertApiConfig(
                port,
                externalUrl,
                env("JDBC_URL", "jdbc:postgresql://localhost:5432/quickpki"),
                env("JDBC_USER", "quickpki"),
                env("JDBC_PASSWORD", "quickpki"),
                caKeyPassword,
                Duration.ofDays(intEnv("CERT_API_CERTIFICATE_DAYS", 90)),
                introspectionUrl,
                clientId,
                clientSecret,
                env("OAUTH_REQUIRED_SCOPE", null),
                Duration.ofSeconds(intEnv("OAUTH_INTROSPECTION_TIMEOUT_SECONDS", 5))
        );
    }

    String url(String path) {
        return externalUrl + path;
    }

    private static String env(String name, String defaultValue) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return value;
    }

    private static int intEnv(String name, int defaultValue) {
        String value = env(name, null);
        return value == null ? defaultValue : Integer.parseInt(value);
    }

    private static String trimTrailingSlash(String value) {
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }
}
