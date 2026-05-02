package com.elevenware.quickpki.acme;

import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;

record AcmeConfig(
        int port,
        String externalUrl,
        String databaseUrl,
        String databaseUser,
        String databasePassword,
        String adminToken,
        String caKeyPassword,
        Duration certificateLifetime,
        Duration authzLifetime,
        Duration challengeTimeout,
        int challengeAttempts,
        List<String> dnsServers
) {

    static AcmeConfig fromEnv() {
        int port = intEnv("PORT", 8080);
        String externalUrl = trimTrailingSlash(env("ACME_EXTERNAL_URL", "http://localhost:" + port));
        URI.create(externalUrl);
        String caKeyPassword = env("ACME_CA_KEY_PASSWORD", null);
        if (caKeyPassword == null || caKeyPassword.length() < 12) {
            throw new IllegalArgumentException("ACME_CA_KEY_PASSWORD must be set and at least 12 characters");
        }
        return new AcmeConfig(
                port,
                externalUrl,
                env("JDBC_URL", "jdbc:postgresql://localhost:5432/quickpki"),
                env("JDBC_USER", "quickpki"),
                env("JDBC_PASSWORD", "quickpki"),
                env("ACME_ADMIN_TOKEN", ""),
                caKeyPassword,
                Duration.ofDays(intEnv("ACME_CERTIFICATE_DAYS", 90)),
                Duration.ofHours(intEnv("ACME_AUTHZ_HOURS", 1)),
                Duration.ofSeconds(intEnv("ACME_CHALLENGE_TIMEOUT_SECONDS", 5)),
                intEnv("ACME_CHALLENGE_ATTEMPTS", 3),
                csvEnv("ACME_DNS_SERVERS")
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

    private static List<String> csvEnv(String name) {
        String value = env(name, "");
        if (value.isBlank()) {
            return List.of();
        }
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    private static String trimTrailingSlash(String value) {
        while (value.endsWith("/")) {
            value = value.substring(0, value.length() - 1);
        }
        return value;
    }
}
