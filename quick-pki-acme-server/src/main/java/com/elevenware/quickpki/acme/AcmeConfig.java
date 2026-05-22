package com.elevenware.quickpki.acme;

import com.elevenware.quickpki.CertificateProfile;

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
        List<String> dnsServers,
        RemoteIssuerConfig remoteIssuer,
        CertificateProfile certificateProfile
) {

    /**
     * Settings for delegating certificate issuance to a deployed certificate
     * API instead of minting certificates locally.
     * <p>
     * Present only when {@code ACME_CERT_API_URL} is set; a {@code null}
     * {@link #remoteIssuer()} means the server runs its own CA. The credentials
     * are used for the OAuth 2.0 client credentials grant against
     * {@code tokenUrl} to obtain tokens for calls to {@code apiUrl}.
     */
    record RemoteIssuerConfig(
            String apiUrl,
            String tokenUrl,
            String clientId,
            String clientSecret,
            String scope,
            Duration timeout
    ) {
    }

    static AcmeConfig fromEnv() {
        int port = intEnv("PORT", 8080);
        String externalUrl = trimTrailingSlash(env("ACME_EXTERNAL_URL", "http://localhost:" + port));
        URI.create(externalUrl);

        RemoteIssuerConfig remoteIssuer = remoteIssuerFromEnv();

        // The CA key password protects the locally minted CA's private key. It
        // is irrelevant when issuance is delegated to a remote certificate API,
        // so it is only required in local mode.
        String caKeyPassword = env("ACME_CA_KEY_PASSWORD", null);
        if (remoteIssuer == null && (caKeyPassword == null || caKeyPassword.length() < 12)) {
            throw new IllegalArgumentException("ACME_CA_KEY_PASSWORD must be set and at least 12 characters "
                    + "unless ACME_CERT_API_URL delegates issuance to a remote certificate API");
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
                csvEnv("ACME_DNS_SERVERS"),
                remoteIssuer,
                // Defaults to TLS_SERVER: ACME issues domain-validated TLS
                // server certificates, so serverAuth is the right shape.
                CertificateProfile.fromName(env("ACME_CERTIFICATE_PROFILE", "TLS_SERVER"))
        );
    }

    private static RemoteIssuerConfig remoteIssuerFromEnv() {
        String apiUrl = env("ACME_CERT_API_URL", null);
        if (apiUrl == null) {
            return null;
        }
        apiUrl = trimTrailingSlash(apiUrl);
        URI.create(apiUrl);

        String tokenUrl = env("ACME_CERT_API_TOKEN_URL", null);
        String clientId = env("ACME_CERT_API_CLIENT_ID", null);
        String clientSecret = env("ACME_CERT_API_CLIENT_SECRET", null);
        if (tokenUrl == null || clientId == null || clientSecret == null) {
            throw new IllegalArgumentException("ACME_CERT_API_URL requires ACME_CERT_API_TOKEN_URL, "
                    + "ACME_CERT_API_CLIENT_ID and ACME_CERT_API_CLIENT_SECRET so the ACME server can "
                    + "obtain access tokens via the OAuth 2.0 client credentials grant");
        }
        URI.create(tokenUrl);
        return new RemoteIssuerConfig(
                apiUrl,
                tokenUrl,
                clientId,
                clientSecret,
                env("ACME_CERT_API_SCOPE", null),
                Duration.ofSeconds(intEnv("ACME_CERT_API_TIMEOUT_SECONDS", 10)));
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
