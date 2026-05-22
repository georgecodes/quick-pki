package com.elevenware.quickpki.acme;

import com.fasterxml.jackson.databind.JsonNode;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/**
 * Delegates certificate issuance to a deployed Quick-PKI certificate API
 * instead of minting certificates from a CA held by the ACME server itself.
 * <p>
 * The certificate API is an OAuth 2.0 protected resource, so this issuer is
 * also an OAuth client: it obtains access tokens from a configured
 * authorization server using the client credentials grant, caches them until
 * they near expiry, and presents them as bearer tokens on each issuance call.
 * SAN policy ({@link CsrValidation}) is still enforced here - the remote API
 * has no knowledge of ACME authorizations.
 */
final class RemoteCertificateIssuer implements CertificateIssuer {

    private static final Logger LOG = LoggerFactory.getLogger(RemoteCertificateIssuer.class);

    // Used when the token response omits expires_in, and subtracted from a
    // returned lifetime so a token is refreshed before an in-flight call
    // races its expiry.
    private static final long DEFAULT_TOKEN_TTL_SECONDS = 300;
    private static final long TOKEN_REFRESH_SKEW_SECONDS = 30;

    private final URI certificatesEndpoint;
    private final URI issuerEndpoint;
    private final URI tokenEndpoint;
    private final String scope;
    private final String basicAuth;
    private final Duration timeout;
    private final HttpClient http;

    private String cachedToken;
    private Instant tokenExpiresAt = Instant.EPOCH;
    private String cachedIssuerPem;

    private RemoteCertificateIssuer(AcmeConfig.RemoteIssuerConfig config) {
        this.certificatesEndpoint = URI.create(config.apiUrl() + "/v1/certificates");
        this.issuerEndpoint = URI.create(config.apiUrl() + "/issuer/root.pem");
        this.tokenEndpoint = URI.create(config.tokenUrl());
        this.scope = config.scope();
        this.timeout = config.timeout();
        this.basicAuth = "Basic " + Base64.getEncoder().encodeToString(
                (config.clientId() + ":" + config.clientSecret()).getBytes(StandardCharsets.UTF_8));
        this.http = HttpClient.newBuilder()
                .connectTimeout(config.timeout())
                .build();
    }

    static RemoteCertificateIssuer fromConfig(AcmeConfig.RemoteIssuerConfig config) {
        // CSR parsing in CsrValidation relies on BouncyCastle; the local CA
        // registers it, but in remote mode that code path never runs.
        Security.addProvider(new BouncyCastleProvider());
        LOG.info("ACME issuance delegated to remote certificate API url={} tokenUrl={} clientId={} scope={}",
                config.apiUrl(), config.tokenUrl(), config.clientId(),
                config.scope() == null ? "(none)" : config.scope());
        return new RemoteCertificateIssuer(config);
    }

    @Override
    public IssuedCertificate issue(byte[] csrDer, List<Identifier> validatedIdentifiers) {
        // Enforce ACME's "only validated SANs" rule before the CSR leaves this
        // process: the remote API issues whatever the CSR asks for.
        CsrValidation.validate(csrDer, validatedIdentifiers);

        String body;
        try {
            body = Json.MAPPER.writeValueAsString(Map.of(
                    "csr", Base64.getEncoder().encodeToString(csrDer)));
        } catch (Exception e) {
            throw upstream("the certificate request could not be encoded");
        }

        HttpResponse<String> response = postCertificate(body, accessToken(false));
        if (response.statusCode() == 401) {
            // The cached token may have been revoked or rotated server-side;
            // force a fresh one and try once more before giving up.
            response = postCertificate(body, accessToken(true));
        }
        return parseIssued(response);
    }

    @Override
    public synchronized String issuerPem() {
        if (cachedIssuerPem != null) {
            return cachedIssuerPem;
        }
        HttpRequest request = HttpRequest.newBuilder(issuerEndpoint)
                .timeout(timeout)
                .header("Accept", "application/pem-certificate-chain")
                .GET()
                .build();
        HttpResponse<String> response = send(request, "issuer certificate");
        if (response.statusCode() != 200) {
            throw upstream("the certificate API returned HTTP " + response.statusCode()
                    + " for the issuer certificate");
        }
        cachedIssuerPem = response.body();
        return cachedIssuerPem;
    }

    private HttpResponse<String> postCertificate(String body, String token) {
        HttpRequest request = HttpRequest.newBuilder(certificatesEndpoint)
                .timeout(timeout)
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return send(request, "certificate issuance");
    }

    private IssuedCertificate parseIssued(HttpResponse<String> response) {
        if (response.statusCode() == 201) {
            try {
                JsonNode body = Json.MAPPER.readTree(response.body());
                return new IssuedCertificate(
                        decodeBase64(body.path("certificate").asText()),
                        decodeBase64(body.path("chain").asText()));
            } catch (Exception e) {
                LOG.warn("Remote certificate API returned an unreadable response detail={}", e.toString());
                throw upstream("the certificate API returned an unreadable response");
            }
        }
        String detail = errorDetail(response);
        if (response.statusCode() == 400) {
            // A rejected CSR is the client's fault: surface it as such so the
            // ACME client sees a 4xx rather than a retryable server error.
            throw new AcmeException(400, "badCSR", "the certificate API rejected the CSR: " + detail);
        }
        LOG.warn("Remote certificate API returned status={} detail={}", response.statusCode(), detail);
        throw upstream("the certificate API returned HTTP " + response.statusCode());
    }

    private synchronized String accessToken(boolean forceRefresh) {
        if (!forceRefresh && cachedToken != null && Instant.now().isBefore(tokenExpiresAt)) {
            return cachedToken;
        }
        StringBuilder form = new StringBuilder("grant_type=client_credentials");
        if (scope != null) {
            form.append("&scope=").append(URLEncoder.encode(scope, StandardCharsets.UTF_8));
        }
        HttpRequest request = HttpRequest.newBuilder(tokenEndpoint)
                .timeout(timeout)
                .header("Authorization", basicAuth)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(form.toString()))
                .build();
        HttpResponse<String> response = send(request, "access token");
        if (response.statusCode() != 200) {
            LOG.warn("Token endpoint returned status={} url={}", response.statusCode(), tokenEndpoint);
            throw upstream("the authorization server returned HTTP " + response.statusCode()
                    + " for the client credentials grant");
        }
        try {
            JsonNode body = Json.MAPPER.readTree(response.body());
            String token = body.path("access_token").asText(null);
            if (token == null || token.isBlank()) {
                throw upstream("the authorization server response contained no access_token");
            }
            long expiresIn = body.path("expires_in").asLong(DEFAULT_TOKEN_TTL_SECONDS);
            cachedToken = token;
            tokenExpiresAt = Instant.now().plusSeconds(Math.max(expiresIn - TOKEN_REFRESH_SKEW_SECONDS, 1));
            return token;
        } catch (AcmeException e) {
            throw e;
        } catch (Exception e) {
            LOG.warn("Token endpoint response could not be parsed url={} detail={}", tokenEndpoint, e.toString());
            throw upstream("the authorization server token response could not be parsed");
        }
    }

    private HttpResponse<String> send(HttpRequest request, String operation) {
        try {
            return http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw upstream("the " + operation + " request was interrupted");
        } catch (IOException e) {
            LOG.warn("Remote certificate API unreachable operation={} detail={}", operation, e.toString());
            throw upstream("the certificate API is unreachable");
        }
    }

    private static String decodeBase64(String value) {
        return new String(Base64.getMimeDecoder().decode(value.trim()), StandardCharsets.UTF_8);
    }

    private static String errorDetail(HttpResponse<String> response) {
        try {
            JsonNode body = Json.MAPPER.readTree(response.body());
            JsonNode description = body.path("error_description");
            if (!description.isMissingNode()) {
                return description.asText();
            }
        } catch (Exception ignored) {
            // Fall through to a generic detail.
        }
        return "no detail provided";
    }

    // Issuance failed because of the upstream certificate API, not the ACME
    // client; a 5xx tells the client the request is worth retrying.
    private static AcmeException upstream(String detail) {
        return new AcmeException(502, "serverInternal", detail);
    }
}
