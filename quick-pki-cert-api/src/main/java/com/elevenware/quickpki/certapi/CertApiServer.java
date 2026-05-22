package com.elevenware.quickpki.certapi;

import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.router.JavalinDefaultRoutingApi;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * The HTTP surface of the certificate issuance API.
 * <p>
 * Routes under {@code /v1} are an OAuth 2.0 protected resource: each request
 * must carry a bearer token, which is validated by introspection against the
 * external authorization server before the request is served. The issuer
 * certificate and health endpoints are deliberately left unauthenticated.
 */
final class CertApiServer {

    private static final Logger LOG = LoggerFactory.getLogger(CertApiServer.class);

    private final CertApiConfig config;
    private final CertApiRepository repository;
    private final CertificateAuthorityService caService;
    private final TokenIntrospector introspector;

    CertApiServer(
            CertApiConfig config,
            CertApiRepository repository,
            CertificateAuthorityService caService,
            TokenIntrospector introspector) {
        this.config = config;
        this.repository = repository;
        this.caService = caService;
        this.introspector = introspector;
    }

    void start() {
        app().start(config.port());
    }

    Javalin app() {
        return Javalin.create(javalinConfig -> {
            javalinConfig.http.defaultContentType = "application/json";
            javalinConfig.routes.before(ctx -> ctx.attribute("startedAtNanos", System.nanoTime()));
            javalinConfig.routes.before(this::authenticate);
            routes(javalinConfig.routes);
            javalinConfig.routes.after(this::logRequest);
            javalinConfig.routes.exception(CertApiException.class, this::handleException);
            // Unexpected exceptions: log the real cause server-side and return
            // a generic body so internal details never reach the caller.
            javalinConfig.routes.exception(Exception.class, (e, ctx) -> {
                LOG.error("Unhandled exception serving request path={}", ctx.path(), e);
                handleException(new CertApiException(500, "server_error", "internal server error"), ctx);
            });
        });
    }

    private void routes(JavalinDefaultRoutingApi routes) {
        routes.post("/v1/certificates", this::issueCertificate);
        routes.get("/v1/certificates/{id}", this::getCertificate);
        routes.get("/issuer/root.pem", ctx -> ctx.contentType("application/pem-certificate-chain")
                .result(caService.issuerPem()));
        routes.get("/healthz", ctx -> ctx.result("ok"));
    }

    // Bearer-token gate for the protected resource. Registered as a pathless
    // 'before' filter (Javalin's typed path filters vary across versions), so
    // it self-selects on the /v1 prefix and lets public routes through.
    private void authenticate(Context ctx) {
        if (!ctx.path().startsWith("/v1/")) {
            return;
        }
        String header = ctx.header("Authorization");
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new CertApiException(401, "invalid_token",
                    "a Bearer access token is required to call this API");
        }
        String token = header.substring(7).trim();
        if (token.isEmpty()) {
            throw new CertApiException(401, "invalid_token", "the Bearer access token is empty");
        }
        TokenIntrospector.Introspection introspection = introspector.introspect(token);
        if (!introspection.active()) {
            throw new CertApiException(401, "invalid_token",
                    "the access token is expired, revoked, or otherwise invalid");
        }
        if (config.requiredScope() != null && !introspection.scopes().contains(config.requiredScope())) {
            throw new CertApiException(403, "insufficient_scope",
                    "the access token is missing the required scope '" + config.requiredScope() + "'");
        }
        ctx.attribute("clientId", introspection.clientId());
        LOG.debug("Authorized request clientId={} path={}", introspection.clientId(), ctx.path());
    }

    private void issueCertificate(Context ctx) {
        CertificateRequest request = parseRequest(ctx);
        PKCS10CertificationRequest csr = Csrs.parse(request.csr());
        CertificateAuthorityService.Issued issued = caService.issue(csr);

        X509Certificate certificate = issued.certificate();
        UUID id = UUID.randomUUID();
        String clientId = ctx.attribute("clientId");
        IssuedCertificate stored = new IssuedCertificate(
                id,
                certificate.getSerialNumber().toString(16),
                certificate.getSubjectX500Principal().getName(),
                issued.certificatePem(),
                issued.chainPem(),
                certificate.getNotBefore().toInstant(),
                certificate.getNotAfter().toInstant(),
                clientId,
                Instant.now());
        repository.saveCertificate(stored);

        LOG.info("Issued certificate id={} serial={} subject={} clientId={}",
                id, stored.serialNumber(), stored.subjectDn(), clientId);
        ctx.status(201)
                .header("Location", config.url("/v1/certificates/" + id))
                .json(certificateJson(stored));
    }

    private void getCertificate(Context ctx) {
        UUID id = uuid(ctx.pathParam("id"));
        IssuedCertificate certificate = repository.loadCertificate(id)
                .orElseThrow(() -> new CertApiException(404, "not_found", "certificate not found"));
        ctx.json(certificateJson(certificate));
    }

    // The issued certificate and chain are returned base64-encoded, mirroring
    // how the CSR arrives, so a caller round-trips the same encoding.
    private Map<String, Object> certificateJson(IssuedCertificate certificate) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("id", certificate.id().toString());
        json.put("serialNumber", certificate.serialNumber());
        json.put("subject", certificate.subjectDn());
        json.put("certificate", base64(certificate.certificatePem()));
        json.put("chain", base64(certificate.chainPem()));
        json.put("notBefore", certificate.notBefore().toString());
        json.put("notAfter", certificate.notAfter().toString());
        json.put("issuedAt", certificate.createdAt().toString());
        return json;
    }

    private static String base64(String pem) {
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    private CertificateRequest parseRequest(Context ctx) {
        try {
            CertificateRequest request = Json.MAPPER.readValue(ctx.body(), CertificateRequest.class);
            if (request == null) {
                throw new CertApiException(400, "invalid_request", "a JSON request body is required");
            }
            return request;
        } catch (CertApiException e) {
            throw e;
        } catch (Exception e) {
            throw new CertApiException(400, "invalid_request",
                    "request body must be a JSON object with a base64-encoded 'csr' field");
        }
    }

    private UUID uuid(String value) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new CertApiException(404, "not_found", "certificate not found");
        }
    }

    private void handleException(CertApiException e, Context ctx) {
        if (e.status() >= 500) {
            LOG.error("Request failed status={} error={} path={} detail={}",
                    e.status(), e.error(), ctx.path(), e.getMessage());
        } else {
            LOG.warn("Request rejected status={} error={} path={} detail={}",
                    e.status(), e.error(), ctx.path(), e.getMessage());
        }
        if (e.status() == 401 || e.status() == 403) {
            ctx.header("WWW-Authenticate", "Bearer error=\"" + e.error()
                    + "\", error_description=\"" + e.getMessage().replace('"', '\'') + "\"");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", e.error());
        body.put("error_description", e.getMessage());
        body.put("status", e.status());
        ctx.status(e.status()).json(body);
    }

    private void logRequest(Context ctx) {
        Long startedAtNanos = ctx.attribute("startedAtNanos");
        long durationMs = startedAtNanos == null ? -1L : (System.nanoTime() - startedAtNanos) / 1_000_000L;
        LOG.info("request method={} path={} status={} durationMs={} remote={}",
                ctx.method(), ctx.path(), ctx.statusCode(), durationMs, ctx.ip());
    }
}
