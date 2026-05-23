package com.elevenware.quickpki.certapi;

import com.elevenware.quickpki.CertificateProfile;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.router.JavalinDefaultRoutingApi;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.SQLException;
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

    // Bound on how long the readiness probe waits to validate a pooled
    // connection: short enough that a stalled database fails the probe
    // promptly rather than letting Kubernetes' own probe timeout fire.
    private static final int READINESS_TIMEOUT_SECONDS = 2;

    private final CertApiConfig config;
    private final CertApiRepository repository;
    private final CertificateAuthorityService caService;
    private final TokenIntrospector introspector;
    private final DataSource dataSource;
    private final String openApiSpec;

    CertApiServer(
            CertApiConfig config,
            CertApiRepository repository,
            CertificateAuthorityService caService,
            TokenIntrospector introspector,
            DataSource dataSource) {
        this.config = config;
        this.repository = repository;
        this.caService = caService;
        this.introspector = introspector;
        this.dataSource = dataSource;
        // The static spec uses a placeholder server URL so the served copy
        // reflects however this instance is actually reached.
        this.openApiSpec = loadResource("/openapi.yaml")
                .replace("__SERVER_URL__", config.externalUrl());
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
        routes.post("/v1/openssl-configs/brcac", this::brcacOpensslConfig);
        routes.post("/v1/openssl-configs/brseal", this::brsealOpensslConfig);
        routes.get("/issuer/root.pem", ctx -> ctx.contentType("application/pem-certificate-chain")
                .result(caService.issuerPem()));
        routes.get("/healthz", this::liveness);
        routes.get("/readyz", this::readiness);
        routes.get("/openapi.yaml", ctx -> ctx.contentType("application/yaml").result(openApiSpec));
        routes.get("/docs", ctx -> ctx.contentType("text/html").result(DOCS_PAGE));
    }

    // Liveness probe: confirms only that the process is up and can serve HTTP.
    // It deliberately touches no dependencies, so a transient database outage
    // sheds traffic via the readiness probe instead of restarting every pod.
    private void liveness(Context ctx) {
        ctx.json(Map.of("status", "alive"));
    }

    // Readiness probe: confirms the service can actually do work, which means
    // its database is reachable. A failure here removes the pod from the
    // Service's endpoints until the dependency recovers — no restart.
    private void readiness(Context ctx) {
        try (Connection connection = dataSource.getConnection()) {
            if (connection.isValid(READINESS_TIMEOUT_SECONDS)) {
                ctx.json(Map.of("status", "ready"));
                return;
            }
            LOG.warn("Readiness check failed: database connection is not valid");
        } catch (SQLException e) {
            LOG.warn("Readiness check failed: database is unreachable", e);
        }
        ctx.status(503).json(Map.of("status", "unavailable", "detail", "database unreachable"));
    }

    // A self-contained API reference page; pulls Redoc from a CDN and renders
    // the spec served at /openapi.yaml (relative, so any base path works).
    private static final String DOCS_PAGE = """
            <!doctype html>
            <html>
            <head>
              <title>Quick-PKI Certificate API</title>
              <meta charset="utf-8"/>
              <meta name="viewport" content="width=device-width, initial-scale=1"/>
            </head>
            <body>
              <redoc spec-url="openapi.yaml"></redoc>
              <script src="https://cdn.redocly.com/redoc/latest/bundles/redoc.standalone.js"></script>
            </body>
            </html>
            """;

    private static String loadResource(String path) {
        try (InputStream in = CertApiServer.class.getResourceAsStream(path)) {
            if (in == null) {
                throw new IllegalStateException("missing classpath resource " + path);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("could not read classpath resource " + path, e);
        }
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
        CertificateProfile profile = resolveProfile(request.profile());
        persistAndRespond(ctx, caService.issue(csr, profile));
    }

    private void brcacOpensslConfig(Context ctx) {
        BrcacOpensslConfigRequest request = parseBody(ctx, BrcacOpensslConfigRequest.class,
                "a JSON body with the BRCAC subject attributes");
        String config = OpensslConfigs.forBrcac(request);
        ctx.json(new OpensslConfigResponse("brcac.cnf", base64(config)));
    }

    private void brsealOpensslConfig(Context ctx) {
        BrsealOpensslConfigRequest request = parseBody(ctx, BrsealOpensslConfigRequest.class,
                "a JSON body with the BRSEAL subject attributes");
        String config = OpensslConfigs.forBrseal(request);
        ctx.json(new OpensslConfigResponse("brseal.cnf", base64(config)));
    }

    private void persistAndRespond(Context ctx, CertificateAuthorityService.Issued issued) {
        X509Certificate certificate = issued.certificate();
        UUID id = UUID.randomUUID();
        String clientId = ctx.attribute("clientId");
        IssuedCertificate stored = new IssuedCertificate(
                id,
                certificate.getSerialNumber().toString(16),
                certificate.getSubjectX500Principal().getName(),
                issued.certificatePem(),
                issued.chainPem(),
                issued.csrPem(),
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
        if (certificate.csrPem() != null) {
            json.put("csr", base64(certificate.csrPem()));
        }
        json.put("notBefore", certificate.notBefore().toString());
        json.put("notAfter", certificate.notAfter().toString());
        json.put("issuedAt", certificate.createdAt().toString());
        return json;
    }

    private static String base64(String pem) {
        return Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));
    }

    // Maps the optional request 'profile' field onto a CertificateProfile,
    // turning an unknown name into a 400 rather than a 500.
    private static CertificateProfile resolveProfile(String name) {
        try {
            return CertificateProfile.fromName(name);
        } catch (IllegalArgumentException e) {
            throw new CertApiException(400, "invalid_request", e.getMessage());
        }
    }

    private CertificateRequest parseRequest(Context ctx) {
        return parseBody(ctx, CertificateRequest.class,
                "a JSON object with a base64-encoded 'csr' field");
    }

    private <T> T parseBody(Context ctx, Class<T> type, String shape) {
        try {
            T request = Json.MAPPER.readValue(ctx.body(), type);
            if (request == null) {
                throw new CertApiException(400, "invalid_request", "a JSON request body is required");
            }
            return request;
        } catch (CertApiException e) {
            throw e;
        } catch (Exception e) {
            throw new CertApiException(400, "invalid_request",
                    "request body must be " + shape);
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
        // Kubernetes polls the probes every few seconds; logging each hit
        // would bury genuine request traffic, so leave them out.
        String path = ctx.path();
        if (path.equals("/healthz") || path.equals("/readyz")) {
            return;
        }
        Long startedAtNanos = ctx.attribute("startedAtNanos");
        long durationMs = startedAtNanos == null ? -1L : (System.nanoTime() - startedAtNanos) / 1_000_000L;
        LOG.info("request method={} path={} status={} durationMs={} remote={}",
                ctx.method(), ctx.path(), ctx.statusCode(), durationMs, ctx.ip());
    }
}
