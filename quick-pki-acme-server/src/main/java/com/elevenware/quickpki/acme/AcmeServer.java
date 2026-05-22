package com.elevenware.quickpki.acme;

import com.elevenware.quickpki.acme.AcmeJwsService.AcmeRequest;
import com.fasterxml.jackson.core.type.TypeReference;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.router.JavalinDefaultRoutingApi;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

final class AcmeServer {

    private static final Logger LOG = LoggerFactory.getLogger(AcmeServer.class);
    private static final TypeReference<List<Map<String, Object>>> LIST_OF_MAPS = new TypeReference<>() {
    };
    private static final String ADMIN_AUTH_SCHEME = "Bearer ";

    private final AcmeConfig config;
    private final AcmeRepository repository;
    private final AtomicReference<CertificateIssuer> certificateIssuer;
    private final NonceService nonceService;
    private final AcmeJwsService jwsService;
    private final ChallengeValidationService challengeValidationService;

    AcmeServer(
            AcmeConfig config,
            AcmeRepository repository,
            CertificateIssuer certificateIssuer,
            NonceService nonceService,
            AcmeJwsService jwsService,
            ChallengeValidationService challengeValidationService) {
        this.config = config;
        this.repository = repository;
        this.certificateIssuer = new AtomicReference<>(certificateIssuer);
        this.nonceService = nonceService;
        this.jwsService = jwsService;
        this.challengeValidationService = challengeValidationService;
    }

    void start() {
        app().start(config.port());
    }

    Javalin app() {
        Javalin app = Javalin.create(javalinConfig -> {
            javalinConfig.http.defaultContentType = "application/json";
            javalinConfig.routes.before(ctx -> ctx.attribute("startedAtNanos", System.nanoTime()));
            routes(javalinConfig.routes);
            javalinConfig.routes.after(this::logRequest);
            javalinConfig.routes.exception(AcmeException.class, this::handleAcmeException);
            // Unexpected exceptions: log the real message + stack trace
            // server-side and return a generic problem document so we don't
            // leak internal details (stack frames, JDBC errors, internal
            // hostnames) to ACME clients.
            javalinConfig.routes.exception(Exception.class, (e, ctx) -> {
                LOG.error("Unhandled exception serving ACME request path={}", ctx.path(), e);
                handleAcmeException(
                        new AcmeException(500, "serverInternal", "internal server error"), ctx);
            });
        });
        return app;
    }

    private void routes(JavalinDefaultRoutingApi routes) {
        routes.get("/acme/directory", this::directory);
        routes.head("/acme/new-nonce", this::newNonce);
        routes.get("/acme/new-nonce", this::newNonce);
        routes.post("/acme/new-account", this::newAccount);
        routes.post("/acme/account/{id}", this::account);
        routes.post("/acme/account/{id}/orders", this::accountOrders);
        routes.post("/acme/new-order", this::newOrder);
        routes.post("/acme/order/{id}", this::order);
        routes.post("/acme/authz/{id}", this::authorization);
        routes.post("/acme/challenge/{id}", this::challenge);
        routes.post("/acme/finalize/{id}", this::finalizeOrder);
        routes.post("/acme/cert/{id}", this::certificate);
        routes.get("/issuer/root.pem", ctx -> ctx.contentType("application/pem-certificate-chain")
                .result(certificateIssuer.get().issuerPem()));
        routes.post("/admin/ca/rotate", this::rotateCa);
        routes.post("/ocsp", this::ocsp);
        routes.get("/healthz", ctx -> ctx.result("ok"));
    }

    private void directory(Context ctx) {
        ctx.json(Map.of(
                "newNonce", config.url("/acme/new-nonce"),
                "newAccount", config.url("/acme/new-account"),
                "newOrder", config.url("/acme/new-order"),
                "meta", Map.of(
                        "website", "https://github.com/georgecodes/quick-pki",
                        "externalAccountRequired", false
                )
        ));
    }

    private void newNonce(Context ctx) {
        addNonce(ctx);
        ctx.status(204);
    }

    private void newAccount(Context ctx) throws Exception {
        AcmeRequest request = jwsService.read(ctx.body(), false);
        String thumbprint = jwsService.thumbprint(request.jwk());
        boolean onlyReturnExisting = Boolean.TRUE.equals(request.payload().get("onlyReturnExisting"));
        Account account = repository.findAccountByThumbprint(thumbprint).orElse(null);
        if (account == null && onlyReturnExisting) {
            throw new AcmeException(400, "accountDoesNotExist", "ACME account does not exist");
        }
        boolean created = false;
        if (account == null) {
            String contactJson = Json.MAPPER.writeValueAsString(request.payload().getOrDefault("contact", List.of()));
            boolean termsAgreed = Boolean.TRUE.equals(request.payload().get("termsOfServiceAgreed"));
            account = repository.createAccount(thumbprint, request.jwk().toPublicJWK().toJSONString(), contactJson, termsAgreed);
            created = true;
            LOG.info("Created ACME account accountId={} thumbprint={} termsAgreed={}",
                    account.id(), account.keyThumbprint(), termsAgreed);
        } else {
            LOG.debug("Returned existing ACME account accountId={} thumbprint={}",
                    account.id(), account.keyThumbprint());
        }
        addNonce(ctx);
        ctx.header("Location", accountUrl(account.id()));
        ctx.status(created ? 201 : 200).json(accountJson(account));
    }

    private void newOrder(Context ctx) {
        AcmeRequest request = jwsService.read(ctx.body(), true);
        List<Identifier> identifiers = identifiersFromPayload(request.payload());
        if (identifiers.isEmpty()) {
            throw new AcmeException(400, "malformed", "newOrder requires at least one identifier");
        }
        Order order = repository.createOrder(request.account(), identifiers, config);
        LOG.info("Created ACME order orderId={} accountId={} identifiers={}",
                order.id(), request.account().id(), identifiers);
        addNonce(ctx);
        ctx.header("Location", orderUrl(order.id()));
        ctx.status(201).json(orderJson(order));
    }

    private void account(Context ctx) throws Exception {
        AcmeRequest request = jwsService.read(ctx.body(), true);
        UUID accountId = uuid(ctx.pathParam("id"));
        if (!request.account().id().equals(accountId)) {
            throw new AcmeException(403, "unauthorized", "account key does not match requested account");
        }
        addNonce(ctx);
        ctx.header("Location", accountUrl(accountId));
        ctx.json(accountJson(request.account()));
    }

    private void accountOrders(Context ctx) {
        AcmeRequest request = jwsService.read(ctx.body(), true);
        UUID accountId = uuid(ctx.pathParam("id"));
        if (!request.account().id().equals(accountId)) {
            throw new AcmeException(403, "unauthorized", "account key does not match requested account");
        }
        addNonce(ctx);
        ctx.json(Map.of("orders", repository.loadOrdersForAccount(accountId).stream()
                .map(order -> orderUrl(order.id()))
                .toList()));
    }

    private void order(Context ctx) {
        jwsService.read(ctx.body(), true);
        Order order = loadOrder(ctx.pathParam("id"));
        addNonce(ctx);
        ctx.json(orderJson(order));
    }

    private void authorization(Context ctx) {
        jwsService.read(ctx.body(), true);
        Authorization authorization = repository.loadAuthorization(uuid(ctx.pathParam("id")))
                .orElseThrow(() -> new AcmeException(404, "malformed", "authorization not found"));
        addNonce(ctx);
        ctx.json(authorizationJson(authorization));
    }

    private void challenge(Context ctx) throws Exception {
        AcmeRequest request = jwsService.read(ctx.body(), true);
        UUID challengeId = uuid(ctx.pathParam("id"));
        Challenge challenge = repository.loadChallenge(challengeId)
                .orElseThrow(() -> new AcmeException(404, "malformed", "challenge not found"));
        Authorization authorization = repository.loadAuthorizationForChallenge(challengeId)
                .orElseThrow(() -> new AcmeException(404, "malformed", "authorization not found"));
        if (!"valid".equals(challenge.status())) {
            try {
                challengeValidationService.validate(authorization, challenge, request.account().keyThumbprint());
                repository.markChallengeValid(challengeId);
                LOG.info("Marked ACME challenge valid challengeId={} authorizationId={} orderId={}",
                        challengeId, authorization.id(), authorization.orderId());
            } catch (AcmeException e) {
                repository.markChallengeInvalid(challengeId, problemJson(e));
                LOG.warn("Marked ACME challenge invalid challengeId={} authorizationId={} orderId={} type={} detail={}",
                        challengeId, authorization.id(), authorization.orderId(), e.type(), e.getMessage());
                throw e;
            }
        }
        addNonce(ctx);
        ctx.header("Link", "<" + authzUrl(authorization.id()) + ">;rel=\"up\"");
        ctx.json(challengeJson(repository.loadChallenge(challengeId).orElseThrow()));
    }

    private void finalizeOrder(Context ctx) {
        AcmeRequest request = jwsService.read(ctx.body(), true);
        Order order = loadOrder(ctx.pathParam("id"));
        if (!order.accountId().equals(request.account().id())) {
            throw new AcmeException(403, "unauthorized", "order belongs to a different account");
        }
        if (!"ready".equals(order.status())) {
            throw new AcmeException(403, "orderNotReady", "all authorizations must be valid before finalization");
        }
        String csr = request.string("csr")
                .orElseThrow(() -> new AcmeException(400, "badCSR", "finalize request missing csr"));
        byte[] csrDer = Base64Url.decode(csr);
        List<Identifier> validIdentifiers = order.authorizations().stream()
                .filter(a -> "valid".equals(a.status()))
                .map(Authorization::identifier)
                .toList();
        CertificateIssuer.IssuedCertificate issued = certificateIssuer.get().issue(csrDer, validIdentifiers);
        repository.finalizeOrder(order.id(), csrDer, issued.certificatePem(), issued.chainPem());
        LOG.info("Finalized ACME order orderId={} accountId={} identifiers={}",
                order.id(), request.account().id(), validIdentifiers);
        addNonce(ctx);
        ctx.json(orderJson(loadOrder(order.id().toString())));
    }

    private void certificate(Context ctx) {
        AcmeRequest request = jwsService.read(ctx.body(), true);
        Order order = loadOrder(ctx.pathParam("id"));
        if (!order.accountId().equals(request.account().id())) {
            throw new AcmeException(403, "unauthorized", "certificate belongs to a different account");
        }
        if (!"valid".equals(order.status()) || order.chainPem() == null) {
            throw new AcmeException(404, "malformed", "certificate is not available");
        }
        LOG.info("Served ACME certificate orderId={} accountId={}", order.id(), request.account().id());
        addNonce(ctx);
        ctx.header("Link", "<" + config.url("/issuer/root.pem") + ">;rel=\"up\"");
        ctx.contentType("application/pem-certificate-chain").result(order.chainPem());
    }

    private void ocsp(Context ctx) throws Exception {
        byte[] response = new OCSPRespBuilder()
                .build(OCSPRespBuilder.UNAUTHORIZED, null)
                .getEncoded();
        ctx.contentType("application/ocsp-response").result(new ByteArrayInputStream(response));
    }

    private void rotateCa(Context ctx) {
        requireAdmin(ctx);
        if (config.remoteIssuer() != null) {
            throw new AcmeException(409, "rotationUnsupported",
                    "CA rotation is unavailable: this server delegates issuance to a remote certificate API");
        }
        CertificateAuthorityService rotated = CertificateAuthorityService.rotate(config, repository);
        certificateIssuer.set(rotated);
        LOG.warn("Rotated active ACME CA issuerName={}", rotated.issuerName());
        ctx.json(Map.of(
                "issuerName", rotated.issuerName(),
                "rotated", true
        ));
    }

    private void requireAdmin(Context ctx) {
        String configuredToken = config.adminToken();
        String authorization = ctx.header("Authorization");
        if (configuredToken == null || configuredToken.isBlank()
                || authorization == null
                || !authorization.equals(ADMIN_AUTH_SCHEME + configuredToken)) {
            throw new AcmeException(403, "unauthorized", "admin token is missing or invalid");
        }
    }

    private Map<String, Object> orderJson(Order order) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("status", order.status());
        json.put("expires", order.expiresAt().toString());
        json.put("identifiers", repository.identifiers(order).stream()
                .map(identifier -> Map.of("type", identifier.type(), "value", identifier.value()))
                .toList());
        json.put("authorizations", order.authorizations().stream()
                .map(a -> authzUrl(a.id()))
                .toList());
        json.put("finalize", finalizeUrl(order.id()));
        if (order.chainPem() != null) {
            json.put("certificate", certificateUrl(order.id()));
        }
        return json;
    }

    private Map<String, Object> authorizationJson(Authorization authorization) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("identifier", Map.of("type", authorization.identifierType(), "value", authorization.identifierValue()));
        json.put("status", authorization.status());
        json.put("expires", authorization.expiresAt().toString());
        if (authorization.wildcard()) {
            json.put("wildcard", true);
        }
        json.put("challenges", authorization.challenges().stream().map(this::challengeJson).toList());
        return json;
    }

    private Map<String, Object> challengeJson(Challenge challenge) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("type", challenge.type());
        json.put("url", challengeUrl(challenge.id()));
        json.put("status", challenge.status());
        json.put("token", challenge.token());
        if (challenge.validatedAt() != null) {
            json.put("validated", challenge.validatedAt().toString());
        }
        if (challenge.errorJson() != null) {
            try {
                json.put("error", Json.MAPPER.readValue(challenge.errorJson(), Map.class));
            } catch (Exception ignored) {
                json.put("error", challenge.errorJson());
            }
        }
        return json;
    }

    private Map<String, Object> accountJson(Account account) throws Exception {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("status", account.status());
        json.put("orders", config.url("/acme/account/" + account.id() + "/orders"));
        json.put("contact", Json.MAPPER.readValue(account.contactJson(), List.class));
        return json;
    }

    private List<Identifier> identifiersFromPayload(Map<String, Object> payload) {
        Object raw = payload.get("identifiers");
        if (raw == null) {
            return List.of();
        }
        List<Map<String, Object>> values = Json.MAPPER.convertValue(raw, LIST_OF_MAPS);
        List<Identifier> identifiers = new ArrayList<>();
        for (Map<String, Object> value : values) {
            String type = String.valueOf(value.get("type"));
            String identifier = String.valueOf(value.get("value"));
            if (!"dns".equals(type) && !"ip".equals(type)) {
                throw new AcmeException(400, "malformed", "identifier type must be dns or ip");
            }
            identifiers.add(new Identifier(type, identifier));
        }
        return identifiers;
    }

    private Order loadOrder(String id) {
        return repository.loadOrder(uuid(id))
                .orElseThrow(() -> new AcmeException(404, "malformed", "order not found"));
    }

    private UUID uuid(String id) {
        try {
            return UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            throw new AcmeException(404, "malformed", "resource not found");
        }
    }

    private void addNonce(Context ctx) {
        ctx.header("Replay-Nonce", nonceService.create());
        ctx.header("Cache-Control", "no-store");
    }

    private void handleAcmeException(AcmeException e, Context ctx) {
        if (e.status() >= 500) {
            LOG.error("ACME request failed status={} type={} path={} detail={}",
                    e.status(), e.type(), ctx.path(), e.getMessage(), e);
        } else {
            LOG.warn("ACME request rejected status={} type={} path={} detail={}",
                    e.status(), e.type(), ctx.path(), e.getMessage());
        }
        addNonce(ctx);
        ctx.status(e.status())
                .contentType("application/problem+json")
                .json(problem(e));
    }

    private void logRequest(Context ctx) {
        Long startedAtNanos = ctx.attribute("startedAtNanos");
        long durationMs = startedAtNanos == null ? -1L : (System.nanoTime() - startedAtNanos) / 1_000_000L;
        LOG.info("ACME request method={} path={} status={} durationMs={} remote={}",
                ctx.method(), ctx.path(), ctx.statusCode(), durationMs, ctx.ip());
    }

    private String problemJson(AcmeException e) throws Exception {
        return Json.MAPPER.writeValueAsString(problem(e));
    }

    private Map<String, Object> problem(AcmeException e) {
        return Map.of(
                "type", "urn:ietf:params:acme:error:" + e.type(),
                "detail", e.getMessage(),
                "status", e.status()
        );
    }

    private String accountUrl(UUID id) {
        return config.url("/acme/account/" + id);
    }

    private String orderUrl(UUID id) {
        return config.url("/acme/order/" + id);
    }

    private String authzUrl(UUID id) {
        return config.url("/acme/authz/" + id);
    }

    private String challengeUrl(UUID id) {
        return config.url("/acme/challenge/" + id);
    }

    private String finalizeUrl(UUID id) {
        return config.url("/acme/finalize/" + id);
    }

    private String certificateUrl(UUID id) {
        return config.url("/acme/cert/" + id);
    }
}
