# ADR: Quick-PKI-backed ACME implementation

## Status

Accepted and implemented. The decisions captured in this ADR are realised by
the `quick-pki-acme-server` Maven module (Javalin + Postgres/Liquibase) and
the `quick-pki-admin` Go BFF + Vue console. The remainder of this document is
preserved as the original design rationale; for current behaviour, consult
the modules and their READMEs.

## Context

RePartee's Quick-PKI library provides a convenient API for generating and signing certificates, 
but it does not include any delivery mechanism. The question is whether it would be feasible to 
build a simple ACME server on top of Quick-PKI, and if so, what the design would look like.

We shall require support for the ACME HTTP-01 and DNS-01 challenge types. These are documented in RFC 8555 and 
widely supported by ACME clients. We will not require support for the TLS-ALPN-01 challenge type at this time,
but we may consider it in the future.

## Implementation constraints

- As a Java project, issuance components shall of course be implemented in Java. 
- However, we may choose to implement the ACME protocol handling in a different language if it simplifies development or deployment.
- The ACME service must be able to serve multiple clients and manage multiple certificates concurrently.
- The ACME service must be able to store account and order state persistently.
- For persistence we shall use Postgresql
- The ACME service should support both RSA and ECDSA keys for account keys and certificate keys, as these are commonly used in ACME.
- The ACME service must implement the necessary endpoints for account management, order management, and challenge handling as defined in RFC 8555.
- The ACME service must provide issuer certificates publically for clients to build trust chains.
- The ACME service should support OCSP and CRL for certificate revocation checking.
- Java components built shall be modules of the Maven project in this folder

## Next Steps

The model or agent will need to design the ACME service architecture, including how it will interact with Quick-PKI for certificate generation and signing, 
how it will manage state and persistence, and how it will handle the ACME protocol. The model may ask the user for additional requirements or constraints to 
inform the design. Once a design is proposed, we can evaluate its feasibility and make an implementation decision.

## Questions and answers from the model 

These questions were asked by the model. Answers are in bold beneath each one

- Intended use case: is this for local/dev/test ACME compatibility, private internal CA use, or something production-like? This determines how
  strict we need to be about RFC 8555 edge cases, security, rate limits, and revocation.
**The intended use case is primarily internal. Typically inside a k8s cluster**

- Protocol stack: should the ACME server be Java-only, or is a non-Java protocol service acceptable as hinted in ACME.md:19? If Java, preferen
  ce for Spring Boot, Quarkus, Javalin, plain servlet, etc.
** The stack need not be Java only. Services integrating directly with Quick-PKI will be, and let us use Javalin for anything HTTP. Golang for anything non-Java**

- Compliance target: minimum interoperability with common clients like Certbot/acme.sh/lego, or fuller RFC 8555 coverage including account key
  rollover, external account binding, revoke-cert, pre-authorization, wildcard DNS-01, etc.
** Interoperability with common clients is the primary target.**

- Persistence scope: ACME.md:22 has an unfinished bullet: “must be able to store account and order state persistently, but the”. Need the
  missing constraint. Also need decisions on storing nonces, authzs, challenges, issued certs, revocation records, and CA material.

** "but the" is a typo. We should persist everything which is not ephemeral to ensure that the service can be restarted without losing state. This includes account and order state, authzs, challenges, issued certs, revocation records, and CA material. ACME nonces are ephemeral replay-prevention state and should not survive restarts; clients can fetch fresh nonces.**
- CA key lifecycle: should the ACME service generate a root/intermediate at startup, load one from disk/env/Postgres/KMS, or expose
  configuration for either? An ACME CA needs stable issuer identity across restarts.
** CA keys shall be persisted in Postgres. The service should generate a new root/intermediate at startup if no key is found in the database, but if a key is found it should load and use that key to ensure stable issuer identity across restarts.**
- 
- Certificate profile: default lifetime, backdating, allowed SAN types, CN behavior, key algorithms, EKUs, key usages, chain shape, root vs
  intermediate issuance, and whether to copy/override CSR subject fields.
** Good anticipation. We shall, later on, be supporting multiple profiles. For now, choose a sensible default profile that allows for a reasonable lifetime o 90 days**
- Challenge validation policy: for HTTP-01/DNS-01, do we actually perform network/DNS validation, or is this a controlled test server that can
  accept mocked validation? Need resolver behavior, timeout/retry policy, wildcard handling, CNAME handling, and whether validation can reach
  public internet/private networks.
**We shall actually perform the challenges. Choose and document a sensible approach**
- Revocation: ACME.md:27 says OCSP and CRL “should” be supported. Need to know whether this is required for v1, and whether CRL/OCSP endpoints
  must be RFC-compatible or just enough for clients/tests.
**They *should* be supported, but for v1 we can start with just OCSP. The OCSP endpoint should be RFC-compatible to ensure interoperability with clients and tests. We can consider adding a CRL endpoint in the future if there is demand for it.**
- Database/deployment: Postgres version, migration tool preference, Docker/Testcontainers acceptability, service configuration style, and
  whether a runnable server module should be added under the existing Maven multi-module project at pom.xml:37.
** We shall use Postgres, managed by Liquibase. Configuration should be via environment variables. A runnable server module should be added under the existing Maven multi-module project at pom.xml:37 for ease of development and deployment.**
- Client compatibility test target: which ACME clients should be used as acceptance tests, and what flows must pass first.
** Certbot and cert-manager are the primary client compatibility test targets. The initial flows that must pass include account registration, order creation, challenge validation, and certificate issuance. We can expand the test suite to cover additional flows such as account key rollover and revocation in the future.**

## Follow-up decisions

- Identifier policy: v1 may issue for any identifier that passes challenge validation. No domain or IP allowlist is required initially.
- V1 feature scope: implement the ACME happy path for certbot and cert-manager: directory, nonce, account registration, order creation, authorization lookup, HTTP-01 and DNS-01 challenge validation, order finalization, certificate download, issuer certificate download, and a loose-compatibility OCSP endpoint. Account key rollover, pre-authorization, TLS-ALPN-01, CRL, and fuller revocation flows may follow later.
- Certificate profile: use a single default profile for v1. Leaf certificates are valid for 90 days. Subject alternative names are copied from the CSR only when they match validated identifiers. DNS names, wildcard DNS names via DNS-01, and IP SANs are allowed.
- Challenge validation: perform real HTTP-01 and DNS-01 validation. Validation may reach public addresses as well as internal cluster addresses. Use sensible documented defaults for retry, timeout, DNS resolver behavior, and CNAME handling.
- CA material: persist CA private keys and certificates in Postgres. Private keys must be encrypted at rest using configuration supplied through environment variables.
- OCSP: v1 only needs loose compatibility. The endpoint should be good enough for common clients and tests, but it need not block initial issuance work on complete responder behavior.
- Deployment: add a runnable Maven server module. Include Dockerfiles for development/deployment; Helm-style Kubernetes manifests are a desirable bonus.
