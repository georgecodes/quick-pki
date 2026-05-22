# Quick-PKI Certificate API

A small RESTful certificate issuance service backed by the Quick-PKI library,
Javalin, Postgres, and Liquibase. A caller sends a JSON request containing a
base64-encoded PKCS#10 CSR and receives a signed certificate back in the same
encoding.

It is an OAuth 2.0 protected resource: every `/v1` request must present a
bearer token, which is validated by RFC 7662 token introspection against an
externally configured authorization server. Callers are expected to obtain
their tokens using the client credentials grant.

## Configuration

All configuration is via environment variables.

Required:

- `CERT_API_CA_KEY_PASSWORD`: password used to derive the AES-GCM key that
  encrypts the issuing CA private key at rest. Must be at least 12 characters.
- `OAUTH_INTROSPECTION_URL`: the authorization server's RFC 7662 token
  introspection endpoint.
- `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET`: this service's own confidential
  client credentials, used as HTTP Basic auth when calling the introspection
  endpoint.

Common:

- `PORT`, default `8080`
- `CERT_API_EXTERNAL_URL`, default `http://localhost:$PORT`
- `CERT_API_CERTIFICATE_DAYS`, default `90` — lifetime of issued certificates
- `OAUTH_REQUIRED_SCOPE`, optional — when set, a token must carry this scope
- `OAUTH_INTROSPECTION_TIMEOUT_SECONDS`, default `5`
- `JDBC_URL`, default `jdbc:postgresql://localhost:5432/quickpki`
- `JDBC_USER`, default `quickpki`
- `JDBC_PASSWORD`, default `quickpki`

## Endpoints

| Method | Path                     | Auth        | Description                          |
|--------|--------------------------|-------------|--------------------------------------|
| POST   | `/v1/certificates`       | Bearer      | Issue a certificate from a CSR       |
| GET    | `/v1/certificates/{id}`  | Bearer      | Fetch a previously issued cert       |
| GET    | `/issuer/root.pem`       | none        | Download the issuing CA certificate  |
| GET    | `/healthz`               | none        | Liveness probe — process is up       |
| GET    | `/readyz`                | none        | Readiness probe — database reachable |
| GET    | `/openapi.yaml`          | none        | OpenAPI 3.0 description of this API   |
| GET    | `/docs`                  | none        | Browsable API reference (Redoc)      |

## Health checks

Two unauthenticated endpoints support Kubernetes probes, both returning a JSON
`{"status": ...}` body:

- `GET /healthz` — liveness. Confirms only that the process is up and serving
  HTTP. It touches no dependencies, so a database outage never restarts pods.
- `GET /readyz` — readiness. Confirms the service can do work by validating a
  pooled database connection. Returns `200` when the database is reachable and
  `503` otherwise, so an affected pod is pulled from the Service's endpoints
  until it recovers — without a restart.

The manifests in `k8s/` wire `/healthz` to both the startup and liveness
probes and `/readyz` to the readiness probe.

## API documentation

The service describes itself with an OpenAPI 3.0 document, served at
`/openapi.yaml` with the `servers` URL set to this deployment's external URL.
A browsable reference rendered with Redoc is available at `/docs`. The source
document lives at `src/main/resources/openapi.yaml`.

### Issuing a certificate

```sh
curl -X POST http://localhost:8080/v1/certificates \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"csr\": \"$(base64 -w0 request.csr)\"}"
```

The `csr` field is a base64 encoding of a PKCS#10 request — either DER or PEM.
The response echoes the same encoding:

```json
{
  "id": "0f5c...e3",
  "serialNumber": "1a2b3c...",
  "subject": "CN=service.example.com",
  "certificate": "<base64-encoded PEM>",
  "chain": "<base64-encoded PEM, leaf-first>",
  "notBefore": "2026-05-22T10:00:00Z",
  "notAfter": "2026-08-20T10:00:00Z",
  "issuedAt": "2026-05-22T10:00:05Z"
}
```

Errors are returned as a JSON object with `error`, `error_description`, and
`status` fields. A missing or invalid token yields `401` with a
`WWW-Authenticate` header; a token lacking `OAUTH_REQUIRED_SCOPE` yields `403`.

## Issuing CA

On first start the service generates a self-signed issuing CA, encrypts its
private key with `CERT_API_CA_KEY_PASSWORD`, and stores it in Postgres. On
subsequent starts it loads the persisted CA, so the issuer identity is stable
across restarts.

## Local Run

```sh
docker compose -f quick-pki-cert-api/docker-compose.yml up --build
```

The compose file starts Postgres and the API. Point the `OAUTH_*` variables at
a reachable authorization server before issuing certificates.
