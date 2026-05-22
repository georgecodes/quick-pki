# Quick-PKI ACME Server

Runnable internal ACME service backed by Quick-PKI, Javalin, Postgres, and Liquibase.

## Configuration

The server issues certificates in one of two modes:

- **Local CA** (default): mints certificates from a CA it holds and persists itself.
- **Remote API**: delegates issuance to a deployed Quick-PKI certificate API,
  selected by setting `ACME_CERT_API_URL`.

Required:

- `ACME_CA_KEY_PASSWORD`: password used to derive the AES-GCM key for CA private
  key encryption at rest. Required in local CA mode only; not needed when issuance
  is delegated to a remote certificate API.

Common:

- `PORT`, default `8080`
- `ACME_EXTERNAL_URL`, default `http://localhost:$PORT`
- `ACME_ADMIN_TOKEN`, bearer token required by the internal CA rotation endpoint
- `JDBC_URL`, default `jdbc:postgresql://localhost:5432/quickpki`
- `JDBC_USER`, default `quickpki`
- `JDBC_PASSWORD`, default `quickpki`
- `ACME_CERTIFICATE_DAYS`, default `90`
- `ACME_DNS_SERVERS`, optional comma-separated DNS servers for DNS-01 validation

### Delegating issuance to a remote certificate API

Set `ACME_CERT_API_URL` to point the server at a deployed certificate issuance
API instead of running its own CA. In this mode the server still validates ACME
challenges and enforces that a finalize CSR only contains validated SANs, but
forwards the CSR to the API for signing. The certificate API is an OAuth 2.0
protected resource, so client credentials are required to obtain access tokens
via the client credentials grant.

- `ACME_CERT_API_URL`: base URL of the certificate API (e.g. `https://certs.example.com`).
  Setting this enables remote mode.
- `ACME_CERT_API_TOKEN_URL`: OAuth 2.0 token endpoint used for the client
  credentials grant. Required in remote mode.
- `ACME_CERT_API_CLIENT_ID` / `ACME_CERT_API_CLIENT_SECRET`: confidential client
  credentials used to obtain access tokens. Required in remote mode.
- `ACME_CERT_API_SCOPE`: optional scope requested with the client credentials grant.
- `ACME_CERT_API_TIMEOUT_SECONDS`: optional HTTP timeout for token and issuance
  calls, default `10`.

The `POST /admin/ca/rotate` endpoint is unavailable in remote mode, since the
issuing CA is owned by the certificate API.

## Local Run

```sh
docker compose -f quick-pki-acme-server/docker-compose.yml up --build
```

The ACME directory is served at:

```text
http://localhost:8080/acme/directory
```

The administrator console is served at:

```text
http://localhost:8090
```

The local compose profile includes `georgemc/fakeid:0.1.0` on port `8091` for zero-interaction OIDC sign-in.
