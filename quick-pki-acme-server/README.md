# Quick-PKI ACME Server

Runnable internal ACME service backed by Quick-PKI, Javalin, Postgres, and Liquibase.

## Configuration

Required:

- `ACME_CA_KEY_PASSWORD`: password used to derive the AES-GCM key for CA private key encryption at rest.

Common:

- `PORT`, default `8080`
- `ACME_EXTERNAL_URL`, default `http://localhost:$PORT`
- `JDBC_URL`, default `jdbc:postgresql://localhost:5432/quickpki`
- `JDBC_USER`, default `quickpki`
- `JDBC_PASSWORD`, default `quickpki`
- `ACME_CERTIFICATE_DAYS`, default `90`
- `ACME_DNS_SERVERS`, optional comma-separated DNS servers for DNS-01 validation

## Local Run

```sh
docker compose -f quick-pki-acme-server/docker-compose.yml up --build
```

The ACME directory is served at:

```text
http://localhost:8080/acme/directory
```
