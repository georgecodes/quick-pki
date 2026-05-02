# Quick-PKI Admin

Vue and Tailwind management console served by a Go Backend-for-Frontend.

The BFF uses `github.com/elevenware/go-bff` for OpenID Connect session handling. The browser never receives client secrets or stores tokens directly; admin JSON endpoints require the BFF session cookie.

## Configuration

- `PORT`, default `8090`
- `PUBLIC_URL`, default `http://localhost:$PORT`
- `STATIC_DIR`, default `web/dist`
- `DATABASE_URL`, default `postgres://quickpki:quickpki@localhost:5432/quickpki?sslmode=disable`
- `OIDC_ISSUER_PUBLIC`, default `http://localhost:8091`
- `OIDC_ISSUER_INTERNAL`, default `OIDC_ISSUER_PUBLIC`
- `OIDC_CLIENT_ID`, default `quick-pki-admin`
- `OIDC_SCOPES`, default `openid,profile,email`
- `ACME_ADMIN_URL`, default `http://localhost:8080`
- `ACME_ADMIN_TOKEN`, shared bearer token for CA rotation

## Local Development

```sh
cd quick-pki-admin/web
npm install
npm run build

cd ..
go run .
```

The complete local stack is available through:

```sh
docker compose -f quick-pki-acme-server/docker-compose.yml up --build
```
