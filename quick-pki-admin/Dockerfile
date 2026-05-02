FROM node:25-alpine AS web
WORKDIR /app/web
COPY quick-pki-admin/web/package*.json ./
RUN npm ci --no-audit
COPY quick-pki-admin/web/ ./
RUN npm run build

FROM golang:1.26-alpine AS go
WORKDIR /app
COPY quick-pki-admin/go.mod quick-pki-admin/go.sum* ./
RUN go mod download
COPY quick-pki-admin/ ./
COPY --from=web /app/web/dist ./web/dist
RUN go build -o /quick-pki-admin .

FROM alpine:3.22
WORKDIR /app
COPY --from=go /quick-pki-admin /usr/local/bin/quick-pki-admin
COPY --from=web /app/web/dist ./web/dist
ENV PORT=8090
EXPOSE 8090
ENTRYPOINT ["quick-pki-admin"]
