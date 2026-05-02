package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	bff "github.com/elevenware/go-bff"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const sessionCookieName = "quick_pki_admin_session"

type config struct {
	Port               int
	PublicURL          string
	StaticDir          string
	DatabaseURL        string
	OIDCIssuerPublic   string
	OIDCIssuerInternal string
	OIDCClientID       string
	OIDCScopes         []string
	ACMEAdminURL       string
	ACMEAdminToken     string
}

type app struct {
	cfg   config
	db    *sql.DB
	store bff.SessionStore
	log   *slog.Logger
	http  *http.Client
}

func main() {
	cfg := loadConfig()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		logger.Error("open database", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(10 * time.Minute)

	store := bff.NewMemoryStore()
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: rewriteTransport(http.DefaultTransport, cfg.OIDCIssuerPublic, cfg.OIDCIssuerInternal),
	}
	oidc, err := bff.New(
		cfg.PublicURL+"/callback",
		bff.WithCookieName(sessionCookieName),
		bff.WithSessionStore(store),
		bff.WithHTTPClient(client),
		bff.WithLogger(logger),
	)
	if err != nil {
		logger.Error("configure bff", "err", err)
		os.Exit(1)
	}

	a := &app{cfg: cfg, db: db, store: store, log: logger, http: client}
	mux := http.NewServeMux()
	oidc.Mount(mux)
	a.mount(mux)

	addr := ":" + strconv.Itoa(cfg.Port)
	logger.Info("quick-pki admin listening", "addr", addr)
	if err := http.ListenAndServe(addr, oidc.LoggingMiddleware(mux)); err != nil {
		logger.Error("serve", "err", err)
		os.Exit(1)
	}
}

func (a *app) mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/app-config", a.appConfig)
	mux.HandleFunc("POST /api/admin/session/logout", a.logout)
	mux.Handle("GET /api/admin/summary", a.requireSession(http.HandlerFunc(a.summary)))
	mux.Handle("GET /api/admin/accounts", a.requireSession(http.HandlerFunc(a.accounts)))
	mux.Handle("GET /api/admin/orders", a.requireSession(http.HandlerFunc(a.orders)))
	mux.Handle("GET /api/admin/orders/{id}", a.requireSession(http.HandlerFunc(a.orderDetail)))
	mux.Handle("GET /api/admin/ca", a.requireSession(http.HandlerFunc(a.ca)))
	mux.Handle("POST /api/admin/ca/rotate", a.requireSession(http.HandlerFunc(a.rotateCA)))
	mux.Handle("GET /", a.spa())
	mux.Handle("GET /assets/", a.spa())
}

func (a *app) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "login required")
			return
		}
		session := a.store.Get(cookie.Value)
		if session == nil || session.Tokens == nil {
			writeError(w, http.StatusUnauthorized, "login required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *app) appConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":   a.cfg.OIDCIssuerPublic,
		"clientId": a.cfg.OIDCClientID,
		"scopes":   a.cfg.OIDCScopes,
	})
}

func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		a.store.Remove(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *app) summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	response := map[string]any{
		"totals": map[string]int64{
			"accounts":       a.count(ctx, "select count(*) from acme_accounts"),
			"orders":         a.count(ctx, "select count(*) from acme_orders"),
			"authorizations": a.count(ctx, "select count(*) from acme_authorizations"),
			"challenges":     a.count(ctx, "select count(*) from acme_challenges"),
			"certificates":   a.count(ctx, "select count(*) from acme_orders where certificate_pem is not null"),
		},
		"orderStatuses":     a.statusCounts(ctx, "select status, count(*) from acme_orders group by status order by status"),
		"challengeStatuses": a.statusCounts(ctx, "select status, count(*) from acme_challenges group by status order by status"),
	}
	writeJSON(w, response)
}

func (a *app) accounts(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `
		select
			a.id::text,
			a.key_thumbprint,
			coalesce(a.contact_json, '[]'),
			a.status,
			a.terms_agreed,
			a.created_at,
			count(o.id) as order_count,
			max(o.created_at) as last_order_at
		from acme_accounts a
		left join acme_orders o on o.account_id = a.id
		group by a.id, a.key_thumbprint, a.contact_json, a.status, a.terms_agreed, a.created_at
		order by a.created_at desc`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	var accounts []accountDTO
	for rows.Next() {
		var dto accountDTO
		var contactJSON string
		var lastOrder sql.NullTime
		if err := rows.Scan(&dto.ID, &dto.KeyThumbprint, &contactJSON, &dto.Status, &dto.TermsAgreed,
			&dto.CreatedAt, &dto.OrderCount, &lastOrder); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		dto.Contact = jsonList(contactJSON)
		if lastOrder.Valid {
			dto.LastOrderAt = &lastOrder.Time
		}
		accounts = append(accounts, dto)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, accounts)
}

func (a *app) orders(w http.ResponseWriter, r *http.Request) {
	rows, err := a.db.QueryContext(r.Context(), `
		select
			o.id::text,
			o.account_id::text,
			a.key_thumbprint,
			o.status,
			o.expires_at,
			o.created_at,
			o.identifiers_json,
			o.certificate_pem is not null,
			count(distinct az.id) as authorization_count,
			count(distinct ch.id) as challenge_count
		from acme_orders o
		join acme_accounts a on a.id = o.account_id
		left join acme_authorizations az on az.order_id = o.id
		left join acme_challenges ch on ch.authorization_id = az.id
		group by o.id, o.account_id, a.key_thumbprint, o.status, o.expires_at, o.created_at, o.identifiers_json, o.certificate_pem
		order by o.created_at desc`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	var orders []orderDTO
	for rows.Next() {
		dto, err := scanOrder(rows)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		orders = append(orders, dto)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, orders)
}

func (a *app) orderDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	row := a.db.QueryRowContext(r.Context(), `
		select
			o.id::text,
			o.account_id::text,
			a.key_thumbprint,
			o.status,
			o.expires_at,
			o.created_at,
			o.identifiers_json,
			o.certificate_pem is not null,
			(select count(*) from acme_authorizations where order_id = o.id),
			(select count(*) from acme_challenges c join acme_authorizations az on az.id = c.authorization_id where az.order_id = o.id)
		from acme_orders o
		join acme_accounts a on a.id = o.account_id
		where o.id = $1`, id)
	dto, err := scanOrder(row)
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, http.StatusNotFound, "order not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	authzRows, err := a.db.QueryContext(r.Context(), `
		select id::text, identifier_type, identifier_value, wildcard, status, expires_at
		from acme_authorizations
		where order_id = $1
		order by identifier_value`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer authzRows.Close()

	var authzs []authorizationDTO
	for authzRows.Next() {
		var authz authorizationDTO
		if err := authzRows.Scan(&authz.ID, &authz.IdentifierType, &authz.IdentifierValue,
			&authz.Wildcard, &authz.Status, &authz.ExpiresAt); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		authz.Challenges, err = a.challenges(r.Context(), authz.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		authzs = append(authzs, authz)
	}
	if err := authzRows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]any{"order": dto, "authorizations": authzs})
}

func (a *app) challenges(ctx context.Context, authzID string) ([]challengeDTO, error) {
	rows, err := a.db.QueryContext(ctx, `
		select id::text, type, token, status, validated_at, error_json
		from acme_challenges
		where authorization_id = $1
		order by type`, authzID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var challenges []challengeDTO
	for rows.Next() {
		var dto challengeDTO
		var validated sql.NullTime
		var errorJSON sql.NullString
		if err := rows.Scan(&dto.ID, &dto.Type, &dto.Token, &dto.Status, &validated, &errorJSON); err != nil {
			return nil, err
		}
		if validated.Valid {
			dto.ValidatedAt = &validated.Time
		}
		if errorJSON.Valid {
			dto.Error = jsonObject(errorJSON.String)
		}
		challenges = append(challenges, dto)
	}
	return challenges, rows.Err()
}

func (a *app) ca(w http.ResponseWriter, r *http.Request) {
	info, err := a.caInfo(r.Context())
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, map[string]any{})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, info)
}

func (a *app) rotateCA(w http.ResponseWriter, r *http.Request) {
	if a.cfg.ACMEAdminToken == "" {
		writeError(w, http.StatusServiceUnavailable, "ACME_ADMIN_TOKEN is not configured")
		return
	}
	endpoint := strings.TrimRight(a.cfg.ACMEAdminURL, "/") + "/admin/ca/rotate"
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("Authorization", "Bearer "+a.cfg.ACMEAdminToken)
	resp, err := a.http.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		writeError(w, http.StatusBadGateway, strings.TrimSpace(string(body)))
		return
	}
	info, err := a.caInfo(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, info)
}

func (a *app) caInfo(ctx context.Context) (caDTO, error) {
	var pemText string
	var createdAt time.Time
	err := a.db.QueryRowContext(ctx, "select certificate_pem, created_at from ca_material where id = 'default'").
		Scan(&pemText, &createdAt)
	if err != nil {
		return caDTO{}, err
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return caDTO{}, fmt.Errorf("CA certificate PEM could not be decoded")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return caDTO{}, err
	}
	sum := sha256.Sum256(cert.Raw)
	return caDTO{
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		Serial:      cert.SerialNumber.String(),
		Fingerprint: strings.ToUpper(hex.EncodeToString(sum[:])),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		CreatedAt:   createdAt,
		PEM:         pemText,
	}, nil
}

func (a *app) count(ctx context.Context, query string) int64 {
	var count int64
	if err := a.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
		a.log.Warn("count failed", "query", query, "err", err)
	}
	return count
}

func (a *app) statusCounts(ctx context.Context, query string) map[string]int64 {
	rows, err := a.db.QueryContext(ctx, query)
	if err != nil {
		a.log.Warn("status count failed", "query", query, "err", err)
		return map[string]int64{}
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var status string
		var count int64
		if err := rows.Scan(&status, &count); err != nil {
			a.log.Warn("status count row failed", "err", err)
			continue
		}
		counts[status] = count
	}
	return counts
}

func scanOrder(scanner interface {
	Scan(dest ...any) error
}) (orderDTO, error) {
	var dto orderDTO
	var identifiersJSON string
	err := scanner.Scan(&dto.ID, &dto.AccountID, &dto.AccountThumbprint, &dto.Status, &dto.ExpiresAt,
		&dto.CreatedAt, &identifiersJSON, &dto.CertificateIssued, &dto.AuthorizationCount, &dto.ChallengeCount)
	if err != nil {
		return dto, err
	}
	dto.Identifiers = jsonIdentifiers(identifiersJSON)
	return dto, nil
}

func jsonList(raw string) []string {
	var values []string
	if err := json.Unmarshal([]byte(raw), &values); err == nil {
		return values
	}
	var generic []any
	if err := json.Unmarshal([]byte(raw), &generic); err != nil {
		return nil
	}
	out := make([]string, 0, len(generic))
	for _, value := range generic {
		out = append(out, fmt.Sprint(value))
	}
	return out
}

func jsonIdentifiers(raw string) []identifierDTO {
	var values []identifierDTO
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil
	}
	return values
}

func jsonObject(raw string) any {
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return raw
	}
	return value
}

func (a *app) spa() http.Handler {
	files := http.FileServer(http.Dir(a.cfg.StaticDir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			files.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, a.cfg.StaticDir+"/index.html")
	})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": message})
}

func loadConfig() config {
	port := intEnv("PORT", 8090)
	publicURL := trimTrailingSlash(env("PUBLIC_URL", "http://localhost:"+strconv.Itoa(port)))
	return config{
		Port:               port,
		PublicURL:          publicURL,
		StaticDir:          env("STATIC_DIR", "web/dist"),
		DatabaseURL:        env("DATABASE_URL", "postgres://quickpki:quickpki@localhost:5432/quickpki?sslmode=disable"),
		OIDCIssuerPublic:   trimTrailingSlash(env("OIDC_ISSUER_PUBLIC", env("OIDC_ISSUER", "http://localhost:8091"))),
		OIDCIssuerInternal: trimTrailingSlash(env("OIDC_ISSUER_INTERNAL", env("OIDC_ISSUER", "http://localhost:8091"))),
		OIDCClientID:       env("OIDC_CLIENT_ID", "quick-pki-admin"),
		OIDCScopes:         csvEnv("OIDC_SCOPES", []string{"openid", "profile", "email"}),
		ACMEAdminURL:       trimTrailingSlash(env("ACME_ADMIN_URL", "http://localhost:8080")),
		ACMEAdminToken:     env("ACME_ADMIN_TOKEN", ""),
	}
}

func env(name, fallback string) string {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	return value
}

func intEnv(name string, fallback int) int {
	value := env(name, "")
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func csvEnv(name string, fallback []string) []string {
	value := env(name, "")
	if value == "" {
		return fallback
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func trimTrailingSlash(value string) string {
	return strings.TrimRight(value, "/")
}

type rewritingTransport struct {
	next          http.RoundTripper
	publicURL     *url.URL
	internalURL   *url.URL
	shouldRewrite bool
}

func rewriteTransport(next http.RoundTripper, publicIssuer, internalIssuer string) http.RoundTripper {
	if next == nil {
		next = http.DefaultTransport
	}
	publicURL, publicErr := url.Parse(publicIssuer)
	internalURL, internalErr := url.Parse(internalIssuer)
	shouldRewrite := publicErr == nil && internalErr == nil &&
		publicURL.Scheme != "" && publicURL.Host != "" &&
		internalURL.Scheme != "" && internalURL.Host != "" &&
		publicURL.Scheme+"://"+publicURL.Host != internalURL.Scheme+"://"+internalURL.Host
	return &rewritingTransport{next: next, publicURL: publicURL, internalURL: internalURL, shouldRewrite: shouldRewrite}
}

func (t *rewritingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.shouldRewrite && req.URL.Scheme == t.publicURL.Scheme && req.URL.Host == t.publicURL.Host {
		clone := req.Clone(req.Context())
		rewritten := *req.URL
		rewritten.Scheme = t.internalURL.Scheme
		rewritten.Host = t.internalURL.Host
		clone.URL = &rewritten
		clone.Host = t.publicURL.Host
		return t.next.RoundTrip(clone)
	}
	return t.next.RoundTrip(req)
}

type accountDTO struct {
	ID            string     `json:"id"`
	KeyThumbprint string     `json:"keyThumbprint"`
	Contact       []string   `json:"contact"`
	Status        string     `json:"status"`
	TermsAgreed   bool       `json:"termsAgreed"`
	CreatedAt     time.Time  `json:"createdAt"`
	OrderCount    int64      `json:"orderCount"`
	LastOrderAt   *time.Time `json:"lastOrderAt,omitempty"`
}

type orderDTO struct {
	ID                 string          `json:"id"`
	AccountID          string          `json:"accountId"`
	AccountThumbprint  string          `json:"accountThumbprint"`
	Status             string          `json:"status"`
	ExpiresAt          time.Time       `json:"expiresAt"`
	CreatedAt          time.Time       `json:"createdAt"`
	Identifiers        []identifierDTO `json:"identifiers"`
	CertificateIssued  bool            `json:"certificateIssued"`
	AuthorizationCount int64           `json:"authorizationCount"`
	ChallengeCount     int64           `json:"challengeCount"`
}

type identifierDTO struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type authorizationDTO struct {
	ID              string         `json:"id"`
	IdentifierType  string         `json:"identifierType"`
	IdentifierValue string         `json:"identifierValue"`
	Wildcard        bool           `json:"wildcard"`
	Status          string         `json:"status"`
	ExpiresAt       time.Time      `json:"expiresAt"`
	Challenges      []challengeDTO `json:"challenges"`
}

type challengeDTO struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	Token       string     `json:"token"`
	Status      string     `json:"status"`
	ValidatedAt *time.Time `json:"validatedAt,omitempty"`
	Error       any        `json:"error,omitempty"`
}

type caDTO struct {
	Subject     string    `json:"subject"`
	Issuer      string    `json:"issuer"`
	Serial      string    `json:"serial"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"notBefore"`
	NotAfter    time.Time `json:"notAfter"`
	CreatedAt   time.Time `json:"createdAt"`
	PEM         string    `json:"pem"`
}
