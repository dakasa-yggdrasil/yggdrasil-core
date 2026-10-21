package addons

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/oidc"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/integrationsurfaces"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
	surfacesvc "github.com/dakasa-yggdrasil/yggdrasil-core/internal/surface"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"go.uber.org/zap"
)

func init() {
	Register("http", bootstrapHTTP, 30)
}

func bootstrapHTTP(ctx context.Context, app *runtime.ServiceApp) error {
	issuer := strings.TrimSpace(os.Getenv("YGGDRASIL_OIDC_ISSUER"))
	if strings.TrimSpace(os.Getenv("YGGDRASIL_OIDC_CLIENTS_FILE")) != "" && issuer == "" {
		return fmt.Errorf("oidc confidential client bootstrap requires YGGDRASIL_OIDC_ISSUER")
	}
	tlsConfig, err := httpTLSConfigFromEnv()
	if err != nil {
		return err
	}
	addr := httpListenAddr()
	secondaryAddr, err := httpTLSSecondaryAddrFromEnv(tlsConfig, addr)
	if err != nil {
		return err
	}
	db, ok := Postgres(app)
	if !ok {
		return fmt.Errorf("postgres addon is not available")
	}

	conn, _ := RabbitMQ(app)
	logger, _ := Logger(app)
	if logger == nil {
		logger = zap.NewNop()
	}

	var opts []httpapi.ServerOption
	// This is an in-process service of the SAME HTTP authorization owner,
	// never a new caller-controlled route or anonymous dispatch wrapper.
	opts = append(opts, httpapi.WithCapacityDispatchServiceReceiver(func(service *httpapi.CapacityDispatchService) {
		app.SetResource(capacityDispatchServiceResource, service)
	}))
	if engine, ok := Reconciler(app); ok {
		opts = append(opts, httpapi.WithReconciler(engine))
	}
	if p, ok := Provisioner(app); ok {
		opts = append(opts, httpapi.WithProvisioner(p))
	}
	// OIDC provider mount is opt-in via YGGDRASIL_OIDC_ISSUER. When set,
	// httpapi.New invokes oidc.MountOIDC which registers /.well-known/
	// openid-configuration plus /oidc/* (authorize, token, keys, userinfo,
	// end_session). The issuer URL must match exactly what tokens claim
	// in the `iss` field — terminating in /oidc preserves StripPrefix
	// isolation (Task 7 follow-up commit ba95e2d). Empty/unset keeps
	// the routes dormant for clusters that haven't onboarded OIDC yet.
	//
	// Before mounting, we run oidc.EnsureSigningKey to load-or-create the
	// active RS256 keypair (Task 5 bootstrap). Without an active key,
	// MountOIDC's deriveCryptoKey would fail with "fetch active signing
	// key: oidc signing key not found". The Ensure* call is idempotent
	// across multi-pod startup races via FOR UPDATE on the singleton
	// oidc_provider_settings row.
	if issuer != "" {
		if ensureErr := ensureConfiguredOIDCClients(ctx, db, logger); ensureErr != nil {
			return ensureErr
		}
		if _, ensureErr := oidc.EnsureSigningKey(ctx, db); ensureErr != nil {
			return fmt.Errorf("oidc signing key bootstrap: %w", ensureErr)
		}
		opts = append(opts, httpapi.WithOIDCIssuer(issuer))
		logger.Info("yggdrasil OIDC provider enabled", zap.String("issuer", issuer))
	}
	surfaceTargets := surfaceTargetsFromEnv(logger)
	if len(surfaceTargets) > 0 {
		opts = append(opts, httpapi.WithSurfaceBaseURLs(surfaceTargets))
	}
	// Federated integration_surfaces (coexists with internal/surface). The
	// integration_surface_sync addon (priority 25) stashes the repo and the
	// synchronous dispatcher into app resources before this addon (priority
	// 30) runs. Missing resources mean the related handlers return 503.
	if raw, ok := app.Resource("integration_surfaces_repo"); ok {
		if repo, ok := raw.(*integrationsurfaces.Repository); ok {
			opts = append(opts, httpapi.WithIntegrationSurfacesRepo(repo))
		}
	}
	if raw, ok := app.Resource("integration_surface_query_dispatcher"); ok {
		if disp, ok := raw.(httpapi.SurfaceQueryDispatcher); ok {
			opts = append(opts, httpapi.WithSurfaceQueryDispatcher(disp))
		}
	}
	// Opt-in surface-query view-access gate. The source resolves a query's
	// declared permission from its surface manifest (spec.queries[].
	// requires_permission); it returns "ungated" for every query that declares
	// none, so wiring it is behaviour-neutral for all current surfaces (zero
	// lockout) and only enforces once a manifest opts a query in.
	if src := httpapi.NewDBSurfaceQueryPermSource(db); src != nil {
		opts = append(opts, httpapi.WithSurfaceQueryPermSource(src))
	}
	discovery := surfacesvc.NewDiscovery(db, surfacesvc.NewClient(nil), logger).
		WithSource(surfaceTargetSource{db: db, fallback: surfaceTargets}).
		WithReconciler(surfacesvc.NewPermissionsReconciler(db, logger))
	discoveryCtx, cancelDiscovery := context.WithCancel(context.Background())
	go func() {
		if err := discovery.Run(
			discoveryCtx,
			httpDurationFromEnv("YGGDRASIL_SURFACE_DISCOVERY_INTERVAL_SECONDS", 30*time.Second),
			intFromEnv("YGGDRASIL_SURFACE_DISCOVERY_PARALLELISM", 4),
		); err != nil {
			logger.Warn("surface discovery stopped", zap.Error(err))
		}
	}()
	app.RegisterCloser(func(context.Context) error {
		cancelDiscovery()
		discovery.Stop()
		return nil
	})
	logger.Info("surface discovery enabled", zap.Int("env_targets", len(surfaceTargets)))
	handler, err := httpapi.New(app.ServiceName, db, conn, logger, opts...)
	if err != nil {
		return fmt.Errorf("build http api: %w", err)
	}

	servers := configuredHTTPServers(addr, secondaryAddr, handler, tlsConfig)
	listeners, err := listenHTTPServers(servers)
	if err != nil {
		return err
	}
	for i, server := range servers {
		listener := listeners[i]
		go func() {
			if serveErr := serveConfiguredHTTP(server, listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				logger.Fatal("http server stopped unexpectedly", zap.String("addr", server.Addr), zap.Error(serveErr))
			}
		}()
		logger.Info("http api started", zap.String("addr", server.Addr), zap.Bool("tls", server.TLSConfig != nil))
	}
	app.SetResource("http_server", servers[0])
	app.SetResource("http_addr", addr)
	if len(servers) == 2 {
		app.SetResource("http_tls_server", servers[1])
		app.SetResource("http_tls_addr", secondaryAddr)
	}
	app.RegisterCloser(func(ctx context.Context) error {
		return shutdownHTTPServers(ctx, servers)
	})
	return nil
}

// A secondary TLS listener uses the SAME handler and private authorization
// registry. It preserves primary HTTP while old and new processes coexist.
func configuredHTTPServers(addr, secondaryAddr string, handler http.Handler, tlsConfig *tls.Config) []*http.Server {
	newServer := func(address string, identity *tls.Config) *http.Server {
		return &http.Server{
			Addr:              address,
			Handler:           handler,
			ReadHeaderTimeout: httpDurationFromEnv("HTTP_READ_HEADER_TIMEOUT_SECONDS", 10*time.Second),
			ReadTimeout:       httpDurationFromEnv("HTTP_READ_TIMEOUT_SECONDS", 30*time.Second),
			WriteTimeout:      httpDurationFromEnv("HTTP_WRITE_TIMEOUT_SECONDS", 30*time.Second),
			IdleTimeout:       httpDurationFromEnv("HTTP_IDLE_TIMEOUT_SECONDS", 120*time.Second),
			TLSConfig:         identity,
		}
	}
	server := newServer(addr, tlsConfig)
	if secondaryAddr == "" {
		return []*http.Server{server}
	}
	server.TLSConfig = nil
	return []*http.Server{server, newServer(secondaryAddr, tlsConfig)}
}

// Bind every listener before any Serve call. A failed second bind closes the
// first socket; it cannot leave a partially started API behind.
func listenHTTPServers(servers []*http.Server) ([]net.Listener, error) {
	var listeners []net.Listener
	for _, server := range servers {
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			for _, bound := range listeners {
				_ = bound.Close()
			}
			return nil, fmt.Errorf("bind http listener: %w", err)
		}
		listeners = append(listeners, listener)
	}
	return listeners, nil
}

func shutdownHTTPServers(ctx context.Context, servers []*http.Server) error {
	var result error
	for _, server := range servers {
		result = errors.Join(result, server.Shutdown(ctx))
	}
	return result
}

func httpTLSSecondaryAddrFromEnv(identity *tls.Config, primaryAddr string) (string, error) {
	addr, present := os.LookupEnv("HTTP_TLS_SECONDARY_ADDR")
	if !present {
		return "", nil
	}
	refuse := func() (string, error) { return "", httpTLSConfigurationError{} }
	if identity == nil || addr == "" || strings.TrimSpace(addr) != addr {
		return refuse()
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return refuse()
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return refuse()
	}
	if host != "" {
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" || ip.String() != host {
			return refuse()
		}
	}
	if net.JoinHostPort(host, port) != addr {
		return refuse()
	}
	_, primaryPort, err := net.SplitHostPort(primaryAddr)
	primaryNumber, portErr := strconv.Atoi(primaryPort)
	if err != nil || portErr != nil || primaryNumber == n {
		return refuse()
	}
	return addr, nil
}

type httpTLSConfigurationError struct{ cause error }

func (httpTLSConfigurationError) Error() string                { return "configured HTTP TLS identity unavailable" }
func (e httpTLSConfigurationError) Unwrap() error              { return e.cause }
func (e httpTLSConfigurationError) Format(s fmt.State, _ rune) { _, _ = fmt.Fprint(s, e.Error()) }

// Explicit mounted identities are loaded once before the HTTP addon accesses
// its database resource or performs OIDC/API bootstrap effects. Earlier addons
// may already have initialized their own resources. Absence preserves the
// original HTTP transport. A partial, blank or
// malformed opt-in never silently falls back to plaintext or a proxy header.
func httpTLSConfigFromEnv() (*tls.Config, error) {
	certFile, hasCert := os.LookupEnv("HTTP_TLS_CERT_FILE")
	keyFile, hasKey := os.LookupEnv("HTTP_TLS_KEY_FILE")
	if !hasCert && !hasKey {
		return nil, nil
	}
	if !hasCert || !hasKey || certFile == "" || keyFile == "" || strings.TrimSpace(certFile) != certFile || strings.TrimSpace(keyFile) != keyFile || !filepath.IsAbs(certFile) || !filepath.IsAbs(keyFile) || filepath.Clean(certFile) != certFile || filepath.Clean(keyFile) != keyFile || strings.ContainsAny(certFile+keyFile, "\r\n\x00") {
		return nil, httpTLSConfigurationError{}
	}
	identity, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, httpTLSConfigurationError{cause: err}
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{identity}}, nil
}

func serveConfiguredHTTP(server *http.Server, listener net.Listener) error {
	if server.TLSConfig == nil {
		return server.Serve(listener)
	}
	// The already loaded identity and SAME original API handler/registry are
	// used. No certificate path/key is retained in server logs or request data.
	return server.ServeTLS(listener, "", "")
}

func ensureConfiguredOIDCClients(ctx context.Context, db *sql.DB, logger *zap.Logger) error {
	if clientsFile := strings.TrimSpace(os.Getenv("YGGDRASIL_OIDC_CLIENTS_FILE")); clientsFile != "" {
		result, err := oidc.EnsureConfiguredConfidentialClientsFromFile(ctx, db, clientsFile)
		if err != nil {
			return fmt.Errorf("oidc confidential client bootstrap: %w", err)
		}
		logger.Info("configured confidential OIDC clients", zap.Int("client_count", len(result.ClientIDs)))
	}
	if err := oidc.EnsureConfiguredPublicClients(ctx, db, os.Getenv("YGGDRASIL_OIDC_PUBLIC_CLIENTS_JSON")); err != nil {
		return fmt.Errorf("oidc public client bootstrap: %w", err)
	}
	return nil
}

func httpListenAddr() string {
	if raw := strings.TrimSpace(os.Getenv("HTTP_ADDR")); raw != "" {
		return raw
	}

	port := strings.TrimSpace(os.Getenv("PORT"))
	if port == "" {
		port = "9080"
	}
	if strings.HasPrefix(port, ":") {
		return port
	}
	return ":" + port
}

func httpDurationFromEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

type surfaceTargetSource struct {
	db       *sql.DB
	fallback map[string]string
}

func (s surfaceTargetSource) List(ctx context.Context) ([]surfacesvc.AdapterTarget, error) {
	targetsByID := make(map[string]string, len(s.fallback))
	for id, baseURL := range s.fallback {
		targetsByID[strings.ToLower(strings.TrimSpace(id))] = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	}

	if s.db != nil {
		targets, err := repository.ListSurfaceRuntimeTargets(ctx, s.db, true)
		if err != nil {
			return nil, err
		}
		for _, target := range targets {
			id := strings.ToLower(strings.TrimSpace(target.SurfaceID))
			if !target.Enabled {
				delete(targetsByID, id)
				continue
			}
			targetsByID[id] = strings.TrimRight(strings.TrimSpace(target.BaseURL), "/")
		}
	}

	keys := make([]string, 0, len(targetsByID))
	for id := range targetsByID {
		if id != "" && targetsByID[id] != "" {
			keys = append(keys, id)
		}
	}
	sort.Strings(keys)
	out := make([]surfacesvc.AdapterTarget, 0, len(keys))
	for _, id := range keys {
		out = append(out, surfacesvc.AdapterTarget{ID: id, BaseURL: targetsByID[id]})
	}
	return out, nil
}

func surfaceTargetsFromEnv(logger *zap.Logger) map[string]string {
	raw := strings.TrimSpace(os.Getenv("YGGDRASIL_SURFACE_TARGETS"))
	if raw == "" {
		return nil
	}
	out := map[string]string{}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == ';'
	}) {
		id, baseURL, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			logger.Warn("ignoring malformed surface target", zap.String("target", part))
			continue
		}
		id = strings.ToLower(strings.TrimSpace(id))
		baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
		if id == "" || !validHTTPBaseURL(baseURL) {
			logger.Warn("ignoring invalid surface target", zap.String("surface", id), zap.String("base_url", baseURL))
			continue
		}
		out[id] = baseURL
	}
	return out
}

func validHTTPBaseURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func intFromEnv(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}
