package httpapi

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/oidc"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/mfa"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/auth/scim"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/cryptoenvelope"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/reqcache"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/provisioner"
	"github.com/dakasa-yggdrasil/yggdrasil-core/reconciler"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

type consoleCreateIntegrationInstanceRequest struct {
	Name           string                 `json:"name"`
	Namespace      string                 `json:"namespace,omitempty"`
	Description    string                 `json:"description,omitempty"`
	Labels         map[string]string      `json:"labels,omitempty"`
	TypeRef        model.ManifestSelector `json:"type_ref"`
	Status         string                 `json:"status,omitempty"`
	Owners         []string               `json:"owners,omitempty"`
	Credentials    map[string]any         `json:"credentials,omitempty"`
	CredentialsRef string                 `json:"credentials_ref,omitempty"`
	Config         map[string]any         `json:"config,omitempty"`
	Discovery      struct {
		Enabled             bool   `json:"enabled"`
		Mode                string `json:"mode,omitempty"`
		SyncIntervalSeconds int    `json:"sync_interval_seconds,omitempty"`
	} `json:"discovery"`
	Execution struct {
		DefaultDryRun bool `json:"default_dry_run,omitempty"`
		MaxBatchSize  int  `json:"max_batch_size,omitempty"`
	} `json:"execution"`
}

type consoleCreateManifestRequest struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	Description string            `json:"description,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Active      *bool             `json:"active,omitempty"`
	Spec        json.RawMessage   `json:"spec"`
}

type catalogDiscoveryRegisterRequest struct {
	Registration model.CatalogDiscoveryRegistration `json:"registration"`
}

type guardianApprovalDecisionRequest struct {
	Status   string         `json:"status"`
	Comment  string         `json:"comment,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type guardianMemoryReviewRequest struct {
	Namespace        string `json:"namespace,omitempty"`
	ActionType       string `json:"action_type"`
	PatternKind      string `json:"pattern_kind,omitempty"`
	PatternValue     string `json:"pattern_value,omitempty"`
	IncidentCategory string `json:"incident_category,omitempty"`
	ProviderGroup    string `json:"provider_group,omitempty"`
	ReviewStatus     string `json:"review_status"`
	Comment          string `json:"comment,omitempty"`
}

type integrationCatalogResponse struct {
	Domains []model.IntegrationCatalogDomain `json:"domains"`
}

type integrationCatalogEntryDetailResponse struct {
	Entry                   model.IntegrationCatalogEntry `json:"entry"`
	IntegrationTypeManifest model.Manifest                `json:"integrationTypeManifest"`
}

type collaboratorsResponse struct {
	Collaborators []model.Collaborator       `json:"collaborators"`
	Pagination    *model.PaginationResponse  `json:"pagination,omitempty"`
}

type teamsResponse struct {
	Teams []model.Team `json:"teams"`
}

type membershipsResponse struct {
	Memberships []model.TeamMembership `json:"memberships"`
}

type manifestsResponse struct {
	Manifests []model.Manifest `json:"manifests"`
}

type managedSecretsResponse struct {
	Secrets []model.ManagedSecretView `json:"secrets"`
}

type rotateManagedSecretRequest struct {
	Data      map[string]string                 `json:"data"`
	Metadata  map[string]any                    `json:"metadata,omitempty"`
	Rotation  model.ManagedSecretRotationPolicy `json:"rotation,omitempty"`
	ExpiresAt *time.Time                        `json:"expires_at,omitempty"`
}

type updateManagedSecretRequest struct {
	Metadata map[string]any `json:"metadata,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// New builds the synchronous HTTP API exposed directly by yggdrasil-core.
func New(serviceName string, db *sql.DB, conn *amqp.Connection, logger *zap.Logger, opts ...ServerOption) (http.Handler, error) {
	if db == nil {
		return nil, fmt.Errorf("http api requires postgres")
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	// Audit 2026-05-27 A12 — fail-loud at boot if security-critical env
	// vars are missing in production. A silent fallback to known-public
	// dev strings (AUTH_THIRD_PARTY_STATE_SECRET, YGGDRASIL_CSRF_HMAC_SECRET)
	// would let a misconfigured deploy roll out looking healthy while the
	// security envelope is wide open.
	if err := validateBootSecrets(); err != nil {
		return nil, err
	}

	server := &Server{
		serviceName: serviceName,
		db:          db,
		rabbitmq:    conn,
		logger:      logger,
	}
	// Optional: auth secrets envelope. KEK is 32 raw bytes base64-encoded
	// in YGGDRASIL_AUTH_KEK_BASE64; if absent the MFA HTTP layer fails
	// loud rather than persisting unencrypted TOTP/WebAuthn material.
	if kek := strings.TrimSpace(os.Getenv("YGGDRASIL_AUTH_KEK_BASE64")); kek != "" {
		raw, err := base64.StdEncoding.DecodeString(kek)
		if err != nil {
			return nil, fmt.Errorf("YGGDRASIL_AUTH_KEK_BASE64: %w", err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("YGGDRASIL_AUTH_KEK_BASE64 must decode to 32 bytes, got %d", len(raw))
		}
		server.envelope = cryptoenvelope.NewWithStaticKEK(raw)
	}
	server.dispatchWorkflow = func(ctx context.Context, ref model.ManifestSelector, inputs map[string]any) error {
		// Persist run to workflow_runs so audit trail + console UI can
		// see webhook-driven dispatches alongside async API dispatches.
		// Before this, webhook-triggered runs (handlePushEvent goroutine)
		// executed in-memory only — RunWorkflow returned an in-memory
		// response that the caller threw away, and the workflow_runs
		// table never got an INSERT. Visible symptom: pushes to a repo
		// with a binding fired `deploy-via-kustomize-source`, the steps
		// executed, but `SELECT * FROM workflow_runs WHERE workflow_name
		// = 'deploy-via-kustomize-source'` showed nothing from today —
		// silent unobservable deploys.
		req := model.RunWorkflowRequest{Workflow: ref, Inputs: inputs}
		runID := uuid.New()
		if err := repository.InsertWorkflowRun(ctx, server.db, runID, req.Workflow, req.Inputs, req.Metadata); err != nil {
			return fmt.Errorf("insert workflow_run: %w", err)
		}
		startedAt := time.Now().UTC()
		_ = repository.MarkWorkflowRunRunning(ctx, server.db, runID, startedAt)

		response, runErr := messagecontroller.RunWorkflow(ctx, server.rabbitmq, server.db, req)

		status := "succeeded"
		errMsg := ""
		var resultPayload any
		if runErr != nil {
			status = "failed"
			errMsg = runErr.Error()
		} else {
			resultPayload = response
			if strings.EqualFold(response.Status, "failed") {
				status = "failed"
				if response.Metadata != nil {
					if v, ok := response.Metadata["failed_step"].(string); ok && v != "" {
						errMsg = "step " + v + " failed"
					}
				}
			}
		}
		_ = repository.FinalizeWorkflowRun(ctx, server.db, runID, status, resultPayload, errMsg, time.Now().UTC())
		return runErr
	}

	for _, opt := range opts {
		opt(server)
	}

	// Load the capability-naming allowlist once at boot. Path is
	// /app/config/ in production images; relative fallback covers
	// local dev where /app does not exist. A missing file leaves the
	// validator disabled silently (warn-only Phase 1 is opt-in).
	if server.capabilityAllowlist == nil {
		allowlistPath := os.Getenv("YGGDRASIL_CAPABILITY_NAMING_ALLOWLIST")
		if allowlistPath == "" {
			if _, statErr := os.Stat("/app/config/capability_naming_allowlist.yaml"); statErr == nil {
				allowlistPath = "/app/config/capability_naming_allowlist.yaml"
			} else {
				allowlistPath = "config/capability_naming_allowlist.yaml"
			}
		}
		if al, alErr := manifestengine.LoadCapabilityNamingAllowlist(allowlistPath); alErr == nil {
			server.capabilityAllowlist = al
		}
	}

	// Resolve the validator phase once at boot.  WithValidatorPhase()
	// (test-only) can override; production reads YGGDRASIL_VALIDATOR_PHASE.
	if server.validatorPhase == "" {
		server.validatorPhase = resolveValidatorPhase()
	}

	// Per-IP login rate limiter (security audit 2026-05-27 A4). The
	// burst+refill numbers are conservative (5/burst, 1/min after that)
	// — high enough to forgive a real user fumbling their password,
	// low enough to slow distributed brute-force significantly. Idle
	// entries GC after 10min so the in-memory map stays small.
	if server.loginLimiter == nil {
		server.loginLimiter = newLoginRateLimiter(5, time.Minute, 10*time.Minute)
	}

	// WebAuthn boot — registration ceremony session store + the lib's
	// engine bound to the relying-party id/origins. We fail soft: a
	// missing/invalid config leaves both fields nil and the handlers
	// return 503 rather than stubbing fake challenges.
	if server.webauthnSessions == nil {
		server.webauthnSessions = mfa.NewSessionStore(5 * time.Minute)
	}
	if server.webauthnEngine == nil {
		if engine, err := mfa.NewWebAuthn(mfa.Config{
			RPDisplayName: webauthnRPDisplayName(),
			RPID:          webauthnRelyingPartyID(),
			Origins:       webauthnAllowedOrigins(),
		}); err == nil {
			server.webauthnEngine = engine
		} else if server.logger != nil {
			server.logger.Warn("webauthn engine boot failed; passkey endpoints will 503", zap.Error(err))
		}
	}

	mux := http.NewServeMux()

	// Routes the credentials middleware must permit even when the collaborator
	// is locked out (password expired / MFA not enrolled). These are the
	// endpoints that ESCAPE the locked state, plus public endpoints that don't
	// have an authenticated user yet.
	credentialsAllowlist := []string{
		"/api/v1/auth/passwords/change",
		"/api/v1/auth/logout",
		"/api/v1/auth/session",
		"/api/v1/auth/mfa/enroll/request",
		"/api/v1/auth/mfa/enroll/validate",
		"/api/v1/auth/mfa/factors/totp/begin",
		"/api/v1/auth/mfa/factors/totp/finish",
		// WebAuthn enroll begin/finish + login begin/finish — same
		// "escape" semantics as the TOTP enroll routes (must work
		// against locked-out users so they can configure MFA before
		// the session unlocks). The login routes are public anyway —
		// they don't require a session by definition.
		"/api/v1/auth/mfa/factors/webauthn/begin",
		"/api/v1/auth/mfa/factors/webauthn/finish",
		"/api/v1/auth/mfa/webauthn/login/begin",
		"/api/v1/auth/mfa/webauthn/login/finish",
	}
	guard := func(h http.HandlerFunc) http.HandlerFunc {
		return server.requirePasswordValid(credentialsAllowlist, h)
	}

	// `GET /{$}` matches the literal root path only (Go 1.22+ ServeMux
	// syntax). The previous `GET /` was a wildcard catch-all that
	// conflicted with sub-routes registered through other paths — most
	// notably `/oidc/` (registered by oidc.MountOIDC) which matches all
	// methods on /oidc/* and therefore tied with the GET / catch-all.
	// Restricting GET / to just the root keeps the original health-style
	// response on `/` and lets the sub-routers own everything below it.
	mux.HandleFunc("GET /{$}", server.handleRoot)
	mux.HandleFunc("GET /healthz", server.handleHealthz)
	mux.HandleFunc("GET /metrics", server.handleMetrics)
	mux.HandleFunc("GET /openapi.json", server.handleOpenAPI)
	// Generic manifest endpoints. Used by the CLI (`yggdrasil get <kind>`,
	// `yggdrasil apply -f <file>`) so adopters work with any kind without
	// the CLI needing a per-kind URL table. Kind-specific endpoints stay
	// for console integrations that want stricter typing.
	mux.HandleFunc("GET /api/v1/manifests", server.handleManifestListGeneric)
	mux.HandleFunc("POST /api/v1/manifests", server.handleManifestCreateGeneric)
	// DELETE companion: hard-delete by default, ?soft=true flips active=FALSE.
	// Same token guard as POST /api/v1/workflow-runs via the in-handler
	// authorizeWorkflowRunRequest call. Idempotent on not-found.
	mux.HandleFunc("DELETE /api/v1/manifests/{id}", server.handleManifestDelete)
	// Public publish endpoint: external sources (Grafana webhooks, K8s
	// informers, …) drop typed events here, the addon trigger loop picks
	// them up and fires workflows declared with trigger.mode=event. Auth
	// reuses the same shared-token helper as POST /api/v1/workflow-runs.
	mux.HandleFunc("POST /api/v1/events", server.handleEventPublish)
	mux.HandleFunc("POST /api/v1/github/webhook", server.handleGitHubWebhook)
	mux.HandleFunc("GET /readyz", server.handleReadyz)
	mux.HandleFunc("POST /api/v1/auth/passwords", server.handleAuthPasswordUpsert)
	// No guard: handler authorizes via YGGDRASIL_AUTH_ADMIN_TOKEN (static admin token),
	// not session. Wrapping with the session-based guard would shadow that auth and
	// reject every admin-token caller with 401 unauthenticated.
	mux.HandleFunc("POST /api/v1/auth/passwords/setup-tokens", server.handleIssueSetupToken)
	mux.HandleFunc("POST /api/v1/auth/passwords/setup", server.handleSetupCommit)
	// Preflight: fail fast before the user fills out the form. Same auth model
	// as /setup (the token itself is the credential).
	mux.HandleFunc("GET /api/v1/auth/passwords/setup/preflight", server.handleSetupPreflight)
	// /passwords/change accepts the current password to derive the new one
	// — same brute-force surface as /login, so the per-IP gate applies.
	mux.Handle("POST /api/v1/auth/passwords/change",
		loginRateLimit(server.loginLimiter, http.HandlerFunc(server.handlePasswordChange)))
	mux.HandleFunc("POST /api/v1/auth/passwords/forgot", server.handlePasswordForgot)
	mux.HandleFunc("POST /api/v1/auth/passwords/reset", server.handlePasswordReset)
	// Login is rate-limited per source IP to slow brute-force attacks
	// (security audit 2026-05-27 A4). The middleware wraps the handler
	// so the limiter check runs before any DB work.
	mux.Handle("POST /api/v1/auth/login", loginRateLimit(server.loginLimiter, http.HandlerFunc(server.handleAuthLogin)))
	mux.HandleFunc("POST /api/v1/auth/third-party/login", server.handleAuthThirdPartyLogin)
	mux.HandleFunc("GET /api/v1/auth/third-party/start/{provider}", server.handleAuthThirdPartyStart)
	mux.HandleFunc("GET /api/v1/auth/third-party/callback/{provider}", server.handleAuthThirdPartyCallback)
	mux.HandleFunc("GET /api/v1/auth/third-party-identities", server.handleThirdPartyIdentityList)
	// RBAC sweep #2 (2026-05-28) — /api/v1/auth/* mutations now gated server-side
	// under permManageAuthProviders, matching the /api/v1/console/auth/* gate.
	// INTEGRATION_CONTRACT §12: backend is the authorization authority — the
	// SPA "hides the UI" defense is not sufficient. Workflow-token automation
	// (no claims attached) is allowed through by the middleware unchanged.
	mux.HandleFunc("POST /api/v1/auth/third-party-identities", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyIdentityUpsert))
	mux.HandleFunc("DELETE /api/v1/auth/third-party-identities/{provider}/{subject}", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyIdentityDelete))
	mux.HandleFunc("GET /api/v1/auth/providers", server.handleThirdPartyAuthProviderList)
	mux.HandleFunc("POST /api/v1/auth/providers", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyAuthProviderUpsert))
	mux.HandleFunc("GET /api/v1/auth/providers/{provider}", server.handleThirdPartyAuthProviderGet)
	mux.HandleFunc("DELETE /api/v1/auth/providers/{provider}", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyAuthProviderDelete))
	mux.HandleFunc("GET /api/v1/auth/session", server.handleAuthSession)
	// ForwardAuth probe for the surface ingress (/s/*). Gated by
	// requireAuthenticatedConsoleAPIs (see requiresAuthenticatedConsoleAPI):
	// resolves the session cookie OR an OP-issued bearer JWT and answers
	// 200 (+ identity headers) / 401 so Traefik's ForwardAuth middleware
	// can guard the operator/AI surfaces.
	mux.HandleFunc("GET /api/v1/auth/verify", server.handleAuthVerify)
	mux.HandleFunc("POST /api/v1/auth/logout", server.handleAuthLogout)
	// MFA enroll endpoints (universal MFA mandatory invariant).
	mux.HandleFunc("POST /api/v1/auth/mfa/enroll/request", server.handleMFAEnrollRequest)
	mux.HandleFunc("GET /api/v1/auth/mfa/enroll/validate", server.handleMFAEnrollValidate)
	mux.HandleFunc("POST /api/v1/auth/mfa/factors/totp/begin", server.handleMFATOTPBegin)
	mux.HandleFunc("POST /api/v1/auth/mfa/factors/totp/finish", server.handleMFATOTPFinish)
	mux.HandleFunc("POST /api/v1/auth/mfa/factors/webauthn/begin", server.handleMFAWebAuthnBegin)
	mux.HandleFunc("POST /api/v1/auth/mfa/factors/webauthn/finish", server.handleMFAWebAuthnFinish)
	// WebAuthn login (passkey 2nd factor) — POSTed by LoginPage AFTER the
	// password step returned 202 mfa_required with `webauthn` in factors.
	//
	// Both endpoints take the user identifier and the finish endpoint also
	// takes the password — same brute-force surface as /api/v1/auth/login.
	// They MUST sit behind the same per-IP rate limiter or an attacker can
	// detour through the passkey flow to skip the gate on /login.
	mux.Handle("POST /api/v1/auth/mfa/webauthn/login/begin",
		loginRateLimit(server.loginLimiter, http.HandlerFunc(server.handleMFAWebAuthnLoginBegin)))
	mux.Handle("POST /api/v1/auth/mfa/webauthn/login/finish",
		loginRateLimit(server.loginLimiter, http.HandlerFunc(server.handleMFAWebAuthnLoginFinish)))
	// Authenticated factor management (rename, remove). List is also
	// available via GET /api/v1/auth/mfa/factors.
	mux.HandleFunc("GET /api/v1/auth/mfa/factors", guard(server.handleMFAFactorsList))
	mux.HandleFunc("PATCH /api/v1/auth/mfa/factors/webauthn/{credential_id}", guard(server.handleMFAWebAuthnRename))
	mux.HandleFunc("DELETE /api/v1/auth/mfa/factors/webauthn/{credential_id}", guard(server.handleMFAWebAuthnDelete))
	mux.HandleFunc("POST /api/v1/auth/mfa/recovery-codes", guard(server.handleMFAGenerateRecoveryCodes))
	// SCIM clients admin (rotate bearer tokens) — RBAC sweep #2.
	mux.HandleFunc("POST /api/v1/auth/scim/clients", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleSCIMClientCreate))
	mux.HandleFunc("GET /api/v1/auth/scim/clients", server.handleSCIMClientList)
	// SAML 2.0 IdP endpoints — Phase 1: metadata + admin SP/key registry are
	// fully wired; SSO/SLO HTTP handlers stub 501 until session-provider
	// integration lands in Phase 2.
	mux.HandleFunc("GET /saml/metadata", server.handleSAMLMetadata)
	mux.HandleFunc("POST /saml/sso", server.handleSAMLSSO)
	mux.HandleFunc("GET /saml/sso", server.handleSAMLSSO)
	mux.HandleFunc("POST /saml/slo", server.handleSAMLSLO)
	// SAML admin mutations — RBAC sweep #2: permManageAuthProviders mirrors
	// /api/v1/console/auth/saml/* gates. List endpoint stays GET-only.
	mux.HandleFunc("POST /api/v1/auth/saml/service-providers", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleSAMLSPRegister))
	mux.HandleFunc("GET /api/v1/auth/saml/service-providers", server.handleSAMLSPList)
	mux.HandleFunc("POST /api/v1/auth/saml/rotate-signing-cert", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleSAMLRotateSigningCert))
	// SCIM 2.0 IdP (read-only do lado SP). Bearer token validated against
	// scim_clients table; PUT/PATCH/DELETE rejected by ReadOnlyGuard to
	// preserve Crossplane-style zero-drift invariant.
	scimMux := http.NewServeMux()
	scim.NewServer(server.db).RegisterRoutes(scimMux)
	mux.Handle("/scim/v2/", scim.BearerAuth(server.db)(scim.ReadOnlyGuard()(scimMux)))
	// RBAC sweep #2 (2026-05-28) — POST /api/v1/invites gated under
	// permCreateCollaborator. The legacy comment "tartaro-fe is responsible
	// for hiding the UI for non-admins" violated INTEGRATION_CONTRACT §12
	// (backend is the authorization authority). Workflow-token automation
	// continues to bypass via the no-claims path.
	mux.HandleFunc("POST /api/v1/invites", server.requireOpsPermissionFunc(permCreateCollaborator, guard(server.handleInviteCreate)))
	mux.HandleFunc("GET /api/v1/invites", guard(server.handleInviteList))
	mux.HandleFunc("GET /api/v1/invites/validate", server.handleInviteValidate)
	mux.HandleFunc("GET /api/v1/integration-catalog", server.handleIntegrationCatalogList)
	mux.HandleFunc("GET /api/v1/integration-catalog/{domain}/{section}/{entry}", server.handleIntegrationCatalogEntry)
	mux.HandleFunc("GET /api/v1/catalog/discovery", server.handleCatalogDiscovery)
	mux.HandleFunc("POST /api/v1/catalog/discovery/register", server.requireOpsPermissionFunc(permManageIntegrations, server.handleCatalogDiscoveryRegister))
	mux.HandleFunc("GET /api/v1/integration-instances", server.handleIntegrationInstanceList)
	mux.HandleFunc("POST /api/v1/integration-instances", server.requireOpsPermissionFunc(permManageIntegrations, server.handleIntegrationInstanceCreate))
	mux.HandleFunc("GET /api/v1/integration-runtime-states", server.handleIntegrationRuntimeStateList)
	// Admin-only manual sync: operator triggers a live describe + apply for one integration_type.
	// Auth: same YGGDRASIL_AUTH_ADMIN_TOKEN check used by POST /api/v1/auth/passwords.
	mux.HandleFunc("POST /api/v1/integration-types/{id}/sync", server.handleIntegrationTypeSync(server.buildManifestSyncDeps()))
	mux.HandleFunc("POST /api/v1/integrations/{instance_id}/webhook", server.handleIntegrationWebhook)

	// Ops console — Phase 1 foundation (RBAC-gated since Phase 5B 2026-05-28).
	// Mirror of /api/v1/console/* enforcement: surface-console's lib/ops/api.ts
	// hits these routes for the surface-runtime and workflow ops dashboards;
	// every route now goes through requireOpsPermissionFunc(perm, …) so the
	// backend is the source of truth for authorization (INTEGRATION_CONTRACT
	// §12). Single `YGGDRASIL_CONSOLE_RBAC_ENFORCE` env switch governs both
	// namespaces, so the Phase-5 observation window covers Phase 5B too.
	//
	// Mapping:
	//   - surfaces/surface-targets: read = view_integrations; mutate = manage_integrations
	//   - workflows: view = view_ops; dispatch/retry/abort/replay = manage_workflows
	//   - approvals / drift: view = view_ops; decide / reconcile = manage_workflows
	//     (these are workflow primitives, same class as guardian-approvals)
	//   - catalog: view_integrations (the FE renders it from the same registry
	//     as /api/v1/console/integration-catalog)
	//   - system/health: view_ops (operator dashboard, read-only)
	//   - audit: view_audit
	//   - collaborators/missing-mfa: view_people (PII listing of identities)
	mux.HandleFunc("GET /api/v1/ops/surfaces", server.requireOpsPermissionFunc(permViewIntegrations, server.handleOpsSurfacesList))
	mux.HandleFunc("GET /api/v1/ops/surface-targets", server.requireOpsPermissionFunc(permViewIntegrations, server.handleOpsSurfaceTargetsList))
	mux.HandleFunc("PUT /api/v1/ops/surface-targets/{id}", server.requireOpsPermissionFunc(permManageIntegrations, server.handleOpsSurfaceTargetUpsert))
	mux.HandleFunc("DELETE /api/v1/ops/surface-targets/{id}", server.requireOpsPermissionFunc(permManageIntegrations, server.handleOpsSurfaceTargetDelete))
	mux.HandleFunc("POST /api/v1/ops/surface-targets/{id}/refresh", server.requireOpsPermissionFunc(permManageIntegrations, server.handleOpsSurfaceTargetRefresh))
	mux.HandleFunc("GET /api/v1/ops/surfaces/{id}/manifest", server.requireOpsPermissionFunc(permViewIntegrations, server.handleOpsSurfaceManifest))
	mux.HandleFunc("GET /api/v1/ops/surfaces/{id}/data/{viewId}", server.requireOpsPermissionFunc(permViewIntegrations, server.handleOpsSurfaceData))
	mux.HandleFunc("POST /api/v1/ops/surfaces/{id}/action/{actionId}", server.requireOpsPermissionFunc(permManageIntegrations, server.handleOpsSurfaceAction))
	mux.HandleFunc("GET /api/v1/ops/workflows", server.requireOpsPermissionFunc(permViewOps, server.handleOpsWorkflowsList))
	mux.HandleFunc("GET /api/v1/ops/workflows/{runId}", server.requireOpsPermissionFunc(permViewOps, server.handleOpsWorkflowDetail))
	mux.HandleFunc("POST /api/v1/ops/workflows/{runId}/retry", server.requireOpsPermissionFunc(permManageWorkflows, server.handleOpsWorkflowRetry))
	mux.HandleFunc("POST /api/v1/ops/workflows/{runId}/abort", server.requireOpsPermissionFunc(permManageWorkflows, server.handleOpsWorkflowAbort))
	mux.HandleFunc("POST /api/v1/ops/workflows/{runId}/replay", server.requireOpsPermissionFunc(permManageWorkflows, server.handleOpsWorkflowReplay))
	mux.HandleFunc("GET /api/v1/ops/approvals", server.requireOpsPermissionFunc(permViewOps, server.handleOpsApprovalsList))
	mux.HandleFunc("POST /api/v1/ops/approvals/{id}/approve", server.requireOpsPermissionFunc(permManageWorkflows, server.handleOpsApprovalDecide("approved")))
	mux.HandleFunc("POST /api/v1/ops/approvals/{id}/reject", server.requireOpsPermissionFunc(permManageWorkflows, server.handleOpsApprovalDecide("rejected")))
	mux.HandleFunc("GET /api/v1/ops/drift", server.requireOpsPermissionFunc(permViewOps, server.handleOpsDriftList))
	mux.HandleFunc("POST /api/v1/ops/drift/{id}/reconcile", server.requireOpsPermissionFunc(permManageWorkflows, server.handleOpsDriftReconcile))
	mux.HandleFunc("GET /api/v1/ops/catalog", server.requireOpsPermissionFunc(permViewIntegrations, server.handleOpsCatalog))
	mux.HandleFunc("GET /api/v1/ops/system/health", server.requireOpsPermissionFunc(permViewOps, server.handleOpsSystemHealth))
	mux.HandleFunc("GET /api/v1/ops/audit", server.requireOpsPermissionFunc(permViewAudit, server.handleOpsAuditList))
	mux.HandleFunc("GET /api/v1/ops/collaborators/missing-mfa", server.requireOpsPermissionFunc(permViewPeople, server.handleOpsCollaboratorsMissingMFA))

	// RBAC sweep #2 (2026-05-28) — every /api/v1/* mutating route that
	// duplicates a /api/v1/console/* route is now wrapped in the canonical
	// permission gate. INTEGRATION_CONTRACT §12: backend is the
	// authorization authority. Workflow-token automation (no claims
	// attached) is allowed through by the middleware unchanged, so
	// CI/CD and adapter callers keep working.
	mux.HandleFunc("GET /api/v1/collaborators", server.handleCollaboratorList)
	mux.HandleFunc("POST /api/v1/collaborators", server.requireOpsPermissionFunc(permCreateCollaborator, server.handleCollaboratorCreate))
	mux.HandleFunc("GET /api/v1/collaborators/{id}", server.handleCollaboratorGet)
	mux.HandleFunc("PATCH /api/v1/collaborators/{id}", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorUpdate))
	mux.HandleFunc("DELETE /api/v1/collaborators/{id}", server.requireOpsPermissionFunc(permOffboardCollaborator, server.handleCollaboratorDelete))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/offboard", server.requireOpsPermissionFunc(permOffboardCollaborator, server.handleCollaboratorOffboard))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/suspend", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorSuspend))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/unsuspend", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorUnsuspend))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/re-onboard", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorReOnboard))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/role-change", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorRoleChange))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/team-add", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorTeamAdd))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/team-remove", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorTeamRemove))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/attribute-set", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorAttributeSet))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/manager-change", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorManagerChange))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/absence/start", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorAbsenceStart))
	mux.HandleFunc("POST /api/v1/collaborators/{id}/absence/end", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorAbsenceEnd))
	mux.HandleFunc("GET /api/v1/collaborators/{id}/lifecycle-events", server.handleCollaboratorLifecycleEvents)
	mux.HandleFunc("GET /api/v1/collaborators/{id}/provider-state", server.handleCollaboratorProviderState)
	mux.HandleFunc("GET /api/v1/collaborators/{id}/effective-tartaro-actions", server.handleEffectiveTartaroActions)
	mux.HandleFunc("POST /api/v1/collaborators/{id}/sync-tartaro-actions", server.requireOpsPermissionFunc(permEditCollaborator, server.handleSyncTartaroActions))
	mux.HandleFunc("POST /api/v1/collaborator-external-identities", server.requireOpsPermissionFunc(permEditCollaborator, server.handleExternalIdentityPost))
	mux.HandleFunc("GET /api/v1/collaborator-external-identities", server.handleExternalIdentityGet)
	mux.HandleFunc("DELETE /api/v1/collaborator-external-identities/{id}", server.requireOpsPermissionFunc(permEditCollaborator, server.handleExternalIdentityDelete))
	mux.HandleFunc("GET /api/v1/permissions/catalog", server.handlePermissionList)
	mux.HandleFunc("POST /api/v1/permissions/catalog", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handlePermissionRegister))
	mux.HandleFunc("GET /api/v1/permissions/bindings", server.handlePermissionBindingList)
	mux.HandleFunc("POST /api/v1/permissions/bindings", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handlePermissionBindingCreate))
	mux.HandleFunc("POST /api/v1/permissions/evaluate", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handlePermissionEvaluate))
	mux.HandleFunc("GET /api/v1/teams", server.handleTeamList)
	mux.HandleFunc("POST /api/v1/teams", server.requireOpsPermissionFunc(permCreateTeam, server.handleTeamCreate))
	mux.HandleFunc("GET /api/v1/teams/{id}", server.handleTeamGet)
	mux.HandleFunc("PATCH /api/v1/teams/{id}", server.requireOpsPermissionFunc(permEditTeam, server.handleTeamUpdate))
	mux.HandleFunc("DELETE /api/v1/teams/{id}", server.requireOpsPermissionFunc(permEditTeam, server.handleTeamDelete))
	mux.HandleFunc("POST /api/v1/teams/{id}/sync", server.requireOpsPermissionFunc(permEditTeam, server.handleTeamSync))
	mux.HandleFunc("GET /api/v1/teams/{id}/provisioning-status", server.handleTeamProvisioningStatus)
	mux.HandleFunc("GET /api/v1/teams/{id}/grants", server.handleTeamGrantList)
	mux.HandleFunc("POST /api/v1/teams/{id}/grants", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handleTeamGrantCreate))
	mux.HandleFunc("DELETE /api/v1/teams/{id}/grants/{grant_id}", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handleTeamGrantDelete))
	mux.HandleFunc("GET /api/v1/teams/{id}/available-sources", server.handleTeamAvailableSources)
	mux.HandleFunc("GET /api/v1/team-memberships", server.handleTeamMembershipList)
	mux.HandleFunc("POST /api/v1/team-memberships", server.requireOpsPermissionFunc(permEditTeam, server.handleTeamMembershipUpsert))
	mux.HandleFunc("GET /api/v1/products", server.handleProductList)
	mux.HandleFunc("POST /api/v1/products", server.requireOpsPermissionFunc(permManageWorkflows, server.handleProductCreate))
	// Managed secrets — Phase 5B split: permManageSecrets (NOT permManageIntegrations).
	mux.HandleFunc("GET /api/v1/secrets", server.handleManagedSecretList)
	mux.HandleFunc("GET /api/v1/secrets/{namespace}/{name}", server.handleManagedSecretGet)
	mux.HandleFunc("POST /api/v1/secrets", server.requireOpsPermissionFunc(permManageSecrets, server.handleManagedSecretCreate))
	mux.HandleFunc("POST /api/v1/secrets/{namespace}/{name}/rotate", server.requireOpsPermissionFunc(permManageSecrets, server.handleManagedSecretRotate))
	mux.HandleFunc("POST /api/v1/secrets/{namespace}/{name}/disable", server.requireOpsPermissionFunc(permManageSecrets, server.handleManagedSecretDisable))
	mux.HandleFunc("POST /api/v1/secrets/{namespace}/{name}/revoke", server.requireOpsPermissionFunc(permManageSecrets, server.handleManagedSecretRevoke))
	mux.HandleFunc("POST /api/v1/secrets/materialize-all", server.requireOpsPermissionFunc(permManageSecrets, server.handleMaterializeAll))
	mux.HandleFunc("POST /api/v1/secrets/{namespace}/{name}/materialize", server.requireOpsPermissionFunc(permManageSecrets, server.handleMaterializeOne))
	mux.HandleFunc("GET /api/v1/reconciler/status", server.handleReconcilerStatus)
	mux.HandleFunc("GET /api/v1/repository-bindings", server.handleRepositoryBindingList)
	mux.HandleFunc("POST /api/v1/repository-bindings", server.requireOpsPermissionFunc(permManageIntegrations, server.handleRepositoryBindingCreate))
	mux.HandleFunc("GET /api/v1/guardian-policies", server.handleGuardianPolicyList)
	mux.HandleFunc("POST /api/v1/guardian-policies", server.requireOpsPermissionFunc(permManageWorkflows, server.handleGuardianPolicyCreate))
	mux.HandleFunc("GET /api/v1/guardian-approvals", server.handleGuardianApprovalList)
	mux.HandleFunc("POST /api/v1/guardian-approvals", server.requireOpsPermissionFunc(permManageWorkflows, server.handleGuardianApprovalCreate))
	mux.HandleFunc("POST /api/v1/guardian-approvals/{namespace}/{name}/decision", server.requireOpsPermissionFunc(permManageWorkflows, server.handleGuardianApprovalDecision))
	mux.HandleFunc("GET /api/v1/guardian-memories", server.handleGuardianMemoryList)
	mux.HandleFunc("GET /api/v1/remediation-bundles", server.handleRemediationBundleList)
	mux.HandleFunc("POST /api/v1/remediation-bundles", server.requireOpsPermissionFunc(permManageWorkflows, server.handleRemediationBundleCreate))
	mux.HandleFunc("POST /api/v1/guardian-memories/review", server.requireOpsPermissionFunc(permManageWorkflows, server.handleGuardianMemoryReview))
	mux.HandleFunc("GET /api/v1/remediation-contracts", server.handleRemediationContractList)
	mux.HandleFunc("POST /api/v1/remediation-contracts", server.requireOpsPermissionFunc(permManageWorkflows, server.handleRemediationContractCreate))
	mux.HandleFunc("GET /api/v1/surfaces", server.handleSurfaceList)
	mux.HandleFunc("POST /api/v1/surfaces", server.requireOpsPermissionFunc(permManageIntegrations, server.handleSurfaceCreate))
	mux.HandleFunc("GET /api/v1/workflows", server.handleWorkflowList)
	mux.HandleFunc("POST /api/v1/workflows", server.requireOpsPermissionFunc(permManageWorkflows, server.handleWorkflowCreate))
	mux.HandleFunc("POST /api/v1/workflow-runs", server.requireOpsPermissionFunc(permManageWorkflows, server.handleWorkflowRun))
	mux.HandleFunc("GET /api/v1/workflow-runs/{run_id}", server.handleWorkflowRunGet)
	mux.HandleFunc("POST /api/v1/integrations/install", server.requireOpsPermissionFunc(permManageIntegrations, server.handleInstallIntegration))
	mux.HandleFunc("POST /api/v1/provision/aws", server.requireOpsPermissionFunc(permManageOrganization, server.handleProvisionAWS))
	mux.HandleFunc("POST /api/v1/products/{namespace}/{name}/deploy", requireDeployToken(server.handleDeployProduct))
	mux.HandleFunc("POST /api/v1/products/deploy-all", requireDeployToken(server.handleDeployAll))
	mux.HandleFunc("POST /api/v1/bootstrap", requireDeployToken(server.handleBootstrap))
	mux.HandleFunc("GET /api/v1/tenant/brand", server.handleTenantBrandGet)
	mux.HandleFunc("PATCH /api/v1/tenant/brand", server.requireOpsPermissionFunc(permManageOrganization, server.handleTenantBrandPatch))
	mux.HandleFunc("GET /api/v1/me", guard(server.handleMe))
	mux.HandleFunc("GET /api/v1/me/preferences", guard(server.handleUserPreferencesGet))
	mux.HandleFunc("PATCH /api/v1/me/preferences", guard(server.handleUserPreferencesPatch))
	// C8: self-service session list + revoke.  The list returns every
	// active session for the caller; revoke kills ONE session (NOT the
	// current one — use POST /auth/logout for that) and fans out the
	// §13 RFC 8417 back-channel logout.
	mux.HandleFunc("GET /api/v1/me/sessions", guard(server.handleMeSessionsList))
	mux.HandleFunc("DELETE /api/v1/me/sessions/{id}", guard(server.handleMeSessionsRevoke))
	// Phase 5 (2026-05-28) — RBAC enforcement on /api/v1/console/* routes.
	// Every route below is gated by `server.requireOpsPermissionFunc(perm, h)`,
	// which checks the caller's permission list (resolved from team_grants on
	// yggdrasil-self) against `perm`. See ops_rbac_middleware.go for the
	// warn/enforce two-phase rollout (`YGGDRASIL_CONSOLE_RBAC_ENFORCE`) and
	// ops_rbac_catalog.go for the permission constants. INTEGRATION_CONTRACT §12.
	//
	// Mapping: GET → view:<area>; POST/PATCH/DELETE → manage:<area> (or the
	// specific operation permission, e.g. offboard_collaborator).

	// Integration catalog & instances — read = view_integrations, write = manage_integrations.
	mux.HandleFunc("GET /api/v1/console/integration-catalog", server.requireOpsPermissionFunc(permViewIntegrations, server.handleIntegrationCatalogList))
	mux.HandleFunc("GET /api/v1/console/integration-catalog/{domain}/{section}/{entry}", server.requireOpsPermissionFunc(permViewIntegrations, server.handleIntegrationCatalogEntry))
	mux.HandleFunc("GET /api/v1/console/catalog-discovery", server.requireOpsPermissionFunc(permViewIntegrations, server.handleCatalogDiscovery))
	mux.HandleFunc("POST /api/v1/console/catalog-discovery/register", server.requireOpsPermissionFunc(permManageIntegrations, server.handleCatalogDiscoveryRegister))
	mux.HandleFunc("GET /api/v1/console/integration-instances", server.requireOpsPermissionFunc(permViewIntegrations, server.handleIntegrationInstanceList))
	mux.HandleFunc("POST /api/v1/console/integration-instances", server.requireOpsPermissionFunc(permManageIntegrations, server.handleIntegrationInstanceCreate))

	// Collaborators — list/read = view_people, create = create_collaborator,
	// update = edit_collaborator, delete/offboard = offboard_collaborator,
	// suspend / role-change / team / attr / manager / absence = edit_collaborator
	// (they all mutate a collaborator's current state; offboard_collaborator
	// stays specific because it's a terminal lifecycle event).
	mux.HandleFunc("GET /api/v1/console/collaborators", server.requireOpsPermissionFunc(permViewPeople, server.handleCollaboratorList))
	mux.HandleFunc("POST /api/v1/console/collaborators", server.requireOpsPermissionFunc(permCreateCollaborator, server.handleCollaboratorCreate))
	mux.HandleFunc("GET /api/v1/console/collaborators/{id}", server.requireOpsPermissionFunc(permViewPeople, server.handleCollaboratorGet))
	mux.HandleFunc("PATCH /api/v1/console/collaborators/{id}", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorUpdate))
	mux.HandleFunc("DELETE /api/v1/console/collaborators/{id}", server.requireOpsPermissionFunc(permOffboardCollaborator, server.handleCollaboratorDelete))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/offboard", server.requireOpsPermissionFunc(permOffboardCollaborator, server.handleCollaboratorOffboard))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/suspend", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorSuspend))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/unsuspend", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorUnsuspend))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/re-onboard", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorReOnboard))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/role-change", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorRoleChange))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/team-add", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorTeamAdd))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/team-remove", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorTeamRemove))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/attribute-set", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorAttributeSet))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/manager-change", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorManagerChange))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/absence/start", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorAbsenceStart))
	mux.HandleFunc("POST /api/v1/console/collaborators/{id}/absence/end", server.requireOpsPermissionFunc(permEditCollaborator, server.handleCollaboratorAbsenceEnd))
	mux.HandleFunc("GET /api/v1/console/collaborators/{id}/lifecycle-events", server.requireOpsPermissionFunc(permViewPeople, server.handleCollaboratorLifecycleEvents))
	mux.HandleFunc("GET /api/v1/console/collaborators/{id}/provider-state", server.requireOpsPermissionFunc(permViewPeople, server.handleCollaboratorProviderState))

	// Permissions catalog/bindings — read = manage_team_permissions (this is
	// admin-side surface, viewing the catalog implies the user is configuring
	// permissions). Evaluate = read-only check, still gated.
	mux.HandleFunc("GET /api/v1/console/permissions/catalog", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handlePermissionList))
	mux.HandleFunc("POST /api/v1/console/permissions/catalog", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handlePermissionRegister))
	mux.HandleFunc("GET /api/v1/console/permissions/bindings", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handlePermissionBindingList))
	mux.HandleFunc("POST /api/v1/console/permissions/bindings", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handlePermissionBindingCreate))
	mux.HandleFunc("POST /api/v1/console/permissions/evaluate", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handlePermissionEvaluate))

	// Teams — list/read = view_teams; create = create_team; update/sync = edit_team;
	// delete = edit_team (no separate destroy_team permission today); grants = manage_team_permissions.
	mux.HandleFunc("GET /api/v1/console/teams", server.requireOpsPermissionFunc(permViewTeams, server.handleTeamList))
	mux.HandleFunc("POST /api/v1/console/teams", server.requireOpsPermissionFunc(permCreateTeam, server.handleTeamCreate))
	mux.HandleFunc("GET /api/v1/console/teams/{id}", server.requireOpsPermissionFunc(permViewTeams, server.handleTeamGet))
	mux.HandleFunc("PATCH /api/v1/console/teams/{id}", server.requireOpsPermissionFunc(permEditTeam, server.handleTeamUpdate))
	mux.HandleFunc("DELETE /api/v1/console/teams/{id}", server.requireOpsPermissionFunc(permEditTeam, server.handleTeamDelete))
	mux.HandleFunc("POST /api/v1/console/teams/{id}/sync", server.requireOpsPermissionFunc(permEditTeam, server.handleTeamSync))
	mux.HandleFunc("GET /api/v1/console/teams/{id}/provisioning-status", server.requireOpsPermissionFunc(permViewTeams, server.handleTeamProvisioningStatus))
	mux.HandleFunc("GET /api/v1/console/teams/{id}/grants", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handleTeamGrantList))
	mux.HandleFunc("POST /api/v1/console/teams/{id}/grants", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handleTeamGrantCreate))
	mux.HandleFunc("DELETE /api/v1/console/teams/{id}/grants/{grant_id}", server.requireOpsPermissionFunc(permManageTeamPermissions, server.handleTeamGrantDelete))
	mux.HandleFunc("GET /api/v1/console/teams/{id}/available-sources", server.requireOpsPermissionFunc(permViewTeams, server.handleTeamAvailableSources))

	// Team memberships — list = view_teams; upsert = edit_team.
	mux.HandleFunc("GET /api/v1/console/team-memberships", server.requireOpsPermissionFunc(permViewTeams, server.handleTeamMembershipList))
	mux.HandleFunc("POST /api/v1/console/team-memberships", server.requireOpsPermissionFunc(permEditTeam, server.handleTeamMembershipUpsert))

	// Auth / third-party identities & providers — manage_auth_providers
	// (read AND write both gated on manage scope: surface-console hides
	// these screens unless the user can administer them).
	mux.HandleFunc("GET /api/v1/console/auth/third-party-identities", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyIdentityList))
	mux.HandleFunc("POST /api/v1/console/auth/third-party-identities", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyIdentityUpsert))
	mux.HandleFunc("DELETE /api/v1/console/auth/third-party-identities/{provider}/{subject}", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyIdentityDelete))
	mux.HandleFunc("GET /api/v1/console/auth/providers", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyAuthProviderList))
	mux.HandleFunc("POST /api/v1/console/auth/providers", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyAuthProviderUpsert))
	mux.HandleFunc("GET /api/v1/console/auth/providers/{provider}", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyAuthProviderGet))
	mux.HandleFunc("DELETE /api/v1/console/auth/providers/{provider}", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleThirdPartyAuthProviderDelete))
	mux.HandleFunc("POST /api/v1/console/auth/scim/clients", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleSCIMClientCreate))
	mux.HandleFunc("GET /api/v1/console/auth/scim/clients", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleSCIMClientList))
	mux.HandleFunc("POST /api/v1/console/auth/saml/service-providers", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleSAMLSPRegister))
	mux.HandleFunc("GET /api/v1/console/auth/saml/service-providers", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleSAMLSPList))
	mux.HandleFunc("POST /api/v1/console/auth/saml/rotate-signing-cert", server.requireOpsPermissionFunc(permManageAuthProviders, server.handleSAMLRotateSigningCert))

	// Products — list = view_ops; create = manage_workflows (products are
	// deployment workflows; create_product == author a new deploy graph).
	mux.HandleFunc("GET /api/v1/console/products", server.requireOpsPermissionFunc(permViewOps, server.handleProductList))
	mux.HandleFunc("POST /api/v1/console/products", server.requireOpsPermissionFunc(permManageWorkflows, server.handleProductCreate))

	// Managed secrets — Phase 5B split (2026-05-28).
	//
	// Previously gated by manage_integrations alongside integration provisioning,
	// the secret surface now uses the dedicated yggdrasil:manage_secrets
	// permission. Rationale: secret read/rotate has a HIGHER blast radius than
	// integration-instance configuration. An integration admin can register a
	// stripe instance with a `credentials_ref` URI WITHOUT inheriting the right
	// to read the underlying cluster secret. Operators who need full custody
	// receive BOTH permissions; the default integration-admin role does not.
	//
	// All routes (list/get/create/rotate/disable/revoke/materialize) use the
	// same gate — Phase 5 did not separate read from mutate inside the secret
	// namespace, and Phase 5B preserves that. The audit hook at
	// /api/v1/console/secrets/{namespace}/{name}/disable etc. still tags
	// audit_events via the existing ops_audit middleware.
	mux.HandleFunc("GET /api/v1/console/secrets", server.requireOpsPermissionFunc(permManageSecrets, server.handleManagedSecretList))
	mux.HandleFunc("GET /api/v1/console/secrets/{namespace}/{name}", server.requireOpsPermissionFunc(permManageSecrets, server.handleManagedSecretGet))
	mux.HandleFunc("POST /api/v1/console/secrets", server.requireOpsPermissionFunc(permManageSecrets, server.handleManagedSecretCreate))
	mux.HandleFunc("POST /api/v1/console/secrets/{namespace}/{name}/rotate", server.requireOpsPermissionFunc(permManageSecrets, server.handleManagedSecretRotate))
	mux.HandleFunc("POST /api/v1/console/secrets/{namespace}/{name}/disable", server.requireOpsPermissionFunc(permManageSecrets, server.handleManagedSecretDisable))
	mux.HandleFunc("POST /api/v1/console/secrets/{namespace}/{name}/revoke", server.requireOpsPermissionFunc(permManageSecrets, server.handleManagedSecretRevoke))
	mux.HandleFunc("POST /api/v1/console/secrets/materialize-all", server.requireOpsPermissionFunc(permManageSecrets, server.handleMaterializeAll))
	mux.HandleFunc("POST /api/v1/console/secrets/{namespace}/{name}/materialize", server.requireOpsPermissionFunc(permManageSecrets, server.handleMaterializeOne))

	// Reconciler status (read-only) → view_ops.
	mux.HandleFunc("GET /api/v1/console/reconciler/status", server.requireOpsPermissionFunc(permViewOps, server.handleReconcilerStatus))

	// Repository bindings — view = view_integrations; create = manage_integrations.
	mux.HandleFunc("GET /api/v1/console/repository-bindings", server.requireOpsPermissionFunc(permViewIntegrations, server.handleRepositoryBindingList))
	mux.HandleFunc("POST /api/v1/console/repository-bindings", server.requireOpsPermissionFunc(permManageIntegrations, server.handleRepositoryBindingCreate))

	// Guardian (policy + approvals + memories + remediation) — these are
	// workflow primitives. View = view_ops; create/decision/review = manage_workflows.
	mux.HandleFunc("GET /api/v1/console/guardian-policies", server.requireOpsPermissionFunc(permViewOps, server.handleGuardianPolicyList))
	mux.HandleFunc("POST /api/v1/console/guardian-policies", server.requireOpsPermissionFunc(permManageWorkflows, server.handleGuardianPolicyCreate))
	mux.HandleFunc("GET /api/v1/console/guardian-approvals", server.requireOpsPermissionFunc(permViewOps, server.handleGuardianApprovalList))
	mux.HandleFunc("POST /api/v1/console/guardian-approvals", server.requireOpsPermissionFunc(permManageWorkflows, server.handleGuardianApprovalCreate))
	mux.HandleFunc("POST /api/v1/console/guardian-approvals/{namespace}/{name}/decision", server.requireOpsPermissionFunc(permManageWorkflows, server.handleGuardianApprovalDecision))
	mux.HandleFunc("GET /api/v1/console/guardian-memories", server.requireOpsPermissionFunc(permViewOps, server.handleGuardianMemoryList))
	mux.HandleFunc("GET /api/v1/console/remediation-bundles", server.requireOpsPermissionFunc(permViewOps, server.handleRemediationBundleList))
	mux.HandleFunc("POST /api/v1/console/remediation-bundles", server.requireOpsPermissionFunc(permManageWorkflows, server.handleRemediationBundleCreate))
	mux.HandleFunc("POST /api/v1/console/guardian-memories/review", server.requireOpsPermissionFunc(permManageWorkflows, server.handleGuardianMemoryReview))
	mux.HandleFunc("GET /api/v1/console/remediation-contracts", server.requireOpsPermissionFunc(permViewOps, server.handleRemediationContractList))
	mux.HandleFunc("POST /api/v1/console/remediation-contracts", server.requireOpsPermissionFunc(permManageWorkflows, server.handleRemediationContractCreate))

	// Surfaces (federated surface manifests) — view = view_integrations;
	// create = manage_integrations.
	mux.HandleFunc("GET /api/v1/console/surfaces", server.requireOpsPermissionFunc(permViewIntegrations, server.handleSurfaceList))
	mux.HandleFunc("POST /api/v1/console/surfaces", server.requireOpsPermissionFunc(permManageIntegrations, server.handleSurfaceCreate))

	// Workflows + workflow-runs — view = view_ops; create/dispatch = manage_workflows.
	mux.HandleFunc("GET /api/v1/console/workflows", server.requireOpsPermissionFunc(permViewOps, server.handleWorkflowList))
	mux.HandleFunc("POST /api/v1/console/workflows", server.requireOpsPermissionFunc(permManageWorkflows, server.handleWorkflowCreate))
	mux.HandleFunc("POST /api/v1/console/workflow-runs", server.requireOpsPermissionFunc(permManageWorkflows, server.handleWorkflowRun))
	mux.HandleFunc("GET /api/v1/console/workflow-runs/{run_id}", server.requireOpsPermissionFunc(permViewOps, server.handleWorkflowRunGet))

	// Integrations install (privileged setup) → manage_integrations.
	mux.HandleFunc("POST /api/v1/console/integrations/install", server.requireOpsPermissionFunc(permManageIntegrations, server.handleInstallIntegration))

	// Cloud provision (cluster admin-only) → manage_organization. AWS provision
	// is bootstrap-class infrastructure; only org admins should run it.
	mux.HandleFunc("POST /api/v1/console/provision/aws", server.requireOpsPermissionFunc(permManageOrganization, server.handleProvisionAWS))

	// Phase 6 aggregator endpoints — audit 2026-05-27 §2.1-§2.4.
	//
	// Replace the N-round-trip patterns identified in the co-design audit
	// with single-call aggregates. Each gates on a dedicated permission
	// (or composite) and returns a denormalized response shape matching
	// what the surface page renders, so the FE drops merge logic.
	//
	//   overview-summary      → replaces 6 OverviewPage queries
	//   teams/{id}/edit-context → replaces 3 TeamEditPage queries
	//   surfaces/{id}/configure-context → replaces 3 OpsIntegrationsPage detail queries
	//
	// The collaborators-enriched response (4th aggregate) is delivered by
	// extending the EXISTING /api/v1/console/collaborators handler rather
	// than registering a new route — the FE just stops issuing the side
	// queries.
	mux.HandleFunc("GET /api/v1/console/overview-summary", server.requireOpsPermissionFunc(permViewOverview, server.handleConsoleOverviewSummary))
	mux.HandleFunc("GET /api/v1/console/teams/{id}/edit-context", server.requireOpsPermissionFunc(permViewTeams, server.handleConsoleTeamEditContext))
	mux.HandleFunc("GET /api/v1/ops/surfaces/{id}/configure-context", server.requireOpsPermissionFunc(permViewIntegrations, server.handleOpsSurfaceConfigureContext))

	// Product deploy + bootstrap routes — already gated by requireDeployToken
	// (machine-only deploy automation, no human actor); RBAC is layered on
	// top so that IF a human session reaches them they STILL need
	// manage_workflows / manage_organization. The deploy token path bypasses
	// RBAC by virtue of having no claims (see middleware).
	mux.HandleFunc("POST /api/v1/console/products/{namespace}/{name}/deploy", server.requireOpsPermissionFunc(permManageWorkflows, requireDeployToken(server.handleDeployProduct)))
	mux.HandleFunc("POST /api/v1/console/products/deploy-all", server.requireOpsPermissionFunc(permManageWorkflows, requireDeployToken(server.handleDeployAll)))
	mux.HandleFunc("POST /api/v1/console/bootstrap", server.requireOpsPermissionFunc(permManageOrganization, requireDeployToken(server.handleBootstrap)))
	mux.HandleFunc("GET /api/v1/audit", server.handleAuditList)
	// RBAC sweep #2 (2026-05-28) — workflow template instantiation gated on permManageWorkflows.
	mux.HandleFunc("POST /api/v1/workflow-templates/{namespace}/{name}/instantiate", server.requireOpsPermissionFunc(permManageWorkflows, server.handleWorkflowTemplateInstantiate))

	// Federated integration_surfaces registry (coexists with the older
	// internal/surface system at /api/v1/ops/surfaces*). See spec
	// 2026-05-17-integration-surfaces and the addons/integration_surface_sync
	// addon that wires the repository + dispatcher into this server.
	mux.HandleFunc("GET /api/v1/integration-surfaces", server.handleIntegrationSurfacesList())
	mux.HandleFunc("GET /api/v1/integration-surfaces/{name}", server.handleIntegrationSurfaceGet())
	mux.HandleFunc("PATCH /api/v1/integration-surfaces/{name}/icon", server.requireOpsPermissionFunc(permManageIntegrations, server.handleIntegrationSurfaceUpdateIcon()))
	mux.HandleFunc("POST /api/v1/integration-surfaces/{name}/sync", server.handleIntegrationSurfaceSync())
	mux.HandleFunc("DELETE /api/v1/integration-surfaces/{name}", server.requireOpsPermissionFunc(permManageIntegrations, server.handleIntegrationSurfaceDeactivate()))
	mux.HandleFunc("POST /api/v1/integrations/{instance_id}/surface-query", server.handleIntegrationSurfaceQuery())

	// Opt-in OIDC OP. Skipped when no issuer is configured (the default)
	// so tests and adopters who don't need OIDC keep a slimmer surface.
	if server.oidcIssuerURL != "" {
		if err := oidc.MountOIDC(context.Background(), mux, server.db, server.oidcIssuerURL); err != nil {
			return nil, fmt.Errorf("mount oidc: %w", err)
		}
		// §13 INTEGRATION_CONTRACT: wire the back-channel logout dispatcher
		// alongside the OIDC OP so /logout (and admin revoke) propagates
		// session termination to every registered OIDC client. Storage is
		// re-built here (cheap — no caches) so the dispatcher owns its own
		// reference independent of the op.Provider's internal Storage.
		server.backchannelDispatcher = oidc.NewBackchannelDispatcher(
			oidc.NewStorage(server.db, server.oidcIssuerURL),
			server.oidcIssuerURL,
		)
		// Opt-in: accept OIDC JWTs this OP issued on the console gate, in
		// addition to opaque session tokens. Inert unless
		// YGGDRASIL_CONSOLE_JWT_AUDIENCES lists at least one allowed client
		// audience (the privilege boundary). Built from the same in-process
		// signing key set the OP publishes at /jwks — no external JWKS fetch.
		server.consoleJWTVerifier = newOPJWTVerifier(
			oidc.NewStorage(server.db, server.oidcIssuerURL),
			server.oidcIssuerURL,
			parseConsoleJWTAudiences(os.Getenv("YGGDRASIL_CONSOLE_JWT_AUDIENCES")),
		)
	}

	// §13 INTEGRATION_CONTRACT: RFC 7662 introspection + admin session
	// revocation routes. Both require admin-token auth (see
	// authorizeAuthAdminRequest); the introspection handler is also
	// callable by manifest_token holders so legacy SSO clients can poll.
	mux.HandleFunc("POST /api/v1/oidc/introspect", server.handleOIDCIntrospect)
	mux.HandleFunc("POST /api/v1/admin/collaborators/{id}/revoke-sessions", server.handleAdminCollaboratorRevokeSessions)
	// Audit 2026-05-27 A10: per-client OIDC AccessTokenLifetime override.
	// PATCH only — high-trust admin-token endpoint; full client lifecycle
	// (POST/DELETE) stays out of scope for this audit. Clients are still
	// created via bootstrap manifests / direct UpsertOIDCClient calls.
	mux.HandleFunc("PATCH /api/v1/admin/oidc-clients/{id}", server.handleAdminOIDCClientPatch)

	// Opt-in console SPA. Mounted under <prefix>/ (e.g. /console/) with
	// the prefix-with-and-without-trailing-slash both routing through.
	if server.consoleHandler != nil && server.consoleMountPrefix != "" {
		prefix := strings.TrimRight(server.consoleMountPrefix, "/")
		// Both /console and /console/* must hit the SPA — Go's ServeMux
		// pattern "/console/" doesn't match the bare "/console", so we
		// register both. Trailing-slash-redirect would also work but
		// produces an extra round-trip.
		mux.Handle(prefix, server.consoleHandler)
		mux.Handle(prefix+"/", server.consoleHandler)
	}

	// Pipeline (outermost → innermost):
	//   withLogging          — access log
	//   reqcache.Middleware  — per-request memoization cache for hot lookups
	//   requireAuthenticatedConsoleAPIs — session/bearer resolution
	//   csrfMiddleware       — X-CSRF-Token enforcement on mutating routes
	//   mux                  — route dispatch
	//
	// CSRF runs AFTER session resolution so it sees claims; it runs
	// BEFORE route dispatch so handlers never need to think about it.
	// reqcache.Middleware sits BETWEEN logging and auth so the
	// session-resolution path is the FIRST writer to the cache
	// (collaborator row from session token is reused by every
	// downstream handler / middleware in the same request).
	//
	// Audit 2026-05-27 A7 (CSRF) + 2026-05-28 F4 (reqcache).
	return server.withLogging(reqcache.Middleware(server.requireAuthenticatedConsoleAPIs(server.csrfMiddleware(mux)))), nil
}

func (s *Server) requireAuthenticatedConsoleAPIs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !requiresAuthenticatedConsoleAPI(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Workflow-run token path: CLI tools, adapter callers and
		// workflow steps authenticate with a shared static token. Accept
		// it as an alternative to the session cookie so the audit-flagged
		// leaking GETs (security audit 2026-05-27 A2) can still be
		// consumed by automation that doesn't carry a session.
		if authorizeWorkflowRunRequest(r) == nil {
			if strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_TOKEN")) != "" {
				// Token was present AND matched — treat as authenticated
				// without attaching collaborator claims (no human actor).
				next.ServeHTTP(w, r)
				return
			}
		}

		// OIDC JWT bearer path (opt-in via consoleJWTVerifier). Accept a JWT
		// this OP issued as an alternative to the opaque session token, so
		// services holding a collaborator's cookie JWT (e.g. the tartaro-api
		// proxy) can call console APIs as that collaborator. ADDITIVE: when no
		// verifier is configured, or the bearer isn't a valid OP JWT (e.g. it's
		// an opaque ys_ token passed as Bearer), we fall through to the session
		// path below — existing behavior is unchanged.
		if s.consoleJWTVerifier != nil {
			if jwtClaims, ok := tryBearerHeader(r, s.consoleJWTVerifier); ok {
				sub, _ := jwtClaims["sub"].(string)
				if sub != "" {
					// Normalize to the SAME claim keys the session path sets,
					// so downstream handlers / permission checks are agnostic
					// to whether the caller used a session token or a JWT.
					norm := map[string]any{
						"collaborator_id": sub,
						"sub":             sub,
					}
					if sid, ok := jwtClaims["sid"].(string); ok && sid != "" {
						norm["session_id"] = sid
					}
					next.ServeHTTP(w, r.WithContext(contextWithClaims(r.Context(), norm)))
					return
				}
			}
		}

		token, ok := extractAuthToken(r)
		if !ok {
			writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}

		session, collaborator, err := repository.ResolveAuthSession(r.Context(), s.db, token)
		if err != nil {
			if isAuthUnauthorizedError(err) {
				clearAuthCookie(w)
				writeJSONError(w, http.StatusUnauthorized, "unauthenticated")
				return
			}
			writeMappedError(w, err)
			return
		}

		claims := map[string]any{
			"collaborator_id": collaborator.ID.String(),
			"session_id":      session.ID.String(),
			"sub":             collaborator.ID.String(),
		}
		next.ServeHTTP(w, r.WithContext(contextWithClaims(r.Context(), claims)))
	})
}

// requiresAuthenticatedConsoleAPI returns true when the path must be gated
// by either a console session OR a workflow-run token. The list was
// expanded by the 2026-05-27 security audit (A2) to cover endpoints that
// previously leaked internal infra config to anonymous callers — secrets
// catalog, integration topology, permission catalog/bindings, workflow
// catalog, manifests, surfaces, products, audit log.
//
// Public allowlist (no auth required): health endpoints, OIDC discovery,
// password/login/MFA flows, tenant brand, /api/v1/auth/* — covered by
// the simple negative check at the call site (path not in this prefix
// list → public).
func requiresAuthenticatedConsoleAPI(path string) bool {
	for _, prefix := range []string{
		// ForwardAuth target: the Traefik surface middleware calls
		// GET /api/v1/auth/verify to decide whether a /s/* request is
		// authenticated. It is the ONE /api/v1/auth/* path that must be
		// gated (the rest — login/MFA/session — are public by design), so
		// the gate resolves the session cookie / OP-issued JWT and returns
		// 401 to ForwardAuth when the caller is anonymous.
		"/api/v1/auth/verify",
		// Original gated prefixes (console UI surface).
		"/api/v1/ops",
		"/api/v1/console",
		"/api/v1/collaborators",
		"/api/v1/teams",
		"/api/v1/team-memberships",
		// 2026-05-27 audit A2 expansion — endpoints leaking infra data.
		"/api/v1/secrets",
		"/api/v1/permissions",
		"/api/v1/workflows",
		"/api/v1/workflow-runs",
		"/api/v1/workflow-templates",
		"/api/v1/manifests",
		"/api/v1/integration-instances",
		"/api/v1/integration-runtime-states",
		"/api/v1/integration-catalog",
		"/api/v1/integration-types",
		"/api/v1/integration-surfaces",
		"/api/v1/integrations",
		"/api/v1/repository-bindings",
		"/api/v1/guardian-policies",
		"/api/v1/guardian-approvals",
		"/api/v1/guardian-memories",
		"/api/v1/remediation-bundles",
		"/api/v1/remediation-contracts",
		"/api/v1/surfaces",
		"/api/v1/products",
		"/api/v1/audit",
		"/api/v1/reconciler",
		"/api/v1/catalog",
		"/api/v1/collaborator-external-identities",
		"/api/v1/me",
		// Note: /api/v1/invites NOT gated here — handleInviteValidate
		// is intentionally public (validates from email), and
		// handleInviteCreate/List self-gate via extractAuthToken.
		// Note: /api/v1/tenant/brand stays OUT of this allowlist —
		// the GET is intentionally public (LoginPage and signup
		// surfaces fetch it pre-session). The PATCH self-gates in
		// handleTenantBrandPatch, requiring an explicit session OR
		// a verified workflow-run-token. Don't widen the prefix here
		// or the public GET breaks.
		"/api/v1/events",
		"/api/v1/provision",
		"/api/v1/bootstrap",
	} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// ServerOption configures optional Server dependencies.
type ServerOption func(*Server)

// WithReconciler injects the reconciler engine into the HTTP server.
func WithReconciler(engine *reconciler.Engine) ServerOption {
	return func(s *Server) { s.reconciler = engine }
}

// WithProvisioner injects the AWS provisioner into the HTTP server.
func WithProvisioner(p *provisioner.AWSProvisioner) ServerOption {
	return func(s *Server) { s.provisioner = p }
}

// WithOIDCIssuer enables the OIDC OpenID Provider on the HTTP server,
// mounting the discovery + token endpoints with this issuer URL. When
// unset (default empty string) OIDC routes are not registered, so tests
// and dev setups that don't need OIDC stay free of its DB requirement
// (an active oidc_signing_keys row).
func WithOIDCIssuer(issuerURL string) ServerOption {
	return func(s *Server) { s.oidcIssuerURL = issuerURL }
}

// WithConsole mounts the provided handler under prefix (e.g. "/console")
// for serving the Yggdrasil console SPA. The handler is typically the
// http.Handler returned by controllers/console.Handler, but any
// http.Handler works (useful for tests and forks that ship a different
// console). Empty prefix or nil handler leaves the console unmounted.
//
// The split between this option and the controllers/console package
// keeps httpapi free of the SPA's go:embed bundle — adopters who don't
// want the console (e.g. headless API-only deploys) avoid linking
// the embedded files.
func WithConsole(prefix string, handler http.Handler) ServerOption {
	return func(s *Server) {
		s.consoleHandler = handler
		s.consoleMountPrefix = prefix
	}
}

// WithSurfaceBaseURLs maps surface ids to adapter health-server base URLs.
// It keeps the core neutral: adopters decide which generic adapter runtime
// backs each surface in their own deployment topology.
func WithSurfaceBaseURLs(baseURLs map[string]string) ServerOption {
	return func(s *Server) {
		s.surfaceBaseURLs = make(map[string]string, len(baseURLs))
		for surfaceID, baseURL := range baseURLs {
			s.surfaceBaseURLs[normalizeSurfaceID(surfaceID)] = baseURL
		}
	}
}

// WithIntegrationSurfacesRepo injects the federated integration_surfaces
// repository, enabling GET/POST /api/v1/integration-surfaces*. When unset
// the handlers return 503.
func WithIntegrationSurfacesRepo(r IntegrationSurfacesRepo) ServerOption {
	return func(s *Server) { s.integrationSurfacesRepo = r }
}

// WithSurfaceQueryDispatcher injects the synchronous on_surface_query
// dispatcher, enabling POST /api/v1/integrations/{instance_id}/surface-query.
// When unset the handler returns 503.
func WithSurfaceQueryDispatcher(d SurfaceQueryDispatcher) ServerOption {
	return func(s *Server) { s.surfaceQueryDispatcher = d }
}

// workflowDispatchFunc dispatches a Yggdrasil workflow_run by manifest ref.
// The default implementation wraps messagecontroller.RunWorkflow; tests
// override the field directly with a fake to assert dispatch behaviour.
type workflowDispatchFunc func(ctx context.Context, ref model.ManifestSelector, inputs map[string]any) error

// Server exposes the synchronous HTTP surface of yggdrasil-core.
type Server struct {
	serviceName      string
	db               *sql.DB
	rabbitmq         *amqp.Connection
	logger           *zap.Logger
	reconciler       *reconciler.Engine
	provisioner      *provisioner.AWSProvisioner
	dispatchWorkflow workflowDispatchFunc
	// oidcIssuerURL, when non-empty, opts the server into mounting the
	// OIDC OP routes (.well-known/openid-configuration + /oidc/*). Set via
	// WithOIDCIssuer. Empty (default) keeps OIDC dormant for tests/dev.
	oidcIssuerURL string
	// consoleHandler, when non-nil, mounts the Yggdrasil console SPA at
	// consoleMountPrefix (e.g. /console) on the same mux. Set via
	// WithConsole. The handler is provided by the caller so this package
	// doesn't import controllers/console (which embeds a >0-byte SPA bundle
	// even when the console isn't wanted — keeps the slim test/dev path).
	consoleHandler     http.Handler
	consoleMountPrefix string
	surfaceBaseURLs    map[string]string
	// envelope encrypts MFA secrets and SAML signing keys at rest. Read from
	// YGGDRASIL_AUTH_KEK_BASE64 (32 raw bytes base64-encoded). When unset
	// MFA enroll handlers refuse with 503 — secrets-at-rest is mandatory.
	envelope *cryptoenvelope.Envelope
	// webauthnSessions caches in-flight WebAuthn ceremony session blobs
	// (challenge + RP metadata) keyed by mfa.RegistrationKey(collabID) or
	// mfa.LoginKey(collabID). Phase 2 in-memory; Phase 3 swaps for a
	// Redis-backed store when HPA goes on. Each ceremony entry TTLs at
	// 5min — long enough for a slow biometric prompt, short enough that
	// abandoned ceremonies can't replay an hour later. The store auto-
	// reaps expired entries on every Get/Put call.
	webauthnSessions *mfa.SessionStore
	// webauthnEngine is the configured *webauthn.WebAuthn instance — the
	// lib's entry point for Begin/Finish registration + login. RP
	// metadata (RPID, RPDisplayName, RPOrigins) baked in once at boot
	// from env (YGGDRASIL_WEBAUTHN_RP_ID + YGGDRASIL_WEBAUTHN_ORIGINS).
	// nil only when boot couldn't resolve a valid config — handlers then
	// 503 instead of stubbing a fake challenge.
	webauthnEngine *webauthn.WebAuthn
	// integrationSurfacesRepo backs GET/POST /api/v1/integration-surfaces*
	// (federated surface registry, coexists with internal/surface). Optional;
	// when nil the handlers return 503. See addons/integration_surface_sync.go.
	integrationSurfacesRepo IntegrationSurfacesRepo
	// surfaceQueryDispatcher backs POST /api/v1/integrations/{id}/surface-query
	// — proxies on_surface_query to the named integration instance. Optional;
	// when nil the handler returns 503.
	surfaceQueryDispatcher SurfaceQueryDispatcher
	// capabilityAllowlist holds the warn-only capability-naming validator
	// allowlist loaded once at boot from
	// config/capability_naming_allowlist.yaml. nil disables the validator
	// (e.g. tests that don't exercise integration_type registration).
	// See docs/superpowers/specs/2026-05-27-yggdrasil-integration-capability-convention.md.
	capabilityAllowlist *manifestengine.CapabilityNamingAllowlist
	// validatorPhase controls whether non-conformant capability names
	// produce HTTP 422 (Phase 2 hard-fail) or HTTP 201 + warnings array
	// (Phase 1 warn-only — the default).  Read once at boot from the
	// YGGDRASIL_VALIDATOR_PHASE environment variable; see
	// validator_phase.go for the resolution logic and the runbook
	// reference_phase2_validator_flip_runbook.md for the cut-over
	// procedure (earliest execution 2026-06-10 after the 14-day
	// observation window that opened 2026-05-27).
	validatorPhase string
	// loginLimiter caps anonymous /api/v1/auth/login attempts per
	// source IP (security audit 2026-05-27 A4). nil disables the
	// middleware (e.g. for narrow unit tests).
	loginLimiter *loginRateLimiter
	// backchannelDispatcher fires RFC 8417 logout_token POSTs to every
	// OIDC client linked to a terminated session (§13 INTEGRATION_CONTRACT).
	// nil disables back-channel dispatch — useful for tests or deploys
	// that don't run OIDC. Set when OIDC routes mount (see MountOIDC).
	backchannelDispatcher *oidc.BackchannelDispatcher
	// consoleJWTVerifier, when non-nil, lets the console auth gate accept an
	// OIDC JWT this OP issued (verified in-process via the signing key set) as
	// an ADDITIVE alternative to the opaque session token. nil = disabled
	// (default): the gate behaves exactly as before. Enabled only when the OP
	// issuer is set AND YGGDRASIL_CONSOLE_JWT_AUDIENCES lists at least one
	// allowed client audience — see newOPJWTVerifier. This is what lets the
	// tartaro-api proxy forward a collaborator's cookie JWT to /api/v1/* and
	// have it authenticate as that collaborator.
	consoleJWTVerifier *opJWTVerifier
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		writer := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(writer, r)

		s.logger.Info("http request served",
			zap.String("service", s.serviceName),
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.Int("status", writer.status),
			zap.Duration("duration", time.Since(startedAt)),
		)
	})
}

func (s *Server) handleRoot(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": s.serviceName,
		"status":  "ok",
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.db.PingContext(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready",
			"reason": "postgres_unavailable",
			"error":  strings.TrimSpace(err.Error()),
		})
		return
	}

	// RabbitMQ is a soft dependency — a closed connection degrades workflow
	// dispatch throughput but does not make the HTTP API unavailable.
	// Without a ReliableConnection the single *amqp.Connection closes after
	// transient broker blips and never recovers until pod restart, which
	// cascaded into /readyz → 503 → Traefik 404 for every external caller.
	// Surface the state via `rabbitmq_status` but stay ready.
	rabbitmqStatus := "ok"
	if strings.TrimSpace(os.Getenv("BROKER_URL")) != "" && !s.isBrokerAvailable() {
		rabbitmqStatus = "degraded"
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "ready",
		"rabbitmq_status": rabbitmqStatus,
	})
}

// isBrokerAvailable reports whether the workflow/event path can dispatch.
// It is the single source of truth for broker liveness: BROKER_URL must be
// configured AND the cached connection must be open. With BROKER_URL unset
// the floor runs IdP-only and this is intentionally false.
func (s *Server) isBrokerAvailable() bool {
	return strings.TrimSpace(os.Getenv("BROKER_URL")) != "" &&
		s.rabbitmq != nil && !s.rabbitmq.IsClosed()
}

func (s *Server) handleIntegrationCatalogList(w http.ResponseWriter, r *http.Request) {
	domains, err := messagecontroller.ListIntegrationCatalog(r.Context(), s.db, model.ListIntegrationCatalogRequest{
		Namespace: queryString(r, "namespace"),
		Domain:    queryString(r, "domain"),
		Section:   queryString(r, "section"),
		Entry:     queryString(r, "entry"),
		CheckKind: queryString(r, "check_kind"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, integrationCatalogResponse{Domains: domains})
}

func (s *Server) handleIntegrationCatalogEntry(w http.ResponseWriter, r *http.Request) {
	entry, err := messagecontroller.GetIntegrationCatalogEntry(r.Context(), s.db, model.GetIntegrationCatalogEntryRequest{
		Namespace: queryString(r, "namespace"),
		Domain:    r.PathValue("domain"),
		Section:   r.PathValue("section"),
		Entry:     r.PathValue("entry"),
		CheckKind: queryString(r, "check_kind"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	typeManifest, err := repository.GetManifestByID(r.Context(), s.db, entry.IntegrationType.ID)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, integrationCatalogEntryDetailResponse{
		Entry:                   entry,
		IntegrationTypeManifest: typeManifest,
	})
}

func (s *Server) handleCatalogDiscovery(w http.ResponseWriter, r *http.Request) {
	response, err := messagecontroller.DiscoverCatalog(r.Context(), s.rabbitmq, s.db, model.DiscoverCatalogRequest{
		Source: model.ManifestSelector{
			ManifestID: queryString(r, "source_manifest_id"),
			Namespace:  queryString(r, "source_namespace"),
			Name:       queryString(r, "source_name"),
		},
		Namespace: queryString(r, "namespace"),
		Kinds:     queryKinds(r),
		Query:     queryString(r, "query"),
		Limit:     queryInt(r, "limit"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, response)
}

func (s *Server) handleCatalogDiscoveryRegister(w http.ResponseWriter, r *http.Request) {
	var req catalogDiscoveryRegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	manifestRecord, err := createManifestVersion(r.Context(), s.db, req.Registration.Manifest)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"manifest": manifestRecord})
}

func (s *Server) handleIntegrationInstanceList(w http.ResponseWriter, r *http.Request) {
	s.handleManifestList(w, r, "integration_instance")
}

func (s *Server) handleIntegrationInstanceCreate(w http.ResponseWriter, r *http.Request) {
	var payload consoleCreateIntegrationInstanceRequest
	if err := decodeJSON(r, &payload); err != nil {
		writeMappedError(w, err)
		return
	}

	_, typeSpec, err := s.resolveIntegrationTypeSpec(r.Context(), payload.TypeRef)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if err := s.materializeIntegrationInstanceCredentials(r.Context(), &payload, typeSpec); err != nil {
		writeMappedError(w, err)
		return
	}
	if err := s.materializeIntegrationInstanceSecretConfig(r.Context(), &payload, typeSpec); err != nil {
		writeMappedError(w, err)
		return
	}

	doc, err := integrationInstanceDocumentFromPayload(payload)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	instanceSpec, err := manifestengine.ParseIntegrationInstanceSpec(doc.Spec)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if err := manifestengine.ValidateIntegrationInstanceCredentialStorage(instanceSpec, typeSpec); err != nil {
		writeMappedError(w, err)
		return
	}
	if err := hydrateIntegrationInstanceInputSecrets(r.Context(), s.db, &instanceSpec); err != nil {
		writeMappedError(w, err)
		return
	}
	if err := manifestengine.ValidateHydratedIntegrationInstanceInputs(instanceSpec, typeSpec); err != nil {
		writeMappedError(w, err)
		return
	}

	manifestRecord, err := createManifestVersion(r.Context(), s.db, doc)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	s.materializeAfterManifestWrite(manifestRecord)

	writeJSON(w, http.StatusCreated, map[string]any{"manifest": manifestRecord})
}

func (s *Server) handleManagedSecretList(w http.ResponseWriter, r *http.Request) {
	secrets, err := repository.ListManagedSecrets(r.Context(), s.db, model.ListManagedSecretsRequest{
		Namespace: queryString(r, "namespace"),
		Status:    queryString(r, "status"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	includeValues := queryBool(r, "include_values")
	items := make([]model.ManagedSecretView, 0, len(secrets))
	for _, secret := range secrets {
		items = append(items, model.BuildManagedSecretView(secret, includeValues))
	}

	writeJSON(w, http.StatusOK, managedSecretsResponse{Secrets: items})
}

func (s *Server) handleManagedSecretGet(w http.ResponseWriter, r *http.Request) {
	secret, err := repository.GetManagedSecret(r.Context(), s.db, model.GetManagedSecretRequest{
		Namespace: r.PathValue("namespace"),
		Name:      r.PathValue("name"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"secret": model.BuildManagedSecretView(secret, queryBool(r, "include_values")),
	})
}

func (s *Server) handleManagedSecretCreate(w http.ResponseWriter, r *http.Request) {
	var req model.UpsertManagedSecretRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	secret, err := repository.UpsertManagedSecret(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	s.materializeAfterWrite(secret)

	writeJSON(w, http.StatusCreated, map[string]any{
		"secret": model.BuildManagedSecretView(secret, queryBool(r, "include_values")),
	})
}

func (s *Server) handleManagedSecretRotate(w http.ResponseWriter, r *http.Request) {
	var req rotateManagedSecretRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	secret, err := repository.RotateManagedSecret(r.Context(), s.db, model.RotateManagedSecretRequest{
		Namespace: r.PathValue("namespace"),
		Name:      r.PathValue("name"),
		Data:      req.Data,
		Metadata:  req.Metadata,
		Rotation:  req.Rotation,
		ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	s.materializeAfterWrite(secret)

	writeJSON(w, http.StatusOK, map[string]any{
		"secret": model.BuildManagedSecretView(secret, queryBool(r, "include_values")),
	})
}

func (s *Server) handleManagedSecretDisable(w http.ResponseWriter, r *http.Request) {
	var req updateManagedSecretRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	secret, err := repository.DisableManagedSecret(r.Context(), s.db, model.DisableManagedSecretRequest{
		Namespace: r.PathValue("namespace"),
		Name:      r.PathValue("name"),
		Metadata:  req.Metadata,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	s.materializeAfterWrite(secret)

	writeJSON(w, http.StatusOK, map[string]any{
		"secret": model.BuildManagedSecretView(secret, queryBool(r, "include_values")),
	})
}

func (s *Server) handleManagedSecretRevoke(w http.ResponseWriter, r *http.Request) {
	var req updateManagedSecretRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	secret, err := repository.RevokeManagedSecret(r.Context(), s.db, model.RevokeManagedSecretRequest{
		Namespace: r.PathValue("namespace"),
		Name:      r.PathValue("name"),
		Metadata:  req.Metadata,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	s.materializeAfterWrite(secret)

	writeJSON(w, http.StatusOK, map[string]any{
		"secret": model.BuildManagedSecretView(secret, queryBool(r, "include_values")),
	})
}

func (s *Server) handleCollaboratorList(w http.ResponseWriter, r *http.Request) {
	req := model.ListCollaboratorsRequest{
		Status: queryString(r, "status"),
		Search: queryString(r, "q"),
	}

	// Phase 6 aggregate (audit 2026-05-27 §2.3): when the caller asks for
	// `?enriched=true`, the response carries denormalized team_names,
	// primary_role, last_login_at, mfa_enrolled directly on each
	// collaborator. This kills the 3-query pattern in CollaboratorListPage.
	enriched := queryBool(r, "enriched")

	// Paginated mode kicks in when the caller asks for it explicitly.
	// Zero limit + no cursor preserves the legacy "give me everything" shape
	// that older console code still relies on.
	limit := queryInt(r, "limit")
	cursor := queryString(r, "cursor")
	if limit > 0 || cursor != "" {
		collaborators, page, err := repository.ListCollaboratorsPaginated(r.Context(), s.db, req, model.PaginationRequest{
			Limit:  limit,
			Cursor: cursor,
		})
		if err != nil {
			writeMappedError(w, err)
			return
		}
		// Total estimate is a separate COUNT(*) under the same WHERE — cheap
		// at DaKasa scale (sub-1k rows) and lets the UI show "showing X of Y".
		// Best-effort: a failure here shouldn't poison the listing.
		if total, err := repository.CountCollaborators(r.Context(), s.db, req); err == nil {
			page.TotalEstimate = total
		}
		if enriched {
			rows, _ := enrichCollaborators(r.Context(), s.db, collaborators)
			writeJSON(w, http.StatusOK, collaboratorEnrichedResponse{
				Collaborators: rows,
				Pagination:    &page,
			})
			return
		}
		writeJSON(w, http.StatusOK, collaboratorsResponse{
			Collaborators: collaborators,
			Pagination:    &page,
		})
		return
	}

	collaborators, err := repository.ListCollaborators(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if enriched {
		rows, _ := enrichCollaborators(r.Context(), s.db, collaborators)
		writeJSON(w, http.StatusOK, collaboratorEnrichedResponse{Collaborators: rows})
		return
	}
	writeJSON(w, http.StatusOK, collaboratorsResponse{Collaborators: collaborators})
}

func (s *Server) handleCollaboratorCreate(w http.ResponseWriter, r *http.Request) {
	var req model.CreateCollaboratorRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	collaborator, err := repository.CreateCollaboratorWithIdentityTx(r.Context(), tx, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit hired lifecycle event for reconcile workflows to consume.
	hiredPayload := map[string]any{}
	if req.EmploymentData != nil {
		if v, ok := req.EmploymentData["start_date"]; ok {
			hiredPayload["start_date"] = v
		}
		if v, ok := req.EmploymentData["role"]; ok {
			hiredPayload["role"] = v
		}
	}
	if pid := strings.TrimSpace(req.PrimaryTeamID); pid != "" {
		hiredPayload["primary_team_id"] = pid
	}
	if mid := strings.TrimSpace(req.ManagerID); mid != "" {
		hiredPayload["manager_id"] = mid
	}
	if _, err := repository.AppendLifecycleEventTx(r.Context(), tx, model.AppendLifecycleEventRequest{
		CollaboratorID: collaborator.ID,
		EventType:      model.LifecycleEventHired,
		Payload:        hiredPayload,
		ActorType:      model.ActorTypeAPI,
		ActorID:        actorIDFromRequest(r),
	}); err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit collaborator.created canon event in the same transaction so
	// event-driven workflows (e.g. reconcile-github-identities-events) and the
	// collaborator/auth_identities/lifecycle rows commit atomically.
	emitPayload := map[string]any{
		"collaborator_id": collaborator.ID.String(),
		"slug":            collaborator.Slug,
		"display_name":    collaborator.DisplayName,
	}
	if collaborator.PrimaryEmail != "" {
		emitPayload["primary_email"] = collaborator.PrimaryEmail
	}
	if collaborator.Status != "" {
		emitPayload["status"] = collaborator.Status
	}
	var actor *model.EventActor
	if actorID := actorIDFromRequest(r); actorID != "" {
		actor = &model.EventActor{Type: "api", ID: actorID}
	}
	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeCollaboratorCreated,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collaborator.ID.String(),
		Actor:         actor,
		Payload:       emitPayload,
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit collaborator.created: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit collaborator.created: %w", err))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"collaborator": collaborator})
}

func (s *Server) handleCollaboratorGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}

	collaborator, err := repository.GetCollaborator(r.Context(), s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collaborator})
}

func (s *Server) handleCollaboratorUpdate(w http.ResponseWriter, r *http.Request) {
	var req model.UpdateCollaboratorRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if pathID := strings.TrimSpace(r.PathValue("id")); pathID != "" {
		req.ID = pathID
	}
	if strings.TrimSpace(req.ID) == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}

	// Capture pre-update state so we can diff for lifecycle events. A miss here
	// (e.g. id not found) lets UpdateCollaborator return the canonical error.
	before, beforeErr := repository.GetCollaborator(r.Context(), s.db, req.ID)

	collaborator, err := repository.UpdateCollaborator(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if beforeErr == nil {
		s.emitCollaboratorUpdateEvents(r.Context(), before, collaborator, actorIDFromRequest(r))
	}

	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collaborator})
}

// emitCollaboratorUpdateEvents writes a lifecycle event per field that changed
// between before and after. Best-effort: a failure to write any one event is
// logged but does not fail the request — the audit trail is a downstream
// concern, not a precondition for the mutation.
func (s *Server) emitCollaboratorUpdateEvents(ctx context.Context, before, after model.Collaborator, actorID string) {
	beforeEmp := beforeEmpData(before)
	afterEmp := beforeEmpData(after)

	beforeRole := stringField(beforeEmp, "role")
	afterRole := stringField(afterEmp, "role")
	beforeTitle := stringField(beforeEmp, "title")
	afterTitle := stringField(afterEmp, "title")
	if beforeRole != afterRole || beforeTitle != afterTitle {
		s.appendLifecycle(ctx, before.ID, model.LifecycleEventRoleChanged, map[string]any{
			"from_role":  beforeRole,
			"to_role":    afterRole,
			"from_title": beforeTitle,
			"to_title":   afterTitle,
		}, actorID)
	}

	beforeStart := stringField(beforeEmp, "start_date")
	afterStart := stringField(afterEmp, "start_date")
	if beforeStart != afterStart {
		s.appendLifecycle(ctx, before.ID, model.LifecycleEventAttributeSet, map[string]any{
			"attribute": "start_date",
			"from":      beforeStart,
			"to":        afterStart,
		}, actorID)
	}

	if !uuidPtrEqual(before.ManagerID, after.ManagerID) {
		payload := map[string]any{}
		if before.ManagerID != nil {
			payload["from_manager_id"] = before.ManagerID.String()
		}
		if after.ManagerID != nil {
			payload["to_manager_id"] = after.ManagerID.String()
		}
		s.appendLifecycle(ctx, before.ID, model.LifecycleEventManagerChanged, payload, actorID)
	}

	if !uuidPtrEqual(before.PrimaryTeamID, after.PrimaryTeamID) {
		payload := map[string]any{"attribute": "primary_team_id"}
		if before.PrimaryTeamID != nil {
			payload["from"] = before.PrimaryTeamID.String()
		}
		if after.PrimaryTeamID != nil {
			payload["to"] = after.PrimaryTeamID.String()
		}
		s.appendLifecycle(ctx, before.ID, model.LifecycleEventAttributeSet, payload, actorID)
	}
}

func (s *Server) appendLifecycle(ctx context.Context, collaboratorID uuid.UUID, eventType string, payload map[string]any, actorID string) {
	if _, err := repository.AppendLifecycleEvent(ctx, s.db, model.AppendLifecycleEventRequest{
		CollaboratorID: collaboratorID,
		EventType:      eventType,
		Payload:        payload,
		ActorType:      model.ActorTypeAPI,
		ActorID:        actorID,
	}); err != nil {
		s.logger.Warn("lifecycle event emit failed (non-fatal)",
			zap.Error(err),
			zap.String("collaborator_id", collaboratorID.String()),
			zap.String("event_type", eventType),
		)
	}
}

// appendLifecycleTx is the *sql.Tx variant used by handlers that mutate state
// and emit canon events atomically. Unlike appendLifecycle, errors here MUST
// fail the request — the caller's tx will roll back the state mutation along
// with the failed lifecycle insert, preserving atomicity.
func (s *Server) appendLifecycleTx(ctx context.Context, tx *sql.Tx, collaboratorID uuid.UUID, eventType string, payload map[string]any, actorID string) error {
	if _, err := repository.AppendLifecycleEventTx(ctx, tx, model.AppendLifecycleEventRequest{
		CollaboratorID: collaboratorID,
		EventType:      eventType,
		Payload:        payload,
		ActorType:      model.ActorTypeAPI,
		ActorID:        actorID,
	}); err != nil {
		return fmt.Errorf("append lifecycle event %s: %w", eventType, err)
	}
	return nil
}

func beforeEmpData(c model.Collaborator) map[string]any {
	if c.EmploymentData == nil {
		return map[string]any{}
	}
	return c.EmploymentData
}

func stringField(m map[string]any, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func uuidPtrEqual(a, b *uuid.UUID) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func (s *Server) handleCollaboratorDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	collaborator, err := repository.DeleteCollaborator(r.Context(), s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collaborator, "deleted": true})
}

func (s *Server) handleTeamList(w http.ResponseWriter, r *http.Request) {
	teams, err := repository.ListTeams(r.Context(), s.db, model.ListTeamsRequest{
		Status: queryString(r, "status"),
		Type:   queryString(r, "type"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, teamsResponse{Teams: teams})
}

func (s *Server) handleTeamCreate(w http.ResponseWriter, r *http.Request) {
	var req model.CreateTeamRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	team, err := repository.CreateTeamTx(r.Context(), tx, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit team.created canon event in the same transaction.
	emitPayload := map[string]any{
		"id":   team.ID.String(),
		"slug": team.Slug,
		"name": team.Name,
		"type": team.Type,
	}
	if team.ParentTeamID != nil {
		emitPayload["parent_team_id"] = team.ParentTeamID.String()
	}
	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamCreated,
		SchemaVersion: "v1",
		AggregateType: "team",
		AggregateID:   team.ID.String(),
		Payload:       emitPayload,
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit team.created: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit team.created: %w", err))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"team": team})
}

func (s *Server) handleTeamGet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("team id is required"))
		return
	}
	team, err := repository.GetTeam(r.Context(), s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"team": team})
}

func (s *Server) handleTeamUpdate(w http.ResponseWriter, r *http.Request) {
	var req model.UpdateTeamRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if pathID := strings.TrimSpace(r.PathValue("id")); pathID != "" {
		req.ID = pathID
	}
	if strings.TrimSpace(req.ID) == "" {
		writeMappedError(w, fmt.Errorf("team id is required"))
		return
	}

	// Build changed_fields from request (only fields present in the PATCH body).
	changedFields := map[string]any{}
	if req.Slug != nil {
		changedFields["slug"] = *req.Slug
	}
	if req.Name != nil {
		changedFields["name"] = *req.Name
	}
	if req.Type != nil {
		changedFields["type"] = *req.Type
	}
	if req.Status != nil {
		changedFields["status"] = *req.Status
	}
	if req.ParentTeamID != nil {
		changedFields["parent_team_id"] = *req.ParentTeamID
	}
	if req.Owners != nil {
		changedFields["owners"] = *req.Owners
	}
	if req.Traits != nil {
		changedFields["traits"] = *req.Traits
	}
	if req.Metadata != nil {
		changedFields["metadata"] = *req.Metadata
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	team, err := repository.UpdateTeamTx(r.Context(), tx, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit team.updated canon event in the same transaction (only when at
	// least one field actually changed).
	if len(changedFields) > 0 {
		emitPayload := map[string]any{
			"id":             team.ID.String(),
			"slug":           team.Slug,
			"changed_fields": changedFields,
		}
		if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
			Type:          repository.EventTypeTeamUpdated,
			SchemaVersion: "v1",
			AggregateType: "team",
			AggregateID:   team.ID.String(),
			Payload:       emitPayload,
		}); err != nil {
			writeMappedError(w, fmt.Errorf("emit team.updated: %w", err))
			return
		}
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit team.updated: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"team": team})
}

func (s *Server) handleTeamDelete(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("team id is required"))
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	team, err := repository.DeleteTeamTx(r.Context(), tx, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit team.deleted canon event in the same transaction so the team row
	// removal and the downstream cleanup notification commit atomically.
	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamDeleted,
		SchemaVersion: "v1",
		AggregateType: "team",
		AggregateID:   team.ID.String(),
		Payload: map[string]any{
			"id":   team.ID.String(),
			"slug": team.Slug,
		},
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit team.deleted: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit team.deleted: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"team": team, "deleted": true})
}

func (s *Server) handleTeamGrantList(w http.ResponseWriter, r *http.Request) {
	grants, err := repository.ListTeamGrants(r.Context(), s.db, model.ListTeamGrantsRequest{
		TeamID: r.PathValue("id"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": grants})
}

func (s *Server) handleTeamGrantCreate(w http.ResponseWriter, r *http.Request) {
	var req model.GrantTeamActionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	req.TeamID = r.PathValue("id")

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	grant, err := repository.GrantTeamActionTx(r.Context(), tx, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	payload := map[string]any{
		"id":                             grant.ID,
		"team_id":                        grant.TeamID,
		"integration_instance_namespace": grant.IntegrationInstanceNamespace,
		"integration_instance_name":      grant.IntegrationInstanceName,
		"action_name":                    grant.ActionName,
	}
	if grant.Scope != nil {
		payload["scope"] = grant.Scope
	}
	if grant.GrantedBy != nil {
		payload["granted_by"] = *grant.GrantedBy
	}
	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamGrantAdded,
		SchemaVersion: "v1",
		AggregateType: "team_grant",
		AggregateID:   grant.ID,
		Payload:       payload,
		Actor: &model.EventActor{
			Type: model.ActorTypeAPI,
			ID:   actorIDFromRequest(r),
		},
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit team_grant.added: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit: %w", err))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"grant": grant})
}

func (s *Server) handleTeamGrantDelete(w http.ResponseWriter, r *http.Request) {
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	grant, err := repository.RevokeTeamGrantTx(r.Context(), tx, r.PathValue("grant_id"))
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeTeamGrantRevoked,
		SchemaVersion: "v1",
		AggregateType: "team_grant",
		AggregateID:   grant.ID,
		Payload: map[string]any{
			"id":                             grant.ID,
			"team_id":                        grant.TeamID,
			"integration_instance_namespace": grant.IntegrationInstanceNamespace,
			"integration_instance_name":      grant.IntegrationInstanceName,
			"action_name":                    grant.ActionName,
		},
		Actor: &model.EventActor{
			Type: model.ActorTypeAPI,
			ID:   actorIDFromRequest(r),
		},
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit team_grant.revoked: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleTeamAvailableSources(w http.ResponseWriter, r *http.Request) {
	sources, err := repository.ListAvailableSourcesForTeam(r.Context(), s.db, r.PathValue("id"))
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": sources})
}

func (s *Server) handleTeamMembershipList(w http.ResponseWriter, r *http.Request) {
	memberships, err := repository.ListTeamMemberships(r.Context(), s.db, model.ListTeamMembershipsRequest{
		TeamID:         queryString(r, "team_id"),
		CollaboratorID: queryString(r, "collaborator_id"),
		ActiveOnly:     queryBool(r, "active_only"),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if memberships == nil {
		memberships = []model.TeamMembership{}
	}

	writeJSON(w, http.StatusOK, membershipsResponse{Memberships: memberships})
}

func (s *Server) handleTeamMembershipUpsert(w http.ResponseWriter, r *http.Request) {
	var req model.UpsertTeamMembershipRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	// Probe previous membership outside the tx so we can tell if this upsert is
	// a transition (joining/leaving) versus a no-op or metadata edit. The
	// transition detection is a stable read of the current row; running it
	// outside the tx avoids holding a read lock across BeginTx.
	prevActive := false
	prev, prevErr := repository.ListTeamMemberships(r.Context(), s.db, model.ListTeamMembershipsRequest{
		TeamID:         req.TeamID,
		CollaboratorID: req.CollaboratorID,
	})
	if prevErr == nil {
		for _, m := range prev {
			if m.Active {
				prevActive = true
				break
			}
		}
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	membership, err := repository.UpsertTeamMembershipTx(r.Context(), tx, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	nowActive := membership.Active
	actorID := actorIDFromRequest(r)

	switch {
	case nowActive && !prevActive:
		if err := s.appendLifecycleTx(r.Context(), tx, membership.CollaboratorID, model.LifecycleEventTeamJoined, map[string]any{
			"team_id":   membership.TeamID.String(),
			"team_slug": membership.TeamSlug,
			"role":      membership.Role,
		}, actorID); err != nil {
			writeMappedError(w, err)
			return
		}
		// Emit team_membership.added canon event in the same transaction.
		if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
			Type:          repository.EventTypeTeamMembershipAdded,
			SchemaVersion: "v1",
			AggregateType: "team_membership",
			AggregateID:   membership.ID.String(),
			Payload: map[string]any{
				"collaborator_id": membership.CollaboratorID.String(),
				"team_id":         membership.TeamID.String(),
				"role":            membership.Role,
				"source":          membership.Source,
			},
		}); err != nil {
			writeMappedError(w, fmt.Errorf("emit team_membership.added: %w", err))
			return
		}
	case !nowActive && prevActive:
		if err := s.appendLifecycleTx(r.Context(), tx, membership.CollaboratorID, model.LifecycleEventTeamLeft, map[string]any{
			"team_id":   membership.TeamID.String(),
			"team_slug": membership.TeamSlug,
			"role":      membership.Role,
		}, actorID); err != nil {
			writeMappedError(w, err)
			return
		}
		// Emit team_membership.removed canon event in the same transaction.
		if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
			Type:          repository.EventTypeTeamMembershipRemoved,
			SchemaVersion: "v1",
			AggregateType: "team_membership",
			AggregateID:   membership.ID.String(),
			Payload: map[string]any{
				"collaborator_id": membership.CollaboratorID.String(),
				"team_id":         membership.TeamID.String(),
			},
		}); err != nil {
			writeMappedError(w, fmt.Errorf("emit team_membership.removed: %w", err))
			return
		}
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit team_membership upsert: %w", err))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"membership": membership})
}

func (s *Server) handleProductList(w http.ResponseWriter, r *http.Request) {
	s.handleManifestList(w, r, "product")
}

func (s *Server) handleProductCreate(w http.ResponseWriter, r *http.Request) {
	s.handleManifestCreate(w, r, "product")
}

func (s *Server) handleSurfaceList(w http.ResponseWriter, r *http.Request) {
	s.handleManifestList(w, r, "surface")
}

func (s *Server) handleRepositoryBindingList(w http.ResponseWriter, r *http.Request) {
	s.handleManifestList(w, r, "repository_binding")
}

func (s *Server) handleRepositoryBindingCreate(w http.ResponseWriter, r *http.Request) {
	s.handleManifestCreate(w, r, "repository_binding")
}

func (s *Server) handleGuardianPolicyList(w http.ResponseWriter, r *http.Request) {
	s.handleManifestList(w, r, "guardian_policy")
}

func (s *Server) handleGuardianPolicyCreate(w http.ResponseWriter, r *http.Request) {
	s.handleManifestCreate(w, r, "guardian_policy")
}

func (s *Server) handleGuardianApprovalList(w http.ResponseWriter, r *http.Request) {
	s.handleManifestList(w, r, "guardian_approval")
}

func (s *Server) handleGuardianApprovalCreate(w http.ResponseWriter, r *http.Request) {
	s.handleManifestCreate(w, r, "guardian_approval")
}

func (s *Server) handleGuardianMemoryList(w http.ResponseWriter, r *http.Request) {
	s.handleManifestList(w, r, "guardian_memory")
}

func (s *Server) handleRemediationBundleList(w http.ResponseWriter, r *http.Request) {
	s.handleManifestList(w, r, "remediation_bundle")
}

func (s *Server) handleRemediationBundleCreate(w http.ResponseWriter, r *http.Request) {
	s.handleManifestCreate(w, r, "remediation_bundle")
}

func (s *Server) handleGuardianMemoryReview(w http.ResponseWriter, r *http.Request) {
	var req guardianMemoryReviewRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	reviewStatus := normalizeGuardianMemoryReviewStatus(req.ReviewStatus)
	if reviewStatus == "" {
		writeMappedError(w, fmt.Errorf("guardian memory review_status %q is unsupported", req.ReviewStatus))
		return
	}
	actionType := strings.ToLower(strings.TrimSpace(req.ActionType))
	if actionType == "" {
		writeMappedError(w, fmt.Errorf("guardian memory action_type is required"))
		return
	}

	namespace := firstNonEmpty(strings.TrimSpace(req.Namespace), "global")
	manifests, err := repository.ListManifests(r.Context(), s.db, model.ListManifestFilters{
		Kind:       "guardian_memory",
		Namespace:  namespace,
		ActiveOnly: true,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	updated := make([]model.Manifest, 0)
	reviewedSpecs := make([]model.GuardianMemoryManifestSpec, 0)
	for _, manifestRecord := range manifests {
		spec, err := manifestengine.ParseGuardianMemorySpec(manifestRecord.Spec)
		if err != nil {
			writeMappedError(w, err)
			return
		}
		spec = manifestengine.NormalizeGuardianMemorySpec(spec)
		if !guardianMemoryMatchesPlaybookReview(spec, req) {
			continue
		}

		spec.Metadata = applyGuardianMemoryReview(spec.Metadata, reviewStatus, req.Comment)
		specRaw, err := json.Marshal(spec)
		if err != nil {
			writeMappedError(w, fmt.Errorf("marshal guardian memory spec: %w", err))
			return
		}

		updatedManifest, err := createManifestVersion(r.Context(), s.db, model.ManifestDocument{
			APIVersion: manifestRecord.APIVersion,
			Kind:       manifestRecord.Kind,
			Metadata:   manifestMetadataInputFromManifest(manifestRecord),
			Spec:       specRaw,
		})
		if err != nil {
			writeMappedError(w, err)
			return
		}
		updated = append(updated, updatedManifest)
		reviewedSpecs = append(reviewedSpecs, spec)
	}

	if len(updated) == 0 {
		writeMappedError(w, repository.ErrManifestNotFound)
		return
	}

	if err := propagateGuardianMemoryReviewToBundles(r.Context(), s.db, reviewedSpecs, reviewStatus, req.Comment, req); err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"updated":   len(updated),
		"manifests": updated,
	})
}

func (s *Server) handleGuardianApprovalDecision(w http.ResponseWriter, r *http.Request) {
	var req guardianApprovalDecisionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	namespace := firstNonEmpty(queryString(r, "namespace"), r.PathValue("namespace"))
	if strings.TrimSpace(namespace) == "" {
		namespace = "global"
	}
	name := firstNonEmpty(queryString(r, "name"), r.PathValue("name"))
	if strings.TrimSpace(name) == "" {
		writeMappedError(w, fmt.Errorf("guardian approval name is required"))
		return
	}

	manifestRecord, err := repository.ResolveManifest(r.Context(), s.db, "guardian_approval", namespace, name, nil, true)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	spec, err := manifestengine.ParseGuardianApprovalSpec(manifestRecord.Spec)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	spec = manifestengine.NormalizeGuardianApprovalSpec(spec)

	status := strings.ToLower(strings.TrimSpace(req.Status))
	switch status {
	case model.GuardianApprovalStatusApproved, model.GuardianApprovalStatusRejected:
	default:
		writeMappedError(w, fmt.Errorf("guardian approval status %q is unsupported", req.Status))
		return
	}

	spec.Status = status
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}
	if strings.TrimSpace(req.Comment) != "" {
		spec.Metadata["decision_comment"] = strings.TrimSpace(req.Comment)
	}
	for key, value := range req.Metadata {
		spec.Metadata[key] = value
	}
	decidedAt := time.Now().UTC().Format(time.RFC3339)
	spec.Metadata["decided_at"] = decidedAt

	specRaw, err := json.Marshal(spec)
	if err != nil {
		writeMappedError(w, fmt.Errorf("marshal guardian approval spec: %w", err))
		return
	}

	updatedManifest, err := createManifestVersion(r.Context(), s.db, model.ManifestDocument{
		APIVersion: manifestRecord.APIVersion,
		Kind:       manifestRecord.Kind,
		Metadata:   guardianApprovalMetadataInput(manifestRecord, spec.Status),
		Spec:       specRaw,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// The core used to drive Heimdall-specific side effects here —
	// updating guardian_memory records, remediation bundles, and
	// dispatching the approved action. Those side effects now live
	// in the guardian integration that observes this approval via
	// the event stream (manifest.created emits for every new version,
	// including the approved one). The core's responsibility ends at
	// persisting the decision.
	writeJSON(w, http.StatusCreated, map[string]any{"manifest": updatedManifest})
}

func guardianApprovalMetadataInput(manifestRecord model.Manifest, status string) model.ManifestMetadataInput {
	labels := cloneStringMap(manifestRecord.Metadata.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	if strings.TrimSpace(status) != "" {
		labels["approval_status"] = strings.TrimSpace(status)
	}

	input := manifestMetadataInputFromManifest(manifestRecord)
	input.Labels = labels
	return input
}

func manifestMetadataInputFromManifest(manifestRecord model.Manifest) model.ManifestMetadataInput {
	return model.ManifestMetadataInput{
		Name:        manifestRecord.Metadata.Name,
		Namespace:   manifestRecord.Metadata.Namespace,
		Description: manifestRecord.Metadata.Description,
		Labels:      cloneStringMap(manifestRecord.Metadata.Labels),
	}
}

func normalizeGuardianMemoryReviewStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "promoted", "blocked":
		return strings.ToLower(strings.TrimSpace(raw))
	case "clear", "cleared", "none", "unreviewed", "":
		return "clear"
	default:
		return ""
	}
}

func applyGuardianMemoryReview(metadata map[string]any, reviewStatus, comment string) map[string]any {
	updated := cloneAnyMap(metadata)
	if updated == nil {
		updated = map[string]any{}
	}
	switch reviewStatus {
	case "clear":
		delete(updated, "learned_playbook_review_status")
		delete(updated, "learned_playbook_reviewed_at")
		delete(updated, "learned_playbook_review_note")
		delete(updated, "learned_playbook_review")
	default:
		updated["learned_playbook_review_status"] = reviewStatus
		recordedAt := time.Now().UTC().Format(time.RFC3339)
		updated["learned_playbook_reviewed_at"] = recordedAt
		if strings.TrimSpace(comment) != "" {
			updated["learned_playbook_review_note"] = strings.TrimSpace(comment)
		} else {
			delete(updated, "learned_playbook_review_note")
		}
		updated["learned_playbook_review"] = map[string]any{
			"kind":        "learned_playbook_review",
			"status":      reviewStatus,
			"summary":     guardianMemoryReviewSummary(reviewStatus),
			"comment":     strings.TrimSpace(comment),
			"source":      "console_review",
			"actor":       "console",
			"recorded_at": recordedAt,
		}
	}
	return updated
}

func guardianMemoryReviewSummary(reviewStatus string) string {
	switch reviewStatus {
	case "promoted":
		return "Learned playbook manually promoted for lightweight reuse."
	case "blocked":
		return "Learned playbook blocked from future lightweight reuse."
	default:
		return "Learned playbook review updated."
	}
}

func propagateGuardianMemoryReviewToBundles(
	ctx context.Context,
	db *sql.DB,
	specs []model.GuardianMemoryManifestSpec,
	reviewStatus string,
	comment string,
	req guardianMemoryReviewRequest,
) error {
	if len(specs) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	for _, spec := range specs {
		ref := remediationBundleRefFromGuardianMemory(spec)
		if ref.namespace == "" || ref.name == "" {
			continue
		}
		key := ref.namespace + "/" + ref.name
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if err := updateRemediationBundlePromotionReview(ctx, db, ref.namespace, ref.name, reviewStatus, comment, req); err != nil {
			return err
		}
	}
	return nil
}

type remediationBundleRef struct {
	namespace string
	name      string
}

func remediationBundleRefFromGuardianMemory(spec model.GuardianMemoryManifestSpec) remediationBundleRef {
	actionTarget, ok := spec.Action["target"].(map[string]any)
	if !ok {
		return remediationBundleRef{}
	}
	bundleRef, ok := actionTarget["remediation_bundle"].(map[string]any)
	if !ok {
		return remediationBundleRef{}
	}
	return remediationBundleRef{
		namespace: firstNonEmpty(anyString(bundleRef["namespace"]), "global"),
		name:      anyString(bundleRef["name"]),
	}
}

func updateRemediationBundlePromotionReview(
	ctx context.Context,
	db *sql.DB,
	namespace string,
	name string,
	reviewStatus string,
	comment string,
	req guardianMemoryReviewRequest,
) error {
	manifestRecord, err := repository.ResolveManifest(ctx, db, "remediation_bundle", namespace, name, nil, true)
	if err != nil {
		return err
	}
	spec, err := manifestengine.ParseRemediationBundleSpec(manifestRecord.Spec)
	if err != nil {
		return err
	}
	spec = manifestengine.NormalizeRemediationBundleSpec(spec)
	if reviewStatus == "clear" {
		spec.PromotionReview = nil
	} else {
		spec.PromotionReview = &model.RemediationBundleReasonSpec{
			Kind:       "learned_playbook_review",
			Status:     reviewStatus,
			Summary:    guardianMemoryReviewSummary(reviewStatus),
			Comment:    strings.TrimSpace(comment),
			Source:     "console_review",
			Actor:      "console",
			RecordedAt: time.Now().UTC().Format(time.RFC3339),
			Metadata: map[string]any{
				"action_type":       strings.TrimSpace(req.ActionType),
				"pattern_kind":      strings.TrimSpace(req.PatternKind),
				"pattern_value":     strings.TrimSpace(req.PatternValue),
				"incident_category": strings.TrimSpace(req.IncidentCategory),
				"provider_group":    strings.TrimSpace(req.ProviderGroup),
			},
		}
	}
	specRaw, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("marshal remediation bundle review spec: %w", err)
	}
	_, err = createManifestVersion(ctx, db, model.ManifestDocument{
		APIVersion: manifestRecord.APIVersion,
		Kind:       manifestRecord.Kind,
		Metadata:   manifestMetadataInputFromManifest(manifestRecord),
		Spec:       specRaw,
	})
	return err
}

func guardianMemoryMatchesPlaybookReview(
	spec model.GuardianMemoryManifestSpec,
	req guardianMemoryReviewRequest,
) bool {
	if strings.TrimSpace(req.ActionType) != "" && guardianMemoryReviewActionType(spec) != strings.ToLower(strings.TrimSpace(req.ActionType)) {
		return false
	}
	if strings.TrimSpace(req.IncidentCategory) != "" && guardianMemoryReviewIncidentCategory(spec) != strings.ToLower(strings.TrimSpace(req.IncidentCategory)) {
		return false
	}
	if strings.TrimSpace(req.ProviderGroup) != "" && guardianMemoryReviewProviderGroup(spec) != strings.ToLower(strings.TrimSpace(req.ProviderGroup)) {
		return false
	}

	patternKind, patternValue := guardianMemoryReviewPattern(spec)
	if strings.TrimSpace(req.PatternKind) != "" && patternKind != strings.ToLower(strings.TrimSpace(req.PatternKind)) {
		return false
	}
	if strings.TrimSpace(req.PatternValue) != "" && patternValue != strings.ToLower(strings.TrimSpace(req.PatternValue)) {
		return false
	}
	return true
}

func guardianMemoryReviewActionType(spec model.GuardianMemoryManifestSpec) string {
	return strings.ToLower(strings.TrimSpace(stringMapValue(spec.Action, "type")))
}

func guardianMemoryReviewIncidentCategory(spec model.GuardianMemoryManifestSpec) string {
	if value := strings.ToLower(strings.TrimSpace(stringMapValue(spec.Metadata, "incident_category"))); value != "" {
		return value
	}
	return strings.ToLower(strings.TrimSpace(stringMapValue(spec.Incident, "category")))
}

func guardianMemoryReviewProviderGroup(spec model.GuardianMemoryManifestSpec) string {
	if value := strings.ToLower(strings.TrimSpace(stringMapValue(spec.Metadata, "provider_group"))); value != "" {
		return value
	}
	providerKey := strings.ToLower(strings.TrimSpace(stringMapValue(spec.Metadata, "provider_key")))
	if providerKey == "" {
		return "unknown"
	}
	parts := strings.SplitN(providerKey, ":", 2)
	if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
		return providerKey
	}
	segments := strings.Split(parts[1], "/")
	return strings.TrimSpace(segments[len(segments)-1])
}

func guardianMemoryReviewPattern(spec model.GuardianMemoryManifestSpec) (string, string) {
	actionType := guardianMemoryReviewActionType(spec)
	target := objectMapValue(spec.Action, "target")
	if actionType != "" {
		if learnedPattern := strings.ToLower(strings.TrimSpace(stringMapValue(target, "learned_playbook_pattern"))); learnedPattern != "" {
			segments := strings.SplitN(learnedPattern, ":", 2)
			if len(segments) == 2 {
				return strings.TrimSpace(segments[0]), strings.TrimSpace(segments[1])
			}
			return actionType, learnedPattern
		}
	}

	switch actionType {
	case "dispatch_workflow":
		workflow := firstNonEmpty(
			stringMapValue(objectMapValue(spec.Action, "workflow"), "workflow"),
			stringMapValue(target, "workflow"),
			"deploy.yml",
		)
		return "workflow_dispatch", strings.ToLower(strings.TrimSpace(workflow))
	case "rightsize_component":
		operation := objectMapValue(spec.Action, "operation")
		resource := firstNonEmpty(stringMapValue(operation, "resource"), "capacity")
		direction := firstNonEmpty(stringMapValue(operation, "direction"), "increase")
		return "rightsize", strings.ToLower(strings.TrimSpace(resource + ":" + direction))
	case "rotate_secret":
		return "rotate_secret", "secret"
	case "page_team":
		team := firstNonEmpty(
			stringMapValue(objectMapValue(spec.Action, "operation"), "team"),
			stringMapValue(target, "team"),
			"team",
		)
		return "page_team", strings.ToLower(strings.TrimSpace(team))
	default:
		return actionType, actionType
	}
}

func stringMapValue(input map[string]any, key string) string {
	if len(input) == 0 {
		return ""
	}
	value, ok := input[key]
	if !ok {
		return ""
	}
	text, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(text)
}

func objectMapValue(input map[string]any, key string) map[string]any {
	if len(input) == 0 {
		return nil
	}
	value, ok := input[key]
	if !ok {
		return nil
	}
	nested, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return nested
}

func (s *Server) handleRemediationContractList(w http.ResponseWriter, r *http.Request) {
	s.handleManifestList(w, r, "remediation_contract")
}

func (s *Server) handleRemediationContractCreate(w http.ResponseWriter, r *http.Request) {
	s.handleManifestCreate(w, r, "remediation_contract")
}

func (s *Server) handleSurfaceCreate(w http.ResponseWriter, r *http.Request) {
	s.handleManifestCreate(w, r, "surface")
}

func (s *Server) handleWorkflowList(w http.ResponseWriter, r *http.Request) {
	s.handleManifestList(w, r, "workflow")
}

func (s *Server) handleWorkflowCreate(w http.ResponseWriter, r *http.Request) {
	s.handleManifestCreate(w, r, "workflow")
}

func (s *Server) handleManifestList(w http.ResponseWriter, r *http.Request, kind string) {
	manifests, err := repository.ListManifests(r.Context(), s.db, model.ListManifestFilters{
		Kind:       kind,
		Namespace:  queryString(r, "namespace"),
		Name:       queryString(r, "name"),
		ActiveOnly: queryActiveOnly(r),
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, manifestsResponse{Manifests: manifests})
}

func (s *Server) handleManifestCreate(w http.ResponseWriter, r *http.Request, kind string) {
	// Auth gate (security audit 2026-05-27 A1 fix): manifest writes are
	// administrative operations that bypass console permission grants.
	// We accept either YGGDRASIL_WORKFLOW_RUN_TOKEN (workflow/admin caller)
	// or a valid console session (a human operator already authenticated
	// by the requireAuthenticatedConsoleAPIs middleware whose claims live
	// in the request context). Without one, the call is anonymous and
	// MUST be refused.
	if !s.manifestWriteAuthorized(r) {
		writeMappedError(w, errWorkflowRunUnauthorized)
		return
	}

	var payload consoleCreateManifestRequest
	if err := decodeJSON(r, &payload); err != nil {
		writeMappedError(w, err)
		return
	}

	doc, err := manifestDocumentFromPayload(kind, payload)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	// Capability-naming validator (Phase 1 warn-only / Phase 2 hard-fail).
	// Runs BEFORE the manifest is persisted so hard-fail can reject the
	// write cleanly — no DB churn, no audit-log misleading "success" then
	// "rollback" pair.  The phase is read once at boot from
	// YGGDRASIL_VALIDATOR_PHASE; default warn-only.  See
	// validator_phase.go + reference_phase2_validator_flip_runbook.md.
	var warnings []manifestengine.Warning
	if kind == "integration_type" {
		warnings = s.collectIntegrationTypeWarnings(doc.Spec)

		// Always emit observability signals — the gauge per
		// integration_type (sets to 0 for conformant ones too so the
		// dashboard shows a zero baseline) plus the unlabeled rolling
		// counter the spike-detection alert evaluates rate() over.
		metrics.SetCapabilityWarnings(doc.Metadata.Name, float64(len(warnings)))
		if len(warnings) > 0 {
			metrics.AddCapabilityWarningsTotal(uint64(len(warnings)))
		}

		// Phase 2 hard-fail short-circuit.  When the operator has
		// flipped YGGDRASIL_VALIDATOR_PHASE=hard-fail and the validator
		// found non-conformant names, refuse the write with HTTP 422
		// (Unprocessable Entity) and return the same warnings array
		// callers already know how to surface.  Stays at zero rejections
		// while the env-var is unset.
		if len(warnings) > 0 && s.validatorPhase == ValidatorPhaseHardFail {
			metrics.IncCapabilityRejections()
			s.recordAudit(r, "manifest.create", kind,
				fmt.Sprintf("%s/%s", doc.Metadata.Namespace, doc.Metadata.Name),
				"rejected", map[string]any{
					"reason":          "capability_naming_nonconformant",
					"validator_phase": s.validatorPhase,
					"warnings":        warnings,
				})
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error":           "manifest rejected by capability-naming validator (Phase 2 hard-fail)",
				"validator_phase": s.validatorPhase,
				"warnings":        warnings,
			})
			return
		}
	}

	manifestRecord, err := createManifestVersion(r.Context(), s.db, doc)
	if err != nil {
		s.recordAudit(r, "manifest.create", kind,
			fmt.Sprintf("%s/%s", doc.Metadata.Namespace, doc.Metadata.Name),
			"error", map[string]any{"error": err.Error()})
		writeMappedError(w, err)
		return
	}

	// Persist warnings to manifests.metadata so the console can render
	// a conformance badge without re-running the validator on every
	// page load.  Runs in warn-only mode (Phase 2 already returned
	// 422 above before we got here when warnings>0).
	if kind == "integration_type" && len(warnings) > 0 {
		annotations, marshalErr := json.Marshal(map[string]any{"warnings": warnings})
		if marshalErr == nil {
			if persistErr := repository.SetManifestMetadata(r.Context(), s.db, manifestRecord.ID, annotations); persistErr != nil {
				// Warning persistence is non-fatal — the response
				// still carries the warnings array. Audit the
				// failure so operators can investigate.
				s.recordAudit(r, "manifest.warnings_persist", kind,
					fmt.Sprintf("%s/%s", manifestRecord.Metadata.Namespace, manifestRecord.Metadata.Name),
					"error", map[string]any{"error": persistErr.Error()})
			}
		}
	}

	s.materializeAfterManifestWrite(manifestRecord)

	s.recordAudit(r, "manifest.create", kind,
		fmt.Sprintf("%s/%s", manifestRecord.Metadata.Namespace, manifestRecord.Metadata.Name),
		"success", map[string]any{"version": manifestRecord.Version, "checksum": manifestRecord.Checksum})

	IncManifestApplied()
	resp := map[string]any{"manifest": manifestRecord}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}
	writeJSON(w, http.StatusCreated, resp)
}

// collectIntegrationTypeWarnings runs the naming validator against an
// integration_type spec.  Phase 1 surfaces the returned slice as
// warnings:[...] on a 201 Created response; Phase 2 turns that same
// slice into a 422 Unprocessable Entity refusal.  See spec
// docs/superpowers/specs/2026-05-27-yggdrasil-integration-capability-convention.md
// and validator_phase.go for the phase resolution.
func (s *Server) collectIntegrationTypeWarnings(specRaw json.RawMessage) []manifestengine.Warning {
	if s.capabilityAllowlist == nil {
		return nil
	}
	spec, err := manifestengine.ParseIntegrationTypeSpec(specRaw)
	if err != nil {
		return nil
	}
	return manifestengine.ValidateActionCatalogNaming(spec.ActionCatalog, s.capabilityAllowlist)
}

func integrationInstanceDocumentFromPayload(payload consoleCreateIntegrationInstanceRequest) (model.ManifestDocument, error) {
	if len(payload.Credentials) > 0 && strings.TrimSpace(payload.CredentialsRef) != "" {
		return model.ManifestDocument{}, fmt.Errorf("provide either credentials or credentials_ref, not both")
	}

	spec := model.IntegrationInstanceManifestSpec{
		TypeRef:        payload.TypeRef,
		Status:         payload.Status,
		Owners:         payload.Owners,
		Credentials:    cloneAnyMap(payload.Credentials),
		CredentialsRef: strings.TrimSpace(payload.CredentialsRef),
		Config:         cloneAnyMap(payload.Config),
		Discovery: model.IntegrationInstanceDiscoverySpec{
			Enabled:             payload.Discovery.Enabled,
			Mode:                payload.Discovery.Mode,
			SyncIntervalSeconds: payload.Discovery.SyncIntervalSeconds,
		},
		Execution: model.IntegrationInstanceExecutionSpec{
			DefaultDryRun: payload.Execution.DefaultDryRun,
			MaxBatchSize:  payload.Execution.MaxBatchSize,
		},
	}

	specRaw, err := json.Marshal(spec)
	if err != nil {
		return model.ManifestDocument{}, fmt.Errorf("marshal integration_instance spec: %w", err)
	}

	return model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "integration_instance",
		Metadata: model.ManifestMetadataInput{
			Name:        payload.Name,
			Namespace:   payload.Namespace,
			Description: payload.Description,
			Labels:      cloneStringMap(payload.Labels),
		},
		Spec: specRaw,
	}, nil
}

func manifestDocumentFromPayload(kind string, payload consoleCreateManifestRequest) (model.ManifestDocument, error) {
	if len(bytesTrimSpace(payload.Spec)) == 0 || string(bytesTrimSpace(payload.Spec)) == "null" {
		return model.ManifestDocument{}, fmt.Errorf("spec is required")
	}

	var specValue any
	if err := json.Unmarshal(payload.Spec, &specValue); err != nil {
		return model.ManifestDocument{}, fmt.Errorf("parse manifest spec: %w", err)
	}

	specRaw, err := json.Marshal(specValue)
	if err != nil {
		return model.ManifestDocument{}, fmt.Errorf("marshal manifest spec: %w", err)
	}

	return model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       kind,
		Metadata: model.ManifestMetadataInput{
			Name:        payload.Name,
			Namespace:   payload.Namespace,
			Description: payload.Description,
			Labels:      cloneStringMap(payload.Labels),
			Active:      payload.Active,
		},
		Spec: specRaw,
	}, nil
}

func createManifestVersion(ctx context.Context, db *sql.DB, doc model.ManifestDocument) (model.Manifest, error) {
	doc = manifestengine.NormalizeDocument(doc)
	if err := manifestengine.ValidateDocument(doc); err != nil {
		return model.Manifest{}, err
	}

	checksum, err := manifestengine.Checksum(doc)
	if err != nil {
		return model.Manifest{}, err
	}

	return repository.CreateManifestVersion(ctx, db, doc, checksum)
}

func decodeJSON(r *http.Request, dst any) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}
	if decoder.More() {
		return fmt.Errorf("decode request body: unexpected trailing JSON")
	}
	return nil
}

func decodeOptionalJSON(r *http.Request, dst any) error {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("read request body: %w", err)
	}
	if len(bytesTrimSpace(raw)) == 0 {
		return nil
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}
	if decoder.More() {
		return fmt.Errorf("decode request body: unexpected trailing JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// writeJSONError emits a §14 RFC 7807 Problem+JSON envelope with the
// `error` legacy field PRESERVED for backward compatibility. The two
// shapes share one body — clients reading `code` get the structured
// path; clients reading `error` keep working until the next major bump
// removes the legacy field.
//
// The Content-Type is application/problem+json so RFC 7807-aware
// clients (FE Problem+JSON middlewares, k8s.io/apimachinery, etc.) parse
// it directly.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeProblemEnvelope(w, status, codeFromGenericMessage(status, msg), httpStatusTitle(status), msg, "")
}

// writeMappedError preserves the legacy entry point used by ~250 call
// sites while transparently emitting the §14 envelope. The `code` is
// derived from the typed error class (errors.Is chain) when possible,
// falling back to a category-based default when the error is anonymous.
//
// Existing callers do NOT need to change — both `error` and `code`
// fields appear in the body. New handlers should prefer
// httperr.WriteProblem directly for richer extras (instance, errors[]).
func writeMappedError(w http.ResponseWriter, err error) {
	status := httpStatusFromError(err)
	code := codeFromError(err, status)
	writeProblemEnvelope(w, status, code, httpStatusTitle(status), strings.TrimSpace(err.Error()), "")
}

// writeProblemEnvelope is the shared body writer for both writeJSONError
// and writeMappedError. The wire shape:
//
//   Content-Type: application/problem+json
//   {
//     "type":   "https://yggdrasil.dakasa.me/errors/<code>",
//     "title":  "<HTTP status text>",
//     "status": <code>,
//     "code":   "<machine-readable code>",
//     "detail": "<original message>",
//     "error":  "<original message>"    // LEGACY — preserved for one minor
//                                       // version so consumers can migrate
//   }
//
// The legacy `error` key is THE ONE backward-compat hack §14 explicitly
// permits (see contract: "code is added alongside for one minor version,
// then the legacy field is removed"). It is the only field outside the
// RFC 7807 reserved set, so RFC-7807 parsers ignore it gracefully.
func writeProblemEnvelope(w http.ResponseWriter, status int, code, title, detail, instance string) {
	p := &httperr.Problem{
		Status:   status,
		Code:     code,
		Title:    title,
		Detail:   detail,
		Instance: instance,
		Extra: map[string]interface{}{
			// LEGACY backward-compat. Drops in the next minor.
			"error": detail,
		},
	}
	httperr.Write(w, p)
}

// codeFromError maps the existing typed errors into the §14 stable
// `code` namespace. Falls back to a category derived from the HTTP
// status when the error is unknown.
func codeFromError(err error, status int) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, messagecontroller.ErrAdapterTransportUnavailable):
		return httperr.CodeIntegrationUnavailable
	case errors.Is(err, errWorkflowRunUnauthorized),
		errors.Is(err, errAuthAdminUnauthorized):
		return httperr.CodeAuthUnauthenticated
	case errors.Is(err, repository.ErrAuthInvalidCredentials):
		return httperr.CodeAuthInvalidCredentials
	case errors.Is(err, repository.ErrAuthSessionNotFound):
		return httperr.CodeAuthSessionNotFound
	case errors.Is(err, repository.ErrAuthSessionExpired):
		return httperr.CodeAuthSessionExpired
	case errors.Is(err, repository.ErrPasswordCredentialNotFound):
		return httperr.CodeAuthInvalidCredentials
	case errors.Is(err, repository.ErrAuthAccountLocked):
		return httperr.CodeAuthAccountLocked
	case errors.Is(err, mfa.ErrMFANotEnrolled):
		return httperr.CodeAuthMFANotEnrolled
	case errors.Is(err, mfa.ErrInvalidRecoveryCode):
		return httperr.CodeAuthMFAInvalid
	case errors.Is(err, repository.ErrMFAEnrollTokenAlreadyConsumed),
		errors.Is(err, repository.ErrMFAEnrollTokenExpired):
		return httperr.CodeAuthSetupTokenInvalid
	case errors.Is(err, repository.ErrManifestNotFound):
		return httperr.CodeManifestNotFound
	case errors.Is(err, repository.ErrThirdPartyIdentityConflict):
		return httperr.CodeManifestConflict
	case errors.Is(err, repository.ErrCollaboratorNotFound),
		errors.Is(err, repository.ErrTeamNotFound),
		errors.Is(err, repository.ErrManagedSecretNotFound),
		errors.Is(err, repository.ErrThirdPartyIdentityNotFound),
		errors.Is(err, repository.ErrThirdPartyAuthProviderNotFound),
		errors.Is(err, repository.ErrMFAEnrollTokenNotFound):
		return httperr.CodeIntegrationNotFound
	case errors.Is(err, errAutoProvisionRejected):
		return httperr.CodePermissionDenied
	}
	// Protected-team invariants get a dedicated code so the FE can
	// surface the right copy ("essa equipe é a raiz e não pode ser
	// alterada"). httpStatusFromError already maps these to 422.
	if status == http.StatusUnprocessableEntity {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "is protected (traits.is_root_admin=true)") ||
			strings.Contains(msg, "grants on the root admin team are frozen") ||
			strings.Contains(msg, "leadership/owners are not allowed") {
			return "team.protected"
		}
	}
	return codeFromGenericMessage(status, err.Error())
}

// codeFromGenericMessage is the last-resort code resolution for plain
// string errors that bypass the typed-error path. Categorizes by HTTP
// status class.
func codeFromGenericMessage(status int, msg string) string {
	switch {
	case status == http.StatusUnauthorized:
		return httperr.CodeAuthUnauthenticated
	case status == http.StatusForbidden:
		return httperr.CodePermissionDenied
	case status == http.StatusNotFound:
		return httperr.CodeIntegrationNotFound
	case status == http.StatusConflict:
		return httperr.CodeManifestConflict
	case status == http.StatusLocked:
		return httperr.CodeAuthAccountLocked
	case status == http.StatusTooManyRequests:
		return httperr.CodeRateLimitExceeded
	case status == http.StatusPreconditionRequired:
		return httperr.CodeAuthMFARequired
	case status >= 400 && status < 500:
		// "decode request body", "validation", "required", etc.
		lowered := strings.ToLower(msg)
		switch {
		case strings.Contains(lowered, "required"):
			return httperr.CodeMissingField
		case strings.Contains(lowered, "validation"):
			return httperr.CodeManifestValidationFailed
		case strings.Contains(lowered, "parse"),
			strings.Contains(lowered, "decode"),
			strings.Contains(lowered, "malformed"):
			return httperr.CodeMalformedBody
		}
		return httperr.CodeInvalidInput
	case status >= 500:
		return httperr.CodeInternal
	}
	return httperr.CodeInternal
}

// httpStatusTitle returns the HTTP status text the response advertises
// in Problem.Title. Falls back to a generic string when http.StatusText
// returns "" (custom statuses).
func httpStatusTitle(status int) string {
	if t := http.StatusText(status); t != "" {
		return t
	}
	return "Error"
}

func httpStatusFromError(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, messagecontroller.ErrAdapterTransportUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, errWorkflowRunUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, errAuthAdminUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, repository.ErrAuthInvalidCredentials),
		errors.Is(err, repository.ErrAuthSessionNotFound),
		errors.Is(err, repository.ErrAuthSessionExpired),
		errors.Is(err, repository.ErrPasswordCredentialNotFound):
		return http.StatusUnauthorized
	case errors.Is(err, repository.ErrAuthAccountLocked):
		// 423 Locked — distinct from 401 so the FE can surface
		// "your account is temporarily locked" without revealing
		// whether the just-tried password was correct.
		return http.StatusLocked
	case errors.Is(err, repository.ErrThirdPartyIdentityConflict):
		return http.StatusConflict
	case errors.Is(err, mfa.ErrMFANotEnrolled):
		return http.StatusPreconditionRequired
	case errors.Is(err, repository.ErrManifestNotFound),
		errors.Is(err, repository.ErrCollaboratorNotFound),
		errors.Is(err, repository.ErrTeamNotFound),
		errors.Is(err, repository.ErrManagedSecretNotFound),
		errors.Is(err, repository.ErrThirdPartyIdentityNotFound),
		errors.Is(err, repository.ErrThirdPartyAuthProviderNotFound),
		errors.Is(err, repository.ErrMFAEnrollTokenNotFound):
		return http.StatusNotFound
	case errors.Is(err, repository.ErrMFAEnrollTokenAlreadyConsumed),
		errors.Is(err, repository.ErrMFAEnrollTokenExpired):
		return http.StatusGone
	case errors.Is(err, errAutoProvisionRejected):
		return http.StatusForbidden
	}

	message := strings.ToLower(strings.TrimSpace(err.Error()))

	// Protected-team invariants (root-admin lock, see repository/identity.go)
	// surface as plain fmt.Errorf strings instead of typed errors. They
	// represent intentional refusals — the operator's request is well-formed
	// but conflicts with a policy invariant — so 422 fits better than 500
	// (the previous default) and avoids leaking the policy text as a
	// generic internal error to non-technical operators.
	if strings.Contains(message, "is protected (traits.is_root_admin=true)") ||
		strings.Contains(message, "grants on the root admin team are frozen") ||
		strings.Contains(message, "leadership/owners are not allowed") {
		return http.StatusUnprocessableEntity
	}

	for _, fragment := range []string{
		"required",
		"invalid",
		"unsupported",
		"cannot",
		"duplicate",
		"unique",
		"must",
		"parse",
		"decode request body",
		"validation",
	} {
		if strings.Contains(message, fragment) {
			return http.StatusBadRequest
		}
	}

	return http.StatusInternalServerError
}

func queryString(r *http.Request, key string) string {
	return strings.TrimSpace(r.URL.Query().Get(key))
}

func queryKinds(r *http.Request) []string {
	values := make([]string, 0)
	for _, raw := range r.URL.Query()["kind"] {
		values = append(values, splitCSV(raw)...)
	}
	for _, raw := range r.URL.Query()["kinds"] {
		values = append(values, splitCSV(raw)...)
	}
	return values
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func queryInt(r *http.Request, key string) int {
	value := queryString(r, key)
	if value == "" {
		return 0
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}
	return parsed
}

func queryBool(r *http.Request, key string) bool {
	value := queryString(r, key)
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}
	return parsed
}

func queryActiveOnly(r *http.Request) bool {
	value := queryString(r, "active_only")
	if value == "" {
		return true
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return true
	}
	return parsed
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneAnyMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func bytesTrimSpace(input []byte) []byte {
	return []byte(strings.TrimSpace(string(input)))
}

func (s *Server) materializeIntegrationInstanceCredentials(
	ctx context.Context,
	payload *consoleCreateIntegrationInstanceRequest,
	typeSpec model.IntegrationTypeManifestSpec,
) error {
	if payload == nil || len(payload.Credentials) == 0 {
		return nil
	}
	if strings.TrimSpace(payload.CredentialsRef) != "" {
		return fmt.Errorf("provide either credentials or credentials_ref, not both")
	}
	policy := manifestengine.EffectiveIntegrationCredentialPolicy(typeSpec)
	if !policy.MaterializeInline {
		return nil
	}

	namespace := strings.TrimSpace(payload.Namespace)
	if namespace == "" {
		namespace = "global"
	}
	secretData := make(map[string]string, len(payload.Credentials))
	for key, value := range payload.Credentials {
		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("integration credentials cannot contain empty keys")
		}
		switch typed := value.(type) {
		case string:
			secretData[key] = typed
		case bool, float64, float32, int, int32, int64, uint, uint32, uint64:
			secretData[key] = fmt.Sprint(typed)
		default:
			return fmt.Errorf("integration credential %q must be a scalar value", key)
		}
	}

	secretName := strings.ToLower(strings.TrimSpace(payload.Name)) + "-credentials"
	secret, err := repository.UpsertManagedSecret(ctx, s.db, model.UpsertManagedSecretRequest{
		Namespace: namespace,
		Name:      secretName,
		Status:    "active",
		Data:      secretData,
		Metadata: map[string]any{
			"source_kind": "integration_instance",
			"integration_instance": map[string]any{
				"namespace": namespace,
				"name":      strings.TrimSpace(payload.Name),
			},
		},
		Rotation: model.ManagedSecretRotationPolicy{Mode: "manual"},
	})
	if err != nil {
		return err
	}

	payload.Credentials = nil
	payload.CredentialsRef = fmt.Sprintf("secret://%s/%s", secret.Namespace, secret.Name)
	return nil
}

func (s *Server) materializeIntegrationInstanceSecretConfig(
	ctx context.Context,
	payload *consoleCreateIntegrationInstanceRequest,
	typeSpec model.IntegrationTypeManifestSpec,
) error {
	if payload == nil || len(payload.Config) == 0 {
		return nil
	}

	namespace := strings.TrimSpace(payload.Namespace)
	if namespace == "" {
		namespace = "global"
	}
	instanceName := strings.ToLower(strings.TrimSpace(payload.Name))
	if instanceName == "" {
		return fmt.Errorf("integration instance name is required to materialize secret config fields")
	}

	secretProperties := map[string]model.IntegrationSchemaProperty{}
	for name, property := range typeSpec.InstanceSchema.Properties {
		if property.Secret {
			secretProperties[name] = property
		}
	}
	if len(secretProperties) == 0 {
		return nil
	}

	for key := range secretProperties {
		value, exists := payload.Config[key]
		if !exists || value == nil {
			continue
		}
		if ref := strings.TrimSpace(anyString(value)); strings.HasPrefix(ref, "secret://") {
			continue
		}

		secretValue, err := stringifySecretScalar(value)
		if err != nil {
			return fmt.Errorf("materialize secret config field %q: %w", key, err)
		}

		secretName := fmt.Sprintf("%s-config-%s", instanceName, normalizeSecretNameToken(key))
		secret, err := repository.UpsertManagedSecret(ctx, s.db, model.UpsertManagedSecretRequest{
			Namespace: namespace,
			Name:      secretName,
			Status:    "active",
			Data: map[string]string{
				"value": secretValue,
			},
			Metadata: map[string]any{
				"source_kind": "integration_instance_config",
				"integration_instance": map[string]any{
					"namespace": namespace,
					"name":      strings.TrimSpace(payload.Name),
				},
				"field": key,
			},
			Rotation: model.ManagedSecretRotationPolicy{Mode: "manual"},
		})
		if err != nil {
			return err
		}

		payload.Config[key] = fmt.Sprintf("secret://%s/%s#value", secret.Namespace, secret.Name)
	}

	return nil
}

func stringifySecretScalar(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	case bool, float64, float32, int, int32, int64, uint, uint32, uint64:
		return fmt.Sprint(typed), nil
	default:
		return "", fmt.Errorf("secret config values must be scalar")
	}
}

func normalizeSecretNameToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.ReplaceAll(value, ".", "-")
	return value
}

func anyString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return ""
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func (s *Server) resolveIntegrationTypeSpec(
	ctx context.Context,
	selector model.ManifestSelector,
) (model.Manifest, model.IntegrationTypeManifestSpec, error) {
	var (
		manifestRecord model.Manifest
		err            error
	)
	if strings.TrimSpace(selector.ManifestID) != "" {
		manifestID, parseErr := uuid.Parse(strings.TrimSpace(selector.ManifestID))
		if parseErr != nil {
			return model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("integration_type manifest_id %q is invalid", selector.ManifestID)
		}
		manifestRecord, err = repository.GetManifestByID(ctx, s.db, manifestID)
	} else {
		namespace := strings.TrimSpace(selector.Namespace)
		if namespace == "" {
			namespace = "global"
		}
		manifestRecord, err = repository.ResolveManifest(ctx, s.db, "integration_type", namespace, selector.Name, selector.Version, true)
	}
	if err != nil {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}
	if manifestRecord.Kind != "integration_type" {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("manifest %s is not an integration_type", manifestRecord.ID)
	}

	spec, err := manifestengine.ParseIntegrationTypeSpec(manifestRecord.Spec)
	if err != nil {
		return model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}
	return manifestRecord, spec, nil
}

func hydrateIntegrationInstanceInputSecrets(ctx context.Context, db *sql.DB, spec *model.IntegrationInstanceManifestSpec) error {
	if spec == nil || db == nil {
		return nil
	}

	if strings.TrimSpace(spec.CredentialsRef) != "" {
		value, err := repository.ResolveSecretObjectRef(ctx, db, spec.CredentialsRef)
		if err != nil {
			return fmt.Errorf("resolve integration instance credentials_ref: %w", err)
		}
		spec.Credentials = mergeStringAnyMaps(spec.Credentials, value)
	}

	if len(spec.Credentials) > 0 {
		resolved, err := repository.ResolveSecretRefs(ctx, db, cloneAnyMap(spec.Credentials))
		if err != nil {
			return fmt.Errorf("resolve integration instance credentials: %w", err)
		}
		if typed, ok := resolved.(map[string]any); ok {
			spec.Credentials = typed
		}
	}

	if len(spec.Config) > 0 {
		resolved, err := repository.ResolveSecretRefs(ctx, db, cloneAnyMap(spec.Config))
		if err != nil {
			return fmt.Errorf("resolve integration instance config: %w", err)
		}
		if typed, ok := resolved.(map[string]any); ok {
			spec.Config = typed
		}
	}

	return nil
}

func mergeStringAnyMaps(base map[string]any, extra map[string]any) map[string]any {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]any, len(base)+len(extra))
	for key, value := range base {
		out[key] = value
	}
	for key, value := range extra {
		out[key] = value
	}
	return out
}
