package httpapi

import (
	"context"
	"database/sql"
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
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/provisioner"
	"github.com/dakasa-yggdrasil/yggdrasil-core/reconciler"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
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
	Collaborators []model.Collaborator `json:"collaborators"`
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

	server := &Server{
		serviceName: serviceName,
		db:          db,
		rabbitmq:    conn,
		logger:      logger,
	}

	for _, opt := range opts {
		opt(server)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", server.handleRoot)
	mux.HandleFunc("GET /healthz", server.handleHealthz)
	mux.HandleFunc("GET /readyz", server.handleReadyz)
	mux.HandleFunc("POST /api/v1/auth/passwords", server.handleAuthPasswordUpsert)
	mux.HandleFunc("POST /api/v1/auth/login", server.handleAuthLogin)
	mux.HandleFunc("POST /api/v1/auth/third-party/login", server.handleAuthThirdPartyLogin)
	mux.HandleFunc("GET /api/v1/auth/third-party/start/{provider}", server.handleAuthThirdPartyStart)
	mux.HandleFunc("GET /api/v1/auth/third-party/callback/{provider}", server.handleAuthThirdPartyCallback)
	mux.HandleFunc("GET /api/v1/auth/third-party-identities", server.handleThirdPartyIdentityList)
	mux.HandleFunc("POST /api/v1/auth/third-party-identities", server.handleThirdPartyIdentityUpsert)
	mux.HandleFunc("DELETE /api/v1/auth/third-party-identities/{provider}/{subject}", server.handleThirdPartyIdentityDelete)
	mux.HandleFunc("GET /api/v1/auth/providers", server.handleThirdPartyAuthProviderList)
	mux.HandleFunc("POST /api/v1/auth/providers", server.handleThirdPartyAuthProviderUpsert)
	mux.HandleFunc("GET /api/v1/auth/providers/{provider}", server.handleThirdPartyAuthProviderGet)
	mux.HandleFunc("DELETE /api/v1/auth/providers/{provider}", server.handleThirdPartyAuthProviderDelete)
	mux.HandleFunc("GET /api/v1/auth/session", server.handleAuthSession)
	mux.HandleFunc("POST /api/v1/auth/logout", server.handleAuthLogout)
	mux.HandleFunc("GET /api/v1/integration-catalog", server.handleIntegrationCatalogList)
	mux.HandleFunc("GET /api/v1/integration-catalog/{domain}/{section}/{entry}", server.handleIntegrationCatalogEntry)
	mux.HandleFunc("GET /api/v1/catalog/discovery", server.handleCatalogDiscovery)
	mux.HandleFunc("POST /api/v1/catalog/discovery/register", server.handleCatalogDiscoveryRegister)
	mux.HandleFunc("GET /api/v1/integration-instances", server.handleIntegrationInstanceList)
	mux.HandleFunc("POST /api/v1/integration-instances", server.handleIntegrationInstanceCreate)
	mux.HandleFunc("GET /api/v1/collaborators", server.handleCollaboratorList)
	mux.HandleFunc("POST /api/v1/collaborators", server.handleCollaboratorCreate)
	mux.HandleFunc("GET /api/v1/teams", server.handleTeamList)
	mux.HandleFunc("POST /api/v1/teams", server.handleTeamCreate)
	mux.HandleFunc("GET /api/v1/team-memberships", server.handleTeamMembershipList)
	mux.HandleFunc("POST /api/v1/team-memberships", server.handleTeamMembershipUpsert)
	mux.HandleFunc("GET /api/v1/products", server.handleProductList)
	mux.HandleFunc("POST /api/v1/products", server.handleProductCreate)
	mux.HandleFunc("GET /api/v1/secrets", server.handleManagedSecretList)
	mux.HandleFunc("GET /api/v1/secrets/{namespace}/{name}", server.handleManagedSecretGet)
	mux.HandleFunc("POST /api/v1/secrets", server.handleManagedSecretCreate)
	mux.HandleFunc("POST /api/v1/secrets/{namespace}/{name}/rotate", server.handleManagedSecretRotate)
	mux.HandleFunc("POST /api/v1/secrets/{namespace}/{name}/disable", server.handleManagedSecretDisable)
	mux.HandleFunc("POST /api/v1/secrets/{namespace}/{name}/revoke", server.handleManagedSecretRevoke)
	mux.HandleFunc("POST /api/v1/secrets/materialize-all", server.handleMaterializeAll)
	mux.HandleFunc("POST /api/v1/secrets/{namespace}/{name}/materialize", server.handleMaterializeOne)
	mux.HandleFunc("GET /api/v1/reconciler/status", server.handleReconcilerStatus)
	mux.HandleFunc("GET /api/v1/repository-bindings", server.handleRepositoryBindingList)
	mux.HandleFunc("POST /api/v1/repository-bindings", server.handleRepositoryBindingCreate)
	mux.HandleFunc("GET /api/v1/guardian-policies", server.handleGuardianPolicyList)
	mux.HandleFunc("POST /api/v1/guardian-policies", server.handleGuardianPolicyCreate)
	mux.HandleFunc("GET /api/v1/guardian-approvals", server.handleGuardianApprovalList)
	mux.HandleFunc("POST /api/v1/guardian-approvals", server.handleGuardianApprovalCreate)
	mux.HandleFunc("POST /api/v1/guardian-approvals/{namespace}/{name}/decision", server.handleGuardianApprovalDecision)
	mux.HandleFunc("GET /api/v1/guardian-memories", server.handleGuardianMemoryList)
	mux.HandleFunc("GET /api/v1/remediation-bundles", server.handleRemediationBundleList)
	mux.HandleFunc("POST /api/v1/remediation-bundles", server.handleRemediationBundleCreate)
	mux.HandleFunc("POST /api/v1/guardian-memories/review", server.handleGuardianMemoryReview)
	mux.HandleFunc("GET /api/v1/remediation-contracts", server.handleRemediationContractList)
	mux.HandleFunc("POST /api/v1/remediation-contracts", server.handleRemediationContractCreate)
	mux.HandleFunc("GET /api/v1/surfaces", server.handleSurfaceList)
	mux.HandleFunc("POST /api/v1/surfaces", server.handleSurfaceCreate)
	mux.HandleFunc("GET /api/v1/workflows", server.handleWorkflowList)
	mux.HandleFunc("POST /api/v1/workflows", server.handleWorkflowCreate)
	mux.HandleFunc("POST /api/v1/workflow-runs", server.handleWorkflowRun)
	mux.HandleFunc("POST /api/v1/provision/aws", server.handleProvisionAWS)
	mux.HandleFunc("GET /api/v1/console/integration-catalog", server.handleIntegrationCatalogList)
	mux.HandleFunc("GET /api/v1/console/integration-catalog/{domain}/{section}/{entry}", server.handleIntegrationCatalogEntry)
	mux.HandleFunc("GET /api/v1/console/catalog-discovery", server.handleCatalogDiscovery)
	mux.HandleFunc("POST /api/v1/console/catalog-discovery/register", server.handleCatalogDiscoveryRegister)
	mux.HandleFunc("GET /api/v1/console/integration-instances", server.handleIntegrationInstanceList)
	mux.HandleFunc("POST /api/v1/console/integration-instances", server.handleIntegrationInstanceCreate)
	mux.HandleFunc("GET /api/v1/console/collaborators", server.handleCollaboratorList)
	mux.HandleFunc("POST /api/v1/console/collaborators", server.handleCollaboratorCreate)
	mux.HandleFunc("GET /api/v1/console/teams", server.handleTeamList)
	mux.HandleFunc("POST /api/v1/console/teams", server.handleTeamCreate)
	mux.HandleFunc("GET /api/v1/console/team-memberships", server.handleTeamMembershipList)
	mux.HandleFunc("POST /api/v1/console/team-memberships", server.handleTeamMembershipUpsert)
	mux.HandleFunc("GET /api/v1/console/auth/third-party-identities", server.handleThirdPartyIdentityList)
	mux.HandleFunc("POST /api/v1/console/auth/third-party-identities", server.handleThirdPartyIdentityUpsert)
	mux.HandleFunc("DELETE /api/v1/console/auth/third-party-identities/{provider}/{subject}", server.handleThirdPartyIdentityDelete)
	mux.HandleFunc("GET /api/v1/console/auth/providers", server.handleThirdPartyAuthProviderList)
	mux.HandleFunc("POST /api/v1/console/auth/providers", server.handleThirdPartyAuthProviderUpsert)
	mux.HandleFunc("GET /api/v1/console/auth/providers/{provider}", server.handleThirdPartyAuthProviderGet)
	mux.HandleFunc("DELETE /api/v1/console/auth/providers/{provider}", server.handleThirdPartyAuthProviderDelete)
	mux.HandleFunc("GET /api/v1/console/products", server.handleProductList)
	mux.HandleFunc("POST /api/v1/console/products", server.handleProductCreate)
	mux.HandleFunc("GET /api/v1/console/secrets", server.handleManagedSecretList)
	mux.HandleFunc("GET /api/v1/console/secrets/{namespace}/{name}", server.handleManagedSecretGet)
	mux.HandleFunc("POST /api/v1/console/secrets", server.handleManagedSecretCreate)
	mux.HandleFunc("POST /api/v1/console/secrets/{namespace}/{name}/rotate", server.handleManagedSecretRotate)
	mux.HandleFunc("POST /api/v1/console/secrets/{namespace}/{name}/disable", server.handleManagedSecretDisable)
	mux.HandleFunc("POST /api/v1/console/secrets/{namespace}/{name}/revoke", server.handleManagedSecretRevoke)
	mux.HandleFunc("POST /api/v1/console/secrets/materialize-all", server.handleMaterializeAll)
	mux.HandleFunc("POST /api/v1/console/secrets/{namespace}/{name}/materialize", server.handleMaterializeOne)
	mux.HandleFunc("GET /api/v1/console/reconciler/status", server.handleReconcilerStatus)
	mux.HandleFunc("GET /api/v1/console/repository-bindings", server.handleRepositoryBindingList)
	mux.HandleFunc("POST /api/v1/console/repository-bindings", server.handleRepositoryBindingCreate)
	mux.HandleFunc("GET /api/v1/console/guardian-policies", server.handleGuardianPolicyList)
	mux.HandleFunc("POST /api/v1/console/guardian-policies", server.handleGuardianPolicyCreate)
	mux.HandleFunc("GET /api/v1/console/guardian-approvals", server.handleGuardianApprovalList)
	mux.HandleFunc("POST /api/v1/console/guardian-approvals", server.handleGuardianApprovalCreate)
	mux.HandleFunc("POST /api/v1/console/guardian-approvals/{namespace}/{name}/decision", server.handleGuardianApprovalDecision)
	mux.HandleFunc("GET /api/v1/console/guardian-memories", server.handleGuardianMemoryList)
	mux.HandleFunc("GET /api/v1/console/remediation-bundles", server.handleRemediationBundleList)
	mux.HandleFunc("POST /api/v1/console/remediation-bundles", server.handleRemediationBundleCreate)
	mux.HandleFunc("POST /api/v1/console/guardian-memories/review", server.handleGuardianMemoryReview)
	mux.HandleFunc("GET /api/v1/console/remediation-contracts", server.handleRemediationContractList)
	mux.HandleFunc("POST /api/v1/console/remediation-contracts", server.handleRemediationContractCreate)
	mux.HandleFunc("GET /api/v1/console/surfaces", server.handleSurfaceList)
	mux.HandleFunc("POST /api/v1/console/surfaces", server.handleSurfaceCreate)
	mux.HandleFunc("GET /api/v1/console/workflows", server.handleWorkflowList)
	mux.HandleFunc("POST /api/v1/console/workflows", server.handleWorkflowCreate)
	mux.HandleFunc("POST /api/v1/console/workflow-runs", server.handleWorkflowRun)
	mux.HandleFunc("POST /api/v1/console/provision/aws", server.handleProvisionAWS)

	return server.withLogging(mux), nil
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

// Server exposes the synchronous HTTP surface of yggdrasil-core.
type Server struct {
	serviceName string
	db          *sql.DB
	rabbitmq    *amqp.Connection
	logger      *zap.Logger
	reconciler  *reconciler.Engine
	provisioner *provisioner.AWSProvisioner
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

	if strings.TrimSpace(os.Getenv("BROKER_URL")) != "" {
		if s.rabbitmq == nil || s.rabbitmq.IsClosed() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "not_ready",
				"reason": "rabbitmq_unavailable",
			})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ready",
	})
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
	collaborators, err := repository.ListCollaborators(r.Context(), s.db, model.ListCollaboratorsRequest{
		Status: queryString(r, "status"),
	})
	if err != nil {
		writeMappedError(w, err)
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

	collaborator, err := repository.CreateCollaborator(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"collaborator": collaborator})
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

	team, err := repository.CreateTeam(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"team": team})
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

	writeJSON(w, http.StatusOK, membershipsResponse{Memberships: memberships})
}

func (s *Server) handleTeamMembershipUpsert(w http.ResponseWriter, r *http.Request) {
	var req model.UpsertTeamMembershipRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	membership, err := repository.UpsertTeamMembership(r.Context(), s.db, req)
	if err != nil {
		writeMappedError(w, err)
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

	if status != model.GuardianApprovalStatusApproved {
		if err := messagecontroller.UpdateHeimdallApprovalMemoryStatus(r.Context(), s.db, spec, status, req.Comment); err != nil {
			writeMappedError(w, err)
			return
		}
		if err := messagecontroller.UpdateHeimdallApprovalBundleStatus(r.Context(), s.db, spec, status); err != nil {
			writeMappedError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"manifest": updatedManifest})
		return
	}

	if err := messagecontroller.UpdateHeimdallApprovalBundleStatus(r.Context(), s.db, spec, status); err != nil {
		writeMappedError(w, err)
		return
	}

	if err := messagecontroller.ExecuteHeimdallApprovedAction(r.Context(), s.rabbitmq, s.db, spec); err != nil {
		writeMappedError(w, err)
		return
	}

	spec.Status = model.GuardianApprovalStatusExecuted
	spec.Metadata["executed_at"] = time.Now().UTC().Format(time.RFC3339)

	executedSpecRaw, err := json.Marshal(spec)
	if err != nil {
		writeMappedError(w, fmt.Errorf("marshal guardian approval execution spec: %w", err))
		return
	}

	executedManifest, err := createManifestVersion(r.Context(), s.db, model.ManifestDocument{
		APIVersion: updatedManifest.APIVersion,
		Kind:       updatedManifest.Kind,
		Metadata:   guardianApprovalMetadataInput(updatedManifest, spec.Status),
		Spec:       executedSpecRaw,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"manifest":          executedManifest,
		"approved_manifest": updatedManifest,
	})
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

	manifestRecord, err := createManifestVersion(r.Context(), s.db, doc)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	s.materializeAfterManifestWrite(manifestRecord)

	writeJSON(w, http.StatusCreated, map[string]any{"manifest": manifestRecord})
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

func writeMappedError(w http.ResponseWriter, err error) {
	status := httpStatusFromError(err)
	writeJSON(w, status, errorResponse{Error: strings.TrimSpace(err.Error())})
}

func httpStatusFromError(err error) int {
	switch {
	case err == nil:
		return http.StatusOK
	case errors.Is(err, messagecontroller.ErrAdapterTransportUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, errWorkflowRunUnauthorized):
		return http.StatusUnauthorized
	case errors.Is(err, repository.ErrAuthInvalidCredentials),
		errors.Is(err, repository.ErrAuthSessionNotFound),
		errors.Is(err, repository.ErrAuthSessionExpired),
		errors.Is(err, repository.ErrPasswordCredentialNotFound):
		return http.StatusUnauthorized
	case errors.Is(err, repository.ErrThirdPartyIdentityConflict):
		return http.StatusConflict
	case errors.Is(err, repository.ErrManifestNotFound),
		errors.Is(err, repository.ErrCollaboratorNotFound),
		errors.Is(err, repository.ErrTeamNotFound),
		errors.Is(err, repository.ErrManagedSecretNotFound),
		errors.Is(err, repository.ErrThirdPartyIdentityNotFound),
		errors.Is(err, repository.ErrThirdPartyAuthProviderNotFound):
		return http.StatusNotFound
	}

	message := strings.ToLower(strings.TrimSpace(err.Error()))
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
