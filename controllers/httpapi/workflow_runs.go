package httpapi

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

var errWorkflowRunUnauthorized = errors.New("workflow run unauthorized")
var errWorkflowAuthorizationDenied = errors.New("workflow dispatch authorization denied")

const legacyWorkflowRunSubjectID = "legacy-workflow-run-token"

type workflowRunActor struct {
	CollaboratorID string
	Subject        model.RBACSubject
}

type workflowRunScopedToken struct {
	Token   string            `json:"token"`
	Subject model.RBACSubject `json:"subject"`
}

// handleWorkflowRun routes between sync and async execution. The default
// is sync (HTTP 201 with the full RunWorkflowResponse) for back-compat.
// `?async=true` returns 202 + {run_id, status} immediately and persists
// the run for polling via GET /api/v1/workflow-runs/{id}. Async is the
// only viable path for runs that exceed the ingress 60s timeout (SES
// multi-step bootstrap, large infra provisioning, etc.).
//
// Resolution precedence for the dispatch mode:
//
//  1. Explicit per-request opt-in/out via `?async=true|false|1|0|yes|no`
//     or the `X-Yggdrasil-Workflow-Mode: async|sync` header. Ops escape
//     hatch — always wins regardless of the manifest value.
//  2. The workflow manifest's `spec.dispatch_mode` field. Workflows whose
//     observable step budgets exceed the ingress timeout declare
//     `dispatch_mode: async` to keep callers from hitting 502s.
//  3. Sync (the historical default) when neither (1) nor (2) is set.
func (s *Server) handleWorkflowRun(w http.ResponseWriter, r *http.Request) {
	actor, err := authenticateWorkflowRunRequest(r)
	if err != nil {
		writeMappedError(w, err)
		return
	}

	if !s.isBrokerAvailable() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error":  "workflow_dispatch_unavailable",
			"detail": "control-plane is broker-degraded; workflow dispatch is temporarily disabled",
		})
		return
	}

	var req model.RunWorkflowRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if err := s.authorizeWorkflowDispatch(r.Context(), req, actor); err != nil {
		if errors.Is(err, errWorkflowAuthorizationDenied) {
			writeProblemJSON(w, http.StatusForbidden, "workflow.authorization_denied", err.Error())
		} else {
			writeMappedError(w, err)
		}
		return
	}

	if s.resolveWorkflowRunAsync(r, req) {
		s.dispatchAsyncWorkflowRun(w, r, req)
		return
	}

	response, err := messagecontroller.RunWorkflow(r.Context(), s.rabbitmq, s.db, req)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	// Emit workflow.run.completed even when the run aborted on a failed
	// step — the AMQP-path handler did this from day one, but the HTTP
	// path silently skipped it, which is why event-triggered workflows
	// (alert-on-reconcile-failure) never fired for runs dispatched via
	// curl + console UI.
	messagecontroller.EmitWorkflowRunCompletedEvent(r.Context(), s.db, s.logger, response)
	writeJSON(w, http.StatusCreated, response)
}

// dispatchAsyncWorkflowRun persists a pending row, returns 202 with the
// run_id, and kicks off a background goroutine that runs the workflow.
// On completion (success or failure) the goroutine updates the same row
// so a subsequent GET can return the full RunWorkflowResponse.
func (s *Server) dispatchAsyncWorkflowRun(w http.ResponseWriter, r *http.Request, req model.RunWorkflowRequest) {
	if !s.isBrokerAvailable() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error":  "workflow_dispatch_unavailable",
			"detail": "control-plane is broker-degraded; workflow dispatch is temporarily disabled",
		})
		return
	}

	runID := uuid.New()
	if err := repository.InsertWorkflowRun(r.Context(), s.db, runID, req.Workflow, req.Inputs, req.Metadata); err != nil {
		writeMappedError(w, err)
		return
	}

	go func(req model.RunWorkflowRequest, runID uuid.UUID) {
		bg, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		startedAt := time.Now().UTC()
		_ = repository.MarkWorkflowRunRunning(bg, s.db, runID, startedAt)

		response, runErr := messagecontroller.RunWorkflow(bg, s.rabbitmq, s.db, req)

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
			// Emit workflow.run.completed for async HTTP-dispatched runs so
			// downstream event-triggered workflows fire (parity with AMQP).
			// Only emit when RunWorkflow returned a typed response — runErr
			// already captures the precondition-failed case.
			messagecontroller.EmitWorkflowRunCompletedEvent(bg, s.db, s.logger, response)
		}
		_ = repository.FinalizeWorkflowRun(bg, s.db, runID, status, resultPayload, errMsg, time.Now().UTC())
	}(req, runID)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"run_id":   runID.String(),
		"status":   "pending",
		"workflow": req.Workflow,
	})
}

// handleWorkflowRunGet exposes the persisted record for a previous async
// run. Returns 404 when the id is unknown so pollers can distinguish a
// transient error from a missing run.
func (s *Server) handleWorkflowRunGet(w http.ResponseWriter, r *http.Request) {
	if err := authorizeWorkflowRunRequest(r); err != nil {
		writeMappedError(w, err)
		return
	}

	idStr := r.PathValue("run_id")
	id, err := uuid.Parse(strings.TrimSpace(idStr))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid run_id"})
		return
	}

	rec, err := repository.GetWorkflowRun(r.Context(), s.db, id)
	if errors.Is(err, repository.ErrWorkflowRunNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "workflow run not found"})
		return
	}
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

// isAsyncWorkflowRunRequest preserves the historical boolean check used by
// the unit tests in workflow_runs_async_test.go. It returns true when an
// explicit per-request opt-in (query `?async=true|1|yes` or header
// `X-Yggdrasil-Workflow-Mode: async`) is present. It does NOT consult the
// manifest's `spec.dispatch_mode` — handleWorkflowRun layers that lookup on
// top via resolveWorkflowRunAsync.
func isAsyncWorkflowRunRequest(r *http.Request) bool {
	mode, ok := explicitWorkflowRunDispatchMode(r)
	return ok && mode == "async"
}

// explicitWorkflowRunDispatchMode returns the dispatch mode requested by the
// caller via `?async=…` query or `X-Yggdrasil-Workflow-Mode` header. The
// second return value is false when the caller did not opt into a mode
// explicitly, so the workflow manifest's spec.dispatch_mode can take over.
//
// Per-request signals always win over the manifest — that is the ops escape
// hatch that lets `?async=false` force sync even on a workflow manifest
// flagged async, and `?async=true` flip a sync-default workflow to async.
func explicitWorkflowRunDispatchMode(r *http.Request) (string, bool) {
	if v := strings.TrimSpace(r.URL.Query().Get("async")); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes":
			return "async", true
		case "0", "false", "no":
			return "sync", true
		}
	}
	if v := strings.TrimSpace(r.Header.Get("X-Yggdrasil-Workflow-Mode")); v != "" {
		switch strings.ToLower(v) {
		case "async":
			return "async", true
		case "sync":
			return "sync", true
		}
	}
	return "", false
}

// resolveWorkflowRunAsync layers the manifest-declared `spec.dispatch_mode`
// on top of the per-request opt-in/out. When the request is explicit the
// manifest is not consulted (and any lookup failure is suppressed so a
// non-existent workflow still reaches the message-controller layer which
// owns the canonical "not found" error code).
//
// Lookup failures while resolving the manifest fall back to sync — the same
// behaviour callers got before this layer existed. The downstream
// `messagecontroller.RunWorkflow` resolves the same selector and emits the
// authoritative error code (`not_found`, `bad_request`, etc.), so we do not
// short-circuit here on a lookup error.
func (s *Server) resolveWorkflowRunAsync(r *http.Request, req model.RunWorkflowRequest) bool {
	if mode, ok := explicitWorkflowRunDispatchMode(r); ok {
		return mode == "async"
	}

	spec, err := s.lookupWorkflowSpec(r.Context(), req)
	if err != nil {
		return false
	}
	return manifestengine.NormalizeWorkflowDispatchMode(spec) == manifestengine.WorkflowDispatchModeAsync
}

// lookupWorkflowSpec resolves the persisted workflow manifest for a run
// request so handleWorkflowRun can read its declared dispatch_mode. It
// intentionally mirrors the resolution rules used by messagecontroller.
// RunWorkflow so the mode decision matches the manifest the runner will
// actually execute (same manifest_id / namespace / name / version path).
func (s *Server) lookupWorkflowSpec(ctx context.Context, req model.RunWorkflowRequest) (model.WorkflowManifestSpec, error) {
	_, spec, err := s.lookupWorkflowManifestSpec(ctx, req)
	return spec, err
}

func (s *Server) lookupWorkflowManifestSpec(ctx context.Context, req model.RunWorkflowRequest) (model.Manifest, model.WorkflowManifestSpec, error) {
	selector := req.Workflow

	if id := strings.TrimSpace(selector.ManifestID); id != "" {
		parsed, err := uuid.Parse(id)
		if err != nil {
			return model.Manifest{}, model.WorkflowManifestSpec{}, err
		}
		record, err := repository.GetManifestByID(ctx, s.db, parsed)
		if err != nil {
			return model.Manifest{}, model.WorkflowManifestSpec{}, err
		}
		spec, err := manifestengine.ParseWorkflowSpec(record.Spec)
		return record, spec, err
	}

	name := strings.TrimSpace(selector.Name)
	if name == "" {
		return model.Manifest{}, model.WorkflowManifestSpec{}, errors.New("workflow name is required when manifest_id is not provided")
	}
	namespace := strings.TrimSpace(selector.Namespace)
	if namespace == "" {
		namespace = "global"
	}

	record, err := repository.ResolveManifest(ctx, s.db, "workflow", namespace, name, selector.Version, true)
	if err != nil {
		return model.Manifest{}, model.WorkflowManifestSpec{}, err
	}
	spec, err := manifestengine.ParseWorkflowSpec(record.Spec)
	return record, spec, err
}

func authorizeWorkflowRunRequest(r *http.Request) error {
	_, err := authenticateWorkflowRunRequest(r)
	return err
}

func authenticateWorkflowRunRequest(r *http.Request) (workflowRunActor, error) {

	// Console session path: the request reached this handler only because
	// requireAuthenticatedConsoleAPIs validated the cookie AND
	// requireOpsPermissionFunc(permManageWorkflows, …) confirmed the
	// caller has permission to dispatch workflows. Trust the claims that
	// the middleware attached — same pattern as manifestWriteAuthorized.
	// Without this, every session-cookie caller (the entire console UI
	// triggerWorkflow path) lands here with no header and gets a 401,
	// even though they're already gated upstream.
	if claims, ok := claimsFromContext(r.Context()); ok {
		collaboratorID, _ := claims["collaborator_id"].(string)
		if strings.TrimSpace(collaboratorID) == "" {
			return workflowRunActor{}, errWorkflowRunUnauthorized
		}
		return workflowRunActor{CollaboratorID: strings.TrimSpace(collaboratorID)}, nil
	}

	candidates := []string{
		strings.TrimSpace(r.Header.Get("X-Yggdrasil-Workflow-Token")),
		bearerToken(r.Header.Get("Authorization")),
	}
	scopedTokens, err := workflowRunScopedTokensFromEnv()
	if err != nil {
		return workflowRunActor{}, err
	}
	for _, candidate := range candidates {
		for _, scoped := range scopedTokens {
			if workflowRunScopedTokenPath(r.URL.Path) && constantTimeTokenEqual(candidate, scoped.Token) {
				return workflowRunActor{Subject: scoped.Subject}, nil
			}
		}
	}

	expected := strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_TOKEN"))
	for _, candidate := range candidates {
		if constantTimeTokenEqual(candidate, expected) {
			return workflowRunActor{Subject: legacyWorkflowRunSubject()}, nil
		}
	}

	if expected == "" && len(scopedTokens) == 0 {
		// Local development convention: no configured credential keeps the
		// endpoint open. Protected workflows still reject this anonymous actor.
		return workflowRunActor{}, nil
	}
	return workflowRunActor{}, errWorkflowRunUnauthorized
}

func workflowRunScopedTokenPath(path string) bool {
	return path == "/api/v1/workflow-runs" ||
		strings.HasPrefix(path, "/api/v1/workflow-runs/") ||
		path == "/api/v1/console/workflow-runs" ||
		strings.HasPrefix(path, "/api/v1/console/workflow-runs/")
}

func workflowRunScopedTokensFromEnv() ([]workflowRunScopedToken, error) {
	raw := strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON"))
	if raw == "" {
		return nil, nil
	}
	var tokens []workflowRunScopedToken
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&tokens); err != nil {
		return nil, fmt.Errorf("parse YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON contains trailing JSON")
	}
	if len(tokens) == 0 {
		return nil, errors.New("YGGDRASIL_WORKFLOW_RUN_SCOPED_TOKENS_JSON must contain at least one token")
	}
	seen := map[string]struct{}{}
	for i := range tokens {
		tokens[i].Token = strings.TrimSpace(tokens[i].Token)
		tokens[i].Subject.Type = strings.ToLower(strings.TrimSpace(tokens[i].Subject.Type))
		tokens[i].Subject.ID = strings.TrimSpace(tokens[i].Subject.ID)
		if tokens[i].Token == "" || tokens[i].Subject.Type == "" || tokens[i].Subject.ID == "" {
			return nil, fmt.Errorf("scoped workflow token %d requires token, subject.type and subject.id", i)
		}
		if _, duplicate := seen[tokens[i].Token]; duplicate {
			return nil, fmt.Errorf("scoped workflow token %d duplicates an earlier credential", i)
		}
		seen[tokens[i].Token] = struct{}{}
	}
	return tokens, nil
}

func legacyWorkflowRunSubject() model.RBACSubject {
	subjectType := strings.ToLower(strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_SUBJECT_TYPE")))
	if subjectType == "" {
		subjectType = "service"
	}
	subjectID := strings.TrimSpace(os.Getenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_SUBJECT_ID"))
	if subjectID == "" {
		subjectID = legacyWorkflowRunSubjectID
	}
	return model.RBACSubject{Type: subjectType, ID: subjectID}
}

func constantTimeTokenEqual(candidate, expected string) bool {
	if candidate == "" || expected == "" || len(candidate) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1
}

func (s *Server) authorizeWorkflowDispatch(ctx context.Context, req model.RunWorkflowRequest, actor workflowRunActor) error {
	workflowManifest, workflowSpec, err := s.lookupWorkflowManifestSpec(ctx, req)
	if err != nil {
		return err
	}
	if workflowSpec.Authorization == nil {
		return nil
	}

	authz := workflowSpec.Authorization
	rbacManifest, err := resolveWorkflowAuthorizationManifest(ctx, s.db, "rbac", authz.RBAC)
	if err != nil {
		return err
	}
	rbacSpec, err := manifestengine.ParseRBACSpec(rbacManifest.Spec)
	if err != nil {
		return err
	}

	var policyManifest model.Manifest
	var policySpec *model.PolicyManifestSpec
	if authz.Policy != nil {
		policyManifest, err = resolveWorkflowAuthorizationManifest(ctx, s.db, "policy", *authz.Policy)
		if err != nil {
			return err
		}
		parsed, err := manifestengine.ParsePolicySpec(policyManifest.Spec)
		if err != nil {
			return err
		}
		policySpec = &parsed
	}

	subjects := make([]model.RBACSubject, 0, 4)
	input := cloneWorkflowAuthorizationInput(manifestengine.MergeWorkflowInputs(workflowSpec, req.Inputs))
	evaluationReq := model.EvaluateAuthorizationRequest{
		RBAC:     authz.RBAC,
		Policy:   authz.Policy,
		Resource: "workflow:" + workflowManifest.Metadata.Namespace + ":" + workflowManifest.Metadata.Name,
		Action:   "run",
		Input:    input,
	}

	var collaboratorRef *model.CollaboratorReference
	var teamRefs []model.TeamReference
	if actor.CollaboratorID != "" {
		collaborator, teams, resolved, err := repository.ResolveAuthorizationSubjects(ctx, s.db, actor.CollaboratorID)
		if err != nil {
			return err
		}
		subjects = append(subjects, resolved...)
		evaluationReq.CollaboratorID = actor.CollaboratorID
		input = workflowAuthorizationContextInput(input, collaborator, teams)
		evaluationReq.Input = input
		collaboratorRef = &model.CollaboratorReference{ID: collaborator.ID, Slug: collaborator.Slug, Status: collaborator.Status}
		teamRefs = workflowAuthorizationTeamReferences(teams)
	} else if actor.Subject.Type != "" && actor.Subject.ID != "" {
		subjects = append(subjects, actor.Subject)
		evaluationReq.Subject = actor.Subject
	} else {
		return fmt.Errorf("%w: protected workflow requires an authenticated subject", errWorkflowAuthorizationDenied)
	}

	response, err := manifestengine.EvaluateAuthorizationSubjects(rbacSpec, policySpec, subjects, evaluationReq.Resource, evaluationReq.Action, input)
	if err != nil {
		return err
	}
	response.Collaborator = collaboratorRef
	response.Teams = teamRefs
	response.RBAC.Manifest = workflowManifestReference(rbacManifest)
	if response.Policy != nil {
		response.Policy.Manifest = workflowManifestReference(policyManifest)
	}
	messagecontroller.EmitAuthorizationEvaluatedEvent(ctx, s.db, s.logger, evaluationReq, response, rbacManifest, policyManifest)

	if s.logger != nil {
		s.logger.Info("workflow dispatch authorization evaluated",
			zap.String("resource", evaluationReq.Resource),
			zap.String("decision", string(response.Decision)),
			zap.Strings("matched_roles", response.RBAC.MatchedRoles),
		)
	}
	if !response.Allowed {
		return fmt.Errorf("%w for %s", errWorkflowAuthorizationDenied, evaluationReq.Resource)
	}
	return nil
}

func resolveWorkflowAuthorizationManifest(ctx context.Context, db *sql.DB, kind string, selector model.ManifestSelector) (model.Manifest, error) {
	if id := strings.TrimSpace(selector.ManifestID); id != "" {
		parsed, err := uuid.Parse(id)
		if err != nil {
			return model.Manifest{}, fmt.Errorf("invalid %s authorization manifest id", kind)
		}
		return repository.GetManifestByID(ctx, db, parsed)
	}
	name := strings.TrimSpace(selector.Name)
	if name == "" {
		return model.Manifest{}, fmt.Errorf("%s authorization manifest name is required", kind)
	}
	namespace := strings.TrimSpace(selector.Namespace)
	if namespace == "" {
		namespace = "global"
	}
	return repository.ResolveManifest(ctx, db, kind, namespace, name, selector.Version, true)
}

func cloneWorkflowAuthorizationInput(input map[string]any) map[string]any {
	out := make(map[string]any, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func workflowAuthorizationContextInput(input map[string]any, collaborator model.Collaborator, teams []model.Team) map[string]any {
	input["collaborator"] = map[string]any{
		"id": collaborator.ID.String(), "slug": collaborator.Slug, "status": collaborator.Status,
		"display_name": collaborator.DisplayName, "primary_email": collaborator.PrimaryEmail,
		"personal_data": collaborator.PersonalData, "employment_data": collaborator.EmploymentData,
		"third_party_identities": collaborator.ThirdPartyIdentities, "traits": collaborator.Traits, "metadata": collaborator.Metadata,
	}
	items := make([]map[string]any, 0, len(teams))
	for _, team := range teams {
		items = append(items, map[string]any{
			"id": team.ID.String(), "slug": team.Slug, "name": team.Name, "type": team.Type,
			"status": team.Status, "owners": team.Owners, "traits": team.Traits, "metadata": team.Metadata,
		})
	}
	input["teams"] = items
	return input
}

func workflowAuthorizationTeamReferences(teams []model.Team) []model.TeamReference {
	refs := make([]model.TeamReference, 0, len(teams))
	for _, team := range teams {
		refs = append(refs, model.TeamReference{ID: team.ID, Slug: team.Slug, Name: team.Name, Type: team.Type})
	}
	return refs
}

func workflowManifestReference(record model.Manifest) model.ManifestReference {
	return model.ManifestReference{ID: record.ID, Kind: record.Kind, Namespace: record.Metadata.Namespace, Name: record.Metadata.Name, Version: record.Version}
}

// manifestWriteAuthorized centralises the auth gate for manifest writes
// (POST /api/v1/manifests, DELETE /api/v1/manifests/{id}, and every
// kind-specific wrapper that funnels through handleManifestCreate).
//
// Accepts:
//   - YGGDRASIL_WORKFLOW_RUN_TOKEN (workflow/admin caller) via the
//     X-Yggdrasil-Workflow-Token header or Authorization: Bearer.
//   - A valid console session whose claims are already attached to the
//     context by the requiresAuthenticatedConsoleAPIs middleware.
//   - When YGGDRASIL_WORKFLOW_RUN_TOKEN is unset (dev/test), it stays
//     open — same convention as authorizeWorkflowRunRequest. Production
//     deploys MUST set the env var (verified by the security audit
//     reference_yggdrasil_dakasa_me_deep_audit_2026_05_27.md).
//
// Returns true when the caller is authorized; the handler should refuse
// the request when this returns false.
func (s *Server) manifestWriteAuthorized(r *http.Request) bool {
	// Console session path: middleware already validated the cookie and
	// attached claims. Trust it.
	if _, ok := claimsFromContext(r.Context()); ok {
		return true
	}
	// Token path (shared env var) — also stays open when the env var is
	// unset to preserve the dev/test contract.
	return authorizeWorkflowRunRequest(r) == nil
}

func bearerToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !strings.HasPrefix(strings.ToLower(value), "bearer ") {
		return ""
	}
	return strings.TrimSpace(value[len("Bearer "):])
}
