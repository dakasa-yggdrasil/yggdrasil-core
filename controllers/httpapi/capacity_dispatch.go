package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/workflowdispatchlock"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const CapacityDispatchEnabledEnv = "YGGDRASIL_CAPACITY_DISPATCH_ENABLED"

var errCapacityDispatch = errors.New("protected capacity dispatch unresolved")

type capacityDispatchError struct{ cause error }

func (e *capacityDispatchError) Error() string              { return errCapacityDispatch.Error() }
func (e *capacityDispatchError) Unwrap() error              { return e.cause }
func (e *capacityDispatchError) GoString() string           { return e.Error() }
func (e *capacityDispatchError) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.Error()) }
func dispatchOpaque(err error) error {
	if err == nil {
		return nil
	}
	return &capacityDispatchError{cause: err}
}

func CapacityDispatchProcessEnabled() (bool, error) {
	switch os.Getenv(CapacityDispatchEnabledEnv) {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, errCapacityDispatch
	}
}

func dispatchContext(ctx context.Context) error {
	if ctx == nil {
		return errCapacityDispatch
	}
	err := errors.Join(ctx.Err(), context.Cause(ctx))
	if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
		err = errors.Join(err, context.DeadlineExceeded)
	}
	return err
}

// This service is registered in existing app resources, never in an HTTP/RPC
// route. Only the persisted operator binding supplies delegation. Its worker
// and scheduler use the same service as the remote native qualification.
type CapacityDispatchService struct{ server *Server }

func WithCapacityDispatchServiceReceiver(receive func(*CapacityDispatchService)) ServerOption {
	return func(s *Server) {
		if receive != nil {
			receive(&CapacityDispatchService{server: s})
		}
	}
}

type CapacityDispatchPrepared struct {
	service  *CapacityDispatchService
	envelope repository.CapacityDispatchEnvelope
}

func (p *CapacityDispatchPrepared) Enqueue(ctx context.Context, tx *sql.Tx) (repository.CapacityDispatchJob, bool, error) {
	if p == nil || p.service == nil || tx == nil {
		return repository.CapacityDispatchJob{}, false, errCapacityDispatch
	}
	if _, _, err := p.service.authorizeEnvelope(ctx, p.envelope); err != nil {
		return repository.CapacityDispatchJob{}, false, err
	}
	job, dedup, err := repository.EnqueueCapacityDispatch(ctx, tx, p.envelope)
	if err == nil {
		_, _, err = p.service.authorizeEnvelope(ctx, p.envelope)
	}
	return job, dedup, dispatchOpaque(errors.Join(err, dispatchContext(ctx)))
}

func dispatchPin(m model.Manifest) repository.CapacityDispatchManifestPin {
	return repository.CapacityDispatchManifestPin{ID: m.ID, Namespace: m.Metadata.Namespace, Name: m.Metadata.Name, Version: m.Version, Checksum: m.Checksum}
}

func dispatchSHA(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func dispatchPrincipalSHA(p *workflowMachinePrincipal) (string, error) {
	refs := make([]machineWorkflowRef, 0, len(p.AllowedWorkflows))
	for ref := range p.AllowedWorkflows {
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].Namespace == refs[j].Namespace {
			return refs[i].Name < refs[j].Name
		}
		return refs[i].Namespace < refs[j].Namespace
	})
	// Only the fingerprint is persisted, including rotation/expiry. No bearer
	// or credential digest becomes job/run metadata or a public result.
	return dispatchSHA(workflowMachinePrincipalConfig{PrincipalID: p.PrincipalID, Status: p.Status, ExpiresAt: p.ExpiresAt, RotationID: p.RotationID, RotatedAt: p.RotatedAt, TokenSHA256: hex.EncodeToString(p.TokenSHA256[:]), AllowedWorkflows: refs})
}

func (s *CapacityDispatchService) principal(id string) (*workflowMachinePrincipal, error) {
	if s == nil || s.server == nil {
		return nil, errCapacityDispatch
	}
	cfg := s.server.workflowRunAuthConfig()
	if cfg == nil || cfg.err != nil {
		return nil, errCapacityDispatch
	}
	for index := range cfg.principals {
		p := &cfg.principals[index]
		if p.PrincipalID == id && p.Status == "active" && time.Now().Before(p.ExpiresAt) {
			return p, nil
		}
	}
	return nil, errCapacityDispatch
}

// Only one current configured operator policy may own a scheduled workflow.
// A paused/deleted latest binding refuses instead of becoming legacy dispatch.
// The bounded original catalog read precedes private hydration.
func (s *CapacityDispatchService) controllerPolicy(ctx context.Context, wf model.Manifest) (model.Manifest, model.CapacityPolicySpec, bool, error) {
	var empty model.Manifest
	var spec model.CapacityPolicySpec
	if s == nil || s.server == nil || dispatchContext(ctx) != nil {
		return empty, spec, false, errCapacityDispatch
	}
	rows, err := s.server.db.QueryContext(ctx, `WITH current_policies AS (SELECT DISTINCT ON(namespace,name) id,spec FROM public.manifests WHERE kind='capacity_policy' ORDER BY namespace,name,version DESC,id) SELECT id FROM current_policies WHERE spec->'controller_binding' IS NOT NULL AND spec->'controller_binding' <> 'null'::jsonb AND spec->'workflow'->>'namespace'=$1 AND spec->'workflow'->>'name'=$2 ORDER BY id LIMIT 65`, wf.Metadata.Namespace, wf.Metadata.Name)
	if err != nil {
		return empty, spec, false, dispatchOpaque(err)
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	joined := errors.Join(err, rows.Err(), rows.Close(), dispatchContext(ctx))
	if joined != nil || len(ids) > 1 {
		return empty, spec, len(ids) != 0, dispatchOpaque(errors.Join(errCapacityDispatch, joined))
	}
	if len(ids) == 0 {
		return empty, spec, false, nil
	}
	policy, err := repository.GetManifestByID(ctx, s.server.db, ids[0])
	if err == nil {
		spec, err = manifestengine.ParseCapacityPolicySpec(policy.Spec)
	}
	if err != nil || !policy.Metadata.Active || policy.Kind != "capacity_policy" || manifestengine.ValidateCapacityPolicySpec(spec) != nil || spec.ControllerBinding == nil {
		return empty, spec, true, errCapacityDispatch
	}
	return policy, spec, true, nil
}

// CapacityScheduleGraphRequiresOwner classifies protected cron graphs even
// when operator delegation has been removed. It grants no authorization or
// capacity evidence; only the original service can admit a current binding.
func CapacityScheduleGraphRequiresOwner(spec model.WorkflowManifestSpec) bool {
	for _, step := range spec.Steps {
		if strings.ToLower(strings.TrimSpace(step.Use.Kind)) == "yggdrasil" && strings.HasPrefix(manifestengine.NormalizeWorkflowStepOperation(step), "capacity.") {
			return true
		}
	}
	return false
}

func dispatchWorkflowGraph(spec model.WorkflowManifestSpec, policy model.Manifest) error {
	if spec.Authorization == nil || spec.Trigger.Mode != "schedule" || spec.Trigger.Enabled == nil || !*spec.Trigger.Enabled || spec.Trigger.Schedule == nil || len(spec.Steps) != 1 {
		return errCapacityDispatch
	}
	step := spec.Steps[0]
	if step.Use.Kind != "yggdrasil" || step.Use.Operation != "capacity.execute_bound" || step.Use.InstanceRef != nil || step.Use.ProviderRef != nil || step.Use.Family != "" || step.Use.Capability != "" || step.Condition != "" || step.ForEach != nil || len(step.DependsOn) != 0 || step.Retry.MaxAttempts > 1 || step.Retry.BackoffSeconds != 0 || len(step.With) != 1 {
		return errCapacityDispatch
	}
	value := step.With["policy"]
	if text, ok := value.(string); ok {
		if strings.TrimSpace(text) == "{{ inputs.policy }}" || strings.TrimSpace(text) == "{{inputs.policy}}" {
			return nil
		}
	}
	raw, err := json.Marshal(value)
	var ref struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
	}
	if err != nil || capacity.DecodeBusinessJSON(raw, &ref) != nil || ref.Namespace != policy.Metadata.Namespace || ref.Name != policy.Metadata.Name {
		return errCapacityDispatch
	}
	return nil
}

// nil preserves unrelated scheduler behavior only for non-capacity graphs.
// A capacity graph without current operator delegation refuses before fallback.
func (s *CapacityDispatchService) PrepareScheduledTick(parent context.Context, workflowID uuid.UUID, tick time.Time) (*CapacityDispatchPrepared, error) {
	if s == nil || s.server == nil || workflowID == uuid.Nil || tick.IsZero() || dispatchContext(parent) != nil {
		return nil, dispatchOpaque(errors.Join(errCapacityDispatch, dispatchContext(parent)))
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	wf, err := repository.GetManifestByID(ctx, s.server.db, workflowID)
	if err != nil || wf.Kind != "workflow" || !wf.Metadata.Active {
		return nil, dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	spec, err := manifestengine.ParseWorkflowSpec(wf.Spec)
	if err != nil {
		return nil, dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	policy, p, found, err := s.controllerPolicy(ctx, wf)
	if err != nil {
		return nil, err
	}
	if !found {
		if CapacityScheduleGraphRequiresOwner(spec) {
			return nil, errCapacityDispatch
		}
		return nil, nil
	}
	enabled, err := CapacityDispatchProcessEnabled()
	if err != nil || !enabled || !p.ExecutionEnabled {
		return nil, errCapacityDispatch
	}
	e := repository.CapacityDispatchEnvelope{Protocol: repository.CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, SourceTick: tick.UTC().Format(time.RFC3339Nano), Policy: dispatchPin(policy), Workflow: dispatchPin(wf), MachinePrincipalID: p.ControllerBinding.MachinePrincipalID}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": policy.Metadata.Namespace, "name": policy.Metadata.Name}}
	e.Metadata = map[string]any{repository.WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "workflow_scheduler", "manifest_id": wf.ID.String(), "scheduled_for": e.SourceTick, "capacity_dispatch_protocol": e.Protocol, "capacity_dispatch_job_id": e.JobID.String()}
	e.BindingSHA256, err = dispatchSHA(p.ControllerBinding)
	principal, principalErr := s.principal(e.MachinePrincipalID)
	if err != nil || principalErr != nil {
		return nil, errCapacityDispatch
	}
	e.PrincipalSHA256, err = dispatchPrincipalSHA(principal)
	if err != nil || dispatchWorkflowGraph(spec, policy) != nil {
		return nil, errCapacityDispatch
	}
	rbac, err := resolveWorkflowAuthorizationManifest(ctx, s.server.db, "rbac", spec.Authorization.RBAC)
	if err != nil || rbac.Kind != "rbac" || !rbac.Metadata.Active {
		return nil, dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	e.RBAC = dispatchPin(rbac)
	if spec.Authorization.Policy != nil {
		authPolicy, err := resolveWorkflowAuthorizationManifest(ctx, s.server.db, "policy", *spec.Authorization.Policy)
		if err != nil || authPolicy.Kind != "policy" || !authPolicy.Metadata.Active {
			return nil, dispatchOpaque(errors.Join(errCapacityDispatch, err))
		}
		pin := dispatchPin(authPolicy)
		e.AuthorizationPolicy = &pin
	}
	_, _, prepared, persisted, err := messagecontroller.PrepareCapacityDispatchWorkflow(ctx, s.server.db, model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: wf.Metadata.Namespace, Name: wf.Metadata.Name}, Inputs: e.Inputs, Metadata: e.Metadata})
	if err != nil {
		return nil, dispatchOpaque(err)
	}
	preparedSHA, _ := dispatchSHA(prepared.Inputs)
	wantedSHA, _ := dispatchSHA(e.Inputs)
	persistedSHA, _ := dispatchSHA(persisted)
	if preparedSHA != wantedSHA || persistedSHA != wantedSHA {
		return nil, errCapacityDispatch
	}
	e.InputsSHA256, e.MetadataSHA256, err = repository.CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		return nil, dispatchOpaque(err)
	}
	if _, _, err = s.authorizeEnvelope(ctx, e); err != nil {
		return nil, err
	}
	if err = dispatchContext(ctx); err != nil {
		return nil, dispatchOpaque(err)
	}
	return &CapacityDispatchPrepared{service: s, envelope: e}, nil
}

func (s *CapacityDispatchService) authorizeEnvelope(ctx context.Context, e repository.CapacityDispatchEnvelope) (model.CapacityPolicySpec, *workflowMachinePrincipal, error) {
	var p model.CapacityPolicySpec
	if s == nil || s.server == nil || dispatchContext(ctx) != nil {
		return p, nil, errCapacityDispatch
	}
	enabled, err := CapacityDispatchProcessEnabled()
	if err != nil || !enabled || e.Protocol != repository.CapacityDispatchProtocol {
		return p, nil, errCapacityDispatch
	}
	policy, err := repository.ResolveManifest(ctx, s.server.db, "capacity_policy", e.Policy.Namespace, e.Policy.Name, nil, true)
	if err != nil || dispatchPin(policy) != e.Policy {
		return p, nil, dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	p, err = manifestengine.ParseCapacityPolicySpec(policy.Spec)
	if err != nil || manifestengine.ValidateCapacityPolicySpec(p) != nil || p.ControllerBinding == nil || !p.ExecutionEnabled || p.ControllerBinding.MachinePrincipalID != e.MachinePrincipalID || p.Environment != e.Environment || p.Domain != e.Domain || p.Dimension != e.Dimension || e.Realm != policy.Metadata.Namespace || p.Workflow.Namespace != e.Workflow.Namespace || p.Workflow.Name != e.Workflow.Name {
		return p, nil, errCapacityDispatch
	}
	bindingSHA, err := dispatchSHA(p.ControllerBinding)
	principal, errPrincipal := s.principal(e.MachinePrincipalID)
	if err != nil || bindingSHA != e.BindingSHA256 || errPrincipal != nil {
		return p, nil, errCapacityDispatch
	}
	principalSHA, err := dispatchPrincipalSHA(principal)
	if err != nil || principalSHA != e.PrincipalSHA256 {
		return p, nil, errCapacityDispatch
	}
	wf, err := repository.ResolveManifest(ctx, s.server.db, "workflow", e.Workflow.Namespace, e.Workflow.Name, nil, true)
	if err != nil || dispatchPin(wf) != e.Workflow {
		return p, nil, dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	spec, err := manifestengine.ParseWorkflowSpec(wf.Spec)
	if err != nil || dispatchWorkflowGraph(spec, policy) != nil {
		return p, nil, errCapacityDispatch
	}
	rbac, err := resolveWorkflowAuthorizationManifest(ctx, s.server.db, "rbac", spec.Authorization.RBAC)
	if err != nil || rbac.Kind != "rbac" || !rbac.Metadata.Active || dispatchPin(rbac) != e.RBAC {
		return p, nil, errCapacityDispatch
	}
	if (spec.Authorization.Policy == nil) != (e.AuthorizationPolicy == nil) {
		return p, nil, errCapacityDispatch
	}
	if spec.Authorization.Policy != nil {
		ap, err := resolveWorkflowAuthorizationManifest(ctx, s.server.db, "policy", *spec.Authorization.Policy)
		if err != nil || ap.Kind != "policy" || !ap.Metadata.Active || dispatchPin(ap) != *e.AuthorizationPolicy {
			return p, nil, errCapacityDispatch
		}
	}
	if err := workflowdispatchlock.CheckEnvironment(wf.Metadata.Namespace, wf.Metadata.Name); err != nil {
		return p, nil, dispatchOpaque(err)
	}
	// Identical subject/allowlist/RBAC/policy evaluation to the machine HTTP
	// dispatch path, obtained from the CURRENT server inventory and operator
	// binding; no caller Auth or alert identity is manufactured as authority.
	req := model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: wf.Metadata.Namespace, Name: wf.Metadata.Name}, Inputs: e.Inputs}
	actor := workflowRunActor{Subject: model.RBACSubject{Type: "service", ID: principal.PrincipalID}, MachinePrincipalID: principal.PrincipalID, MachinePrincipal: principal}
	if err := s.server.authorizeWorkflowDispatch(ctx, req, actor); err != nil {
		return p, nil, dispatchOpaque(err)
	}
	if err := s.authorizeDemandOrigin(ctx, e, p); err != nil {
		return p, nil, err
	}
	if err := dispatchContext(ctx); err != nil || !time.Now().Before(principal.ExpiresAt) {
		return p, nil, dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	return p, principal, nil
}

// RunOne owns one actual original workflow call. It only claims a new-v1 job
// whose possible-start marker is absent. An error after Start is never replay.
func (s *CapacityDispatchService) RunOne(parent context.Context, realm, environment string) (ran bool, returnedErr error) {
	enabled, err := CapacityDispatchProcessEnabled()
	if err != nil || !enabled || s == nil || s.server == nil || dispatchContext(parent) != nil || !s.server.isBrokerAvailable() {
		return false, dispatchOpaque(errors.Join(errCapacityDispatch, err, dispatchContext(parent)))
	}
	// The finite original claim will be bounded again by the persisted binding
	// and principal expiry before invocation. No subsequent call renews it.
	job, err := repository.ClaimCapacityDispatch(parent, s.server.db, realm, environment, uuid.New(), 90*time.Second)
	if err != nil {
		return false, dispatchOpaque(err)
	}
	p, principal, err := s.authorizeEnvelope(parent, job.CapacityDispatchEnvelope)
	if err != nil || job.LeaseExpiresAt == nil {
		return false, dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	deadline := *job.LeaseExpiresAt
	if principal.ExpiresAt.Before(deadline) {
		deadline = principal.ExpiresAt
	}
	// Shorter binding budgets are measured from the ORIGINAL 90s claim,
	// never from the time authorization or any native read finally returns.
	bound := job.LeaseExpiresAt.Add(-90*time.Second + time.Duration(p.ControllerBinding.DispatchLeaseSeconds)*time.Second)
	if bound.Before(deadline) {
		deadline = bound
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	guard := func(owner context.Context, started bool) error {
		if err := errors.Join(dispatchContext(owner), dispatchContext(parent)); err != nil || !time.Now().Before(deadline) {
			return errors.Join(errCapacityDispatch, err)
		}
		if err := repository.ValidateCapacityDispatchClaim(owner, s.server.db, job, started); err != nil {
			return err
		}
		_, _, err := s.authorizeEnvelope(owner, job.CapacityDispatchEnvelope)
		return errors.Join(err, dispatchContext(owner), dispatchContext(parent))
	}
	if err := guard(ctx, false); err != nil {
		return false, dispatchOpaque(err)
	}
	job, err = repository.StartCapacityDispatch(ctx, s.server.db, job)
	if err != nil {
		return false, dispatchOpaque(err)
	}
	if err := guard(ctx, true); err != nil {
		// Durable StartPossible is conservative; no original call follows.
		return false, dispatchOpaque(err)
	}
	ctx = messagecontroller.WithCapacityDispatchFence(ctx, func(owner context.Context) error { return guard(owner, true) })
	// A panic is not an observed original return. The started row remains an
	// explicit HOLD; only this private opaque error reaches the addon logger.
	defer func() {
		if recover() != nil {
			returnedErr = errCapacityDispatch
		}
	}()
	req := model.RunWorkflowRequest{Workflow: model.ManifestSelector{ManifestID: job.Workflow.ID.String()}, Inputs: job.Inputs, Metadata: job.Metadata}
	ran = true
	response, runErr := messagecontroller.RunWorkflow(ctx, s.server.rabbitmq, s.server.db, req)
	actualReturnedAt := time.Now().UTC()
	ownerErr := guard(ctx, true)
	joined := errors.Join(runErr, ownerErr, dispatchContext(ctx), dispatchContext(parent))
	finishErr := repository.FinishCapacityDispatch(ctx, s.server.db, job, response, actualReturnedAt, dispatchOpaque(joined), func(owner context.Context) error {
		_, _, err := s.authorizeEnvelope(owner, job.CapacityDispatchEnvelope)
		return errors.Join(err, dispatchContext(owner), dispatchContext(parent))
	})
	return ran, dispatchOpaque(errors.Join(joined, finishErr, dispatchContext(ctx), dispatchContext(parent)))
}

// A bounded catalog roster supplies realms, never caller-selected admission.
// Started/unknown rows are not selected here and cannot become fresh work.
func (s *CapacityDispatchService) RunPass(ctx context.Context) (returnedErr error) {
	enabled, err := CapacityDispatchProcessEnabled()
	if err != nil || !enabled {
		return err
	}
	if s == nil || s.server == nil {
		return errCapacityDispatch
	}
	if err := dispatchContext(ctx); err != nil {
		return dispatchOpaque(err)
	}
	// Retain refused demand without starving independently authorized queued
	// work. Only RunOne can start a job; the scan never invokes the executor.
	demandErr := s.runDemandPass(ctx)
	defer func() { returnedErr = dispatchOpaque(errors.Join(returnedErr, demandErr)) }()
	rows, err := s.server.db.QueryContext(ctx, `SELECT DISTINCT realm,environment FROM public.capacity_dispatch_jobs WHERE protocol=$1 AND state='queued' AND started_at IS NULL ORDER BY realm,environment LIMIT 65`, repository.CapacityDispatchProtocol)
	if err != nil {
		return dispatchOpaque(err)
	}
	var scopes [][2]string
	for rows.Next() {
		var scope [2]string
		if err = rows.Scan(&scope[0], &scope[1]); err != nil {
			break
		}
		scopes = append(scopes, scope)
	}
	if err = errors.Join(err, rows.Err(), rows.Close(), dispatchContext(ctx)); err != nil || len(scopes) > 64 {
		return dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	work := make(chan [2]string, len(scopes)*4)
	for _, scope := range scopes {
		for i := 0; i < 4; i++ {
			work <- scope
		}
	}
	close(work)
	var owners sync.WaitGroup
	var mu sync.Mutex
	var causes []error
	for i := 0; i < 4; i++ {
		owners.Add(1)
		goroutine.SafeGo("capacity_dispatch_owned_pass", func() {
			defer owners.Done()
			for scope := range work {
				_, err := s.RunOne(ctx, scope[0], scope[1])
				if err != nil && !errors.Is(err, repository.ErrCapacityDispatchClaim) {
					mu.Lock()
					causes = append(causes, err)
					mu.Unlock()
				}
			}
		})
	}
	// Cancellation does not stand in for any original worker return.
	owners.Wait()
	return dispatchOpaque(errors.Join(append(causes, dispatchContext(ctx))...))
}
