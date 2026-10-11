package httpapi

import (
	"context"
	"errors"
	"strconv"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type capacityDemandPolicy struct {
	manifest model.Manifest
	spec     model.CapacityPolicySpec
}

func (s *CapacityDispatchService) demandPolicies(ctx context.Context) ([]capacityDemandPolicy, error) {
	if s == nil || s.server == nil || dispatchContext(ctx) != nil {
		return nil, errCapacityDispatch
	}
	rows, err := s.server.db.QueryContext(ctx, `WITH current_policies AS
        (SELECT DISTINCT ON(namespace,name) id,spec FROM public.manifests WHERE kind='capacity_policy' ORDER BY namespace,name,version DESC,id)
        SELECT id FROM current_policies WHERE spec->'controller_binding'->'demand_source' IS NOT NULL
        AND spec->'controller_binding'->'demand_source'<>'null'::jsonb ORDER BY id LIMIT 65`)
	if err != nil {
		return nil, dispatchOpaque(err)
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
	if joined != nil || len(ids) > 64 {
		return nil, dispatchOpaque(errors.Join(errCapacityDispatch, joined))
	}
	var out []capacityDemandPolicy
	var refused error
	for _, id := range ids {
		if failure := dispatchContext(ctx); failure != nil {
			return out, dispatchOpaque(errors.Join(refused, failure))
		}
		m, e := repository.GetManifestByID(ctx, s.server.db, id)
		p, f := manifestengine.ParseCapacityPolicySpec(m.Spec)
		if e != nil || f != nil || !m.Metadata.Active || m.Kind != "capacity_policy" || manifestengine.ValidateCapacityPolicySpec(p) != nil || !p.ExecutionEnabled || p.ControllerBinding == nil || p.ControllerBinding.DemandSource == nil {
			refused = errors.Join(refused, errCapacityDispatch, e, f)
			continue
		}
		out = append(out, capacityDemandPolicy{m, p})
	}
	return out, dispatchOpaque(errors.Join(refused, dispatchContext(ctx)))
}

func (s *CapacityDispatchService) demandSource(ctx context.Context, p model.CapacityPolicySpec) (model.Manifest, error) {
	if p.ControllerBinding == nil || p.ControllerBinding.DemandSource == nil || dispatchContext(ctx) != nil {
		return model.Manifest{}, errCapacityDispatch
	}
	d := p.ControllerBinding.DemandSource
	wf, err := repository.ResolveManifest(ctx, s.server.db, "workflow", d.Namespace, d.Name, nil, false)
	if err != nil || !wf.Metadata.Active || wf.ID.String() != d.ManifestID || wf.Version != d.Version || wf.Checksum != d.Checksum {
		return model.Manifest{}, dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	spec, err := manifestengine.ParseWorkflowSpec(wf.Spec)
	if err != nil || spec.Trigger.Mode != "schedule" || spec.Trigger.Schedule == nil || (spec.Trigger.Enabled != nil && !*spec.Trigger.Enabled) || CapacityScheduleGraphRequiresOwner(spec) || (wf.Metadata.Namespace == p.Workflow.Namespace && wf.Metadata.Name == p.Workflow.Name) {
		return model.Manifest{}, errCapacityDispatch
	}
	return wf, dispatchOpaque(dispatchContext(ctx))
}

// Only the independently reread original event columns can install this origin.
// Event bodies/metric outputs never become action inputs, a principal or proof.
func (s *CapacityDispatchService) prepareDemand(ctx context.Context, policy capacityDemandPolicy, event repository.CapacityDemandEvent) (*CapacityDispatchPrepared, error) {
	p := policy.spec
	source, err := s.demandSource(ctx, p)
	if err != nil {
		return nil, err
	}
	if event.SourceWorkflow != dispatchPin(source) || event.EmittedAt.After(time.Now()) || time.Since(event.EmittedAt) > time.Duration(p.ControllerBinding.DemandSource.MaxAgeSeconds)*time.Second {
		return nil, errCapacityDispatch
	}
	wf, err := repository.ResolveManifest(ctx, s.server.db, "workflow", p.Workflow.Namespace, p.Workflow.Name, nil, false)
	if err != nil || !wf.Metadata.Active {
		return nil, dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	spec, err := manifestengine.ParseWorkflowSpec(wf.Spec)
	if err != nil || dispatchWorkflowGraph(spec, policy.manifest) != nil {
		return nil, errCapacityDispatch
	}
	e := repository.CapacityDispatchEnvelope{Protocol: repository.CapacityDispatchProtocol, JobID: uuid.New(), RunID: uuid.New(), Realm: policy.manifest.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, SourceTick: "event:" + event.EventID.String(), Policy: dispatchPin(policy.manifest), Workflow: dispatchPin(wf), MachinePrincipalID: p.ControllerBinding.MachinePrincipalID}
	e.Inputs = map[string]any{"policy": map[string]any{"namespace": policy.manifest.Metadata.Namespace, "name": policy.manifest.Metadata.Name}}
	e.Metadata = map[string]any{repository.WorkflowRunCreatorMachinePrincipalMetadataKey: e.MachinePrincipalID, "triggered_by": "capacity_demand", "manifest_id": wf.ID.String(), "capacity_dispatch_protocol": e.Protocol, "capacity_dispatch_job_id": e.JobID.String(), "source_event_id": event.EventID.String(), "source_event_sha256": event.SHA256, "source_run_id": event.RunID.String(), "source_workflow_id": source.ID.String()}
	e.BindingSHA256, err = dispatchSHA(p.ControllerBinding)
	principal, f := s.principal(e.MachinePrincipalID)
	if err != nil || f != nil {
		return nil, errCapacityDispatch
	}
	e.PrincipalSHA256, err = dispatchPrincipalSHA(principal)
	if err != nil {
		return nil, errCapacityDispatch
	}
	rbac, err := resolveWorkflowAuthorizationManifest(ctx, s.server.db, "rbac", spec.Authorization.RBAC)
	if err != nil || !rbac.Metadata.Active {
		return nil, errCapacityDispatch
	}
	e.RBAC = dispatchPin(rbac)
	if spec.Authorization.Policy != nil {
		m, f := resolveWorkflowAuthorizationManifest(ctx, s.server.db, "policy", *spec.Authorization.Policy)
		if f != nil || !m.Metadata.Active {
			return nil, errCapacityDispatch
		}
		pin := dispatchPin(m)
		e.AuthorizationPolicy = &pin
	}
	_, _, prepared, persisted, err := messagecontroller.PrepareCapacityDispatchWorkflow(ctx, s.server.db, model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: wf.Metadata.Namespace, Name: wf.Metadata.Name}, Inputs: e.Inputs, Metadata: e.Metadata})
	if err != nil {
		return nil, dispatchOpaque(err)
	}
	a, _ := dispatchSHA(e.Inputs)
	b, _ := dispatchSHA(prepared.Inputs)
	c, _ := dispatchSHA(persisted)
	if a != b || a != c {
		return nil, errCapacityDispatch
	}
	e.InputsSHA256, e.MetadataSHA256, err = repository.CapacityDispatchEnvelopeHashes(e)
	if err != nil {
		return nil, dispatchOpaque(err)
	}
	if _, _, err = s.authorizeEnvelope(ctx, e); err != nil {
		return nil, err
	}
	return &CapacityDispatchPrepared{service: s, envelope: e}, dispatchOpaque(dispatchContext(ctx))
}

func (s *CapacityDispatchService) authorizeDemandOrigin(ctx context.Context, e repository.CapacityDispatchEnvelope, p model.CapacityPolicySpec) error {
	if e.Metadata["triggered_by"] != "capacity_demand" {
		return nil
	}
	source, err := s.demandSource(ctx, p)
	if err != nil {
		return err
	}
	text, ok := e.Metadata["source_event_id"].(string)
	if !ok {
		return errCapacityDispatch
	}
	id, err := uuid.Parse(text)
	if err != nil || id == uuid.Nil || id.String() != text {
		return errCapacityDispatch
	}
	original, err := repository.ReadCapacityDemandEvent(ctx, s.server.db, id)
	if err != nil || original.SourceWorkflow != dispatchPin(source) || original.SHA256 != e.Metadata["source_event_sha256"] || original.RunID.String() != e.Metadata["source_run_id"] || source.ID.String() != e.Metadata["source_workflow_id"] {
		return dispatchOpaque(errors.Join(errCapacityDispatch, err))
	}
	return dispatchOpaque(dispatchContext(ctx))
}

func demandScope(policy capacityDemandPolicy) repository.CapacityDemandScope {
	id, _ := uuid.Parse(policy.spec.ControllerBinding.DemandSource.ManifestID)
	return repository.CapacityDemandScope{Realm: policy.manifest.Metadata.Namespace, Environment: policy.spec.Environment, Domain: policy.spec.Domain, Dimension: policy.spec.Dimension, SourceWorkflowID: id, MaxAgeSeconds: policy.spec.ControllerBinding.DemandSource.MaxAgeSeconds}
}

// The original RunPass has one10s owner and no new timer. Each independently
// fixed dimension selects latest fresh unconsumed demand. A refusal is retained
// opaquely and cannot starve another dimension. Only RunOne may start work.
func (s *CapacityDispatchService) runDemandPass(parent context.Context) error {
	if s == nil || s.server == nil || dispatchContext(parent) != nil {
		return dispatchOpaque(errors.Join(errCapacityDispatch, dispatchContext(parent)))
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	policies, refused := s.demandPolicies(ctx)
	candidates := 0
	for _, policy := range policies {
		if failure := errors.Join(dispatchContext(ctx), dispatchContext(parent)); failure != nil {
			return dispatchOpaque(errors.Join(refused, failure))
		}
		if _, err := s.demandSource(ctx, policy.spec); err != nil {
			refused = errors.Join(refused, err)
			continue
		}
		scope := demandScope(policy)
		batch, err := repository.ReadCapacityDemandBatch(ctx, s.server.db, scope)
		if err != nil {
			refused = errors.Join(refused, err)
			continue
		}
		for _, candidate := range batch {
			candidates++
			if candidates > repository.CapacityDemandBatchLimit {
				return dispatchOpaque(errors.Join(refused, errCapacityDispatch))
			}
			original, err := repository.ReadCapacityDemandEvent(ctx, s.server.db, candidate.EventID)
			if err == nil && original.Sequence != candidate.Sequence {
				err = errCapacityDispatch
			}
			if err == nil {
				err = s.admitDemand(ctx, policy, scope, original)
			}
			refused = errors.Join(refused, err)
			if failure := errors.Join(dispatchContext(ctx), dispatchContext(parent)); failure != nil {
				return dispatchOpaque(errors.Join(refused, failure))
			}
		}
	}
	return dispatchOpaque(errors.Join(refused, dispatchContext(ctx), dispatchContext(parent)))
}

func (s *CapacityDispatchService) admitDemand(ctx context.Context, policy capacityDemandPolicy, scope repository.CapacityDemandScope, event repository.CapacityDemandEvent) error {
	prepared, err := s.prepareDemand(ctx, policy, event)
	if err != nil {
		return err
	}
	cursor, err := repository.ReadCapacityDemandCursor(ctx, s.server.db, scope)
	if err != nil {
		return dispatchOpaque(err)
	}
	tx, err := s.server.db.BeginTx(ctx, nil)
	if err != nil {
		return dispatchOpaque(err)
	}
	if _, _, err = prepared.Enqueue(ctx, tx); err == nil {
		err = repository.AdvanceCapacityDemandCursor(ctx, tx, scope, cursor, strconv.FormatInt(event.Sequence, 10))
	}
	if failure := errors.Join(err, dispatchContext(ctx)); failure != nil {
		return dispatchOpaque(errors.Join(failure, tx.Rollback(), dispatchContext(ctx)))
	}
	return dispatchOpaque(errors.Join(tx.Commit(), dispatchContext(ctx)))
}
