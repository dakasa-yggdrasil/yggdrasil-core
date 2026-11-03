package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"slices"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executoractivity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executorpower"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const executorPowerProfile = "executor_power_v1"

// powerTransaction reuses the dimension lock and the existing native resource
// ledger. The additional global physical-resource lock covers different policies
// and integration instances. No provider IO occurs under database locks.
func (s CapacityStore) powerTransaction(ctx context.Context, policy model.Manifest, adopt bool, fn func(*sql.Tx, model.CapacityPolicySpec, executorpower.Scope, time.Time) error) error {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return err
	}
	b := p.ExecutorPowerBinding
	if s.DB == nil || b == nil || executorpower.ValidateBinding(*b) != nil || s.AdmissionOnly || s.WorkflowID == uuid.Nil {
		return executorpower.ErrDenied
	}
	wf := p.Workflow
	if adopt {
		wf = model.ManifestSelector{Namespace: b.AdoptionWorkflow.Namespace, Name: b.AdoptionWorkflow.Name}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "capacity-power-instance/"+b.Resource.InstanceID); err != nil {
		return err
	}
	var active bool
	var checksum string
	if err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active); err != nil {
		return err
	}
	if !active || checksum != policy.Checksum {
		return ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, s.WorkflowID, wf.Namespace, wf.Name).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrCapacityConflict
	}
	ib := model.CapacityMutationBinding{IntegrationInstanceID: b.IntegrationID, IntegrationChecksum: b.IntegrationChecksum, IntegrationTypeID: b.TypeID, IntegrationTypeChecksum: b.TypeChecksum}
	if err = checkPowerIntegration(ctx, tx, ib); err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	scope := executorpower.Scope{Namespace: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID.String()}
	if err = fn(tx, p, scope, now); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return errors.Join(executorpower.ErrUnknown, err)
	}
	return nil
}

// AdoptExecutorPower performs the independent fixed read before beginning the
// transaction. An observer is deliberately not installed in workflow bootstrap.
// An operator must later qualify and explicitly wire that trusted provider port.
func (s CapacityStore) AdoptExecutorPower(ctx context.Context, policy model.Manifest) (executorpower.Adoption, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return executorpower.Adoption{}, err
	}
	b := p.ExecutorPowerBinding
	if b == nil || !s.ExecutorPowerEnabled || !s.ExecutionEnabled || !p.ExecutionEnabled || !b.Enabled || s.ExecutorPowerOperator == "" || s.ExecutorPowerObserver == nil {
		return executorpower.Adoption{}, executorpower.ErrDenied
	}
	// Check operator and binding before even a read-only WAN request.
	allowed := false
	for _, id := range b.Operators {
		allowed = allowed || id == s.ExecutorPowerOperator
	}
	if !allowed || executorpower.ValidateBinding(*b) != nil {
		return executorpower.Adoption{}, executorpower.ErrDenied
	}
	o, err := s.ExecutorPowerObserver.Observe(ctx, b.Resource)
	if err != nil {
		return executorpower.Adoption{}, err
	}
	var result executorpower.Adoption
	err = s.powerTransaction(ctx, policy, true, func(tx *sql.Tx, p model.CapacityPolicySpec, scope executorpower.Scope, now time.Time) error {
		a, e := executorpower.Adopt(*p.ExecutorPowerBinding, s.ExecutorPowerOperator, uuid.NewString(), o, now, true)
		if e != nil {
			return e
		}
		// Never overwrite or silently adopt another registration (including VM slots).
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE resource_id IN ($1,$2)`, executorpower.Key(b.Resource), b.Resource.InstanceID).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return ErrCapacityConflict
		}
		// Never adopt a target of an unresolved legacy mutation. An original
		// creation with unknown native identity is conservatively a global hold.
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE NOT (grant_record ? 'authority_kind') AND state IN ('issued','redeemed','settled','compensating') AND (grant_record->'grant'->>'expected_resource_id'=$1 OR grant_record->'settlement'->>'resource_id'=$1 OR grant_record->'proof'->>'resource_id'=$1 OR (grant_record->'grant'->>'capability' ~ '^ensure_' AND state IN ('redeemed','settled','compensating') AND COALESCE(grant_record->'settlement'->>'resource_id','')=''))`, b.Resource.InstanceID).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return ErrCapacityConflict
		}
		raw, e := json.Marshal(a)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9::jsonb)`, b.IntegrationID, executorpower.Digest(b.Resource), executorPowerProfile, scope.Namespace, scope.Environment, scope.Domain, scope.Dimension, b.Resource.InstanceID, string(raw))
		if e == nil {
			result = a
		}
		return e
	})
	if err != nil {
		return executorpower.Adoption{}, err
	}
	return result, nil
}

func loadPowerAdoption(ctx context.Context, tx *sql.Tx, b executorpower.Binding, scope executorpower.Scope) (executorpower.Adoption, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT slot_record FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=1 AND namespace=$4 AND environment=$5 AND domain=$6 AND dimension=$7 AND resource_id=$8 FOR UPDATE`, b.IntegrationID, executorpower.Digest(b.Resource), executorPowerProfile, scope.Namespace, scope.Environment, scope.Domain, scope.Dimension, b.Resource.InstanceID).Scan(&raw)
	var a executorpower.Adoption
	if err != nil {
		return a, err
	}
	if len(raw) > 32768 || capacity.DecodeNativeCapacity(json.RawMessage(raw), &a) != nil || a.Kind != executorpower.AdoptionKind || a.BindingSHA != executorpower.Digest(b) || !executorpower.SameResource(a.Resource, b.Resource) {
		return a, executorpower.ErrDenied
	}
	return a, nil
}
func loadPowerActivity(ctx context.Context, tx *sql.Tx, scope executorpower.Scope) (executoractivity.ExecutorActivityState, error) {
	key, _ := json.Marshal([]string{scope.Namespace, scope.Environment, scope.Domain, scope.Dimension})
	pin, _ := json.Marshal([]string{scope.PolicyID, scope.PolicyChecksum, scope.WorkflowID})
	return (executoractivity.PostgresStore{Tx: tx, Binding: fmt.Sprintf("%x", sha256.Sum256(pin))}).Load(ctx, string(key))
}

func (s CapacityStore) IssueExecutorPower(ctx context.Context, policy model.Manifest, commandID string) (executorpower.Grant, error) {
	var result executorpower.Grant
	err := s.powerTransaction(ctx, policy, false, func(tx *sql.Tx, p model.CapacityPolicySpec, scope executorpower.Scope, now time.Time) error {
		b := *p.ExecutorPowerBinding
		if !s.ExecutorPowerEnabled || !s.ExecutionEnabled || !p.ExecutionEnabled || !b.Enabled || s.ExecutorID == "" || s.ExecutorActivityPrincipal != "machine:"+b.ControllerPrincipal {
			return executorpower.ErrDenied
		}
		a, e := loadPowerAdoption(ctx, tx, b, scope)
		if e != nil {
			return e
		}
		state, e := loadPowerActivity(ctx, tx, scope)
		if e != nil {
			return e
		}
		if state.Power == nil {
			return executorpower.ErrDenied
		}
		// A command has exactly one grant, forever. Even rejected or expired attempts
		// require a new explicitly reconciled command; retries never recreate authority.
		var count int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE grant_record->>'authority_kind'=$1 AND (grant_record->>'command_id'=$2 OR (grant_record->>'adoption_id'=$3 AND state IN ('issued','redeemed','settled')))`, executorpower.Kind, commandID, a.ID).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return ErrCapacityConflict
		}
		g, e := executorpower.Issue(b, a, scope, s.ExecutorActivityPrincipal, uuid.NewString(), commandID, state.Power.Action, state, now, true)
		if e != nil {
			return e
		}
		raw, e := json.Marshal(g)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,1,'issued',$10::jsonb,$11)`, g.ID, scope.Namespace, scope.Environment, scope.Domain, scope.Dimension, int64(state.Revision), b.IntegrationID, executorpower.Digest(b.Resource), executorPowerProfile, string(raw), g.ExpiresAt)
		if e == nil {
			result = g
		}
		return e
	})
	if err != nil {
		return executorpower.Grant{}, err
	}
	return result, nil
}

func decodePowerGrant(raw []byte) (executorpower.Grant, error) {
	var g executorpower.Grant
	if len(raw) > 32768 || capacity.DecodeNativeCapacity(json.RawMessage(raw), &g) != nil || executorpower.ValidateGrant(g) != nil {
		return g, executorpower.ErrDenied
	}
	return g, nil
}
func savePowerGrant(ctx context.Context, tx *sql.Tx, g executorpower.Grant) error {
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET state=$2,grant_record=$3::jsonb,updated_at=clock_timestamp() WHERE id=$1 AND grant_record->>'authority_kind'=$4`, g.ID, g.State, string(raw), executorpower.Kind)
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err == nil && n != 1 {
		return ErrCapacityConflict
	}
	return err
}

// Callback loads scope from the original ledger, never callback-supplied policy.
// Settlement remains available after disabling execution so a late original
// result can close uncertainty without obtaining new send permission.
func (s CapacityStore) executorPowerCallback(ctx context.Context, id, principal, integration, action string, send bool, fn func(*sql.Tx, *executorpower.Grant, time.Time, bool) error) error {
	if s.DB == nil || uuid.Validate(id) != nil {
		return executorpower.ErrDenied
	}
	var raw []byte
	var sqlState string
	if err := s.DB.QueryRowContext(ctx, `SELECT state,grant_record FROM public.capacity_mutation_grants WHERE id=$1`, id).Scan(&sqlState, &raw); err != nil {
		return err
	}
	original, err := decodePowerGrant(raw)
	if err != nil {
		return err
	}
	if original.State != sqlState {
		return executorpower.ErrDenied
	}
	if original.Binding.AdapterPrincipal != principal || original.Binding.IntegrationID != integration || original.Action != action {
		return executorpower.ErrDenied
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	key, _ := json.Marshal([]string{original.Scope.Namespace, original.Scope.Environment, original.Scope.Domain, original.Scope.Dimension})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(key)); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "capacity-power-instance/"+original.Binding.Resource.InstanceID); err != nil {
		return err
	}
	if err = tx.QueryRowContext(ctx, `SELECT state,grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, id).Scan(&sqlState, &raw); err != nil {
		return err
	}
	g, err := decodePowerGrant(raw)
	if err != nil {
		return err
	}
	if g.State != sqlState {
		return executorpower.ErrDenied
	}
	if g.RequestSHA != original.RequestSHA || g.ID != id {
		return ErrCapacityConflict
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	enabled := false
	if send && g.State == "issued" {
		var policyRaw []byte
		var checksum string
		var active bool
		if err = tx.QueryRowContext(ctx, `SELECT spec,checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, g.Scope.PolicyID).Scan(&policyRaw, &checksum, &active); err != nil {
			return err
		}
		var p model.CapacityPolicySpec
		if json.Unmarshal(policyRaw, &p) != nil {
			return executorpower.ErrDenied
		}
		enabled = s.ExecutionEnabled && s.ExecutorPowerEnabled && !s.AdmissionOnly && active && checksum == g.Scope.PolicyChecksum && p.ExecutionEnabled && p.ExecutorPowerBinding != nil && executorpower.Digest(*p.ExecutorPowerBinding) == executorpower.Digest(g.Binding)
		if enabled {
			if err = tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, g.Scope.WorkflowID, p.Workflow.Namespace, p.Workflow.Name).Scan(&active); err != nil {
				return err
			}
			enabled = active
			if enabled {
				err = checkPowerIntegration(ctx, tx, model.CapacityMutationBinding{IntegrationInstanceID: g.Binding.IntegrationID, IntegrationChecksum: g.Binding.IntegrationChecksum, IntegrationTypeID: g.Binding.TypeID, IntegrationTypeChecksum: g.Binding.TypeChecksum})
				if err != nil {
					return err
				}
			}
		}
	}
	if err = fn(tx, &g, now, enabled); err != nil {
		return err
	}
	if err = savePowerGrant(ctx, tx, g); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return errors.Join(executorpower.ErrUnknown, err)
	}
	return nil
}
func (s CapacityStore) RedeemExecutorPower(ctx context.Context, principal, integration string, c executorpower.Claim) (executorpower.ClaimReply, error) {
	var result executorpower.ClaimReply
	err := s.executorPowerCallback(ctx, c.GrantID, principal, integration, c.Action, true, func(tx *sql.Tx, g *executorpower.Grant, now time.Time, enabled bool) error {
		current := false
		if enabled && g.State == "issued" {
			a, e := loadPowerAdoption(ctx, tx, g.Binding, g.Scope)
			if e != nil {
				return e
			}
			state, e := loadPowerActivity(ctx, tx, g.Scope)
			if e != nil {
				return e
			}
			current = executorpower.Current(g.Binding, a, state, g.CommandID, g.Action, g.Epoch, now)
		}
		var e error
		result, e = executorpower.Redeem(g, principal, c, now, enabled, current)
		return e
	})
	if err != nil {
		return executorpower.ClaimReply{}, err
	}
	return result, nil
}
func (s CapacityStore) SettleExecutorPower(ctx context.Context, principal, integration, action, token string, result executorpower.Result) error {
	return s.executorPowerCallback(ctx, result.GrantID, principal, integration, action, false, func(_ *sql.Tx, g *executorpower.Grant, now time.Time, _ bool) error {
		return executorpower.Settle(g, principal, token, result, now)
	})
}
func (s CapacityStore) ConfirmExecutorPower(ctx context.Context, policy model.Manifest, id string) (executorpower.Grant, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return executorpower.Grant{}, err
	}
	if p.ExecutorPowerBinding == nil || s.ExecutorPowerObserver == nil || s.ExecutorActivityPrincipal != "machine:"+p.ExecutorPowerBinding.ControllerPrincipal {
		return executorpower.Grant{}, executorpower.ErrDenied
	}
	o, err := s.ExecutorPowerObserver.Observe(ctx, p.ExecutorPowerBinding.Resource)
	if err != nil {
		return executorpower.Grant{}, err
	}
	var result executorpower.Grant
	err = s.powerTransaction(ctx, policy, false, func(tx *sql.Tx, p model.CapacityPolicySpec, scope executorpower.Scope, now time.Time) error {
		var raw []byte
		var sqlState string
		if e := tx.QueryRowContext(ctx, `SELECT state,grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, id).Scan(&sqlState, &raw); e != nil {
			return e
		}
		g, e := decodePowerGrant(raw)
		if e != nil {
			return e
		}
		if g.State != sqlState {
			return executorpower.ErrDenied
		}
		if g.Scope != scope || executorpower.Digest(g.Binding) != executorpower.Digest(*p.ExecutorPowerBinding) {
			return executorpower.ErrDenied
		}
		a, e := loadPowerAdoption(ctx, tx, g.Binding, scope)
		if e != nil {
			return e
		}
		if a.ID != g.AdoptionID {
			return executorpower.ErrDenied
		}
		if e = executorpower.Confirm(&g, o, now); e != nil {
			return e
		}
		if e = savePowerGrant(ctx, tx, g); e != nil {
			return e
		}
		result = g
		return nil
	})
	if err != nil {
		return executorpower.Grant{}, err
	}
	return result, nil
}

// Power capabilities must be declared by the exact pinned AWS type; presence of
// legacy start/stop helpers or an ensure/destroy VM pair never qualifies them.
func checkPowerIntegration(ctx context.Context, tx *sql.Tx, b model.CapacityMutationBinding) error {
	if err := checkMutationIntegration(ctx, tx, b); err != nil {
		return err
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1 AND checksum=$2 AND kind='integration_type' FOR SHARE`, b.IntegrationTypeID, b.IntegrationTypeChecksum).Scan(&raw); err != nil {
		return err
	}
	return validatePowerCatalog(raw)
}
func validatePowerCatalog(raw []byte) error {
	spec, err := manifest.ParseIntegrationTypeSpec(raw)
	if err != nil || spec.Provider != "aws" || !slices.Contains(spec.Capabilities, "execute") {
		return executorpower.ErrDenied
	}
	for _, name := range []string{executorpower.Running, executorpower.Stopped} {
		declared, dispatched := false, false
		for _, r := range spec.ResourceTypes {
			if r.Name == "ec2_instance" && slices.Contains(r.DefaultActions, name) {
				declared = true
			}
		}
		for _, a := range spec.ActionCatalog {
			if a.Name == name && (a.Category == "" || a.Category == "capability") && slices.Contains(a.ResourceTypes, "ec2_instance") {
				dispatched = true
			}
		}
		if !declared || !dispatched {
			return executorpower.ErrDenied
		}
	}
	return nil
}
