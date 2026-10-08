package repository

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrCapacityMutationAuthorization = errors.New("capacity mutation authorization denied")

type capacityMutationRecord struct {
	Grant                 model.CapacityMutationGrant          `json:"grant"`
	Binding               model.CapacityMutationBinding        `json:"binding"`
	PolicyID              uuid.UUID                            `json:"policy_id"`
	PolicyChecksum        string                               `json:"policy_checksum"`
	WorkflowID            uuid.UUID                            `json:"workflow_id"`
	Generation            int64                                `json:"generation"`
	FencingToken          int64                                `json:"fencing_token"`
	LeaseOwner            string                               `json:"lease_owner"`
	ExecutorID            string                               `json:"executor_id"`
	CreatedAt             time.Time                            `json:"created_at"`
	AttemptID             string                               `json:"attempt_id,omitempty"`
	SettlementTokenSHA256 string                               `json:"settlement_token_sha256,omitempty"`
	Settlement            *model.CapacityMutationSettleRequest `json:"settlement,omitempty"`
	Proof                 *model.CapacityMutationProof         `json:"proof,omitempty"`
	EventProvider         string                               `json:"event_provider"`
	EventResource         string                               `json:"event_resource"`
}

type capacityResourceSlot struct {
	BindingName       string    `json:"binding_name"`
	ProfileName       string    `json:"profile_name"`
	DesiredSpecSHA256 string    `json:"desired_spec_sha256"`
	ResourceID        string    `json:"resource_id"`
	ResourceCreatedAt string    `json:"resource_created_at"`
	ReceiptRef        string    `json:"receipt_ref"`
	ObservedAt        time.Time `json:"observed_at"`
	Tombstone         bool      `json:"tombstone"`
}

// lockMutationScope uses the same lock as capacity intents. Every mutation path
// acquires it before row locks. Neither this transaction nor callbacks call WAN.
func lockMutationScope(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec) error {
	key, _ := json.Marshal([]string{namespace, p.Environment, p.Domain, p.Dimension})
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(key))
	return err
}

// A logical native slot is global across policy realms. Scope locks alone
// cannot serialize two first registrations of an absent native-slot row.
func lockNativeMutationSlot(ctx context.Context, tx *sql.Tx, b model.CapacityMutationBinding, slot int) error {
	key, _ := json.Marshal([]any{"capacity-native-slot", b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, slot})
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(key))
	return err
}

func (s CapacityStore) mutationTransaction(ctx context.Context, policy model.Manifest, historical bool, generation, fence int64, owner string, fn func(*sql.Tx, model.CapacityPolicySpec, model.CapacityIntent, time.Time) error) error {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return err
	}
	if s.WorkflowID == uuid.Nil {
		return ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return err
	}
	var checksum string
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 AND name=$3 FOR SHARE`, policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).Scan(&checksum, &active); err != nil {
		return err
	}
	if checksum != policy.Checksum || (!historical && !active) {
		return ErrCapacityConflict
	}
	if err = tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, s.WorkflowID, p.Workflow.Namespace, p.Workflow.Name).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrCapacityMutationAuthorization
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	intent, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return err
	}
	if historical && intent.RecoveryOnly {
		err = s.checkRecoveryLease(policy, &intent, generation, fence, owner, now)
	} else {
		err = s.checkLease(p, policy, &intent, generation, fence, owner, now)
	}
	if err != nil {
		return err
	}
	if err = fn(tx, p, intent, now.UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func checkMutationIntegration(ctx context.Context, tx *sql.Tx, b model.CapacityMutationBinding) error {
	var checksum string
	var active bool
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT checksum,active,spec->'type_ref' FROM public.manifests WHERE id=$1 AND kind='integration_instance' FOR SHARE`, b.IntegrationInstanceID).Scan(&checksum, &active, &raw); err != nil {
		return err
	}
	if !active || checksum != b.IntegrationChecksum {
		return ErrCapacityConflict
	}
	var ref model.ManifestSelector
	if err := json.Unmarshal(raw, &ref); err != nil {
		return err
	}
	var ns, name string
	var version int
	if err := tx.QueryRowContext(ctx, `SELECT checksum,active,namespace,name,version FROM public.manifests WHERE id=$1 AND kind='integration_type' FOR SHARE`, b.IntegrationTypeID).Scan(&checksum, &active, &ns, &name, &version); err != nil {
		return err
	}
	if !active || checksum != b.IntegrationTypeChecksum {
		return ErrCapacityConflict
	}
	if ref.ManifestID != "" {
		if ref.ManifestID != b.IntegrationTypeID {
			return ErrCapacityConflict
		}
	} else {
		if ref.Namespace == "" {
			ref.Namespace = "global"
		}
		if ref.Namespace != ns || ref.Name != name || (ref.Version != nil && *ref.Version != version) {
			return ErrCapacityConflict
		}
	}
	return nil
}

// IssueMutation creates one durable permission, not a provider resource. A
// redeemed or unresolved slot never becomes free merely because time elapsed.
func (s CapacityStore) IssueMutation(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, issue model.CapacityMutationIssue) (model.CapacityMutationGrant, error) {
	var result model.CapacityMutationGrant
	err := s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, intent model.CapacityIntent, now time.Time) error {
		plan, err := capacity.PrepareMutationPlan(p, issue)
		if err != nil {
			return err
		}
		b := plan.Binding
		if err = lockNativeMutationSlot(ctx, tx, b, plan.Slot); err != nil {
			return err
		}
		if err = checkMutationIntegration(ctx, tx, b); err != nil {
			return err
		}
		provider, resource, err := capacityMutationEventIdentity(ctx, tx, b)
		if err != nil {
			return err
		}
		if b.ProfileName != intent.Decision.Profile || !capacityProfileCurrent(p, intent.Decision, now) {
			return ErrCapacityConflict
		}
		if plan.Capability == b.EnsureCapability && (intent.Phase != "preparing" || capacityIntentReduction(intent)) {
			return ErrCapacityConflict
		}
		if plan.Capability == b.DestroyCapability && (intent.Phase != "drained" || !capacityIntentReduction(intent)) {
			return ErrCapacityConflict
		}
		slot, exists, err := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, plan.Slot)
		if err != nil {
			return err
		}
		if plan.Capability == b.DestroyCapability {
			if !exists || slot.ResourceID == "" {
				return ErrCapacityConflict
			}
			plan, err = capacity.BindMutationDestroyPlan(plan, slot.ResourceID, slot.ResourceCreatedAt)
			if err != nil {
				return ErrCapacityConflict
			}
		}
		// Never-redeemed permissions have never authorized an SDK send. Only
		// those may expire without a remote mutation receipt.
		if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET state='expired',grant_record=jsonb_set(grant_record,'{grant,state}','"expired"'),updated_at=$5 WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state='issued' AND expires_at<=$5`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, now); err != nil {
			return err
		}
		var data []byte
		err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4 AND state IN ('issued','redeemed','settled') FOR UPDATE`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, plan.Slot).Scan(&data)
		if err == nil {
			var old capacityMutationRecord
			if err = json.Unmarshal(data, &old); err != nil {
				return err
			}
			if old.PolicyID != policy.ID || old.Generation != generation || old.FencingToken != fence || old.ExecutorID != s.ExecutorID || old.Grant.RequestSHA256 != plan.RequestSHA256 {
				return ErrCapacityConflict
			}
			result = old.Grant
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		var foreign int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4 AND (namespace<>$5 OR environment<>$6 OR domain<>$7 OR dimension<>$8)`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, plan.Slot, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&foreign); err != nil {
			return err
		}
		if foreign != 0 {
			return ErrCapacityConflict
		}
		var live, pending, pendingDestroy, started int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>''`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&live); err != nil {
			return err
		}
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE state IN ('issued','redeemed','settled') AND grant_record->'grant'->>'capability' ~ '^ensure_'),count(*) FILTER(WHERE state IN ('issued','redeemed','settled') AND grant_record->'grant'->>'capability' ~ '^destroy_'),count(*) FILTER(WHERE generation=$5 AND state<>'expired' AND state<>'rejected') FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, generation).Scan(&pending, &pendingDestroy, &started); err != nil {
			return err
		}
		if started == 0 && live != intent.BaselineSnapshot.Units {
			return fmt.Errorf("%w: native membership has not been completely registered", ErrCapacityConflict)
		}
		var fresh int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND resource_id<>'' AND (slot_record->>'observed_at')::timestamptz BETWEEN $5 AND $6`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, now.Add(-time.Duration(p.MaxEvidenceAgeSeconds)*time.Second), now.Add(5*time.Second)).Scan(&fresh); err != nil {
			return err
		}
		if fresh != live {
			return fmt.Errorf("%w: native membership readback is stale", ErrCapacityConflict)
		}
		if plan.Capability == b.EnsureCapability {
			if (exists && slot.ResourceID != "") || live+pending >= intent.Decision.Units || live+pending >= p.Ceiling {
				return ErrCapacityConflict
			}
		} else {
			if !exists || slot.ResourceID != plan.ExpectedResourceID || slot.ResourceCreatedAt != plan.ExpectedResourceCreatedAt || slot.ProfileName != b.ProfileName || live-pendingDestroy <= intent.Decision.Units || live-pendingDestroy <= p.Floor || pending != 0 {
				return ErrCapacityConflict
			}
		}
		expires := now.Add(60 * time.Second)
		if intent.LeaseExpiresAt.Before(expires) {
			expires = *intent.LeaseExpiresAt
		}
		result = model.CapacityMutationGrant{GrantID: uuid.NewString(), BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: plan.Slot, Capability: plan.Capability, RequestSHA256: plan.RequestSHA256, ExpectedResourceID: plan.ExpectedResourceID, ExpectedResourceCreatedAt: plan.ExpectedResourceCreatedAt, ExpiresAt: expires, State: "issued"}
		record := capacityMutationRecord{Grant: result, Binding: b, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, WorkflowID: s.WorkflowID, Generation: generation, FencingToken: fence, LeaseOwner: owner, ExecutorID: s.ExecutorID, CreatedAt: now, EventProvider: provider, EventResource: resource}
		data, err = json.Marshal(record)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_mutation_grants(id,namespace,environment,domain,dimension,generation,integration_instance_id,scope_checksum,profile_name,slot,state,grant_record,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'issued',$11::jsonb,$12)`, result.GrantID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, generation, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, plan.Slot, data, expires)
		return err
	})
	return result, err
}

func loadMutationSlot(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec, b model.CapacityMutationBinding, slot int) (capacityResourceSlot, bool, error) {
	var result capacityResourceSlot
	var ns, env, domain, dimension string
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension,slot_record FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4 FOR UPDATE`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, slot).Scan(&ns, &env, &domain, &dimension, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	if ns != namespace || env != p.Environment || domain != p.Domain || dimension != p.Dimension {
		return result, true, ErrCapacityConflict
	}
	err = json.Unmarshal(raw, &result)
	return result, true, err
}

func saveMutationSlot(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec, b model.CapacityMutationBinding, slot int, record capacityResourceSlot) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_resource_slots(integration_instance_id,scope_checksum,profile_name,slot,namespace,environment,domain,dimension,resource_id,slot_record) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb) ON CONFLICT(integration_instance_id,scope_checksum,profile_name,slot) DO UPDATE SET resource_id=EXCLUDED.resource_id,slot_record=EXCLUDED.slot_record,revision=capacity_resource_slots.revision+1,updated_at=clock_timestamp() WHERE capacity_resource_slots.namespace=EXCLUDED.namespace AND capacity_resource_slots.environment=EXCLUDED.environment AND capacity_resource_slots.domain=EXCLUDED.domain AND capacity_resource_slots.dimension=EXCLUDED.dimension`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, slot, namespace, p.Environment, p.Domain, p.Dimension, record.ResourceID, raw)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return ErrCapacityConflict
	}
	return nil
}

func saveMutationGrant(ctx context.Context, tx *sql.Tx, record capacityMutationRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET state=$2,grant_record=$3::jsonb,updated_at=clock_timestamp() WHERE id=$1`, record.Grant.GrantID, record.Grant.State, raw)
	return err
}

// callbackTransaction first finds the durable scope, then takes the shared
// scope lock. Settlement deliberately does not require an active lease/policy:
// revocation must not erase a late owning adapter's transport facts.
func (s CapacityStore) callbackTransaction(ctx context.Context, id string, fn func(*sql.Tx, *capacityMutationRecord, string, model.CapacityPolicySpec, time.Time) error) error {
	if parsed, err := uuid.Parse(id); err != nil || parsed == uuid.Nil {
		return ErrCapacityMutationAuthorization
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var ns string
	var p model.CapacityPolicySpec
	if err = tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension FROM public.capacity_mutation_grants WHERE id=$1`, id).Scan(&ns, &p.Environment, &p.Domain, &p.Dimension); err != nil {
		return err
	}
	if err = lockMutationScope(ctx, tx, ns, p); err != nil {
		return err
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR UPDATE`, id).Scan(&raw); err != nil {
		return err
	}
	var record capacityMutationRecord
	if err = json.Unmarshal(raw, &record); err != nil {
		return err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return err
	}
	if err = fn(tx, &record, ns, p, now.UTC()); err != nil {
		return err
	}
	if err = saveMutationGrant(ctx, tx, record); err != nil {
		return err
	}
	return tx.Commit()
}

func (s CapacityStore) RedeemMutation(ctx context.Context, principal string, r model.CapacityMutationRedeemRequest) (model.CapacityMutationRedeemResponse, error) {
	response := model.CapacityMutationRedeemResponse{Mode: "read_only", GrantID: r.GrantID, AttemptID: r.AttemptID, RequestSHA256: r.RequestSHA256}
	if !validCapacityExecutor(r.AttemptID) || !capacity.ValidDigest(r.SettlementTokenSHA256) {
		return response, ErrCapacityMutationAuthorization
	}
	err := s.callbackTransaction(ctx, r.GrantID, func(tx *sql.Tx, record *capacityMutationRecord, ns string, scope model.CapacityPolicySpec, now time.Time) error {
		g, b := record.Grant, record.Binding
		if principal != b.AdapterPrincipalID || r.Capability != g.Capability || r.IntegrationInstanceID != g.IntegrationInstanceID || r.ScopeChecksum != g.ScopeChecksum || r.ProfileName != g.ProfileName || r.Slot != g.Slot || r.RequestSHA256 != g.RequestSHA256 || r.ExpectedResourceID != g.ExpectedResourceID || r.ExpectedResourceCreatedAt != g.ExpectedResourceCreatedAt {
			return ErrCapacityMutationAuthorization
		}
		response.ExpiresAt = g.ExpiresAt.Format(time.RFC3339Nano)
		// This includes a replay with the original attempt ID. A lost reply
		// cannot reacquire permission to send another native mutation.
		if g.State != "issued" {
			return nil
		}
		if !g.ExpiresAt.After(now) {
			record.Grant.State = "expired"
			return nil
		}
		if !s.ExecutionEnabled {
			return ErrCapacityDisabled
		}
		var raw []byte
		var active bool
		var checksum string
		if err := tx.QueryRowContext(ctx, `SELECT spec,active,checksum FROM public.manifests WHERE id=$1 AND kind='capacity_policy' FOR SHARE`, record.PolicyID).Scan(&raw, &active, &checksum); err != nil {
			return err
		}
		var p model.CapacityPolicySpec
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
		if !active || checksum != record.PolicyChecksum || !p.ExecutionEnabled {
			return ErrCapacityDisabled
		}
		if err := checkMutationIntegration(ctx, tx, b); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' FOR SHARE`, record.WorkflowID).Scan(&active); err != nil {
			return err
		}
		if !active {
			return ErrCapacityConflict
		}
		intent, err := loadCapacityIntent(ctx, tx, ns, scope, true)
		if err != nil {
			return err
		}
		store := s
		store.ExecutorID = record.ExecutorID
		policy := model.Manifest{ID: record.PolicyID, Checksum: record.PolicyChecksum}
		if err = store.checkLease(p, policy, &intent, record.Generation, record.FencingToken, record.LeaseOwner, now); err != nil {
			return err
		}
		if !capacityProfileCurrent(p, intent.Decision, now) {
			return ErrCapacityConflict
		}
		record.AttemptID, record.SettlementTokenSHA256, record.Grant.State = r.AttemptID, r.SettlementTokenSHA256, "redeemed"
		response.Mode = "write_once"
		return nil
	})
	return response, err
}

func (s CapacityStore) MutationReceipt(ctx context.Context, principal, id string) (model.CapacityMutationReceipt, error) {
	var result model.CapacityMutationReceipt
	if !validCapacityExecutor(id) {
		return result, ErrCapacityMutationAuthorization
	}
	var raw []byte
	if err := s.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, id).Scan(&raw); err != nil {
		return result, err
	}
	var record capacityMutationRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return result, err
	}
	if record.Binding.AdapterPrincipalID != principal {
		return result, ErrCapacityMutationAuthorization
	}
	result.Grant, result.AttemptID = record.Grant, record.AttemptID
	if record.Settlement != nil {
		r := record.Settlement
		result.Outcome, result.TransportCompleted, result.ResourceID, result.ResourceCreatedAt, result.ActionID, result.NextActionIDs = r.Outcome, r.TransportCompleted, r.ResourceID, r.ResourceCreatedAt, r.ActionID, append([]string(nil), r.NextActionIDs...)
		result.AuxiliaryResources = append([]model.CapacityMutationAuxiliaryResource(nil), r.AuxiliaryResources...)
		result.AuxiliaryInventoryComplete = r.AuxiliaryInventoryComplete
	}
	return result, nil
}

var mutationErrorCodePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{0,64}$`)

func (s CapacityStore) SettleMutation(ctx context.Context, principal, nonce string, r model.CapacityMutationSettleRequest) (model.CapacityMutationGrant, error) {
	var result model.CapacityMutationGrant
	if len(nonce) < 32 || len(nonce) > 256 || !r.TransportCompleted || !validCapacityExecutor(r.AttemptID) || !capacity.ValidDigest(r.RequestSHA256) || !mutationErrorCodePattern.MatchString(r.ProviderErrorCode) {
		return result, ErrCapacityMutationAuthorization
	}
	if r.Outcome != "accepted" && r.Outcome != "uncertain" && r.Outcome != "rejected_before_send" && r.Outcome != "provider_rejected" {
		return result, ErrCapacityMutationAuthorization
	}
	err := s.callbackTransaction(ctx, r.GrantID, func(_ *sql.Tx, record *capacityMutationRecord, _ string, _ model.CapacityPolicySpec, now time.Time) error {
		digest := sha256.Sum256([]byte(nonce))
		expected, err := hex.DecodeString(record.SettlementTokenSHA256)
		if err != nil || subtle.ConstantTimeCompare(digest[:], expected) != 1 || principal != record.Binding.AdapterPrincipalID || record.AttemptID != r.AttemptID || record.Grant.RequestSHA256 != r.RequestSHA256 {
			return ErrCapacityMutationAuthorization
		}
		observed, err := time.Parse(time.RFC3339Nano, r.ObservedAt)
		if err != nil || observed.Before(record.CreatedAt.Add(-5*time.Second)) || observed.After(now.Add(5*time.Second)) {
			return ErrCapacityMutationAuthorization
		}
		if !validMutationIdentity(r.ResourceID, r.ResourceCreatedAt, r.Outcome == "accepted") || !validMutationActions(r.ActionID, r.NextActionIDs, r.Outcome == "accepted") {
			return ErrCapacityMutationAuthorization
		}
		if !validMutationAuxiliaries(r.AuxiliaryResources) {
			return ErrCapacityMutationAuthorization
		}
		if record.Grant.Capability == record.Binding.DestroyCapability && r.Outcome == "accepted" {
			if !r.AuxiliaryInventoryComplete {
				return ErrCapacityMutationAuthorization
			}
			for _, resource := range r.AuxiliaryResources {
				if !resource.RequiresAbsence {
					return ErrCapacityMutationAuthorization
				}
			}
		}
		if r.ResourceID != "" && record.Grant.Capability == record.Binding.EnsureCapability {
			created, _ := time.Parse(time.RFC3339Nano, r.ResourceCreatedAt)
			if created.Before(record.CreatedAt.Add(-5*time.Second)) || created.After(observed.Add(5*time.Second)) {
				return ErrCapacityMutationAuthorization
			}
		}
		if r.Outcome == "rejected_before_send" && (r.ResourceID != "" || r.ResourceCreatedAt != "" || r.ActionID != "" || len(r.NextActionIDs) != 0 || len(r.AuxiliaryResources) != 0 || r.AuxiliaryInventoryComplete) {
			return ErrCapacityMutationAuthorization
		}
		if r.Outcome == "provider_rejected" {
			if r.ResourceID != "" || r.ResourceCreatedAt != "" || r.ActionID != "" || len(r.NextActionIDs) != 0 || len(r.AuxiliaryResources) != 0 || r.AuxiliaryInventoryComplete {
				return ErrCapacityMutationAuthorization
			}
			allowed := false
			for _, rejection := range record.Binding.DefinitiveRejections {
				if rejection.StatusCode == r.ProviderStatusCode && rejection.ErrorCode == r.ProviderErrorCode {
					allowed = true
				}
			}
			if !allowed {
				return ErrCapacityMutationAuthorization
			}
		} else if r.ProviderStatusCode != 0 {
			return ErrCapacityMutationAuthorization
		}
		if record.Grant.ExpectedResourceID != "" && r.ResourceID != "" && (record.Grant.ExpectedResourceID != r.ResourceID || record.Grant.ExpectedResourceCreatedAt != r.ResourceCreatedAt) {
			return ErrCapacityMutationAuthorization
		}
		if record.Settlement != nil {
			old, _ := json.Marshal(record.Settlement)
			fresh, _ := json.Marshal(r)
			if string(old) != string(fresh) {
				return ErrCapacityConflict
			}
			result = record.Grant
			return nil
		}
		if record.Grant.State != "redeemed" {
			return ErrCapacityConflict
		}
		record.Settlement = &r
		record.Grant.State = "settled"
		if r.Outcome == "rejected_before_send" || r.Outcome == "provider_rejected" {
			record.Grant.State = "rejected"
		}
		result = record.Grant
		return nil
	})
	return result, err
}

func validMutationIdentity(id, created string, required bool) bool {
	if id == "" || created == "" {
		return !required && id == "" && created == ""
	}
	date, err := time.Parse(time.RFC3339Nano, created)
	return len(id) <= 128 && err == nil && !date.IsZero()
}

func validMutationActions(first string, next []string, required bool) bool {
	if required && first == "" || len(next) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, id := range append([]string{first}, next...) {
		if id == "" && !required && len(next) == 0 {
			continue
		}
		if id == "" || len(id) > 256 || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

func validMutationProof(p model.CapacityPolicySpec, proof model.CapacityMutationProof, now time.Time) bool {
	return proof.OwnerVerified && proof.SpecVerified && proof.ReceiptRef != "" && len(proof.ReceiptRef) <= 512 && capacity.Fresh(proof.ObservedAt, now, p.MaxEvidenceAgeSeconds) && validMutationIdentity(proof.ResourceID, proof.ResourceCreatedAt, true)
}

var mutationAuxiliaryKindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func validMutationAuxiliaries(resources []model.CapacityMutationAuxiliaryResource) bool {
	if len(resources) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, resource := range resources {
		key := resource.Kind + "/" + resource.ID
		if !mutationAuxiliaryKindPattern.MatchString(resource.Kind) || resource.ID == "" || len(resource.ID) > 256 || seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}

// RecordMutationSlot registers an exact existing native tuple from a protected
// fresh read. It never adopts drift, overwrites a tombstone, or performs a write.
func (s CapacityStore) RecordMutationSlot(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, issue model.CapacityMutationIssue, proof model.CapacityMutationProof) error {
	return s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, _ model.CapacityIntent, now time.Time) error {
		plan, err := capacity.PrepareMutationPlan(p, issue)
		if err != nil {
			return err
		}
		b := plan.Binding
		if err = lockNativeMutationSlot(ctx, tx, b, plan.Slot); err != nil {
			return err
		}
		if plan.Capability != b.EnsureCapability || proof.ResourceAbsent || proof.BindingName != b.Name || proof.Slot != plan.Slot || proof.RequestSHA256 != plan.RequestSHA256 || !validMutationProof(p, proof, now) {
			return ErrCapacityConflict
		}
		if err = checkMutationIntegration(ctx, tx, b); err != nil {
			return err
		}
		var count, history int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE state IN ('issued','redeemed','settled')),count(*) FROM public.capacity_mutation_grants WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, plan.Slot).Scan(&count, &history); err != nil {
			return err
		}
		if count != 0 {
			return ErrCapacityConflict
		}
		old, exists, err := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, plan.Slot)
		if err != nil {
			return err
		}
		if !exists && history != 0 {
			return ErrCapacityConflict
		}
		if exists && (old.Tombstone || old.ResourceID != proof.ResourceID || old.ResourceCreatedAt != proof.ResourceCreatedAt || old.DesiredSpecSHA256 != plan.RequestSHA256) {
			return ErrCapacityConflict
		}
		return saveMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, plan.Slot, capacityResourceSlot{BindingName: b.Name, ProfileName: b.ProfileName, DesiredSpecSHA256: plan.RequestSHA256, ResourceID: proof.ResourceID, ResourceCreatedAt: proof.ResourceCreatedAt, ReceiptRef: proof.ReceiptRef, ObservedAt: proof.ObservedAt})
	})
}

// ConfirmMutation is available inside the fixed protected workflow, including a
// historical recovery lease. Native action proof cannot substitute for missing
// owning-transport settlement. No current GET proves a lost POST never arrived.
func (s CapacityStore) ConfirmMutation(ctx context.Context, policy model.Manifest, generation, fence int64, owner string, proof model.CapacityMutationProof) (model.CapacityMutationGrant, error) {
	var result model.CapacityMutationGrant
	err := s.mutationTransaction(ctx, policy, true, generation, fence, owner, func(tx *sql.Tx, p model.CapacityPolicySpec, _ model.CapacityIntent, now time.Time) error {
		var raw []byte
		if err := tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2 AND environment=$3 AND domain=$4 AND dimension=$5 AND generation=$6`, proof.GrantID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, generation).Scan(&raw); err != nil {
			return err
		}
		var record capacityMutationRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return err
		}
		g, b := record.Grant, record.Binding
		if err := lockNativeMutationSlot(ctx, tx, b, g.Slot); err != nil {
			return err
		}
		if record.PolicyID == policy.ID && record.PolicyChecksum == policy.Checksum && record.WorkflowID == s.WorkflowID && g.State == "confirmed" && record.Proof != nil {
			previous, _ := json.Marshal(record.Proof)
			requested, _ := json.Marshal(proof)
			if string(previous) == string(requested) {
				result = g
				return nil
			}
		}
		if record.PolicyID != policy.ID || record.PolicyChecksum != policy.Checksum || record.WorkflowID != s.WorkflowID || g.State != "settled" || record.Settlement == nil || !record.Settlement.TransportCompleted || proof.BindingName != b.Name || proof.Slot != g.Slot || proof.RequestSHA256 != g.RequestSHA256 || !validMutationProof(p, proof, now) || !proof.ActionsTerminal || !proof.ActionsSuccessful || len(proof.ActionIDs) == 0 || len(proof.ActionIDs) > 64 {
			return ErrCapacityConflict
		}
		seen := map[string]bool{}
		for _, id := range proof.ActionIDs {
			if id == "" || len(id) > 256 || seen[id] {
				return ErrCapacityConflict
			}
			seen[id] = true
		}
		settled := record.Settlement
		if settled.ResourceID != "" && (settled.ResourceID != proof.ResourceID || settled.ResourceCreatedAt != proof.ResourceCreatedAt) {
			return ErrCapacityConflict
		}
		if g.Capability == b.EnsureCapability {
			if proof.ObservedCreationGrantID != g.GrantID {
				return ErrCapacityConflict
			}
			created, _ := time.Parse(time.RFC3339Nano, proof.ResourceCreatedAt)
			if created.Before(record.CreatedAt.Add(-5*time.Second)) || created.After(proof.ObservedAt.Add(5*time.Second)) {
				return ErrCapacityConflict
			}
		}
		for _, id := range append([]string{settled.ActionID}, settled.NextActionIDs...) {
			if id != "" && !slices.Contains(proof.ActionIDs, id) {
				return ErrCapacityConflict
			}
		}
		slot, exists, err := loadMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, g.Slot)
		if err != nil {
			return err
		}
		if g.Capability == b.DestroyCapability {
			if !settled.AuxiliaryInventoryComplete || !validMutationAuxiliaries(proof.AuxiliaryAbsent) {
				return ErrCapacityConflict
			}
			for _, aux := range settled.AuxiliaryResources {
				found := false
				for _, absent := range proof.AuxiliaryAbsent {
					if aux.Kind == absent.Kind && aux.ID == absent.ID {
						found = true
					}
				}
				if aux.RequiresAbsence && !found {
					return ErrCapacityConflict
				}
			}
			if !proof.ResourceAbsent || !exists || slot.ResourceID != g.ExpectedResourceID || slot.ResourceCreatedAt != g.ExpectedResourceCreatedAt || proof.ResourceID != g.ExpectedResourceID || proof.ResourceCreatedAt != g.ExpectedResourceCreatedAt || g.Slot <= b.ProtectedSlots {
				return ErrCapacityConflict
			}
			slot.ResourceID = ""
			slot.Tombstone = true
		} else {
			if proof.ResourceAbsent || (exists && slot.ResourceID != "") {
				return ErrCapacityConflict
			}
			slot = capacityResourceSlot{BindingName: b.Name, ProfileName: b.ProfileName, DesiredSpecSHA256: g.RequestSHA256, ResourceID: proof.ResourceID, ResourceCreatedAt: proof.ResourceCreatedAt}
		}
		slot.ReceiptRef, slot.ObservedAt = proof.ReceiptRef, proof.ObservedAt
		if err = saveMutationSlot(ctx, tx, policy.Metadata.Namespace, p, b, g.Slot, slot); err != nil {
			return err
		}
		record.Grant.State = "confirmed"
		record.Proof = &proof
		result = record.Grant
		if err = saveMutationGrant(ctx, tx, record); err != nil {
			return err
		}
		return emitCapacityMutationEvent(ctx, tx, policy.Metadata.Namespace, p, record, proof, now)
	})
	return result, err
}

// Snapshot event routing from the exact registered type at issuance. Recovery
// does not depend on a later active type or reinterpret an old native effect.
func capacityMutationEventIdentity(ctx context.Context, tx *sql.Tx, b model.CapacityMutationBinding) (string, string, error) {
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1 AND checksum=$2 AND kind='integration_type' FOR SHARE`, b.IntegrationTypeID, b.IntegrationTypeChecksum).Scan(&raw); err != nil {
		return "", "", err
	}
	var spec model.IntegrationTypeManifestSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		return "", "", err
	}
	resource := strings.TrimPrefix(b.EnsureCapability, "ensure_")
	if !mutationAuxiliaryKindPattern.MatchString(spec.Provider) || !mutationAuxiliaryKindPattern.MatchString(resource) || len(spec.Provider)+len(resource)+1 > 64 || b.DestroyCapability != "destroy_"+resource || !slices.Contains(spec.Capabilities, b.EnsureCapability) || !slices.Contains(spec.Capabilities, b.DestroyCapability) {
		return "", "", ErrCapacityConflict
	}
	return spec.Provider, resource, nil
}

func emitCapacityMutationEvent(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec, record capacityMutationRecord, proof model.CapacityMutationProof, now time.Time) error {
	verb := "ensured"
	if record.Grant.Capability == record.Binding.DestroyCapability {
		verb = "destroyed"
	}
	if !mutationAuxiliaryKindPattern.MatchString(record.EventProvider) || !mutationAuxiliaryKindPattern.MatchString(record.EventResource) {
		return ErrCapacityConflict
	}
	_, err := EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          record.EventProvider + "." + record.EventResource + "." + verb,
		SchemaVersion: "v1", AggregateType: record.EventProvider + "_" + record.EventResource, AggregateID: proof.ResourceID,
		Actor:          &model.EventActor{Type: "workflow", ID: record.WorkflowID.String()},
		IdempotencyKey: "capacity-mutation/" + record.Grant.GrantID,
		Payload:        map[string]any{"provider": record.EventProvider, "resource": record.EventResource, "verb": verb, "resource_id": proof.ResourceID, "instance_id": record.Grant.IntegrationInstanceID, "emitted_at": now.Format(time.RFC3339Nano), "observed": map[string]any{"grant_id": record.Grant.GrantID, "scope_checksum": record.Grant.ScopeChecksum, "profile_name": record.Grant.ProfileName, "slot": record.Grant.Slot, "resource_created_at": proof.ResourceCreatedAt, "action_ids": proof.ActionIDs, "receipt_ref": proof.ReceiptRef}},
		Metadata:       map[string]any{"namespace": namespace, "environment": p.Environment, "domain": p.Domain, "dimension": p.Dimension, "instance_id": record.Grant.IntegrationInstanceID, "source": "integration_mutation", "idempotency": "capacity-mutation/" + record.Grant.GrantID},
	})
	return err
}
