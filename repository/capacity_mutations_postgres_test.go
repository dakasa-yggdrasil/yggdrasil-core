package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type mutationFixture struct {
	db        *sql.DB
	policy    model.Manifest
	store     CapacityStore
	a         model.CapacityAssessment
	intent    model.CapacityIntent
	binding   model.CapacityMutationBinding
	plans     map[int]model.CapacityMutationIssue
	alternate map[int]model.CapacityMutationIssue
	created   string
}

func mutationPostgresFixture(t *testing.T, register bool) mutationFixture {
	t.Helper()
	db, original, a := capacityPostgresFixture(t)
	ctx := context.Background()
	create := func(kind, name string, spec any) model.Manifest {
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		m, err := CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "yggdrasil.io/v1alpha1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: original.Metadata.Namespace, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	wf := create("workflow", "scale-api", map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": original.Metadata.Namespace, "name": "scale-rbac"}}})
	ty := create("integration_type", "fleet-type", map[string]any{"provider": "fixture", "revision": "1", "capabilities": []string{"ensure_server", "destroy_server"}})
	instance := create("integration_instance", "fleet", map[string]any{"type_ref": model.ManifestSelector{ManifestID: ty.ID.String()}})
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(original.Spec, &p); err != nil {
		t.Fatal(err)
	}
	p.LeaseSeconds = 120
	b := model.CapacityMutationBinding{Name: "burst", IntegrationInstanceID: instance.ID.String(), IntegrationChecksum: instance.Checksum, IntegrationTypeID: ty.ID.String(), IntegrationTypeChecksum: ty.Checksum, AdapterPrincipalID: "fleet-adapter", ScopeChecksum: strings.Repeat("a", 64), ProfileName: "base", EnsureCapability: "ensure_server", DestroyCapability: "destroy_server", ProtectedSlots: 2, MaxSlots: 20}
	plans := map[int]model.CapacityMutationIssue{}
	for slot := 1; slot <= b.MaxSlots; slot++ {
		raw, _ := json.Marshal(map[string]any{"schema_version": "capacity_vm_slot_v1", "capability": b.EnsureCapability, "integration_instance_id": b.IntegrationInstanceID, "scope_checksum": b.ScopeChecksum, "profile_name": b.ProfileName, "profile_checksum": strings.Repeat("c", 64), "admission_checksum": strings.Repeat("d", 64), "slot": slot, "native_name": fmt.Sprintf("node-%d", slot), "bootstrap_sha256": strings.Repeat("b", 64)})
		var approved *model.CapacityMutationSpecV1
		if err := json.Unmarshal(raw, &approved); err != nil {
			t.Fatal(err)
		}
		b.Slots = append(b.Slots, model.CapacityMutationSlotBinding{Slot: slot, DesiredSpecSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), DesiredSpec: approved})
		plans[slot] = model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw}
	}
	alt := b
	alt.Name = "burst-alt"
	alt.ProfileName = "alternate"
	alt.ProtectedSlots = 0
	alt.Slots = nil
	alternate := map[int]model.CapacityMutationIssue{}
	for slot := 1; slot <= alt.MaxSlots; slot++ {
		var spec map[string]any
		_ = json.Unmarshal(plans[slot].DesiredSpec, &spec)
		spec["profile_name"] = alt.ProfileName
		spec["native_name"] = fmt.Sprintf("alternate-%d", slot)
		raw, _ := json.Marshal(spec)
		alternate[slot] = model.CapacityMutationIssue{BindingName: alt.Name, DesiredSpec: raw}
		var approved *model.CapacityMutationSpecV1
		if err := json.Unmarshal(raw, &approved); err != nil {
			t.Fatal(err)
		}
		alt.Slots = append(alt.Slots, model.CapacityMutationSlotBinding{Slot: slot, DesiredSpecSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), DesiredSpec: approved})
	}
	profile := p.Profiles[0]
	profile.Name = alt.ProfileName
	profile.UnitMonthlyCostMinor = 200
	p.Profiles = append(p.Profiles, profile)
	p.MutationBindings = []model.CapacityMutationBinding{b, alt}
	policy := create("capacity_policy", "api", p)
	store := CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString()}
	intent, err := store.Assess(ctx, policy, a)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = store.Claim(ctx, policy, intent.Generation, a)
	if err != nil {
		t.Fatal(err)
	}
	f := mutationFixture{db: db, policy: policy, store: store, a: a, intent: intent, binding: b, plans: plans, alternate: alternate, created: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)}
	t.Cleanup(func() {
		if _, err := db.ExecContext(ctx, `DELETE FROM public.event_log WHERE metadata->>'namespace'=$1`, policy.Metadata.Namespace); err != nil {
			t.Error(err)
		}
		for _, table := range []string{"capacity_mutation_grants", "capacity_resource_slots"} {
			if _, err := db.ExecContext(ctx, `DELETE FROM public.`+table+` WHERE namespace=$1`, policy.Metadata.Namespace); err != nil {
				t.Error(err)
			}
		}
	})
	if register {
		for slot := 1; slot <= 4; slot++ {
			f.record(t, slot)
		}
	}
	return f
}

func (f mutationFixture) proof(t *testing.T, slot int) model.CapacityMutationProof {
	t.Helper()
	var p model.CapacityPolicySpec
	_ = json.Unmarshal(f.policy.Spec, &p)
	plan, err := capacity.PrepareMutationPlan(p, f.plans[slot])
	if err != nil {
		t.Fatal(err)
	}
	return model.CapacityMutationProof{BindingName: f.binding.Name, Slot: slot, ResourceID: fmt.Sprintf("resource-%d", slot), ResourceCreatedAt: f.created, RequestSHA256: plan.RequestSHA256, ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:native-read", OwnerVerified: true, SpecVerified: true}
}

func (f mutationFixture) record(t *testing.T, slot int) {
	t.Helper()
	if err := f.store.RecordMutationSlot(context.Background(), f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[slot], f.proof(t, slot)); err != nil {
		t.Fatal(err)
	}
}

func (f mutationFixture) issue(t *testing.T, slot int) model.CapacityMutationGrant {
	t.Helper()
	g, err := f.store.IssueMutation(context.Background(), f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[slot])
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func mutationRedeem(g model.CapacityMutationGrant, nonce string) model.CapacityMutationRedeemRequest {
	return model.CapacityMutationRedeemRequest{GrantID: g.GrantID, AttemptID: uuid.NewString(), SettlementTokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(nonce))), Capability: g.Capability, IntegrationInstanceID: g.IntegrationInstanceID, ScopeChecksum: g.ScopeChecksum, ProfileName: g.ProfileName, Slot: g.Slot, RequestSHA256: g.RequestSHA256, ExpectedResourceID: g.ExpectedResourceID, ExpectedResourceCreatedAt: g.ExpectedResourceCreatedAt, CompensationOf: g.CompensationOf}
}

func mutationSettlement(r model.CapacityMutationRedeemRequest, created string) model.CapacityMutationSettleRequest {
	if strings.HasPrefix(r.Capability, "ensure_") {
		created = time.Now().UTC().Format(time.RFC3339Nano)
	}
	result := model.CapacityMutationSettleRequest{GrantID: r.GrantID, AttemptID: r.AttemptID, RequestSHA256: r.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: fmt.Sprintf("resource-%d", r.Slot), ResourceCreatedAt: created, ActionID: "native-action", NextActionIDs: []string{"bootstrap-action"}, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if strings.HasPrefix(r.Capability, "destroy_") {
		result.AuxiliaryInventoryComplete = true
		result.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "ip-fixture", RequiresAbsence: true}}
	}
	return result
}

func TestCapacityMutationPostgres(t *testing.T) {
	ctx := context.Background()
	t.Run("global_slot_registration_cannot_cross_policy_realms", func(t *testing.T) {
		f := mutationPostgresFixture(t, false)
		ns := "capacity-cross-" + uuid.NewString()
		otherPolicy, err := CreateManifestVersion(ctx, f.db, model.ManifestDocument{APIVersion: f.policy.APIVersion, Kind: "capacity_policy", Metadata: model.ManifestMetadataInput{Namespace: ns, Name: f.policy.Metadata.Name}, Spec: f.policy.Spec}, f.policy.Checksum)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			for _, table := range []string{"capacity_resource_slots", "capacity_mutation_grants", "capacity_intent_events", "capacity_intents", "manifests"} {
				if _, err := f.db.ExecContext(ctx, `DELETE FROM public.`+table+` WHERE namespace=$1`, ns); err != nil {
					t.Error(err)
				}
			}
		})
		otherStore := f.store
		otherStore.ExecutorID = uuid.NewString()
		lease, err := otherStore.Assess(ctx, otherPolicy, f.a)
		if err != nil {
			t.Fatal(err)
		}
		lease, err = otherStore.Claim(ctx, otherPolicy, lease.Generation, f.a)
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		outcomes := make(chan struct {
			namespace, id string
			err           error
		}, 2)
		for i := 0; i < 2; i++ {
			go func(i int) {
				<-start
				store, policy, intent := f.store, f.policy, f.intent
				if i == 1 {
					store, policy, intent = otherStore, otherPolicy, lease
				}
				proof := f.proof(t, 1)
				proof.ResourceID = fmt.Sprintf("cross-native-%d", i)
				err := store.RecordMutationSlot(ctx, policy, 1, intent.FencingToken, intent.LeaseOwner, f.plans[1], proof)
				outcomes <- struct {
					namespace, id string
					err           error
				}{policy.Metadata.Namespace, proof.ResourceID, err}
			}(i)
		}
		close(start)
		wins := 0
		winnerNS, winnerID := "", ""
		for i := 0; i < 2; i++ {
			result := <-outcomes
			if result.err == nil {
				wins++
				winnerNS, winnerID = result.namespace, result.id
			} else if !errors.Is(result.err, ErrCapacityConflict) {
				t.Fatal(result.err)
			}
		}
		var storedNS, storedID string
		if err = f.db.QueryRowContext(ctx, `SELECT namespace,resource_id FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=1`, f.binding.IntegrationInstanceID, f.binding.ScopeChecksum, f.binding.ProfileName).Scan(&storedNS, &storedID); err != nil {
			t.Fatal(err)
		}
		if wins != 1 || storedNS != winnerNS || storedID != winnerID {
			t.Fatalf("foreign upsert overwrote native slot: wins=%d owner=%s id=%s", wins, storedNS, storedID)
		}
	})
	t.Run("native_profiles_have_independent_slot_identities", func(t *testing.T) {
		f := mutationPostgresFixture(t, false)
		f.record(t, 1)
		var p model.CapacityPolicySpec
		_ = json.Unmarshal(f.policy.Spec, &p)
		plan, err := capacity.PrepareMutationPlan(p, f.alternate[1])
		if err != nil {
			t.Fatal(err)
		}
		proof := f.proof(t, 1)
		proof.BindingName = plan.Binding.Name
		proof.ResourceID = "alternate-native-1"
		proof.RequestSHA256 = plan.RequestSHA256
		if err = f.store.RecordMutationSlot(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, f.alternate[1], proof); err != nil {
			t.Fatal(err)
		}
		var count int
		if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND scope_checksum=$2 AND slot=1`, f.binding.IntegrationInstanceID, f.binding.ScopeChecksum).Scan(&count); err != nil || count != 2 {
			t.Fatal(count, err)
		}
	})
	t.Run("paused_unredeemed_expiry_can_reconcile_without_native_fence", func(t *testing.T) {
		f := mutationPostgresFixture(t, true)
		g := f.issue(t, 5)
		if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1`, g.GrantID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		recovery := f.store
		recovery.ExecutionEnabled = false
		recovery.ExecutorID = uuid.NewString()
		lease, err := recovery.Recover(ctx, f.policy, 1, freshCapacityTestAssessment(f.a, 4))
		if err != nil {
			t.Fatal(err)
		}
		proof := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(f.a, 4), ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:never-redeemed", Healthy: true, Inflight: capacityTestCount(0), MutationInflight: capacityTestCount(0), NoMutationVerified: true, MutationAuthorityKind: "core_mutation_grants"}
		result, err := recovery.Reconcile(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, "aborted", proof)
		if err != nil || result.Phase != "aborted" {
			t.Fatal(result, err)
		}
		var state string
		if err = f.db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, g.GrantID).Scan(&state); err != nil || state != "expired" {
			t.Fatal(state, err)
		}
	})
	t.Run("concurrent_issue_and_single_redemption", func(t *testing.T) {
		f := mutationPostgresFixture(t, true)
		var wg sync.WaitGroup
		var lock sync.Mutex
		grants := map[string]bool{}
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				g, err := f.store.IssueMutation(ctx, f.policy, f.intent.Generation, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[5])
				if err != nil {
					t.Error(err)
					return
				}
				lock.Lock()
				grants[g.GrantID] = true
				lock.Unlock()
			}()
		}
		wg.Wait()
		if len(grants) != 1 {
			t.Fatalf("duplicate durable reservations: %v", grants)
		}
		g := f.issue(t, 5)
		var writes atomic.Int32
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := mutationRedeem(g, uuid.NewString())
				response, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, r)
				if err != nil {
					t.Error(err)
					return
				}
				if response.Mode == "write_once" {
					writes.Add(1)
				}
			}()
		}
		wg.Wait()
		if writes.Load() != 1 {
			t.Fatalf("native send permissions=%d", writes.Load())
		}
	})
	t.Run("lost_reply_same_attempt_is_read_only", func(t *testing.T) {
		f := mutationPostgresFixture(t, true)
		g := f.issue(t, 5)
		nonce := uuid.NewString()
		r := mutationRedeem(g, nonce)
		first, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, r)
		if err != nil || first.Mode != "write_once" {
			t.Fatal(first, err)
		}
		replay, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, r)
		if err != nil || replay.Mode != "read_only" {
			t.Fatal(replay, err)
		}
		settle := model.CapacityMutationSettleRequest{GrantID: g.GrantID, AttemptID: r.AttemptID, RequestSHA256: g.RequestSHA256, Outcome: "rejected_before_send", TransportCompleted: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		if _, err = f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); err != nil {
			t.Fatal("idempotent settlement", err)
		}
		next := f.issue(t, 5)
		if next.GrantID == g.GrantID {
			t.Fatal("retired unsent grant reused")
		}
	})
	t.Run("settlement_nonce_scope_pause_and_private_receipt", func(t *testing.T) {
		f := mutationPostgresFixture(t, true)
		g := f.issue(t, 5)
		nonce := uuid.NewString()
		r := mutationRedeem(g, nonce)
		if _, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, r); err != nil {
			t.Fatal(err)
		}
		settle := mutationSettlement(r, f.created)
		if _, err := f.store.SettleMutation(ctx, "other", nonce, settle); !errors.Is(err, ErrCapacityMutationAuthorization) {
			t.Fatal(err)
		}
		if _, err := f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, uuid.NewString(), settle); !errors.Is(err, ErrCapacityMutationAuthorization) {
			t.Fatal(err)
		}
		paused := f.store
		paused.ExecutionEnabled = false
		if _, err := paused.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); err != nil {
			t.Fatal("pause lost owning transport receipt", err)
		}
		receipt, err := paused.MutationReceipt(ctx, f.binding.AdapterPrincipalID, g.GrantID)
		if err != nil || receipt.ResourceID != settle.ResourceID || receipt.ActionID != settle.ActionID || !receipt.TransportCompleted {
			t.Fatal(receipt, err)
		}
		encoded, _ := json.Marshal(receipt)
		for _, private := range []string{nonce, r.SettlementTokenSHA256, f.intent.LeaseOwner, f.store.ExecutorID} {
			if strings.Contains(string(encoded), private) {
				t.Fatal("private authority leaked")
			}
		}
		if _, err = paused.MutationReceipt(ctx, "other", g.GrantID); !errors.Is(err, ErrCapacityMutationAuthorization) {
			t.Fatal(err)
		}
		settle.ActionID = "different"
		if _, err = paused.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("conflicting receipt overwritten", err)
		}
	})
	t.Run("unresolved_mutation_blocks_terminal_and_expiry_reissue", func(t *testing.T) {
		f := mutationPostgresFixture(t, true)
		g := f.issue(t, 5)
		r := mutationRedeem(g, uuid.NewString())
		if _, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, r); err != nil {
			t.Fatal(err)
		}
		proof := model.CapacityTransitionProof{Assessment: f.a, ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:ready", Healthy: true, Inflight: capacityTestCount(0)}
		for _, phase := range []string{"prepared", "canary"} {
			if _, err := f.store.Advance(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, phase, proof); err != nil {
				t.Fatal(err)
			}
		}
		proof.Assessment.Snapshot.Units = f.intent.Decision.Units
		if _, err := f.store.Advance(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, "promoted", proof); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("unsettled authority promoted", err)
		}
		if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1`, g.GrantID); err != nil {
			t.Fatal(err)
		}
		replay, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, r)
		if err != nil || replay.Mode != "read_only" {
			t.Fatal(replay, err)
		}
		var state string
		if err = f.db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, g.GrantID).Scan(&state); err != nil || state != "redeemed" {
			t.Fatal(state, err)
		}
	})
	t.Run("native_action_cannot_replace_transport_settlement", func(t *testing.T) {
		f := mutationPostgresFixture(t, true)
		g := f.issue(t, 5)
		nonce := uuid.NewString()
		r := mutationRedeem(g, nonce)
		if _, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, r); err != nil {
			t.Fatal(err)
		}
		proof := f.proof(t, 5)
		proof.GrantID = g.GrantID
		proof.ActionsTerminal = true
		proof.ActionsSuccessful = true
		proof.ActionIDs = []string{"native-action", "bootstrap-action"}
		if _, err := f.store.ConfirmMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, proof); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("missing transport settled by GET", err)
		}
		settle := mutationSettlement(r, f.created)
		if _, err := f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); err != nil {
			t.Fatal(err)
		}
		var auditCount int
		if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+g.GrantID).Scan(&auditCount); err != nil || auditCount != 0 {
			t.Fatal("accepted transport emitted an applied event", auditCount, err)
		}
		proof.ResourceCreatedAt = settle.ResourceCreatedAt
		proof.ObservedCreationGrantID = g.GrantID
		proof.ActionIDs = []string{"native-action"}
		if _, err := f.store.ConfirmMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, proof); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("unobserved next action", err)
		}
		proof.ActionIDs = []string{"native-action", "bootstrap-action"}
		proof.ResourceID = "replacement"
		if _, err := f.store.ConfirmMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, proof); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("native replacement adopted", err)
		}
		proof.ResourceID = settle.ResourceID
		for _, creationGrantID := range []string{"", uuid.NewString()} {
			proof.ObservedCreationGrantID = creationGrantID
			if _, err := f.store.ConfirmMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, proof); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("creation identity without its exact native grant label", err)
			}
		}
		proof.ObservedCreationGrantID = g.GrantID
		result, err := f.store.ConfirmMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, proof)
		if err != nil || result.State != "confirmed" {
			t.Fatal(result, err)
		}
		if _, err = f.store.ConfirmMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, proof); err != nil {
			t.Fatal("exact confirmation replay", err)
		}
		var eventType, aggregateType, resourceID, instanceID string
		if err := f.db.QueryRowContext(ctx, `SELECT type,aggregate_type,payload->>'resource_id',payload->>'instance_id' FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+g.GrantID).Scan(&eventType, &aggregateType, &resourceID, &instanceID); err != nil || eventType != "fixture.server.ensured" || aggregateType != "fixture_server" || resourceID != proof.ResourceID || instanceID != f.binding.IntegrationInstanceID {
			t.Fatal("canonical native event", eventType, resourceID, err)
		}
		if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+g.GrantID).Scan(&auditCount); err != nil || auditCount != 1 {
			t.Fatal("duplicate confirmation event", auditCount, err)
		}
	})
	t.Run("historical_recovery_confirms_after_pause", func(t *testing.T) {
		f := mutationPostgresFixture(t, true)
		g := f.issue(t, 5)
		nonce := uuid.NewString()
		r := mutationRedeem(g, nonce)
		if _, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, r); err != nil {
			t.Fatal(err)
		}
		settle := mutationSettlement(r, f.created)
		if _, err := f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, f.policy.ID); err != nil {
			t.Fatal(err)
		}
		recovery := f.store
		recovery.ExecutorID = uuid.NewString()
		recovery.ExecutionEnabled = false
		lease, err := recovery.Recover(ctx, f.policy, 1, freshCapacityTestAssessment(f.a, 4))
		if err != nil {
			t.Fatal(err)
		}
		proof := f.proof(t, 5)
		proof.GrantID = g.GrantID
		proof.ActionsTerminal = true
		proof.ActionsSuccessful = true
		proof.ActionIDs = []string{"native-action", "bootstrap-action"}
		proof.ResourceCreatedAt = settle.ResourceCreatedAt
		proof.ObservedCreationGrantID = g.GrantID
		result, err := recovery.ConfirmMutation(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, proof)
		if err != nil || result.State != "confirmed" {
			t.Fatal(result, err)
		}
	})
	t.Run("partial_recovery_matches_fresh_membership_and_allows_new_intent", func(t *testing.T) {
		f := mutationPostgresFixture(t, true)
		g := f.issue(t, 5)
		nonce := uuid.NewString()
		r := mutationRedeem(g, nonce)
		if _, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, r); err != nil {
			t.Fatal(err)
		}
		settled := mutationSettlement(r, f.created)
		if _, err := f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settled); err != nil {
			t.Fatal(err)
		}
		native := f.proof(t, 5)
		native.GrantID, native.ResourceCreatedAt, native.ObservedCreationGrantID = g.GrantID, settled.ResourceCreatedAt, g.GrantID
		native.ActionsTerminal, native.ActionsSuccessful = true, true
		native.ActionIDs = []string{"native-action", "bootstrap-action"}
		if _, err := f.store.ConfirmMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, native); err != nil {
			t.Fatal(err)
		}
		unsent := f.issue(t, 6)
		if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		recovery := f.store
		recovery.ExecutionEnabled, recovery.ExecutorID = false, uuid.NewString()
		lease, err := recovery.Recover(ctx, f.policy, 1, freshCapacityTestAssessment(f.a, 5))
		if err != nil {
			t.Fatal(err)
		}
		zero := 0
		proof := model.CapacityTransitionProof{Assessment: freshCapacityTestAssessment(f.a, 5), ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:complete-partial-inventory", Healthy: true, Inflight: &zero, MutationInflight: &zero, MutationAuthorityKind: "core_mutation_grants", MembershipComplete: true}
		if _, err := recovery.Reconcile(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", proof); err == nil {
			t.Fatal("partial recovery ignored an outstanding permission")
		}
		if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET expires_at=$2 WHERE id=$1`, unsent.GrantID, time.Now().Add(-time.Second)); err != nil {
			t.Fatal(err)
		}
		for _, scenario := range []string{"incomplete", "wrong_count", "outside_change", "no_mutation", "provider_fence"} {
			bad := proof
			switch scenario {
			case "incomplete":
				bad.MembershipComplete = false
			case "wrong_count":
				bad.Assessment.Snapshot.Units = 4
			case "outside_change":
				bad.Assessment.Snapshot.Units = 7
			case "no_mutation":
				bad.NoMutationVerified = true
			case "provider_fence":
				bad.ProviderFencingToken = lease.FencingToken
			}
			if _, err := recovery.Reconcile(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", bad); err == nil {
				t.Fatal("partial recovery accepted unsafe proof", scenario)
			}
		}
		if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_resource_slots SET slot_record=jsonb_set(slot_record,'{observed_at}',to_jsonb($2::text)) WHERE namespace=$1 AND slot=1`, f.policy.Metadata.Namespace, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := recovery.Reconcile(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", proof); err == nil {
			t.Fatal("partial recovery accepted stale membership")
		}
		if err := recovery.RecordMutationSlot(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, f.plans[7], f.proof(t, 7)); err == nil {
			t.Fatal("recovery registered a new native tuple")
		}
		for slot := 1; slot <= 5; slot++ {
			observed := f.proof(t, slot)
			if slot == 5 {
				observed.ResourceCreatedAt = settled.ResourceCreatedAt
			}
			if err := recovery.RecordMutationSlot(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, f.plans[slot], observed); err != nil {
				t.Fatal("read-only recovery did not refresh exact membership", slot, err)
			}
		}
		partial, err := recovery.Reconcile(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner, "reconciled_partial", proof)
		if err != nil || partial.Phase != "reconciled_partial" || partial.Assessment.Snapshot.Units != 5 || partial.LeaseOwner != "" || partial.Decision.ExecutionPermitted {
			t.Fatal("partial observed state did not close safely", partial, err)
		}
		if _, err := recovery.RenewRecovery(ctx, f.policy, 1, lease.FencingToken, lease.LeaseOwner); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("partial terminal state retained authority", err)
		}
		// Advance only the persisted cooldown clock, never wall-clock sleeps.
		if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{decision,clock,last_action_at}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		next, err := f.store.Assess(ctx, f.policy, freshCapacityTestAssessment(f.a, 5))
		if err != nil || next.Generation != 2 || next.Phase != "proposed" || next.Decision.Units != 7 {
			t.Fatal("partial state prevented a separately assessed new generation", next, err)
		}
	})
	t.Run("floor_drain_pending_delete_budget_and_tombstone", func(t *testing.T) {
		f := mutationPostgresFixture(t, true)
		// A fixture records a requested reduction. The real Advance method,
		// rather than a caller flag, must admit its drained transition.
		f.intent.Decision.Action = "drain"
		f.intent.Decision.Units = 2
		f.intent.Phase = "draining"
		raw, _ := json.Marshal(f.intent)
		if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=$2::jsonb WHERE namespace=$1`, f.policy.Metadata.Namespace, raw); err != nil {
			t.Fatal(err)
		}
		destroy := func(slot int) model.CapacityMutationIssue {
			var spec map[string]any
			_ = json.Unmarshal(f.plans[slot].DesiredSpec, &spec)
			spec["capability"] = f.binding.DestroyCapability
			spec["expected_resource_id"] = fmt.Sprintf("resource-%d", slot)
			spec["expected_resource_created_at"] = f.created
			encoded, _ := json.Marshal(spec)
			return model.CapacityMutationIssue{BindingName: f.binding.Name, DesiredSpec: encoded}
		}
		if _, err := f.store.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, destroy(4)); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("undrained delete admitted", err)
		}
		proof := model.CapacityTransitionProof{Assessment: f.a, ObservedAt: time.Now().UTC(), ReceiptRef: "fixture:drain", Healthy: true, Inflight: capacityTestCount(0)}
		if _, err := f.store.Advance(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, "drained", proof); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, destroy(2)); err == nil {
			t.Fatal("floor deletion admitted")
		}
		g, err := f.store.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, destroy(4))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, destroy(3)); err != nil {
			t.Fatal(err)
		}
		nonce := uuid.NewString()
		redeem := mutationRedeem(g, nonce)
		if _, err = f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, redeem); err != nil {
			t.Fatal(err)
		}
		settle := mutationSettlement(redeem, f.created)
		if _, err = f.store.SettleMutation(ctx, f.binding.AdapterPrincipalID, nonce, settle); err != nil {
			t.Fatal(err)
		}
		deleted := f.proof(t, 4)
		deleted.GrantID = g.GrantID
		deleted.RequestSHA256 = g.RequestSHA256
		deleted.ResourceAbsent = true
		deleted.ActionsTerminal = true
		deleted.ActionsSuccessful = true
		deleted.ActionIDs = []string{"native-action", "bootstrap-action"}
		if _, err = f.store.ConfirmMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, deleted); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("unobserved paid auxiliary disappearance", err)
		}
		deleted.AuxiliaryAbsent = []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "ip-fixture"}}
		if _, err = f.store.ConfirmMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, deleted); err != nil {
			t.Fatal(err)
		}
		var applied int
		if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND type='fixture.server.destroyed' AND payload->>'resource_id'=$2`, "capacity-mutation/"+g.GrantID, deleted.ResourceID).Scan(&applied); err != nil || applied != 1 {
			t.Fatal("canonical deletion event", applied, err)
		}
		if err = f.store.RecordMutationSlot(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[4], f.proof(t, 4)); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("tombstone silently readopted", err)
		}
	})
	t.Run("policy_instance_type_and_executor_fences", func(t *testing.T) {
		for _, target := range []string{"policy", "instance", "type", "executor"} {
			t.Run(target, func(t *testing.T) {
				f := mutationPostgresFixture(t, true)
				g := f.issue(t, 5)
				id := f.policy.ID.String()
				if target == "instance" {
					id = f.binding.IntegrationInstanceID
				}
				if target == "type" {
					id = f.binding.IntegrationTypeID
				}
				if target == "executor" {
					if _, err := f.db.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_executor_id}',to_jsonb($2::text)) WHERE namespace=$1`, f.policy.Metadata.Namespace, uuid.NewString()); err != nil {
						t.Fatal(err)
					}
				} else {
					if _, err := f.db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, id); err != nil {
						t.Fatal(err)
					}
				}
				if response, err := f.store.RedeemMutation(ctx, f.binding.AdapterPrincipalID, mutationRedeem(g, uuid.NewString())); err == nil || response.Mode == "write_once" {
					t.Fatal("stale authority redeemed", response, err)
				}
			})
		}
	})
	t.Run("complete_membership_and_bound_plan_required", func(t *testing.T) {
		f := mutationPostgresFixture(t, false)
		if _, err := f.store.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[5]); !errors.Is(err, ErrCapacityConflict) {
			t.Fatal("incomplete native inventory admitted", err)
		}
		for slot := 1; slot <= 4; slot++ {
			f.record(t, slot)
		}
		bad := f.plans[5]
		bad.DesiredSpec = json.RawMessage(strings.Replace(string(bad.DesiredSpec), "node-5", "caller-selected", 1))
		if _, err := f.store.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, bad); err == nil {
			t.Fatal("caller changed approved spec")
		}
		other := f.store
		other.ExecutorID = uuid.NewString()
		if _, err := other.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[5]); !errors.Is(err, ErrCapacityLease) {
			t.Fatal("other invocation stole grant", err)
		}
		other = f.store
		other.WorkflowID = uuid.Nil
		if _, err := other.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[5]); !errors.Is(err, ErrCapacityMutationAuthorization) {
			t.Fatal("unprotected repository call", err)
		}
	})
}
