package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
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
	return mutationPostgresFixtureWithBaseline(t, register, 2, 4)
}

func mutationPostgresFixtureWithBaseline(t *testing.T, register bool, floor, units int) mutationFixture {
	return mutationPostgresFixtureWithGuestShape(t, register, floor, units, false)
}

// Structural Guest fixture reaches earlier guards without provider authority.
func mutationPostgresFixtureWithGuestShape(t *testing.T, register bool, floor, units int, guestShape bool) mutationFixture {
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
	typeSpec := mutationTypeFixture()
	rawType, err := json.Marshal(typeSpec)
	if err != nil {
		t.Fatal(err)
	}
	parsedType, err := manifest.ParseIntegrationTypeSpec(rawType)
	if err != nil || manifest.ValidateIntegrationTypeSpec(parsedType) != nil {
		t.Fatal("mutation fixture must be registration-valid", err)
	}
	ty := create("integration_type", "fleet-type", typeSpec)
	instance := create("integration_instance", "fleet", map[string]any{"type_ref": model.ManifestSelector{ManifestID: ty.ID.String()}})
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(original.Spec, &p); err != nil {
		t.Fatal(err)
	}
	p.LeaseSeconds, p.Floor, a.Snapshot.Units = 120, floor, units
	p.Profiles[0].MinUnits = floor
	b := model.CapacityMutationBinding{Name: "burst", IntegrationInstanceID: instance.ID.String(), IntegrationChecksum: instance.Checksum, IntegrationTypeID: ty.ID.String(), IntegrationTypeChecksum: ty.Checksum, AdapterPrincipalID: "fleet-adapter", ScopeChecksum: strings.Repeat("a", 64), ProfileName: "base", EnsureCapability: "ensure_server", DestroyCapability: "destroy_server", ProtectedSlots: floor, MaxSlots: 20}
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
	if guestShape {
		source, digest := strings.Repeat("1", 40), strings.Repeat("b", 64)
		writer := model.CapacityGuestProtectedWriterDefinition{ID: "structural-writer", SourceCommit: source, BinarySHA256: digest, CgroupRelativePath: ".", CommandSHA256: digest, HandleContractSHA256: digest}
		profile := model.CapacityGuestProtectedProfileManifest{Schema: capacity.GuestProtectedProfileSchema, Profile: b.ProfileName, MutationBinding: b.Name, CoverageClass: "native_qualification_subset", BootstrapOwnerSourceCommit: source, BootstrapOwnerBinarySHA256: digest, BootstrapReaderBinarySHA256: digest, BootstrapPayloadSHA256: digest, BootstrapSHA256: digest, OriginalProvisioningBudgetSeconds: 60, OriginalProvisioningStepID: "structural-step", OwnerSourceCommit: source, OwnerBinarySHA256: digest, ProtectedCgroup: capacity.GuestProtectedCgroup, ActorSourceCommit: source, ActorBinarySHA256: digest, RuntimeClientCommandSHA256: digest, PoweroffCommandSHA256: digest, Writers: []model.CapacityGuestProtectedWriterDefinition{writer}}
		r := model.CapacityGuestRetirementBinding{Mode: capacity.GuestRetirementSchema, MutationBindingName: b.Name, EvidenceClass: "native_qemu_qualification", ProvisionerSourceCommit: source, GuestSourceCommit: source, CoreAuthoritySourceCommit: source, ProvisionerPublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), EnrollmentIssuerPublicKey: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("b", 32))), EnrollmentSigningKeyRef: "secret://fixture/enrollment#value", IntentSigningKeyRef: "secret://fixture/intent#value", ProfileManifest: profile, ProfileManifestSHA256: capacity.GuestRetirementSHA(profile), MaxEvidenceAgeSeconds: 30}
		for slot := 1; slot <= b.MaxSlots; slot++ {
			name := fmt.Sprintf("structural-%d", slot)
			r.Members = append(r.Members, model.CapacityGuestRetirementMemberBinding{Name: name, Slot: slot, Origin: fmt.Sprintf("https://127.0.0.1:%d", 20000+slot), ServerCARef: "secret://fixture/ca#value", ClientCertificateRef: "secret://fixture/cert#value", ClientKeyRef: "secret://fixture/key#value", ActorClientPrincipal: name + "-actor", ProvisionerClientPrincipal: name + "-provisioner"})
		}
		p.GuestRetirementBinding = &r
		if err := capacity.ValidateGuestRetirementBinding(p, &r); err != nil {
			t.Fatal("structural Guest fixture invalid", err)
		}
		if capacity.GuestOriginalProfileEnabled(p, r, "fixture") {
			t.Fatal("structural Guest fixture unexpectedly approved")
		}
	}
	policy := create("capacity_policy", "api", p)
	store := CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString()}
	if guestShape {
		store = store.WithOriginalGuestProvisioning(model.WorkflowStepSpec{}, strings.Repeat("1", 40), strings.Repeat("c", 64))
	}
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
		for slot := 1; slot <= units; slot++ {
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
		r := repositoryOriginalFixture(t)
		if !r.RepositoryPausedUnredeemed {
			t.Fatal("source-owned paused unredeemed recovery did not pass")
		}
	})
	t.Run("concurrent_issue_and_single_redemption", func(t *testing.T) {
		r := repositoryOriginalFixture(t)
		if r.IssuanceReturns != 20 || !r.SerializedIssueMatches || r.ActiveGrantRows != 1 || r.PreregistrationRows != 1 || r.RedeemReturns != 20 || r.WriteOnce != 1 || r.ReadOnly != 19 {
			t.Fatal("source-owned concurrent issuance/redemption did not satisfy the original invariant", r)
		}
	})
	t.Run("lost_reply_same_attempt_is_read_only", func(t *testing.T) {
		r := repositoryOriginalFixture(t)
		if !r.RepositoryLostReply {
			t.Fatal("source-owned original replay and before-send settlement did not pass")
		}
	})
	t.Run("settlement_nonce_scope_pause_and_private_receipt", func(t *testing.T) {
		r := repositoryOriginalFixture(t)
		if !r.SettlementScopePrivacyPassed {
			t.Fatal("source-owned settlement scope, pause, or privacy check did not pass")
		}
	})
	t.Run("unresolved_mutation_blocks_terminal_and_expiry_reissue", func(t *testing.T) {
		r := repositoryOriginalFixture(t)
		if !r.RepositoryUnresolved {
			t.Fatal("source-owned unresolved authority and expired replay check did not pass")
		}
	})
	t.Run("native_action_cannot_replace_transport_settlement", func(t *testing.T) {
		r := repositoryOriginalFixture(t)
		if !r.RepositoryNativeConfirmation {
			t.Fatal("source-owned settlement and synthetic native confirmation check did not pass")
		}
		assertGenericCapacityMutationEvent(t)
	})
	t.Run("historical_recovery_confirms_after_pause", func(t *testing.T) {
		r := repositoryOriginalFixture(t)
		if !r.RepositoryHistoricalRecovery {
			t.Fatal("source-owned historical confirmation after pause did not pass")
		}
	})
	t.Run("partial_recovery_matches_fresh_membership_and_allows_new_intent", func(t *testing.T) {
		r := repositoryOriginalFixture(t)
		if !r.RepositoryPartialRecovery {
			t.Fatal("source-owned partial recovery and new assessment did not pass")
		}
	})
	t.Run("floor_drain_pending_delete_budget_and_tombstone", func(t *testing.T) {
		runSyntheticFloorGate(t)
	})

	t.Run("policy_instance_type_and_executor_fences", func(t *testing.T) {
		for _, target := range []string{"policy", "instance", "type", "executor"} {
			t.Run(target, func(t *testing.T) {
				r := repositoryOriginalFixture(t)
				if !r.RepositoryAuthorityFences {
					t.Fatal("source-owned authority fence and restored control did not pass", target)
				}
			})
		}
	})
	t.Run("complete_membership_and_bound_plan_required", func(t *testing.T) {
		f := mutationPostgresFixtureWithGuestShape(t, false, 2, 4, true)
		if _, err := f.store.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[5]); !errors.Is(err, ErrCapacityConflict) || !strings.Contains(err.Error(), "native membership has not been completely registered") {
			t.Fatal("incomplete native inventory admitted", err)
		}
		for slot := 1; slot <= 4; slot++ {
			f.record(t, slot)
		}
		if _, err := f.store.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, f.plans[5]); !errors.Is(err, ErrCapacityConflict) || !strings.Contains(err.Error(), "complete original protected Guest preregistration required") {
			t.Fatal("complete membership did not reach the unapproved Guest hold", err)
		}
		var grants, preregistrations int
		if err := f.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1), (SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations WHERE preregistration_record->>'policy_id'=$2)`, f.policy.Metadata.Namespace, f.policy.ID.String()).Scan(&grants, &preregistrations); err != nil || grants != 0 || preregistrations != 0 {
			t.Fatal("unapproved Guest hold did not roll back grant/preregistration", grants, preregistrations, err)
		}
		bad := f.plans[5]
		bad.DesiredSpec = json.RawMessage(strings.Replace(string(bad.DesiredSpec), "node-5", "caller-selected", 1))
		if _, err := f.store.IssueMutation(ctx, f.policy, 1, f.intent.FencingToken, f.intent.LeaseOwner, bad); err == nil || !strings.Contains(err.Error(), "desired spec is not the operator-approved slot revision") {
			t.Fatal("caller changed approved spec", err)
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
