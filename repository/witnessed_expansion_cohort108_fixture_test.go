//go:build recoveryfixture && !nativequalification

package repository

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Declare a distinct current cohort before admitting any cleanup in this clone.
// The original producer and every original S1 signed DTO remain untouched. Only
// synthetic S2/history/catalog operands are regenerated for this new fixture;
// neither this declaration nor its SDK DTOs are production or workflow evidence.
func witnessedExpansion108CrossContractFixture(t *testing.T, original *witnessedCleanup106Fixture, migrations string) (*witnessedCleanup106Fixture, func(bool) []capacity.GuestContractInventory) {
	t.Helper()
	f := witnessedCleanup106Clone(t, original, migrations)
	oldPolicy, oldSpec := f.Policy, f.Spec
	var head model.CapacityPolicySpec
	if json.Unmarshal(failedServingWire(t, oldSpec), &head) != nil {
		t.Fatal("declared current cohort spec")
	}
	b := &head.MutationBindings[0]
	oldInstance := b.IntegrationInstanceID
	b.IntegrationInstanceID = uuid.NewString()
	b.IntegrationChecksum = capacity.BusinessCreationSHA256([]byte("declared108-current-instance-" + b.IntegrationInstanceID))
	b.ScopeChecksum = capacity.BusinessCreationSHA256([]byte("declared108-current-scope-" + b.IntegrationInstanceID))
	for i := range b.Slots {
		s := b.Slots[i].DesiredSpec
		s.IntegrationInstanceID, s.ScopeChecksum = b.IntegrationInstanceID, b.ScopeChecksum
		projection := map[string]any{"schema_version": s.SchemaVersion, "capability": s.Capability, "integration_instance_id": s.IntegrationInstanceID, "scope_checksum": s.ScopeChecksum, "profile_checksum": s.ProfileChecksum, "admission_checksum": s.AdmissionChecksum, "profile_name": s.ProfileName, "slot": s.Slot, "native_name": s.NativeName, "bootstrap_sha256": s.BootstrapSHA256}
		b.Slots[i].DesiredSpecSHA256 = capacity.BusinessCreationSHA256(failedServingWire(t, projection))
	}
	head.GuestContractSuccessor = &model.CapacityGuestContractSuccessor{Schema: capacity.GuestContractSuccessorSchema, RetainedPolicyContracts: []model.CapacityGuestRetainedPolicyContract{{PolicyID: oldPolicy.ID.String(), PolicyChecksum: oldPolicy.Checksum, ContractSHA256: guestContractDigest(oldSpec)}}}
	if err := capacity.RegisterRecoveryFixtureApproval(head, *head.GuestRetirementBinding, "hetzner"); err != nil || capacity.ValidateGuestContractSuccessor(head) != nil {
		t.Fatal("declared current cohort approval/retained original", err)
	}
	f.Policy = oldPolicy
	f.Policy.ID, f.Policy.Version = uuid.New(), oldPolicy.Version+1
	f.Policy.Spec = failedServingWire(t, head)
	f.Policy.Checksum = capacity.BusinessCreationSHA256(f.Policy.Spec)
	f.Spec = head
	// The S1 fixture view remains its actual original policy, registration,
	// enrollment and clock, rather than borrowing the new target's credentials.
	if f.private.p.MutationBindings[0].IntegrationInstanceID != oldInstance || f.private.pre.PolicyID != oldPolicy.ID.String() {
		t.Fatal("original S1 fixture view changed")
	}
	if json.Unmarshal(failedServingWire(t, original.parent), &f.parent) != nil {
		t.Fatal("declared S2 original clone")
	}
	f.parent.Binding, f.parent.PolicyID, f.parent.PolicyChecksum = *b, f.Policy.ID, f.Policy.Checksum
	f.parent.Grant.IntegrationInstanceID, f.parent.Grant.ScopeChecksum = b.IntegrationInstanceID, b.ScopeChecksum
	f.parent.Grant.RequestSHA256 = b.Slots[1].DesiredSpecSHA256
	f.parent.Settlement.RequestSHA256 = f.parent.Grant.RequestSHA256
	f.parent.Settlement.OriginalProviderCreateReturn.RequestSHA256 = f.parent.Grant.RequestSHA256
	// Match the real shape: one original auto-delete paid primary IP, not two.
	f.parent.Settlement.AuxiliaryResources = append([]model.CapacityMutationAuxiliaryResource(nil), f.parent.Settlement.AuxiliaryResources[:1]...)
	if f.parent.Settlement.AuxiliaryResources[0].Kind != "primary_ip" {
		t.Fatal("declared original paid IP")
	}
	f.pre.PolicyID, f.pre.PolicyChecksum = f.Policy.ID.String(), f.Policy.Checksum
	f.pre.OriginalCreateRequestSHA256 = f.parent.Grant.RequestSHA256
	f.witness, f.registration, f.receipt = capacity.RecoveryFixtureCompensationRegistration(t, head, *head.GuestRetirementBinding, f.pre, *f.parent.Settlement)
	f.installation = witnessedCleanup106Installation(t, f)
	f.job.Policy = CapacityDispatchManifestPin{ID: f.Policy.ID, Namespace: f.Policy.Metadata.Namespace, Name: f.Policy.Metadata.Name, Version: f.Policy.Version, Checksum: f.Policy.Checksum}
	envelope, err := encodeCapacityDispatchEnvelope(f.job.CapacityDispatchEnvelope)
	if err != nil {
		t.Fatal("declared current original envelope", err)
	}
	f.job.EnvelopeSHA256 = capacityDispatchSHA(envelope)
	f.intent.PolicyID, f.intent.PolicyChecksum = f.Policy.ID, f.Policy.Checksum
	tx, err := f.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	// ONLY declaration of the new isolated fixture, before the tested APIs.
	// All operations under test run after COMMIT with normal trigger authority.
	if _, err = tx.Exec("SET LOCAL session_replication_role=replica"); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		if _, e := tx.Exec(query, args...); e != nil {
			t.Fatal("declare cross-cohort fixture", e)
		}
	}
	exec("UPDATE public.manifests SET active=false WHERE id=$1", oldPolicy.ID)
	exec("INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) VALUES($1,'v1','capacity_policy',$2,$3,$4,$5,$6::jsonb,true)", f.Policy.ID, f.Policy.Metadata.Namespace, f.Policy.Metadata.Name, f.Policy.Version, f.Policy.Checksum, string(f.Policy.Spec))
	exec("INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec,active) SELECT $1::uuid,api_version,kind,namespace,name||'-cohort108',version,$2,spec,true FROM public.manifests WHERE id=$3::uuid", b.IntegrationInstanceID, b.IntegrationChecksum, oldInstance)
	exec("UPDATE public.capacity_mutation_grants SET integration_instance_id=$2,scope_checksum=$3,grant_record=$4::jsonb WHERE id=$1", f.pre.OriginalCreateGrantID, b.IntegrationInstanceID, b.ScopeChecksum, string(failedServingWire(t, f.parent)))
	exec("UPDATE public.capacity_vm_provisioning_preregistrations SET preregistration_record=$2::jsonb,original_wire=$3,binding_wire=$4 WHERE id=$1", f.pre.PreregistrationID, string(failedServingWire(t, f.pre)), failedServingWire(t, f.pre), failedServingWire(t, *head.GuestRetirementBinding))
	exec("UPDATE public.capacity_guest_original_create_witnesses SET resource_tuple_sha256=$2,witness_sha256=$3,original_wire=$4,original_record=$5::jsonb WHERE preregistration_id=$1", f.pre.PreregistrationID, capacity.GuestRetirementSHA(f.witness.Tuple), capacity.GuestRetirementSHA(f.witness), failedServingWire(t, f.witness), string(failedServingWire(t, f.witness)))
	exec("UPDATE public.capacity_dispatch_jobs SET envelope=$2,envelope_sha256=$3 WHERE id=$1", f.job.JobID, string(envelope), f.job.EnvelopeSHA256)
	exec("UPDATE public.capacity_intents SET intent=$2::jsonb WHERE namespace=$1 AND environment=$3 AND domain=$4 AND dimension=$5", f.Policy.Metadata.Namespace, string(failedServingWire(t, f.intent)), head.Environment, head.Domain, head.Dimension)
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Snapshot only this newly declared dataset. The original 106/107 snapshots
	// are never replaced, and clone DB/store pointers remain isolated.
	f.base = witnessedCleanup106Rows(t, f.DB)
	if _, err = readCapacityDispatchJob(context.Background(), f.DB, f.job.JobID, false); err != nil {
		t.Fatal("declared envelope must pass real closed decoder", err)
	}
	label := func(digest string) string {
		raw, e := hex.DecodeString(digest)
		if e != nil {
			t.Fatal(e)
		}
		return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	}
	inventories := func(target bool) []capacity.GuestContractInventory {
		now := time.Now().UTC()
		prior := capacity.RecoveryFixtureInventory(t, oldSpec, f.private.reg, now)
		prior.Members[0].Server.Status = "running"
		inv := capacity.RecoveryFixtureInventory(t, head, f.private.reg, now)
		member := inv.Members[0]
		inv.Members = []model.CapacityVMFleetInventoryMember{}
		inv.MissingSlots = []int{1, 2, 3, 4, 5, 6, 7, 8}
		if target {
			member.Slot, member.Protected = 2, false
			member.DesiredSpec, member.RequestSHA256 = *b.Slots[1].DesiredSpec, b.Slots[1].DesiredSpecSHA256
			member.Server.ID, member.Server.CreatedAt, member.Server.Name = f.parent.Settlement.ResourceID, f.parent.Settlement.ResourceCreatedAt, member.DesiredSpec.NativeName
			member.Server.Status = "running"
			member.Server.Labels = map[string]string{"yggdrasil.io/owner": head.Owner, "yggdrasil.io/scope": label(b.ScopeChecksum), "yggdrasil.io/spec": label(member.DesiredSpec.ProfileChecksum), "yggdrasil.io/profile": b.ProfileName, "yggdrasil.io/slot": "2", "yggdrasil.io/intent": f.parent.Grant.GrantID}
			member.Server.PrimaryIPv4ID = f.parent.Settlement.AuxiliaryResources[0].ID
			member.Server.IndependentBillableResources, member.Server.AuxiliaryInventoryComplete = true, true
			inv.Members = []model.CapacityVMFleetInventoryMember{member}
			inv.MissingSlots = []int{1, 3, 4, 5, 6, 7, 8}
		}
		out := []capacity.GuestContractInventory{{ContractSHA256: guestContractDigest(head), Inventory: inv}, {ContractSHA256: guestContractDigest(oldSpec), Inventory: prior}}
		view, e := capacity.GuestContractView(head, oldSpec)
		if e != nil {
			t.Fatal(e)
		}
		if _, _, e = capacity.GuestContractReconcileSnapshot(f.Policy, head, []model.CapacityPolicySpec{head, view}, out, now); e != nil {
			t.Fatal("declared two-cohort native returns", e)
		}
		return out
	}
	return f, inventories
}
