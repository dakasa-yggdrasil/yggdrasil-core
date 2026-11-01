//go:build recoveryfixture && !nativequalification

package repository

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Generates a self-consistent declared test create/installation lineage. The
// provider response and proof are synthetic, with no native or Guest authority.
func labCompleteSyntheticInstalled(t *testing.T, p model.CapacityPolicySpec, b model.CapacityGuestRetirementBinding, prior model.CapacityGuestOriginalProvisioningRegistration) (model.CapacityGuestOriginalProvisioningRegistration, model.CapacityGuestOriginalProvisioningReceipt, model.CapacityGuestOriginalInstallationConfirmation, capacityMutationRecord) {
	t.Helper()
	pre := prior.Result.ProductionClock.Authority.Preregistration
	binding := p.MutationBindings[0]
	pre.OriginalCreateRequestSHA256 = binding.Slots[0].DesiredSpecSHA256
	attempt := prior.Result.ProductionClock.Authority.CreateWitness.OriginalCreateAttemptID
	created := prior.Result.Tuple.CreatedAt
	returned := pre.ReservedAt.Add(time.Second).UTC().Format(time.RFC3339Nano)
	deadline := pre.OriginalDeadline.UTC().Format(time.RFC3339Nano)
	grant := model.CapacityMutationGrant{GrantID: pre.OriginalCreateGrantID, BindingName: binding.Name, IntegrationInstanceID: binding.IntegrationInstanceID, ScopeChecksum: binding.ScopeChecksum, ProfileName: binding.ProfileName, Slot: pre.Slot, Capability: binding.EnsureCapability, RequestSHA256: pre.OriginalCreateRequestSHA256, State: "confirmed"}
	aux := []model.CapacityMutationAuxiliaryResource{{Kind: "volume", ID: "fixture-volume-1", RequiresAbsence: true}}
	settle := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: attempt, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: prior.Result.Tuple.ResourceID, ResourceCreatedAt: created, ActionID: uuid.NewString(), NextActionIDs: []string{}, ObservedAt: returned, AuxiliaryResources: aux, AuxiliaryInventoryComplete: true}
	settle.OriginalProviderCreateReturn = &model.CapacityOriginalProviderCreateReturn{Schema: "hetzner_original_create_return_v1", Provider: "hetzner", AdapterSourceCommit: binding.OriginalProviderSourceCommit, GrantID: grant.GrantID, AttemptID: attempt, RequestSHA256: grant.RequestSHA256, ResourceID: settle.ResourceID, ResourceCreatedAt: created, ActionID: settle.ActionID, NextActionIDs: []string{}, CalledAt: returned, ReturnedAt: returned, ContextDeadline: deadline, ResponseStatus: 201, ResponseBodySHA256: strings.Repeat("d", 64), ResponseBytes: 100}
	_, reg, receipt := capacity.RecoveryFixtureCompensationRegistration(t, p, b, pre, settle)
	clock := reg.Result.ProductionClock
	guest := reg.EnrollmentStatement.IssuedAt.Add(time.Second)
	ownerClock := &model.CapacityGuestProductionInstallationClockV2{Schema: capacity.GuestInstallationClockV2Schema, OriginalProvisioningClockSHA256: capacity.GuestRetirementSHA(*clock), OriginalReceiptReadStartedMonotonicNS: int64(111 * time.Second), OriginalReceiptReadReturnedMonotonicNS: int64(112 * time.Second), OriginalReceiptReadReturnedAt: guest, InstalledMonotonicNS: int64(113 * time.Second), AdmittedMonotonicNS: int64(114 * time.Second), OriginalConfirmationPreparedMonotonicNS: int64(115 * time.Second)}
	confirmation := model.CapacityGuestOriginalInstallationConfirmation{Schema: capacity.GuestInstallationV2Schema, PreregistrationID: pre.PreregistrationID, OriginalReceiptSHA256: capacity.GuestRetirementSHA(receipt), EnrollmentSHA256: capacity.GuestRetirementSHA(receipt.Enrollment), InstalledAt: guest.Add(time.Second), AdmittedAt: guest.Add(2 * time.Second), ProductionClock: ownerClock}
	confirmation.Signature, _ = capacity.GuestLifecycleSignature(ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", 32))), confirmation)
	if err := capacity.GuestOriginalInstallationV2(pre, receipt, confirmation, b.ProvisionerPublicKey, *clock, receipt.RecordedAt.Add(time.Second)); err != nil {
		t.Fatal("synthetic installation", err)
	}
	record := capacityMutationRecord{Grant: grant, Binding: binding, PolicyID: uuid.MustParse(pre.PolicyID), PolicyChecksum: pre.PolicyChecksum, WorkflowID: uuid.MustParse(pre.WorkflowID), Generation: pre.Generation, FencingToken: pre.Fence, LeaseOwner: pre.LeaseOwner, ExecutorID: pre.ExecutorID, AttemptID: attempt, Settlement: &settle, Proof: &model.CapacityMutationProof{}}
	return reg, receipt, confirmation, record
}

func TestLABCompleteSyntheticInstalledLocal(t *testing.T) {
	if os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		t.Skip("explicit test fixture only")
	}
	p, b, prior, _, _ := capacity.RecoveryFixtureInstalled(t)
	reg, receipt, _, record := labCompleteSyntheticInstalled(t, p, b, prior)
	pre := reg.Result.ProductionClock.Authority.Preregistration
	if record.Grant.RequestSHA256 != pre.OriginalCreateRequestSHA256 || record.Settlement.ResourceID != receipt.Enrollment.Statement.Tuple.ResourceID || record.Proof == nil {
		t.Fatal("synthetic create linkage")
	}
	spec, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	c := model.CapacityOriginalCreateDispositionCandidate{OriginalPolicy: model.Manifest{Spec: spec}, Binding: record.Binding, Request: model.CapacityOriginalCreateDispositionReadRequest{OriginalAuxiliaryInventoryComplete: true, Profile: record.Binding.ProfileName, Slot: record.Grant.Slot, GrantID: record.Grant.GrantID, AttemptID: record.AttemptID, RequestSHA256: record.Grant.RequestSHA256, ExpectedResourceID: record.Settlement.ResourceID, ExpectedResourceCreatedAt: record.Settlement.ResourceCreatedAt, OriginalAdapterSourceCommit: record.Binding.OriginalProviderSourceCommit, AuxiliaryResources: record.Settlement.AuxiliaryResources}}
	_ = labSyntheticNativeAbsence(t, c)
}

// Entire observation is declared test data; no HTTP, provider or native
// resource is contacted. It cannot be used as evidence outside this fixture.
func labSyntheticNativeAbsence(t *testing.T, c model.CapacityOriginalCreateDispositionCandidate) model.CapacityOriginalCreateDispositionObservation {
	t.Helper()
	r := c.Request
	now := time.Now().UTC()
	body := []byte(`{"error":{"code":"not_found"}}`)
	o := model.CapacityOriginalCreateDispositionObservation{InventoryBasis: "original_accepted_auxiliary_inventory_v1", Schema: model.OriginalCreateDispositionObservationSchema, Provider: "hetzner", Profile: r.Profile, Slot: r.Slot, GrantID: r.GrantID, AttemptID: r.AttemptID, RequestSHA256: r.RequestSHA256, ResourceID: r.ExpectedResourceID, ResourceCreatedAt: r.ExpectedResourceCreatedAt, OriginalAdapterSourceCommit: r.OriginalAdapterSourceCommit, AdapterSourceCommit: enrolledFailedHetznerCreator, ResourceState: "absent", ResourceAbsenceComplete: true, AuxiliaryInventoryComplete: true, SharedResourcesPreserved: true, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{}, NativeReads: []model.CapacityOriginalCreateDispositionNativeRead{}, ObservationStartedAt: now, ObservedAt: now}
	appendRead := func(kind, id string) {
		o.NativeReads = append(o.NativeReads, model.CapacityOriginalCreateDispositionNativeRead{Operation: "synthetic_declared_absence", ResourceKind: kind, ResourceID: id, Status: 404, ResponseSHA256: originalDispositionDigest(body), ResponseBytes: int64(len(body)), ResponseBodyBase64: base64.StdEncoding.EncodeToString(body), ResponseRepresentation: "raw_http_body_v1", CalledAt: now, ReturnedAt: now})
	}
	appendRead("server", r.ExpectedResourceID)
	for _, a := range r.AuxiliaryResources {
		if a.RequiresAbsence {
			appendRead(a.Kind, a.ID)
			o.AuxiliaryResources = append(o.AuxiliaryResources, model.CapacityVMAuxiliaryObservation{Kind: a.Kind, ID: a.ID, Absent: true, ObservedAt: now.Format(time.RFC3339Nano)})
		}
	}
	if err := validateEnrolledFailedOriginalObservation(c, o, now, now, 30*time.Second); err != nil {
		t.Fatal("synthetic absence content", err)
	}
	return o
}
