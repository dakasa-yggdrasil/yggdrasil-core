package repository

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func declaredHTTPMaintenanceMembers() json.RawMessage {
	return json.RawMessage(`[{"slot":1,"resource_id":"declared-member","preregistration_id":"11111111-1111-4111-8111-111111111111","enrollment_sha256":"` + strings.Repeat("a", 64) + `","installation_sha256":"` + strings.Repeat("b", 64) + `","slot_sha256":"` + strings.Repeat("c", 64) + `","policy_id":"22222222-2222-4222-8222-222222222222","policy_checksum":"` + strings.Repeat("d", 64) + `"}]`)
}

func declaredHTTPMaintenanceScan() CapacityDispatchHTTPMaintenanceEffectScan {
	return CapacityDispatchHTTPMaintenanceEffectScan{
		Schema: CapacityDispatchHTTPMaintenanceScanSchema,
		Base: CapacityDispatchFinalizationLostEffectScan{
			CapacityDispatchAbandonedEffectScan: CapacityDispatchAbandonedEffectScan{
				ClockSkewMarginSeconds: 30, CanaryChallengesSinceStart: 1, CanaryNoncesSinceStart: 1,
				CanaryPossibleSendsSinceStart: 1, CanaryReturnsSinceStart: 1,
			},
			Schema: CapacityDispatchFinalizationLostScanSchema, BaseSchema: CapacityDispatchAbandonedScanSchema,
		},
		CurrentMembers: declaredHTTPMaintenanceMembers(), CurrentMembersSHA256: strings.Repeat("e", 64),
		CurrentMemberCount: 1, PolicyEpochValid: true, RefreshOnlyResult: true,
	}
}

func TestHTTPMaintenanceDispositionRetainedScanBoundary(t *testing.T) {
	supersededHTTPMaintenanceScanTest(t)
	// These are declared codec operands only; SQL separately recomputes the
	// retained member digest and proves original rows, deadlines and lineage.
	if !declaredHTTPMaintenanceScan().tolerable() {
		t.Fatal("the declared one-member, one-held-publish class was refused")
	}
	for name, change := range map[string]func(*CapacityDispatchHTTPMaintenanceEffectScan){
		"old87_schema": func(s *CapacityDispatchHTTPMaintenanceEffectScan) {
			s.Schema = CapacityDispatchUnknownMaintenanceScanSchema
		},
		"missing_epoch":       func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.PolicyEpochValid = false },
		"wrong_result":        func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.RefreshOnlyResult = false },
		"invalid_canary":      func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.InvalidMaintenanceCanaryRows = 1 },
		"no_member":           func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.CurrentMemberCount = 0 },
		"multiple_members":    func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.CurrentMemberCount = 2 },
		"missing_challenge":   func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.Base.CanaryChallengesSinceStart = 0 },
		"extra_nonce":         func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.Base.CanaryNoncesSinceStart = 2 },
		"negative_send":       func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.Base.CanaryPossibleSendsSinceStart = -1 },
		"missing_return":      func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.Base.CanaryReturnsSinceStart = 0 },
		"native_command":      func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.Base.NativeCommandsSinceStart = 1 },
		"provider_read":       func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.Base.ProviderReadPerformed = true },
		"open_grant":          func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.Base.OpenUndisposedGrants = 1 },
		"unproved_assessment": func(s *CapacityDispatchHTTPMaintenanceEffectScan) { s.Base.IntentsUpdatedSinceStart = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			scan := declaredHTTPMaintenanceScan()
			change(&scan)
			if scan.tolerable() {
				t.Fatal("an altered retained boundary became authority")
			}
		})
	}
	withProvedRefreshes := declaredHTTPMaintenanceScan()
	withProvedRefreshes.Base.IntentsUpdatedSinceStart = 1
	withProvedRefreshes.Base.PureAssessmentIntentUpdates = 1
	withProvedRefreshes.Base.ResourceSlotsUpdatedSinceStart = 1
	withProvedRefreshes.Base.ObservationRefreshSlotUpdates = 1
	if !withProvedRefreshes.tolerable() {
		t.Fatal("existing ADR90 row-proved refresh tolerance changed")
	}
}

func TestHTTPMaintenanceDispositionMembersRemainClosed(t *testing.T) {
	valid := string(declaredHTTPMaintenanceMembers())
	if _, err := httpMaintenanceMembers(json.RawMessage(valid)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"null":               "null",
		"empty":              "[]",
		"foreign_slot":       strings.Replace(valid, `"slot":1`, `"slot":2`, 1),
		"extra_field":        strings.Replace(valid, `"slot":1`, `"slot":1,"authority":true`, 1),
		"duplicate_field":    strings.Replace(valid, `"slot":1`, `"slot":1,"slot":1`, 1),
		"nonliteral_key":     strings.Replace(valid, `"slot":1`, `"Slot":1`, 1),
		"missing_policy":     strings.Replace(valid, `"policy_id":`, `"foreign_policy_id":`, 1),
		"foreign_UUID_shape": strings.Replace(valid, "22222222-2222-4222-8222-222222222222", "not-a-UUID", 1),
		"bad_enrollment_SHA": strings.Replace(valid, strings.Repeat("a", 64), "short", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := httpMaintenanceMembers(json.RawMessage(raw)); err == nil {
				t.Fatal("malformed stored member projection was accepted")
			}
		})
	}
}

func TestHTTPMaintenanceDispositionAdmissionOperands(t *testing.T) {
	r := CapacityDispatchHTTPMaintenanceDispositionRequest{CapacityDispatchUnknownMaintenanceDispositionRequest: CapacityDispatchUnknownMaintenanceDispositionRequest{
		CapacityDispatchAbandonedDispositionRequest: CapacityDispatchAbandonedDispositionRequest{
			JobID: uuid.New(), ExpectedRunID: uuid.New(), ExpectedLeaseOwner: uuid.New(),
			ExpectedEnvelopeSHA256: strings.Repeat("a", 64), ExpectedFencingToken: 1, ExpectedPendingWakeCount: 1,
			Issuer: "collaborator:" + uuid.NewString(),
		},
		ExpectedReturnedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), ExpectedRunSHA256: strings.Repeat("b", 64), ExpectedMembersSHA256: strings.Repeat("c", 64),
	}}
	if !validCapacityDispatchHTTPMaintenanceRequest(r) {
		t.Fatal("closed nine-CAS request refused")
	}
	for name, change := range map[string]func(*CapacityDispatchHTTPMaintenanceDispositionRequest){
		"missing_job":    func(r *CapacityDispatchHTTPMaintenanceDispositionRequest) { r.JobID = uuid.Nil },
		"missing_run":    func(r *CapacityDispatchHTTPMaintenanceDispositionRequest) { r.ExpectedRunID = uuid.Nil },
		"missing_owner":  func(r *CapacityDispatchHTTPMaintenanceDispositionRequest) { r.ExpectedLeaseOwner = uuid.Nil },
		"missing_return": func(r *CapacityDispatchHTTPMaintenanceDispositionRequest) { r.ExpectedReturnedAt = time.Time{} },
		"bad_members":    func(r *CapacityDispatchHTTPMaintenanceDispositionRequest) { r.ExpectedMembersSHA256 = "" },
		"bad_run":        func(r *CapacityDispatchHTTPMaintenanceDispositionRequest) { r.ExpectedRunSHA256 = "" },
		"invalid_fence":  func(r *CapacityDispatchHTTPMaintenanceDispositionRequest) { r.ExpectedFencingToken = 0 },
		"invalid_wakes":  func(r *CapacityDispatchHTTPMaintenanceDispositionRequest) { r.ExpectedPendingWakeCount = 33 },
		"machine_issuer": func(r *CapacityDispatchHTTPMaintenanceDispositionRequest) { r.Issuer = "machine:declared" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := r
			change(&copy)
			if validCapacityDispatchHTTPMaintenanceRequest(copy) {
				t.Fatal("invalid CAS or nonhuman issuer accepted")
			}
		})
	}
	for _, dimension := range []string{"original_notify_aws_vm_members", "original_notify_hetzner_vm_members"} {
		job := CapacityDispatchJob{CapacityDispatchEnvelope: CapacityDispatchEnvelope{Protocol: CapacityDispatchProtocol, Realm: "dakasa-production", Environment: "production", Domain: "notify", Dimension: dimension}}
		if !httpMaintenanceScope(job) {
			t.Fatal("qualified Notify scope refused")
		}
		job.Realm = "foreign"
		if httpMaintenanceScope(job) {
			t.Fatal("foreign scope accepted")
		}
	}
}
