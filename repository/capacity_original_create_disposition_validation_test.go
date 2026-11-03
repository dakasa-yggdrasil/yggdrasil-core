package repository

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func originalDispositionObservationFixture(t *testing.T) (model.CapacityOriginalCreateDispositionCandidate, model.CapacityOriginalCreateDispositionObservation, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	spec, _ := json.Marshal(model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: "original", Provider: "aws"}}})
	req := model.CapacityOriginalCreateDispositionReadRequest{OriginalAuxiliaryInventoryComplete: true, Profile: "original", Slot: 1, GrantID: "11111111-1111-4111-8111-111111111111", AttemptID: "22222222-2222-4222-8222-222222222222", RequestSHA256: strings.Repeat("a", 64), ExpectedResourceID: "i-original", ExpectedResourceCreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), OriginalAdapterSourceCommit: strings.Repeat("b", 40), AuxiliaryResources: []model.CapacityMutationAuxiliaryResource{{Kind: "aws_ebs_volume", ID: "vol-original", RequiresAbsence: true}, {Kind: "aws_network_interface", ID: "eni-original", RequiresAbsence: true}}}
	c := model.CapacityOriginalCreateDispositionCandidate{OriginalPolicy: model.Manifest{Spec: spec}, Binding: model.CapacityMutationBinding{ProfileName: "original"}, Request: req}
	o := model.CapacityOriginalCreateDispositionObservation{InventoryBasis: "original_accepted_auxiliary_inventory_v1", Schema: model.OriginalCreateDispositionObservationSchema, Provider: "aws", Profile: req.Profile, Slot: req.Slot, GrantID: req.GrantID, AttemptID: req.AttemptID, RequestSHA256: req.RequestSHA256, ResourceID: req.ExpectedResourceID, ResourceCreatedAt: req.ExpectedResourceCreatedAt, OriginalAdapterSourceCommit: req.OriginalAdapterSourceCommit, AdapterSourceCommit: strings.Repeat("c", 40), ResourceState: "terminated", ResourceAbsenceComplete: true, AuxiliaryInventoryComplete: true, SharedResourcesPreserved: true, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{}, NativeReads: []model.CapacityOriginalCreateDispositionNativeRead{}, ObservationStartedAt: now.Add(-time.Second), ObservedAt: now}
	resources := []struct{ kind, id string }{{"aws_ec2_instance", req.ExpectedResourceID}, {"aws_ebs_volume", "vol-original"}, {"aws_network_interface", "eni-original"}}
	for i, r := range resources {
		raw := []byte("<original-return/> ")
		called := now.Add(-time.Second + time.Duration(i)*100*time.Millisecond)
		returned := called.Add(50 * time.Millisecond)
		o.NativeReads = append(o.NativeReads, model.CapacityOriginalCreateDispositionNativeRead{Operation: "DescribeExactOriginal", ResourceKind: r.kind, ResourceID: r.id, Status: 200, ResponseSHA256: originalDispositionDigest(raw), ResponseBytes: int64(len(raw)), ResponseBodyBase64: base64.StdEncoding.EncodeToString(raw), ResponseRepresentation: "raw_http_body_v1", CalledAt: called, ReturnedAt: returned})
		if i > 0 {
			o.AuxiliaryResources = append(o.AuxiliaryResources, model.CapacityVMAuxiliaryObservation{Kind: r.kind, ID: r.id, Absent: true, ObservedAt: returned.Format(time.RFC3339Nano)})
		}
	}
	return c, o, now
}
func cloneDispositionObservation(o model.CapacityOriginalCreateDispositionObservation) model.CapacityOriginalCreateDispositionObservation {
	raw, _ := json.Marshal(o)
	var out model.CapacityOriginalCreateDispositionObservation
	_ = json.Unmarshal(raw, &out)
	return out
}
func TestOriginalDispositionNativeClosure(t *testing.T) {
	c, o, now := originalDispositionObservationFixture(t)
	if err := validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(o)
	if !strings.Contains(string(raw), "response_body_base64") {
		t.Fatal("original body omitted")
	}
	for name, change := range map[string]func(*model.CapacityOriginalCreateDispositionObservation){
		"wrong_grant":   func(o *model.CapacityOriginalCreateDispositionObservation) { o.GrantID = "other" },
		"wrong_attempt": func(o *model.CapacityOriginalCreateDispositionObservation) { o.AttemptID = "other" },
		"wrong_request": func(o *model.CapacityOriginalCreateDispositionObservation) { o.RequestSHA256 = strings.Repeat("d", 64) },
		"wrong_historical_source": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.OriginalAdapterSourceCommit = o.AdapterSourceCommit
		},
		"wrong_provider":              func(o *model.CapacityOriginalCreateDispositionObservation) { o.Provider = "hetzner" },
		"running_original":            func(o *model.CapacityOriginalCreateDispositionObservation) { o.ResourceState = "running" },
		"missing_native_absence":      func(o *model.CapacityOriginalCreateDispositionObservation) { o.ResourceAbsenceComplete = false },
		"missing_auxiliary_inventory": func(o *model.CapacityOriginalCreateDispositionObservation) { o.AuxiliaryInventoryComplete = false },
		"missing_auxiliary": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.AuxiliaryResources = o.AuxiliaryResources[:1]
		},
		"wrong_auxiliary":         func(o *model.CapacityOriginalCreateDispositionObservation) { o.AuxiliaryResources[0].ID = "other" },
		"live_auxiliary":          func(o *model.CapacityOriginalCreateDispositionObservation) { o.AuxiliaryResources[0].Absent = false },
		"shared_resource_changed": func(o *model.CapacityOriginalCreateDispositionObservation) { o.SharedResourcesPreserved = false },
		"mutating_return":         func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeMutations = 1 },
		"business_claim": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.GuestAdmissionOrBusinessOrSavingsAuthority = true
		},
		"old_observation": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.ObservationStartedAt = now.Add(-2 * time.Minute)
			o.ObservedAt = now.Add(-time.Minute)
		},
		"future_observation":  func(o *model.CapacityOriginalCreateDispositionObservation) { o.ObservedAt = now.Add(time.Minute) },
		"missing_reads":       func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads = nil },
		"missing_server_read": func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads = o.NativeReads[1:] },
		"missing_aux_read":    func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads = o.NativeReads[:2] },
		"body_missing":        func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[0].ResponseBodyBase64 = "" },
		"body_changed": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[0].ResponseBodyBase64 = base64.StdEncoding.EncodeToString([]byte("changed"))
		},
		"hash_changed": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[0].ResponseSHA256 = strings.Repeat("f", 64)
		},
		"extent_changed": func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[0].ResponseBytes++ },
		"failed_http":    func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[0].Status = 500 },
		"redirect":       func(o *model.CapacityOriginalCreateDispositionObservation) { o.NativeReads[0].Status = 302 },
		"overlapping_calls": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[1].CalledAt = o.NativeReads[0].CalledAt
		},
		"read_after_observed": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[0].ReturnedAt = now.Add(time.Second)
		},
		"raw_falsely_sdk_json": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[0].ResponseRepresentation = "canonical_provider_SDK_result_v1"
		},
		"unknown_representation": func(o *model.CapacityOriginalCreateDispositionObservation) {
			o.NativeReads[0].ResponseRepresentation = "claimed_only"
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := cloneDispositionObservation(o)
			change(&bad)
			if validateOriginalDispositionObservation(c, bad, now.Add(-2*time.Second), now, 30*time.Second) == nil {
				t.Fatal("invalid original accepted")
			}
		})
	}
}
func TestOriginalDispositionRawBounds(t *testing.T) {
	c, o, now := originalDispositionObservationFixture(t)
	raw := []byte(strings.Repeat("x", 64<<10))
	for i := range o.NativeReads {
		o.NativeReads[i].ResponseBodyBase64 = base64.StdEncoding.EncodeToString(raw)
		o.NativeReads[i].ResponseBytes = int64(len(raw))
		o.NativeReads[i].ResponseSHA256 = originalDispositionDigest(raw)
	}
	if err := validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second); err != nil {
		t.Fatal("64KiB original refused", err)
	}
	o.NativeReads[0].ResponseBytes++
	if validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second) == nil {
		t.Fatal("read cap bypassed")
	}
	c, o, now = originalDispositionObservationFixture(t)
	for len(o.NativeReads) < 65 {
		o.NativeReads = append(o.NativeReads, o.NativeReads[len(o.NativeReads)-1])
	}
	if validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second) == nil {
		t.Fatal("call bound bypassed")
	}
}

func TestOriginalDispositionHcloudKnownInventory(t *testing.T) {
	c, o, now := originalDispositionObservationFixture(t)
	c.OriginalPolicy.Spec, _ = json.Marshal(model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: "original", Provider: "hetzner"}}})
	c.Request.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "157184349", RequiresAbsence: true}}
	o.Provider = "hetzner"
	o.ResourceState = "absent"
	o.AuxiliaryResources = o.AuxiliaryResources[:1]
	o.AuxiliaryResources[0].Kind = "primary_ip"
	o.AuxiliaryResources[0].ID = "157184349"
	o.NativeReads = o.NativeReads[:2]
	o.NativeReads[0].ResourceKind = "server"
	o.NativeReads[0].Status = 404
	o.NativeReads[1].ResourceKind = "primary_ip"
	o.NativeReads[1].ResourceID = "157184349"
	o.NativeReads[1].Status = 404
	if err := validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second); err != nil {
		t.Fatal(err)
	}
	c.Request.OriginalAuxiliaryInventoryComplete = false
	if validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second) == nil {
		t.Fatal("unknown original inventory became complete")
	}
}
func TestOriginalDispositionAggregateBodyBound(t *testing.T) {
	c, o, now := originalDispositionObservationFixture(t)
	raw := []byte(strings.Repeat("x", 64<<10))
	for i := range o.NativeReads {
		o.NativeReads[i].ResponseBodyBase64 = base64.StdEncoding.EncodeToString(raw)
		o.NativeReads[i].ResponseBytes = int64(len(raw))
		o.NativeReads[i].ResponseSHA256 = originalDispositionDigest(raw)
	}
	for len(o.NativeReads) < 17 {
		r := o.NativeReads[len(o.NativeReads)-1]
		r.CalledAt = r.ReturnedAt.Add(time.Millisecond)
		r.ReturnedAt = r.CalledAt.Add(time.Millisecond)
		o.NativeReads = append(o.NativeReads, r)
	}
	if validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second) == nil {
		t.Fatal("aggregate one MiB exceeded")
	}
}

func TestOriginalDispositionProviderKinds(t *testing.T) {
	c, o, now := originalDispositionObservationFixture(t)
	for _, kind := range []string{"ec2_instance", "server", "hcloud_server"} {
		bad := cloneDispositionObservation(o)
		bad.NativeReads[0].ResourceKind = kind
		if validateOriginalDispositionObservation(c, bad, now.Add(-2*time.Second), now, 30*time.Second) == nil {
			t.Fatalf("AWS accepted cross-provider/legacy kind %s", kind)
		}
	}
	c.OriginalPolicy.Spec, _ = json.Marshal(model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: "original", Provider: "hetzner"}}})
	o.Provider = "hetzner"
	o.ResourceState = "absent"
	o.NativeReads[0].ResourceKind = "aws_ec2_instance"
	if validateOriginalDispositionObservation(c, o, now.Add(-2*time.Second), now, 30*time.Second) == nil {
		t.Fatal("Hetzner accepted AWS native kind")
	}
}
