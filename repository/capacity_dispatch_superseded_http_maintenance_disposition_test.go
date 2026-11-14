package repository

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func supersededHTTPMaintenanceScanTest(t *testing.T) {
	t.Helper()
	old := declaredHTTPMaintenanceScan()
	s := CapacityDispatchSupersededHTTPMaintenanceEffectScan{
		Schema: CapacityDispatchSupersededHTTPMaintenanceScanSchema, Base: old.Base, CurrentMembers: old.CurrentMembers, CurrentMembersSHA256: old.CurrentMembersSHA256, CurrentMemberCount: 1,
		EquivalentPolicyValid: true, OtherCatalogPinsValid: true, StableEpochValid: true, ReadonlyResultValid: true, CurrentIntentSHA256: strings.Repeat("f", 64),
		CanaryEvidence: CapacityDispatchSupersededHTTPMaintenanceCanaryEvidence{PublishID: uuid.New(), ReadID: uuid.New(), PublishChallengeSHA256: strings.Repeat("1", 64), ReadChallengeSHA256: strings.Repeat("2", 64), PublishReturnSHA256: strings.Repeat("3", 64)},
	}
	s.Base.CanaryChallengesSinceStart, s.Base.CanaryNoncesSinceStart, s.Base.CanaryPossibleSendsSinceStart, s.Base.CanaryReturnsSinceStart = 2, 2, 2, 1
	s.Base.IntentsUpdatedSinceStart, s.Base.PureAssessmentIntentUpdates, s.Base.ResourceSlotsUpdatedSinceStart, s.Base.ObservationRefreshSlotUpdates = 1, 1, 1, 1
	wire, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeSupersededHTTPMaintenanceScan(wire); err != nil {
		t.Fatal("declared exact newscan positive", err)
	}
	// The genuine two-part canary cannot become an old migration91 positive.
	old.Base = s.Base
	if old.tolerable() {
		t.Fatal("new pair relaxed old91 contract")
	}
	for _, change := range []func(*CapacityDispatchSupersededHTTPMaintenanceEffectScan){
		func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) {
			v.Schema = CapacityDispatchHTTPMaintenanceScanSchema
		},
		func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) { v.EquivalentPolicyValid = false }, func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) { v.OtherCatalogPinsValid = false },
		func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) { v.StableEpochValid = false }, func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) { v.ReadonlyResultValid = false },
		func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) { v.InvalidCanaryPairRows = 1 }, func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) {
			v.CanaryEvidence.ReadID = v.CanaryEvidence.PublishID
		},
		func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) { v.Base.CanaryReturnsSinceStart = 2 }, func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) { v.Base.CanaryNoncesSinceStart = 1 },
		func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) { v.Base.PureAssessmentIntentUpdates = 0 }, func(v *CapacityDispatchSupersededHTTPMaintenanceEffectScan) { v.Base.ObservationRefreshSlotUpdates = 0 },
	} {
		v := s
		change(&v)
		if v.tolerable() {
			t.Fatal("newscan accepted changed proof")
		}
	}
	// Every inherited counter/flag is required, including zero-valued fields.
	var tree map[string]json.RawMessage
	if json.Unmarshal(wire, &tree) != nil {
		t.Fatal("scan tree")
	}
	for _, object := range []string{"", "base", "canary_evidence"} {
		var fields map[string]json.RawMessage
		if object == "" {
			fields = tree
		} else if json.Unmarshal(tree[object], &fields) != nil {
			t.Fatal("nested tree")
		}
		for key := range fields {
			for _, remove := range []bool{false, true} {
				var top map[string]json.RawMessage
				_ = json.Unmarshal(wire, &top)
				var part map[string]json.RawMessage
				if object == "" {
					part = top
				} else {
					_ = json.Unmarshal(top[object], &part)
				}
				if remove {
					delete(part, key)
				} else {
					part[key] = json.RawMessage("null")
				}
				if object != "" {
					top[object], _ = json.Marshal(part)
				}
				bad, _ := json.Marshal(top)
				if _, e := decodeSupersededHTTPMaintenanceScan(bad); e == nil {
					t.Fatal("missing/null proof accepted", object, key, remove)
				}
			}
		}
	}
	base := reflect.ValueOf(s.Base.CapacityDispatchAbandonedEffectScan)
	for i := 0; i < base.NumField(); i++ {
		field := base.Type().Field(i)
		if base.Field(i).Kind() != reflect.Int64 {
			continue
		}
		v := s
		b := reflect.ValueOf(&v.Base.CapacityDispatchAbandonedEffectScan).Elem()
		b.Field(i).SetInt(base.Field(i).Int() + 1)
		if v.tolerable() {
			t.Fatal("extra inherited effect accepted", field.Name)
		}
	}
}
