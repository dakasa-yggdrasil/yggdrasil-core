package repository

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestGuestRetirementForwardStorageDecoderIsClosedAndAtomic(t *testing.T) {
	type operand struct {
		Accepted bool            `json:"accepted"`
		Spec     json.RawMessage `json:"spec"`
		Optional string          `json:"optional,omitempty"`
	}
	want := operand{Spec: json.RawMessage(`{"operation":"read_only"}`)}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	target := operand{Accepted: true, Optional: "old"}
	if err = decodeRetirementForward(raw, &target); err != nil || !reflect.DeepEqual(target, want) {
		t.Fatal("canonical sparse object did not clear prior fields", err)
	}
	for _, invalid := range []string{`null`, `[]`, `{}`, `{"accepted":false,"spec":{"operation":"read_only"},"extra":true}`, `{"accepted":false,"accepted":false,"spec":{"operation":"read_only"}}`, string(raw) + `{}`, " " + string(raw), `{"accepted":false,"spec":`} {
		before := target
		if decodeRetirementForward([]byte(invalid), &target) == nil || !reflect.DeepEqual(target, before) {
			t.Fatal("unknown, duplicate, missing or noncanonical storage changed caller", invalid)
		}
	}
	if decodeRetirementForward(raw, nil) == nil || decodeRetirementForward(raw, want) == nil {
		t.Fatal("invalid target admitted")
	}
}

func TestGuestRetirementForwardFailedCallerTimeline(t *testing.T) {
	start := time.Date(2026, 11, 3, 1, 0, 0, 0, time.UTC)
	i := model.CapacityGuestRetirementIntentV2{CapacityGuestRetirementIntent: model.CapacityGuestRetirementIntent{RequestID: "retirement", AttemptID: "attempt", IssuedAt: start, OriginalDeadline: start.Add(30 * time.Second)}}
	failed := GuestOriginalCallerReturn{RequestID: i.RequestID, AttemptID: i.AttemptID, OriginalDeadline: i.OriginalDeadline, StartedAt: start, DoStartedAt: start, DoReturnedAt: start.Add(31 * time.Second), DriverReturnedAt: start.Add(31 * time.Second), DoFailed: true, OriginalContextFailed: true, Body: []byte{}, ResponseBodyScope: capacity.GuestOriginalBodyNoRead, RetainedPrefixSHA256: capacity.BusinessCreationSHA256(nil)}
	if !guestForwardCallerTimelineValid(failed, i) {
		t.Fatal("truthful late context-failed original was relabeled as success or discarded")
	}
	for _, name := range []string{"do_after_driver", "do_before_start", "close_before_do", "close_after_driver", "read_before_do", "read_without_close", "missing_read_close_without_do_failure", "preflight_only"} {
		t.Run(name, func(t *testing.T) {
			c := failed
			switch name {
			case "do_after_driver":
				c.DoReturnedAt = c.DriverReturnedAt.Add(time.Nanosecond)
			case "do_before_start":
				c.DoStartedAt = start.Add(-time.Nanosecond)
			case "close_before_do":
				c.CloseReturnedAt = start.Add(time.Second)
			case "close_after_driver":
				c.CloseReturnedAt = c.DriverReturnedAt.Add(time.Nanosecond)
			case "read_before_do":
				c.ReadReturnedAt = start.Add(time.Second)
			case "read_without_close":
				c.ReadReturnedAt = c.DoReturnedAt
			case "missing_read_close_without_do_failure":
				c.DoFailed = false
			case "preflight_only":
				c.PreflightFailed = true
			}
			if guestForwardCallerTimelineValid(c, i) {
				t.Fatal("impossible original caller timeline accepted", name)
			}
		})
	}
}

func TestGuestRetirementForwardReadonlyObserverJoins(t *testing.T) {
	source := strings.Repeat("d", 40) // Pure validator operand, never a published pin.
	read := GuestRetirementForwardRead{Schema: GuestRetirementForwardReadSchema, Kind: "absence", ReadID: "prepared-read", AdapterSourceCommit: enrolledFailedAWSCreator, Tuple: model.CapacityGuestNativeTuple{Provider: "aws"}}
	receipt := model.CapacityMutationReceipt{Grant: model.CapacityMutationGrant{GrantID: "old-destroy", RequestSHA256: strings.Repeat("a", 64)}}
	observation := model.CapacityVMRetirementObservation{NextActions: []model.CapacityVMActionObservation{}, AuxiliaryResources: []model.CapacityVMAuxiliaryObservation{}, HoldReasons: []string{}}
	for _, fault := range []string{"exact", "absent_pair", "source_only", "wrapper_only", "wrong_source", "wrong_creator", "wrong_read", "wrong_read_sha", "wrong_receipt_sha", "wrong_observation", "wrong_schema", "wrong_purpose", "unknown_key", "duplicate_key", "missing_key", "null", "trailing"} {
		t.Run(fault, func(t *testing.T) {
			r := GuestRetirementForwardReadReturn{Read: read, OriginalDestroyReceipt: &receipt, Observation: &observation, ObserverSourceCommit: source}
			v := GuestRetirementReadonlyReturn{Schema: GuestRetirementReadonlyReturnSchema, ObserverSourceCommit: source, OriginalAdapterSourceCommit: enrolledFailedAWSCreator, ReadID: read.ReadID, ReadSHA256: capacity.GuestRetirementSHA(read), OriginalReceiptSHA256: capacity.GuestRetirementSHA(receipt), Observation: observation}
			switch fault {
			case "wrong_source":
				v.ObserverSourceCommit = strings.Repeat("e", 40)
			case "wrong_creator":
				v.OriginalAdapterSourceCommit = source
			case "wrong_read":
				v.ReadID = "another"
			case "wrong_read_sha":
				v.ReadSHA256 = strings.Repeat("b", 64)
			case "wrong_receipt_sha":
				v.OriginalReceiptSHA256 = strings.Repeat("b", 64)
			case "wrong_observation":
				v.Observation.ServerAbsent = true
			case "wrong_schema":
				v.Schema = GuestRetirementReadonlyRequestSchema
			case "wrong_purpose":
				r.Read.Kind = "off"
			}
			r.OriginalObserverReturn, _ = json.Marshal(v)
			switch fault {
			case "absent_pair":
				r.ObserverSourceCommit = ""
				r.OriginalObserverReturn = nil
			case "source_only":
				r.OriginalObserverReturn = nil
			case "wrapper_only":
				r.ObserverSourceCommit = ""
			case "unknown_key":
				r.OriginalObserverReturn = append([]byte(`{"secret":"must-refuse",`), r.OriginalObserverReturn[1:]...)
			case "duplicate_key":
				r.OriginalObserverReturn = append([]byte(`{"schema":"duplicate",`), r.OriginalObserverReturn[1:]...)
			case "missing_key":
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(r.OriginalObserverReturn, &fields)
				delete(fields, "read_id")
				r.OriginalObserverReturn, _ = json.Marshal(fields)
			case "null":
				r.OriginalObserverReturn = []byte("null")
			case "trailing":
				r.OriginalObserverReturn = append(r.OriginalObserverReturn, []byte("{}")...)
			}
			if retirementForwardObserverValid(r, true, source) != (fault == "exact") {
				t.Fatal("fresh observer join", fault)
			}
			if fault == "exact" && retirementForwardObserverValid(r, true, "") {
				t.Fatal("unbound production source qualified")
			}
		})
	}
	// Old success and failure records retain the exact pre-extension encoding.
	for _, failed := range []bool{false, true} {
		legacy := GuestRetirementForwardReadReturn{Read: read, CallFailed: failed, OriginalContextFailed: failed}
		raw, _ := json.Marshal(legacy)
		if bytes.Contains(raw, []byte("observer")) {
			t.Fatal("legacy fields invented")
		}
		var decoded GuestRetirementForwardReadReturn
		if decodeRetirementForward(raw, &decoded) != nil || !retirementForwardObserverValid(decoded, false, source) {
			t.Fatal("historical unextended wire refused")
		}
		next, _ := json.Marshal(decoded)
		if !bytes.Equal(raw, next) {
			t.Fatal("legacy bytes changed")
		}
	}
	// Raw public wrapper bytes survive storage without whitespace/key rewriting.
	preserved := GuestRetirementForwardReadReturn{ObserverSourceCommit: source, OriginalObserverReturn: []byte(` { "observed": false } `)}
	raw, _ := json.Marshal(preserved)
	var roundtrip GuestRetirementForwardReadReturn
	if json.Unmarshal(raw, &roundtrip) != nil || !bytes.Equal(preserved.OriginalObserverReturn, roundtrip.OriginalObserverReturn) {
		t.Fatal("original wrapper bytes rewritten")
	}
}
