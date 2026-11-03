package repository

import (
	"encoding/json"
	"reflect"
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
