package repository

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeDeniedOriginalACKLanesAndWire(t *testing.T) {
	returned := time.Date(2026, 10, 23, 22, 50, 14, 466000000, time.UTC)
	ack := returned.Add(time.Millisecond)
	lease := returned.Add(time.Minute)
	unknown := CapacityDispatchJob{State: "unknown", ReturnedAt: &returned, LeaseExpiresAt: &lease}
	known := unknown
	known.State, known.FinalizationAckAt = "returned", &ack
	for _, row := range []struct {
		job    CapacityDispatchJob
		schema string
	}{
		{unknown, model.NativeDeniedDispositionSchema}, {known, model.NativeDeniedReturnedACKDispositionSchema},
	} {
		if schema, ok := nativeDeniedDispatchSchema(row.job); !ok || schema != row.schema {
			t.Fatal("original ACK lane", schema, ok)
		}
	}
	for _, name := range []string{"unknown_with_ACK", "returned_without_ACK", "ACK_before_return", "ACK_at_deadline", "foreign_state"} {
		bad := known
		switch name {
		case "unknown_with_ACK":
			bad.State = "unknown"
		case "returned_without_ACK":
			bad.FinalizationAckAt = nil
		case "ACK_before_return":
			x := returned.Add(-time.Microsecond)
			bad.FinalizationAckAt = &x
		case "ACK_at_deadline":
			bad.FinalizationAckAt = &lease
		case "foreign_state":
			bad.State = "started"
		}
		if _, ok := nativeDeniedDispatchSchema(bad); ok {
			t.Fatal("foreign ACK lane", name)
		}
	}
	v1 := model.CapacityNativeDeniedDisposition{Schema: model.NativeDeniedDispositionSchema, OriginalUnknownACKPreserved: true}
	raw, err := json.Marshal(v1)
	if err != nil || !nativeDeniedDispositionACKMatches(v1, nil) || strings.Contains(string(raw), "original_dispatch_state") || strings.Contains(string(raw), "original_finalization_ack_at") || strings.Contains(string(raw), "original_failed_workflow_ACK_preserved") {
		t.Fatal("V1 representation changed", err)
	}
	v2 := model.CapacityNativeDeniedDisposition{Schema: model.NativeDeniedReturnedACKDispositionSchema, OriginalDispatchState: "returned", OriginalFinalizationACKAt: &ack, OriginalFailedWorkflowACKPreserved: true}
	if !nativeDeniedDispositionACKMatches(v2, &ack) || nativeDeniedDispositionACKMatches(v2, nil) || nativeDeniedDispositionACKMatches(v1, &ack) {
		t.Fatal("ACK relabelled")
	}
	for _, name := range []string{"unknown_flag", "timestamp", "missing_state", "missing_preserved", "foreign_schema"} {
		bad := v2
		switch name {
		case "unknown_flag":
			bad.OriginalUnknownACKPreserved = true
		case "timestamp":
			x := ack.Add(time.Microsecond)
			bad.OriginalFinalizationACKAt = &x
		case "missing_state":
			bad.OriginalDispatchState = ""
		case "missing_preserved":
			bad.OriginalFailedWorkflowACKPreserved = false
		case "foreign_schema":
			bad.Schema = "foreign"
		}
		if nativeDeniedDispositionACKMatches(bad, &ack) {
			t.Fatal("forged ACK DTO", name)
		}
	}
}
