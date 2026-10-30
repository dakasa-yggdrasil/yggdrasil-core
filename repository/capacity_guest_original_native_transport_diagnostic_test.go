//go:build linux && nativequalification

package repository_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
)

func TestOriginalAuthorityTransportFailureDiagnostic(t *testing.T) {
	now := time.Now().UTC()
	reply := []byte("actual returned body")
	digest := capacity.BusinessCreationSHA256(reply)
	original := guestOriginalAuthorityTransport{}
	original.ReadID = "read"
	original.Stage = "journal"
	original.OriginalDeadline = now.Add(time.Minute)
	original.StartedAt = now
	original.DoStartedAt = now
	original.DoReturnedAt = now
	original.ReadReturnedAt = now
	original.CloseReturnedAt = now
	original.DriverReturnedAt = now
	original.Status = 200
	original.ResponseSHA256 = digest
	original.ReceivedBodyBytes = len(reply)
	original.ResponseBodyScope = capacity.GuestOriginalBodyCompleteRead
	original.RetainedPrefixBytes = len(reply)
	original.RetainedPrefixSHA256 = digest
	for _, tc := range []struct {
		name, want string
	}{
		{"valid", "unknown"},
		{"sql_inconsistent", "sql_consistency"},
		{"wire_digest", "wire_digest"},
		{"wire_decode", "wire_decode"},
		{"reply_absent", "prefix_length"},
		{"reply_changed", "prefix_digest"},
		{"read_binding", "read_binding"},
		{"stage_binding", "stage_binding"},
		{"clock", "clock_order"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fact := original
			body := append([]byte(nil), reply...)
			id, stage, consistent := "read", "journal", true
			if tc.name == "clock" {
				fact.DriverReturnedAt = fact.OriginalDeadline
			}
			wire, err := json.Marshal(fact)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "wire_decode" {
				wire = []byte(`{"unknown":true}`)
			}
			wireDigest := capacity.BusinessCreationSHA256(wire)
			switch tc.name {
			case "sql_inconsistent":
				consistent = false
			case "wire_digest":
				wireDigest = capacity.BusinessCreationSHA256([]byte("other"))
			case "reply_absent":
				body = nil
			case "reply_changed":
				body[0] ^= 1
			case "read_binding":
				id = "other"
			case "stage_binding":
				stage = "snapshot"
			}
			if got := guestOriginalAuthorityTransportFailure(wire, body, wireDigest, id, stage, consistent); got != tc.want {
				t.Fatalf("unexpected closed failure label %q", got)
			}
		})
	}
	if got := guestOriginalAuthorityTransportLocation("before_start", 2, "journal"); got != "before_start_2_journal" {
		t.Fatal("valid location refused")
	}
	if got := guestOriginalAuthorityTransportLocation("sensitive", 99, "private"); got != "unknown" {
		t.Fatal("unexpected location accepted")
	}
}
