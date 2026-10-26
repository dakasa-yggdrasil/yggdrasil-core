package httpapi

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"strings"
	"testing"
)

func TestFailedInstalledCoreReplacementRequestAcceptsOnlyIDsAndClosedMode(t *testing.T) {
	ids := `"preregistration_id":"11111111-1111-4111-8111-111111111111","expected_failed_run_id":"22222222-2222-4222-8222-222222222222"`
	for _, mode := range []string{"", `,"replacement_mode":"original_canary_core_bound_v1"`} {
		a, b, m, e := decodeFailedInstalledGuestDisposalRequest(strings.NewReader(`{` + ids + mode + `}`))
		if e != nil || a == "" || b == "" || (mode != "" && m != repository.FailedInstalledCoreReplacementMode) {
			t.Fatal("IDs/mode", e)
		}
	}
	for _, extra := range []string{`,"replacement_mode":""`, `,"replacement_mode":null`, `,"replacement_mode":"any_Core"`, `,"replacement_mode":"original_canary_core_bound_v1","replacement_mode":"original_canary_core_bound_v1"`, `,"original_failed_issuer_core_source":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `,"replacement_core_source":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"`, `,"Guest_source":"anything"`, `,"useful_capacity_before":0`} {
		if _, _, _, e := decodeFailedInstalledGuestDisposalRequest(strings.NewReader(`{` + ids + extra + `}`)); e == nil {
			t.Fatal("caller-supplied authority or duplicate")
		}
	}
}
