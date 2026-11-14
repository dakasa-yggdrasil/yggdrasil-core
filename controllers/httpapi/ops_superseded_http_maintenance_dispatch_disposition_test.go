package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Invoked by the existing HTTP-maintenance owning root: no extra root, skip or
// authority-bearing test endpoint is introduced.
func supersededHTTPMaintenanceClosedCASTest(t *testing.T) {
	t.Helper()
	good := unknownMaintenanceDispatchCASFixture()
	good["expected_replacement_policy_id"] = "aabbccdd-1234-4abc-8def-123456abcdef"
	good["expected_replacement_policy_version"] = 21
	good["expected_replacement_policy_checksum"] = strings.Repeat("d", 64)
	encode := func(v any) string {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	raw := encode(good)
	request, err := decodeSupersededHTTPMaintenanceDispatchDisposition(strings.NewReader(raw))
	if err != nil || request.Issuer != "" || request.ExpectedReplacementPolicyVersion != 21 || request.ExpectedReplacementPolicyID.String() != good["expected_replacement_policy_id"] {
		t.Fatal("closed new CAS positive", err)
	}
	for key := range good {
		for _, omit := range []bool{false, true} {
			v := map[string]any{}
			for k, x := range good {
				v[k] = x
			}
			if omit {
				delete(v, key)
			} else {
				v[key] = nil
			}
			if _, e := decodeSupersededHTTPMaintenanceDispatchDisposition(strings.NewReader(encode(v))); e == nil {
				t.Fatal("missing/null new CAS accepted", key, omit)
			}
		}
	}
	for _, fault := range []struct {
		k string
		v any
	}{
		{"expected_replacement_policy_id", uuid.Nil.String()}, {"expected_replacement_policy_id", strings.ToUpper(good["expected_replacement_policy_id"].(string))},
		{"expected_replacement_policy_version", 0}, {"expected_replacement_policy_version", 1.5}, {"expected_replacement_policy_version", "21"}, {"expected_replacement_policy_version", int64(2147483648)},
		{"expected_replacement_policy_checksum", strings.Repeat("D", 64)}, {"issuer", "collaborator:" + uuid.NewString()}, {"equivalent_policy_valid", true}, {"effect_scan", map[string]any{}}, {"finalization_ack_at", "2026-11-14T06:23:11Z"},
	} {
		v := map[string]any{}
		for k, x := range good {
			v[k] = x
		}
		v[fault.k] = fault.v
		if _, e := decodeSupersededHTTPMaintenanceDispatchDisposition(strings.NewReader(encode(v))); e == nil {
			t.Fatal("new authority/malformed CAS accepted", fault.k)
		}
	}
	for _, v := range []string{raw + raw, strings.TrimSuffix(raw, "}") + `,"expected_replacement_policy_version":21}`, strings.TrimSuffix(raw, "}") + `,"\u0065xpected_replacement_policy_version":21}`, raw + strings.Repeat(" ", unknownMaintenanceDispatchBodyLimit+1)} {
		if _, e := decodeSupersededHTTPMaintenanceDispatchDisposition(strings.NewReader(v)); e == nil {
			t.Fatal("duplicate/trailing/oversized new CAS accepted")
		}
	}
	for _, handle := range []func(*Server, http.ResponseWriter, *http.Request){(*Server).handleOpsSupersededHTTPMaintenanceDispatchDisposition, (*Server).handleOpsSupersededHTTPMaintenanceDispatchDispositionRead} {
		w := httptest.NewRecorder()
		handle(&Server{}, w, httptest.NewRequest(http.MethodPost, "/api/v1/ops/capacity/superseded-http-maintenance-dispatch-dispositions", strings.NewReader(raw)))
		if w.Code != http.StatusUnauthorized {
			t.Fatal("new disposition reached repository without current human", w.Code)
		}
	}
	summary := supersededHTTPMaintenanceDispatchDispositionSummary(repository.CapacityDispatchSupersededHTTPMaintenanceDisposition{})
	for _, name := range []string{"original_dispatch_wire", "original_run_wire", "original_policy_wire", "replacement_policy_wire", "current_intent_wire", "current_members_wire", "original_result", "authorization"} {
		if _, ok := summary[name]; ok {
			t.Fatal("private archived body exported", name)
		}
	}
	if summary["finalization_ack_at"] != nil || summary["original_finalization_ack_present"] != false || summary["provider_read_performed"] != false || summary["replayed"] != false || summary["new_current_admission_required"] != true {
		t.Fatal("summary fabricated finalization or usefulness", summary)
	}
}
