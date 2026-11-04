package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func externalCauseRequestFixture() map[string]any {
	return map[string]any{
		"preregistration_id":      "b8076d1e-0000-4000-8000-000000000001",
		"peer_preregistration_id": "2a23af4b-0000-4000-8000-000000000002",
		"cause_evidence":          "RabbitMQ user dakasa-notify lacked read/configure on notify.guest-canary.*; fixed 2026-11-02 ~07:20Z and made durable.",
	}
}

func TestFailedInstalledExternalCauseReplacementClosedRequest(t *testing.T) {
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	good := encode(externalCauseRequestFixture())
	request, err := decodeFailedInstalledExternalCauseReplacement(strings.NewReader(good))
	if err != nil || request.PreregistrationID != externalCauseRequestFixture()["preregistration_id"] || request.PeerPreregistrationID != externalCauseRequestFixture()["peer_preregistration_id"] ||
		request.CauseEvidence != externalCauseRequestFixture()["cause_evidence"] || request.Issuer != "" {
		t.Fatal("valid request refused, evidence changed or issuer synthesized", request, err)
	}
	for key := range externalCauseRequestFixture() {
		for _, absent := range []bool{false, true} {
			value := externalCauseRequestFixture()
			value[key] = nil
			if absent {
				delete(value, key)
			}
			if _, err := decodeFailedInstalledExternalCauseReplacement(strings.NewReader(encode(value))); err == nil {
				t.Fatal("missing/null accepted", key, absent)
			}
		}
	}
	for _, mutation := range []struct {
		key   string
		value any
	}{
		{"issuer", "collaborator:" + uuid.NewString()}, {"replacement_mode", "original_canary_core_bound_v1"},
		{"guest_source_commit", strings.Repeat("b", 40)}, {"profile_manifest_sha256", strings.Repeat("c", 64)},
		{"binding", map[string]any{}}, {"core_source", strings.Repeat("a", 40)}, {"dimension", "original_notify_hetzner_vm_members"},
		{"peer_read_challenge_id", uuid.NewString()}, {"recorded_at", time.Now().UTC()}, {"cause_evidence_sha256", strings.Repeat("a", 64)},
		{"cause_fixed", true}, {"disposal_id", uuid.NewString()},
		{"preregistration_id", strings.ToUpper(externalCauseRequestFixture()["preregistration_id"].(string))},
		{"preregistration_id", uuid.Nil.String()}, {"peer_preregistration_id", "not-a-uuid"},
		{"peer_preregistration_id", externalCauseRequestFixture()["preregistration_id"]},
		{"preregistration_id", 42}, {"cause_evidence", ""}, {"cause_evidence", "  \n "},
		{"cause_evidence", strings.Repeat("x", repository.FailedInstalledExternalCauseEvidenceMax+1)},
		{"cause_evidence", "log\u0000line"}, {"cause_evidence", "bell\u0007"}, {"cause_evidence", 42}, {"cause_evidence", []string{"line"}},
		{"cause_evidence", map[string]any{"text": "x"}}, {"cause_evidence", true},
	} {
		value := externalCauseRequestFixture()
		value[mutation.key] = mutation.value
		if _, err := decodeFailedInstalledExternalCauseReplacement(strings.NewReader(encode(value))); err == nil {
			t.Fatal("foreign/malformed accepted", mutation.key, mutation.value)
		}
	}
	maximum := externalCauseRequestFixture()
	maximum["cause_evidence"] = strings.Repeat("x", repository.FailedInstalledExternalCauseEvidenceMax)
	if _, err := decodeFailedInstalledExternalCauseReplacement(strings.NewReader(encode(maximum))); err != nil {
		t.Fatal("8 KiB evidence refused", err)
	}
	duplicate := strings.TrimSuffix(good, "}") + `,"preregistration_id":"b8076d1e-0000-4000-8000-000000000001"}`
	for _, raw := range []string{"", "{}", "null", "[]", good + good, good + strings.Repeat(" ", failedInstalledExternalCauseBodyLimit), duplicate} {
		if _, err := decodeFailedInstalledExternalCauseReplacement(strings.NewReader(raw)); err == nil {
			t.Fatal("empty/duplicate/trailing/oversize accepted", len(raw))
		}
	}
	// encoding/json would silently turn these into U+FFFD, so the stored
	// evidence and its SHA-256 would differ from the bytes the operator sent.
	withEvidence := func(token string) string {
		return `{"preregistration_id":"b8076d1e-0000-4000-8000-000000000001","peer_preregistration_id":"2a23af4b-0000-4000-8000-000000000002","cause_evidence":` + token + `}`
	}
	for _, token := range []string{"\"bad \xc3 byte\"", "\"bad \xff\xfe\"", `"lone \ud800 high"`, `"lone \udfff low"`, `"high then text \ud83dx"`, `"reversed \ude00\ud83d"`, `"truncated \ud83d\u00"`} {
		if _, err := decodeFailedInstalledExternalCauseReplacement(strings.NewReader(withEvidence(token))); err == nil {
			t.Fatal("evidence that does not round-trip exactly accepted", token)
		}
	}
	for token, want := range map[string]string{`"pair 😀 ok"`: "pair \U0001F600 ok", `"esc A \\u d800 \n"`: "esc A \\u d800 \n", "\"raw é\"": "raw é"} {
		request, err := decodeFailedInstalledExternalCauseReplacement(strings.NewReader(withEvidence(token)))
		if err != nil || request.CauseEvidence != want {
			t.Fatal("valid escaped or multi-byte evidence refused or changed", token, request.CauseEvidence, err)
		}
	}
}

func TestFailedInstalledExternalCauseReplacementRequiresAuthenticatedOperator(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	path := "/api/v1/ops/capacity/failed-installed-guest-disposals/external-cause-replacements"
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server := &Server{}
		response := httptest.NewRecorder()
		request := httptest.NewRequest(method, path, strings.NewReader("{}"))
		if method == http.MethodPost {
			server.handleOpsFailedInstalledExternalCauseReplacement(response, request)
		} else {
			server.handleOpsFailedInstalledExternalCauseReplacementRead(response, request)
		}
		if response.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated request reached repository", method, response.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
		request := rbacTestRequestWithClaims(method, path, actor)
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsFailedInstalledExternalCauseReplacement(response, request)
		} else {
			server.handleOpsFailedInstalledExternalCauseReplacementRead(response, request)
		}
		if response.Code != http.StatusForbidden {
			t.Fatal("manage_workflows alone reached repository", method, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodGet} {
		server, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
		request := rbacTestRequestWithClaims(method, path, actor)
		request.Body = http.NoBody
		response := httptest.NewRecorder()
		if method == http.MethodPost {
			server.handleOpsFailedInstalledExternalCauseReplacement(response, request)
		} else {
			request.SetPathValue("preregistrationId", "invalid")
			server.handleOpsFailedInstalledExternalCauseReplacementRead(response, request)
		}
		if response.Code != http.StatusBadRequest {
			t.Fatal("god-mode malformed request reached repository", method, response.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFailedInstalledExternalCauseReplacementSummaryOmitsEvidence(t *testing.T) {
	now := time.Now().UTC()
	v := repository.FailedInstalledExternalCauseAdmission{ID: uuid.NewString(), Schema: repository.FailedInstalledExternalCauseSchema, DisposalID: uuid.NewString(), DisposalStage: "terminal",
		PreregistrationID: uuid.NewString(), PeerPreregistrationID: uuid.NewString(), BlockedGuestSource: strings.Repeat("b", 40), PeerGuestSource: strings.Repeat("b", 40),
		Reason: repository.FailedInstalledExternalCauseReason, CauseEvidenceSHA256: strings.Repeat("a", 64), CauseEvidenceBytes: 117, RecordedAt: now,
		Issuer: "collaborator:" + uuid.NewString()}
	result := failedInstalledExternalCauseSummary(v)
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if result["cause_evidence_is_authority"] != false || result["original_failure_cause_claimed_by_core"] != false || result["original_failure_preserved"] != true ||
		result["same_build_replacement_admitted_for_this_disposal_only"] != true || result["unchanged_binding_and_current_compiled_approval_required"] != true ||
		result["other_disposals_still_checked"] != true || result["provider_read_performed"] != false || result["intent_or_fence_changed"] != false ||
		result["peer_intent_phase"] != "promoted" || result["cause_evidence_sha256"] != v.CauseEvidenceSHA256 || result["cause_evidence_bytes"] != 117 {
		t.Fatal("summary overstates the admission", string(raw))
	}
	for _, forbidden := range []string{"\"cause_evidence\"", "RabbitMQ", "token\":\"", "bearer", "credential", "private_key"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("summary exports the evidence body or private material", forbidden)
		}
	}
}
