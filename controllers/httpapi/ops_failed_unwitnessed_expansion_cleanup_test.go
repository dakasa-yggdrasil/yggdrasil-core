package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func TestFailedUnwitnessedExpansionCleanupRequiresAuthenticatedOperator(t *testing.T) {
	for _, mode := range []string{"enforce", "warn"} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", mode)
			for _, method := range []string{http.MethodGet, http.MethodPost} {
				t.Run(method, func(t *testing.T) {
					// Nil DB/broker makes an authentication bypass fail before it
					// could acquire storage or provider authority.
					s := &Server{}
					r := httptest.NewRequest(method, "/api/v1/ops/capacity/failed-unwitnessed-expansion-cleanups", strings.NewReader(`{}`))
					w := httptest.NewRecorder()
					if method == http.MethodGet {
						s.handleOpsFailedUnwitnessedExpansionCleanupRead(w, r)
					} else {
						s.handleOpsFailedUnwitnessedExpansionCleanup(w, r)
					}
					if w.Code != http.StatusUnauthorized {
						t.Fatal("cleanup reached an unauthenticated boundary", w.Code)
					}
				})
			}
		})
	}
}

func TestFailedUnwitnessedExpansionCleanupRejectsCallerEvidenceBeforeStorage(t *testing.T) {
	const grant = "a12b1afc-1b7e-48b2-91dd-accfcc4713e6"
	const job = "04742a97-f45a-46a7-9745-1123fe17f0f4"
	good := `{"grant_id":"` + grant + `","job_id":"` + job + `"}`
	cases := map[string]string{
		"missing_job":        `{"grant_id":"` + grant + `"}`,
		"duplicate_grant":    strings.TrimSuffix(good, "}") + `,"grant_id":"` + grant + `"}`,
		"duplicate_job":      strings.TrimSuffix(good, "}") + `,"job_id":"` + job + `"}`,
		"caller_native_fact": strings.TrimSuffix(good, "}") + `,"native_absent":true}`,
		"caller_ACK":         strings.TrimSuffix(good, "}") + `,"finalization_ack_at":"2026-01-01T00:00:00Z"}`,
		"caller_witness":     strings.TrimSuffix(good, "}") + `,"witness":{}}`,
		"caller_floor":       strings.TrimSuffix(good, "}") + `,"survivor_count":1}`,
		"noncanonical_key":   strings.Replace(good, "grant_id", "GRANT_ID", 1),
		"noncanonical_UUID":  strings.Replace(good, grant, strings.ToUpper(grant), 1),
		"trailing_document":  good + `{}`,
		"oversized_body":     strings.Repeat(" ", 4097) + good,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			s, mock := rbacTestSetup(t)
			actor := uuid.New()
			programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
			r := rbacTestRequestWithClaims(http.MethodPost, "/api/v1/ops/capacity/failed-unwitnessed-expansion-cleanups", actor)
			r.Body = io.NopCloser(strings.NewReader(body))
			r.ContentLength = int64(len(body))
			w := httptest.NewRecorder()
			s.handleOpsFailedUnwitnessedExpansionCleanup(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatal("caller evidence passed the closed identity boundary", w.Code, w.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal("invalid admission acquired additional storage/native work", err)
			}
		})
	}
}

func TestFailedUnwitnessedExpansionCleanupRequiresAdministrativeGrant(t *testing.T) {
	t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", "warn")
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			s, mock := rbacTestSetup(t)
			actor := uuid.New()
			programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
			r := rbacTestRequestWithClaims(method, "/api/v1/ops/capacity/failed-unwitnessed-expansion-cleanups", actor)
			w := httptest.NewRecorder()
			if method == http.MethodGet {
				s.handleOpsFailedUnwitnessedExpansionCleanupRead(w, r)
			} else {
				s.handleOpsFailedUnwitnessedExpansionCleanup(w, r)
			}
			if w.Code != http.StatusForbidden {
				t.Fatal("ordinary workflow permission acquired cleanup authority", w.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFailedUnwitnessedExpansionCleanupSummaryPreservesPrivateEvidenceAndFailure(t *testing.T) {
	record := repository.FailedUnwitnessedExpansionCleanup{
		Schema: repository.FailedUnwitnessedExpansionCleanupSchema,
		ID:     "declared-admission", GrantID: "declared-original-grant", JobID: "declared-failed-job",
		RunID: "declared-failed-run", ChildGrantID: "declared-cleanup-child", OriginalAuxiliaryKnown: false,
	}
	var events []repository.FailedUnwitnessedExpansionCleanupEvent
	for n, stage := range []string{"claimed", "terminate_accepted", "terminal"} {
		events = append(events, repository.FailedUnwitnessedExpansionCleanupEvent{
			Sequence: int64(n + 1), Stage: stage, CleanupID: record.ID, ChildGrantID: record.ChildGrantID,
			Evidence: json.RawMessage(`{"raw_SDK":"PRIVATE_SDK_BYTES","nonce":"PRIVATE_NONCE","token":"PRIVATE_TOKEN","receipt":{"body":"PRIVATE_RECEIPT"}}`),
		})
	}
	for _, count := range []int{0, len(events)} {
		summary := failedUnwitnessedExpansionCleanupSummary(record, events[:count])
		raw, err := json.Marshal(summary)
		if err != nil || strings.Contains(string(raw), "PRIVATE_") || strings.Contains(string(raw), `"evidence":`) {
			t.Fatal("administrative summary exported private event/native evidence", err)
		}
		for _, key := range []string{"original_auxiliary_inventory_complete", "original_guest_success", "clean_cycle_credit", "serving_or_business_or_savings_authority"} {
			if summary[key] != false {
				t.Fatal("cleanup relabelled unknown inventory or the failed original as success", key)
			}
		}
		if summary["grant_id"] != record.GrantID || summary["job_id"] != record.JobID || summary["run_id"] != record.RunID || summary["event_count"] != count {
			t.Fatal("summary lost original failure identity or event extent")
		}
		if count > 0 && summary["stage"] != events[count-1].Stage {
			t.Fatal("summary omitted the actual latest cleanup stage")
		}
	}
}
