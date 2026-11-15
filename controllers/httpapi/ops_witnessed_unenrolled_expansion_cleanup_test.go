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

// Existing owning inventory root calls this helper; no additional root or
// protocol-bearing fixture endpoint is introduced.
func witnessedUnenrolledCleanupHTTPBoundaries(t *testing.T) {
	t.Helper()
	const base = "/api/v1/ops/capacity/witnessed-unenrolled-expansion-cleanups"
	const grant = "a12b1afc-1b7e-48b2-91dd-accfcc4713e6"
	const job = "04742a97-f45a-46a7-9745-1123fe17f0f4"
	good := `{"grant_id":"` + grant + `","job_id":"` + job + `"}`
	call := func(s *Server, method string, w http.ResponseWriter, r *http.Request) {
		if method == http.MethodGet {
			s.handleOpsWitnessedUnenrolledExpansionCleanupRead(w, r)
		} else {
			s.handleOpsWitnessedUnenrolledExpansionCleanup(w, r)
		}
	}
	for _, mode := range []string{"enforce", "warn"} {
		t.Setenv("YGGDRASIL_CONSOLE_RBAC_ENFORCE", mode)
		for _, method := range []string{http.MethodPost, http.MethodGet} {
			s := &Server{}
			w := httptest.NewRecorder()
			call(s, method, w, httptest.NewRequest(method, base, strings.NewReader(good)))
			if w.Code != http.StatusUnauthorized {
				t.Fatal("witnessed cleanup reached nil storage without a human", mode, method, w.Code)
			}
			r := httptest.NewRequest(method, base, strings.NewReader(good))
			r.Header.Set("Authorization", "Bearer declared-workflow-only-credential")
			w = httptest.NewRecorder()
			s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { call(s, method, w, r) })).ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatal("nonhuman credential crossed witnessed cleanup gate", mode, method, w.Code)
			}
			s, mock := rbacTestSetup(t)
			actor := uuid.New()
			programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:manage_workflows"})
			r = rbacTestRequestWithClaims(method, base, actor)
			r.Body = io.NopCloser(strings.NewReader(good))
			r.SetPathValue("grantId", grant)
			w = httptest.NewRecorder()
			call(s, method, w, r)
			if w.Code != http.StatusForbidden {
				t.Fatal("ordinary workflow permission acquired cleanup authority", mode, method, w.Code)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal("wrong permission reached additional storage", err)
			}
		}
	}
	// A permitted human still cannot supply native/ACK/floor claims, ambiguous
	// identities or oversized/trailing data. No repository call is expected.
	for _, body := range []string{
		`{}`, `null`, `[]`, `{"grant_id":"` + grant + `"}`, `{"grant_id":"` + grant + `","job_id":null}`,
		strings.TrimSuffix(good, "}") + `,"grant_id":"` + grant + `"}`,
		strings.TrimSuffix(good, "}") + `,"native_absent":true}`,
		strings.TrimSuffix(good, "}") + `,"finalization_ack_at":"2026-01-01T00:00:00Z"}`,
		strings.TrimSuffix(good, "}") + `,"survivor_count":1}`,
		strings.Replace(good, grant, strings.ToUpper(grant), 1), good + `{}`, strings.Repeat(" ", 4097) + good,
	} {
		s, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
		r := rbacTestRequestWithClaims(http.MethodPost, base, actor)
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		w := httptest.NewRecorder()
		s.handleOpsWitnessedUnenrolledExpansionCleanup(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatal("witnessed cleanup accepted caller authority/ambiguous body", w.Code, w.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal("invalid body reached additional storage", err)
		}
	}
	for _, id := range []string{"", "not-a-uuid", uuid.Nil.String(), strings.ToUpper(grant)} {
		s, mock := rbacTestSetup(t)
		actor := uuid.New()
		programCollaboratorWithPermissions(mock, actor, []string{"yggdrasil:*"})
		r := rbacTestRequestWithClaims(http.MethodGet, base, actor)
		r.SetPathValue("grantId", id)
		w := httptest.NewRecorder()
		s.handleOpsWitnessedUnenrolledExpansionCleanupRead(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatal("invalid witnessed cleanup GET identity reached storage", id, w.Code)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	}
	record := repository.WitnessedUnenrolledExpansionCleanup{Schema: repository.WitnessedUnenrolledExpansionCleanupSchema, OriginalWitnessWire: []byte("PRIVATE_WITNESS"), OriginalSDKReturnWire: []byte("PRIVATE_SDK"), OriginalRunWire: []byte("PRIVATE_RUN")}
	events := []repository.WitnessedUnenrolledExpansionCleanupEvent{{Stage: "terminal", Evidence: json.RawMessage(`{"private":"PRIVATE_NATIVE"}`)}}
	summary := witnessedUnenrolledExpansionCleanupSummary(record, events)
	raw, err := json.Marshal(summary)
	if err != nil || strings.Contains(string(raw), "PRIVATE_") {
		t.Fatal("witnessed cleanup summary leaked retained private evidence", err)
	}
	for _, key := range []string{"original_guest_success", "clean_cycle_credit", "serving_or_business_or_savings_authority"} {
		if summary[key] != false {
			t.Fatal("cleanup summary invented authority", key)
		}
	}
}
