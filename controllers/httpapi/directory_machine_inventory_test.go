package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

func TestDirectoryMachineInventoryIsReadOnceAtBoot(t *testing.T) {
	// The inventory a request sees is the one New validated. Rewriting,
	// emptying, or corrupting the environment after boot changes nothing
	// until the next boot: the boot credential keeps being served, and a
	// credential that exists only in the rewritten environment is unknown.
	const rotatedToken = "directory-token-that-exists-only-after-boot"
	id := uuid.New()
	cases := []struct {
		name    string
		rewrite func(*testing.T)
	}{
		{name: "inventory replaced by another principal", rewrite: func(t *testing.T) {
			t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
				testDirectoryPrincipalConfig(rotatedToken, "rotated-directory", []string{directoryCapabilityRead})))
		}},
		{name: "inventory removed", rewrite: func(t *testing.T) {
			t.Setenv(directoryMachinePrincipalsEnv, "")
		}},
		{name: "inventory corrupted", rewrite: func(t *testing.T) {
			t.Setenv(directoryMachinePrincipalsEnv, `[{"principal_id":"broken"}]`)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
			handler, mock, capture := newDirectoryGateServer(t)
			tc.rewrite(t)

			// The boot credential is still served from the boot inventory.
			mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
				WillReturnRows(directoryCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "active", "Ana Souza", testLookupEmail))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String(), "header", testDirectoryToken))
			if recorder.Code != http.StatusOK {
				t.Fatalf("boot credential after the environment rewrite: status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
			}
			assertMinimalProjection(t, decodeDirectoryBody(t, recorder)["collaborator"].(map[string]any), id, testLookupEmail)
			requireSingleAudit(t, capture, "success", directoryCapabilityRead, id.String(), "")

			// A credential that exists only in the rewritten environment is
			// unknown: in the dedicated header it is refused with nothing to
			// attribute, and as a bearer it is not a directory attempt at
			// all, so it continues to the console session path, which
			// refuses it without a directory audit row.
			recorder = httptest.NewRecorder()
			handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String(), "header", rotatedToken))
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("post-boot credential in the dedicated header: status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
			}
			mock.ExpectQuery(`FROM public\.auth_sessions`).WillReturnError(sql.ErrNoRows)
			recorder = httptest.NewRecorder()
			handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String(), "bearer", rotatedToken))
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("post-boot credential as bearer: status=%d body=%s, want 401 from the console path", recorder.Code, recorder.Body.String())
			}
			if events := capture.snapshot(); len(events) != 1 {
				t.Fatalf("the post-boot credential produced directory audit rows: %+v", events[1:])
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectoryMachineBareServerWithoutInventoryRefusesTheHeaderAndIgnoresBearers(t *testing.T) {
	// A Server with no inventory (the boot found no
	// YGGDRASIL_DIRECTORY_MACHINE_PRINCIPALS_JSON) refuses the dedicated
	// header as unknown and treats a bearer as a console credential, the
	// same contract an empty environment had before the inventory moved to
	// the Server.
	server := &Server{logger: zap.NewNop()}
	reached := false
	gate := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusTeapot)
	}))

	recorder := httptest.NewRecorder()
	gate.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/healthz", "header", testDirectoryToken))
	if recorder.Code != http.StatusUnauthorized || reached {
		t.Fatalf("dedicated header without inventory: status=%d reached=%v, want 401 from the directory branch", recorder.Code, reached)
	}

	recorder = httptest.NewRecorder()
	gate.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/healthz", "bearer", testDirectoryToken))
	if recorder.Code != http.StatusTeapot || !reached {
		t.Fatalf("bearer without inventory: status=%d reached=%v, want the public route to keep its behavior", recorder.Code, reached)
	}
}

func TestNewRefusesEveryMalformedDirectoryInventoryShapeInEveryEnvironment(t *testing.T) {
	// Boot is the only place the inventory is read, so it is the only gate
	// against a malformed one: New refuses to build the server, in the dev
	// environment that skips the production secret checks and in production
	// alike, and names the variable without echoing its content.
	valid := testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, []string{directoryCapabilityRead})
	shapes := []struct {
		name string
		raw  string
	}{
		{name: "missing fields", raw: `[{"principal_id":"broken"}]`},
		{name: "object instead of array", raw: `{}`},
		{name: "empty array", raw: `[]`},
		{name: "raw token field", raw: `[{"principal_id":"x","token":"raw"}]`},
		{name: "trailing json", raw: testDirectoryMachinePrincipalsJSON(t, valid) + "[]"},
		{name: "unknown capability", raw: testDirectoryMachinePrincipalsJSON(t, func() directoryMachinePrincipalConfig {
			c := valid
			c.Capabilities = []string{"directory.write"}
			return c
		}())},
	}
	for _, environment := range []string{"", "production"} {
		for _, shape := range shapes {
			t.Run(environment+"/"+shape.name, func(t *testing.T) {
				if environment == "" {
					clearMachineCredentialEnv(t)
				} else {
					setValidProductionBootEnvironment(t, environment)
				}
				t.Setenv(directoryMachinePrincipalsEnv, shape.raw)
				db, _, err := sqlmock.New()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				handler, err := New("yggdrasil-core-test", db, nil, zap.NewNop())
				if err == nil || handler != nil {
					t.Fatalf("New accepted a malformed directory inventory (handler=%v)", handler)
				}
				if !strings.Contains(err.Error(), directoryMachinePrincipalsEnv) {
					t.Fatalf("boot error does not name the inventory variable: %v", err)
				}
				if strings.Contains(err.Error(), testDirectoryToken) || strings.Contains(err.Error(), testTokenSHA256(testDirectoryToken)) {
					t.Fatalf("boot error leaks credential material: %v", err)
				}
			})
		}
	}
}

func TestDirectoryAuditFailureReasonClassification(t *testing.T) {
	cases := []struct {
		name            string
		err             error
		deadlineExpired bool
		want            string
	}{
		{name: "store unconfigured", err: errDirectoryAuditStoreUnconfigured, want: metrics.DirectoryAuditFailureStoreUnconfigured},
		{name: "wrapped deadline", err: fmt.Errorf("insert audit_event: %w", context.DeadlineExceeded), want: metrics.DirectoryAuditFailureInsertTimeout},
		{name: "deadline text without the sentinel", err: errors.New("insert audit_event: " + context.DeadlineExceeded.Error()), want: metrics.DirectoryAuditFailureInsertFailed},
		{name: "driver cancellation after the deadline fired", err: errors.New("pq: canceling statement due to user request"), deadlineExpired: true, want: metrics.DirectoryAuditFailureInsertTimeout},
		{name: "constraint violation", err: errors.New("pq: value too long for type character varying(255)"), want: metrics.DirectoryAuditFailureInsertFailed},
		{name: "connection refused", err: errors.New("dial tcp: connection refused"), want: metrics.DirectoryAuditFailureInsertFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := directoryAuditFailureReason(tc.err, tc.deadlineExpired); got != tc.want {
				t.Fatalf("reason=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestDirectoryMachineAuditFailureIsCountedByReason(t *testing.T) {
	// Every outcome withheld for lack of an audit row bumps exactly one
	// bucket of yggdrasil_directory_audit_failures_total, labeled with why
	// the row could not be stored. A stored row bumps nothing.
	id := uuid.New()
	collaboratorQuery := func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
			WillReturnRows(directoryCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "active", "Ana Souza", testLookupEmail))
	}
	wantOnly := func(t *testing.T, reason string, count uint64) {
		t.Helper()
		snap := metrics.DirectoryAuditFailuresSnapshot()
		for key, value := range snap {
			want := uint64(0)
			if key == reason {
				want = count
			}
			if value != want {
				t.Fatalf("yggdrasil_directory_audit_failures_total{reason=%q}=%d, want %d (snapshot %v)", key, value, want, snap)
			}
		}
	}
	withheld := func(t *testing.T, recorder *httptest.ResponseRecorder) {
		t.Helper()
		if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "directory audit is unavailable") || strings.Contains(recorder.Body.String(), id.String()) {
			t.Fatalf("status=%d body=%s, want the withheld 500", recorder.Code, recorder.Body.String())
		}
	}

	t.Run("insert rejected by the store", func(t *testing.T) {
		metrics.ResetForTest()
		configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
		handler, mock := newDirectoryGateServerWithDurableAudit(t)
		collaboratorQuery(mock)
		mock.ExpectExec(`INSERT INTO public\.audit_events`).WillReturnError(errors.New("pq: value too long for type character varying(255)"))

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String(), "header", testDirectoryToken))
		withheld(t, recorder)
		wantOnly(t, metrics.DirectoryAuditFailureInsertFailed, 1)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("insert that outlives the write deadline", func(t *testing.T) {
		// sqlmock answers a cancelled statement with its own error, as
		// lib/pq does; the classification must still read the deadline off
		// the write context instead of trusting the driver text.
		metrics.ResetForTest()
		previous := directoryAuditWriteTimeout
		directoryAuditWriteTimeout = 20 * time.Millisecond
		t.Cleanup(func() { directoryAuditWriteTimeout = previous })
		configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
		handler, mock := newDirectoryGateServerWithDurableAudit(t)
		collaboratorQuery(mock)
		mock.ExpectExec(`INSERT INTO public\.audit_events`).WillDelayFor(500 * time.Millisecond).WillReturnResult(sqlmock.NewResult(0, 1))

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String(), "header", testDirectoryToken))
		withheld(t, recorder)
		wantOnly(t, metrics.DirectoryAuditFailureInsertTimeout, 1)
	})

	t.Run("no store at all", func(t *testing.T) {
		metrics.ResetForTest()
		configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
		server := &Server{logger: zap.NewNop(), directoryMachinePrincipals: loadDirectoryPrincipalsForTest(t)}
		gate := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("directory request reached the console handler chain")
		}))

		recorder := httptest.NewRecorder()
		gate.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String(), "header", testDirectoryToken))
		withheld(t, recorder)
		wantOnly(t, metrics.DirectoryAuditFailureStoreUnconfigured, 1)
	})

	t.Run("sink refusals count as insert failures and accumulate", func(t *testing.T) {
		metrics.ResetForTest()
		configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
		handler, mock := newDirectoryGateServerWithOptions(t, withDirectoryAuditSink(func(model.AuditEvent) error {
			return errors.New("sink refused the row")
		}))
		for range 3 {
			collaboratorQuery(mock)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String(), "header", testDirectoryToken))
			withheld(t, recorder)
		}
		wantOnly(t, metrics.DirectoryAuditFailureInsertFailed, 3)
	})

	t.Run("stored row bumps nothing", func(t *testing.T) {
		metrics.ResetForTest()
		configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
		handler, mock := newDirectoryGateServerWithDurableAudit(t)
		collaboratorQuery(mock)
		mock.ExpectExec(`INSERT INTO public\.audit_events`).WillReturnResult(sqlmock.NewResult(0, 1))

		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, directoryRequest(http.MethodGet, "/api/v1/collaborators/"+id.String(), "header", testDirectoryToken))
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
		}
		wantOnly(t, "", 0)
	})
}

func TestHandleMetricsRendersDirectoryAuditFailuresByReason(t *testing.T) {
	metrics.ResetForTest()
	metrics.IncDirectoryAuditFailure(metrics.DirectoryAuditFailureInsertFailed)
	metrics.IncDirectoryAuditFailure(metrics.DirectoryAuditFailureInsertFailed)
	metrics.IncDirectoryAuditFailure(metrics.DirectoryAuditFailureInsertTimeout)

	server := &Server{logger: zap.NewNop()}
	recorder := httptest.NewRecorder()
	server.handleMetrics(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	body := recorder.Body.String()
	for _, expected := range []string{
		"# TYPE yggdrasil_directory_audit_failures_total counter",
		`yggdrasil_directory_audit_failures_total{reason="store_unconfigured"} 0`,
		`yggdrasil_directory_audit_failures_total{reason="insert_timeout"} 1`,
		`yggdrasil_directory_audit_failures_total{reason="insert_failed"} 2`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("expected %q in body:\n%s", expected, body)
		}
	}
}
