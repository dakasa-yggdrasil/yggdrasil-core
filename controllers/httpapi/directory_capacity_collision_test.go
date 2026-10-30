package httpapi

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestDirectoryCapacityCredentialCollisionsFailClosed(t *testing.T) {
	const guestToken = "guest-collision-test-token"
	const hostToken = "host-collision-test-token"
	const mutationToken = "mutation-collision-test-token"
	id := uuid.New()
	directoryPath := "/api/v1/collaborators/" + id.String()
	cases := []struct {
		name, path, directory, bearer, secondBearer, secondDirectory, canary string
		status                                                               int
		reason                                                               string
	}{
		{"guest on directory route", directoryPath, testDirectoryToken, guestToken, "", "", "", 403, "ambiguous_credentials"},
		{"guest on guest route", guestProvisioningBase + "/registrations", testDirectoryToken, guestToken, "", "", "", 403, "ambiguous_credentials"},
		{"host on host route", hostFactoryRouteBase + "/test", testDirectoryToken, hostToken, "", "", "", 403, "ambiguous_credentials"},
		{"mutation on mutation route", capacityMutationBasePath + "/test", testDirectoryToken, mutationToken, "", "", "", 403, "ambiguous_credentials"},
		{"directory bearer then guest", directoryPath, "", testDirectoryToken, guestToken, "", "", 403, "ambiguous_credentials"},
		{"guest bearer then directory", directoryPath, "", guestToken, testDirectoryToken, "", "", 403, "ambiguous_credentials"},
		{"two directory headers", directoryPath, "unknown", "", "", testDirectoryToken, "", 403, "ambiguous_credentials"},
		{"canary header", directoryPath, testDirectoryToken, "", "", "", "present", 403, "ambiguous_credentials"},
		{"canary route", capacityOriginalCanaryAuthorityPath, testDirectoryToken, "", "", "", "", 403, "ambiguous_credentials"},
		{"directory on guest route", guestProvisioningBase + "/registrations", testDirectoryToken, "", "", "", "", 403, "route_not_allowed"},
		{"unknown directory with guest", guestProvisioningBase + "/registrations", "unknown", guestToken, "", "", "", 401, ""},
		{"directory alone", directoryPath, testDirectoryToken, "", "", "", "", 200, "success"},
		{"guest alone isolated", "/healthz", "", guestToken, "", "", "", 403, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			capture := &directoryAuditCapture{}
			base := func(token string) validatedMachinePrincipalBase {
				return validatedMachinePrincipalBase{status: "active", expiresAt: time.Now().Add(time.Hour), tokenSHA256: sha256.Sum256([]byte(token))}
			}
			s := &Server{
				db:                            db,
				directoryAuditSink:            capture.add,
				directoryMachinePrincipals:    loadDirectoryPrincipalsForTest(t),
				capacityGuestPrincipals:       []capacityGuestPrincipal{{base: base(guestToken), role: "provisioner"}},
				capacityHostFactoryPrincipals: []hostFactoryPrincipal{{base: base(hostToken)}},
				capacityMutationPrincipals:    []capacityMutationPrincipal{{base: base(mutationToken)}},
			}
			reached := false
			gate := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(http.StatusTeapot) }))
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.TLS = &tls.ConnectionState{}
			if tc.directory != "" {
				req.Header.Add(directoryMachineTokenHeader, tc.directory)
			}
			if tc.secondDirectory != "" {
				req.Header.Add(directoryMachineTokenHeader, tc.secondDirectory)
			}
			if tc.bearer != "" {
				req.Header.Add("Authorization", "Bearer "+tc.bearer)
			}
			if tc.secondBearer != "" {
				req.Header.Add("Authorization", "Bearer "+tc.secondBearer)
			}
			if tc.canary != "" {
				req.Header.Add(capacityOriginalCanaryAuthorityHeader, tc.canary)
			}
			if tc.reason == "success" {
				mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
					WillReturnRows(directoryCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "active", "Ana Souza", testLookupEmail))
			}
			recorder := httptest.NewRecorder()
			gate.ServeHTTP(recorder, req)
			if recorder.Code != tc.status || reached {
				t.Fatalf("status=%d reached=%v body=%s", recorder.Code, reached, recorder.Body.String())
			}
			if tc.reason == "success" {
				requireSingleAudit(t, capture, "success", directoryCapabilityRead, id.String(), "")
			} else if tc.reason != "" {
				requireSingleAudit(t, capture, "denied", "", "", tc.reason)
			} else if events := capture.snapshot(); len(events) != 0 {
				t.Fatalf("unexpected audit: %+v", events)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDirectoryCapacityCollisionWithholdsDenialWhenAuditFails(t *testing.T) {
	configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
	s := &Server{
		directoryMachinePrincipals: loadDirectoryPrincipalsForTest(t),
		directoryAuditSink:         func(model.AuditEvent) error { return errors.New("audit unavailable") },
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators/"+uuid.NewString(), nil)
	req.Header.Set(directoryMachineTokenHeader, testDirectoryToken)
	req.Header.Set(capacityOriginalCanaryAuthorityHeader, "present")
	w := httptest.NewRecorder()
	s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("reached fallback") })).ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", w.Code)
	}
}

func TestDirectoryPresentEmptyHeaderAndDistinctIdentities(t *testing.T) {
	const secondToken = "second-directory-collision-test-token"
	const secondID = "second-directory"
	const guestToken = "guest-collision-test-token"
	cases := []struct {
		name   string
		path   string
		header string
		bearer string
		canary bool
		status int
		actors []string
	}{
		{"empty public", "/healthz", "", "", false, 401, nil},
		{"whitespace public", "/healthz", " \t ", "", false, 401, nil},
		{"empty guest", guestProvisioningBase + "/registrations", "", guestToken, false, 401, nil},
		{"whitespace guest", guestProvisioningBase + "/registrations", " \t ", guestToken, false, 401, nil},
		{"empty canary", capacityOriginalCanaryAuthorityPath, "", "", true, 401, nil},
		{"whitespace canary", capacityOriginalCanaryAuthorityPath, " \t ", "", true, 401, nil},
		{"empty header directory bearer", "/healthz", "", testDirectoryToken, false, 403, []string{testDirectoryPrincipalID}},
		{"whitespace header directory bearer", "/healthz", " \t ", testDirectoryToken, false, 403, []string{testDirectoryPrincipalID}},
		{"distinct directory identities", "/api/v1/collaborators/" + uuid.NewString(), testDirectoryToken, secondToken, false, 403, []string{testDirectoryPrincipalID, secondID}},
		{"same directory identity twice", "/api/v1/collaborators/" + uuid.NewString(), testDirectoryToken, testDirectoryToken, false, 403, []string{testDirectoryPrincipalID}},
		{"unknown header known bearer", "/api/v1/collaborators/" + uuid.NewString(), "unknown", secondToken, false, 403, []string{secondID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearMachineCredentialEnv(t)
			t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
				testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, []string{directoryCapabilityRead}),
				testDirectoryPrincipalConfig(secondToken, secondID, []string{directoryCapabilityRead})))
			capture := &directoryAuditCapture{}
			s := &Server{
				directoryMachinePrincipals: loadDirectoryPrincipalsForTest(t),
				directoryAuditSink:         capture.add,
				capacityGuestPrincipals: []capacityGuestPrincipal{{base: validatedMachinePrincipalBase{
					status: "active", expiresAt: time.Now().Add(time.Hour), tokenSHA256: sha256.Sum256([]byte(guestToken)),
				}, role: "provisioner"}},
			}
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.TLS = &tls.ConnectionState{}
			req.Header.Set(directoryMachineTokenHeader, tc.header)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.canary {
				req.Header.Set(capacityOriginalCanaryAuthorityHeader, "present")
			}
			reached := false
			gate := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
			w := httptest.NewRecorder()
			gate.ServeHTTP(w, req)
			if w.Code != tc.status || reached {
				t.Fatalf("status=%d reached=%v body=%s", w.Code, reached, w.Body.String())
			}
			events := capture.snapshot()
			if len(events) != len(tc.actors) {
				t.Fatalf("audit count=%d, want %d", len(events), len(tc.actors))
			}
			for _, actor := range tc.actors {
				found := false
				for _, event := range events {
					if event.Actor == "service:"+actor && event.Outcome == "denied" && event.Metadata["reason"] == "ambiguous_credentials" {
						found = true
					}
				}
				if !found {
					t.Fatalf("no attributable denied audit for %q: %+v", actor, events)
				}
			}
			assertAuditNeverCarries(t, events, testDirectoryToken, secondToken, guestToken)
		})
	}
}

func TestDirectoryAmbiguousPrincipalsWithholdDenialOnAuditFailure(t *testing.T) {
	const secondToken = "second-directory-collision-test-token"
	clearMachineCredentialEnv(t)
	t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
		testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, []string{directoryCapabilityRead}),
		testDirectoryPrincipalConfig(secondToken, "second-directory", []string{directoryCapabilityRead})))
	calls := 0
	s := &Server{
		directoryMachinePrincipals: loadDirectoryPrincipalsForTest(t),
		directoryAuditSink: func(model.AuditEvent) error {
			calls++
			return errors.New("audit unavailable")
		},
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators/"+uuid.NewString(), nil)
	req.Header.Set(directoryMachineTokenHeader, "unknown")
	req.Header.Set("Authorization", "Bearer "+secondToken)
	w := httptest.NewRecorder()
	s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("reached fallback") })).ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || calls != 1 {
		t.Fatalf("status=%d audit calls=%d, want 500 and 1", w.Code, calls)
	}
}

func TestDirectoryAmbiguousExpiredAndInactivePrincipals(t *testing.T) {
	const secondToken = "second-directory-inactive-test-token"
	for _, tc := range []struct {
		name, status     string
		mixed, failAudit bool
		wantStatus       int
		wantAudits       int
	}{
		{"expired duplicated", "expired", false, false, 401, 1},
		{"disabled duplicated", "disabled", false, false, 401, 1},
		{"revoked duplicated", "revoked", false, false, 401, 1},
		{"active and expired", "expired", true, false, 403, 2},
		{"active and revoked", "revoked", true, false, 403, 2},
		{"inactive audit unavailable", "disabled", false, true, 500, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearMachineCredentialEnv(t)
			t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
				testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, []string{directoryCapabilityRead}),
				testDirectoryPrincipalConfig(secondToken, "second-directory", []string{directoryCapabilityRead})))
			principals := loadDirectoryPrincipalsForTest(t)
			if tc.status == "expired" {
				principals[0].ExpiresAt = time.Now().Add(-time.Hour)
			} else {
				principals[0].Status = tc.status
			}
			capture := &directoryAuditCapture{}
			sink := capture.add
			if tc.failAudit {
				sink = func(event model.AuditEvent) error {
					_ = capture.add(event)
					return errors.New("audit unavailable")
				}
			}
			s := &Server{directoryMachinePrincipals: principals, directoryAuditSink: sink}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators/"+uuid.NewString(), nil)
			req.Header.Set(directoryMachineTokenHeader, testDirectoryToken)
			bearer := testDirectoryToken
			if tc.mixed {
				bearer = secondToken
			}
			req.Header.Set("Authorization", "Bearer "+bearer)
			w := httptest.NewRecorder()
			s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("reached fallback") })).ServeHTTP(w, req)
			if w.Code != tc.wantStatus || len(capture.snapshot()) != tc.wantAudits {
				t.Fatalf("status=%d audits=%d, want %d and %d", w.Code, len(capture.snapshot()), tc.wantStatus, tc.wantAudits)
			}
			assertAuditNeverCarries(t, capture.snapshot(), testDirectoryToken, secondToken)
		})
	}
}

func TestDirectoryCanaryAuditRedactsMethodAndPath(t *testing.T) {
	const pathSecret = "private-canary-path-secret"
	const methodSecret = "PRIVATE-METHOD-SECRET"
	for _, tc := range []struct {
		name, method, path, canaryHeader, wantMethod, wantPath string
	}{
		{"canary path GET", http.MethodGet, capacityOriginalCanaryAuthorityPath + "/" + pathSecret, "", http.MethodGet, capacityOriginalCanaryAuthorityPath},
		{"canary path private method", methodSecret, capacityOriginalCanaryAuthorityPath + "/" + pathSecret, "", "PRIVATE_REFUSED", capacityOriginalCanaryAuthorityPath},
		{"canary header private path", methodSecret, "/" + pathSecret, "present", "PRIVATE_REFUSED", capacityOriginalCanaryAuthorityPath},
		{"ordinary directory audit retained", http.MethodGet, "/healthz", "", http.MethodGet, "/healthz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
			capture := &directoryAuditCapture{}
			s := &Server{directoryMachinePrincipals: loadDirectoryPrincipalsForTest(t), directoryAuditSink: capture.add}
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set(directoryMachineTokenHeader, testDirectoryToken)
			if tc.canaryHeader != "" {
				req.Header.Set(capacityOriginalCanaryAuthorityHeader, tc.canaryHeader)
			}
			w := httptest.NewRecorder()
			s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("reached fallback") })).ServeHTTP(w, req)
			events := capture.snapshot()
			if w.Code != http.StatusForbidden || len(events) != 1 {
				t.Fatalf("status=%d audit count=%d, want 403 and 1", w.Code, len(events))
			}
			if events[0].Metadata["method"] != tc.wantMethod || events[0].Metadata["path"] != tc.wantPath {
				t.Fatalf("audit metadata=%v, want method=%q path=%q", events[0].Metadata, tc.wantMethod, tc.wantPath)
			}
			assertAuditNeverCarries(t, events, pathSecret, methodSecret, testDirectoryToken)
		})
	}
}

func TestDirectorySecondAmbiguousAuditFailureWithholdsDenial(t *testing.T) {
	const secondToken = "second-directory-second-audit-test-token"
	clearMachineCredentialEnv(t)
	t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
		testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, []string{directoryCapabilityRead}),
		testDirectoryPrincipalConfig(secondToken, "second-directory", []string{directoryCapabilityRead})))
	capture := &directoryAuditCapture{}
	calls := 0
	s := &Server{directoryMachinePrincipals: loadDirectoryPrincipalsForTest(t), directoryAuditSink: func(event model.AuditEvent) error {
		calls++
		if calls == 2 {
			return errors.New("second audit unavailable")
		}
		return capture.add(event)
	}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators/"+uuid.NewString(), nil)
	req.Header.Set(directoryMachineTokenHeader, testDirectoryToken)
	req.Header.Set("Authorization", "Bearer "+secondToken)
	w := httptest.NewRecorder()
	s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("reached fallback") })).ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || calls != 2 || len(capture.snapshot()) != 1 {
		t.Fatalf("status=%d calls=%d persisted=%d, want 500, 2, 1", w.Code, calls, len(capture.snapshot()))
	}
	assertAuditNeverCarries(t, capture.snapshot(), testDirectoryToken, secondToken)
}

func TestDirectoryAuditRedactsUnknownPathAndMethod(t *testing.T) {
	const pathSecret = "unknown-route-credential-secret"
	const methodSecret = "UNKNOWN-METHOD-SECRET"
	id := uuid.NewString()
	for _, tc := range []struct {
		name, method, path, wantMethod, wantPath string
	}{
		{"unknown path", http.MethodGet, "/private/" + pathSecret, http.MethodGet, "/directory/refused"},
		{"unknown method and path", methodSecret, "/private/" + pathSecret, "PRIVATE_REFUSED", "/directory/refused"},
		{"known directory route", http.MethodGet, "/api/v1/collaborators/" + id, http.MethodGet, "/api/v1/collaborators/" + id},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
			capture := &directoryAuditCapture{}
			s := &Server{directoryMachinePrincipals: loadDirectoryPrincipalsForTest(t), directoryAuditSink: capture.add}
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set(directoryMachineTokenHeader, testDirectoryToken)
			if tc.name == "known directory route" {
				// The unknown bearer is accepted by the Directory branch, but a
				// second value makes the request ambiguous before repository use.
				req.Header.Add("Authorization", "Bearer unrelated")
				req.Header.Add("Authorization", "Bearer unrelated-2")
			}
			w := httptest.NewRecorder()
			s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("reached fallback") })).ServeHTTP(w, req)
			events := capture.snapshot()
			if w.Code != http.StatusForbidden || len(events) != 1 {
				t.Fatalf("status=%d audit count=%d, want 403 and 1", w.Code, len(events))
			}
			if events[0].Metadata["method"] != tc.wantMethod || events[0].Metadata["path"] != tc.wantPath {
				t.Fatalf("audit metadata=%v, want method=%q path=%q", events[0].Metadata, tc.wantMethod, tc.wantPath)
			}
			assertAuditNeverCarries(t, events, pathSecret, methodSecret, testDirectoryToken)
		})
	}
}

func TestDirectoryAccessLogRedactsCallerControlledFields(t *testing.T) {
	const secretPath = "directory-private-path-secret"
	const secretMethod = "DIRECTORY-METHOD-SECRET"
	for _, tc := range []struct {
		name, method, path, header, wantMethod, wantPath string
		wantStatus                                       int
	}{
		{"known directory", secretMethod, "/private/" + secretPath, testDirectoryToken, "PRIVATE_REFUSED", "/directory/refused", 403},
		{"unknown directory", secretMethod, "/private/" + secretPath, "unknown", "PRIVATE_REFUSED", "/directory/refused", 401},
		{"empty directory", secretMethod, "/private/" + secretPath, "", "PRIVATE_REFUSED", "/directory/refused", 401},
		{"human unchanged", secretMethod, "/private/" + secretPath, "absent", secretMethod, "/private/" + secretPath, 418},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configureDirectoryPrincipal(t, []string{directoryCapabilityRead})
			core, logs := observer.New(zap.InfoLevel)
			capture := &directoryAuditCapture{}
			s := &Server{logger: zap.New(core), directoryAuditSink: capture.add, directoryMachinePrincipals: loadDirectoryPrincipalsForTest(t)}
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.header != "absent" {
				req.Header.Set(directoryMachineTokenHeader, tc.header)
			}
			gate := s.withLogging(s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })))
			w := httptest.NewRecorder()
			gate.ServeHTTP(w, req)
			if w.Code != tc.wantStatus || logs.Len() != 1 {
				t.Fatalf("status=%d logs=%d, want %d and 1", w.Code, logs.Len(), tc.wantStatus)
			}
			entry := logs.All()[0]
			fields := entry.ContextMap()
			if fields["method"] != tc.wantMethod || fields["path"] != tc.wantPath {
				t.Fatalf("access log method=%v path=%v", fields["method"], fields["path"])
			}
			if tc.header != "absent" {
				encoded, err := json.Marshal(entry)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), secretPath) || strings.Contains(string(encoded), secretMethod) || strings.Contains(string(encoded), testDirectoryToken) {
					t.Fatalf("access log contains sensitive request bytes: %s", encoded)
				}
			}
		})
	}
}

func TestDirectoryUUIDCredentialIsNeverPersistedAsTarget(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		presentTarget, configuredTarget bool
		wantStatus                      int
	}{
		{"presented credential equals target", true, true, 403},
		{"other configured credential equals target", false, true, 403},
		{"unknown presented header equals target", true, false, 403},
		{"ordinary collaborator target", false, false, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := uuid.New()
			target := id.String()
			clearMachineCredentialEnv(t)
			configs := []directoryMachinePrincipalConfig{
				testDirectoryPrincipalConfig(testDirectoryToken, testDirectoryPrincipalID, []string{directoryCapabilityRead}),
			}
			if tc.configuredTarget {
				configs = append(configs, testDirectoryPrincipalConfig(target, "uuid-directory", []string{directoryCapabilityRead}))
			}
			t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t, configs...))
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			capture := &directoryAuditCapture{}
			core, logs := observer.New(zap.InfoLevel)
			s := &Server{db: db, logger: zap.New(core), directoryMachinePrincipals: loadDirectoryPrincipalsForTest(t), directoryAuditSink: capture.add}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators/"+target, nil)
			if tc.presentTarget {
				req.Header.Set(directoryMachineTokenHeader, target)
				if !tc.configuredTarget {
					req.Header.Set("Authorization", "Bearer "+testDirectoryToken)
				}
			} else {
				req.Header.Set(directoryMachineTokenHeader, testDirectoryToken)
			}
			if tc.wantStatus == http.StatusOK {
				mock.ExpectQuery(`FROM public\.collaborators\s+WHERE id = \$1`).WithArgs(id).
					WillReturnRows(directoryCollaboratorRow(sqlmock.NewRows(collaboratorColumns()), id, "active", "Ana Souza", testLookupEmail))
			}
			w := httptest.NewRecorder()
			s.withLogging(s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("reached fallback") }))).ServeHTTP(w, req)
			events := capture.snapshot()
			if w.Code != tc.wantStatus || len(events) != 1 || logs.Len() != 1 {
				t.Fatalf("status=%d audits=%d logs=%d", w.Code, len(events), logs.Len())
			}
			fields := logs.All()[0].ContextMap()
			if tc.wantStatus == http.StatusOK {
				if events[0].ResourceID != target || events[0].Metadata["path"] != req.URL.Path || fields["path"] != req.URL.Path {
					t.Fatalf("ordinary target lost from audit/log: %+v %+v", events[0], fields)
				}
			} else {
				if events[0].ResourceID != "" || events[0].Metadata["path"] != "/directory/refused" || fields["path"] != "/directory/refused" {
					t.Fatalf("colliding target persisted: %+v %+v", events[0], fields)
				}
				assertAuditNeverCarries(t, events, target, testDirectoryToken)
				encoded, err := json.Marshal(logs.All()[0])
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), target) || strings.Contains(w.Body.String(), target) {
					t.Fatalf("colliding target leaked in log or response")
				}
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
