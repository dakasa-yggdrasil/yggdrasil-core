package httpapi

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
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
