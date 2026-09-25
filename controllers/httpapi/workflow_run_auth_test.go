package httpapi

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// ADR-0022: the workflow-run credential surface is loaded once, a blank
// inventory is refused, cross-scope digests refuse the colliding surface,
// refused bridge settings never lock principals out, the credential-free
// posture needs an explicit development YGGDRASIL_ENV, and every use of the
// legacy bridge is logged, counted, audited and stamped.

const (
	workflowAuthPrincipalToken = "workflow-auth-principal-token"
	workflowAuthPrincipalID    = "cd-web-rollout-dispatcher"
	workflowAuthLegacyToken    = "workflow-auth-legacy-token"
	workflowAuthBootSummary    = "workflow run credential surface loaded"
	workflowAuthRefusedLine    = "workflow machine principal inventory refused; every machine request to /api/v1/workflow-runs answers 401 until Core restarts with a valid inventory"
	workflowAuthLegacyLine     = "legacy workflow-run bridge settings refused; the bridge and anonymous dispatch are off, workflow principals keep working"
	workflowAuthDirectoryLine  = "directory machine principal digest collides with another credential scope; directory machine reads answer 401"
	legacyBridgeAcceptedLine   = "legacy workflow-run bridge accepted"
	workflowAuthGenericEvent   = `{"type":"deployment.completed","aggregate_type":"deployment","aggregate_id":"one","payload":{}}`
)

var workflowAuthAllowedWorkflow = machineWorkflowRef{Namespace: "dakasa", Name: "roll-app-fe-web-production"}

// clearWorkflowRunAuthEnv unsets every variable the machine credential
// surfaces read, so each test states exactly what it configures.
func clearWorkflowRunAuthEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		workflowMachinePrincipalsEnv,
		legacyScopedWorkflowTokensEnv,
		"YGGDRASIL_WORKFLOW_RUN_TOKEN",
		"YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED",
		"YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT",
		"YGGDRASIL_WORKFLOW_RUN_LEGACY_SUBJECT_TYPE",
		"YGGDRASIL_WORKFLOW_RUN_LEGACY_SUBJECT_ID",
		eventPublisherPrincipalsEnv,
		legacyEventPublishTokenEnv,
		legacyEventPublishEnabledEnv,
		legacyEventPublishExpiryEnv,
		directoryMachinePrincipalsEnv,
		"YGGDRASIL_DEPLOY_TOKEN",
		"YGGDRASIL_AUTH_ADMIN_TOKEN",
		"YGGDRASIL_CONSOLE_JWT_AUDIENCES",
		"BROKER_URL",
	} {
		unsetEnvForTest(t, key)
	}
}

func setWorkflowAuthPrincipal(t *testing.T, token string) {
	t.Helper()
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, token, workflowAuthPrincipalID, workflowAuthAllowedWorkflow))
}

func workflowDispatchRequest(bearer string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", strings.NewReader(`{}`))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return req
}

func workflowPollRequest(bearer string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/workflow-runs/"+uuid.NewString(), nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return req
}

func newWorkflowAuthBootServer(t *testing.T, logger *zap.Logger) (http.Handler, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if logger == nil {
		logger = zap.NewNop()
	}
	handler, err := New("yggdrasil-core-test", db, nil, logger)
	if err != nil {
		t.Fatalf("New refused to boot: %v", err)
	}
	return handler, mock
}

func serveWorkflowAuth(handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func TestWorkflowMachinePrincipalsRefuseSetButBlankInventory(t *testing.T) {
	for _, blank := range []string{"", "  ", "\n"} {
		t.Run(strconv.Quote(blank), func(t *testing.T) {
			unsetEnvForTest(t, legacyScopedWorkflowTokensEnv)
			t.Setenv(workflowMachinePrincipalsEnv, blank)
			principals, err := workflowMachinePrincipalsFromEnv()
			if err == nil || !strings.Contains(err.Error(), workflowMachinePrincipalsEnv+" is set but blank") || principals != nil {
				t.Fatalf("a set but blank inventory was not refused: principals=%v err=%v", principals, err)
			}
		})
	}
	t.Run("unset", func(t *testing.T) {
		unsetEnvForTest(t, legacyScopedWorkflowTokensEnv)
		unsetEnvForTest(t, workflowMachinePrincipalsEnv)
		principals, err := workflowMachinePrincipalsFromEnv()
		if err != nil || principals != nil {
			t.Fatalf("an unset inventory must mean no principals: principals=%v err=%v", principals, err)
		}
	})
	for _, raw := range []string{"null", "[]"} {
		t.Run(raw, func(t *testing.T) {
			unsetEnvForTest(t, legacyScopedWorkflowTokensEnv)
			t.Setenv(workflowMachinePrincipalsEnv, raw)
			if _, err := workflowMachinePrincipalsFromEnv(); err == nil {
				t.Fatalf("%s was accepted as an inventory", raw)
			}
		})
	}
}

func TestRefusedWorkflowInventoryNeverFallsBackToAnonymous(t *testing.T) {
	clearWorkflowRunAuthEnv(t)
	// Even the explicit development environment cannot turn a refused
	// inventory into the credential-free posture.
	t.Setenv("YGGDRASIL_ENV", "dev")
	t.Setenv(workflowMachinePrincipalsEnv, "  ")

	server := &Server{}
	if config := server.workflowRunAuthConfig(); config.err == nil {
		t.Fatal("the loaded surface kept a blank inventory")
	}
	for _, req := range []*http.Request{workflowDispatchRequest(""), workflowPollRequest("")} {
		if _, err := server.authenticateWorkflowRunRequest(req); !errors.Is(err, errWorkflowRunUnauthorized) {
			t.Fatalf("%s %s: err=%v, want 401", req.Method, req.URL.Path, err)
		}
	}
	recorder := httptest.NewRecorder()
	server.handleWorkflowRun(recorder, workflowDispatchRequest(""))
	if recorder.Code != http.StatusUnauthorized || strings.Contains(recorder.Body.String(), workflowMachinePrincipalsEnv) {
		t.Fatalf("dispatch: status=%d body=%s, want a 401 without the parser diagnostics", recorder.Code, recorder.Body.String())
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/workflow-runs/{run_id}", server.handleWorkflowRunGet)
	recorder = httptest.NewRecorder()
	mux.ServeHTTP(recorder, workflowPollRequest(""))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("poll: status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
	}
	if server.manifestWriteAuthorized(httptest.NewRequest(http.MethodPost, "/api/v1/manifests", nil)) {
		t.Fatal("a refused workflow inventory opened anonymous manifest writes")
	}

	// Through New and the full gate: Core boots, logs the refusal once, and
	// answers 401 to both routes.
	core, logs := observer.New(zapcore.InfoLevel)
	handler, mock := newWorkflowAuthBootServer(t, zap.New(core))
	for _, req := range []*http.Request{workflowDispatchRequest(""), workflowPollRequest("")} {
		if recorder := serveWorkflowAuth(handler, req); recorder.Code != http.StatusUnauthorized {
			t.Fatalf("gate %s %s: status=%d body=%s, want 401", req.Method, req.URL.Path, recorder.Code, recorder.Body.String())
		}
	}
	if logs.FilterMessage(workflowAuthRefusedLine).Len() != 1 {
		t.Fatalf("the refused inventory was not logged once: %v", logs.All())
	}
	summaries := logs.FilterMessage(workflowAuthBootSummary).All()
	if len(summaries) != 1 {
		t.Fatalf("boot summaries=%d, want 1", len(summaries))
	}
	fields := summaries[0].ContextMap()
	if fields["workflow_refused"] != true || fields["usable"] != int64(0) || fields["anonymous_allowed"] != false {
		t.Fatalf("summary=%v", fields)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestServerNewLoadsWorkflowRunAuthEagerly(t *testing.T) {
	clearWorkflowRunAuthEnv(t)
	unsetEnvForTest(t, "YGGDRASIL_ENV")
	setWorkflowAuthPrincipal(t, workflowAuthPrincipalToken)
	handler, mock := newWorkflowAuthBootServer(t, nil)

	// Changing the environment after New changes nothing until a restart:
	// the principal loaded at start still authenticates, and the gate still
	// sees a configured surface, so an anonymous caller stays out even
	// though the environment now looks credential-free and development.
	unsetEnvForTest(t, workflowMachinePrincipalsEnv)
	t.Setenv("YGGDRASIL_ENV", "dev")

	// Authenticated by the gate and by the handler; with no broker the
	// handler then answers 503.
	if recorder := serveWorkflowAuth(handler, workflowDispatchRequest(workflowAuthPrincipalToken)); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("loaded principal: status=%d body=%s, want 503 (authenticated, broker-degraded)", recorder.Code, recorder.Body.String())
	}
	if recorder := serveWorkflowAuth(handler, workflowDispatchRequest("")); recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous after start: status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestLiteralServerLoadsWorkflowRunAuthOnceOnFirstUse(t *testing.T) {
	clearWorkflowRunAuthEnv(t)
	unsetEnvForTest(t, "YGGDRASIL_ENV")
	server := &Server{}

	// Building the literal reads nothing: the environment at first use counts.
	setWorkflowAuthPrincipal(t, workflowAuthPrincipalToken)
	actor, err := server.authenticateWorkflowRunRequest(workflowDispatchRequest(workflowAuthPrincipalToken))
	if err != nil || actor.MachinePrincipalID != workflowAuthPrincipalID {
		t.Fatalf("first use: actor=%+v err=%v", actor, err)
	}

	// Later changes do not reach this server.
	t.Setenv(workflowMachinePrincipalsEnv, testWorkflowMachinePrincipalsJSON(t, "rotated-token", "rotated-principal", workflowAuthAllowedWorkflow))
	if _, err := server.authenticateWorkflowRunRequest(workflowDispatchRequest("rotated-token")); err == nil {
		t.Fatal("a literal Server re-read the inventory after its first use")
	}
	if _, err := server.authenticateWorkflowRunRequest(workflowPollRequest(workflowAuthPrincipalToken)); err != nil {
		t.Fatalf("the loaded principal stopped matching: %v", err)
	}

	// A fresh literal reads the new environment.
	if _, err := (&Server{}).authenticateWorkflowRunRequest(workflowDispatchRequest("rotated-token")); err != nil {
		t.Fatalf("a fresh literal did not read the current environment: %v", err)
	}

	// A literal that carries a surface keeps it and never loads another.
	preset := &workflowRunAuthConfig{}
	presetServer := &Server{workflowRunAuth: preset}
	if presetServer.workflowRunAuthConfig() != preset {
		t.Fatal("a preset surface was replaced by an environment load")
	}
	if _, err := presetServer.authenticateWorkflowRunRequest(workflowDispatchRequest("rotated-token")); err == nil {
		t.Fatal("a preset empty surface authenticated a principal from the environment")
	}
}

func TestWorkflowRunAuthIsLoadedOnce(t *testing.T) {
	clearWorkflowRunAuthEnv(t)
	setWorkflowAuthPrincipal(t, workflowAuthPrincipalToken)
	server := &Server{}

	configs := make([]*workflowRunAuthConfig, 16)
	var wg sync.WaitGroup
	for index := range configs {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			configs[index] = server.workflowRunAuthConfig()
		}(index)
	}
	wg.Wait()
	for index, config := range configs {
		if config == nil || config != configs[0] {
			t.Fatalf("call %d returned %p, want the one loaded surface %p", index, config, configs[0])
		}
	}

	unsetEnvForTest(t, workflowMachinePrincipalsEnv)
	if server.workflowRunAuthConfig() != configs[0] {
		t.Fatal("a later call loaded the surface again")
	}
	if len(configs[0].principals) != 1 || configs[0].err != nil {
		t.Fatalf("loaded surface=%+v", configs[0])
	}
}

func TestLegacyWorkflowBridgeErrorKeepsPrincipals(t *testing.T) {
	clearWorkflowRunAuthEnv(t)
	t.Setenv("YGGDRASIL_ENV", "dev")
	setWorkflowAuthPrincipal(t, workflowAuthPrincipalToken)
	// The token without YGGDRASIL_WORKFLOW_RUN_LEGACY_ENABLED=true is refused
	// bridge settings.
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", workflowAuthLegacyToken)

	server := &Server{}
	config := server.workflowRunAuthConfig()
	if config.err != nil || config.legacyErr == nil {
		t.Fatalf("err=%v legacyErr=%v, want only the bridge refused", config.err, config.legacyErr)
	}
	for _, req := range []*http.Request{workflowDispatchRequest(workflowAuthPrincipalToken), workflowPollRequest(workflowAuthPrincipalToken)} {
		actor, err := server.authenticateWorkflowRunRequest(req)
		if err != nil || actor.Subject != (model.RBACSubject{Type: "service", ID: workflowAuthPrincipalID}) || actor.LegacyMigration {
			t.Fatalf("%s: the principal was locked out by refused bridge settings: actor=%+v err=%v", req.Method, actor, err)
		}
	}
	for _, bearer := range []string{workflowAuthLegacyToken, "", "wrong-token"} {
		if _, err := server.authenticateWorkflowRunRequest(workflowDispatchRequest(bearer)); !errors.Is(err, errWorkflowRunUnauthorized) {
			t.Fatalf("bearer %q: err=%v, want 401", bearer, err)
		}
	}

	// With no principal either, refused bridge settings still keep the
	// credential-free posture closed in a development environment.
	unsetEnvForTest(t, workflowMachinePrincipalsEnv)
	if _, err := (&Server{}).authenticateWorkflowRunRequest(workflowDispatchRequest("")); !errors.Is(err, errWorkflowRunUnauthorized) {
		t.Fatalf("refused bridge settings opened the anonymous posture: %v", err)
	}
}

func TestRetiredBridgeShapeLeavesLegacyUnconfigured(t *testing.T) {
	for _, mask := range []string{"", " "} {
		t.Run(strconv.Quote(mask), func(t *testing.T) {
			clearWorkflowRunAuthEnv(t)
			unsetEnvForTest(t, "YGGDRASIL_ENV")
			setWorkflowAuthPrincipal(t, workflowAuthPrincipalToken)
			// The retirement patch: an explicit empty token masks the envFrom
			// value, and ENABLED and EXPIRES_AT are deleted.
			t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", mask)

			config := loadWorkflowRunAuthConfig(nil, nil)
			if config.err != nil || config.legacyErr != nil || config.legacy.Configured || len(config.principals) != 1 {
				t.Fatalf("config=%+v, want principals and an unconfigured bridge", config)
			}
			server := &Server{workflowRunAuth: config}
			if _, err := server.authenticateWorkflowRunRequest(workflowDispatchRequest("")); !errors.Is(err, errWorkflowRunUnauthorized) {
				t.Fatalf("no credential: err=%v, want 401", err)
			}
			if actor, err := server.authenticateWorkflowRunRequest(workflowDispatchRequest(workflowAuthPrincipalToken)); err != nil || actor.MachinePrincipalID != workflowAuthPrincipalID {
				t.Fatalf("principal: actor=%+v err=%v", actor, err)
			}
		})
	}
}

func TestAnonymousWorkflowPostureRequiresExplicitDevelopmentEnv(t *testing.T) {
	for _, test := range []struct {
		name        string
		environment *string
		allowed     bool
	}{
		{name: "unset"},
		{name: "empty", environment: stringPointer("")},
		{name: "production", environment: stringPointer("production")},
		{name: "prod", environment: stringPointer("prod")},
		{name: "staging", environment: stringPointer("staging")},
		{name: "validation", environment: stringPointer("validation")},
		{name: "dev", environment: stringPointer("dev"), allowed: true},
		{name: "development", environment: stringPointer("development"), allowed: true},
		{name: "local", environment: stringPointer("local"), allowed: true},
		{name: "test", environment: stringPointer("test"), allowed: true},
		{name: "padded mixed case", environment: stringPointer(" Development "), allowed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearWorkflowRunAuthEnv(t)
			if test.environment == nil {
				unsetEnvForTest(t, "YGGDRASIL_ENV")
			} else {
				t.Setenv("YGGDRASIL_ENV", *test.environment)
			}
			if got := machineAnonymousAllowed(); got != test.allowed {
				t.Fatalf("machineAnonymousAllowed=%v, want %v", got, test.allowed)
			}
			for _, req := range []*http.Request{workflowDispatchRequest(""), workflowPollRequest("")} {
				_, err := (&Server{}).authenticateWorkflowRunRequest(req)
				if (err == nil) != test.allowed {
					t.Fatalf("%s %s: err=%v, want allowed=%v", req.Method, req.URL.Path, err, test.allowed)
				}
			}
			if got := (&Server{}).manifestWriteAuthorized(httptest.NewRequest(http.MethodPost, "/api/v1/manifests", nil)); got != test.allowed {
				t.Fatalf("anonymous manifest write authorized=%v, want %v", got, test.allowed)
			}

			called := false
			gate := (&Server{}).requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			}))
			recorder := serveWorkflowAuth(gate, workflowDispatchRequest(""))
			if called != test.allowed {
				t.Fatalf("gate called=%v status=%d, want allowed=%v", called, recorder.Code, test.allowed)
			}
			if !test.allowed && recorder.Code != http.StatusUnauthorized {
				t.Fatalf("gate status=%d, want 401", recorder.Code)
			}
		})
	}
}

func TestEventAnonymousPostureRequiresExplicitDevelopmentEnv(t *testing.T) {
	for _, test := range []struct {
		name        string
		environment *string
		allowed     bool
	}{
		{name: "unset"},
		{name: "empty", environment: stringPointer("")},
		{name: "production", environment: stringPointer("production")},
		{name: "prod", environment: stringPointer("prod")},
		{name: "staging", environment: stringPointer("staging")},
		{name: "dev", environment: stringPointer("dev"), allowed: true},
		{name: "development", environment: stringPointer("development"), allowed: true},
		{name: "local", environment: stringPointer("local"), allowed: true},
		{name: "test", environment: stringPointer("test"), allowed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			setEventPublishAuthEnvironment(t, "", "")
			if test.environment == nil {
				unsetEnvForTest(t, "YGGDRASIL_ENV")
			} else {
				t.Setenv("YGGDRASIL_ENV", *test.environment)
			}
			err := eventPublishServerFromEnv(t).authorizeEventPublishRequest(httptest.NewRequest(http.MethodPost, "/api/v1/events", nil))
			if (err == nil) != test.allowed {
				t.Fatalf("anonymous event publish err=%v, want allowed=%v", err, test.allowed)
			}
		})
	}
}

func TestWorkflowPrincipalDigestCollisionRefusesWorkflowSurface(t *testing.T) {
	const shared = "shared-across-scopes-token"
	for _, test := range []struct {
		name  string
		setup func(t *testing.T)
		want  string
	}{
		{
			name: "directory principal",
			setup: func(t *testing.T) {
				t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
					testDirectoryPrincipalConfig(shared, testDirectoryPrincipalID, []string{directoryCapabilityRead})))
			},
			want: directoryMachinePrincipalsEnv + " entry 0",
		},
		{
			name: "event principal",
			setup: func(t *testing.T) {
				t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, shared, "adapter-aws"))
			},
			want: eventPublisherPrincipalsEnv + " entry 0",
		},
		{
			name:  "legacy workflow bridge",
			setup: func(t *testing.T) { setTestLegacyWorkflowCredential(t, shared) },
			want:  "must differ from YGGDRASIL_WORKFLOW_RUN_TOKEN",
		},
		{
			name:  "legacy event bridge",
			setup: func(t *testing.T) { setTestLegacyEventPublishCredential(t, shared) },
			want:  "must differ from " + legacyEventPublishTokenEnv,
		},
		{
			name:  "deploy token",
			setup: func(t *testing.T) { t.Setenv("YGGDRASIL_DEPLOY_TOKEN", shared) },
			want:  "must differ from YGGDRASIL_DEPLOY_TOKEN",
		},
		{
			name:  "auth-admin token",
			setup: func(t *testing.T) { t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", shared) },
			want:  "must differ from YGGDRASIL_AUTH_ADMIN_TOKEN",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearWorkflowRunAuthEnv(t)
			t.Setenv("YGGDRASIL_ENV", "dev")
			setWorkflowAuthPrincipal(t, shared)
			test.setup(t)
			events, err := eventPublisherPrincipalsFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			directory, err := directoryMachinePrincipalsFromEnv()
			if err != nil {
				t.Fatal(err)
			}

			config := loadWorkflowRunAuthConfig(events, directory)
			if config.err == nil || !strings.Contains(config.err.Error(), workflowMachinePrincipalsEnv+" entry 0") || !strings.Contains(config.err.Error(), test.want) {
				t.Fatalf("err=%v, want a refusal naming %q", config.err, test.want)
			}
			if strings.Contains(config.err.Error(), shared) || strings.Contains(config.err.Error(), testTokenSHA256(shared)) {
				t.Fatalf("the refusal leaks credential material: %v", config.err)
			}
			server := &Server{workflowRunAuth: config}
			for _, bearer := range []string{shared, ""} {
				if _, err := server.authenticateWorkflowRunRequest(workflowDispatchRequest(bearer)); !errors.Is(err, errWorkflowRunUnauthorized) {
					t.Fatalf("bearer %q on a refused surface: err=%v, want 401", bearer, err)
				}
			}
		})
	}

	t.Run("distinct credentials load", func(t *testing.T) {
		clearWorkflowRunAuthEnv(t)
		setWorkflowAuthPrincipal(t, workflowAuthPrincipalToken)
		setTestLegacyWorkflowCredential(t, workflowAuthLegacyToken)
		t.Setenv("YGGDRASIL_DEPLOY_TOKEN", "deploy-only-token")
		t.Setenv("YGGDRASIL_AUTH_ADMIN_TOKEN", "auth-admin-only-token")
		t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, "event-only-token", "adapter-aws"))
		events, err := eventPublisherPrincipalsFromEnv()
		if err != nil {
			t.Fatal(err)
		}
		if config := loadWorkflowRunAuthConfig(events, nil); config.err != nil || config.legacyErr != nil {
			t.Fatalf("distinct credentials were refused: err=%v legacyErr=%v", config.err, config.legacyErr)
		}
	})

	t.Run("through New only the workflow surface is refused", func(t *testing.T) {
		clearWorkflowRunAuthEnv(t)
		unsetEnvForTest(t, "YGGDRASIL_ENV")
		setWorkflowAuthPrincipal(t, shared)
		t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, shared, "adapter-aws"))
		core, logs := observer.New(zapcore.InfoLevel)
		handler, mock := newWorkflowAuthBootServer(t, zap.New(core))
		if logs.FilterMessage(workflowAuthRefusedLine).Len() != 1 {
			t.Fatalf("the collision was not logged: %v", logs.All())
		}
		// The workflow bearer reaches no workflow match; the gate hands it
		// to the session path, which does not know it either.
		mock.ExpectQuery(`FROM public\.auth_sessions`).WillReturnError(sql.ErrNoRows)
		if recorder := serveWorkflowAuth(handler, workflowDispatchRequest(shared)); recorder.Code != http.StatusUnauthorized {
			t.Fatalf("workflow dispatch: status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
		}
		// The event surface is untouched: the principal authenticates and
		// its generic event is refused with 403.
		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(workflowAuthGenericEvent))
		req.Header.Set("Authorization", "Bearer "+shared)
		if recorder := serveWorkflowAuth(handler, req); recorder.Code != http.StatusForbidden {
			t.Fatalf("event publish: status=%d body=%s, want 403", recorder.Code, recorder.Body.String())
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
}

func TestDirectoryEventDigestCollisionRefusesDirectorySurfaceOnly(t *testing.T) {
	const shared = "directory-and-event-token"
	for _, collision := range []struct {
		name  string
		setup func(t *testing.T)
		// eventStillPublishes is true when the colliding scope is the event
		// inventory, so the test can prove that surface is untouched.
		eventStillPublishes bool
	}{
		{
			name: "event principal",
			setup: func(t *testing.T) {
				t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, shared, "adapter-aws"))
			},
			eventStillPublishes: true,
		},
		{
			name:  "deploy token",
			setup: func(t *testing.T) { t.Setenv("YGGDRASIL_DEPLOY_TOKEN", shared) },
		},
	} {
		t.Run(collision.name, func(t *testing.T) {
			clearMachineCredentialEnv(t)
			clearWorkflowRunAuthEnv(t)
			t.Setenv(directoryMachinePrincipalsEnv, testDirectoryMachinePrincipalsJSON(t,
				testDirectoryPrincipalConfig(shared, testDirectoryPrincipalID, []string{directoryCapabilityRead})))
			collision.setup(t)
			setWorkflowAuthPrincipal(t, workflowAuthPrincipalToken)

			core, logs := observer.New(zapcore.InfoLevel)
			handler, mock := newWorkflowAuthBootServer(t, zap.New(core))
			if logs.FilterMessage(workflowAuthDirectoryLine).Len() != 1 {
				t.Fatalf("the directory collision was not logged once: %v", logs.All())
			}
			summaries := logs.FilterMessage(workflowAuthBootSummary).All()
			if len(summaries) != 1 || summaries[0].ContextMap()["directory_refused"] != true || summaries[0].ContextMap()["workflow_refused"] != false {
				t.Fatalf("summary=%v", summaries)
			}

			// Directory reads answer 401: the dedicated header matches no
			// served principal.
			read := httptest.NewRequest(http.MethodGet, "/api/v1/collaborators/"+uuid.NewString(), nil)
			read.Header.Set(directoryMachineTokenHeader, shared)
			if recorder := serveWorkflowAuth(handler, read); recorder.Code != http.StatusUnauthorized {
				t.Fatalf("directory read: status=%d body=%s, want 401", recorder.Code, recorder.Body.String())
			}
			if collision.eventStillPublishes {
				// The event principal keeps its scope: authenticated, then its
				// generic event is refused with 403, not the directory 403.
				req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(workflowAuthGenericEvent))
				req.Header.Set("Authorization", "Bearer "+shared)
				if recorder := serveWorkflowAuth(handler, req); recorder.Code != http.StatusForbidden || strings.Contains(recorder.Body.String(), "directory") {
					t.Fatalf("event publish: status=%d body=%s, want the event 403", recorder.Code, recorder.Body.String())
				}
			}
			// The workflow surface is untouched: authenticated, then 503
			// without a broker.
			if recorder := serveWorkflowAuth(handler, workflowDispatchRequest(workflowAuthPrincipalToken)); recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("workflow dispatch: status=%d body=%s, want 503", recorder.Code, recorder.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// legacyBridgeStampArg matches the metadata argument of the workflow_runs
// insert and requires the server-authored legacy bridge stamp.
type legacyBridgeStampArg struct{}

func (legacyBridgeStampArg) Match(value driver.Value) bool {
	var raw []byte
	switch typed := value.(type) {
	case string:
		raw = []byte(typed)
	case []byte:
		raw = typed
	default:
		return false
	}
	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return false
	}
	_, machine := metadata[repository.WorkflowRunCreatorMachinePrincipalMetadataKey]
	return metadata[repository.WorkflowRunCreatorLegacyBridgeMetadataKey] == "true" && !machine
}

type legacyBridgeAuditCapture struct {
	mu   sync.Mutex
	rows []model.AuditEvent
}

func (c *legacyBridgeAuditCapture) add(event model.AuditEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows = append(c.rows, event)
	return nil
}

func (c *legacyBridgeAuditCapture) snapshot() []model.AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]model.AuditEvent(nil), c.rows...)
}

func TestLegacyBridgeUseIsLoggedCountedAuditedAndStamped(t *testing.T) {
	clearWorkflowRunAuthEnv(t)
	unsetEnvForTest(t, "YGGDRASIL_ENV")
	setTestLegacyWorkflowCredential(t, workflowAuthLegacyToken)
	t.Setenv("BROKER_URL", "amqp://unit-test")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	spec := `{"steps":[{"id":"observe","use":{"kind":"integration","instance_ref":{"namespace":"dakasa","name":"example"},"operation":"observe_state"}}]}`
	// One lookup authorizes the dispatch, one prepares the persisted run.
	expectWorkflowAuthorizationManifest(mock, "workflow", "deploy", spec)
	expectWorkflowAuthorizationManifest(mock, "workflow", "deploy", spec)
	mock.ExpectExec(`INSERT INTO public\.workflow_runs`).
		WithArgs(sqlmock.AnyArg(), "dakasa", "deploy", nil, sqlmock.AnyArg(), legacyBridgeStampArg{}).
		WillReturnResult(sqlmock.NewResult(0, 1))

	originalLauncher := launchAsyncWorkflowRun
	launched := 0
	launchAsyncWorkflowRun = func(string, func()) { launched++ }
	t.Cleanup(func() { launchAsyncWorkflowRun = originalLauncher })

	core, logs := observer.New(zapcore.InfoLevel)
	capture := &legacyBridgeAuditCapture{}
	server := &Server{db: db, rabbitmq: &amqp.Connection{}, logger: zap.New(core), legacyBridgeAuditSink: capture.add}
	before := metrics.WorkflowRunLegacyBridgeRequestsSnapshot()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs?async=true", strings.NewReader(
		`{"workflow":{"namespace":"dakasa","name":"deploy"},"metadata":{"`+repository.WorkflowRunCreatorLegacyBridgeMetadataKey+`":"spoofed"}}`))
	req.Header.Set("Authorization", "Bearer "+workflowAuthLegacyToken)
	req.Header.Set("User-Agent", "dakasa-adr-0286-legacy-probe")
	req.RemoteAddr = "203.0.113.7:4242"
	recorder := httptest.NewRecorder()
	server.handleWorkflowRun(recorder, req)
	if recorder.Code != http.StatusAccepted || launched != 1 {
		t.Fatalf("legacy async dispatch: status=%d launched=%d body=%s", recorder.Code, launched, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the run was not stamped as a legacy bridge run: %v", err)
	}

	// A dispatch refused before its body is read (broker-degraded) is still
	// a legacy use.
	unsetEnvForTest(t, "BROKER_URL")
	degraded := httptest.NewRequest(http.MethodPost, "/api/v1/workflow-runs", strings.NewReader(`{}`))
	degraded.Header.Set("X-Yggdrasil-Workflow-Token", workflowAuthLegacyToken)
	recorder = httptest.NewRecorder()
	server.handleWorkflowRun(recorder, degraded)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("degraded legacy dispatch: status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	after := metrics.WorkflowRunLegacyBridgeRequestsSnapshot()
	if got := after[metrics.WorkflowRunLegacyBridgeRouteDispatch] - before[metrics.WorkflowRunLegacyBridgeRouteDispatch]; got != 2 {
		t.Fatalf("dispatch counter delta=%d, want 2", got)
	}
	if got := after[metrics.WorkflowRunLegacyBridgeRoutePoll] - before[metrics.WorkflowRunLegacyBridgeRoutePoll]; got != 0 {
		t.Fatalf("poll counter delta=%d, want 0", got)
	}

	accepted := logs.FilterMessage(legacyBridgeAcceptedLine).All()
	if len(accepted) != 2 || accepted[0].Level != zapcore.WarnLevel {
		t.Fatalf("accepted log lines=%v", accepted)
	}
	first := accepted[0].ContextMap()
	if first["route"] != "dispatch" || first["workflow"] != "dakasa/deploy" || first["user_agent"] != "dakasa-adr-0286-legacy-probe" ||
		first["remote_ip"] != "203.0.113.7:4242" || first["subject"] != "service:"+legacyWorkflowRunSubjectID {
		t.Fatalf("log fields=%v", first)
	}

	rows := capture.snapshot()
	if len(rows) != 2 {
		t.Fatalf("audit rows=%d, want 2: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.Actor != "service:"+legacyWorkflowRunSubjectID || row.Action != "workflow_run.legacy_bridge" || row.ResourceKind != "workflow" ||
		row.ResourceID != "dakasa/deploy" || row.Outcome != "accepted" {
		t.Fatalf("audit row=%+v", row)
	}
	if row.Metadata["route"] != "dispatch" || row.Metadata["user_agent"] != "dakasa-adr-0286-legacy-probe" || row.Metadata["remote_ip"] != "203.0.113.7:4242" {
		t.Fatalf("audit metadata=%v", row.Metadata)
	}
	if rows[1].ResourceID != "" || rows[1].Metadata["route"] != "dispatch" {
		t.Fatalf("degraded audit row=%+v", rows[1])
	}
	for _, entry := range logs.All() {
		rendered := entry.Message + fmt.Sprint(entry.ContextMap())
		if strings.Contains(rendered, workflowAuthLegacyToken) || strings.Contains(rendered, testTokenSHA256(workflowAuthLegacyToken)) {
			t.Fatalf("a log line carries the legacy credential: %s", rendered)
		}
	}

	// The stamp is server-authored: a client value is always dropped, and
	// only a dispatch the bridge authenticated carries it.
	request := model.RunWorkflowRequest{Metadata: map[string]any{
		repository.WorkflowRunCreatorLegacyBridgeMetadataKey: "true",
		"source": "kept",
	}}
	for _, actor := range []workflowRunActor{
		{MachinePrincipalID: workflowAuthPrincipalID, Subject: model.RBACSubject{Type: "service", ID: workflowAuthPrincipalID}},
		{CollaboratorID: uuid.NewString()},
		{},
	} {
		bound, _ := bindWorkflowRunMachineActor(request, actor)
		if _, stamped := bound.Metadata[repository.WorkflowRunCreatorLegacyBridgeMetadataKey]; stamped || bound.Metadata["source"] != "kept" {
			t.Fatalf("actor %+v: metadata=%v", actor, bound.Metadata)
		}
	}
	legacyBound, _ := bindWorkflowRunMachineActor(model.RunWorkflowRequest{}, workflowRunActor{Subject: legacyWorkflowRunSubject(), LegacyMigration: true})
	if legacyBound.Metadata[repository.WorkflowRunCreatorLegacyBridgeMetadataKey] != "true" {
		t.Fatalf("legacy metadata=%v", legacyBound.Metadata)
	}
	if request.Metadata[repository.WorkflowRunCreatorLegacyBridgeMetadataKey] != "true" {
		t.Fatal("binding mutated the caller metadata in place")
	}
}

func TestLegacyPollAuditIsDedupedPerRun(t *testing.T) {
	clearWorkflowRunAuthEnv(t)
	unsetEnvForTest(t, "YGGDRASIL_ENV")
	setTestLegacyWorkflowCredential(t, workflowAuthLegacyToken)

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	runA, runB := uuid.New(), uuid.New()
	for _, runID := range []uuid.UUID{runA, runA, runB} {
		mock.ExpectQuery(`FROM public\.workflow_runs`).WithArgs(runID).WillReturnRows(emptyWorkflowRunRows())
	}

	core, logs := observer.New(zapcore.InfoLevel)
	capture := &legacyBridgeAuditCapture{}
	server := &Server{db: db, logger: zap.New(core), legacyBridgeAuditSink: capture.add}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/workflow-runs/{run_id}", server.handleWorkflowRunGet)
	before := metrics.WorkflowRunLegacyBridgeRequestsSnapshot()

	poll := func(runID string, want int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/workflow-runs/"+runID, nil)
		req.Header.Set("Authorization", "Bearer "+workflowAuthLegacyToken)
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, req)
		if recorder.Code != want {
			t.Fatalf("poll %s: status=%d body=%s, want %d", runID, recorder.Code, recorder.Body.String(), want)
		}
	}
	poll(runA.String(), http.StatusNotFound)
	poll(runA.String(), http.StatusNotFound)
	poll(runB.String(), http.StatusNotFound)
	poll("not-a-run-id", http.StatusBadRequest)
	poll("still-not-a-run-id", http.StatusBadRequest)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}

	after := metrics.WorkflowRunLegacyBridgeRequestsSnapshot()
	if got := after[metrics.WorkflowRunLegacyBridgeRoutePoll] - before[metrics.WorkflowRunLegacyBridgeRoutePoll]; got != 5 {
		t.Fatalf("poll counter delta=%d, want every poll counted (5)", got)
	}
	rows := capture.snapshot()
	var ids []string
	for _, row := range rows {
		if row.ResourceKind != "workflow_run" || row.Metadata["route"] != "poll" {
			t.Fatalf("poll audit row=%+v", row)
		}
		ids = append(ids, row.ResourceID)
	}
	if want := []string{runA.String(), runB.String(), ""}; fmt.Sprint(ids) != fmt.Sprint(want) {
		t.Fatalf("audited run ids=%v, want one row per run id %v", ids, want)
	}
	if got := logs.FilterMessage(legacyBridgeAcceptedLine).Len(); got != 3 {
		t.Fatalf("accepted log lines=%d, want one per run id (3)", got)
	}

	// The per-process set is bounded and cleared when full.
	var set legacyWorkflowBridgePollSet
	for index := 0; index < legacyWorkflowBridgePollDedupeLimit; index++ {
		if !set.firstSighting(strconv.Itoa(index)) {
			t.Fatalf("id %d was reported as seen", index)
		}
	}
	if set.firstSighting("0") {
		t.Fatal("a seen id was reported again before the set filled")
	}
	if !set.firstSighting("overflow") || len(set.seen) != 1 {
		t.Fatalf("the full set was not cleared: size=%d", len(set.seen))
	}
}

func TestLegacyBridgeAuditFailureIsCountedAndNeverRefusesTheRequest(t *testing.T) {
	clearWorkflowRunAuthEnv(t)
	unsetEnvForTest(t, "YGGDRASIL_ENV")
	setTestLegacyWorkflowCredential(t, workflowAuthLegacyToken)

	core, logs := observer.New(zapcore.InfoLevel)
	server := &Server{logger: zap.New(core), legacyBridgeAuditSink: func(model.AuditEvent) error {
		return errors.New("audit store unavailable")
	}}
	before := metrics.WorkflowRunLegacyBridgeAuditFailuresSnapshot()
	req := workflowDispatchRequest(workflowAuthLegacyToken)
	recorder := httptest.NewRecorder()
	server.handleWorkflowRun(recorder, req)
	// No broker: the request is served its normal 503, not refused by the
	// audit failure.
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s, want 503", recorder.Code, recorder.Body.String())
	}
	if got := metrics.WorkflowRunLegacyBridgeAuditFailuresSnapshot() - before; got != 1 {
		t.Fatalf("audit failure delta=%d, want 1", got)
	}
	if logs.FilterLevelExact(zapcore.ErrorLevel).Len() != 1 {
		t.Fatalf("the audit failure was not logged: %v", logs.All())
	}

	// A server with neither a database nor a sink cannot store the row
	// either, and still serves the request.
	bare := &Server{}
	recorder = httptest.NewRecorder()
	bare.handleWorkflowRun(recorder, workflowDispatchRequest(workflowAuthLegacyToken))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("bare server: status=%d, want 503", recorder.Code)
	}
	if got := metrics.WorkflowRunLegacyBridgeAuditFailuresSnapshot() - before; got != 2 {
		t.Fatalf("audit failure delta=%d, want 2", got)
	}
}

func TestBoundedAuditTextKeepsRuneBoundariesAndDropsControls(t *testing.T) {
	if got := boundedAuditText("  agent\r\nx\x00y  ", 128); got != "agentxy" {
		t.Fatalf("got %q", got)
	}
	long := strings.Repeat("é", 100) // 200 bytes
	got := boundedAuditText(long, 7)
	if got != strings.Repeat("é", 3) {
		t.Fatalf("got %q (%d bytes), want three whole runes", got, len(got))
	}
	if got := boundedAuditText(strings.Repeat("a", 300), legacyWorkflowBridgeAuditColumnMax); len(got) != legacyWorkflowBridgeAuditColumnMax {
		t.Fatalf("len=%d, want %d", len(got), legacyWorkflowBridgeAuditColumnMax)
	}
}

func TestWorkflowRunAuthBootSummaryCarriesNoDigest(t *testing.T) {
	clearMachineCredentialEnv(t)
	clearWorkflowRunAuthEnv(t)
	tokens := map[string]string{
		"cd-web-rollout-dispatcher": "summary-dispatcher-token",
		"earlier-dispatcher":        "summary-earlier-token",
		"revoked-dispatcher":        "summary-revoked-token",
	}
	configs := []workflowMachinePrincipalConfig{
		{PrincipalID: "cd-web-rollout-dispatcher", Status: "active", ExpiresAt: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), RotationID: "r1",
			TokenSHA256: testTokenSHA256(tokens["cd-web-rollout-dispatcher"]), AllowedWorkflows: []machineWorkflowRef{workflowAuthAllowedWorkflow}},
		{PrincipalID: "earlier-dispatcher", Status: "active", ExpiresAt: time.Date(2098, 6, 1, 0, 0, 0, 0, time.UTC), RotationID: "r1",
			TokenSHA256: testTokenSHA256(tokens["earlier-dispatcher"]), AllowedWorkflows: []machineWorkflowRef{workflowAuthAllowedWorkflow}},
		{PrincipalID: "revoked-dispatcher", Status: "revoked", ExpiresAt: time.Date(2097, 1, 1, 0, 0, 0, 0, time.UTC), RotationID: "r1",
			TokenSHA256: testTokenSHA256(tokens["revoked-dispatcher"]), AllowedWorkflows: []machineWorkflowRef{workflowAuthAllowedWorkflow}},
	}
	raw, err := json.Marshal(configs)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(workflowMachinePrincipalsEnv, string(raw))
	setTestLegacyWorkflowCredential(t, workflowAuthLegacyToken)

	core, logs := observer.New(zapcore.DebugLevel)
	newWorkflowAuthBootServer(t, zap.New(core))

	summaries := logs.FilterMessage(workflowAuthBootSummary).All()
	if len(summaries) != 1 || summaries[0].Level != zapcore.InfoLevel {
		t.Fatalf("boot summaries=%v", summaries)
	}
	fields := summaries[0].ContextMap()
	want := map[string]any{
		"principals":        int64(3),
		"usable":            int64(2),
		"earliest_expiry":   "2098-06-01T00:00:00Z",
		"workflow_refused":  false,
		"legacy_configured": true,
		"legacy_active":     true,
		"legacy_expires_at": "2099-01-01T00:00:00Z",
		"legacy_refused":    false,
		"anonymous_allowed": false,
		"directory_refused": false,
	}
	for key, value := range want {
		if fields[key] != value {
			t.Fatalf("summary[%s]=%#v, want %#v (summary=%v)", key, fields[key], value, fields)
		}
	}
	if fmt.Sprint(fields["principal_ids"]) != "[cd-web-rollout-dispatcher earlier-dispatcher revoked-dispatcher]" {
		t.Fatalf("principal_ids=%v", fields["principal_ids"])
	}
	for _, line := range []string{workflowAuthRefusedLine, workflowAuthLegacyLine, workflowAuthDirectoryLine} {
		if logs.FilterMessage(line).Len() != 0 {
			t.Fatalf("a healthy surface logged %q", line)
		}
	}
	for _, entry := range logs.All() {
		rendered := entry.Message + fmt.Sprint(entry.ContextMap())
		for _, token := range append([]string{workflowAuthLegacyToken}, tokens["cd-web-rollout-dispatcher"], tokens["earlier-dispatcher"], tokens["revoked-dispatcher"]) {
			if strings.Contains(rendered, token) || strings.Contains(rendered, testTokenSHA256(token)) {
				t.Fatalf("a boot line carries credential material: %s", rendered)
			}
		}
	}
}

func TestWorkflowRunAuthBootLogsRefusedBridgeSettings(t *testing.T) {
	clearMachineCredentialEnv(t)
	clearWorkflowRunAuthEnv(t)
	setWorkflowAuthPrincipal(t, workflowAuthPrincipalToken)
	// Partial retirement: ENABLED deleted, the token still present.
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_TOKEN", workflowAuthLegacyToken)
	t.Setenv("YGGDRASIL_WORKFLOW_RUN_LEGACY_EXPIRES_AT", "2099-01-01T00:00:00Z")

	core, logs := observer.New(zapcore.InfoLevel)
	newWorkflowAuthBootServer(t, zap.New(core))
	if logs.FilterMessage(workflowAuthLegacyLine).Len() != 1 {
		t.Fatalf("refused bridge settings were not logged: %v", logs.All())
	}
	fields := logs.FilterMessage(workflowAuthBootSummary).All()[0].ContextMap()
	if fields["legacy_refused"] != true || fields["legacy_configured"] != false || fields["legacy_active"] != false || fields["usable"] != int64(1) {
		t.Fatalf("summary=%v", fields)
	}
}

func stringPointer(value string) *string {
	return &value
}
