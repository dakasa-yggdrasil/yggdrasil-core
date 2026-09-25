package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// Logical event publisher grants (ADR-0021): a grant whose instance_id is
// "<namespace>/<name>" matches only after Core resolved the event's
// instance_id to that logical integration instance.

const (
	logicalTestToken     = "kubernetes-adapter-event-token"
	logicalTestEventType = "kubernetes.object.destroyed"
	logicalTestInstance  = "dakasa/kubernetes-dakasa-production"
)

var logicalTestActiveID = uuid.MustParse("6827a9a6-c7af-4d3d-a9fc-4fafe59e2a64")

func setLogicalEventPrincipal(t *testing.T, grants ...eventPublisherEventRef) {
	t.Helper()
	setEventPublishAuthEnvironment(t, "", "")
	t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, logicalTestToken, "integration-kubernetes-adapter", grants...))
}

func logicalGrant(instanceID string) eventPublisherEventRef {
	return eventPublisherEventRef{Provider: "kubernetes", InstanceID: instanceID, EventType: logicalTestEventType}
}

func activeKubernetesInstance() repository.IntegrationInstanceIdentity {
	return repository.IntegrationInstanceIdentity{
		Namespace:        "dakasa",
		Name:             "kubernetes-dakasa-production",
		ActiveManifestID: logicalTestActiveID,
		ActiveVersion:    51,
		TypeProvider:     "kubernetes",
	}
}

// logicalServer loads the event surface from the environment, the way New
// does, and replaces the manifests lookup with resolve. The returned counter
// counts lookups, so a test can prove no lookup happened.
func logicalServer(t *testing.T, resolve func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error)) (*Server, *int) {
	t.Helper()
	calls := 0
	server := eventPublishServerFromEnv(t)
	server.eventInstanceResolver = func(ctx context.Context, ref eventInstanceRef) (repository.IntegrationInstanceIdentity, error) {
		calls++
		if _, bounded := ctx.Deadline(); !bounded {
			t.Error("the instance lookup ran without a deadline")
		}
		return resolve(ref)
	}
	return server, &calls
}

func mutationBody(instanceID string, metadata map[string]any) string {
	body := map[string]any{
		"event_type":  logicalTestEventType,
		"provider":    "kubernetes",
		"resource":    "object",
		"verb":        "destroyed",
		"resource_id": "deployment/dakasa/web",
		"instance_id": instanceID,
		"idempotency": "destroy-web-1",
	}
	if metadata != nil {
		body["metadata"] = metadata
	}
	raw, _ := json.Marshal(body)
	return string(raw)
}

func publishWith(server *Server, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+logicalTestToken)
	recorder := httptest.NewRecorder()
	server.handleEventPublish(recorder, req)
	return recorder
}

func publishRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func authenticatedLogicalActor(t *testing.T, server *Server) eventPublishActor {
	t.Helper()
	actor, err := server.authenticateEventPublishRequest(publishRequest(logicalTestToken))
	if err != nil || actor.MachinePrincipal == nil {
		t.Fatalf("authenticate the logical test principal: actor=%+v err=%v", actor, err)
	}
	return actor
}

func TestEventPublisherConfigSeparatesExactAndLogicalGrants(t *testing.T) {
	setLogicalEventPrincipal(t,
		logicalGrant("6827a9a6-c7af-4d3d-a9fc-4fafe59e2a64"),
		logicalGrant("kubernetes-dakasa-validation"),
		logicalGrant(logicalTestInstance),
	)
	principals, err := eventPublisherPrincipalsFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	principal := &principals[0]
	if len(principal.AllowedEvents) != 2 || len(principal.LogicalEvents) != 1 {
		t.Fatalf("exact=%d logical=%d, want 2 and 1", len(principal.AllowedEvents), len(principal.LogicalEvents))
	}
	if eventPublisherPrincipalAllows(principal, "kubernetes", logicalTestInstance, logicalTestEventType) {
		t.Fatal("a slash-form grant matched a wire value without resolution")
	}
	if !eventPublisherPrincipalHasLogicalGrant(principal, "kubernetes", logicalTestEventType) {
		t.Fatal("logical grant not indexed by provider and event type")
	}
	for _, declared := range []string{logicalTestInstance, "kubernetes-dakasa-validation", "6827a9a6-c7af-4d3d-a9fc-4fafe59e2a64"} {
		if !eventPublisherPrincipalDeclares(principal, "kubernetes", declared, logicalTestEventType) {
			t.Fatalf("inventory check does not see the declared grant %q", declared)
		}
	}
	for _, undeclared := range []string{"dakasa/kubernetes-dakasa-validation", "Dakasa/kubernetes-dakasa-production", "kubernetes-dakasa-production"} {
		if eventPublisherPrincipalDeclares(principal, "kubernetes", undeclared, logicalTestEventType) {
			t.Fatalf("inventory check reports an undeclared grant %q", undeclared)
		}
	}
	if eventPublisherPrincipalDeclares(principal, "kubernetes", logicalTestInstance, "kubernetes.object.ensured") {
		t.Fatal("inventory check ignored the event type")
	}
}

func TestEventPublisherConfigRejectsMalformedLogicalGrants(t *testing.T) {
	for _, instanceID := range []string{
		"dakasa/kubernetes/extra",
		"/kubernetes-dakasa-production",
		"dakasa/",
		"Dakasa/kubernetes-dakasa-production",
		"dakasa/ kubernetes-dakasa-production",
		"dakasa /kubernetes-dakasa-production",
		"dakasa/kubernetes-*",
		"dakasa/kubernetes-dakasa-production\x00",
		"dakasa/kube\x07rnetes",
	} {
		t.Run(instanceID, func(t *testing.T) {
			// One malformed grant refuses the whole inventory, next to a
			// valid exact grant.
			setLogicalEventPrincipal(t, logicalGrant("kubernetes-dakasa-validation"), logicalGrant(instanceID))
			if _, err := eventPublisherPrincipalsFromEnv(); err == nil {
				t.Fatalf("malformed logical grant %q was accepted", instanceID)
			}
		})
	}
}

func TestEventPublisherConfigRejectsDuplicateLogicalGrantsAfterTrimming(t *testing.T) {
	setLogicalEventPrincipal(t,
		logicalGrant(logicalTestInstance),
		logicalGrant("  "+logicalTestInstance+"  "),
	)
	if _, err := eventPublisherPrincipalsFromEnv(); err == nil {
		t.Fatal("duplicate logical grant was accepted")
	}
}

func TestEventPublisherConfigAllowsExactAndLogicalGrantForTheSameInstance(t *testing.T) {
	// The transition keeps a bare-name or UUID grant next to its logical twin.
	setLogicalEventPrincipal(t,
		logicalGrant("kubernetes-dakasa-production"),
		logicalGrant(logicalTestActiveID.String()),
		logicalGrant(logicalTestInstance),
	)
	if _, err := eventPublisherPrincipalsFromEnv(); err != nil {
		t.Fatalf("exact and logical grant for one instance rejected: %v", err)
	}
}

func TestExactEventGrantNeverTouchesTheDatabase(t *testing.T) {
	uuidGrant := "902b0a7a-b2f2-4b4f-9f4a-00b899c6b655"
	setLogicalEventPrincipal(t, logicalGrant(uuidGrant), logicalGrant("kubernetes-dakasa-validation"), logicalGrant(logicalTestInstance))
	server, calls := logicalServer(t, func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) {
		t.Error("an exact grant consulted the instance lookup")
		return repository.IntegrationInstanceIdentity{}, nil
	})
	actor := authenticatedLogicalActor(t, server)
	for _, wire := range []string{uuidGrant, "kubernetes-dakasa-validation"} {
		decided, err := server.authorizeEventPublishPayload(context.Background(), eventPublishRequest{
			EventType: logicalTestEventType, Provider: "kubernetes", InstanceID: wire,
		}, actor)
		if err != nil || decided.GrantForm != eventGrantFormExact || decided.Instance != nil {
			t.Fatalf("%s: decision=%+v err=%v", wire, decided, err)
		}
	}
	if *calls != 0 {
		t.Fatalf("instance lookups=%d, want 0", *calls)
	}
}

func TestLogicalGrantAcceptsAnyVersionUUIDAndLiteralName(t *testing.T) {
	setLogicalEventPrincipal(t, logicalGrant(logicalTestInstance))
	oldVersion := uuid.MustParse("0b6c2f36-2f1b-4f44-9d7e-7c1e3a7d5a10")
	for _, test := range []struct {
		wire string
		want eventInstanceRef
	}{
		{wire: oldVersion.String(), want: eventInstanceRef{ManifestID: oldVersion}},
		{wire: logicalTestActiveID.String(), want: eventInstanceRef{ManifestID: logicalTestActiveID}},
		{wire: logicalTestInstance, want: eventInstanceRef{Namespace: "dakasa", Name: "kubernetes-dakasa-production"}},
	} {
		t.Run(test.wire, func(t *testing.T) {
			server, calls := logicalServer(t, func(got eventInstanceRef) (repository.IntegrationInstanceIdentity, error) {
				if got != test.want {
					t.Errorf("lookup got %+v, want %+v", got, test.want)
				}
				return activeKubernetesInstance(), nil
			})
			decided, err := server.authorizeEventPublishPayload(context.Background(), eventPublishRequest{
				EventType: logicalTestEventType, Provider: "kubernetes", InstanceID: test.wire,
			}, authenticatedLogicalActor(t, server))
			if err != nil || decided.GrantForm != eventGrantFormLogical || decided.Instance == nil || *calls != 1 {
				t.Fatalf("decision=%+v err=%v calls=%d", decided, err, *calls)
			}
			if *decided.Instance != activeKubernetesInstance() {
				t.Fatalf("stamped identity=%+v, want the active version", *decided.Instance)
			}
		})
	}
}

func TestLogicalGrantAdmitsTheEventToPersistence(t *testing.T) {
	setLogicalEventPrincipal(t, logicalGrant(logicalTestInstance))
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server, calls := logicalServer(t, func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) {
		return activeKubernetesInstance(), nil
	})
	server.db = db
	// Stop at the transaction: reaching it proves the handler authorized the
	// event, and persistence itself is not what this test pins.
	mock.ExpectBegin().WillReturnError(errors.New("stop after authorization"))

	recorder := publishWith(server, mutationBody(logicalTestActiveID.String(), nil))
	switch recorder.Code {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable:
		t.Fatalf("status=%d, the logical grant did not admit the event; body=%s", recorder.Code, recorder.Body.String())
	}
	if *calls != 1 {
		t.Fatalf("instance lookups=%d, want 1", *calls)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the handler never reached persistence: %v", err)
	}
}

func TestLogicalGrantIsNotConsultedForOtherProviderOrEventType(t *testing.T) {
	setLogicalEventPrincipal(t,
		logicalGrant(logicalTestInstance),
		eventPublisherEventRef{Provider: "helm", InstanceID: "helm-dakasa-production", EventType: "helm.release.destroyed"},
	)
	server, calls := logicalServer(t, func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) {
		return activeKubernetesInstance(), nil
	})
	actor := authenticatedLogicalActor(t, server)
	for _, req := range []eventPublishRequest{
		// Same provider, event type without a logical grant.
		{EventType: "kubernetes.object.ensured", Provider: "kubernetes", InstanceID: logicalTestActiveID.String()},
		// Another provider, for which the principal holds only an exact grant.
		{EventType: "helm.release.destroyed", Provider: "helm", InstanceID: logicalTestActiveID.String()},
		{EventType: "helm.release.destroyed", Provider: "helm", InstanceID: logicalTestInstance},
	} {
		if _, err := server.authorizeEventPublishPayload(context.Background(), req, actor); !errors.Is(err, errEventPublishAuthorizationDenied) {
			t.Fatalf("%+v: err=%v, want denied", req, err)
		}
	}
	if *calls != 0 {
		t.Fatalf("instance lookups=%d, want 0", *calls)
	}
}

func TestLogicalNotFoundNotGrantedAndWrongProviderAnswerTheSame403(t *testing.T) {
	setLogicalEventPrincipal(t, logicalGrant(logicalTestInstance))
	otherInstance := activeKubernetesInstance()
	otherInstance.Name = "kubernetes-dakasa-validation"
	otherNamespace := activeKubernetesInstance()
	otherNamespace.Namespace = "global"
	wrongProvider := activeKubernetesInstance()
	wrongProvider.TypeProvider = "helm"

	cases := []struct {
		name    string
		resolve func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error)
	}{
		{name: "not found", resolve: func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) {
			return repository.IntegrationInstanceIdentity{}, repository.ErrIntegrationInstanceNotResolvable
		}},
		{name: "not granted", resolve: func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) { return otherInstance, nil }},
		{name: "same name in another namespace", resolve: func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) { return otherNamespace, nil }},
		{name: "wrong provider", resolve: func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) { return wrongProvider, nil }},
	}
	var first string
	for _, test := range cases {
		server, calls := logicalServer(t, test.resolve)
		recorder := publishWith(server, mutationBody(logicalTestActiveID.String(), nil))
		if recorder.Code != http.StatusForbidden || *calls != 1 {
			t.Fatalf("%s: status=%d calls=%d body=%s", test.name, recorder.Code, *calls, recorder.Body.String())
		}
		var problem map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil || problem["code"] != "event.authorization_denied" {
			t.Fatalf("%s: body=%s", test.name, recorder.Body.String())
		}
		if first == "" {
			first = recorder.Body.String()
		} else if recorder.Body.String() != first {
			t.Fatalf("%s answers %q, not %q: a caller could tell the cases apart", test.name, recorder.Body.String(), first)
		}
	}
}

func TestLogicalResolutionFailureAnswers503WithoutDetail(t *testing.T) {
	setLogicalEventPrincipal(t, logicalGrant(logicalTestInstance))
	server, _ := logicalServer(t, func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) {
		return repository.IntegrationInstanceIdentity{}, errors.New("pq: connection refused to 10.0.0.5")
	})
	core, logs := observer.New(zapcore.DebugLevel)
	server.logger = zap.New(core)
	recorder := publishWith(server, mutationBody(logicalTestActiveID.String(), nil))
	if logs.FilterLevelExact(zapcore.ErrorLevel).Len() != 1 {
		t.Fatalf("a database failure must be logged once at error level, got %v", logs.All())
	}
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var problem map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if problem["code"] != "event.authorization_unavailable" || problem["detail"] != eventPublishUnavailableDetail {
		t.Fatalf("body=%s", recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "10.0.0.5") || strings.Contains(recorder.Body.String(), "pq:") {
		t.Fatalf("the 503 echoes the database error: %s", recorder.Body.String())
	}
}

// unresolvableWireValues are instance_id values the logical path must never
// look up: a bare name only ever matches an exact grant, and a UUID is
// accepted only in the canonical lowercase hyphenated form.
func unresolvableWireValues() []string {
	return []string{
		"kubernetes-dakasa-production",
		"",
		strings.ToUpper(logicalTestActiveID.String()),
		"urn:uuid:" + logicalTestActiveID.String(),
		"{" + logicalTestActiveID.String() + "}",
		strings.ReplaceAll(logicalTestActiveID.String(), "-", ""),
		"Dakasa/kubernetes-dakasa-production",
		"dakasa/a/b",
		"dakasa/",
		"dakasa/kubernetes-dakasa-production\x00",
		"dakasa/kubernetes\x1b-dakasa-production",
		"\x00dakasa/kubernetes-dakasa-production",
	}
}

func TestUnresolvableWireValuesNeverReachTheInstanceLookup(t *testing.T) {
	setLogicalEventPrincipal(t, logicalGrant(logicalTestInstance))
	server, calls := logicalServer(t, func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) {
		return activeKubernetesInstance(), nil
	})
	actor := authenticatedLogicalActor(t, server)
	for _, wire := range unresolvableWireValues() {
		_, err := server.authorizeEventPublishPayload(context.Background(), eventPublishRequest{
			EventType: logicalTestEventType, Provider: "kubernetes", InstanceID: wire,
		}, actor)
		if !errors.Is(err, errEventPublishAuthorizationDenied) {
			t.Fatalf("%q: err=%v, want denied", wire, err)
		}
	}
	if *calls != 0 {
		t.Fatalf("instance lookups=%d, want 0", *calls)
	}
}

func TestProductionResolverRefusesUnresolvableWireValuesWithoutQuerying(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := &Server{db: db, logger: zap.NewNop()}
	for _, wire := range unresolvableWireValues() {
		if _, err := server.resolveEventInstance(context.Background(), wire); !errors.Is(err, repository.ErrIntegrationInstanceNotResolvable) {
			t.Fatalf("%q: err=%v", wire, err)
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestBindEventPublishActorStampsTheVerifiedInstanceAndDropsClientValues(t *testing.T) {
	identity := activeKubernetesInstance()
	actor := eventPublishActor{
		MachinePrincipal: &eventPublisherPrincipal{PrincipalID: "integration-kubernetes-adapter"},
		GrantForm:        eventGrantFormLogical,
		Instance:         &identity,
	}
	bound := bindEventPublishActor(eventPublishRequest{InstanceID: logicalTestActiveID.String(), Metadata: map[string]any{
		eventPublisherInstanceNameMetadataKey:       "spoofed",
		eventPublisherInstanceManifestIDMetadataKey: "spoofed",
		"yggdrasil.io/publisher_future_key":         "spoofed",
		"trace":                                     "kept",
	}}, actor)
	want := map[string]any{
		eventPublisherMachinePrincipalMetadataKey:   "integration-kubernetes-adapter",
		eventPublisherGrantFormMetadataKey:          eventGrantFormLogical,
		eventPublisherInstanceNamespaceMetadataKey:  "dakasa",
		eventPublisherInstanceNameMetadataKey:       "kubernetes-dakasa-production",
		eventPublisherInstanceManifestIDMetadataKey: logicalTestActiveID.String(),
		eventPublisherInstanceVersionMetadataKey:    51,
		"trace":                                     "kept",
	}
	if len(bound.Metadata) != len(want) {
		t.Fatalf("metadata=%v", bound.Metadata)
	}
	for key, value := range want {
		if bound.Metadata[key] != value {
			t.Fatalf("metadata[%s]=%v, want %v", key, bound.Metadata[key], value)
		}
	}
	if bound.InstanceID != logicalTestActiveID.String() {
		t.Fatalf("the wire instance_id changed to %q; payload.instance_id must stay what the adapter sent", bound.InstanceID)
	}
}

func TestBindEventPublishActorExactAndLegacyCarryNoInstanceKeys(t *testing.T) {
	spoofed := map[string]any{eventPublisherInstanceNameMetadataKey: "spoofed", eventPublisherGrantFormMetadataKey: "logical"}
	exact := bindEventPublishActor(eventPublishRequest{Metadata: spoofed}, eventPublishActor{
		MachinePrincipal: &eventPublisherPrincipal{PrincipalID: "integration-aws"}, GrantForm: eventGrantFormExact,
	})
	if exact.Metadata[eventPublisherGrantFormMetadataKey] != eventGrantFormExact || exact.Metadata[eventPublisherInstanceNameMetadataKey] != nil {
		t.Fatalf("exact metadata=%v", exact.Metadata)
	}
	for _, actor := range []eventPublishActor{{LegacyMigration: true}, {}} {
		bound := bindEventPublishActor(eventPublishRequest{Metadata: spoofed}, actor)
		for key := range bound.Metadata {
			if strings.HasPrefix(key, eventPublisherReservedMetadataPrefix) && key != eventPublisherMachinePrincipalMetadataKey {
				t.Fatalf("actor %+v kept reserved key %s", actor, key)
			}
		}
	}
}

func TestEventPublisherSurfaceIsLoadedOnceByNew(t *testing.T) {
	clearMachineCredentialEnv(t)
	setLogicalEventPrincipal(t, logicalGrant(logicalTestInstance))
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler, err := New("yggdrasil-core-test", db, nil, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	// Removing the inventory after start must change nothing until a restart.
	unsetEnvForTest(t, eventPublisherPrincipalsEnv)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(
		`{"type":"deployment.completed","aggregate_type":"deployment","aggregate_id":"one","payload":{}}`))
	req.Header.Set("Authorization", "Bearer "+logicalTestToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	// Authenticated by the loaded copy, then refused as a generic event: 403,
	// not the 401 of an unknown bearer and not the anonymous dev posture.
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRefusedEventInventoryBootsAndFailsEveryPublishClosed(t *testing.T) {
	clearMachineCredentialEnv(t)
	refused := `[{"principal_id":"x","status":"active","expires_at":"2099-01-01T00:00:00Z","rotation_id":"r","token_sha256":"` +
		testTokenSHA256("x") + `","allowed_events":[{"provider":"kubernetes","instance_id":"Dakasa/x","event_type":"` + logicalTestEventType + `"}]}]`
	t.Setenv(eventPublisherPrincipalsEnv, refused)
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler, err := New("yggdrasil-core-test", db, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("a refused event inventory must not stop boot when YGGDRASIL_ENV is unset: %v", err)
	}
	for _, bearer := range []string{"", "x"} {
		if bearer != "" {
			// The bearer is no event credential, so the gate hands it to the
			// human session path, which does not know it either.
			mock.ExpectQuery(`FROM public\.auth_sessions`).WillReturnError(sql.ErrNoRows)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(mutationBody("dakasa/x", nil)))
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("bearer %q: status=%d, want 401 (no anonymous fallback); body=%s", bearer, recorder.Code, recorder.Body.String())
		}
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}

	// The handler itself answers the same 401 and never echoes the parser
	// diagnostics of the refused inventory.
	server := eventPublishServerFromEnv(t)
	if server.eventPublishAuth.err == nil {
		t.Fatal("the test inventory was expected to be refused")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(mutationBody("dakasa/x", nil)))
	req.Header.Set("Authorization", "Bearer x")
	recorder := httptest.NewRecorder()
	server.handleEventPublish(recorder, req)
	if recorder.Code != http.StatusUnauthorized || strings.Contains(recorder.Body.String(), eventPublisherPrincipalsEnv) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestServerNotBuiltByNewAuthenticatesNoEventPublisher(t *testing.T) {
	setEventPublishAuthEnvironment(t, "", "")
	t.Setenv("YGGDRASIL_ENV", "")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)
	if err := (&Server{}).authorizeEventPublishRequest(req); err == nil {
		t.Fatal("a Server without a loaded event surface fell into the anonymous posture")
	}
}

func TestControlCharactersInALogicalWireValueAnswer403WithoutALookup(t *testing.T) {
	setLogicalEventPrincipal(t, logicalGrant(logicalTestInstance))
	server, calls := logicalServer(t, func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) {
		return activeKubernetesInstance(), nil
	})
	for _, wire := range []string{logicalTestInstance + "\x00", "dakasa/kubernetes\x00-dakasa-production"} {
		recorder := publishWith(server, mutationBody(wire, nil))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("%q: status=%d, want 403; body=%s", wire, recorder.Code, recorder.Body.String())
		}
	}
	if *calls != 0 {
		t.Fatalf("instance lookups=%d, want 0: a control character reached the lookup", *calls)
	}
}

func TestCancelledRequestDuringTheLookupIsNotLoggedAsAnOutage(t *testing.T) {
	setLogicalEventPrincipal(t, logicalGrant(logicalTestInstance))
	server, calls := logicalServer(t, func(eventInstanceRef) (repository.IntegrationInstanceIdentity, error) {
		return repository.IntegrationInstanceIdentity{}, context.Canceled
	})
	core, logs := observer.New(zapcore.DebugLevel)
	server.logger = zap.New(core)
	actor := authenticatedLogicalActor(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := server.authorizeEventPublishPayload(ctx, eventPublishRequest{
		EventType: logicalTestEventType, Provider: "kubernetes", InstanceID: logicalTestActiveID.String(),
	}, actor)
	if !errors.Is(err, errEventPublishAuthorizationUnavailable) || *calls != 1 {
		t.Fatalf("err=%v calls=%d", err, *calls)
	}
	if logs.FilterLevelExact(zapcore.ErrorLevel).Len() != 0 {
		t.Fatalf("a cancelled request was logged as an outage: %v", logs.All())
	}
	if logs.FilterLevelExact(zapcore.DebugLevel).Len() != 1 {
		t.Fatalf("a cancelled request must leave one debug line, got %v", logs.All())
	}
}

func TestReservedPublisherMetadataIgnoresCaseAndWhitespace(t *testing.T) {
	for _, key := range []string{
		"yggdrasil.io/publisher_instance_name",
		"Yggdrasil.IO/Publisher_Instance_Name",
		" yggdrasil.io/publisher_grant_form",
		"YGGDRASIL.IO/PUBLISHER_MACHINE_PRINCIPAL_ID\t",
		"yggdrasil.io/publisher_future_key",
	} {
		if !isReservedPublisherMetadataKey(key) {
			t.Fatalf("%q was not treated as reserved", key)
		}
	}
	for _, key := range []string{"trace", "yggdrasil.io/publisher", "yggdrasil.io/other_key", "x-yggdrasil.io/publisher_grant_form"} {
		if isReservedPublisherMetadataKey(key) {
			t.Fatalf("%q was treated as reserved", key)
		}
	}

	identity := activeKubernetesInstance()
	bound := bindEventPublishActor(eventPublishRequest{Metadata: map[string]any{
		"Yggdrasil.IO/Publisher_Instance_Name":         "spoofed",
		" yggdrasil.io/publisher_grant_form":           "exact",
		"YGGDRASIL.IO/PUBLISHER_MACHINE_PRINCIPAL_ID ": "spoofed",
		"trace": "kept",
	}}, eventPublishActor{
		MachinePrincipal: &eventPublisherPrincipal{PrincipalID: "integration-kubernetes-adapter"},
		GrantForm:        eventGrantFormLogical,
		Instance:         &identity,
	})
	for key, value := range bound.Metadata {
		if key == "trace" {
			continue
		}
		if key != strings.ToLower(strings.TrimSpace(key)) {
			t.Fatalf("a look-alike client key survived next to the stamped ones: %q=%v", key, value)
		}
	}
	if bound.Metadata[eventPublisherGrantFormMetadataKey] != eventGrantFormLogical || len(bound.Metadata) != 7 {
		t.Fatalf("metadata=%v", bound.Metadata)
	}
}

func TestBlankEventInventoryIsRefusedWhileAnUnsetOneKeepsTheDevPosture(t *testing.T) {
	for _, blank := range []string{"", " ", "\n\t "} {
		t.Run("blank "+strconv.Quote(blank), func(t *testing.T) {
			setEventPublishAuthEnvironment(t, "", "")
			t.Setenv("YGGDRASIL_ENV", "")
			t.Setenv(eventPublisherPrincipalsEnv, blank)
			if _, err := eventPublisherPrincipalsFromEnv(); err == nil || !strings.Contains(err.Error(), eventPublisherPrincipalsEnv) {
				t.Fatalf("a set but blank inventory was not refused: %v", err)
			}
			server := eventPublishServerFromEnv(t)
			if server.eventPublishAuth.err == nil {
				t.Fatal("the loaded surface kept a blank inventory")
			}
			if err := server.authorizeEventPublishRequest(httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)); err == nil {
				t.Fatal("a blank inventory opened the anonymous posture")
			}
		})
	}

	t.Run("unset", func(t *testing.T) {
		setEventPublishAuthEnvironment(t, "", "")
		// ADR-0022: the development posture also needs YGGDRASIL_ENV to name
		// a development environment explicitly.
		t.Setenv("YGGDRASIL_ENV", "dev")
		if _, present := os.LookupEnv(eventPublisherPrincipalsEnv); present {
			t.Fatal("the helper did not unset the inventory")
		}
		if err := eventPublishServerFromEnv(t).authorizeEventPublishRequest(httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)); err != nil {
			t.Fatalf("an unset inventory lost the development posture: %v", err)
		}
	})
}

func TestBlankEventInventoryFailsEveryPublishThroughTheGate(t *testing.T) {
	clearMachineCredentialEnv(t)
	t.Setenv(eventPublisherPrincipalsEnv, "  ")
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler, err := New("yggdrasil-core-test", db, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("a blank event inventory must not stop boot when YGGDRASIL_ENV is unset: %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(
		`{"type":"deployment.completed","aggregate_type":"deployment","aggregate_id":"one","payload":{}}`)))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous publish with a blank inventory: status=%d, want 401; body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRefusedLegacyBridgeSettingsKeepEventPrincipalsWorking(t *testing.T) {
	clearMachineCredentialEnv(t)
	t.Setenv(eventPublisherPrincipalsEnv, testEventPublisherPrincipalsJSON(t, "adapter-event-token", "adapter-aws"))
	t.Setenv(legacyEventPublishTokenEnv, "legacy-event-token")
	t.Setenv(legacyEventPublishEnabledEnv, "true")
	t.Setenv(legacyEventPublishExpiryEnv, "next tuesday")

	server := eventPublishServerFromEnv(t)
	if server.eventPublishAuth.err != nil || server.eventPublishAuth.legacyErr == nil {
		t.Fatalf("err=%v legacyErr=%v, want only the bridge refused", server.eventPublishAuth.err, server.eventPublishAuth.legacyErr)
	}
	if err := server.authorizeEventPublishRequest(publishRequest("adapter-event-token")); err != nil {
		t.Fatalf("a refused bridge setting locked out the hashed principal: %v", err)
	}
	if err := server.authorizeEventPublishRequest(publishRequest("legacy-event-token")); err == nil {
		t.Fatal("the bridge with refused settings still authenticated")
	}

	// Through New and the full middleware chain: the principal still
	// authenticates (then its generic event is refused with 403), and the
	// bridge bearer falls through to the session path, which refuses it.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler, err := New("yggdrasil-core-test", db, nil, zap.NewNop())
	if err != nil {
		t.Fatalf("refused bridge settings must not stop boot when YGGDRASIL_ENV is unset: %v", err)
	}
	generic := `{"type":"deployment.completed","aggregate_type":"deployment","aggregate_id":"one","payload":{}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(generic))
	req.Header.Set("Authorization", "Bearer adapter-event-token")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("principal: status=%d, want 403 (authenticated, generic refused); body=%s", recorder.Code, recorder.Body.String())
	}
	mock.ExpectQuery(`FROM public\.auth_sessions`).WillReturnError(sql.ErrNoRows)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/events", strings.NewReader(mutationBody("aws-primary", nil)))
	req.Header.Set("Authorization", "Bearer legacy-event-token")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("bridge: status=%d, want 401; body=%s", recorder.Code, recorder.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestRefusedLegacyBridgeSettingsRefuseTheAnonymousPosture(t *testing.T) {
	setEventPublishAuthEnvironment(t, "", "")
	t.Setenv("YGGDRASIL_ENV", "")
	// A token without the explicit opt-in is refused bridge settings.
	t.Setenv(legacyEventPublishTokenEnv, "legacy-event-token")
	server := eventPublishServerFromEnv(t)
	if server.eventPublishAuth.err != nil || server.eventPublishAuth.legacyErr == nil {
		t.Fatalf("err=%v legacyErr=%v", server.eventPublishAuth.err, server.eventPublishAuth.legacyErr)
	}
	if err := server.authorizeEventPublishRequest(httptest.NewRequest(http.MethodPost, "/api/v1/events", nil)); err == nil {
		t.Fatal("refused bridge settings opened the anonymous posture")
	}
}
