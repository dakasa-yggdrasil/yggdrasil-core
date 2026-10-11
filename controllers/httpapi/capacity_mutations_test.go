package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func capacityMutationTestPrincipal(t *testing.T, token, instance string) []capacityMutationPrincipal {
	t.Helper()
	config := []capacityMutationPrincipalConfig{{PrincipalID: "fixture-adapter", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "fixture-rotation", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), IntegrationInstanceID: instance, Capabilities: []string{"ensure_server", "destroy_server"}}}
	raw, _ := json.Marshal(config)
	t.Setenv(capacityMutationPrincipalsEnv, string(raw))
	principals, err := loadCapacityMutationPrincipals(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return principals
}

func TestCapacityMutationCredentialScope(t *testing.T) {
	token := "fixture-private-adapter-token"
	instance := uuid.NewString()
	server := &Server{capacityMutationPrincipals: capacityMutationTestPrincipal(t, token, instance)}
	var fallthroughCalls int
	handler := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fallthroughCalls++; w.WriteHeader(204) }))
	for _, test := range []struct {
		method, path, credential string
		status                   int
	}{
		{"POST", capacityMutationBasePath + "/redeem", "", 401},
		{"POST", capacityMutationBasePath + "/redeem", "human-session-token", 401},
		{"GET", "/healthz", token, 403},
		{"POST", "/api/v1/workflow-runs", token, 403},
		{"POST", "/api/v1/events", token, 403},
		{"POST", capacityMutationBasePath + "/redeem?url=https://caller.example", token, 403},
		{"GET", capacityMutationBasePath + "/../events", token, 403},
	} {
		request := httptest.NewRequest(test.method, test.path, strings.NewReader("{}"))
		if test.credential != "" {
			request.Header.Set("Authorization", "Bearer "+test.credential)
		}
		request.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "human-cookie"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || strings.Contains(response.Body.String(), token) {
			t.Fatalf("%s %s: %d %s", test.method, test.path, response.Code, response.Body.String())
		}
	}
	if fallthroughCalls != 0 {
		t.Fatal("adapter credential reached another credential surface")
	}
	server.capacityMutationPrincipals[0].base.status = "revoked"
	request := httptest.NewRequest("GET", "/healthz", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatal(response.Code)
	}
	server.capacityMutationPrincipals[0].base.status = "active"
	request = httptest.NewRequest("GET", "/healthz", nil)
	request.Header.Add("Authorization", "Bearer "+token)
	request.Header.Add("Authorization", "Bearer another")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatal("ambiguous credential fell through", response.Code)
	}
}

func TestCapacityMutationInventoryFailsClosed(t *testing.T) {
	token := "fixture-private-adapter-token"
	instance := uuid.NewString()
	capacityMutationTestPrincipal(t, token, instance)
	for _, raw := range []string{"", "null", "[]", "{}", `[{"principal_id":"unknown","unknown":true}]`} {
		t.Setenv(capacityMutationPrincipalsEnv, raw)
		if _, err := loadCapacityMutationPrincipals(nil, nil, nil); err == nil {
			t.Fatalf("invalid inventory accepted: %q", raw)
		}
	}
	p := capacityMutationTestPrincipal(t, token, instance)
	if _, err := loadCapacityMutationPrincipals([]workflowMachinePrincipal{{TokenSHA256: p[0].base.tokenSHA256}}, nil, nil); err == nil {
		t.Fatal("cross-scope credential collision")
	}
	if _, err := loadCapacityMutationPrincipals(nil, []eventPublisherPrincipal{{TokenSHA256: p[0].base.tokenSHA256}}, nil); err == nil {
		t.Fatal("event collision")
	}
	if _, err := loadCapacityMutationPrincipals(nil, nil, []directoryMachinePrincipal{{TokenSHA256: p[0].base.tokenSHA256}}); err == nil {
		t.Fatal("directory collision")
	}
	config := []capacityMutationPrincipalConfig{{PrincipalID: "fixture", Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "r", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), IntegrationInstanceID: instance, Capabilities: []string{"ensure_*"}}}
	raw, _ := json.Marshal(config)
	t.Setenv(capacityMutationPrincipalsEnv, string(raw))
	if _, err := loadCapacityMutationPrincipals(nil, nil, nil); err == nil {
		t.Fatal("wildcard capability")
	}
}

func TestCapacityMutationExactJSON(t *testing.T) {
	for _, body := range []string{`{"grant_id":"x","unexpected":true}`, `{} {}`, strings.Repeat(" ", 32769) + `{}`} {
		r := httptest.NewRequest("POST", capacityMutationBasePath+"/redeem", strings.NewReader(body))
		var value model.CapacityMutationRedeemRequest
		if err := decodeCapacityMutationJSON(httptest.NewRecorder(), r, &value); err == nil {
			t.Fatal("unbounded/ambiguous callback accepted")
		}
	}
}

func TestCapacityMutationHTTPPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("DB_URL required by capacity callback gate")
		}
		t.Skip("PostgreSQL callback protocol runs in CI")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	ns := "capacity-http-" + uuid.NewString()
	t.Cleanup(func() {
		for _, table := range []string{"capacity_mutation_grants", "capacity_resource_slots", "capacity_intent_events", "capacity_intents", "manifests"} {
			if _, err := db.ExecContext(ctx, `DELETE FROM public.`+table+` WHERE namespace=$1`, ns); err != nil {
				t.Error(err)
			}
		}
	})
	create := func(kind, name string, spec any) model.Manifest {
		raw, _ := json.Marshal(spec)
		m, err := repository.CreateManifestVersion(ctx, db, model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: raw}, fmt.Sprintf("%x", sha256.Sum256(raw)))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	wf := create("workflow", "scale", map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": ns, "name": "rbac"}}})
	typeSpec := model.IntegrationTypeManifestSpec{
		Provider:         "fixture",
		Adapter:          model.IntegrationAdapterSpec{Transport: "rabbitmq", Version: "0.1.0", TimeoutSeconds: 65, Queues: model.IntegrationAdapterQueue{Describe: "fixture.describe", Execute: "fixture.execute"}},
		Capabilities:     []string{"describe", "execute"},
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "none"},
		InstanceSchema:   model.IntegrationSchemaSpec{Mode: "none"},
		ResourceTypes:    []model.IntegrationResourceType{{Name: "server", CanonicalPrefix: "thirdparty.fixture.server", IdentityTemplate: "server.{id}", DefaultActions: []string{"ensure_server", "destroy_server"}}},
		ActionCatalog:    []model.IntegrationActionDefinition{{Name: "ensure_server", ResourceTypes: []string{"server"}, Idempotent: true}, {Name: "destroy_server", ResourceTypes: []string{"server"}, Idempotent: true}},
		Discovery:        model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"},
		Normalization:    model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.fixture.custom"},
		Execution:        model.IntegrationExecutionSpec{SupportsDryRun: true, IdempotentActions: []string{"ensure_server", "destroy_server"}},
	}
	if err := manifest.ValidateIntegrationTypeSpec(typeSpec); err != nil {
		t.Fatal("HTTP mutation fixture must be registration-valid", err)
	}
	ty := create("integration_type", "type", typeSpec)
	in := create("integration_instance", "instance", map[string]any{"type_ref": model.ManifestSelector{ManifestID: ty.ID.String()}})
	now := time.Now().UTC()
	scope := strings.Repeat("a", 64)
	b := model.CapacityMutationBinding{Name: "fleet", IntegrationInstanceID: in.ID.String(), IntegrationChecksum: in.Checksum, IntegrationTypeID: ty.ID.String(), IntegrationTypeChecksum: ty.Checksum, AdapterPrincipalID: "fixture-adapter", ScopeChecksum: scope, ProfileName: "base", EnsureCapability: "ensure_server", DestroyCapability: "destroy_server", ProtectedSlots: 2, MaxSlots: 3}
	plans := map[int]model.CapacityMutationIssue{}
	for slot := 1; slot <= 3; slot++ {
		raw, _ := json.Marshal(map[string]any{"schema_version": "capacity_vm_slot_v1", "capability": "ensure_server", "integration_instance_id": in.ID.String(), "scope_checksum": scope, "profile_name": "base", "slot": slot, "profile_checksum": strings.Repeat("c", 64), "admission_checksum": strings.Repeat("d", 64), "native_name": fmt.Sprintf("node-%d", slot), "bootstrap_sha256": strings.Repeat("b", 64)})
		plans[slot] = model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw}
		var approved *model.CapacityMutationSpecV1
		if err := json.Unmarshal(raw, &approved); err != nil {
			t.Fatal(err)
		}
		b.Slots = append(b.Slots, model.CapacityMutationSlotBinding{Slot: slot, DesiredSpecSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), DesiredSpec: approved})
	}
	p := model.CapacityPolicySpec{Environment: "production", Domain: "fleet", Dimension: "slots", TargetIdentity: "fixture/fleet", Owner: "fixture", Workflow: model.ManifestSelector{Namespace: ns, Name: "scale"}, Currency: "EUR", Floor: 2, Ceiling: 3, Step: 1, MaxEvidenceAgeSeconds: 60, MinSamples: 3, MaxSampleGapSeconds: 30, DownHoldSeconds: 1, LeaseSeconds: 120, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "pressure", SourceIdentity: "fixture/prom", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}}, Profiles: []model.CapacityProfile{{Name: "base", Provider: "fixture", Region: "fixture", MinUnits: 2, MaxUnits: 3, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:qualification"}}, MutationBindings: []model.CapacityMutationBinding{b}}
	policy := create("capacity_policy", "fleet", p)
	v := 0.9
	a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, Owner: p.Owner, ResourceUID: "fixture-pool", WorkloadUID: "fixture-workload", ResourceVersion: "1", WorkloadResourceVersion: "1", Profile: "base", Units: 2, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "pressure", SourceIdentity: "fixture/prom", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &v, RangeMin: &v, RangeMax: &v, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 5, CoverageComplete: true, MaxGapSeconds: 15}}}
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: uuid.NewString()}
	intent, err := store.Assess(ctx, policy, a)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = store.Claim(ctx, policy, intent.Generation, a)
	if err != nil {
		t.Fatal(err)
	}
	for slot := 1; slot <= 2; slot++ {
		proof := model.CapacityMutationProof{BindingName: b.Name, Slot: slot, ResourceID: fmt.Sprintf("native-%d", slot), ResourceCreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), RequestSHA256: b.Slots[slot-1].DesiredSpecSHA256, ObservedAt: now, ReceiptRef: "fixture:native-read", OwnerVerified: true, SpecVerified: true}
		if err = store.RecordMutationSlot(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, plans[slot], proof); err != nil {
			t.Fatal(err)
		}
	}
	g, err := store.IssueMutation(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, plans[3])
	if err != nil {
		t.Fatal(err)
	}
	token := "fixture-private-adapter-token"
	server := &Server{db: db, capacityMutationPrincipals: capacityMutationTestPrincipal(t, token, in.ID.String())}
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	handler := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("callback escaped exact machine gate") }))
	nonce := uuid.NewString()
	attempt := uuid.NewString()
	r := model.CapacityMutationRedeemRequest{GrantID: g.GrantID, AttemptID: attempt, SettlementTokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(nonce))), Capability: g.Capability, IntegrationInstanceID: g.IntegrationInstanceID, ScopeChecksum: g.ScopeChecksum, ProfileName: g.ProfileName, Slot: g.Slot, RequestSHA256: g.RequestSHA256}
	call := func(method, path string, payload any, settlement string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(payload)
		request := httptest.NewRequest(method, path, strings.NewReader(string(raw)))
		request.Header.Set("Authorization", "Bearer "+token)
		if settlement != "" {
			request.Header.Set("X-Capacity-Mutation-Settlement", settlement)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	response := call("POST", capacityMutationBasePath+"/redeem", r, "")
	var redeemed model.CapacityMutationRedeemResponse
	_ = json.Unmarshal(response.Body.Bytes(), &redeemed)
	if response.Code != 200 || redeemed.Mode != "write_once" || redeemed.GrantID != g.GrantID || redeemed.AttemptID != attempt {
		t.Fatal(response.Code, response.Body.String())
	}
	response = call("POST", capacityMutationBasePath+"/redeem", r, "")
	_ = json.Unmarshal(response.Body.Bytes(), &redeemed)
	if response.Code != 200 || redeemed.Mode != "read_only" {
		t.Fatal(response.Code, response.Body.String())
	}
	settle := model.CapacityMutationSettleRequest{GrantID: g.GrantID, AttemptID: attempt, RequestSHA256: g.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: "native-3", ResourceCreatedAt: time.Now().UTC().Format(time.RFC3339Nano), ActionID: "action-3", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "false")
	response = call("POST", capacityMutationBasePath+"/settle", settle, "wrong-nonce-that-has-thirty-two-bytes")
	if response.Code != 403 {
		t.Fatal(response.Code, response.Body.String())
	}
	response = call("POST", capacityMutationBasePath+"/settle", settle, nonce)
	var echoed map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &echoed)
	if response.Code != 200 || echoed["status"] != "settled" || echoed["grant_id"] != g.GrantID || echoed["attempt_id"] != attempt || echoed["request_sha256"] != g.RequestSHA256 {
		t.Fatal(response.Code, response.Body.String())
	}
	response = call("GET", capacityMutationBasePath+"/"+g.GrantID, nil, "")
	var receipt model.CapacityMutationReceipt
	_ = json.Unmarshal(response.Body.Bytes(), &receipt)
	if response.Code != 200 || receipt.ActionID != "action-3" || receipt.ResourceID != "native-3" || !receipt.TransportCompleted {
		t.Fatal(response.Code, response.Body.String())
	}
	for _, secret := range []string{token, nonce, r.SettlementTokenSHA256, intent.LeaseOwner, store.ExecutorID} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("private authority exposed in wire receipt")
		}
	}
}
