//go:build linux && nativequalification

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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// This consumer uses only actual source-owned grants from the owning two-slot
// corpus. It cannot issue a grant, synthesize a native proof or create a VM.
// The old synthetic HTTP root remains unchanged and is not aliased to this root.
func TestCapacityGuestOriginalHTTPCallbacksPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var corpus q.Corpus
	if os.Getenv("REQUIRE_CAPACITY_GUEST_NATIVE_CORPUS") != "true" {
		t.Fatal("owning original corpus is required")
	}
	if _, err := q.ReadPrivate(ctx, os.Getenv("CAPACITY_GUEST_NATIVE_CORPUS_FILE"), &corpus); err != nil {
		t.Fatal("full closed original corpus unavailable", err)
	}
	if corpus.Schema != "core_original_guest_native_qemu_corpus_v1" || !q.PositiveCase(corpus.NativeCase) || corpus.NativeCase != os.Getenv("GUEST_ORIGINAL_NATIVE_CASE") || corpus.CaseOutcome != "ORIGINAL_PROTECTED_LIFECYCLE_JOINED" || !guestOriginalPinnedCoreSource(corpus.ActualCoreSourceCommit) || len(corpus.OriginalPreregistrationIDs) != 2 || len(corpus.NativeResources) != 2 {
		t.Fatal("current exact owning two-slot positive corpus required")
	}
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for n, id := range corpus.OriginalPreregistrationIDs {
		var wire, grantWire []byte
		var consistent bool
		if err := db.QueryRowContext(ctx, `SELECT p.original_wire,g.grant_record,p.preregistration_record=convert_from(p.original_wire,'UTF8')::jsonb AND p.create_grant_id::text=p.preregistration_record->>'original_create_grant_id' FROM public.capacity_vm_provisioning_preregistrations p JOIN public.capacity_mutation_grants g ON g.id=p.create_grant_id WHERE p.id=$1 AND g.namespace=$2`, id, corpus.Namespace).Scan(&wire, &grantWire, &consistent); err != nil || !consistent {
			t.Fatal("actual preregistration/grant/source row missing", err)
		}
		var pre model.CapacityGuestOriginalProvisioningPreregistration
		var stored struct {
			Grant model.CapacityMutationGrant `json:"grant"`
			Binding model.CapacityMutationBinding `json:"binding"`
			PolicyID string `json:"policy_id"`
			PolicyChecksum string `json:"policy_checksum"`
			WorkflowID string `json:"workflow_id"`
			LeaseOwner string `json:"lease_owner"`
			ExecutorID string `json:"executor_id"`
			AttemptID string `json:"attempt_id"`
			SettlementTokenSHA256 string `json:"settlement_token_sha256"`
		}
		if capacity.DecodeGuestLifecycle(wire, &pre) != nil || json.Unmarshal(grantWire, &stored) != nil || pre.PreregistrationID != id || pre.CoreSourceCommit != corpus.ActualCoreSourceCommit || pre.PolicyID != corpus.PolicyID || pre.PolicyChecksum != corpus.PolicyChecksum || pre.WorkflowID != corpus.WorkflowID || pre.WorkflowChecksum != corpus.WorkflowChecksum || pre.ProfileManifestSHA256 != corpus.ProfileManifestSHA256 || pre.Slot != n+1 || pre.OriginalCreateGrantID != stored.Grant.GrantID || stored.PolicyID != corpus.PolicyID || stored.PolicyChecksum != corpus.PolicyChecksum || stored.WorkflowID != corpus.WorkflowID || stored.Binding.AdapterPrincipalID == "" || stored.Grant.Slot != n+1 {
			t.Fatal("private callback rows are not from this actual source")
		}
		var policyChecksum, workflowChecksum string
		if err := db.QueryRowContext(ctx, `SELECT p.checksum,w.checksum FROM public.manifests p JOIN public.manifests w ON w.id=$2 WHERE p.id=$1 AND p.namespace=$3 AND w.namespace=$3 AND p.kind='capacity_policy' AND w.kind='workflow'`, corpus.PolicyID, corpus.WorkflowID, corpus.Namespace).Scan(&policyChecksum, &workflowChecksum); err != nil || policyChecksum != corpus.PolicyChecksum || workflowChecksum != corpus.WorkflowChecksum {
			t.Fatal("same-DB policy/workflow not bound to owning corpus", err)
		}
		store := repository.CapacityStore{DB: db}
		before, err := store.MutationReceipt(ctx, stored.Binding.AdapterPrincipalID, stored.Grant.GrantID)
		if err != nil || before.AttemptID != stored.AttemptID || before.ResourceID != corpus.NativeResources[n].ResourceID || before.ResourceCreatedAt != corpus.NativeResources[n].ResourceCreatedAt || !before.TransportCompleted || before.Outcome != "accepted" {
			t.Fatal("actual accepted transport receipt unavailable", err)
		}
		// Register a new test-only callback credential for the SAME actual principal
		// and exact instance. It is not an original transport nonce or authority.
		token := uuid.NewString()+uuid.NewString()
		config := []capacityMutationPrincipalConfig{{PrincipalID: stored.Binding.AdapterPrincipalID, Status: "active", ExpiresAt: time.Now().Add(time.Minute), RotationID: "original-corpus-readback", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), IntegrationInstanceID: stored.Grant.IntegrationInstanceID, Capabilities: []string{stored.Grant.Capability}}}
		raw, err := json.Marshal(config)
		if err != nil { t.Fatal(err) }
		t.Setenv(capacityMutationPrincipalsEnv, string(raw))
		principals, err := loadCapacityMutationPrincipals(nil, nil, nil)
		if err != nil { t.Fatal(err) }
		server := &Server{db: db, capacityMutationPrincipals: principals}
		handler := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("callback escaped machine gate") }))
		call := func(method, path string, payload any, nonce string) *httptest.ResponseRecorder {
			body, err := json.Marshal(payload)
			if err != nil { t.Fatal(err) }
			r := httptest.NewRequest(method, path, strings.NewReader(string(body))).WithContext(ctx)
			r.Header.Set("Authorization", "Bearer "+token)
			if nonce != "" { r.Header.Set("X-Capacity-Mutation-Settlement", nonce) }
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			return w
		}
		g := before.Grant
		request := model.CapacityMutationRedeemRequest{GrantID:g.GrantID, AttemptID:before.AttemptID, SettlementTokenSHA256:stored.SettlementTokenSHA256, Capability:g.Capability, IntegrationInstanceID:g.IntegrationInstanceID, ScopeChecksum:g.ScopeChecksum, ProfileName:g.ProfileName, Slot:g.Slot, RequestSHA256:g.RequestSHA256, ExpectedResourceID:g.ExpectedResourceID, ExpectedResourceCreatedAt:g.ExpectedResourceCreatedAt, CompensationOf:g.CompensationOf}
		response := call("POST", capacityMutationBasePath+"/redeem", request, "")
		var replay model.CapacityMutationRedeemResponse
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &replay) != nil || replay.Mode != "read_only" || replay.GrantID != g.GrantID || replay.AttemptID != before.AttemptID || replay.RequestSHA256 != g.RequestSHA256 {
			t.Fatal("actual grant replay reacquired native permission", response.Code)
		}
		t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "false")
		settle := model.CapacityMutationSettleRequest{GrantID:g.GrantID, AttemptID:before.AttemptID, RequestSHA256:g.RequestSHA256, Outcome:"accepted", TransportCompleted:true, ResourceID:before.ResourceID, ResourceCreatedAt:before.ResourceCreatedAt, ActionID:before.ActionID, ObservedAt:time.Now().UTC().Format(time.RFC3339Nano)}
		response = call("POST", capacityMutationBasePath+"/settle", settle, uuid.NewString()+uuid.NewString())
		var problem struct {
			Type string `json:"type"`
			Title string `json:"title"`
			Status int `json:"status"`
			Detail string `json:"detail"`
			Code string `json:"code"`
		}
		if response.Code != 403 || capacity.DecodeGuestLifecycle(response.Body.Bytes(), &problem) != nil || problem.Status != 403 || problem.Code != "capacity.mutation_scope_denied" || problem.Title != problem.Code || problem.Type != "https://yggdrasil.dakasa.me/problems/"+problem.Code { t.Fatal("wrong actual settlement nonce not refused by exact authorization problem", response.Code) }
		response = call("GET", capacityMutationBasePath+"/"+g.GrantID, nil, "")
		var got model.CapacityMutationReceipt
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &got) != nil || !reflect.DeepEqual(before, got) { t.Fatal("typed actual wire receipt changed") }
		for _, secret := range []string{token, stored.LeaseOwner, stored.ExecutorID, stored.SettlementTokenSHA256} {
			if secret == "" || strings.Contains(response.Body.String(), secret) { t.Fatal("private callback authority exposed") }
		}
		after, err := store.MutationReceipt(ctx, stored.Binding.AdapterPrincipalID, g.GrantID)
		var afterWire []byte
		var events int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2`, "capacity-mutation/"+g.GrantID, corpus.Namespace).Scan(&events); err != nil || events != 1 { t.Fatal("HTTP replay/negative changed canonical event multiplicity",err) }
		if err != nil || !reflect.DeepEqual(before, after) { t.Fatal("read-only callback checks altered canonical receipt", err) }
		if err := db.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, g.GrantID).Scan(&afterWire); err != nil || string(afterWire) != string(grantWire) { t.Fatal("callback negative changed private ledger", err) }
	}
}

// Test binaries are not VCS-stamped, so the corpus is bound to the Core pin
// the native job checked out instead of the build info revision.
func guestOriginalPinnedCoreSource(value string) bool {
	pin := os.Getenv("CORE_ORIGINAL_GUEST_NATIVE_SOURCE_COMMIT")
	if len(pin) != 40 || strings.Trim(pin, "0123456789abcdef") != "" {
		return false
	}
	return value == pin
}
