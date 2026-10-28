//go:build linux && capacitytest && nativequalification

package httpapi

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// AssertSyntheticCapacityHTTP runs the real private authentication and HTTP
// callbacks against a caller-owned isolated fixture DB. The grant is generated
// by the source-identified fixture before this function is called. It does not
// call a provider or establish native/production evidence.
func AssertSyntheticCapacityHTTP(db *sql.DB, grant model.CapacityMutationGrant, principalID, leaseOwner, executorID string) error {
	const token = "synthetic-private-adapter-token-only"
	config := []capacityMutationPrincipalConfig{{PrincipalID: principalID, Status: "active", ExpiresAt: time.Now().Add(time.Hour), RotationID: "synthetic-rotation", TokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(token))), IntegrationInstanceID: grant.IntegrationInstanceID, Capabilities: []string{"ensure_server", "destroy_server"}}}
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	oldPrincipals, hadPrincipals := os.LookupEnv(capacityMutationPrincipalsEnv)
	oldExecution, hadExecution := os.LookupEnv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED")
	defer func() {
		if hadPrincipals {
			_ = os.Setenv(capacityMutationPrincipalsEnv, oldPrincipals)
		} else {
			_ = os.Unsetenv(capacityMutationPrincipalsEnv)
		}
		if hadExecution {
			_ = os.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", oldExecution)
		} else {
			_ = os.Unsetenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED")
		}
	}()
	if os.Setenv(capacityMutationPrincipalsEnv, string(raw)) != nil || os.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true") != nil {
		return errors.New("synthetic callback environment unavailable")
	}
	principals, err := loadCapacityMutationPrincipals(nil, nil, nil)
	if err != nil {
		return err
	}
	server := &Server{db: db, capacityMutationPrincipals: principals}
	escaped := false
	handler := server.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { escaped = true }))
	nonce, attempt := uuid.NewString(), uuid.NewString()
	r := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: attempt, SettlementTokenSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(nonce))), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256}
	call := func(method, path string, payload any, settlement string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		request := httptest.NewRequest(method, path, strings.NewReader(string(body)))
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
	if json.Unmarshal(response.Body.Bytes(), &redeemed) != nil || response.Code != 200 || redeemed.Mode != "write_once" || redeemed.GrantID != grant.GrantID || redeemed.AttemptID != attempt {
		return errors.New("synthetic HTTP first redemption failed")
	}
	response = call("POST", capacityMutationBasePath+"/redeem", r, "")
	if json.Unmarshal(response.Body.Bytes(), &redeemed) != nil || response.Code != 200 || redeemed.Mode != "read_only" {
		return errors.New("synthetic HTTP redemption replay failed")
	}
	created := time.Now().UTC().Format(time.RFC3339Nano)
	settle := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: attempt, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: "synthetic-http-resource", ResourceCreatedAt: created, ActionID: "synthetic-http-action", ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if os.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "false") != nil {
		return errors.New("synthetic callback pause failed")
	}
	response = call("POST", capacityMutationBasePath+"/settle", settle, "wrong-nonce-that-has-thirty-two-bytes")
	if response.Code != 403 {
		return errors.New("synthetic HTTP wrong nonce accepted")
	}
	response = call("POST", capacityMutationBasePath+"/settle", settle, nonce)
	var echoed map[string]any
	if json.Unmarshal(response.Body.Bytes(), &echoed) != nil || response.Code != 200 || echoed["status"] != "settled" || echoed["grant_id"] != grant.GrantID || echoed["attempt_id"] != attempt || echoed["request_sha256"] != grant.RequestSHA256 {
		return errors.New("synthetic HTTP settlement failed")
	}
	response = call("GET", capacityMutationBasePath+"/"+grant.GrantID, nil, "")
	var receipt model.CapacityMutationReceipt
	if json.Unmarshal(response.Body.Bytes(), &receipt) != nil || response.Code != 200 || receipt.ActionID != settle.ActionID || receipt.ResourceID != settle.ResourceID || !receipt.TransportCompleted {
		return errors.New("synthetic HTTP receipt differs")
	}
	for _, private := range []string{token, nonce, r.SettlementTokenSHA256, leaseOwner, executorID} {
		if strings.Contains(response.Body.String(), private) {
			return errors.New("synthetic HTTP receipt exposed private authority")
		}
	}
	if escaped {
		return errors.New("synthetic callback escaped exact machine gate")
	}
	return nil
}
