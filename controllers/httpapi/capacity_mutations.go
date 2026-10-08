package httpapi

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const capacityMutationBasePath = "/api/v1/capacity/mutations"
const capacityMutationPrincipalsEnv = "YGGDRASIL_CAPACITY_MUTATION_PRINCIPALS_JSON"

type capacityMutationPrincipalConfig struct {
	PrincipalID           string    `json:"principal_id"`
	Status                string    `json:"status"`
	ExpiresAt             time.Time `json:"expires_at"`
	RotationID            string    `json:"rotation_id"`
	RotatedAt             time.Time `json:"rotated_at"`
	TokenSHA256           string    `json:"token_sha256"`
	IntegrationInstanceID string    `json:"integration_instance_id"`
	Capabilities          []string  `json:"capabilities"`
}

type capacityMutationPrincipal struct {
	base         validatedMachinePrincipalBase
	instanceID   string
	capabilities map[string]bool
}

// A malformed opt-in inventory fails boot, not open. Credentials are hashes,
// with independent lifecycle/rotation and one exact instance per principal.
func loadCapacityMutationPrincipals(workflows []workflowMachinePrincipal, events []eventPublisherPrincipal, directory []directoryMachinePrincipal) ([]capacityMutationPrincipal, error) {
	if raw, present := os.LookupEnv(capacityMutationPrincipalsEnv); present && strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("%s is set but blank", capacityMutationPrincipalsEnv)
	}
	var configs []capacityMutationPrincipalConfig
	if err := decodeMachinePrincipalConfig(capacityMutationPrincipalsEnv, &configs); err != nil {
		return nil, err
	}
	if configs == nil && os.Getenv(capacityMutationPrincipalsEnv) == "" {
		return nil, nil
	}
	if len(configs) == 0 || len(configs) > 128 {
		return nil, fmt.Errorf("capacity mutation inventory requires 1..128 principals")
	}
	result := make([]capacityMutationPrincipal, 0, len(configs))
	ids := map[string]bool{}
	hashes := map[[sha256.Size]byte]bool{}
	for index, c := range configs {
		base, err := validateMachinePrincipalBase(capacityMutationPrincipalsEnv, index, c.PrincipalID, c.Status, c.ExpiresAt, c.RotationID, c.RotatedAt, c.TokenSHA256)
		if err != nil {
			return nil, err
		}
		id, err := uuid.Parse(c.IntegrationInstanceID)
		if err != nil || id == uuid.Nil || id.String() != c.IntegrationInstanceID || len(base.principalID) > 128 || ids[base.principalID] || hashes[base.tokenSHA256] || len(c.Capabilities) == 0 || len(c.Capabilities) > 32 {
			return nil, fmt.Errorf("capacity mutation principal identity or scope is invalid")
		}
		p := capacityMutationPrincipal{base: base, instanceID: c.IntegrationInstanceID, capabilities: map[string]bool{}}
		for _, capability := range c.Capabilities {
			if (!strings.HasPrefix(capability, "ensure_") && !strings.HasPrefix(capability, "destroy_")) || len(capability) > 128 || containsWildcard(capability) || strings.IndexFunc(capability, func(r rune) bool { return r != '_' && (r < 'a' || r > 'z') && (r < '0' || r > '9') }) >= 0 || p.capabilities[capability] {
				return nil, fmt.Errorf("capacity mutation principal capability must be exact")
			}
			p.capabilities[capability] = true
		}
		collision := false
		for _, other := range workflows {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.TokenSHA256)
		}
		for _, other := range events {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.TokenSHA256)
		}
		for _, other := range directory {
			collision = collision || machineCredentialDigestsCollide(base.tokenSHA256, other.TokenSHA256)
		}
		for _, other := range plaintextMachineCredentialScopes() {
			collision = collision || digestMatchesPlaintext(base.tokenSHA256, other.value)
		}
		if collision {
			return nil, fmt.Errorf("capacity mutation principal credential collides with another credential surface")
		}
		ids[base.principalID], hashes[base.tokenSHA256] = true, true
		result = append(result, p)
	}
	return result, nil
}

func (s *Server) capacityMutationCredential(r *http.Request) *capacityMutationPrincipal {
	values := r.Header.Values("Authorization")
	var matched *capacityMutationPrincipal
	for _, value := range values {
		parts := strings.Fields(value)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) > 4096 {
			continue
		}
		for i := range s.capacityMutationPrincipals {
			if machineCredentialMatches(parts[1], s.capacityMutationPrincipals[i].base.tokenSHA256) {
				matched = &s.capacityMutationPrincipals[i]
			}
		}
	}
	return matched
}

func capacityMutationPath(path string) bool {
	return path == capacityMutationBasePath || strings.HasPrefix(path, capacityMutationBasePath+"/")
}

// This branch runs before console/directory/workflow credential fallbacks. It
// also claims expired/revoked matching credentials on every route, preventing a
// valid browser cookie or plaintext bridge from widening the adapter's scope.
func (s *Server) serveCapacityMutationRequest(w http.ResponseWriter, r *http.Request, p *capacityMutationPrincipal) {
	w.Header().Set("Cache-Control", "no-store")
	if p == nil || len(r.Header.Values("Authorization")) != 1 || p.base.status != "active" || !time.Now().Before(p.base.expiresAt) {
		writeProblemJSON(w, http.StatusUnauthorized, "capacity.mutation_unauthorized", "an active capacity mutation adapter credential is required")
		return
	}
	if !capacityMutationPath(r.URL.Path) || path.Clean(r.URL.Path) != r.URL.Path || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		writeProblemJSON(w, http.StatusForbidden, "capacity.mutation_scope_denied", "credential is restricted to exact capacity mutation callbacks")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	store := repository.CapacityStore{DB: s.db, ExecutionEnabled: os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") == "true"}
	if s.db == nil {
		mutationHTTPError(w, fmt.Errorf("database unavailable"))
		return
	}
	route := r.URL.Path
	switch {
	case r.Method == http.MethodPost && route == capacityMutationBasePath+"/redeem":
		var payload model.CapacityMutationRedeemRequest
		if err := decodeCapacityMutationJSON(w, r, &payload); err != nil {
			writeProblemJSON(w, 400, "capacity.mutation_invalid", "a bounded exact JSON request is required")
			return
		}
		if payload.IntegrationInstanceID != p.instanceID || !p.capabilities[payload.Capability] {
			mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		response, err := store.RedeemMutation(ctx, p.base.principalID, payload)
		if err != nil {
			mutationHTTPError(w, err)
			return
		}
		writeJSON(w, 200, response)
	case r.Method == http.MethodPost && route == capacityMutationBasePath+"/settle":
		var payload model.CapacityMutationSettleRequest
		if err := decodeCapacityMutationJSON(w, r, &payload); err != nil {
			writeProblemJSON(w, 400, "capacity.mutation_invalid", "a bounded exact JSON request is required")
			return
		}
		receipt, err := store.MutationReceipt(ctx, p.base.principalID, payload.GrantID)
		if err != nil {
			mutationHTTPError(w, err)
			return
		}
		if receipt.Grant.IntegrationInstanceID != p.instanceID || !p.capabilities[receipt.Grant.Capability] {
			mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		nonces := r.Header.Values("X-Capacity-Mutation-Settlement")
		if len(nonces) != 1 {
			mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		_, err = store.SettleMutation(ctx, p.base.principalID, nonces[0], payload)
		if err != nil {
			mutationHTTPError(w, err)
			return
		}
		writeJSON(w, 200, map[string]any{"grant_id": payload.GrantID, "attempt_id": payload.AttemptID, "request_sha256": payload.RequestSHA256, "status": "settled"})
	case r.Method == http.MethodGet && strings.HasPrefix(route, capacityMutationBasePath+"/"):
		id := strings.TrimPrefix(route, capacityMutationBasePath+"/")
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			writeProblemJSON(w, 404, "capacity.mutation_not_found", "exact grant receipt route required")
			return
		}
		receipt, err := store.MutationReceipt(ctx, p.base.principalID, id)
		if err != nil {
			mutationHTTPError(w, err)
			return
		}
		if receipt.Grant.IntegrationInstanceID != p.instanceID || !p.capabilities[receipt.Grant.Capability] {
			mutationHTTPError(w, repository.ErrCapacityMutationAuthorization)
			return
		}
		writeJSON(w, 200, receipt)
	default:
		writeProblemJSON(w, 404, "capacity.mutation_not_found", "exact capacity mutation callback required")
	}
}

func decodeCapacityMutationJSON(w http.ResponseWriter, r *http.Request, value any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 32768)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("one JSON object required")
	}
	return nil
}

func mutationHTTPError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrCapacityMutationAuthorization), errors.Is(err, sql.ErrNoRows):
		writeProblemJSON(w, 403, "capacity.mutation_scope_denied", "exact adapter grant authorization required")
	case errors.Is(err, repository.ErrCapacityConflict), errors.Is(err, repository.ErrCapacityLease), errors.Is(err, repository.ErrCapacityDisabled):
		writeProblemJSON(w, 409, "capacity.mutation_conflict", "mutation authority is stale, disabled or unresolved; recover by reads")
	default:
		writeProblemJSON(w, 503, "capacity.mutation_unavailable", "durable mutation authority is unavailable; do not send a provider mutation")
	}
}
