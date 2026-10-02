package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type replaceReactorDispatchPolicyRequest struct {
	PausedEventTypes *[]string `json:"paused_event_types"`
	ExpectedRevision *int64    `json:"expected_revision"`
}

// This control always enforces the named permission. The general console
// middleware has an operator-controlled warn mode that deliberately lets
// missing permissions through; that mode must not allow dispatch changes or
// expose the operator's pause policy.
func (s *Server) requireReactorPolicyPermissionFunc(perm string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := claimsFromContext(r.Context())
		if !ok {
			writeProblemJSON(w, http.StatusUnauthorized, "auth.unauthenticated", "A verified operator session is required.")
			return
		}
		actorRaw, _ := claims["collaborator_id"].(string)
		if _, err := uuid.Parse(actorRaw); err != nil {
			writeProblemJSON(w, http.StatusUnauthorized, "auth.unauthenticated", "The operator identity is invalid.")
			return
		}
		allowed, err := s.collaboratorHasOpsPermission(r.Context(), actorRaw, perm)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rbac_check_failed")
			return
		}
		if !allowed {
			metrics.IncRBACDenied(perm, "enforce")
			s.recordOpsAuditDenied(r, actorRaw, perm)
			writeProblemJSON(w, http.StatusForbidden, "permission.denied", "You do not have the required permission "+perm+" to perform this action.")
			return
		}
		next(w, r)
	}
}

// The policy API uses the logical integration instance identity. Re-applying
// an instance manifest and the integration_type manifest sync cannot overwrite
// an operator's dispatch pause.
func (s *Server) handleReactorDispatchPolicyGet(w http.ResponseWriter, r *http.Request) {
	namespace, name := reactorDispatchPolicyIdentity(r)
	if namespace == "" || name == "" {
		writeJSONError(w, http.StatusBadRequest, "namespace and name are required")
		return
	}
	p, err := repository.GetIntegrationReactorDispatchPolicy(r.Context(), s.db, namespace, name)
	if errors.Is(err, repository.ErrIntegrationReactorPolicyInstanceNotFound) {
		writeJSONError(w, http.StatusNotFound, "active integration instance not found")
		return
	}
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) handleReactorDispatchPolicyPut(w http.ResponseWriter, r *http.Request) {
	claims, hasClaims := claimsFromContext(r.Context())
	if !hasClaims {
		writeProblemJSON(w, http.StatusUnauthorized, "auth.unauthenticated", "A verified operator session is required.")
		return
	}
	actorRaw, _ := claims["collaborator_id"].(string)
	actorID, actorErr := uuid.Parse(actorRaw)
	if actorErr != nil {
		writeProblemJSON(w, http.StatusUnauthorized, "auth.unauthenticated", "The operator identity is invalid.")
		return
	}
	namespace, name := reactorDispatchPolicyIdentity(r)
	if namespace == "" || name == "" {
		writeJSONError(w, http.StatusBadRequest, "namespace and name are required")
		return
	}
	var body replaceReactorDispatchPolicyRequest
	if err := decodeJSON(r, &body); err != nil {
		writeMappedError(w, err)
		return
	}
	if body.PausedEventTypes == nil {
		writeJSONError(w, http.StatusBadRequest, "paused_event_types is required; use [] to resume")
		return
	}
	if body.ExpectedRevision == nil || *body.ExpectedRevision < 0 {
		writeJSONError(w, http.StatusBadRequest, "expected_revision is required and cannot be negative")
		return
	}
	paused, err := validatePausedReactorEventTypes(*body.PausedEventTypes)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	p, err := repository.ReplaceIntegrationReactorDispatchPolicy(r.Context(), s.db, namespace, name, paused, *body.ExpectedRevision, actorID)
	if errors.Is(err, repository.ErrIntegrationReactorPolicyRevisionConflict) {
		writeJSONError(w, http.StatusConflict, "reactor dispatch policy changed; GET the current revision")
		return
	}
	if errors.Is(err, repository.ErrIntegrationReactorPolicyInstanceNotFound) {
		writeJSONError(w, http.StatusNotFound, "active integration instance not found")
		return
	}
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func reactorDispatchPolicyIdentity(r *http.Request) (string, string) {
	return strings.TrimSpace(r.PathValue("namespace")), strings.TrimSpace(r.PathValue("name"))
}

func validatePausedReactorEventTypes(values []string) ([]string, error) {
	if len(values) > 128 {
		return nil, fmt.Errorf("paused_event_types cannot exceed 128 entries")
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != strings.TrimSpace(value) ||
			(!repository.IsCanonLifecycleEvent(value) && !repository.IsIntegrationMutationEvent(value)) {
			return nil, fmt.Errorf("paused_event_types contains unsupported exact event type %q", value)
		}
		if _, exists := seen[value]; exists {
			return nil, fmt.Errorf("paused_event_types contains duplicate %q", value)
		}
		seen[value] = struct{}{}
	}
	result := slices.Clone(values)
	slices.Sort(result)
	return result, nil
}
