package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// This administrative boundary never inherits the warn-mode or no-claims
// machine bypass. The original issuer is the authenticated operator identity,
// never a request-supplied principal, health flag or provider observation.
func (s *Server) originalDispositionIssuer(w http.ResponseWriter, r *http.Request) (string, bool) {
	claims, ok := claimsFromContext(r.Context())
	actor, _ := claims["collaborator_id"].(string)
	id, err := uuid.Parse(actor)
	if !ok || err != nil || id == uuid.Nil || id.String() != actor {
		writeProblemJSON(w, http.StatusUnauthorized, "auth.unauthenticated", "An authenticated operator identity is required.")
		return "", false
	}
	allowed, err := s.collaboratorHasOpsPermission(r.Context(), actor, repository.YggdrasilGodModeAction)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "original_disposition_authorization_unavailable")
		return "", false
	}
	if !allowed {
		writeProblemJSON(w, http.StatusForbidden, "permission.denied", "Administrative recovery permission is required.")
		return "", false
	}
	return "collaborator:" + actor, true
}

func dispositionGrantID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

// Decode a closed, bounded object. Duplicate identities and caller-supplied
// native health/absence fields are refused before any repository/native read.
func decodeOriginalDispositionGrant(input io.Reader) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return "", errors.New("invalid disposition request")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return "", errors.New("closed original grant request required")
	}
	id := ""
	seen := false
	for d.More() {
		key, e := d.Token()
		if e != nil || key != "grant_id" || seen {
			return "", errors.New("only one original grant identity required")
		}
		seen = true
		if d.Decode(&id) != nil {
			return "", errors.New("invalid original grant identity")
		}
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || !seen || !dispositionGrantID(id) || !errors.Is(d.Decode(&struct{}{}), io.EOF) {
		return "", errors.New("invalid original grant request")
	}
	return id, nil
}

func dispositionSummary(value model.CapacityOriginalCreateDisposition) map[string]any {
	// Raw native response bodies remain in the immutable DB evidence, not in
	// the ordinary administrative HTTP result or the public audit projection.
	return map[string]any{"schema": value.Schema, "id": value.ID, "grant_id": value.GrantID, "preregistration_id": value.PreregistrationID,
		"issuer": value.Issuer, "recorded_at": value.RecordedAt, "observation_sha256": value.ObservationSHA256,
		"closed_generation": value.ClosedGeneration, "closed_fencing_token": value.ClosedFencingToken,
		"historical_core_source_commit": value.HistoricalCoreSourceCommit, "historical_create_source_commit": value.Observation.OriginalAdapterSourceCommit,
		"observer_source_commit": value.Observation.AdapterSourceCommit, "inventory_basis": value.Observation.InventoryBasis,
		"original_auxiliary_inventory_complete": value.OriginalAuxiliaryInventoryComplete, "resource_id": value.Observation.ResourceID, "resource_created_at": value.Observation.ResourceCreatedAt,
		"original_accepted_unchanged": value.OriginalAcceptedUnchanged, "serving_or_business_or_savings_authority": false,
		"new_assessment_decision_and_single_use_grant_still_required": true, "provider_mutations": 0}
}

func (s *Server) handleOpsOriginalCreateDisposition(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	grantID, err := decodeOriginalDispositionGrant(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_grant_uuid_required")
		return
	}
	result, err := messagecontroller.RecordOriginalCreateDisposition(r.Context(), s.db, s.rabbitmq, grantID, issuer)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "original_create_disposition_unresolved")
		return
	}
	writeJSON(w, http.StatusCreated, dispositionSummary(result))
}

func (s *Server) handleOpsOriginalCreateDispositionRead(w http.ResponseWriter, r *http.Request) {
	_, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	id := r.PathValue("grantId")
	if !dispositionGrantID(id) {
		writeJSONError(w, http.StatusBadRequest, "only_original_grant_uuid_required")
		return
	}
	result, err := (repository.CapacityStore{DB: s.db}).ReadOriginalCreateDisposition(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "original_create_disposition_not_found")
		return
	}
	writeJSON(w, http.StatusOK, dispositionSummary(result))
}
