package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Historical admission accepts only the original identities and an exact
// current-frame CAS. Native observations, clocks and executor facts are owned
// by Core; a caller cannot supply a replacement Guest result or proof.
func decodeGuestRetirementForwardRequest(reader io.Reader) (model.CapacityGuestRetirementForwardRequest, error) {
	var out model.CapacityGuestRetirementForwardRequest
	d := json.NewDecoder(reader)
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return out, repository.ErrCapacityMutationAuthorization
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return out, repository.ErrCapacityMutationAuthorization
		}
		seen[key] = true
		switch key {
		case "preregistration_id":
			err = d.Decode(&out.PreregistrationID)
		case "retirement_request_id":
			err = d.Decode(&out.RetirementRequestID)
		case "policy_id":
			err = d.Decode(&out.PolicyID)
		case "policy_checksum":
			err = d.Decode(&out.PolicyChecksum)
		case "generation":
			err = d.Decode(&out.Generation)
		case "fencing_token":
			err = d.Decode(&out.FencingToken)
		case "intent_sha256":
			err = d.Decode(&out.IntentSHA256)
		default:
			return out, repository.ErrCapacityMutationAuthorization
		}
		if err != nil {
			return out, repository.ErrCapacityMutationAuthorization
		}
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || len(seen) != 7 || d.Decode(new(any)) != io.EOF ||
		!dispositionGrantID(out.PreregistrationID) || !dispositionGrantID(out.RetirementRequestID) || !dispositionGrantID(out.PolicyID) ||
		!capacity.ValidDigest(out.PolicyChecksum) || !capacity.ValidDigest(out.IntentSHA256) || out.Generation < 1 || out.FencingToken < 1 {
		return out, repository.ErrCapacityMutationAuthorization
	}
	return out, nil
}

// The repository retains private original wires and contexts. Export only this
// closed projection; a forward admission is never a normal Guest success.
func guestRetirementForwardSummary(r repository.GuestRetirementForward) map[string]any {
	return map[string]any{
		"schema":                       repository.GuestRetirementForwardSchema,
		"id":                           r.ID,
		"root_admission_id":            r.RootAdmissionID,
		"parent_admission_id":          r.ParentAdmissionID,
		"parent_admission_sha256":      r.ParentAdmissionSHA256,
		"stage":                        r.Stage,
		"mode":                         r.Mode,
		"preregistration_id":           r.PreregistrationID,
		"retirement_request_id":        r.RetirementRequestID,
		"admission_sha256":             r.AdmissionSHA256,
		"prefix_sha256":                r.PrefixSHA256,
		"original_caller_sha256":       r.OriginalCallerSHA256,
		"native_off_sha256":            r.NativeOffSHA256,
		"destroy_grant_id":             r.DestroyGrantID,
		"native_absence_sha256":        r.NativeAbsenceSHA256,
		"recorded_at":                  r.RecordedAt,
		"original_failure_preserved":   true,
		"normal_guest_success_claimed": false,
		"guest_command_replayed":       false,
		"native_off_observed":          r.NativeOffSHA256 != "",
		"native_absence_observed":      r.NativeAbsenceSHA256 != "",
	}
}

func (s *Server) handleOpsGuestRetirementForward(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	request, err := decodeGuestRetirementForwardRequest(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "only_original_retirement_IDs_and_current_frame_CAS_required")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 20*time.Second)
	defer stop()
	revalidate := func(checkCtx context.Context) error {
		return s.capacityDispatchPrestartOperatorCurrent(checkCtx, strings.TrimPrefix(issuer, "collaborator:"))
	}
	record, err := (repository.CapacityStore{DB: s.db}).RequestGuestRetirementForwardHistorical(ctx, request, issuer, currentAbandonedDispatchBarrier(), revalidate)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "partial_retirement_forward_not_admitted")
		return
	}
	writeJSON(w, http.StatusCreated, guestRetirementForwardSummary(record))
}

func (s *Server) handleOpsGuestRetirementForwardRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	id := r.PathValue("preregistrationId")
	if !dispositionGrantID(id) {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_UUID_required")
		return
	}
	ctx, stop := context.WithTimeout(r.Context(), 10*time.Second)
	defer stop()
	rows, err := (repository.CapacityStore{DB: s.db}).ReadGuestRetirementForwards(ctx, id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "partial_retirement_forward_not_found")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, guestRetirementForwardSummary(row))
	}
	writeJSON(w, http.StatusOK, out)
}
