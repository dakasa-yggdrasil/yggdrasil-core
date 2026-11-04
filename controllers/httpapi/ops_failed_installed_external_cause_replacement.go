package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

var errFailedInstalledExternalCauseRequest = errors.New("closed external-cause replacement admission request required")

// 8 KiB of evidence may grow under JSON escaping; the body bound stays fixed.
const failedInstalledExternalCauseBodyLimit = 65536

var failedInstalledExternalCauseRequestFields = map[string]bool{
	"preregistration_id": true, "peer_preregistration_id": true, "cause_evidence": true,
}

// The request names the disposed Guest, the peer Guest and the operator's
// opaque cause evidence. No build, binding, time, dimension, Core identity or
// membership assertion can enter the admission: Core derives all of them.
func decodeFailedInstalledExternalCauseReplacement(input io.Reader) (repository.FailedInstalledExternalCauseReplacementRequest, error) {
	var request repository.FailedInstalledExternalCauseReplacementRequest
	raw, err := io.ReadAll(io.LimitReader(input, failedInstalledExternalCauseBodyLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > failedInstalledExternalCauseBodyLimit {
		return request, errFailedInstalledExternalCauseRequest
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return request, errFailedInstalledExternalCauseRequest
	}
	values := make(map[string]string, len(failedInstalledExternalCauseRequestFields))
	for d.More() {
		token, tokenErr := d.Token()
		key, ok := token.(string)
		if tokenErr != nil || !ok || !failedInstalledExternalCauseRequestFields[key] {
			return request, errFailedInstalledExternalCauseRequest
		}
		if _, exists := values[key]; exists {
			return request, errFailedInstalledExternalCauseRequest
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return request, errFailedInstalledExternalCauseRequest
		}
		var text string
		trimmed := bytes.TrimSpace(value)
		if len(trimmed) == 0 || trimmed[0] != '"' || !failedInstalledExternalCauseExactJSONString(trimmed) || json.Unmarshal(trimmed, &text) != nil {
			return request, errFailedInstalledExternalCauseRequest
		}
		values[key] = text
	}
	last, err := d.Token()
	if err != nil || last != json.Delim('}') || len(values) != len(failedInstalledExternalCauseRequestFields) || !errors.Is(d.Decode(&struct{}{}), io.EOF) {
		return request, errFailedInstalledExternalCauseRequest
	}
	request.PreregistrationID = values["preregistration_id"]
	request.PeerPreregistrationID = values["peer_preregistration_id"]
	request.CauseEvidence = values["cause_evidence"]
	if !dispositionGrantID(request.PreregistrationID) || !dispositionGrantID(request.PeerPreregistrationID) ||
		request.PreregistrationID == request.PeerPreregistrationID || !repository.ValidFailedInstalledExternalCauseEvidence(request.CauseEvidence) {
		return request, errFailedInstalledExternalCauseRequest
	}
	return request, nil
}

// encoding/json replaces invalid UTF-8 bytes and unpaired UTF-16 surrogate
// escapes with U+FFFD instead of failing. The admission stores the evidence
// with its SHA-256, so the decoded text must be exactly what the operator
// sent: refuse a raw JSON string token holding invalid UTF-8 or any \uD800-
// \uDFFF escape that is not one half of a valid surrogate pair.
func failedInstalledExternalCauseExactJSONString(token []byte) bool {
	if !utf8.Valid(token) {
		return false
	}
	escape := func(i int) (rune, bool) {
		if i+6 > len(token) || token[i] != '\\' || token[i+1] != 'u' {
			return 0, false
		}
		v, err := strconv.ParseUint(string(token[i+2:i+6]), 16, 16)
		return rune(v), err == nil
	}
	for i := 0; i < len(token); i++ {
		if token[i] != '\\' {
			continue
		}
		if i+1 >= len(token) {
			return false
		}
		if token[i+1] != 'u' {
			i++
			continue
		}
		r, ok := escape(i)
		if !ok {
			return false
		}
		switch {
		case r >= 0xDC00 && r <= 0xDFFF:
			return false
		case r >= 0xD800 && r <= 0xDBFF:
			low, ok := escape(i + 6)
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			i += 11
		default:
			i += 5
		}
	}
	return true
}

// Identities, hashes, times and derived facts only: never the evidence body.
// The summary states what the admission is NOT: no cause finding by Core, no
// rewritten failure, no provider read and no relaxation for other disposals.
func failedInstalledExternalCauseSummary(v repository.FailedInstalledExternalCauseAdmission) map[string]any {
	return map[string]any{
		"schema": v.Schema, "id": v.ID, "disposal_id": v.DisposalID, "disposal_stage": v.DisposalStage, "preregistration_id": v.PreregistrationID,
		"namespace": v.Namespace, "environment": v.Environment, "domain": v.Domain, "dimension": v.Dimension,
		"blocked_guest_source": v.BlockedGuestSource, "blocked_profile_sha256": v.BlockedProfileSHA256,
		"admitted_binding_sha256": v.AdmittedBindingSHA256, "admitted_policy_id": v.AdmittedPolicyID, "admitted_policy_checksum": v.AdmittedPolicyChecksum,
		"original_failed_run_id": v.OriginalFailedRunID, "original_failed_run_finished_at": v.OriginalFailedRunFinishedAt,
		"peer_preregistration_id": v.PeerPreregistrationID, "peer_namespace": v.PeerNamespace, "peer_environment": v.PeerEnvironment,
		"peer_domain": v.PeerDomain, "peer_dimension": v.PeerDimension, "peer_guest_source": v.PeerGuestSource, "peer_profile_sha256": v.PeerProfileSHA256,
		"peer_read_challenge_id": v.PeerReadChallengeID, "peer_read_recorded_at": v.PeerReadRecordedAt, "peer_read_return_recorded_at": v.PeerReadReturnRecordedAt,
		"peer_intent_phase": "promoted", "peer_intent_generation": v.PeerIntentGeneration, "peer_intent_fencing_token": v.PeerIntentFencingToken, "peer_resource_id": v.PeerResourceID,
		"admitting_core_source": v.AdmittingCoreSource, "issuer": v.Issuer, "reason": v.Reason, "recorded_at": v.RecordedAt,
		"cause_evidence_sha256": v.CauseEvidenceSHA256, "cause_evidence_bytes": v.CauseEvidenceBytes, "cause_evidence_is_authority": false,
		"original_failure_cause_claimed_by_core": false, "original_failure_preserved": true, "original_CREATE_installation_ACK_and_canaries_unchanged": true,
		"same_build_replacement_admitted_for_this_disposal_only": true, "unchanged_binding_and_current_compiled_approval_required": true,
		"other_disposals_still_checked": true, "provider_read_performed": false, "intent_or_fence_changed": false,
	}
}

func (s *Server) handleOpsFailedInstalledExternalCauseReplacement(w http.ResponseWriter, r *http.Request) {
	issuer, ok := s.originalDispositionIssuer(w, r)
	if !ok {
		return
	}
	request, err := decodeFailedInstalledExternalCauseReplacement(http.MaxBytesReader(w, r.Body, failedInstalledExternalCauseBodyLimit))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_external_cause_replacement_admission_request")
		return
	}
	request.Issuer = issuer
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	record, err := (repository.CapacityStore{DB: s.db}).AdmitFailedInstalledExternalCauseReplacement(ctx, request)
	if err != nil {
		writeJSONError(w, http.StatusConflict, "external_cause_replacement_not_admitted")
		return
	}
	writeJSON(w, http.StatusCreated, failedInstalledExternalCauseSummary(record))
}

func (s *Server) handleOpsFailedInstalledExternalCauseReplacementRead(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.originalDispositionIssuer(w, r); !ok {
		return
	}
	id := r.PathValue("preregistrationId")
	if !dispositionGrantID(id) {
		writeJSONError(w, http.StatusBadRequest, "only_original_preregistration_UUID_required")
		return
	}
	record, err := (repository.CapacityStore{DB: s.db}).ReadFailedInstalledExternalCauseAdmission(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "external_cause_replacement_admission_not_found")
		return
	}
	writeJSON(w, http.StatusOK, failedInstalledExternalCauseSummary(record))
}
