package httpapi

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/contactphone"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const phoneProfileRequiredCode = "auth.phone_profile_required"

// This exact exemption is a profile-completion seam, not permission to read
// another collaborator or the console. Credential recovery keeps its existing
// public, token-bound handlers and is never made conditional on a legacy phone.
func phoneProfileExemptPath(path string) bool {
	return path == "/api/v1/me/contact/phone" || mfaEnrollmentExemptPath(path)
}

func (s *Server) allowPhoneProfile(w http.ResponseWriter, r *http.Request, collaborator model.Collaborator) bool {
	if !collaborator.PhoneProfileRequired || phoneProfileExemptPath(r.URL.Path) {
		return true
	}
	writeProblemJSON(w, http.StatusForbidden, phoneProfileRequiredCode, "Complete the declared phone contact before accessing this resource.")
	return false
}

// JWT/workflow human branches must re-read current state; token claims are not
// authority for completing or bypassing a provisional profile.
func (s *Server) allowPhoneProfileID(w http.ResponseWriter, r *http.Request, id string) bool {
	if s.db == nil {
		writeProblemJSON(w, http.StatusServiceUnavailable, "directory.unavailable", "Profile state is unavailable.")
		return false
	}
	c, err := repository.GetCollaborator(r.Context(), s.db, id)
	if err != nil {
		writeProblemJSON(w, http.StatusServiceUnavailable, "directory.unavailable", "Profile state is unavailable.")
		return false
	}
	return s.allowPhoneProfile(w, r, c)
}

func (s *Server) handleSelfPhoneGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, c, ok := s.resolveCurrentCollaborator(w, r)
	if !ok {
		return
	}
	if !c.PhoneProfileRequired {
		identity, err := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.db, c.ID)
		if err != nil || identity.MFAEnrolledAt == nil {
			writeProblemJSON(w, http.StatusForbidden, httperr.CodeAuthMFANotEnrolled, "MFA is required to read an existing phone contact.")
			return
		}
	}
	phone, err := repository.GetPhoneContact(r.Context(), s.db, s.envelope, c.ID)
	if err != nil {
		writePhoneError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, model.SelfPhoneContactResponse{Required: c.PhoneProfileRequired, PhoneContact: phone})
}

func (s *Server) handleSelfPhonePut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, c, ok := s.resolveCurrentCollaborator(w, r)
	if !ok {
		return
	}
	if !c.PhoneProfileRequired {
		identity, err := repository.GetAuthIdentityByCollaboratorID(r.Context(), s.db, c.ID)
		if err != nil || identity.MFAEnrolledAt == nil {
			writeProblemJSON(w, http.StatusForbidden, httperr.CodeAuthMFANotEnrolled, "MFA is required to change an existing phone contact.")
			return
		}
	}
	s.writePhoneDeclaration(w, r, c.ID, "collaborator:"+c.ID.String(), "self_profile")
}

func (s *Server) handleOperatorPhoneGet(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		writePhoneError(w, contactphone.ErrInvalid)
		return
	}
	claims, ok := claimsFromContext(r.Context())
	actorID, _ := claims["collaborator_id"].(string)
	actor, parseErr := uuid.Parse(actorID)
	if !ok || parseErr != nil || actor == uuid.Nil {
		writeProblemJSON(w, http.StatusUnauthorized, httperr.CodeAuthUnauthenticated, "A human identity is required.")
		return
	}
	// Resolve the exact grant and read the contact from one PostgreSQL
	// snapshot. A membership/grant change cannot combine old authority with
	// a contact introduced by a later committed revision.
	tx, err := s.db.BeginTx(r.Context(), &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		writePhoneError(w, repository.ErrPhoneUnavailable)
		return
	}
	defer func() { _ = tx.Rollback() }()
	granted, grantErr := repository.HasExactPhoneContactRead(r.Context(), tx, actor)
	if grantErr != nil {
		writePhoneError(w, grantErr)
		return
	}
	if !granted {
		if err := repository.RecordAuditEvent(r.Context(), s.db, model.AuditEvent{Actor: "collaborator:" + actor.String(), Action: "contact.phone_read", ResourceKind: "collaborator", ResourceID: id.String(), Outcome: "denied"}); err != nil {
			writePhoneError(w, repository.ErrPhoneUnavailable)
			return
		}
		writeProblemJSON(w, http.StatusForbidden, httperr.CodePermissionDenied, "An explicit phone-contact read grant is required.")
		return
	}
	phone, err := repository.GetPhoneContact(r.Context(), tx, s.envelope, id)
	if err != nil {
		writePhoneError(w, err)
		return
	}
	if tx.Commit() != nil {
		writePhoneError(w, repository.ErrPhoneUnavailable)
		return
	}
	// The audit writer must acknowledge before any contact leaves the server.
	if err := repository.RecordAuditEvent(r.Context(), s.db, model.AuditEvent{Actor: "collaborator:" + actor.String(), Action: "contact.phone_read", ResourceKind: "collaborator", ResourceID: id.String(), Outcome: "success"}); err != nil {
		writePhoneError(w, repository.ErrPhoneUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"phone_contact": phone})
}

func (s *Server) handleOperatorPhonePut(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil || id == uuid.Nil {
		writePhoneError(w, contactphone.ErrInvalid)
		return
	}
	s.writePhoneDeclaration(w, r, id, actorIDFromRequest(r), "operator_assertion")
}

func (s *Server) writePhoneDeclaration(w http.ResponseWriter, r *http.Request, id uuid.UUID, actor, source string) {
	w.Header().Set("Cache-Control", "no-store")
	var body struct {
		PhoneE164       string `json:"phone_e164"`
		ExpectedVersion *int64 `json:"expected_version,omitempty"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1025))
	dec.DisallowUnknownFields()
	var decodeErr error
	if source == "operator_assertion" {
		var operator struct {
			PhoneE164       string          `json:"phone_e164"`
			ExpectedVersion json.RawMessage `json:"expected_version,omitempty"`
		}
		decodeErr = dec.Decode(&operator)
		body.PhoneE164 = operator.PhoneE164
		if len(operator.ExpectedVersion) > 0 {
			var expected int64
			if bytes.Equal(bytes.TrimSpace(operator.ExpectedVersion), []byte("null")) {
				decodeErr = contactphone.ErrInvalid
			} else if err := json.Unmarshal(operator.ExpectedVersion, &expected); err != nil {
				decodeErr = contactphone.ErrInvalid
			} else {
				body.ExpectedVersion = &expected
			}
		}
	} else {
		// Self-profile writes keep their original contract. Even null for the
		// new operator-only field is an unknown field on this route.
		var self struct {
			PhoneE164 string `json:"phone_e164"`
		}
		decodeErr = dec.Decode(&self)
		body.PhoneE164 = self.PhoneE164
	}
	if decodeErr != nil || !errors.Is(dec.Decode(&struct{}{}), io.EOF) || contactphone.Validate(body.PhoneE164) != nil || body.ExpectedVersion != nil && *body.ExpectedVersion < 0 {
		writePhoneError(w, contactphone.ErrInvalid)
		return
	}
	if s.envelope == nil {
		writePhoneError(w, repository.ErrPhoneUnavailable)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writePhoneError(w, repository.ErrPhoneUnavailable)
		return
	}
	defer func() { _ = tx.Rollback() }()
	var phone model.PhoneContact
	if body.ExpectedVersion != nil {
		phone, err = repository.SetPhoneContactIfVersionTx(r.Context(), tx, s.envelope, id, body.PhoneE164, actor, *body.ExpectedVersion)
	} else {
		phone, err = repository.SetPhoneContactTx(r.Context(), tx, s.envelope, id, body.PhoneE164, actor, source)
	}
	if err != nil {
		writePhoneError(w, err)
		return
	}
	if tx.Commit() != nil {
		writePhoneError(w, repository.ErrPhoneUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, model.SelfPhoneContactResponse{Required: false, PhoneContact: &phone})
}

func writePhoneError(w http.ResponseWriter, err error) {
	if errors.Is(err, repository.ErrPhoneVersionConflict) {
		writeProblemJSON(w, http.StatusConflict, "contact.version_conflict", "A contact declaration already exists or changed; review before updating it.")
		return
	}
	if errors.Is(err, contactphone.ErrInvalid) || errors.Is(err, repository.ErrPhoneRequired) {
		writeProblemJSON(w, http.StatusUnprocessableEntity, httperr.CodeInvalidInput, "Supply a canonical international phone contact in phone_e164.")
		return
	}
	writeProblemJSON(w, http.StatusServiceUnavailable, "contact.unavailable", "Phone contact is unavailable.")
}
