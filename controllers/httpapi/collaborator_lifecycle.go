package httpapi

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// validOffboardReasons is the canonical set accepted by /offboard.
var validOffboardReasons = map[string]struct{}{
	"voluntary":    {},
	"involuntary":  {},
	"contract-end": {},
	"deceased":     {},
}

// validAbsenceTypes is the set accepted by /absence/start.
var validAbsenceTypes = map[string]struct{}{
	"vacation":         {},
	"leave-medical":    {},
	"leave-parental":   {},
	"leave-sabbatical": {},
}

// ----- Status-changing handlers (offboard/suspend/unsuspend/re-onboard) -----

type offboardRequest struct {
	Reason              string `json:"reason"`
	EndDate             string `json:"end_date,omitempty"`
	VoluntaryNoticeDays int    `json:"voluntary_notice_days,omitempty"`
}

func (s *Server) handleCollaboratorOffboard(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	var req offboardRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if _, ok := validOffboardReasons[strings.TrimSpace(req.Reason)]; !ok {
		writeMappedError(w, fmt.Errorf("invalid offboard reason: %q (allowed: voluntary, involuntary, contract-end, deceased)", req.Reason))
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	st := "offboarded"
	collab, err := repository.UpdateCollaboratorTx(r.Context(), tx, model.UpdateCollaboratorRequest{ID: id, Status: &st})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	lifecyclePayload := map[string]any{"reason": strings.TrimSpace(req.Reason)}
	if d := strings.TrimSpace(req.EndDate); d != "" {
		lifecyclePayload["end_date"] = d
	}
	if req.VoluntaryNoticeDays > 0 {
		lifecyclePayload["voluntary_notice_days"] = req.VoluntaryNoticeDays
	}
	if err := appendLifecycleEventTx(r, tx, collab.ID, model.LifecycleEventOffboarded, lifecyclePayload); err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit collaborator.offboarded canon event in the SAME transaction as the
	// state mutation. Spec §lifecycle-reactor requires atomic state+emit so a
	// crash between them cannot leave a collaborator whose canon event was
	// silently dropped.
	emitPayload := map[string]any{
		"collaborator_id": collab.ID.String(),
		"reason":          strings.TrimSpace(req.Reason),
	}
	if collab.PrimaryEmail != "" {
		emitPayload["primary_email"] = collab.PrimaryEmail
	}
	if d := strings.TrimSpace(req.EndDate); d != "" {
		emitPayload["end_date"] = d
	}
	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeCollaboratorOffboarded,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       emitPayload,
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit collaborator.offboarded: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit collaborator.offboarded: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

type reasonOnlyRequest struct {
	Reason string `json:"reason,omitempty"`
}

func (s *Server) handleCollaboratorSuspend(w http.ResponseWriter, r *http.Request) {
	s.statusChangeHandler(w, r, "suspended", model.LifecycleEventSuspended)
}

func (s *Server) handleCollaboratorUnsuspend(w http.ResponseWriter, r *http.Request) {
	s.statusChangeHandler(w, r, "active", model.LifecycleEventUnsuspended)
}

func (s *Server) statusChangeHandler(w http.ResponseWriter, r *http.Request, newStatus, eventType string) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	var req reasonOnlyRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	collab, err := repository.UpdateCollaborator(r.Context(), s.db, model.UpdateCollaboratorRequest{ID: id, Status: &newStatus})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	payload := map[string]any{}
	if reason := strings.TrimSpace(req.Reason); reason != "" {
		payload["reason"] = reason
	}
	if err := appendLifecycleEvent(r, s.db, collab.ID, eventType, payload); err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

type reOnboardRequest struct {
	NewStartDate string `json:"new_start_date,omitempty"`
	Role         string `json:"role,omitempty"`
}

func (s *Server) handleCollaboratorReOnboard(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	var req reOnboardRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	st := "pending_start"
	collab, err := repository.UpdateCollaboratorTx(r.Context(), tx, model.UpdateCollaboratorRequest{ID: id, Status: &st})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	lifecyclePayload := map[string]any{}
	if d := strings.TrimSpace(req.NewStartDate); d != "" {
		lifecyclePayload["new_start_date"] = d
	}
	if rl := strings.TrimSpace(req.Role); rl != "" {
		lifecyclePayload["role"] = rl
	}
	if err := appendLifecycleEventTx(r, tx, collab.ID, model.LifecycleEventReOnboarded, lifecyclePayload); err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit collaborator.re_onboarded canon event in the same transaction.
	// Note: previous_offboarded_at is not stored on the collaborator row; omitted.
	emitPayload := map[string]any{
		"collaborator_id": collab.ID.String(),
	}
	if collab.PrimaryEmail != "" {
		emitPayload["primary_email"] = collab.PrimaryEmail
	}
	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeCollaboratorReOnboarded,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       emitPayload,
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit collaborator.re_onboarded: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit collaborator.re_onboarded: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

// ----- Field-changing handlers -----

type roleChangeRequest struct {
	NewRole string `json:"new_role"`
}

func (s *Server) handleCollaboratorRoleChange(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	var req roleChangeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	newRole := strings.TrimSpace(req.NewRole)
	if newRole == "" {
		writeMappedError(w, fmt.Errorf("new_role is required"))
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	prev, err := repository.GetCollaboratorTx(r.Context(), tx, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	employment := prev.EmploymentData
	if employment == nil {
		employment = map[string]any{}
	}
	previous, _ := employment["role"].(string)
	employment["role"] = newRole
	collab, err := repository.UpdateCollaboratorTx(r.Context(), tx, model.UpdateCollaboratorRequest{
		ID:             id,
		EmploymentData: &employment,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}

	lifecyclePayload := map[string]any{"to": newRole}
	if previous != "" {
		lifecyclePayload["from"] = previous
	}
	if err := appendLifecycleEventTx(r, tx, collab.ID, model.LifecycleEventRoleChanged, lifecyclePayload); err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit collaborator.role_changed canon event in the same transaction.
	emitPayload := map[string]any{
		"collaborator_id": collab.ID.String(),
		"role_to":         newRole,
	}
	if collab.PrimaryEmail != "" {
		emitPayload["primary_email"] = collab.PrimaryEmail
	}
	if previous != "" {
		emitPayload["role_from"] = previous
	}
	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeCollaboratorRoleChanged,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       emitPayload,
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit collaborator.role_changed: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit collaborator.role_changed: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

type teamMembershipRequest struct {
	TeamID     string `json:"team_id"`
	RoleInTeam string `json:"role_in_team,omitempty"`
}

func (s *Server) handleCollaboratorTeamAdd(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	var req teamMembershipRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if strings.TrimSpace(req.TeamID) == "" {
		writeMappedError(w, fmt.Errorf("team_id is required"))
		return
	}
	collab, err := repository.GetCollaborator(r.Context(), s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	active := true
	roleInTeam := strings.TrimSpace(req.RoleInTeam)
	if roleInTeam == "" {
		roleInTeam = "member"
	}
	if _, err := repository.UpsertTeamMembership(r.Context(), s.db, model.UpsertTeamMembershipRequest{
		TeamID:         strings.TrimSpace(req.TeamID),
		CollaboratorID: collab.ID.String(),
		Role:           roleInTeam,
		Active:         &active,
		Source:         "lifecycle",
	}); err != nil {
		writeMappedError(w, err)
		return
	}
	payload := map[string]any{"team_id": req.TeamID, "role_in_team": roleInTeam}
	if err := appendLifecycleEvent(r, s.db, collab.ID, model.LifecycleEventTeamJoined, payload); err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

func (s *Server) handleCollaboratorTeamRemove(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	var req teamMembershipRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	if strings.TrimSpace(req.TeamID) == "" {
		writeMappedError(w, fmt.Errorf("team_id is required"))
		return
	}
	collab, err := repository.GetCollaborator(r.Context(), s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	inactive := false
	if _, err := repository.UpsertTeamMembership(r.Context(), s.db, model.UpsertTeamMembershipRequest{
		TeamID:         strings.TrimSpace(req.TeamID),
		CollaboratorID: collab.ID.String(),
		Active:         &inactive,
		Source:         "lifecycle",
	}); err != nil {
		writeMappedError(w, err)
		return
	}
	if err := appendLifecycleEvent(r, s.db, collab.ID, model.LifecycleEventTeamLeft, map[string]any{"team_id": req.TeamID}); err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

type attributeSetRequest struct {
	Key       string `json:"key"`
	Value     any    `json:"value"`
	ValueType string `json:"value_type,omitempty"`
}

func (s *Server) handleCollaboratorAttributeSet(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	var req attributeSetRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		writeMappedError(w, fmt.Errorf("key is required"))
		return
	}
	prev, err := repository.GetCollaborator(r.Context(), s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	traits := prev.Traits
	if traits == nil {
		traits = map[string]any{}
	}
	previousValue := traits[key]
	traits[key] = req.Value
	collab, err := repository.UpdateCollaborator(r.Context(), s.db, model.UpdateCollaboratorRequest{
		ID:     id,
		Traits: &traits,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	payload := map[string]any{"key": key, "value": req.Value}
	if req.ValueType != "" {
		payload["value_type"] = req.ValueType
	}
	if previousValue != nil {
		payload["previous_value"] = previousValue
	}
	if err := appendLifecycleEvent(r, s.db, collab.ID, model.LifecycleEventAttributeSet, payload); err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

type managerChangeRequest struct {
	NewManagerID string `json:"new_manager_id"`
}

func (s *Server) handleCollaboratorManagerChange(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	var req managerChangeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	prev, err := repository.GetCollaborator(r.Context(), s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	mgrID := strings.TrimSpace(req.NewManagerID)
	collab, err := repository.UpdateCollaborator(r.Context(), s.db, model.UpdateCollaboratorRequest{
		ID:        id,
		ManagerID: &mgrID,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	payload := map[string]any{}
	if prev.ManagerID != nil {
		payload["from_manager_id"] = prev.ManagerID.String()
	}
	if mgrID != "" {
		payload["to_manager_id"] = mgrID
	}
	if err := appendLifecycleEvent(r, s.db, collab.ID, model.LifecycleEventManagerChanged, payload); err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

// ----- Absence handlers -----

type absenceStartRequest struct {
	Type         string `json:"type"`
	From         string `json:"from"`
	To           string `json:"to"`
	DurationDays int    `json:"duration_days,omitempty"`
}

func (s *Server) handleCollaboratorAbsenceStart(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	var req absenceStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}
	absType := strings.TrimSpace(req.Type)
	if _, ok := validAbsenceTypes[absType]; !ok {
		writeMappedError(w, fmt.Errorf("invalid absence type: %q (allowed: vacation, leave-medical, leave-parental, leave-sabbatical)", req.Type))
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	collab, err := repository.GetCollaboratorTx(r.Context(), tx, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	// Long leaves transition active → on_leave. Vacation stays on active.
	if absType != "vacation" && collab.Status == "active" {
		st := "on_leave"
		updated, err := repository.UpdateCollaboratorTx(r.Context(), tx, model.UpdateCollaboratorRequest{ID: id, Status: &st})
		if err != nil {
			writeMappedError(w, err)
			return
		}
		collab = updated
	}

	lifecyclePayload := map[string]any{"type": absType}
	if d := strings.TrimSpace(req.From); d != "" {
		lifecyclePayload["from"] = d
	}
	if d := strings.TrimSpace(req.To); d != "" {
		lifecyclePayload["to"] = d
	}
	if req.DurationDays > 0 {
		lifecyclePayload["duration_days"] = req.DurationDays
	}
	if err := appendLifecycleEventTx(r, tx, collab.ID, model.LifecycleEventAbsenceStarted, lifecyclePayload); err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit collaborator.absence_started canon event in the same transaction.
	emitPayload := map[string]any{
		"collaborator_id": collab.ID.String(),
		"type":            absType,
	}
	if collab.PrimaryEmail != "" {
		emitPayload["primary_email"] = collab.PrimaryEmail
	}
	if d := strings.TrimSpace(req.From); d != "" {
		emitPayload["from"] = d
	}
	if d := strings.TrimSpace(req.To); d != "" {
		emitPayload["to"] = d
	}
	if req.DurationDays > 0 {
		emitPayload["duration_days"] = req.DurationDays
	}
	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeCollaboratorAbsenceStarted,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       emitPayload,
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit collaborator.absence_started: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit collaborator.absence_started: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

type absenceEndRequest struct {
	AbsenceEventID string `json:"absence_event_id,omitempty"`
	ActualEnd      string `json:"actual_end,omitempty"`
}

func (s *Server) handleCollaboratorAbsenceEnd(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	var req absenceEndRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeMappedError(w, err)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeMappedError(w, fmt.Errorf("begin tx: %w", err))
		return
	}
	defer func() { _ = tx.Rollback() }()

	collab, err := repository.GetCollaboratorTx(r.Context(), tx, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	if collab.Status == "on_leave" {
		st := "active"
		updated, err := repository.UpdateCollaboratorTx(r.Context(), tx, model.UpdateCollaboratorRequest{ID: id, Status: &st})
		if err != nil {
			writeMappedError(w, err)
			return
		}
		collab = updated
	}

	lifecyclePayload := map[string]any{}
	if d := strings.TrimSpace(req.AbsenceEventID); d != "" {
		lifecyclePayload["absence_event_id"] = d
	}
	if d := strings.TrimSpace(req.ActualEnd); d != "" {
		lifecyclePayload["actual_end"] = d
	}
	if err := appendLifecycleEventTx(r, tx, collab.ID, model.LifecycleEventAbsenceEnded, lifecyclePayload); err != nil {
		writeMappedError(w, err)
		return
	}

	// Emit collaborator.absence_ended canon event in the same transaction.
	emitPayload := map[string]any{
		"collaborator_id": collab.ID.String(),
	}
	if collab.PrimaryEmail != "" {
		emitPayload["primary_email"] = collab.PrimaryEmail
	}
	if _, err := repository.EmitEvent(r.Context(), tx, model.EmitEventRequest{
		Type:          repository.EventTypeCollaboratorAbsenceEnded,
		SchemaVersion: "v1",
		AggregateType: "collaborator",
		AggregateID:   collab.ID.String(),
		Payload:       emitPayload,
	}); err != nil {
		writeMappedError(w, fmt.Errorf("emit collaborator.absence_ended: %w", err))
		return
	}

	if err := tx.Commit(); err != nil {
		writeMappedError(w, fmt.Errorf("commit collaborator.absence_ended: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"collaborator": collab})
}

// ----- Audit GETs -----

func (s *Server) handleCollaboratorLifecycleEvents(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	collab, err := repository.GetCollaborator(r.Context(), s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	q := r.URL.Query()
	limit := 100
	if l := strings.TrimSpace(q.Get("limit")); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	events, err := repository.ListLifecycleEventsByCollaborator(r.Context(), s.db, model.ListLifecycleEventsRequest{
		CollaboratorID: collab.ID,
		EventType:      strings.TrimSpace(q.Get("event_type")),
		Limit:          limit,
	})
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *Server) handleCollaboratorProviderState(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		writeMappedError(w, fmt.Errorf("collaborator id is required"))
		return
	}
	collab, err := repository.GetCollaborator(r.Context(), s.db, id)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	state, err := repository.ListProviderStateByCollaborator(r.Context(), s.db, collab.ID)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"provider_state": state})
}

// ----- helpers -----

func appendLifecycleEvent(r *http.Request, db *sql.DB, collabID uuid.UUID, eventType string, payload map[string]any) error {
	_, err := repository.AppendLifecycleEvent(r.Context(), db, model.AppendLifecycleEventRequest{
		CollaboratorID: collabID,
		EventType:      eventType,
		Payload:        payload,
		ActorType:      model.ActorTypeAPI,
		ActorID:        actorIDFromRequest(r),
	})
	return err
}

// appendLifecycleEventTx is the *sql.Tx variant of appendLifecycleEvent used by
// lifecycle handlers that mutate state and emit canon events atomically.
func appendLifecycleEventTx(r *http.Request, tx *sql.Tx, collabID uuid.UUID, eventType string, payload map[string]any) error {
	_, err := repository.AppendLifecycleEventTx(r.Context(), tx, model.AppendLifecycleEventRequest{
		CollaboratorID: collabID,
		EventType:      eventType,
		Payload:        payload,
		ActorType:      model.ActorTypeAPI,
		ActorID:        actorIDFromRequest(r),
	})
	return err
}

// actorIDFromRequest pulls the caller identifier from request headers.
// Phase 1 trusts X-Actor; auth middleware will populate it from session later.
func actorIDFromRequest(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Actor"))
}
