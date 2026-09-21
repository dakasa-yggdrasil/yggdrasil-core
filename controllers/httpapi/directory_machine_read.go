package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/metrics"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// directoryMachineAuditAction is the single audit action for every outcome of
// the directory machine-read path. The exercised capability, when the request
// got that far, is carried in metadata so operators can filter one action and
// still see which scope was used or refused.
const directoryMachineAuditAction = "directory.machine_read"

// directoryLookupAmbiguityProbe is the row bound used by the email lookup. The
// unique index on LOWER(primary_email) makes a second active row impossible;
// asking for two lets the handler detect a broken invariant and fail closed
// instead of silently picking one identity.
const directoryLookupAmbiguityProbe = 2

type directoryMachineRoute int

const (
	directoryRouteNone directoryMachineRoute = iota
	directoryRouteLookupEmail
	directoryRouteGet
	directoryRouteEffectiveActions
)

func (route directoryMachineRoute) capability() string {
	switch route {
	case directoryRouteLookupEmail:
		return directoryCapabilityLookupEmail
	case directoryRouteGet:
		return directoryCapabilityRead
	case directoryRouteEffectiveActions:
		return directoryCapabilityEffectiveActions
	default:
		return ""
	}
}

// directoryMachineClaim is the gate's view of one request: whether the caller
// presented itself as a directory machine principal, and which configured
// principal (in any lifecycle state) the credential digest matched.
type directoryMachineClaim struct {
	claimed   bool
	principal *directoryMachinePrincipal
}

// directoryMachineClaimFor decides whether the request must be served by the
// directory machine path. The dedicated header always marks the request as a
// machine attempt, even when its value matches nothing, so a malformed or
// rotated-out directory credential is refused here and never evaluated as a
// console session. A plain bearer marks the request only when its digest
// matches a configured directory principal; an unknown bearer keeps today's
// console behavior for OIDC JWTs and opaque session tokens.
//
// The credential is matched against s.directoryMachinePrincipals, the
// inventory New loaded and validated once at boot. The environment is never
// read on the request path, so a malformed inventory can only refuse the
// boot, never a request, and an inventory rotated in the environment of a
// running process takes effect only at the next boot. With no inventory the
// header matches nothing (refused as unknown) and a bearer is not a directory
// attempt.
func (s *Server) directoryMachineClaimFor(r *http.Request) directoryMachineClaim {
	if header := strings.TrimSpace(r.Header.Get(directoryMachineTokenHeader)); header != "" {
		return directoryMachineClaim{claimed: true, principal: directoryMachinePrincipalByCredential(header, s.directoryMachinePrincipals)}
	}
	if bearer := bearerToken(r.Header.Get("Authorization")); bearer != "" {
		if principal := directoryMachinePrincipalByCredential(bearer, s.directoryMachinePrincipals); principal != nil {
			return directoryMachineClaim{claimed: true, principal: principal}
		}
	}
	return directoryMachineClaim{}
}

// directoryMachineRouteFor classifies the request against the three exact
// read routes. Anything else, including other methods, trailing slashes,
// extra segments, non-canonical identifiers, and percent-encoded or
// traversal path variants, is not a directory route.
func directoryMachineRouteFor(r *http.Request) (directoryMachineRoute, string) {
	if r.Method != http.MethodGet {
		return directoryRouteNone, ""
	}
	path := r.URL.Path
	if r.URL.EscapedPath() != path {
		return directoryRouteNone, ""
	}
	segments := strings.Split(path, "/")
	if len(segments) < 4 || segments[0] != "" || segments[1] != "api" || segments[2] != "v1" || segments[3] != "collaborators" {
		return directoryRouteNone, ""
	}
	switch len(segments) {
	case 4:
		return directoryRouteLookupEmail, ""
	case 5:
		if canonicalCollaboratorUUID(segments[4]) {
			return directoryRouteGet, segments[4]
		}
	case 6:
		if canonicalCollaboratorUUID(segments[4]) && segments[5] == "effective-tartaro-actions" {
			return directoryRouteEffectiveActions, segments[4]
		}
	}
	return directoryRouteNone, ""
}

// canonicalCollaboratorUUID accepts only the lowercase hyphenated form so a
// braced, URN, uppercase, or otherwise re-encoded identifier is refused.
func canonicalCollaboratorUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed == uuid.Nil {
		return false
	}
	return parsed.String() == value
}

// directoryLookupEmailPattern is intentionally narrower than RFC 5322: one
// local part of unreserved characters, one domain with at least one dot, no
// whitespace, comments, display names, or SQL/glob wildcard characters.
var directoryLookupEmailPattern = regexp.MustCompile(`^[A-Za-z0-9._+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$`)

func validDirectoryLookupEmail(value string) bool {
	if value == "" || len(value) > 254 || value != strings.TrimSpace(value) {
		return false
	}
	at := strings.IndexByte(value, '@')
	if at <= 0 || at > 64 {
		return false
	}
	return directoryLookupEmailPattern.MatchString(value)
}

// parseDirectoryLookupQuery enforces the exact lookup contract: q is one
// exact email, status is exactly active, limit is optional and bounded, and
// no other query mode is accepted.
func parseDirectoryLookupQuery(rawQuery string) (string, error) {
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", errors.New("query string is malformed")
	}
	for key, items := range values {
		switch key {
		case "q", "status", "limit":
			if len(items) != 1 {
				return "", fmt.Errorf("query parameter %s must appear exactly once", key)
			}
		default:
			return "", fmt.Errorf("query parameter %s is not accepted on the directory lookup", key)
		}
	}
	q, ok := values["q"]
	if !ok {
		return "", errors.New("query parameter q is required and must be one exact email address")
	}
	if !validDirectoryLookupEmail(q[0]) {
		return "", errors.New("query parameter q must be one exact email address")
	}
	status, ok := values["status"]
	if !ok || status[0] != "active" {
		return "", errors.New("query parameter status must be exactly active")
	}
	if limit, ok := values["limit"]; ok {
		n, convErr := strconv.Atoi(limit[0])
		if convErr != nil || n < 1 || n > 100 || strconv.Itoa(n) != limit[0] {
			return "", errors.New("query parameter limit must be an integer between 1 and 100")
		}
	}
	return q[0], nil
}

// Minimal projections. These are deliberately distinct from model.Collaborator
// so a machine caller never receives personal, employment, provider, trait, or
// metadata fields even if the full view grows.
type directoryCollaboratorProjection struct {
	ID           string `json:"id"`
	PrimaryEmail string `json:"primary_email"`
	DisplayName  string `json:"display_name"`
	Status       string `json:"status"`
}

type directoryLookupResponse struct {
	Collaborators []directoryCollaboratorProjection `json:"collaborators"`
}

type directoryCollaboratorResponse struct {
	Collaborator directoryCollaboratorProjection `json:"collaborator"`
}

type directoryEffectiveActionsResponse struct {
	CollaboratorID         string   `json:"collaborator_id"`
	ComputedTartaroActions []string `json:"computed_tartaro_actions"`
}

func projectDirectoryCollaborator(collaborator model.Collaborator) directoryCollaboratorProjection {
	return directoryCollaboratorProjection{
		ID:           collaborator.ID.String(),
		PrimaryEmail: collaborator.PrimaryEmail,
		DisplayName:  collaborator.DisplayName,
		Status:       collaborator.Status,
	}
}

// serveDirectoryMachineRequest is the whole directory machine path. It never
// delegates to the console handlers, never attaches collaborator claims, and
// answers every failure itself, so a directory principal cannot be treated as
// a human collaborator by any downstream middleware or handler.
//
// Every outcome that can be attributed to a configured principal is audited
// before it is answered: auditDirectoryMachineOutcome writes the row
// synchronously and, when the row cannot be written, answers 500 itself so
// no data and no verdict leave without their trail.
func (s *Server) serveDirectoryMachineRequest(w http.ResponseWriter, r *http.Request, claim directoryMachineClaim) {
	principal := claim.principal
	if usable, reason := directoryMachinePrincipalUsable(principal, time.Now().UTC()); !usable {
		if !s.auditDirectoryMachineOutcome(w, r, principal, "", "", "denied", reason) {
			return
		}
		writeProblemJSON(w, http.StatusUnauthorized, httperr.CodeAuthUnauthenticated, "directory credential is missing, unknown, expired, or not active")
		return
	}

	route, collaboratorID := directoryMachineRouteFor(r)
	if route == directoryRouteNone {
		if !s.auditDirectoryMachineOutcome(w, r, principal, "", "", "denied", "route_not_allowed") {
			return
		}
		writeProblemJSON(w, http.StatusForbidden, httperr.CodePermissionDenied, "directory principal is not authorized for this route")
		return
	}
	capability := route.capability()
	if !directoryMachinePrincipalHasCapability(principal, capability) {
		if !s.auditDirectoryMachineOutcome(w, r, principal, capability, collaboratorID, "denied", "capability_missing") {
			return
		}
		writeProblemJSON(w, http.StatusForbidden, httperr.CodePermissionDenied, "directory principal lacks the "+capability+" capability")
		return
	}
	if route == directoryRouteEffectiveActions &&
		!directoryMachinePrincipalAllowsTartaroInstance(principal, tartaroInstanceNamespace, tartaroInstanceName) {
		if !s.auditDirectoryMachineOutcome(w, r, principal, capability, collaboratorID, "denied", "tartaro_instance_not_allowed") {
			return
		}
		writeProblemJSON(w, http.StatusForbidden, httperr.CodePermissionDenied, "directory principal is not allowed on the configured Tartaro instance")
		return
	}

	switch route {
	case directoryRouteLookupEmail:
		s.serveDirectoryLookupEmail(w, r, principal)
	case directoryRouteGet:
		s.serveDirectoryCollaboratorGet(w, r, principal, collaboratorID)
	case directoryRouteEffectiveActions:
		s.serveDirectoryEffectiveActions(w, r, principal, collaboratorID)
	default:
		writeProblemJSON(w, http.StatusForbidden, httperr.CodePermissionDenied, "directory principal is not authorized for this route")
	}
}

func (s *Server) serveDirectoryLookupEmail(w http.ResponseWriter, r *http.Request, principal *directoryMachinePrincipal) {
	email, err := parseDirectoryLookupQuery(r.URL.RawQuery)
	if err != nil {
		if !s.auditDirectoryMachineOutcome(w, r, principal, directoryCapabilityLookupEmail, "", "denied", "invalid_query") {
			return
		}
		writeProblemJSON(w, http.StatusBadRequest, httperr.CodeInvalidInput, err.Error())
		return
	}
	if s.db == nil {
		s.writeDirectoryRepositoryFailure(w, r, principal, directoryCapabilityLookupEmail, "", "database_unavailable", errors.New("directory database is not configured"))
		return
	}
	collaborators, err := repository.ListActiveCollaboratorsByPrimaryEmail(r.Context(), s.db, email, directoryLookupAmbiguityProbe)
	if err != nil {
		s.writeDirectoryRepositoryFailure(w, r, principal, directoryCapabilityLookupEmail, "", "lookup_failed", err)
		return
	}
	if len(collaborators) > 1 {
		// Two active rows for one address violates the unique index. Do not
		// choose; the caller must not act on an ambiguous identity.
		if !s.auditDirectoryMachineOutcome(w, r, principal, directoryCapabilityLookupEmail, "", "error", "ambiguous_identity") {
			return
		}
		writeProblemJSON(w, http.StatusInternalServerError, httperr.CodeInternal, "directory identity is ambiguous")
		return
	}
	response := directoryLookupResponse{Collaborators: []directoryCollaboratorProjection{}}
	targetID := ""
	outcome := "not_found"
	for _, collaborator := range collaborators {
		response.Collaborators = append(response.Collaborators, projectDirectoryCollaborator(collaborator))
		targetID = collaborator.ID.String()
		outcome = "success"
	}
	if !s.auditDirectoryMachineOutcome(w, r, principal, directoryCapabilityLookupEmail, targetID, outcome, "") {
		return
	}
	writeJSON(w, http.StatusOK, response)
}

// loadActiveDirectoryCollaborator resolves the canonical identifier and
// applies the active-record policy: a collaborator that is not active is
// indistinguishable from an absent one for a machine caller.
func (s *Server) loadActiveDirectoryCollaborator(ctx context.Context, collaboratorID string) (model.Collaborator, string, error) {
	if s.db == nil {
		return model.Collaborator{}, "database_unavailable", errors.New("directory database is not configured")
	}
	collaborator, err := repository.GetCollaborator(ctx, s.db, collaboratorID)
	if err != nil {
		if errors.Is(err, repository.ErrCollaboratorNotFound) {
			return model.Collaborator{}, "not_found", err
		}
		return model.Collaborator{}, "lookup_failed", err
	}
	if collaborator.Status != "active" {
		return model.Collaborator{}, "inactive", repository.ErrCollaboratorNotFound
	}
	return collaborator, "", nil
}

func (s *Server) writeDirectoryLoadFailure(w http.ResponseWriter, r *http.Request, principal *directoryMachinePrincipal, capability, collaboratorID, reason string, err error) {
	switch reason {
	case "not_found", "inactive":
		if !s.auditDirectoryMachineOutcome(w, r, principal, capability, collaboratorID, "not_found", reason) {
			return
		}
		writeMappedError(w, repository.ErrCollaboratorNotFound)
	default:
		s.writeDirectoryRepositoryFailure(w, r, principal, capability, collaboratorID, reason, err)
	}
}

// writeDirectoryRepositoryFailure answers every repository or database
// failure on the machine path with the same fixed 500 body. The driver text
// is never sent to the principal and never chooses the status: the generic
// writeMappedError maps message fragments such as "invalid" to 400 and echoes
// the message, which would leak internals to a least-privilege caller and
// misreport a failed read as a contract violation. The detail goes to the log
// and the fixed reason to the audit row.
func (s *Server) writeDirectoryRepositoryFailure(w http.ResponseWriter, r *http.Request, principal *directoryMachinePrincipal, capability, collaboratorID, reason string, err error) {
	if s.logger != nil {
		s.logger.Error("directory machine read failed",
			zap.String("principal_id", principal.PrincipalID),
			zap.String("capability", capability),
			zap.String("collaborator_id", collaboratorID),
			zap.String("reason", reason),
			zap.Error(err))
	}
	if !s.auditDirectoryMachineOutcome(w, r, principal, capability, collaboratorID, "error", reason) {
		return
	}
	writeProblemJSON(w, http.StatusInternalServerError, httperr.CodeInternal, "directory is unavailable")
}

func (s *Server) serveDirectoryCollaboratorGet(w http.ResponseWriter, r *http.Request, principal *directoryMachinePrincipal, collaboratorID string) {
	if r.URL.RawQuery != "" {
		if !s.auditDirectoryMachineOutcome(w, r, principal, directoryCapabilityRead, collaboratorID, "denied", "invalid_query") {
			return
		}
		writeProblemJSON(w, http.StatusBadRequest, httperr.CodeInvalidInput, "query parameters are not accepted on this route")
		return
	}
	collaborator, reason, err := s.loadActiveDirectoryCollaborator(r.Context(), collaboratorID)
	if err != nil {
		s.writeDirectoryLoadFailure(w, r, principal, directoryCapabilityRead, collaboratorID, reason, err)
		return
	}
	if !s.auditDirectoryMachineOutcome(w, r, principal, directoryCapabilityRead, collaboratorID, "success", "") {
		return
	}
	writeJSON(w, http.StatusOK, directoryCollaboratorResponse{Collaborator: projectDirectoryCollaborator(collaborator)})
}

func (s *Server) serveDirectoryEffectiveActions(w http.ResponseWriter, r *http.Request, principal *directoryMachinePrincipal, collaboratorID string) {
	if r.URL.RawQuery != "" {
		if !s.auditDirectoryMachineOutcome(w, r, principal, directoryCapabilityEffectiveActions, collaboratorID, "denied", "invalid_query") {
			return
		}
		writeProblemJSON(w, http.StatusBadRequest, httperr.CodeInvalidInput, "query parameters are not accepted on this route")
		return
	}
	collaborator, reason, err := s.loadActiveDirectoryCollaborator(r.Context(), collaboratorID)
	if err != nil {
		s.writeDirectoryLoadFailure(w, r, principal, directoryCapabilityEffectiveActions, collaboratorID, reason, err)
		return
	}
	effective, err := s.computeAuthorizedTartaroActions(r.Context(), collaborator.ID)
	if err != nil {
		s.writeDirectoryRepositoryFailure(w, r, principal, directoryCapabilityEffectiveActions, collaboratorID, "effective_actions_failed", err)
		return
	}
	if !s.auditDirectoryMachineOutcome(w, r, principal, directoryCapabilityEffectiveActions, collaboratorID, "success", "") {
		return
	}
	writeJSON(w, http.StatusOK, directoryEffectiveActionsResponse{
		CollaboratorID:         collaborator.ID.String(),
		ComputedTartaroActions: effective.Computed,
	})
}

// directoryAuditWriteTimeout bounds the synchronous audit insert. The write
// is detached from the request's cancellation so a caller that disconnects
// while its outcome is being recorded does not erase the row. A variable
// only so a test can shorten it to prove the timeout classification.
var directoryAuditWriteTimeout = 5 * time.Second

// directoryMachineAuditEvent builds the audit row for one machine outcome. It
// carries the principal, rotation, capability, method, path, target
// collaborator id, outcome, and reason. It never carries the credential, the
// query string, or any email address: the lookup email lives only in the
// query, which is deliberately not recorded. The trace reference is taken
// from a valid W3C traceparent only (requestTraceIDs, shared by every audit
// writer).
func directoryMachineAuditEvent(r *http.Request, principal *directoryMachinePrincipal, capability, targetID, outcome, reason string) model.AuditEvent {
	metadata := map[string]any{
		"principal_id": principal.PrincipalID,
		"rotation_id":  principal.RotationID,
		"method":       r.Method,
		"path":         r.URL.Path,
	}
	if capability != "" {
		metadata["capability"] = capability
	}
	if reason != "" {
		metadata["reason"] = reason
	}
	traceID, spanID := requestTraceIDs(r)
	return model.AuditEvent{
		Actor:        directoryAuditActorPrefix + principal.PrincipalID,
		Action:       directoryMachineAuditAction,
		ResourceKind: "collaborator",
		ResourceID:   targetID,
		Outcome:      outcome,
		TraceID:      traceID,
		SpanID:       spanID,
		Metadata:     metadata,
	}
}

// auditDirectoryMachineOutcome persists the audit row for one attributable
// outcome before that outcome is answered, and reports whether the caller may
// now write its response. The write is synchronous and fail-closed: when the
// row cannot be stored (no audit store, or the insert fails) the caller's
// verdict, including a 200 with data, is withheld and this function answers
// 500 itself, so the only directory responses that ever leave without their
// row are that 500. Each withheld outcome bumps
// yggdrasil_directory_audit_failures_total once, labeled with why the row
// could not be stored, and is logged with the outcome it withheld. A request
// with no matched principal has nothing to attribute and is not audited.
func (s *Server) auditDirectoryMachineOutcome(w http.ResponseWriter, r *http.Request, principal *directoryMachinePrincipal, capability, targetID, outcome, reason string) bool {
	if principal == nil {
		return true
	}
	event := directoryMachineAuditEvent(r, principal, capability, targetID, outcome, reason)
	var err error
	deadlineExpired := false
	switch {
	case s.directoryAuditSink != nil:
		err = s.directoryAuditSink(event)
	case s.db == nil:
		err = errDirectoryAuditStoreUnconfigured
	default:
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), directoryAuditWriteTimeout)
		defer cancel()
		err = repository.RecordAuditEvent(ctx, s.db, event)
		deadlineExpired = errors.Is(ctx.Err(), context.DeadlineExceeded)
	}
	if err == nil {
		return true
	}
	failure := directoryAuditFailureReason(err, deadlineExpired)
	metrics.IncDirectoryAuditFailure(failure)
	if s.logger != nil {
		s.logger.Error("directory machine audit insert failed; withholding the outcome",
			zap.String("principal_id", principal.PrincipalID),
			zap.String("capability", capability),
			zap.String("collaborator_id", targetID),
			zap.String("outcome", outcome),
			zap.String("reason", reason),
			zap.String("audit_failure", failure),
			zap.Error(err))
	}
	writeProblemJSON(w, http.StatusInternalServerError, httperr.CodeInternal, "directory audit is unavailable")
	return false
}

// errDirectoryAuditStoreUnconfigured is the failure of a server that has
// neither a database nor an in-process sink to store the row in.
var errDirectoryAuditStoreUnconfigured = errors.New("directory audit store is not configured")

// directoryAuditFailureReason classifies one failed audit write for
// yggdrasil_directory_audit_failures_total. A missing store is its own
// reason. The write is a timeout when the synchronous deadline fired,
// whether the driver reports the deadline itself or its own cancellation
// error after the deadline cancelled the statement (lib/pq answers
// "canceling statement due to user request", so the deadline is read from
// the write context, not only from the error). Every other error is an
// insert failure.
func directoryAuditFailureReason(err error, deadlineExpired bool) string {
	switch {
	case errors.Is(err, errDirectoryAuditStoreUnconfigured):
		return metrics.DirectoryAuditFailureStoreUnconfigured
	case deadlineExpired || errors.Is(err, context.DeadlineExceeded):
		return metrics.DirectoryAuditFailureInsertTimeout
	default:
		return metrics.DirectoryAuditFailureInsertFailed
	}
}

// withDirectoryAuditSink replaces the durable audit writer with an in-process
// sink. Tests use it to assert audit content synchronously without a database
// and to simulate a failing store; a sink error withholds the outcome exactly
// as a failed insert does.
func withDirectoryAuditSink(sink func(model.AuditEvent) error) ServerOption {
	return func(s *Server) {
		s.directoryAuditSink = sink
	}
}
