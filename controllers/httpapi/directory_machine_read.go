package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	safego "github.com/dakasa-yggdrasil/yggdrasil-core/internal/goroutine"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/httperr"
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
	configErr error
}

// directoryMachineClaimFor decides whether the request must be served by the
// directory machine path. The dedicated header always marks the request as a
// machine attempt, even when its value matches nothing, so a malformed or
// rotated-out directory credential is refused here and never evaluated as a
// console session. A plain bearer marks the request only when its digest
// matches a configured directory principal; an unknown bearer keeps today's
// console behavior for OIDC JWTs and opaque session tokens.
func directoryMachineClaimFor(r *http.Request) directoryMachineClaim {
	header := strings.TrimSpace(r.Header.Get(directoryMachineTokenHeader))
	bearer := bearerToken(r.Header.Get("Authorization"))

	principals, err := directoryMachinePrincipalsFromEnv()
	if err != nil {
		// The inventory is unusable. A request that named itself through the
		// dedicated header is refused; a bare bearer cannot be attributed to
		// this path without digests, so it continues to the console gate.
		return directoryMachineClaim{claimed: header != "", configErr: err}
	}
	if header != "" {
		return directoryMachineClaim{claimed: true, principal: directoryMachinePrincipalByCredential(header, principals)}
	}
	if bearer != "" {
		if principal := directoryMachinePrincipalByCredential(bearer, principals); principal != nil {
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

// muxCleanPath mirrors the canonical form net/http's ServeMux computes before
// dispatch: path.Clean plus the trailing slash the mux preserves. A request
// whose escaped path differs from this form never matches a registered
// pattern; the mux answers it with a redirect to the clean spelling instead.
func muxCleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	cleaned := path.Clean(p)
	if p[len(p)-1] == '/' && cleaned != "/" {
		cleaned += "/"
	}
	return cleaned
}

// nonCanonicalRequestPath reports whether the mux would redirect this request
// to a cleaned spelling of its path: a doubled slash, a dot segment, or a
// missing leading slash. Such a spelling can escape the console gate prefixes
// while its clean form is gated, so the gate checks it before its public
// pass-through: a directory machine attempt on it is a path variant and fails
// closed instead of receiving the redirect.
func nonCanonicalRequestPath(r *http.Request) bool {
	escaped := r.URL.EscapedPath()
	return muxCleanPath(escaped) != escaped
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
func (s *Server) serveDirectoryMachineRequest(w http.ResponseWriter, r *http.Request, claim directoryMachineClaim) {
	if claim.configErr != nil {
		if s.logger != nil {
			s.logger.Error("directory machine principals configuration is invalid; refusing machine directory request",
				zap.String("method", r.Method), zap.String("path", r.URL.Path), zap.Error(claim.configErr))
		}
		writeProblemJSON(w, http.StatusUnauthorized, httperr.CodeAuthUnauthenticated, "directory credential is missing, unknown, expired, or not active")
		return
	}
	principal := claim.principal
	if usable, reason := directoryMachinePrincipalUsable(principal, time.Now().UTC()); !usable {
		if principal != nil {
			s.recordDirectoryMachineAudit(r, principal, "", "", "denied", reason)
		}
		writeProblemJSON(w, http.StatusUnauthorized, httperr.CodeAuthUnauthenticated, "directory credential is missing, unknown, expired, or not active")
		return
	}

	route, collaboratorID := directoryMachineRouteFor(r)
	if route == directoryRouteNone {
		s.recordDirectoryMachineAudit(r, principal, "", "", "denied", "route_not_allowed")
		writeProblemJSON(w, http.StatusForbidden, httperr.CodePermissionDenied, "directory principal is not authorized for this route")
		return
	}
	capability := route.capability()
	if !directoryMachinePrincipalHasCapability(principal, capability) {
		s.recordDirectoryMachineAudit(r, principal, capability, collaboratorID, "denied", "capability_missing")
		writeProblemJSON(w, http.StatusForbidden, httperr.CodePermissionDenied, "directory principal lacks the "+capability+" capability")
		return
	}
	if route == directoryRouteEffectiveActions &&
		!directoryMachinePrincipalAllowsTartaroInstance(principal, tartaroInstanceNamespace, tartaroInstanceName) {
		s.recordDirectoryMachineAudit(r, principal, capability, collaboratorID, "denied", "tartaro_instance_not_allowed")
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
		s.recordDirectoryMachineAudit(r, principal, directoryCapabilityLookupEmail, "", "denied", "invalid_query")
		writeProblemJSON(w, http.StatusBadRequest, httperr.CodeInvalidInput, err.Error())
		return
	}
	if s.db == nil {
		s.recordDirectoryMachineAudit(r, principal, directoryCapabilityLookupEmail, "", "error", "database_unavailable")
		writeProblemJSON(w, http.StatusInternalServerError, httperr.CodeInternal, "directory is unavailable")
		return
	}
	collaborators, err := repository.ListActiveCollaboratorsByPrimaryEmail(r.Context(), s.db, email, directoryLookupAmbiguityProbe)
	if err != nil {
		s.recordDirectoryMachineAudit(r, principal, directoryCapabilityLookupEmail, "", "error", "lookup_failed")
		writeMappedError(w, err)
		return
	}
	if len(collaborators) > 1 {
		// Two active rows for one address violates the unique index. Do not
		// choose; the caller must not act on an ambiguous identity.
		s.recordDirectoryMachineAudit(r, principal, directoryCapabilityLookupEmail, "", "error", "ambiguous_identity")
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
	s.recordDirectoryMachineAudit(r, principal, directoryCapabilityLookupEmail, targetID, outcome, "")
	writeJSON(w, http.StatusOK, response)
}

// loadActiveDirectoryCollaborator resolves the canonical identifier and
// applies the active-record policy: a collaborator that is not active is
// indistinguishable from an absent one for a machine caller.
func (s *Server) loadActiveDirectoryCollaborator(ctx context.Context, collaboratorID string) (model.Collaborator, string, error) {
	if s.db == nil {
		return model.Collaborator{}, "database_unavailable", errors.New("directory is unavailable")
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
		s.recordDirectoryMachineAudit(r, principal, capability, collaboratorID, "not_found", reason)
		writeMappedError(w, repository.ErrCollaboratorNotFound)
	case "database_unavailable":
		s.recordDirectoryMachineAudit(r, principal, capability, collaboratorID, "error", reason)
		writeProblemJSON(w, http.StatusInternalServerError, httperr.CodeInternal, "directory is unavailable")
	default:
		s.recordDirectoryMachineAudit(r, principal, capability, collaboratorID, "error", reason)
		writeMappedError(w, err)
	}
}

func (s *Server) serveDirectoryCollaboratorGet(w http.ResponseWriter, r *http.Request, principal *directoryMachinePrincipal, collaboratorID string) {
	if r.URL.RawQuery != "" {
		s.recordDirectoryMachineAudit(r, principal, directoryCapabilityRead, collaboratorID, "denied", "invalid_query")
		writeProblemJSON(w, http.StatusBadRequest, httperr.CodeInvalidInput, "query parameters are not accepted on this route")
		return
	}
	collaborator, reason, err := s.loadActiveDirectoryCollaborator(r.Context(), collaboratorID)
	if err != nil {
		s.writeDirectoryLoadFailure(w, r, principal, directoryCapabilityRead, collaboratorID, reason, err)
		return
	}
	s.recordDirectoryMachineAudit(r, principal, directoryCapabilityRead, collaboratorID, "success", "")
	writeJSON(w, http.StatusOK, directoryCollaboratorResponse{Collaborator: projectDirectoryCollaborator(collaborator)})
}

func (s *Server) serveDirectoryEffectiveActions(w http.ResponseWriter, r *http.Request, principal *directoryMachinePrincipal, collaboratorID string) {
	if r.URL.RawQuery != "" {
		s.recordDirectoryMachineAudit(r, principal, directoryCapabilityEffectiveActions, collaboratorID, "denied", "invalid_query")
		writeProblemJSON(w, http.StatusBadRequest, httperr.CodeInvalidInput, "query parameters are not accepted on this route")
		return
	}
	collaborator, reason, err := s.loadActiveDirectoryCollaborator(r.Context(), collaboratorID)
	if err != nil {
		s.writeDirectoryLoadFailure(w, r, principal, directoryCapabilityEffectiveActions, collaboratorID, reason, err)
		return
	}
	effective, err := s.computeEffectiveTartaroActions(r.Context(), collaborator.ID)
	if err != nil {
		s.recordDirectoryMachineAudit(r, principal, directoryCapabilityEffectiveActions, collaboratorID, "error", "effective_actions_failed")
		writeMappedError(w, err)
		return
	}
	s.recordDirectoryMachineAudit(r, principal, directoryCapabilityEffectiveActions, collaboratorID, "success", "")
	writeJSON(w, http.StatusOK, directoryEffectiveActionsResponse{
		CollaboratorID:         collaborator.ID.String(),
		ComputedTartaroActions: effective.Computed,
	})
}

// recordDirectoryMachineAudit persists one audit row per machine outcome. The
// row carries the principal, rotation, capability, method, path, target
// collaborator id, outcome, and reason. It never carries the credential, the
// query string, or any email address: the lookup email lives only in the
// query, which is deliberately not recorded.
func (s *Server) recordDirectoryMachineAudit(r *http.Request, principal *directoryMachinePrincipal, capability, targetID, outcome, reason string) {
	if principal == nil {
		return
	}
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
	event := model.AuditEvent{
		Actor:        "service:" + principal.PrincipalID,
		Action:       directoryMachineAuditAction,
		ResourceKind: "collaborator",
		ResourceID:   targetID,
		Outcome:      outcome,
		TraceID:      r.Header.Get("traceparent"),
		Metadata:     metadata,
	}
	if s.directoryAuditSink != nil {
		s.directoryAuditSink(event)
		return
	}
	if s.db == nil {
		return
	}
	safego.SafeGo("directory_machine_audit", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := repository.RecordAuditEvent(ctx, s.db, event); err != nil && s.logger != nil {
			s.logger.Warn("directory machine audit insert failed",
				zap.String("principal_id", principal.PrincipalID),
				zap.String("outcome", outcome),
				zap.Error(err))
		}
	})
}

// withDirectoryAuditSink replaces the durable audit writer with an in-process
// sink. Tests use it to assert audit content synchronously without a database.
func withDirectoryAuditSink(sink func(model.AuditEvent)) ServerOption {
	return func(s *Server) {
		s.directoryAuditSink = sink
	}
}
