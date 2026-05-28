package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// Stable audit-event action codes for auth flows. Surfaces, compliance
// reports, and SIEM consumers MUST treat these as opaque identifiers —
// new outcomes get new codes; existing codes never change semantics.
//
// Naming follows the verb.outcome pattern so the action string is
// self-describing in a SIEM grep.
const (
	AuditAuthLoginSucceeded     = "auth.login.succeeded"
	AuditAuthLoginFailed        = "auth.login.failed"
	AuditAuthLoginRateLimited   = "auth.login.rate_limited"
	AuditAuthLoginAccountLocked = "auth.login.account_locked"
	AuditAuthLogout             = "auth.logout"
	AuditAuthMFAVerifySucceeded = "auth.mfa.verify.succeeded"
	AuditAuthMFAVerifyFailed    = "auth.mfa.verify.failed"
	AuditAuthMFAEnrolled        = "auth.mfa.enrolled"
	AuditAuthMFAUnenrolled      = "auth.mfa.unenrolled"
	AuditAuthSessionCreated     = "auth.session.created"
	AuditAuthSessionRevoked     = "auth.session.revoked"
	AuditAuthPasswordChanged    = "auth.password.changed"
	AuditAuthThirdPartyLogin    = "auth.third_party.login.succeeded"
)

// Standard outcomes the audit_events.outcome column accepts. The set is
// constrained so the surface dashboards can pivot reliably.
const (
	AuditOutcomeSuccess = "success"
	AuditOutcomeFailure = "failure"
	AuditOutcomeDenied  = "denied"
)

// recordAuthAudit emits an audit_events row tagged with the auth-flow
// context. Differs from recordAudit in that:
//   - actor is derived from the collaborator UUID (or "anonymous" when
//     pre-auth e.g. failed login by unknown identifier)
//   - resource_kind is fixed to "collaborator" so dashboards can pivot
//     on "every action affecting collaborator X"
//   - metadata is enriched with source IP + user agent + the supplied
//     extras
//
// Fire-and-forget: the underlying recordAudit goroutine swallows DB
// errors. Audit MUST NOT gate the request that triggered it.
//
// §13 INTEGRATION_CONTRACT: every state-mutating auth action emits one
// row here. Listed actions are the closed set of `auth.*` codes above.
func (s *Server) recordAuthAudit(
	r *http.Request,
	action string,
	collaboratorID string,
	outcome string,
	extras map[string]any,
) {
	actor := "anonymous"
	if collaboratorID != "" {
		actor = "user:" + collaboratorID
	}

	metadata := map[string]any{
		"source_ip":  clientIP(r),
		"user_agent": r.UserAgent(),
	}
	for k, v := range extras {
		metadata[k] = v
	}

	go func() {
		_ = s.recordAuthAuditSync(r, actor, action, collaboratorID, outcome, metadata)
	}()
}

// recordAuthAuditSync is the synchronous helper used both by the
// goroutine wrapper above AND by tests that need to assert the row
// landed. Tests SHOULD NOT poll the goroutine; they call this directly.
func (s *Server) recordAuthAuditSync(
	r *http.Request,
	actor, action, collaboratorID, outcome string,
	metadata map[string]any,
) error {
	if s.db == nil {
		return nil
	}
	// Late import avoidance — repository pkg already imported elsewhere.
	traceparent := ""
	if r != nil {
		traceparent = r.Header.Get("traceparent")
	}
	ev := model.AuditEvent{
		Actor:        actor,
		Action:       action,
		ResourceKind: "collaborator",
		ResourceID:   collaboratorID,
		Outcome:      outcome,
		TraceID:      traceparent,
		Metadata:     metadata,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := repository.RecordAuditEvent(ctx, s.db, ev); err != nil {
		if s.logger != nil {
			s.logger.Sugar().Warnw("audit insert failed",
				"action", action,
				"resource", "collaborator/"+collaboratorID,
				"error", err.Error(),
			)
		}
		return err
	}
	return nil
}

// recordAuthAuditCollaborator emits with a parsed UUID — convenience for
// the call sites that already have one.
func (s *Server) recordAuthAuditCollaborator(
	r *http.Request,
	action string,
	collaboratorID uuid.UUID,
	outcome string,
	extras map[string]any,
) {
	s.recordAuthAudit(r, action, collaboratorID.String(), outcome, extras)
}
