package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/collaboratorstate"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// collaboratorStatusChangeSource is the session_revocation.metadata source of
// a termination caused by a status change (ADR-0087).
const collaboratorStatusChangeSource = "collaborator_status_change"

// TerminateCollaboratorSessionsTx is the §13 INTEGRATION_CONTRACT fan-out for
// one collaborator, inside the caller's transaction: every console session
// and every OIDC refresh token is revoked, a global session_revocation row
// (no session jti) tells introspection and adapters, and
// collaborator.session.terminated is emitted with the idempotency key
// session.terminated.<revocation id>. It is the single termination primitive
// of credential replacement (setup re-access, self-service reset, MFA reset)
// and of status changes to a status that cannot sign in. The caller fires the
// back-channel logout after its commit.
func TerminateCollaboratorSessionsTx(ctx context.Context, tx *sql.Tx, collab model.Collaborator, reason string, metadata map[string]any) (model.SessionRevocation, error) {
	if _, err := RevokeAllAuthSessions(ctx, tx, collab.ID); err != nil {
		return model.SessionRevocation{}, err
	}
	rev, err := InsertSessionRevocation(ctx, nil, tx, InsertSessionRevocationRequest{
		CollaboratorID: collab.ID,
		SessionJTI:     nil,
		Reason:         reason,
		Metadata:       metadata,
	})
	if err != nil {
		return model.SessionRevocation{}, err
	}
	sessionPayload := map[string]any{
		"collaborator_id": collab.ID.String(),
		"reason":          reason,
		"revocation_id":   rev.ID.String(),
		"emitted_at":      time.Now().UTC().Format(time.RFC3339),
	}
	if collab.PrimaryEmail != "" {
		sessionPayload["primary_email"] = collab.PrimaryEmail
	}
	if _, err := EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:           EventTypeCollaboratorSessionTerminated,
		SchemaVersion:  "v1",
		AggregateType:  "collaborator",
		AggregateID:    collab.ID.String(),
		Payload:        sessionPayload,
		IdempotencyKey: "session.terminated." + rev.ID.String(),
	}); err != nil {
		return model.SessionRevocation{}, err
	}
	return rev, nil
}

// applyCollaboratorStatusSessionPolicyTx runs after the version-checked
// UPDATE of a collaborator, in the same transaction, so the session policy
// commits or rolls back with the status change (ADR-0087):
//
//   - status unchanged (same-status or non-status write): nothing;
//   - the new status cannot sign in: one termination, reason offboarded for
//     offboarded and admin_revoked otherwise, metadata {source, from_status,
//     to_status}. A move between two statuses that cannot sign in terminates
//     again; that is redundant but harmless and sweeps anything a raced login
//     left behind;
//   - the new status can sign in (reactivation): every console session and
//     refresh token left over is revoked, with no revocation row, event or
//     back-channel, so a reactivation never revives a session opened before
//     the collaborator stopped being allowed to sign in.
//
// A failure fails the write (fail closed).
func applyCollaboratorStatusSessionPolicyTx(ctx context.Context, tx *sql.Tx, previousStatus string, updated model.Collaborator) error {
	if previousStatus == updated.Status {
		return nil
	}
	if collaboratorstate.CanSignIn(updated.Status) {
		if _, err := RevokeAllAuthSessions(ctx, tx, updated.ID); err != nil {
			return fmt.Errorf("revoke leftover sessions on reactivation: %w", err)
		}
		return nil
	}
	reason := SessionRevocationReasonAdminRevoked
	if strings.ToLower(strings.TrimSpace(updated.Status)) == string(collaboratorstate.StatusOffboarded) {
		reason = SessionRevocationReasonOffboarded
	}
	if _, err := TerminateCollaboratorSessionsTx(ctx, tx, updated, reason, map[string]any{
		"source":      collaboratorStatusChangeSource,
		"from_status": previousStatus,
		"to_status":   updated.Status,
	}); err != nil {
		return fmt.Errorf("terminate sessions on status change: %w", err)
	}
	return nil
}
