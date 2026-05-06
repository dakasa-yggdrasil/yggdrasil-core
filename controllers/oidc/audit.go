package oidc

import (
	"context"
	"database/sql"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// recordOIDCAudit writes one row to the platform-wide audit_events table
// (migration 00017) tagged with resource_kind="oidc". Reuses the existing
// audit log instead of carrying a parallel oidc_audit_events surface.
//
// Best-effort: errors are swallowed because audit is observability, not
// business logic. A failed insert must never poison a token endpoint
// response or interfere with replay defense.
func recordOIDCAudit(
	ctx context.Context,
	db *sql.DB,
	action string,
	collaboratorID *uuid.UUID,
	clientID string,
	metadata map[string]any,
	outcome string,
) {
	actor := "service:oidc"
	if collaboratorID != nil {
		actor = "user:" + collaboratorID.String()
	}
	if metadata == nil {
		metadata = map[string]any{}
	}
	if clientID != "" {
		metadata["oidc_client_id"] = clientID
	}
	_ = repository.RecordAuditEvent(ctx, db, model.AuditEvent{
		Actor:        actor,
		Action:       action,
		ResourceKind: "oidc",
		ResourceID:   clientID,
		Outcome:      outcome,
		Metadata:     metadata,
	})
}

// tokenPrefix returns the first 8 characters of an opaque token (or the
// whole token if shorter). Used in audit metadata so operators can
// correlate events with logs without leaking the full secret.
func tokenPrefix(token string) string {
	const n = 8
	if len(token) <= n {
		return token
	}
	return token[:n]
}
