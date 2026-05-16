package externalidentity

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// CleanupTick hard-deletes external identity rows that have been
// soft-deleted for longer than retention. For each purged row, an
// external_identity.purged event is emitted so audit logs stay complete
// even after the row is gone.
//
// Returns the count of purged rows for tests/telemetry.
func CleanupTick(ctx context.Context, db *sql.DB, retention time.Duration) (int, error) {
	cutoff := time.Now().UTC().Add(-retention)
	purged, err := HardCleanup(ctx, db, cutoff)
	if err != nil {
		return 0, fmt.Errorf("hard cleanup: %w", err)
	}
	now := time.Now().UTC()
	for _, ident := range purged {
		_ = EmitEvent(ctx, db, repository.EventTypeExternalIdentityPurged, ident.ID,
			BuildPurgedPayload(PurgedInputs{
				IdentityID:            ident.ID,
				CollaboratorID:        ident.CollaboratorID,
				IntegrationInstanceID: ident.IntegrationInstanceID,
				ExternalID:            ident.ExternalID,
				PurgedAt:              now,
			}))
	}
	return len(purged), nil
}
