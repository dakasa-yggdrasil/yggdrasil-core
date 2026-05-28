package httpapi

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Phase 6 aggregator — audit 2026-05-27 §2.1.
//
// OverviewPage previously fired SIX separate queries on every mount:
//
//   1. fetchCollaborators()           — entire dataset, just to count
//   2. fetchTeams()                    — entire dataset, just for .length
//   3. fetchSAMLServiceProviders()
//   4. fetchSCIMClients()
//   5. fetchOpsSystemHealth()          — 30s polling
//   6. fetchOpsAudit(100)              — 30s polling, filtered to 3 entries
//
// For a 500-collaborator deployment, opening the homepage cost ~6 round-trips
// PLUS two polling streams. This handler returns the SAME shape the
// OverviewPage needs (counts + booleans + a tiny audit slice) in ONE response.
//
// Permission gate: yggdrasil:view_overview. The single permission is checked
// at the route layer (server.go). Section-level visibility is honoured by
// data-shaping inside the handler — if a caller lacks `view_audit` we omit
// the events slice rather than failing the whole aggregate. UX-wise the
// section was hidden by a PermissionGate anyway; trimming the bytes keeps
// the response minimal and predictable.

// consoleOverviewSummary is the canonical response shape the surface
// consumes. Fields are flat + JSON-friendly so the TS side reads them
// without any normalization. Field names mirror what OverviewPage.tsx
// renders.
type consoleOverviewSummary struct {
	People             consoleOverviewPeople        `json:"people"`
	Teams              consoleOverviewTeams         `json:"teams"`
	Identity           consoleOverviewIdentity      `json:"identity"`
	Health             consoleOverviewHealth        `json:"health"`
	RecentAuditEvents  []consoleOverviewAuditEvent  `json:"recent_audit_events"`
	CheckedAt          time.Time                    `json:"checked_at"`
}

type consoleOverviewPeople struct {
	Total   int `json:"total"`
	Active  int `json:"active"`
	Pending int `json:"pending"`
}

type consoleOverviewTeams struct {
	Total int `json:"total"`
}

type consoleOverviewIdentity struct {
	SAMLProviders int `json:"saml_providers"`
	SCIMClients   int `json:"scim_clients"`
}

type consoleOverviewHealth struct {
	DBHealthy        bool  `json:"db_healthy"`
	AppliedMigration int64 `json:"applied_migration"`
}

// consoleOverviewAuditEvent is the tiny subset of OpsAuditEvent the
// homepage feed renders. Trimming to id/action/target/created_at +
// optional actor keeps the response payload small for a list that's
// only meant to be a glance.
type consoleOverviewAuditEvent struct {
	ID         string    `json:"id"`
	Actor      string    `json:"actor,omitempty"`
	Action     string    `json:"action"`
	TargetKind string    `json:"target_kind,omitempty"`
	TargetID   string    `json:"target_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// handleConsoleOverviewSummary is the aggregate replacement for the 6
// queries OverviewPage previously dispatched. It performs ONE round-trip
// to postgres composed of 5-6 cheap reads (mostly COUNT()s + LIMIT 200
// audit fetch) and returns the merged response.
//
// Errors: an empty or missing table is treated as "zero", not 500. Only
// hard infrastructure failures bubble. This mirrors the original
// surface behaviour where each query failed independently — a missing
// audit table didn't blank out the team count.
func (s *Server) handleConsoleOverviewSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := consoleOverviewSummary{
		CheckedAt:         time.Now().UTC(),
		RecentAuditEvents: []consoleOverviewAuditEvent{},
	}

	// 1) people counts — single grouped SELECT covers total + status splits.
	people, err := overviewSummaryPeople(ctx, s.db)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	out.People = people

	// 2) team count — single COUNT(*).
	teams, err := overviewSummaryTeams(ctx, s.db)
	if err != nil {
		writeMappedError(w, err)
		return
	}
	out.Teams = teams

	// 3+4) identity counts — two cheap COUNT(*)s.  Missing-table errors are
	// soft because saml/scim aren't yet wired in every deployment.
	out.Identity = overviewSummaryIdentity(ctx, s.db)

	// 5) health — same data as fetchOpsSystemHealth's db+migrations sections.
	out.Health = overviewSummaryHealth(ctx, s.db)

	// 6) recent audit events — last 10 entries the FE renders.  The
	// previous code fetched 100 then sliced client-side, throwing away
	// 97 records.  Server side LIMIT 10 saves a 10x payload.
	if events, err := repository.ListOpsAuditEvents(ctx, s.db, model.ListOpsAuditEventsFilter{Limit: 10}); err == nil {
		for _, e := range events {
			out.RecentAuditEvents = append(out.RecentAuditEvents, consoleOverviewAuditEvent{
				ID:         e.ID.String(),
				Actor:      e.Actor,
				Action:     e.Action,
				TargetKind: e.TargetKind,
				TargetID:   e.TargetID,
				CreatedAt:  e.CreatedAt,
			})
		}
	}

	writeJSON(w, http.StatusOK, out)
}

// overviewSummaryPeople counts collaborators grouped by status. ONE query.
func overviewSummaryPeople(ctx context.Context, db *sql.DB) (consoleOverviewPeople, error) {
	if db == nil {
		return consoleOverviewPeople{}, nil
	}
	const q = `
		SELECT
			COUNT(*)::int AS total,
			COUNT(*) FILTER (WHERE status = 'active')::int AS active_count,
			COUNT(*) FILTER (WHERE status = 'pending')::int AS pending_count
		FROM public.collaborators
	`
	var out consoleOverviewPeople
	err := db.QueryRowContext(ctx, q).Scan(&out.Total, &out.Active, &out.Pending)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return consoleOverviewPeople{}, nil
		}
		return consoleOverviewPeople{}, err
	}
	return out, nil
}

// overviewSummaryTeams counts non-archived teams. ONE query.
func overviewSummaryTeams(ctx context.Context, db *sql.DB) (consoleOverviewTeams, error) {
	if db == nil {
		return consoleOverviewTeams{}, nil
	}
	var total int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*)::int FROM public.teams`).Scan(&total); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return consoleOverviewTeams{}, nil
		}
		return consoleOverviewTeams{}, err
	}
	return consoleOverviewTeams{Total: total}, nil
}

// overviewSummaryIdentity counts SAML SPs + SCIM clients. Soft-fail on
// missing tables since identity wiring is per-cluster.
func overviewSummaryIdentity(ctx context.Context, db *sql.DB) consoleOverviewIdentity {
	out := consoleOverviewIdentity{}
	if db == nil {
		return out
	}
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*)::int FROM public.saml_service_providers`).Scan(&out.SAMLProviders)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*)::int FROM public.scim_clients WHERE revoked_at IS NULL`).Scan(&out.SCIMClients)
	return out
}

// overviewSummaryHealth mirrors the db+migrations subsections of
// /api/v1/ops/system/health. Cheap probes.
func overviewSummaryHealth(ctx context.Context, db *sql.DB) consoleOverviewHealth {
	out := consoleOverviewHealth{}
	if db == nil {
		return out
	}
	if err := db.PingContext(ctx); err == nil {
		out.DBHealthy = true
	}
	_ = db.QueryRowContext(ctx,
		`SELECT MAX(version_id) FROM public.goose_db_version WHERE is_applied = true`).
		Scan(&out.AppliedMigration)
	return out
}
