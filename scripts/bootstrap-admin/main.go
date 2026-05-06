// bootstrap-admin promotes an already-existing collaborator into the
// yggdrasil-admin team so they can perform privileged operations via
// the OIDC-secured console. The collaborator MUST have already logged in
// once (via Google OIDC third-party callback or password) so a row
// exists in the collaborators table — this CLI does not create users.
//
// Usage:
//
//	yggdrasil-bootstrap-admin --email alice@dakasa.me
//	yggdrasil-bootstrap-admin --email alice@dakasa.me --team tartaro-mod
//
// Idempotent: re-running for the same (email, team) pair succeeds
// silently because team membership creation uses ON CONFLICT DO NOTHING.
//
// Connects to Postgres via psql.Open(), which reads DB_HOST/DB_PORT/...
// from the environment — same convention as the long-running daemon.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/psql"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// defaultTimeout caps the total time the CLI spends on its DB operations.
// Bootstrap is interactive — fast feedback matters more than retries.
const defaultTimeout = 10 * time.Second

func main() {
	fs := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	email := fs.String("email", "", "primary email of the collaborator to promote (required)")
	teamSlug := fs.String("team", "yggdrasil-admin", "team slug to promote into")
	timeout := fs.Duration("timeout", defaultTimeout, "deadline for the DB operations")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *email == "" {
		fmt.Fprintln(os.Stderr, "error: --email is required")
		fs.Usage()
		os.Exit(2)
	}

	db, err := psql.Open()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open postgres: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	collabID, err := promoteAdmin(ctx, db, *email, *teamSlug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK promoted %s to %s (collaborator_id=%s)\n", *email, *teamSlug, collabID)
}

// promoteAdmin resolves the collaborator by primary email and adds them
// to the named team. Returns the collaborator UUID for the caller to log.
//
// Errors:
//   - ErrCollaboratorNotFound (wrapped): the collaborator has not logged
//     in yet. The CLI does NOT create collaborators; that path is the
//     auto-provision flow on first OIDC login.
//   - any other error: surfaces verbatim with context.
//
// Idempotent: AddCollaboratorToTeamBySlugTx uses ON CONFLICT DO NOTHING.
func promoteAdmin(ctx context.Context, db *sql.DB, email, teamSlug string) (string, error) {
	collab, err := repository.GetCollaboratorByPrimaryEmail(ctx, db, email)
	if err != nil {
		if errors.Is(err, repository.ErrCollaboratorNotFound) {
			// Wrap to preserve the sentinel for callers using errors.Is,
			// while leading the message with operator-actionable guidance.
			return "", fmt.Errorf("collaborator with email %q not found — they must log in once via OIDC before being promoted: %w", email, err)
		}
		return "", fmt.Errorf("lookup collaborator: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := repository.AddCollaboratorToTeamBySlugTx(ctx, tx, collab.ID, teamSlug, "bootstrap-cli"); err != nil {
		return "", fmt.Errorf("add to team %q: %w", teamSlug, err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit: %w", err)
	}
	return collab.ID.String(), nil
}
