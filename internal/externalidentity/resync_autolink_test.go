package externalidentity

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedCollaboratorWith inserts a collaborator carrying the given primary_email,
// traits, and metadata JSONB, and registers cleanup. Empty email/traits/metadata
// fall back to sane defaults so callers only set what the case under test needs.
func seedCollaboratorWith(t *testing.T, db *sql.DB, email, traitsJSON, metadataJSON string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if email == "" {
		email = id.String() + "@dakasa.me"
	}
	if traitsJSON == "" {
		traitsJSON = "{}"
	}
	if metadataJSON == "" {
		metadataJSON = "{}"
	}
	_, err := db.Exec(`INSERT INTO collaborators (id, slug, status, display_name, primary_email, traits, metadata)
	                   VALUES ($1, $2, 'active', 'Test', $3, $4::jsonb, $5::jsonb)`,
		id, "autolink-"+id.String()[:8], email, traitsJSON, metadataJSON)
	require.NoError(t, err)
	t.Cleanup(func() { db.Exec(`DELETE FROM collaborators WHERE id = $1`, id) })
	return id
}

func TestFindCollaboratorForExternal_HandleMatch(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	want := seedCollaboratorWith(t, db, "", `{"github_login":"octo-x"}`, "")

	got, matched, err := findCollaboratorForExternal(ctx, db, "github", "octo-x", map[string]any{})
	require.NoError(t, err)
	require.True(t, matched, "expected a unique handle match")
	assert.Equal(t, want, got)
}

func TestFindCollaboratorForExternal_HandleMatchViaMetadata(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	// Handle stored in metadata (not traits) — must still match.
	want := seedCollaboratorWith(t, db, "", "", `{"github_login":"octo-meta"}`)

	got, matched, err := findCollaboratorForExternal(ctx, db, "github", "octo-meta", map[string]any{})
	require.NoError(t, err)
	require.True(t, matched)
	assert.Equal(t, want, got)
}

func TestFindCollaboratorForExternal_HandleMatchBareProviderFallback(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	// Stored under the bare provider key ("github"), not "github_login".
	want := seedCollaboratorWith(t, db, "", `{"github":"octo-bare"}`, "")

	got, matched, err := findCollaboratorForExternal(ctx, db, "github", "octo-bare", map[string]any{})
	require.NoError(t, err)
	require.True(t, matched)
	assert.Equal(t, want, got)
}

func TestFindCollaboratorForExternal_EmailMatch(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	email := "auto-" + uuid.New().String()[:8] + "@dakasa.me"
	want := seedCollaboratorWith(t, db, email, "", "")

	// Case-insensitive + tries multiple meta keys (here "primary_email").
	got, matched, err := findCollaboratorForExternal(ctx, db, "github", "no-handle",
		map[string]any{"primary_email": " " + upper(email) + " "})
	require.NoError(t, err)
	require.True(t, matched)
	assert.Equal(t, want, got)
}

func TestFindCollaboratorForExternal_Ambiguous(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	// Two distinct collaborators carry the SAME handle → must NOT guess.
	_ = seedCollaboratorWith(t, db, "", `{"github_login":"dupe-x"}`, "")
	_ = seedCollaboratorWith(t, db, "", `{"github_login":"dupe-x"}`, "")

	got, matched, err := findCollaboratorForExternal(ctx, db, "github", "dupe-x", map[string]any{})
	require.NoError(t, err)
	assert.False(t, matched, "ambiguous (>1 distinct) must not match")
	assert.Equal(t, uuid.Nil, got)
}

func TestFindCollaboratorForExternal_NoMatch(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	got, matched, err := findCollaboratorForExternal(ctx, db, "github", "ghost-handle",
		map[string]any{"email": "nobody-" + uuid.New().String() + "@nowhere.example"})
	require.NoError(t, err)
	assert.False(t, matched)
	assert.Equal(t, uuid.Nil, got)
}

func TestFindCollaboratorForExternal_EmailAndHandleSameCollabIsUnique(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	t.Cleanup(func() { db.Close() })

	// Email AND handle both resolve to the SAME collaborator → still unique.
	email := "both-" + uuid.New().String()[:8] + "@dakasa.me"
	want := seedCollaboratorWith(t, db, email, `{"github_login":"both-x"}`, "")

	got, matched, err := findCollaboratorForExternal(ctx, db, "github", "both-x",
		map[string]any{"email": email})
	require.NoError(t, err)
	require.True(t, matched)
	assert.Equal(t, want, got)
}

// upper is a tiny local helper to avoid importing strings just for one call.
func upper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'z' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}
