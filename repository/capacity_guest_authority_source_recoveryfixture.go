//go:build recoveryfixture && !nativequalification

package repository

import (
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type guestAuthorityFixtureScope struct {
	db               *sql.DB
	policy, workflow uuid.UUID
	kind             string
}

var guestAuthorityFixtureIssuers sync.Map

func guestAuthorityFixtureProcess() bool {
	return strings.HasSuffix(filepath.Base(os.Args[0]), ".test") && os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") == "true"
}

// Only explicitly declared old installed-resume issuers in an owned test DB
// differ from the actual build. Each immutable original is emitted once with
// that declared operand; no stored history or runtime build identity changes.
func guestAuthorityIssueSource(s CapacityStore, policy model.Manifest, kind string) string {
	if guestAuthorityFixtureProcess() {
		if source, ok := guestAuthorityFixtureIssuers.Load(guestAuthorityFixtureScope{s.DB, policy.ID, s.WorkflowID, kind}); ok {
			return source.(string)
		}
	}
	return capacity.CurrentGuestCoreSource()
}

func registerInstalledReadinessFixtureIssuer(t *testing.T, db *sql.DB, policy, workflow uuid.UUID, source string) func() {
	t.Helper()
	if !guestAuthorityFixtureProcess() || db == nil || policy == uuid.Nil || workflow == uuid.Nil || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(source) || source == capacity.CurrentGuestCoreSource() {
		t.Fatal("explicit owned fixture with a distinct declared old issuer required")
	}
	key := guestAuthorityFixtureScope{db, policy, workflow, "installed_reconcile"}
	if _, exists := guestAuthorityFixtureIssuers.LoadOrStore(key, source); exists {
		t.Fatal("fixture issuer scope already owned")
	}
	var once sync.Once
	release := func() { once.Do(func() { guestAuthorityFixtureIssuers.Delete(key) }) }
	t.Cleanup(release)
	return release
}
