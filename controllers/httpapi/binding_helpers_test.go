package httpapi

import "testing"

func TestMatchesBranchFilterDefaultMain(t *testing.T) {
	if !matchesBranchFilter("refs/heads/main", []string{"main"}) {
		t.Fatal("main should match ['main']")
	}
	if matchesBranchFilter("refs/heads/feature/x", []string{"main"}) {
		t.Fatal("feature/x should not match ['main']")
	}
}

func TestMatchesBranchFilterWildcard(t *testing.T) {
	if !matchesBranchFilter("refs/heads/anything", []string{"*"}) {
		t.Fatal("wildcard should match anything")
	}
}

func TestMatchesBranchFilterMultiple(t *testing.T) {
	if !matchesBranchFilter("refs/heads/release", []string{"main", "release"}) {
		t.Fatal("release should match list")
	}
	if matchesBranchFilter("refs/heads/develop", []string{"main", "release"}) {
		t.Fatal("develop should not match list")
	}
}

func TestMatchesBranchFilterAcceptsRefsHeadsPrefix(t *testing.T) {
	if !matchesBranchFilter("refs/heads/main", []string{"refs/heads/main"}) {
		t.Fatal("explicit refs/heads/main entry should match")
	}
}

func TestMatchesBranchFilterEmptyList(t *testing.T) {
	if !matchesBranchFilter("refs/heads/main", []string{}) {
		t.Fatal("empty filter is defensive and accepts anything")
	}
}

func TestMatchesPathFilterEmptyReturnsFalse(t *testing.T) {
	if matchesPathFilter([]string{"a/b"}, []string{}) {
		t.Fatal("empty globs should return false (caller bypasses)")
	}
}

func TestMatchesPathFilterTopLevelGlob(t *testing.T) {
	if !matchesPathFilter([]string{"deploy/file.yaml"}, []string{"deploy/*"}) {
		t.Fatal("deploy/* should match top-level deploy/file.yaml")
	}
	if matchesPathFilter([]string{"src/main.go"}, []string{"deploy/*"}) {
		t.Fatal("deploy/* should not match src/main.go")
	}
}

func TestMatchesPathFilterMultipleGlobs(t *testing.T) {
	if !matchesPathFilter([]string{"src/main.go"}, []string{"deploy/*", "src/*"}) {
		t.Fatal("src/main.go should match src/* in multi-glob list")
	}
}

func TestMatchesPathFilterAnyOfModifiedMatches(t *testing.T) {
	modified := []string{"README.md", "deploy/overlay.yaml"}
	if !matchesPathFilter(modified, []string{"deploy/*"}) {
		t.Fatal("any-of semantics: at least one modified file matches")
	}
}
