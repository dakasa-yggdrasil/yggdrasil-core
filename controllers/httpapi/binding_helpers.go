package httpapi

import (
	"path/filepath"
	"strings"
)

// matchesBranchFilter reports whether a push to `ref` (e.g. "refs/heads/main")
// is allowed by the binding's branch filter list. Empty list permits any branch
// (defensive — NormalizeRepositoryBindingSpec sets ["main"] for missing values).
// A single "*" entry permits any branch. Each entry is matched as the branch
// short name (with or without the "refs/heads/" prefix).
func matchesBranchFilter(ref string, filter []string) bool {
	if len(filter) == 0 {
		return true
	}
	if len(filter) == 1 && filter[0] == "*" {
		return true
	}
	for _, b := range filter {
		short := strings.TrimPrefix(b, "refs/heads/")
		if ref == "refs/heads/"+short {
			return true
		}
	}
	return false
}

// matchesPathFilter reports whether at least one file in `modified` matches
// any of the `globs` (path/filepath.Match semantics). Returns false when
// `globs` is empty (caller should bypass path filtering when that is the case).
func matchesPathFilter(modified []string, globs []string) bool {
	if len(globs) == 0 {
		return false
	}
	for _, file := range modified {
		for _, g := range globs {
			if matched, err := filepath.Match(g, file); err == nil && matched {
				return true
			}
		}
	}
	return false
}
