//go:build !recoveryfixture || nativequalification

package repository

import "testing"

// The untagged/native gate never enables a synthetic production profile.
func syntheticCompensationIfEnabled(*testing.T, bool, bool) bool { return false }
