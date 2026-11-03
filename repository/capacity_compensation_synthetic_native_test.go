//go:build nativequalification

package repository

import "testing"

// Native qualification retains the original unmodified test path.
func syntheticCompensationIfEnabled(*testing.T, bool, bool) bool { return false }

func syntheticFailedFloorIfEnabled(*testing.T) bool { return false }
