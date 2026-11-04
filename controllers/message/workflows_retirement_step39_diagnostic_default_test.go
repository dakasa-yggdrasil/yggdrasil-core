//go:build !linux || !nativequalification

package message

import "testing"

func TestRetirementStep39ProductionPredicateUnchanged(t *testing.T) {
	if got := guestRetirementStep39Predicate(true, true, true, true, true, true); got != "original-guest-step-39" {
		t.Fatal("production aggregate refusal changed")
	}
}
