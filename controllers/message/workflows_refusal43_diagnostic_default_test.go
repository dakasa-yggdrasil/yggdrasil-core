//go:build !linux || !nativequalification

package message

import (
	"errors"
	"testing"
)

func TestOriginalRefusal43ProductionPredicateUnchanged(t *testing.T) {
	if guestOriginalRefusal43Predicate(errors.New("private")) != "original-guest-step-43" {
		t.Fatal("production predicate changed")
	}
}
