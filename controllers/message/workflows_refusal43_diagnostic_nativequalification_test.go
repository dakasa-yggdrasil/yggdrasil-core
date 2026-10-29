//go:build linux && nativequalification

package message

import (
	"errors"
	"fmt"
	"testing"
)

func TestOriginalRefusal43DiagnosticClosed(t *testing.T) {
	cause := errors.New("private cause")
	for _, kind := range []string{"pre", "initial", "publish"} {
		e := guestRefusal43Error(0, kind, cause)
		if !errors.Is(e, cause) || guestOriginalRefusal43Predicate(e) != "original-refusal-43-"+kind {
			t.Fatal(kind)
		}
	}
	for i := 1; i <= 11; i++ {
		for _, kind := range []string{"accepted", "error", "state"} {
			e := guestRefusal43Error(i, kind, cause)
			if !errors.Is(e, cause) || guestOriginalRefusal43Predicate(e) != fmt.Sprintf("original-refusal-43-check-%02d-%s", i, kind) {
				t.Fatal(i, kind)
			}
		}
	}
	for _, e := range []error{cause, guestRefusal43Error(12, "state", cause), guestRefusal43Error(1, "secret", cause)} {
		if guestOriginalRefusal43Predicate(e) != "original-guest-step-43" {
			t.Fatal("unrecognized diagnostic escaped")
		}
	}
}
