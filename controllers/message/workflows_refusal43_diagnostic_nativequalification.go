//go:build linux && nativequalification

package message

import (
	"errors"
	"fmt"
)

type guestRefusal43Diagnostic struct {
	predicate string
	cause     error
}

func (e *guestRefusal43Diagnostic) Error() string { return "original guest source held" }
func (e *guestRefusal43Diagnostic) Unwrap() error { return e.cause }

func guestRefusal43Error(index int, kind string, cause error) error {
	var predicate string
	switch {
	case index == 0 && (kind == "pre" || kind == "initial" || kind == "publish"):
		predicate = "original-refusal-43-" + kind
	case index >= 1 && index <= 11 && (kind == "accepted" || kind == "error" || kind == "state"):
		predicate = fmt.Sprintf("original-refusal-43-check-%02d-%s", index, kind)
	default:
		return cause
	}
	return &guestRefusal43Diagnostic{predicate: predicate, cause: cause}
}
func guestOriginalRefusal43Predicate(err error) string {
	var d *guestRefusal43Diagnostic
	if errors.As(err, &d) {
		return d.predicate
	}
	return "original-guest-step-43"
}
