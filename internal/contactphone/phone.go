// Package contactphone validates the canonical representation of a declared
// international phone contact. Formatting is not verification of ownership,
// allocation, reachability or messaging consent.
package contactphone

import (
	"errors"
	"regexp"
)

// E.164 caps the international number at 15 digits. A country code starts
// with a nonzero digit; this structural check deliberately makes no claim
// about national numbering plans. Callers must supply the canonical + form,
// rather than guessing a country from local punctuation or a display name.
var canonical = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)

var ErrInvalid = errors.New("phone_e164 must use '+' followed by an international number of at most 15 digits")

func Validate(value string) error {
	if !canonical.MatchString(value) {
		return ErrInvalid
	}
	return nil
}
