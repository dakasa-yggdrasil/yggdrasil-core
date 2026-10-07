package contactphone

import (
	"errors"
	"testing"
)

func TestCanonicalDeclarationDoesNotGuessNationalNumbers(t *testing.T) {
	// The NANP 555-01xx examples are synthetic fixtures, never live contacts.
	for _, value := range []string{"+12025550100", "+12025550101", "+123456789012345"} {
		if err := Validate(value); err != nil {
			t.Fatal("canonical declaration rejected")
		}
	}
	for name, value := range map[string]string{
		"local number":        "2025550100",
		"punctuation":         "+1 (202) 555-0100",
		"leading whitespace":  " +12025550100",
		"trailing whitespace": "+12025550100 ",
		"extension":           "+12025550100x12",
		"prefix zero":         "+02025550100",
		"over maximum":        "+1234567890123456",
		"non ASCII digit":     "+１２３４５６７８９",
		"empty":               "",
		"country only":        "+1",
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(Validate(value), ErrInvalid) {
				t.Fatal("noncanonical declaration must fail without echoing its value")
			}
		})
	}
}
