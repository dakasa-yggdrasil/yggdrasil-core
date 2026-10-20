package capacity

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGuestQualificationRefusalClosedProjection(t *testing.T) {
	cause := errors.New("SECRET SQL HTTP credential body")
	cases := []struct{ stage, predicate string }{
		{"observe", "original-guest-step-60"},
		{"lease_missing", "original-guest-step-61"},
		{"generation", "original-guest-step-62"},
		{"fence", "original-guest-step-63"},
		{"phase", "original-guest-step-64"},
		{"binding", "original-guest-step-65"},
		{"owned_slots", "original-guest-step-66"},
		{"member", "original-guest-step-67"},
		{"client", "original-guest-step-68"},
		{"probe", "original-guest-step-69"},
		{"fresh_native", "original-guest-step-70"},
		{"projection", "original-guest-step-71"},
		{"projection_encode", "original-guest-step-72"},
		{"record_slot", "original-guest-step-73"},
		{"advance_prepared", "original-guest-step-74"},
		{"advance_canary", "original-guest-step-75"},
		{"advance_promoted", "original-guest-step-76"},
		{"realm_profile", "original-guest-step-77"},
		{"enrollment", "original-guest-step-78"},
		{"key_writers", "original-guest-step-79"},
		{"deadline", "original-guest-step-80"},
		{"nonce", "original-guest-step-81"},
		{"signature", "original-guest-step-82"},
		{"request_encode", "original-guest-step-83"},
		{"reserve_probe", "original-guest-step-84"},
		{"probe_http", "original-guest-step-85"},
		{"probe_decode", "original-guest-step-86"},
		{"probe_validate", "original-guest-step-87"},
		{"finish_probe", "original-guest-step-88"},
		{"publish_probe", "original-guest-step-89"},
		{"arbitrary SECRET", "original-guest-step-17"},
		{"probe_http\nSECRET", "original-guest-step-17"},
		{"", "original-guest-step-17"},
	}
	for i, tc := range cases {
		t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
			err := GuestQualificationRefusal(tc.stage, cause)
			if !errors.Is(err, cause) {
				t.Fatal("cause identity lost")
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatal("private text exposed")
			}
			if got := GuestQualificationPredicate(fmt.Errorf("outer: %w", err)); got != tc.predicate {
				t.Fatalf("got %q", got)
			}
		})
	}
	if GuestQualificationRefusal("probe_http", nil) != nil {
		t.Fatal("success changed")
	}
	for _, err := range []error{nil, cause, fmt.Errorf("original-guest-step-85: %w", cause)} {
		if GuestQualificationPredicate(err) != "original-guest-step-17" {
			t.Fatal("untyped error acquired stage")
		}
	}
}
