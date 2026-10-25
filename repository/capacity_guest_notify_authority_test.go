package repository

import (
	"strings"
	"testing"
)

// Uses an existing signed historical fixture. No real build identity or
// production profile approval is substituted by this content-only test.
func TestGuestNotifyHistoricalEnrollmentPreservesSignedAuthority(t *testing.T) {
	for _, name := range []string{"historical_signed_content", "rewritten_enrollment", "foreign_binding", "foreign_tuple", "invalid_issuer_signature"} {
		t.Run(name, func(t *testing.T) {
			stored, p, receipt, _ := enrolledReceiptFixture(t)
			historical := receipt.Enrollment.Statement.CoreAuthoritySourceCommit
			declaredSuccessor := strings.Repeat("f", 40)
			if historical == declaredSuccessor {
				t.Fatal("test must cover distinct issuer and historical authority")
			}
			switch name {
			case "rewritten_enrollment":
				receipt.Enrollment.Statement.CoreAuthoritySourceCommit = declaredSuccessor
			case "foreign_binding":
				stored.binding.CoreAuthoritySourceCommit = declaredSuccessor
			case "foreign_tuple":
				receipt.Enrollment.Statement.Tuple.ResourceID = "foreign"
			case "invalid_issuer_signature":
				receipt.Enrollment.Signature = "invalid"
			}
			if guestNotifyHistoricalEnrollmentMatches(p, stored, receipt) != (name == "historical_signed_content") {
				t.Fatal("historical enrollment was refused or altered signed content accepted")
			}
		})
	}
}
