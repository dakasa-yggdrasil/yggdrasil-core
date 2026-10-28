//go:build linux && nativequalification

package httpapi

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"log"
)

func guestRegistrationDiagnosticLog(err error) {
	if stage := repository.GuestRegistrationDiagnostic(err); stage != "" {
		log.Printf("original_guest_registration_diagnostic_v1 stage=%s", stage)
	}
}
