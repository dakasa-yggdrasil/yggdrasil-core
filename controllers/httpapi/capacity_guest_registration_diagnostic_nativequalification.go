//go:build linux && nativequalification

package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/lib/pq"
)

func guestRegistrationDiagnosticLog(err error) {
	stage := repository.GuestRegistrationDiagnostic(err)
	if stage != "" {
		log.Printf("original_guest_registration_diagnostic_v1 stage=%s", stage)
		if detail := repository.GuestRegistrationDiagnosticDetail(err); detail != "" {
			log.Printf("original_guest_registration_protected_diagnostic_v1 group=%s", detail)
		}
	}
	if stage == "" {
		stage = "unclassified"
	}
	log.Printf("original_guest_registration_failure_diagnostic_v1 stage=%s class=%s sqlstate=%s", stage, guestRegistrationDiagnosticClass(err), guestRegistrationDiagnosticSQLState(err))
}

// Classify only typed errors. Error/Message/Detail/Constraint and request data
// are never formatted or inspected by this qualification-only logger.
func guestRegistrationDiagnosticClass(err error) string {
	var timeout net.Error
	var operation *net.OpError
	var certificate *tls.CertificateVerificationError
	var header tls.RecordHeaderError
	var authority x509.UnknownAuthorityError
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, repository.ErrCapacityConflict), errors.Is(err, repository.ErrCapacityMutationAuthorization):
		return "held"
	case errors.As(err, &timeout) && timeout.Timeout():
		return "timeout"
	case errors.As(err, &certificate), errors.As(err, &header), errors.As(err, &authority):
		return "tls"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.ErrClosedPipe), errors.Is(err, net.ErrClosed), errors.As(err, &operation):
		return "io"
	default:
		return "other"
	}
}

func guestRegistrationDiagnosticSQLState(err error) string {
	var database *pq.Error
	if !errors.As(err, &database) || database == nil {
		return "none"
	}
	switch database.Code {
	case "23502", "23503", "23505", "23514", "40001", "40P01", "55P03", "57014", "25P02", "08000", "08003", "08006", "57P01", "53300", "53400", "P0001":
		return string(database.Code)
	default:
		return "other"
	}
}
