//go:build nativequalification

package message

import (
	"context"
	"database/sql"
	"errors"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

var errFailedInstalledGuestProductionOnly = errors.New("failed installed Guest disposal requires the production owner")

// Qualification cannot attest production Guest quiescence or provider absence.
// Keep these routes linked, but refuse before touching storage or transport.
func RecordFailedInstalledGuestNativeAbsence(context.Context, *sql.DB, *amqp.Connection, string, string, string) (repository.FailedInstalledGuestDisposal, error) {
	return repository.FailedInstalledGuestDisposal{}, errFailedInstalledGuestProductionOnly
}

func AdvanceFailedInstalledGuestNativeCleanup(context.Context, *sql.DB, *amqp.Connection, string, string, string) (repository.FailedInstalledGuestDisposal, error) {
	return repository.FailedInstalledGuestDisposal{}, errFailedInstalledGuestProductionOnly
}
