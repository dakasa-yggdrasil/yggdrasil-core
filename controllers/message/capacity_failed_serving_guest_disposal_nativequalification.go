//go:build nativequalification

package message

import (
	"context"
	"database/sql"
	"errors"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

var errFailedServingGuestProductionOnly = errors.New("failed serving Guest disposal requires the production owner")

// A qualification fixture grants no production quarantine, OFF or absence.
func RequestFailedServingGuestQuarantine(context.Context, *sql.DB, *amqp.Connection, model.CapacityFailedServingGuestDisposalRequest, string) (repository.FailedServingGuestDisposal, error) {
	return repository.FailedServingGuestDisposal{}, errFailedServingGuestProductionOnly
}
func ObserveFailedServingGuestNativeOff(context.Context, *sql.DB, *amqp.Connection, string, string, string) (repository.FailedServingGuestDisposal, error) {
	return repository.FailedServingGuestDisposal{}, errFailedServingGuestProductionOnly
}
func CompleteFailedServingGuestAbsence(context.Context, *sql.DB, *amqp.Connection, string, string, string) (repository.FailedServingGuestDisposal, error) {
	return repository.FailedServingGuestDisposal{}, errFailedServingGuestProductionOnly
}
