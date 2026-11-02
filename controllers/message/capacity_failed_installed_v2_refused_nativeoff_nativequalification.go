//go:build nativequalification

package message

import (
	"context"
	"database/sql"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Qualification cannot attest a production native OFF read. Keep the route
// linked, but refuse before touching storage or transport.
func QuiesceFailedInstalledV2RefusedNativeOff(context.Context, *sql.DB, *amqp.Connection, string, string, string, string) (repository.FailedInstalledV2RefusedNativeOff, repository.FailedInstalledGuestDisposal, error) {
	return repository.FailedInstalledV2RefusedNativeOff{}, repository.FailedInstalledGuestDisposal{}, errFailedInstalledGuestProductionOnly
}
