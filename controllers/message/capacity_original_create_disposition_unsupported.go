//go:build nativequalification

package message

import (
	"context"
	"database/sql"
	"errors"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	amqp "github.com/rabbitmq/amqp091-go"
)

// An administrative production disposition never gains authority from the
// qualification harness or its emulated provider/SQL realm.
func RecordOriginalCreateDisposition(context.Context, *sql.DB, *amqp.Connection, string, string) (model.CapacityOriginalCreateDisposition, error) {
	return model.CapacityOriginalCreateDisposition{}, errors.New("production original create disposition unavailable in qualification")
}
