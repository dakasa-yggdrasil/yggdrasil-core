//go:build nativequalification

package message

import (
	"context"
	"database/sql"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	amqp "github.com/rabbitmq/amqp091-go"
)

func RecordNativeDeniedDisposition(context.Context, *sql.DB, *amqp.Connection, string, string, string) (model.CapacityNativeDeniedDisposition, error) {
	return model.CapacityNativeDeniedDisposition{}, errors.New("production denied disposition unavailable in qualification")
}
