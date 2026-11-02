//go:build nativequalification

package message

import (
	"context"
	"database/sql"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	amqp "github.com/rabbitmq/amqp091-go"
)

func RecordFailedOriginalDisposition(context.Context, *sql.DB, *amqp.Connection, string, string, string) (model.CapacityFailedOriginalDisposition, error) {
	return model.CapacityFailedOriginalDisposition{}, errors.New("production failed original disposition unavailable in qualification")
}
