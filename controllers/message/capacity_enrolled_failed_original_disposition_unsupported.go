//go:build nativequalification

package message

import (
	"context"
	"database/sql"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	amqp "github.com/rabbitmq/amqp091-go"
)

func RecordEnrolledFailedOriginalDisposition(context.Context, *sql.DB, *amqp.Connection, string, string, string) (model.CapacityEnrolledFailedOriginalDisposition, error) {
	return model.CapacityEnrolledFailedOriginalDisposition{}, errors.New("production enrolled-failed disposition unavailable in qualification")
}
