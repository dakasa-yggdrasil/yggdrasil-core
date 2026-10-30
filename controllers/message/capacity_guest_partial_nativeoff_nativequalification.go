//go:build nativequalification

package message

import (
	"context"
	"database/sql"
	amqp "github.com/rabbitmq/amqp091-go"
)

type PartialNativeOffObservationResult struct {
	ReadID                     string `json:"read_id"`
	Ordinal                    int    `json:"ordinal"`
	ReconciliationID           string `json:"reconciliation_id"`
	QuiescentQualified         bool   `json:"quiescent_qualified"`
	GuestRequestOrPoweroffSent bool   `json:"Guest_request_or_poweroff_sent"`
}

func ObserveFailedInstalledPartialNativeOff(context.Context, *sql.DB, *amqp.Connection, string, string, string) (PartialNativeOffObservationResult, error) {
	return PartialNativeOffObservationResult{}, errFailedInstalledGuestProductionOnly
}
