//go:build nativequalification

package message

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
)

func TestNativeQualificationRefusesFailedInstalledGuestProductionDisposal(t *testing.T) {
	operations := map[string]func(context.Context, *sql.DB, *amqp.Connection, string, string, string) (repository.FailedInstalledGuestDisposal, error){
		"native_absence": RecordFailedInstalledGuestNativeAbsence,
		"native_cleanup": AdvanceFailedInstalledGuestNativeCleanup,
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			for _, withInputs := range []bool{false, true} {
				var ctx context.Context
				var db *sql.DB
				var conn *amqp.Connection
				var preID, admissionID, issuer string
				if withInputs {
					ctx = context.Background()
					// Uninitialized dependencies panic if a production path uses
					// them. Qualification must refuse even well-shaped IDs first.
					db, conn = &sql.DB{}, &amqp.Connection{}
					preID = "10000000-0000-4000-8000-000000000001"
					admissionID = "10000000-0000-4000-8000-000000000002"
					issuer = "declared-qualification-test-only"
				}
				result, err := operation(ctx, db, conn, preID, admissionID, issuer)
				if !errors.Is(err, errFailedInstalledGuestProductionOnly) || !reflect.DeepEqual(result, repository.FailedInstalledGuestDisposal{}) {
					t.Fatal("qualification admitted production disposal or returned an observation")
				}
			}
		})
	}
}
