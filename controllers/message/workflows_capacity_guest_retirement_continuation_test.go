//go:build !nativequalification

package message

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This exercises the real finish orchestration boundary. It establishes no
// provider execution or native absence qualification claim.
func TestGuestRetirementForwardContinuationKnownDestroyOnly(t *testing.T) {
	for _, name := range []string{
		"settled", "confirmed", "missing_receipt", "foreign_grant", "empty_expected_grant", "empty_receipt_grant",
		"issued", "uncertain", "rejected", "transport_incomplete", "receipt_error",
		"inventory_error", "floor_error", "floor_cancelled", "completion_error", "no_deadline", "insufficient_reserve", "cancelled",
	} {
		t.Run(name, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			if name == "no_deadline" {
				parent = context.Background()
			}
			if name == "insufficient_reserve" {
				parent, cancel = context.WithTimeout(context.Background(), 59*time.Second)
				defer cancel()
			}
			if name == "cancelled" {
				cancel()
			}
			deadline, _ := parent.Deadline()
			const grantID = "same-original-accepted-destroy"
			expectedGrantID := grantID
			receipt := model.CapacityMutationReceipt{
				Grant:   model.CapacityMutationGrant{GrantID: grantID, State: "settled"},
				Outcome: "accepted", TransportCompleted: true,
			}
			found := true
			switch name {
			case "confirmed":
				receipt.Grant.State = "confirmed"
			case "missing_receipt":
				found = false
			case "foreign_grant":
				receipt.Grant.GrantID = "foreign-destroy"
			case "empty_expected_grant":
				expectedGrantID = ""
			case "empty_receipt_grant":
				receipt.Grant.GrantID = ""
			case "issued":
				receipt.Grant.State = "issued"
			case "uncertain", "rejected":
				receipt.Outcome = name
			case "transport_incomplete":
				receipt.TransportCompleted = false
			}
			fault := errors.New(name)
			calls := []string{}
			checkPreparation := func(ctx context.Context) {
				t.Helper()
				want := deadline.Add(-60 * time.Second)
				if name == "confirmed" {
					want = deadline
				}
				got, ok := ctx.Deadline()
				if !ok || !got.Equal(want) || ctx.Err() != nil {
					t.Fatal("continuation changed the parent deadline or destroy reserve", got, want, ctx.Err())
				}
			}
			result := &struct{ completed bool }{true}
			got, err := finishGuestRetirementForwardWithCalls(parent, guestRetirementForwardFinishCalls{
				knownDestroyOnly: true,
				destroyGrantID:   expectedGrantID,
				receipt: func(ctx context.Context) (model.CapacityMutationReceipt, bool, error) {
					calls = append(calls, "receipt")
					if ctx != parent {
						t.Fatal("receipt lookup replaced the original finish context")
					}
					if name == "receipt_error" {
						return receipt, found, fault
					}
					return receipt, found, nil
				},
				off: func(context.Context) error {
					calls = append(calls, "off")
					t.Fatal("known-destroy continuation entered the OFF branch")
					return nil
				},
				inventory: func(ctx context.Context) error {
					calls = append(calls, "inventory")
					checkPreparation(ctx)
					if name == "inventory_error" {
						return fault
					}
					return nil
				},
				floor: func(ctx context.Context) error {
					calls = append(calls, "floor")
					checkPreparation(ctx)
					if name == "floor_error" {
						return fault
					}
					if name == "floor_cancelled" {
						cancel()
					}
					return nil
				},
				complete: func(ctx context.Context, actual model.CapacityMutationReceipt, actualFound bool) (any, error) {
					calls = append(calls, "complete")
					if ctx != parent || !actualFound || !reflect.DeepEqual(actual, receipt) || actual.Grant.GrantID != grantID {
						t.Fatal("completion lost the exact original receipt or finish context", actual, actualFound)
					}
					if name == "completion_error" {
						return nil, fault
					}
					return result, nil
				},
			})
			want := []string{"receipt"}
			success := name == "settled" || name == "confirmed"
			switch name {
			case "settled", "confirmed", "completion_error":
				want = append(want, "inventory", "floor", "complete")
			case "inventory_error":
				want = append(want, "inventory")
			case "floor_error", "floor_cancelled":
				want = append(want, "inventory", "floor")
			}
			if !reflect.DeepEqual(calls, want) || (err == nil) != success || (success && got != result) || (!success && got != nil) {
				t.Fatal("continuation advanced after a refusal, skipped fresh preparation, or changed completion", calls, want, got, err)
			}
			if (name == "receipt_error" || name == "inventory_error" || name == "floor_error" || name == "completion_error") && !errors.Is(err, fault) {
				t.Fatal("continuation hid the original boundary error", err)
			}
		})
	}
}
