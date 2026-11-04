//go:build !nativequalification

package message

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestGuestRetirementForwardAWSReadDoesNotRelabelPendingAsOff(t *testing.T) {
	at := time.Date(2026, 11, 3, 5, 28, 0, 123, time.UTC)
	for _, state := range []string{"stopped", "stopping"} {
		for _, fault := range []string{"exact", "missing_action", "foreign_action", "foreign_schema", "mismatched_state", "running", "terminated", "missing_server", "zero_observed", "unjoined_clock"} {
			t.Run(state+"/"+fault, func(t *testing.T) {
				plan := model.CapacityVMFleetPlan{ObservedAt: at.Format(time.RFC3339Nano), Server: &model.CapacityVMServerObservation{Status: state}}
				lifecycle := model.CapacityAWSInstanceLifecycle{Schema: "aws_original_request_and_instance_status_v1", RequestID: "original-create-action", EC2State: state, ObservedAt: at}
				action := "original-create-action"
				switch fault {
				case "missing_action":
					action = ""
				case "foreign_action":
					lifecycle.RequestID = "foreign"
				case "foreign_schema":
					lifecycle.Schema = "future"
				case "mismatched_state":
					plan.Server.Status = "running"
				case "running":
					lifecycle.EC2State, plan.Server.Status = "running", "running"
				case "terminated":
					lifecycle.EC2State, plan.Server.Status = "terminated", "terminated"
				case "missing_server":
					plan.Server = nil
				case "zero_observed":
					lifecycle.ObservedAt = time.Time{}
				case "unjoined_clock":
					lifecycle.ObservedAt = at.Add(time.Nanosecond)
				}
				if originalAWSForwardNativeOffLifecycleJoin(plan, lifecycle, action) != (fault == "exact") {
					t.Fatal("foreign lifecycle admitted for forward read")
				}
				// The established normal path still requires actual stopped. A
				// same-tuple stopping read only permits a fresh bounded GET.
				if originalAWSNativeOffLifecycleJoin(plan, lifecycle, action) != (fault == "exact" && state == "stopped") {
					t.Fatal("normal stopped-only contract changed")
				}
			})
		}
	}
}

func TestGuestRetirementForwardWorkflowMetadataNeverInventsCallerSuccess(t *testing.T) {
	deadline := time.Date(2026, 11, 3, 5, 22, 40, 0, time.UTC)
	for _, tc := range []struct {
		name                string
		returned            time.Time
		contextFailed, want bool
	}{
		{"timely", deadline.Add(-time.Nanosecond), false, true},
		{"exact_deadline", deadline, false, false},
		{"late_timer_race", deadline.Add(time.Nanosecond), false, false},
		{"context_failed", deadline.Add(-time.Nanosecond), true, false},
		{"missing_return", time.Time{}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := repository.GuestOriginalCallerReturn{OriginalDeadline: deadline, DriverReturnedAt: tc.returned, OriginalContextFailed: tc.contextFailed}
			if originalGuestCallerClosedBeforeDeadlineV2(c) != tc.want {
				t.Fatal("late/failed original caller was relabeled normal")
			}
		})
	}
	const private = "PRIVATE_FRAME_AND_CALLER_BODY"
	r := repository.GuestRetirementForward{ID: "admission", RootAdmissionID: "root", RetirementRequestID: "original-retirement", Stage: "admitted", OriginalIntentWire: []byte(private), FailedRun: []byte(private), Issuer: private}
	out := guestRetirementForwardResult(r)
	wire, err := json.Marshal(out)
	if err != nil || strings.Contains(string(wire), private) || len(out) != 8 || out["request_id"] != r.RetirementRequestID || out["retirement_forward_id"] != r.ID || out["root_admission_id"] != r.RootAdmissionID || out["original_failure_preserved"] != true || out["normal_guest_success"] != false || out["guest_command_replayed"] != false || out["native_destroy_sent"] != false {
		t.Fatal("original failure was promoted or private frame escaped", err, out)
	}
}

// Function arguments model only the orchestration boundary. These checks make
// no adapter, Guest, delete, confirmation or native qualification claim.
func TestGuestRetirementForwardFinishOrderingAndOriginalBudgets(t *testing.T) {
	for _, name := range []string{"pending_then_off", "known_settled", "known_confirmed", "unknown_issued", "uncertain_settlement", "incomplete_settlement", "foreign_read_error", "inventory_refusal", "floor_refusal", "completion_lost", "insufficient_original_budget", "no_original_deadline"} {
		t.Run(name, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			if name == "insufficient_original_budget" {
				parent, cancel = context.WithTimeout(context.Background(), 59*time.Second)
				defer cancel()
			}
			if name == "no_original_deadline" {
				parent = context.Background()
			}
			parentDeadline, _ := parent.Deadline()
			calls := []string{}
			offs, completions := 0, 0
			known := name == "known_settled" || name == "known_confirmed" || name == "unknown_issued" || name == "uncertain_settlement" || name == "incomplete_settlement"
			receipt := model.CapacityMutationReceipt{Grant: model.CapacityMutationGrant{GrantID: "original-owned-destroy", State: "settled"}, Outcome: "accepted", TransportCompleted: true}
			if name == "known_confirmed" {
				receipt.Grant.State = "confirmed"
			}
			if name == "unknown_issued" {
				receipt.Grant.State = "issued"
			}
			if name == "uncertain_settlement" {
				receipt.Outcome = "uncertain"
			}
			if name == "incomplete_settlement" {
				receipt.TransportCompleted = false
			}
			checkPrepare := func(ctx context.Context) {
				t.Helper()
				want := parentDeadline.Add(-60 * time.Second)
				if name == "known_confirmed" {
					want = parentDeadline
				}
				got, ok := ctx.Deadline()
				if !ok || !got.Equal(want) || ctx.Err() != nil {
					t.Fatal("preparation extended the actual finish budget or consumed destroy reserve", got, want)
				}
			}
			_, err := finishGuestRetirementForwardWithCalls(parent, guestRetirementForwardFinishCalls{
				receipt: func(context.Context) (model.CapacityMutationReceipt, bool, error) {
					calls = append(calls, "receipt")
					return receipt, known, nil
				},
				off: func(ctx context.Context) error {
					calls = append(calls, "off")
					checkPrepare(ctx)
					offs++
					if name == "foreign_read_error" {
						return errors.New("arbitrary-not-pending")
					}
					if name == "pending_then_off" && offs == 1 {
						return repository.ErrGuestRetirementForwardNativePending
					}
					return nil
				},
				inventory: func(ctx context.Context) error {
					calls = append(calls, "inventory")
					checkPrepare(ctx)
					if name == "inventory_refusal" {
						return errors.New("inventory")
					}
					return nil
				},
				floor: func(ctx context.Context) error {
					calls = append(calls, "floor")
					checkPrepare(ctx)
					if name == "floor_refusal" {
						return errors.New("floor")
					}
					return nil
				},
				complete: func(ctx context.Context, got model.CapacityMutationReceipt, found bool) (any, error) {
					calls = append(calls, "complete")
					completions++
					d, ok := ctx.Deadline()
					if !ok || !d.Equal(parentDeadline) || found != known || !reflect.DeepEqual(got, receipt) {
						t.Fatal("completion replaced original context/receipt")
					}
					if name == "completion_lost" {
						return nil, errors.New("lost original completion")
					}
					return nil, nil
				},
			})
			want := []string{"receipt", "off", "inventory", "floor", "complete"}
			success := true
			switch name {
			case "pending_then_off":
				want = []string{"receipt", "off", "off", "inventory", "floor", "complete"}
			case "known_settled", "known_confirmed":
				want = []string{"receipt", "inventory", "floor", "complete"}
			case "unknown_issued", "uncertain_settlement", "incomplete_settlement", "insufficient_original_budget", "no_original_deadline":
				want = []string{"receipt"}
				success = false
			case "foreign_read_error":
				want = []string{"receipt", "off"}
				success = false
			case "inventory_refusal":
				want = []string{"receipt", "off", "inventory"}
				success = false
			case "floor_refusal":
				want = []string{"receipt", "off", "inventory", "floor"}
				success = false
			case "completion_lost":
				success = false
			}
			if !reflect.DeepEqual(calls, want) || completions > 1 || (err == nil) != success {
				t.Fatal("forward ordering, known-only read continuation or once rule changed", calls, want, err)
			}
		})
	}
}
