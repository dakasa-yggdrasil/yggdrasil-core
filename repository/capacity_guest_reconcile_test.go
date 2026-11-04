package repository

import (
	"context"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Simulate a context whose cancellation notification is delayed; absolute
// owner expiry remains independently authoritative before any SQL/effect.
type guestReconcileDelayedCancellation struct {
	context.Context
	expiry time.Time
}

func TestOriginalGuestReconcileMaintenanceIsSourceClassified(t *testing.T) {
	for _, name := range []string{"legacy", "source_refresh", "absent", "caller_opcode_only", "provision", "foreign_step", "foreign_operation"} {
		t.Run(name, func(t *testing.T) {
			s := CapacityStore{}
			step := model.WorkflowStepSpec{ID: "refresh-original-membership", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: capacity.CompleteOriginalGuestOperation}}
			if name != "absent" {
				s = s.WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
			}
			switch name {
			case "legacy":
				step.Use.Operation = GuestNotifyMaintenanceOperation
				s = s.WithOriginalGuestNotifyCanary(step, capacity.CurrentGuestCoreSource())
			case "source_refresh", "provision", "foreign_step", "foreign_operation":
				mode := "refresh"
				if name == "provision" {
					mode = "provision"
				}
				if name == "foreign_step" {
					step.ID = "other"
				}
				if name == "foreign_operation" {
					step.Use.Operation = capacity.PlanOriginalGuestOperation
				}
				s = s.WithOriginalGuestReconcile(model.Manifest{}, step, capacity.CurrentGuestCoreSource(), mode, "", model.CapacityVMFleetInventory{}, model.CapacityMetricRangeObservation{})
			}
			if s.guestNotifyMaintenanceOrigin() != (name == "legacy" || name == "source_refresh") {
				t.Fatal("caller/mode/foreign step reclassified as maintenance")
			}
		})
	}
}

func (c guestReconcileDelayedCancellation) Deadline() (time.Time, bool) { return c.expiry, true }
func (c guestReconcileDelayedCancellation) Err() error                  { return nil }

func TestOriginalGuestReconcileRequiresLiveOriginalOwner(t *testing.T) {
	for _, mode := range []string{"no_deadline", "expired_without_notification", "canceled", "live"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			cancel := func() {}
			switch mode {
			case "expired_without_notification":
				ctx = guestReconcileDelayedCancellation{context.Background(), time.Now().Add(-time.Millisecond)}
			case "canceled":
				ctx, cancel = context.WithTimeout(ctx, time.Second)
				cancel()
			case "live":
				ctx, cancel = context.WithTimeout(ctx, time.Second)
			}
			defer cancel()
			if guestReconcileLive(ctx) != (mode == "live") {
				t.Fatal("expiry depends on scheduled context notification")
			}
		})
	}
}

func TestOriginalGuestReconcileCannotSupplyAbsentSQLAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	store := CapacityStore{}
	if _, _, err := store.OriginalGuestReconcileMembers(ctx, model.Manifest{}); err == nil {
		t.Fatal("absent original SQL/member authority accepted")
	}
	if _, err := store.AssessOriginalGuest(ctx, model.Manifest{}, model.CapacityAssessment{}); err == nil {
		t.Fatal("absent source context assessed")
	}
	if _, err := store.AdvanceOriginalGuest(ctx, model.Manifest{}, 1, 1, "invented", "promoted", model.CapacityAssessment{}); err == nil {
		t.Fatal("caller invented complete/useful/retirement authority")
	}
}
