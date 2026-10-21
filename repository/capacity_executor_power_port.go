package repository

import (
	"context"
	"database/sql"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executoractivity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executorpower"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

// ExecutorPowerDispatch is an authenticated, fixed adapter transport, not an EC2
// client in Core. No implementation or boot registration is installed by this patch.
// A transport error may hide an original redemption and must never cause retry.
type ExecutorPowerDispatch interface {
	ExecuteGrant(context.Context, executorpower.Grant) error
}

type ExecutorPowerPort struct {
	Store      CapacityStore
	Policy     model.Manifest
	AdoptionID string
	Dispatch   ExecutorPowerDispatch
}

var _ executoractivity.PowerPort = ExecutorPowerPort{}

func (p ExecutorPowerPort) checkResource(r executoractivity.ExactResource) error {
	spec, err := parseCapacityPolicy(p.Policy)
	if err != nil {
		return err
	}
	b := spec.ExecutorPowerBinding
	if b == nil || !b.Enabled || !p.Store.ExecutorPowerEnabled || !p.Store.ExecutionEnabled || !spec.ExecutionEnabled || p.Store.ExecutorActivityPrincipal != "machine:"+b.ControllerPrincipal || p.AdoptionID == "" || r.OwnershipBindingID != p.AdoptionID || r.AccountID != b.Resource.AccountID || r.Region != b.Resource.Region || r.InstanceID != b.Resource.InstanceID {
		return executorpower.ErrDenied
	}
	return nil
}
func (p ExecutorPowerPort) Observe(ctx context.Context, r executoractivity.ExactResource) (executoractivity.PowerSnapshot, error) {
	if err := p.checkResource(r); err != nil {
		return executoractivity.PowerSnapshot{}, err
	}
	if p.Store.ExecutorPowerObserver == nil {
		return executoractivity.PowerSnapshot{}, executorpower.ErrDenied
	}
	spec, err := parseCapacityPolicy(p.Policy)
	if err != nil {
		return executoractivity.PowerSnapshot{}, err
	}
	o, err := p.Store.ExecutorPowerObserver.Observe(ctx, spec.ExecutorPowerBinding.Resource)
	if err != nil {
		return executoractivity.PowerSnapshot{}, err
	}
	err = p.Store.powerTransaction(ctx, p.Policy, false, func(tx *sql.Tx, spec model.CapacityPolicySpec, scope executorpower.Scope, now time.Time) error {
		a, e := loadPowerAdoption(ctx, tx, *spec.ExecutorPowerBinding, scope)
		if e != nil {
			return e
		}
		if a.ID != p.AdoptionID {
			return executorpower.ErrDenied
		}
		return executorpower.CheckObservation(*spec.ExecutorPowerBinding, o, now)
	})
	if err != nil {
		return executoractivity.PowerSnapshot{}, err
	}
	return executoractivity.PowerSnapshot{Resource: r, State: o.State, BootID: o.BootID, ObservedAt: o.ObservedAt}, nil
}
func (p ExecutorPowerPort) Execute(ctx context.Context, c executoractivity.PowerCommand) error {
	if err := p.checkResource(c.Resource); err != nil {
		return err
	}
	if p.Dispatch == nil {
		return executorpower.ErrDenied
	}
	g, err := p.Store.IssueExecutorPower(ctx, p.Policy, c.ID)
	if err != nil {
		return err
	}
	if g.Action != c.Action || g.CommandID != c.ID || g.AdoptionID != p.AdoptionID {
		return executorpower.ErrDenied
	}
	return p.Dispatch.ExecuteGrant(ctx, g) // Never retried, including on lost return.
}
func (p ExecutorPowerPort) Settlement(ctx context.Context, c executoractivity.PowerCommand) (executoractivity.PowerSettlement, error) {
	if err := p.checkResource(c.Resource); err != nil {
		return executoractivity.PowerSettlement{}, err
	}
	var grant executorpower.Grant
	err := p.Store.powerTransaction(ctx, p.Policy, false, func(tx *sql.Tx, spec model.CapacityPolicySpec, scope executorpower.Scope, _ time.Time) error {
		a, e := loadPowerAdoption(ctx, tx, *spec.ExecutorPowerBinding, scope)
		if e != nil {
			return e
		}
		if a.ID != p.AdoptionID {
			return executorpower.ErrDenied
		}
		var raw []byte
		var sqlState string
		if e = tx.QueryRowContext(ctx, `SELECT state,grant_record FROM public.capacity_mutation_grants WHERE grant_record->>'authority_kind'=$1 AND grant_record->>'command_id'=$2 AND grant_record->>'adoption_id'=$3 FOR UPDATE`, executorpower.Kind, c.ID, p.AdoptionID).Scan(&sqlState, &raw); e != nil {
			return e
		}
		grant, e = decodePowerGrant(raw)
		if e != nil {
			return e
		}
		if grant.State != sqlState {
			return executorpower.ErrDenied
		}
		if grant.Scope != scope || grant.Action != c.Action || grant.CommandID != c.ID {
			return executorpower.ErrDenied
		}
		return nil
	})
	if err != nil {
		return executoractivity.PowerSettlement{}, err
	}
	if (grant.State == "rejected" || grant.State == "expired") && grant.Outcome == "rejected_before_send" && grant.AttemptID == "" {
		return executoractivity.PowerSettlement{CommandID: c.ID, Resource: c.Resource, Action: c.Action, OriginalInvocationJoined: true, State: "rejected_no_effect"}, nil
	}
	if grant.State != "confirmed" {
		if grant.State != "settled" || grant.Outcome != "accepted" {
			return executoractivity.PowerSettlement{}, executorpower.ErrUnknown
		}
		grant, err = p.Store.ConfirmExecutorPower(ctx, p.Policy, grant.ID)
		if err != nil {
			return executoractivity.PowerSettlement{}, err
		}
	}
	return executoractivity.PowerSettlement{CommandID: c.ID, Resource: c.Resource, Action: c.Action, OriginalInvocationJoined: true, State: "succeeded"}, nil
}
