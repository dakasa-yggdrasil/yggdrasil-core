// Package capacityguestprovider owns one original source-selected provisioning
// invocation. It supplies no registry approval, SQL authority or native result.
package capacityguestprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrOriginal = errors.New("original Guest provider invocation unavailable")

type Scope struct {
	InvocationID              string
	PolicyID                  string
	PolicyChecksum            string
	WorkflowID                string
	WorkflowChecksum          string
	StepID                    string
	StepTimeoutSeconds        int
	ProvisioningBudgetSeconds int
	MemberBindingName         string
	Slot                      int
	Generation                int64
	Fence                     int64
	LeaseOwner                string
	ExecutorID                string
	CoreSourceCommit          string
	ProfileSHA256             string
	Binding                   model.CapacityMutationBinding
}

// Supplier is implemented by the reviewed source constructor. Create owns its
// original transport return; Read is a separate native observation. The owner
// never turns Read into a successful original create or retries an uncertain send.
type Supplier interface {
	Prepare(context.Context, int) error
	Create(context.Context, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityMutationProof, error)
	Read(context.Context, model.CapacityMutationGrant) (model.CapacityMutationProof, error)
}

type invocationKey struct{}
type slotState struct {
	preparing       bool
	prepared        bool
	attempted       bool
	returned        bool
	grant           model.CapacityMutationGrant
	preregistration model.CapacityGuestOriginalProvisioningPreregistration
}

type Invocation struct {
	ctx      context.Context
	scope    Scope
	supplier Supplier
	mu       sync.Mutex
	slots    map[int]*slotState
}

func digest(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}
func identity(s string) bool {
	id, e := uuid.Parse(s)
	return e == nil && id != uuid.Nil && id.String() == s
}

// New freezes the binding before any supplier call. The caller must already
// have checked the compiled approval, current policy/workflow and private lease.
// The returned context retains the original cancellation and absolute deadline.
func New(parent context.Context, scope Scope, supplier Supplier) (*Invocation, error) {
	if parent == nil || supplier == nil || reflect.ValueOf(supplier).Kind() == reflect.Pointer && reflect.ValueOf(supplier).IsNil() || parent.Err() != nil || !identity(scope.InvocationID) || !identity(scope.PolicyID) || !identity(scope.WorkflowID) || !identity(scope.ExecutorID) || scope.InvocationID != scope.ExecutorID || scope.Generation < 1 || scope.Fence < 1 || !identity(scope.LeaseOwner) || !digest(scope.PolicyChecksum, 64) || !digest(scope.WorkflowChecksum, 64) || !digest(scope.CoreSourceCommit, 40) || !digest(scope.ProfileSHA256, 64) || scope.StepID == "" || scope.StepTimeoutSeconds < scope.ProvisioningBudgetSeconds || scope.StepTimeoutSeconds > 86400 || scope.ProvisioningBudgetSeconds < 1 || scope.MemberBindingName == "" || scope.Slot < 1 || scope.Slot > 64 || scope.Binding.Name == "" || scope.Binding.EnsureCapability == "" || scope.Binding.MaxSlots < scope.Slot || scope.Binding.MaxSlots > 64 || len(scope.Binding.Slots) < 1 {
		return nil, ErrOriginal
	}
	deadline, ok := parent.Deadline()
	if !ok || !time.Now().Before(deadline) {
		return nil, ErrOriginal
	}
	raw, err := json.Marshal(scope)
	if err != nil {
		return nil, ErrOriginal
	}
	var frozen Scope
	if json.Unmarshal(raw, &frozen) != nil {
		return nil, ErrOriginal
	}
	seen := map[int]bool{}
	for _, slot := range frozen.Binding.Slots {
		if slot.Slot < 1 || slot.Slot > frozen.Binding.MaxSlots || seen[slot.Slot] || slot.DesiredSpec == nil || !digest(slot.DesiredSpecSHA256, 64) {
			return nil, ErrOriginal
		}
		seen[slot.Slot] = true
		raw, err := json.Marshal(slot.DesiredSpec)
		if err != nil {
			return nil, ErrOriginal
		}
		// The existing mutation protocol sorts the closed projection's keys.
		// Struct field order is not that canonical request digest.
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return nil, ErrOriginal
		}
		raw, err = json.Marshal(fields)
		if err != nil {
			return nil, ErrOriginal
		}
		hash := sha256.Sum256(raw)
		if hex.EncodeToString(hash[:]) != slot.DesiredSpecSHA256 {
			return nil, ErrOriginal
		}
	}
	if !seen[frozen.Slot] {
		return nil, ErrOriginal
	}
	i := &Invocation{scope: frozen, supplier: supplier, slots: map[int]*slotState{}}
	i.ctx = context.WithValue(parent, invocationKey{}, i)
	return i, nil
}
func (i *Invocation) Context() context.Context {
	if i == nil {
		return nil
	}
	return i.ctx
}
func (i *Invocation) check(ctx context.Context) error {
	if i == nil || ctx == nil || ctx.Value(invocationKey{}) != i || ctx.Err() != nil || i.ctx.Err() != nil {
		return ErrOriginal
	}
	own, ok := i.ctx.Deadline()
	current, currentOK := ctx.Deadline()
	if !ok || !currentOK || current.After(own) || !time.Now().Before(current) || !time.Now().Before(own) {
		return ErrOriginal
	}
	return nil
}
func (i *Invocation) approved(slot int) bool {
	if slot != i.scope.Slot {
		return false
	}
	for _, s := range i.scope.Binding.Slots {
		if s.Slot == slot {
			return true
		}
	}
	return false
}
func (i *Invocation) Prepare(ctx context.Context, slot int) error {
	if i.check(ctx) != nil || !i.approved(slot) {
		return ErrOriginal
	}
	i.mu.Lock()
	if i.slots[slot] != nil {
		i.mu.Unlock()
		return ErrOriginal
	}
	state := &slotState{preparing: true}
	i.slots[slot] = state
	i.mu.Unlock()
	err := i.supplier.Prepare(ctx, slot)
	joined := errors.Join(err, i.check(ctx))
	i.mu.Lock()
	state.preparing = false
	state.prepared = joined == nil
	i.mu.Unlock()
	return joined
}
func (i *Invocation) matches(g model.CapacityMutationGrant, p model.CapacityGuestOriginalProvisioningPreregistration) bool {
	b, s := i.scope.Binding, i.scope
	if !identity(g.GrantID) || g.State != "issued" || g.CompensationOf != "" || g.BindingName != b.Name || g.Capability != b.EnsureCapability || g.IntegrationInstanceID != b.IntegrationInstanceID || g.ScopeChecksum != b.ScopeChecksum || g.ProfileName != b.ProfileName || g.ExpectedResourceID != "" || g.ExpectedResourceCreatedAt != "" || g.Slot != s.Slot || g.Slot != p.Slot || p.Schema != "original_guest_provisioning_preregistration_v1" || p.BindingName != s.MemberBindingName || p.OriginalCreateGrantID != g.GrantID || p.OriginalCreateRequestSHA256 != g.RequestSHA256 || p.PolicyID != s.PolicyID || p.PolicyChecksum != s.PolicyChecksum || p.WorkflowID != s.WorkflowID || p.WorkflowChecksum != s.WorkflowChecksum || p.OriginalWorkflowStepID != s.StepID || p.OriginalWorkflowStepTimeoutSeconds != s.StepTimeoutSeconds || p.Generation != s.Generation || p.Fence != s.Fence || p.LeaseOwner != s.LeaseOwner || p.ExecutorID != s.ExecutorID || p.CoreSourceCommit != s.CoreSourceCommit || p.ProfileManifestSHA256 != s.ProfileSHA256 || !identity(p.PreregistrationID) || !digest(p.NonceSHA256, 64) || p.ReservedAt.IsZero() || p.ReservedAt.After(time.Now()) || !p.OriginalDeadline.After(p.ReservedAt) || !time.Now().Before(g.ExpiresAt) {
		return false
	}
	deadline, _ := i.ctx.Deadline()
	expected := p.ReservedAt.Add(time.Duration(s.ProvisioningBudgetSeconds) * time.Second)
	if deadline.Before(expected) {
		expected = deadline
	}
	if !p.OriginalWorkflowContextDeadline.Equal(deadline) || !p.OriginalDeadline.Equal(expected) || !time.Now().Before(p.OriginalDeadline) {
		return false
	}
	for _, slot := range b.Slots {
		if slot.Slot == g.Slot {
			return slot.DesiredSpecSHA256 == g.RequestSHA256
		}
	}
	return false
}
func (i *Invocation) Create(ctx context.Context, g model.CapacityMutationGrant, p model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityMutationProof, error) {
	if i.check(ctx) != nil || !i.matches(g, p) {
		return model.CapacityMutationProof{}, ErrOriginal
	}
	deadline, _ := ctx.Deadline()
	if deadline.After(p.OriginalDeadline) {
		return model.CapacityMutationProof{}, ErrOriginal
	}
	i.mu.Lock()
	state := i.slots[g.Slot]
	if state == nil || !state.prepared || state.preparing || state.attempted {
		i.mu.Unlock()
		return model.CapacityMutationProof{}, ErrOriginal
	}
	state.attempted = true
	state.grant = g
	state.preregistration = p
	i.mu.Unlock()
	// Ownership is consumed before the original call. A panic/error/cancellation
	// cannot reopen it, and no goroutine outlives this caller on our behalf.
	proof, err := i.supplier.Create(ctx, g, p)
	if joined := errors.Join(err, i.check(ctx)); joined != nil {
		return model.CapacityMutationProof{}, joined
	}
	i.mu.Lock()
	state.returned = true
	i.mu.Unlock()
	return proof, nil
}
func (i *Invocation) Read(ctx context.Context, g model.CapacityMutationGrant) (model.CapacityMutationProof, error) {
	if i.check(ctx) != nil {
		return model.CapacityMutationProof{}, ErrOriginal
	}
	i.mu.Lock()
	state := i.slots[g.Slot]
	deadline, _ := ctx.Deadline()
	matched := state != nil && state.returned && reflect.DeepEqual(state.grant, g) && !deadline.After(state.preregistration.OriginalDeadline) && time.Now().Before(state.preregistration.OriginalDeadline)
	i.mu.Unlock()
	if !matched {
		return model.CapacityMutationProof{}, ErrOriginal
	}
	proof, err := i.supplier.Read(ctx, g)
	if joined := errors.Join(err, i.check(ctx)); joined != nil {
		return model.CapacityMutationProof{}, joined
	}
	return proof, nil
}

// OriginalReturned reports only this local invocation's successful caller
// return. It carries no SQL, registry, provider or product authority.
func (i *Invocation) OriginalReturned(ctx context.Context, g model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) bool {
	if i.check(ctx) != nil {
		return false
	}
	deadline, _ := ctx.Deadline()
	i.mu.Lock()
	defer i.mu.Unlock()
	state := i.slots[g.Slot]
	return state != nil && state.returned && reflect.DeepEqual(state.grant, g) && reflect.DeepEqual(state.preregistration, pre) && !deadline.After(pre.OriginalDeadline) && time.Now().Before(pre.OriginalDeadline)
}
