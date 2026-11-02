package capacityguestprovider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// These doubles test invocation ownership only. They grant no registry entry,
// native transport, SQL authority, installation or production qualification.
type testSupplier struct {
	prepares atomic.Int32
	creates  atomic.Int32
	reads    atomic.Int32
	prepare  func(context.Context) error
	create   func(context.Context) error
	read     func(context.Context) error
}

func (s *testSupplier) Prepare(ctx context.Context, _ int) error {
	s.prepares.Add(1)
	if s.prepare != nil {
		return s.prepare(ctx)
	}
	return nil
}
func (s *testSupplier) Create(ctx context.Context, _ model.CapacityMutationGrant, _ model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityMutationProof, error) {
	s.creates.Add(1)
	if s.create != nil {
		return model.CapacityMutationProof{}, s.create(ctx)
	}
	return model.CapacityMutationProof{ResourceID: "original-unit-result"}, nil
}
func (s *testSupplier) Read(ctx context.Context, _ model.CapacityMutationGrant) (model.CapacityMutationProof, error) {
	s.reads.Add(1)
	if s.read != nil {
		return model.CapacityMutationProof{}, s.read(ctx)
	}
	return model.CapacityMutationProof{ResourceID: "fresh-unit-read"}, nil
}

func fixture(t *testing.T, supplier Supplier) (*Invocation, Scope, model.CapacityMutationGrant, model.CapacityGuestOriginalProvisioningPreregistration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	id := uuid.NewString()
	spec := &model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: "ensure_server", IntegrationInstanceID: uuid.NewString(), ScopeChecksum: strings.Repeat("b", 64), ProfileName: "reviewed-slot", Slot: 1}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]json.RawMessage
	if err := json.Unmarshal(raw, &projection); err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	scope := Scope{InvocationID: id, ExecutorID: id, PolicyID: uuid.NewString(), PolicyChecksum: strings.Repeat("a", 64), WorkflowID: uuid.NewString(), WorkflowChecksum: strings.Repeat("c", 64), StepID: "original-create", StepTimeoutSeconds: 30, ProvisioningBudgetSeconds: 30, MemberBindingName: "member-one", Slot: 1, Generation: 3, Fence: 7, LeaseOwner: uuid.NewString(), CoreSourceCommit: strings.Repeat("d", 40), ProfileSHA256: strings.Repeat("e", 64), Binding: model.CapacityMutationBinding{Name: "servers", EnsureCapability: "ensure_server", IntegrationInstanceID: spec.IntegrationInstanceID, ScopeChecksum: spec.ScopeChecksum, ProfileName: spec.ProfileName, MaxSlots: 2, Slots: []model.CapacityMutationSlotBinding{{Slot: 1, DesiredSpec: spec, DesiredSpecSHA256: digest}}}}
	i, err := New(ctx, scope, supplier)
	if err != nil {
		t.Fatal(err)
	}
	deadline, _ := ctx.Deadline()
	reserved := time.Now().UTC()
	g := model.CapacityMutationGrant{GrantID: uuid.NewString(), BindingName: scope.Binding.Name, IntegrationInstanceID: spec.IntegrationInstanceID, ScopeChecksum: spec.ScopeChecksum, ProfileName: spec.ProfileName, Slot: 1, Capability: spec.Capability, RequestSHA256: digest, ExpiresAt: deadline, State: "issued"}
	pre := model.CapacityGuestOriginalProvisioningPreregistration{Schema: "original_guest_provisioning_preregistration_v1", PreregistrationID: uuid.NewString(), BindingName: scope.MemberBindingName, OriginalCreateGrantID: g.GrantID, OriginalCreateRequestSHA256: digest, NonceSHA256: strings.Repeat("f", 64), ProfileManifestSHA256: scope.ProfileSHA256, PolicyID: scope.PolicyID, PolicyChecksum: scope.PolicyChecksum, WorkflowID: scope.WorkflowID, WorkflowChecksum: scope.WorkflowChecksum, OriginalWorkflowStepID: scope.StepID, OriginalWorkflowStepTimeoutSeconds: scope.StepTimeoutSeconds, OriginalWorkflowContextDeadline: deadline, CoreSourceCommit: scope.CoreSourceCommit, Generation: scope.Generation, Fence: scope.Fence, LeaseOwner: scope.LeaseOwner, ExecutorID: scope.ExecutorID, Slot: 1, ReservedAt: reserved, OriginalDeadline: deadline}
	return i, scope, g, pre
}

func TestInvocationConcurrentCreateIsConsumedBeforeOriginalCall(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	supplier := &testSupplier{create: func(context.Context) error { close(entered); <-release; return nil }}
	i, _, g, pre := fixture(t, supplier)
	if err := i.Prepare(i.Context(), 1); err != nil {
		t.Fatal(err)
	}
	const contenders = 20
	results := make(chan error, contenders)
	var wg sync.WaitGroup
	for n := 0; n < contenders; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := i.Create(i.Context(), g, pre); results <- err }()
	}
	<-entered
	if i.OriginalReturned(i.Context(), g, pre) {
		t.Fatal("original return appeared while supplier was still running")
	}
	if _, err := i.Read(i.Context(), g); !errors.Is(err, ErrOriginal) {
		t.Fatal("read accepted before original return")
	}
	close(release)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 || supplier.creates.Load() != 1 {
		t.Fatalf("successful owners=%d original sends=%d", successes, supplier.creates.Load())
	}
	if !i.OriginalReturned(i.Context(), g, pre) {
		t.Fatal("actual successful original return missing")
	}
	if _, err := i.Read(i.Context(), g); err != nil {
		t.Fatal(err)
	}
}

func TestInvocationUncertainCreateCannotRetryOrBecomeReadSuccess(t *testing.T) {
	lost := errors.New("original reply lost")
	supplier := &testSupplier{create: func(context.Context) error { return lost }}
	i, _, g, pre := fixture(t, supplier)
	if err := i.Prepare(i.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Create(i.Context(), g, pre); !errors.Is(err, lost) {
		t.Fatal("original error lost", err)
	}
	if _, err := i.Create(i.Context(), g, pre); !errors.Is(err, ErrOriginal) {
		t.Fatal("uncertain create reopened")
	}
	if _, err := i.Read(i.Context(), g); !errors.Is(err, ErrOriginal) {
		t.Fatal("readback manufactured original success")
	}
	if supplier.creates.Load() != 1 || supplier.reads.Load() != 0 {
		t.Fatal("supplier invoked after uncertain original")
	}
	if i.OriginalReturned(i.Context(), g, pre) {
		t.Fatal("uncertain original manufactured caller return")
	}
}

func TestInvocationCancellationAfterOriginalReturnStillConsumesSend(t *testing.T) {
	supplier := &testSupplier{}
	i, _, g, pre := fixture(t, supplier)
	ctx, cancel := context.WithCancel(i.Context())
	supplier.create = func(context.Context) error { cancel(); return nil }
	if err := i.Prepare(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Create(ctx, g, pre); !errors.Is(err, ErrOriginal) {
		t.Fatal("late success accepted")
	}
	if _, err := i.Create(i.Context(), g, pre); !errors.Is(err, ErrOriginal) {
		t.Fatal("send reopened after cancelled caller")
	}
	if _, err := i.Read(i.Context(), g); !errors.Is(err, ErrOriginal) {
		t.Fatal("cancelled create gained read authority")
	}
	if supplier.creates.Load() != 1 {
		t.Fatal("send count differs")
	}
}

func TestInvocationPanicNeverReopensOriginalCreate(t *testing.T) {
	supplier := &testSupplier{create: func(context.Context) error { panic("unit original supplier panic") }}
	i, _, g, pre := fixture(t, supplier)
	if err := i.Prepare(i.Context(), 1); err != nil {
		t.Fatal(err)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("unit panic missing")
			}
		}()
		_, _ = i.Create(i.Context(), g, pre)
	}()
	if _, err := i.Create(i.Context(), g, pre); !errors.Is(err, ErrOriginal) {
		t.Fatal("panic reopened original create")
	}
	if _, err := i.Read(i.Context(), g); !errors.Is(err, ErrOriginal) {
		t.Fatal("panic gained original read authority")
	}
	if supplier.creates.Load() != 1 {
		t.Fatal("original call repeated")
	}
}

func TestInvocationRequiresProvisioningDeadlineOnSupplierContext(t *testing.T) {
	supplier := &testSupplier{}
	i, _, g, pre := fixture(t, supplier)
	// A workflow may outlive its shorter immutable provisioning budget.
	i.scope.ProvisioningBudgetSeconds = 10
	pre.OriginalDeadline = pre.ReservedAt.Add(10 * time.Second)
	if err := i.Prepare(i.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := i.Create(i.Context(), g, pre); !errors.Is(err, ErrOriginal) {
		t.Fatal("longer workflow context reached original supplier")
	}
	original, cancel := context.WithDeadline(i.Context(), pre.OriginalDeadline)
	defer cancel()
	if _, err := i.Create(original, g, pre); err != nil {
		t.Fatal("original provisioning context refused", err)
	}
	if _, err := i.Read(i.Context(), g); !errors.Is(err, ErrOriginal) {
		t.Fatal("read extended provisioning deadline")
	}
	if _, err := i.Read(original, g); err != nil {
		t.Fatal(err)
	}
	if supplier.creates.Load() != 1 || supplier.reads.Load() != 1 {
		t.Fatal("deadline refusal reached supplier")
	}
}

func TestInvocationRejectsForeignAndExtendedContexts(t *testing.T) {
	supplier := &testSupplier{}
	i, _, g, pre := fixture(t, supplier)
	// WithoutCancel intentionally retains values while dropping the owner clock.
	extended, cancel := context.WithTimeout(context.WithoutCancel(i.Context()), time.Hour)
	defer cancel()
	for _, ctx := range []context.Context{context.Background(), extended} {
		if err := i.Prepare(ctx, 1); !errors.Is(err, ErrOriginal) {
			t.Fatal("foreign or extended context accepted")
		}
		if _, err := i.Create(ctx, g, pre); !errors.Is(err, ErrOriginal) {
			t.Fatal("foreign create accepted")
		}
	}
	if supplier.prepares.Load() != 0 || supplier.creates.Load() != 0 {
		t.Fatal("refusal reached supplier")
	}
	if err := i.Prepare(i.Context(), 1); err != nil {
		t.Fatal("valid context consumed by refusals", err)
	}
}

func TestInvocationRejectsChangedOriginalOperandsBeforeSend(t *testing.T) {
	for _, name := range []string{"grant", "scope", "workflow", "step", "member", "epoch", "nonce", "deadline", "context_deadline", "reserved_future", "expired_grant", "slot"} {
		t.Run(name, func(t *testing.T) {
			supplier := &testSupplier{}
			i, _, g, pre := fixture(t, supplier)
			if err := i.Prepare(i.Context(), 1); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "grant":
				pre.OriginalCreateGrantID = uuid.NewString()
			case "scope":
				g.ScopeChecksum = strings.Repeat("0", 64)
			case "workflow":
				pre.WorkflowChecksum = strings.Repeat("0", 64)
			case "step":
				pre.OriginalWorkflowStepID = "other-step"
			case "member":
				pre.BindingName = "other-member"
			case "epoch":
				pre.Fence++
			case "nonce":
				pre.NonceSHA256 = "invalid"
			case "deadline":
				pre.OriginalDeadline = pre.OriginalDeadline.Add(time.Second)
			case "context_deadline":
				pre.OriginalWorkflowContextDeadline = pre.OriginalWorkflowContextDeadline.Add(time.Second)
			case "reserved_future":
				pre.ReservedAt = time.Now().Add(time.Hour)
			case "expired_grant":
				g.ExpiresAt = time.Now().Add(-time.Second)
			case "slot":
				g.Slot, pre.Slot = 2, 2
			}
			if _, err := i.Create(i.Context(), g, pre); !errors.Is(err, ErrOriginal) {
				t.Fatal("changed original accepted")
			}
			if supplier.creates.Load() != 0 {
				t.Fatal("invalid operands reached supplier")
			}
		})
	}
}

func TestInvocationFreezesBindingAndRestrictsPreparedSlot(t *testing.T) {
	supplier := &testSupplier{}
	i, scope, g, pre := fixture(t, supplier)
	scope.Binding.Slots[0].DesiredSpec.NativeName = "changed-after-construction"
	scope.Binding.Slots[0].DesiredSpecSHA256 = strings.Repeat("0", 64)
	if err := i.Prepare(i.Context(), 2); !errors.Is(err, ErrOriginal) {
		t.Fatal("unselected slot prepared")
	}
	if err := i.Prepare(i.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if err := i.Prepare(i.Context(), 1); !errors.Is(err, ErrOriginal) {
		t.Fatal("slot prepared twice")
	}
	if _, err := i.Create(i.Context(), g, pre); err != nil {
		t.Fatal("caller mutation changed frozen binding", err)
	}
	other := g
	other.GrantID = uuid.NewString()
	if _, err := i.Read(i.Context(), other); !errors.Is(err, ErrOriginal) {
		t.Fatal("foreign grant read accepted")
	}
}

func TestInvocationRejectsTypedNilAndInvalidConstructor(t *testing.T) {
	supplier := &testSupplier{}
	i, scope, _, _ := fixture(t, supplier)
	var typedNil *testSupplier
	if _, err := New(i.Context(), scope, typedNil); !errors.Is(err, ErrOriginal) {
		t.Fatal("typed nil supplier accepted")
	}
	for _, name := range []string{"no_deadline", "invocation", "slot", "digest", "budget"} {
		t.Run(name, func(t *testing.T) {
			ctx := i.Context()
			copy := scope
			switch name {
			case "no_deadline":
				ctx = context.Background()
			case "invocation":
				copy.InvocationID = uuid.NewString()
			case "slot":
				copy.Slot = 2
			case "digest":
				copy.WorkflowChecksum = "bad"
			case "budget":
				copy.ProvisioningBudgetSeconds = 31
			}
			if _, err := New(ctx, copy, supplier); !errors.Is(err, ErrOriginal) {
				t.Fatal("invalid owner constructed")
			}
		})
	}
	if supplier.prepares.Load() != 0 || supplier.creates.Load() != 0 {
		t.Fatal("constructor invoked supplier")
	}
}
