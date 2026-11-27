package repository

import (
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestNativeAbortCallbackRestoresOnlyOriginalPrivateAuthorityAndKeepsLateCustody(t *testing.T) {
	f, store, _, authority, _, _ := nativeWorkerAbortPGFixture(t, 30)
	ctx := t.Context()
	a := abortPGChild(t, f, store, authority)
	permit, err := store.Begin(ctx, f.policy, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := map[string]bool{a.Execution.DestroyCapability: true}
	if !store.MachineAuthorized(ctx, a.Execution.Adapter.ManifestID, a.Execution.SDKSourceCommit, capabilities) || store.MachineAuthorized(ctx, a.Execution.Adapter.ManifestID, a.Execution.SDKSourceCommit, map[string]bool{a.Execution.EnsureCapability: true}) {
		t.Fatal("creator permission was substituted for destruction authority")
	}
	for _, fault := range []string{"binding", "instance", "source", "capability", "permit"} {
		binding, instance, source, id := a.Execution.BindingName, a.Execution.Adapter.ManifestID, a.Execution.SDKSourceCommit, permit.PermitID
		caps := capabilities
		switch fault {
		case "binding":
			binding = "foreign"
		case "instance":
			instance = uuid.NewString()
		case "source":
			source = strings.Repeat("0", 40)
		case "capability":
			caps = map[string]bool{a.Execution.EnsureCapability: true}
		case "permit":
			id = uuid.New()
		}
		if _, _, _, err := store.ResolveAbortCaller(ctx, id, binding, instance, source, caps); err == nil {
			t.Fatal("substituted callback scope resolved original authority", fault)
		}
	}
	// A request supplies neither of these private identities. Resolution must
	// restore the original immutable Source record, not trust this outer state.
	outer := store
	outer.Workers.Capacity.ExecutorID, outer.RecoveryWorkflowID = uuid.NewString(), uuid.New()
	resolved, policy, caller, err := outer.ResolveAbortCaller(ctx, permit.PermitID, a.Execution.BindingName, a.Execution.Adapter.ManifestID, a.Execution.SDKSourceCommit, capabilities)
	if err != nil || resolved.Workers.Capacity.ExecutorID != store.Workers.Capacity.ExecutorID || resolved.RecoveryWorkflowID != store.RecoveryWorkflowID || policy.ID != f.policy.ID || caller.Capability != a.Execution.DestroyCapability {
		t.Fatal("original private authority was not restored", err)
	}
	grant, err := resolved.Redeem(ctx, policy, permit.PermitID, caller)
	if err != nil || !grant.MutationPermitted || grant.SettlementToken == "" {
		t.Fatal("exact source callback could not redeem its one original right", err)
	}
	resolved.Enabled, resolved.Workers.Enabled, resolved.Workers.Capacity.ExecutionEnabled = false, false, false
	resolved.Runtime, resolved.Workers.Runtime = nil, nil
	if err := resolved.Receive(ctx, policy, caller, model.CapacityNativeWorkerAbortReceive{PermitID: permit.PermitID, BindingName: caller.BindingName, SettlementToken: grant.SettlementToken, OriginalReturn: []byte("private incomplete original"), CaptureComplete: false, ErrorClass: "ORIGINAL_TRANSPORT_UNCERTAIN"}); err != nil {
		t.Fatal("disabled or unavailable runtime erased late original custody", err)
	}
	stored := abortPGStored(t, f, permit.PermitID)
	if stored.Context.State != "unknown" || stored.Original == nil || stored.Original.SettlementToken != "" || string(stored.Original.OriginalReturn) != "private incomplete original" {
		t.Fatal("late private custody became public authority or was lost")
	}
	if _, err := resolved.Redeem(ctx, policy, permit.PermitID, caller); err == nil {
		t.Fatal("an exposed recovery right was reopened after disable")
	}
}
