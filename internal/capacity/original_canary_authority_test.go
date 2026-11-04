package capacity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// These are source protocol tests. A nil-returning callback does not prove
// actual Core SQL, machine RBAC, a current dispatch or a native lease.
func sourceCanaryAuthorityScope() OriginalCanaryAuthorityScope {
	return OriginalCanaryAuthorityScope{
		WindowID: uuid.NewString(), ScopeSHA256: strings.Repeat("a", 64),
		PolicyID: uuid.NewString(), PolicyChecksum: strings.Repeat("b", 64),
		WorkflowID: uuid.NewString(), WorkflowChecksum: strings.Repeat("c", 64),
		DispatchJobID: uuid.NewString(), DispatchFence: 1, IntentGeneration: 1, IntentFence: 1,
		LeaseOwner: uuid.NewString(), ExecutorID: uuid.NewString(), MachinePrincipalID: "source-protocol-only",
		Deadline: time.Now().UTC().Add(30 * time.Second),
	}
}

func TestOriginalCanaryAuthorityProtocol(t *testing.T) {
	t.Run("missing_original_deadline_or_guard_cannot_register", func(t *testing.T) {
		r := NewOriginalCanaryAuthorityRegistry()
		var calls int
		guard := func(context.Context) error { calls++; return nil }
		if token, release, err := r.Register(context.Background(), sourceCanaryAuthorityScope(), guard); err == nil || token.HeaderValue() != "" || release != nil || calls != 0 {
			t.Fatal("deadline-free owner created authority")
		}
		owner, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		if token, release, err := r.Register(owner, sourceCanaryAuthorityScope(), nil); err == nil || token.HeaderValue() != "" || release != nil {
			t.Fatal("absent original source guard created authority")
		}
	})
	t.Run("permission_scope_never_claims_human_or_capacity_completion", func(t *testing.T) {
		owner, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		r := NewOriginalCanaryAuthorityRegistry()
		scope := sourceCanaryAuthorityScope()
		var calls int
		token, release, err := r.Register(owner, scope, func(context.Context) error { calls++; return nil })
		if err != nil || release == nil || calls != 1 {
			t.Fatal("source-only registry setup refused")
		}
		defer release()
		reply, err := r.Observe(owner, token.HeaderValue(), scope.ScopeSHA256)
		if err != nil || calls != 3 || reply.Schema != OriginalCanaryAuthoritySchema || reply.Scope != scope || !reply.OriginalLiveLeaseVerified || !reply.CurrentMachineRBACVerified || reply.HumanSessionVerified || reply.UsefulCapacityKnown || reply.FullTransitionQualified {
			t.Fatal("source-only permission shape or before/after guard differs")
		}
		for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x"} {
			if strings.Contains(fmt.Sprintf(format, token), token.HeaderValue()) {
				t.Fatal("private bearer escaped token formatting")
			}
		}
		encoded, err := json.Marshal(token)
		if err != nil || string(encoded) != "null" || strings.Contains(string(encoded), token.HeaderValue()) {
			t.Fatal("private bearer escaped JSON")
		}
	})
	t.Run("foreign_scope_release_and_fresh_process_refuse_without_guard", func(t *testing.T) {
		owner, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		r := NewOriginalCanaryAuthorityRegistry()
		scope := sourceCanaryAuthorityScope()
		calls := 0
		token, release, err := r.Register(owner, scope, func(context.Context) error { calls++; return nil })
		if err != nil {
			t.Fatal("source-only registry setup refused")
		}
		defer release()
		if _, err := r.Observe(owner, token.HeaderValue(), strings.Repeat("d", 64)); err == nil || calls != 1 {
			t.Fatal("foreign immutable scope reached original source guard")
		}
		if _, err := NewOriginalCanaryAuthorityRegistry().Observe(owner, token.HeaderValue(), scope.ScopeSHA256); err == nil || calls != 1 {
			t.Fatal("new process adopted original permission")
		}
		release()
		if _, err := r.Observe(owner, token.HeaderValue(), scope.ScopeSHA256); err == nil || calls != 1 {
			t.Fatal("revoked permission reached original source guard")
		}
	})
	t.Run("captured_original_deadline_cannot_be_extended", func(t *testing.T) {
		owner, cancel := context.WithTimeout(t.Context(), 20*time.Second)
		defer cancel()
		scope := sourceCanaryAuthorityScope()
		calls := 0
		if token, release, err := NewOriginalCanaryAuthorityRegistry().Register(owner, scope, func(context.Context) error { calls++; return nil }); err == nil || token.HeaderValue() != "" || release != nil || calls != 0 {
			t.Fatal("scope extended its original owner deadline")
		}
	})
	t.Run("same_live_dispatch_never_registers_second_bearer", func(t *testing.T) {
		owner, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		r := NewOriginalCanaryAuthorityRegistry()
		scope := sourceCanaryAuthorityScope()
		_, release, err := r.Register(owner, scope, func(context.Context) error { return nil })
		if err != nil {
			t.Fatal("source-only registry setup refused")
		}
		defer release()
		scope.WindowID = uuid.NewString()
		if token, release, err := r.Register(owner, scope, func(context.Context) error { return nil }); err == nil || token.HeaderValue() != "" || release != nil {
			t.Fatal("same original live dispatch created second bearer")
		}
	})
}

func TestOriginalCanaryAuthorityHeldOriginalGuard(t *testing.T) {
	base, deadlineCancel := context.WithTimeout(t.Context(), time.Minute)
	defer deadlineCancel()
	owner, cancelCause := context.WithCancelCause(base)
	defer cancelCause(nil)
	r := NewOriginalCanaryAuthorityRegistry()
	scope := sourceCanaryAuthorityScope()
	arrived, unblock := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	token, revoke, err := r.Register(owner, scope, func(context.Context) error {
		if calls.Add(1) == 3 {
			close(arrived)
			<-unblock
		}
		return nil
	})
	if err != nil {
		t.Fatal("source-only registry setup refused")
	}
	defer revoke()
	type outcome struct {
		reply OriginalCanaryAuthorityReply
		err   error
	}
	returned := make(chan outcome, 1)
	go func() {
		reply, err := r.Observe(base, token.HeaderValue(), scope.ScopeSHA256)
		returned <- outcome{reply: reply, err: err}
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		close(unblock)
		t.Fatal("actual original final guard did not reach held stage")
	}
	privateCause := errors.New("private-original-canary-owner-cause")
	cancelCause(privateCause)
	select {
	case <-returned:
		close(unblock)
		t.Fatal("pending original guard became returned permission")
	default:
	}
	close(unblock)
	select {
	case out := <-returned:
		if out.reply != (OriginalCanaryAuthorityReply{}) || !errors.Is(out.err, privateCause) || !errors.Is(out.err, ErrOriginalCanaryAuthority) || calls.Load() != 3 {
			t.Fatal("late original guard lost owner cause or invented permission")
		}
		for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x"} {
			if strings.Contains(fmt.Sprintf(format, out.err), privateCause.Error()) {
				t.Fatal("private original cause escaped formatting")
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("actual original guard return was not joined")
	}
}
