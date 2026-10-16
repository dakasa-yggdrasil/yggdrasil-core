//go:build linux && nativequalification

package httpapi

import (
	"context"
	"errors"
	"testing"
	"time"
)

type refusedOriginalWorkflowOwner struct{ err error }

func (o refusedOriginalWorkflowOwner) Begin() (context.Context, func(), error) {
	return nil, nil, o.err
}

// These source lifetime checks provide no native callback, capacity or proof.
// The real supplier and same-PG readonly corpus separately own those facts.
func TestCapacityGuestOriginalAsyncOwner(t *testing.T) {
	t.Run("default_parent_is_unchanged", func(t *testing.T) {
		parent, finish, err := (&Server{}).beginOriginalGuestAsyncWorkflow()
		if err != nil || parent != context.Background() || finish == nil {
			t.Fatal("default owner changed production parent")
		}
		if _, capped := parent.Deadline(); capped {
			t.Fatal("default production parent was capped")
		}
		finish()
	})
	t.Run("same_first_deadline_is_inherited", func(t *testing.T) {
		deadline := time.Now().Add(600 * time.Second)
		original, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		owner, err := NewNativeOriginalWorkflowOwners(original)
		if err != nil {
			t.Fatal(err)
		}
		parent, finish, err := (&Server{originalGuestAsyncWorkflowOwner: owner}).beginOriginalGuestAsyncWorkflow()
		if err != nil || parent != original {
			t.Fatal("original context replaced", err)
		}
		child, cancelChild := context.WithTimeout(parent, 30*time.Minute)
		defer cancelChild()
		actual, present := child.Deadline()
		if !present || !actual.Equal(deadline) {
			t.Fatal("original deadline extended")
		}
		finish()
		if err := owner.Join(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("join_waits_same_original_goroutine_return", func(t *testing.T) {
		original, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		owner, err := NewNativeOriginalWorkflowOwners(original)
		if err != nil {
			t.Fatal(err)
		}
		_, finish, err := owner.Begin()
		if err != nil {
			t.Fatal(err)
		}
		entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() { defer close(returned); defer finish(); close(entered); <-release }()
		<-entered
		bounded, cancelBounded := context.WithTimeout(context.Background(), time.Millisecond)
		if err := owner.Join(bounded); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("pending original owner became complete", err)
		}
		cancelBounded()
		close(release)
		join, cancelJoin := context.WithTimeout(context.Background(), time.Second)
		defer cancelJoin()
		if err := owner.Join(join); err != nil {
			t.Fatal(err)
		}
		<-returned
	})
	t.Run("expired_owner_refuses_before_launch", func(t *testing.T) {
		original, cancel := context.WithTimeout(context.Background(), time.Minute)
		owner, err := NewNativeOriginalWorkflowOwners(original)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		parent, finish, err := owner.Begin()
		if err == nil || parent != nil || finish != nil {
			t.Fatal("expired source owner launched")
		}
		if err := owner.Join(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("sealed_owner_refuses_before_launch", func(t *testing.T) {
		original, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		owner, err := NewNativeOriginalWorkflowOwners(original)
		if err != nil {
			t.Fatal(err)
		}
		if err := owner.Join(context.Background()); err != nil {
			t.Fatal(err)
		}
		parent, finish, err := owner.Begin()
		if err == nil || parent != nil || finish != nil {
			t.Fatal("sealed source owner launched")
		}
	})
	t.Run("original_error_is_retained", func(t *testing.T) {
		originalErr := errors.New("original source owner refusal")
		parent, finish, err := (&Server{originalGuestAsyncWorkflowOwner: refusedOriginalWorkflowOwner{originalErr}}).beginOriginalGuestAsyncWorkflow()
		if err != originalErr || parent != nil || finish != nil {
			t.Fatal("original refusal replaced")
		}
	})
	t.Run("all_original_returns_are_required_once", func(t *testing.T) {
		original, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		owner, err := NewNativeOriginalWorkflowOwners(original)
		if err != nil {
			t.Fatal(err)
		}
		_, first, err := owner.Begin()
		if err != nil {
			t.Fatal(err)
		}
		_, second, err := owner.Begin()
		if err != nil {
			t.Fatal(err)
		}
		first()
		first()
		bounded, cancelBounded := context.WithCancel(context.Background())
		cancelBounded()
		if err := owner.Join(bounded); !errors.Is(err, context.Canceled) {
			t.Fatal("second original owner was dropped", err)
		}
		second()
		second()
		if err := owner.Join(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("original_cancellation_does_not_join_pending_return", func(t *testing.T) {
		original, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		owner, err := NewNativeOriginalWorkflowOwners(original)
		if err != nil {
			t.Fatal(err)
		}
		_, finish, err := owner.Begin()
		if err != nil {
			t.Fatal(err)
		}
		canceled, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() { defer close(returned); defer finish(); <-original.Done(); close(canceled); <-release }()
		cancel()
		<-canceled
		if err := owner.Join(original); !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation became original owner return", err)
		}
		if _, replacement, err := owner.Begin(); err == nil || replacement != nil {
			t.Fatal("canceled sealed original launched replacement")
		}
		close(release)
		if err := owner.Join(context.WithoutCancel(original)); err != nil {
			t.Fatal(err)
		}
		<-returned
	})
}
