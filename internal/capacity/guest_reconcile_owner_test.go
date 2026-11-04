package capacity

import (
	"context"
	"testing"
	"time"
)

func TestOriginalGuestReconcileOwnerNeverRenewsLease(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	o := &OriginalGuestReconcileOwner{}
	original := time.Now().Add(40 * time.Millisecond)
	if err := o.Capture(parent, original); err != nil {
		t.Fatal(err)
	}
	first, stop := o.Context(parent)
	defer stop()
	a, _ := first.Deadline()
	if !a.Equal(original) {
		t.Fatal("original lease was not captured")
	}
	if o.Capture(parent, time.Now().Add(time.Hour)) == nil {
		t.Fatal("lease renewed")
	}
	<-first.Done()
	later, finish := o.Context(parent)
	defer finish()
	b, _ := later.Deadline()
	if !b.Equal(original) || time.Now().Before(b) {
		t.Fatal("later operation renewed expired original")
	}
	short, stopShort := context.WithDeadline(parent, original.Add(-time.Millisecond))
	defer stopShort()
	clipped, stopClip := o.Context(short)
	defer stopClip()
	d, _ := clipped.Deadline()
	if d.After(original.Add(-time.Millisecond)) {
		t.Fatal("owner lengthened parent")
	}
}

func TestOriginalGuestReconcileOwnerFencesInsideMutex(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	o := &OriginalGuestReconcileOwner{}
	o.mu.Lock()
	deadline := time.Now().Add(20 * time.Millisecond)
	joined := make(chan error, 1)
	go func() { joined <- o.Capture(parent, deadline) }()
	gate, stop := context.WithDeadline(parent, deadline)
	<-gate.Done()
	stop()
	o.mu.Unlock()
	if err := <-joined; err == nil {
		t.Fatal("mutex wait minted an expired owner")
	}
	if o.captured {
		t.Fatal("expired capture changed ownership")
	}
}

func TestOriginalGuestReconcileOwnerRequiresBoundedLiveCreator(t *testing.T) {
	for _, mode := range []string{"unbounded", "expired", "canceled", "zero"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			deadline := time.Now().Add(time.Second)
			stop := func() {}
			switch mode {
			case "expired":
				ctx, stop = context.WithTimeout(ctx, time.Second)
				deadline = time.Now().Add(-time.Millisecond)
			case "canceled":
				ctx, stop = context.WithTimeout(ctx, time.Second)
				stop()
			case "zero":
				ctx, stop = context.WithTimeout(ctx, time.Second)
				deadline = time.Time{}
			}
			defer stop()
			if (&OriginalGuestReconcileOwner{}).Capture(ctx, deadline) == nil {
				t.Fatal("missing/expired original accepted")
			}
		})
	}
}
