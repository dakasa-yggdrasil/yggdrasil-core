//go:build linux && nativequalification

package httpapi

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestQualificationSnapshotClockWaitOriginalContext(t *testing.T) {
	var read repository.GuestOriginalAuthorityRead
	if err := guestQualificationBeforeSnapshotGET(context.Background(), read); err != nil {
		t.Fatal("non-qualification path changed", err)
	}
	read.Original.Binding.EvidenceClass = "native_qemu_qualification"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := guestQualificationBeforeSnapshotGET(ctx, read); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatal("original context not preserved", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	start = time.Now()
	if err := guestQualificationBeforeSnapshotGET(ctx2, read); err != nil || time.Since(start) < 90*time.Millisecond {
		t.Fatal("qualification window not elapsed", err)
	}
}

func TestQualificationSnapshotFailureHeader(t *testing.T) {
	var read repository.GuestOriginalAuthorityRead
	read.Original.Binding.EvidenceClass = "native_qemu_qualification"
	read.Phase, read.Ordinal = "before_start", 2
	for _, stage := range []string{"retention", "transport", "decode", "snapshot_record"} {
		r := httptest.NewRecorder()
		guestQualificationSnapshotFailure(r, read, stage)
		if r.Header().Get("X-Guest-Qualification-Snapshot-Failure") != stage {
			t.Fatal("original failure stage not retained")
		}
	}
	for _, tc := range []struct {
		stage   string
		phase   string
		ordinal int
		class   string
	}{
		{"private-value", "before_start", 2, "native_qemu_qualification"},
		{"decode", "before_poweroff", 2, "native_qemu_qualification"},
		{"decode", "before_start", 1, "native_qemu_qualification"},
		{"decode", "before_start", 2, "production"},
	} {
		read.Original.Binding.EvidenceClass = tc.class
		read.Phase, read.Ordinal = tc.phase, tc.ordinal
		r := httptest.NewRecorder()
		guestQualificationSnapshotFailure(r, read, tc.stage)
		if r.Header().Get("X-Guest-Qualification-Snapshot-Failure") != "" {
			t.Fatal("failure header escaped its closed qualification scope")
		}
	}
}
