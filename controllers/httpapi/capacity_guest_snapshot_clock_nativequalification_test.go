//go:build linux && nativequalification

package httpapi

import (
	"context"
	"errors"
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
