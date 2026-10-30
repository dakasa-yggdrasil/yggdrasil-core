//go:build linux && nativequalification

package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// The source-only QEMU fixture uses independent Guest and host clocks. Give
// the already committed challenge time to cross the observed millisecond-scale
// offset; this does not renew its original deadline or change validation.
func guestQualificationBeforeSnapshotGET(ctx context.Context, read repository.GuestOriginalAuthorityRead) error {
	if read.Original.Binding.EvidenceClass != "native_qemu_qualification" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

// Qualification-only closed failure observation; it never grants authority.
func guestQualificationSnapshotFailure(w http.ResponseWriter, read repository.GuestOriginalAuthorityRead, stage string) {
	if read.Original.Binding.EvidenceClass != "native_qemu_qualification" || read.Phase != "before_start" || read.Ordinal != 2 {
		return
	}
	switch stage {
	case "retention", "transport", "decode", "snapshot_record":
		w.Header().Set("X-Guest-Qualification-Snapshot-Failure", stage)
	}
}
