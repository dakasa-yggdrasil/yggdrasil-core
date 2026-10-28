//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityqualification"
)

// RecordPG17ReadDiagnostic retains a fixed, detail-free failure stage only in
// the source-owned positive QEMU fixture. Failure to write is never evidence
// of a successful or unsuccessful provider operation.
func (r *Realm) RecordPG17ReadDiagnostic(ctx context.Context, origin, stage string) error {
	if r == nil || ctx == nil || ctx.Err() != nil || r.Request.NativeCase != "positive_original_lifecycle" || !filepath.IsAbs(r.PrivateDirectory) {
		return errors.New("qualification read diagnostic scope required")
	}
	d, err := capacityqualification.NewReadDiagnostic(origin, stage)
	if err != nil {
		return err
	}
	_, err = Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, 2), "pg17-read-diagnostic-"+origin+".json"), d)
	return err
}
