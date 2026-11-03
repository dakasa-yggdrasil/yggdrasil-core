//go:build linux

package capacityhostfactory

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestFinalSourceAuditFrameOversizedRetainsRefusalWithoutWrite(t *testing.T) {
	envelope := bytes.Repeat([]byte("a"), bodyLimit)
	worker := &originalSealedWorker{
		publisher: &originalNativePublisher{},
		lastCtx:   context.Background(),
		emitted:   map[string]bool{},
	}
	err := worker.emitOriginalFinalSourceAuditCarrier(envelope)
	if err == nil {
		t.Fatal("oversized encoded frame was accepted")
	}
	want, err := json.Marshal(originalWorkerSignedFrame{
		"source_private_original_final_source_audit_signed_frame_v1", "final-source-audit-worker", envelope,
	})
	if err != nil || len(want) <= bodyLimit || !bytes.Equal(worker.finalCarrierRaw, want) ||
		!worker.emitted["final-source-audit-worker"] || len(worker.frameReturns) != 0 || worker.stdoutBytes != 0 {
		t.Fatal("oversized frame changed original refusal state or attempted a write")
	}
}
