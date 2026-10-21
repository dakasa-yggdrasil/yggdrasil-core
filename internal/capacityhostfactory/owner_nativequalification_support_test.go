//go:build linux && nativequalification

package capacityhostfactory

import "context"

// Exact former production wrappers used only by the existing tagged Source tests.
// No test root, assertion, operation, effect or owning return is added or removed.
func controlRegistrarPublishGetdentsFile(ctx context.Context, audit *originalLedger, anchor *callHandle, temporary, final string, raw []byte, uid, gid uint32) error {
	_, _, err := controlRegistrarPublishGetdentsFileCaptured(ctx, audit, anchor, temporary, final, raw, uid, gid)
	return err
}

func controlRegistrarReadFile(ctx context.Context, audit *originalLedger, anchor *callHandle, name string, uid, gid uint32) ([]byte, error) {
	raw, _, err := controlRegistrarReadCustodyFile(ctx, audit, anchor, name, uid, gid, false)
	return raw, err
}

func controlRegistrarReadGetdentsFile(ctx context.Context, audit *originalLedger, anchor *callHandle, name string, uid, gid uint32) ([]byte, error) {
	raw, _, err := controlRegistrarReadCustodyFile(ctx, audit, anchor, name, uid, gid, true)
	return raw, err
}

func controlRegistrarRequireOriginalPhase(p *originalNativePublisher, ctx context.Context, requestID string, basal *basalOwner) error {
	_, err := controlRegistrarOriginalPhaseCalledAt(p, ctx, requestID, basal)
	return err
}

func controlRegistrarOriginalPhaseContext(original context.Context, request controlRegistrarRequest) (context.Context, context.CancelFunc, error) {
	if request.Phase == "closing" {
		return nil, nil, refused("original_context_refused", nil) // cleanup has its own Source-owned diagnostic context, never a native phase
	}
	if original == nil || original.Err() != nil {
		return nil, nil, refused("original_context_refused", nil)
	}
	if err := controlRegistrarValidateRequest(request); err != nil {
		return nil, nil, err
	}
	bound, err := controlRegistrarCanonicalTime(request.OriginalEffectivePhaseDeadline)
	if err != nil {
		return nil, nil, err
	}
	if _, ok := original.Deadline(); !ok {
		return nil, nil, refused("original_context_refused", nil)
	}
	phase, cancel := context.WithDeadline(original, bound)
	actual, ok := phase.Deadline()
	if !ok || !actual.Equal(bound) || phase.Err() != nil {
		cancel()
		return nil, nil, refused("original_context_refused", nil)
	}
	return phase, cancel, nil
}
