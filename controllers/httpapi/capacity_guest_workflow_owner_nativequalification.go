//go:build linux && nativequalification

package httpapi

import (
	"context"
	"errors"
)

// Native qualification uses the same production ownership implementation while
// retaining its mandatory original bounded parent and existing constructor ABI.
type NativeOriginalWorkflowOwners = OriginalWorkflowOwners

func NewNativeOriginalWorkflowOwners(ctx context.Context) (*NativeOriginalWorkflowOwners, error) {
	if _, ok := ctx.Deadline(); !ok || ctx.Err() != nil {
		return nil, errors.New("original native workflow deadline required")
	}
	return NewOriginalWorkflowOwners(ctx)
}
func WithNativeOriginalWorkflowOwners(o *NativeOriginalWorkflowOwners) ServerOption {
	return WithOriginalWorkflowOwners(o)
}
