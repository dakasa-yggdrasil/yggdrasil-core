package message

import (
	"context"
	"strings"
)

type executorActivityActorKey struct{}

// WithExecutorActivityMachinePrincipal is a trusted ingress bridge, not a parser
// for request metadata. HTTP calls it only after its existing machine auth and
// exact workflow authorization. No bearer is retained or propagated.
func WithExecutorActivityMachinePrincipal(ctx context.Context, principalID string) context.Context {
	if principalID == "" || len(principalID) > 128 || strings.TrimSpace(principalID) != principalID || strings.ContainsAny(principalID, "\r\n\t") {
		return ctx
	}
	return context.WithValue(ctx, executorActivityActorKey{}, "machine:"+principalID)
}

// Private operator carrier is set only after human workflow authentication.
type executorPowerOperatorKey struct{}

func WithExecutorPowerOperator(ctx context.Context, collaboratorID string) context.Context {
	return context.WithValue(ctx, executorPowerOperatorKey{}, collaboratorID)
}
