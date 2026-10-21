package executorpower

import (
	"context"
	"time"
)

// Ledger is Core's existing mutation-authority transport, authenticated separately
// from workflow issuance. The supplied settlement token remains only in original
// adapter custody; a lost execute_once reply never authorizes another send.
type Ledger interface {
	Redeem(context.Context, Claim) (ClaimReply, error)
	Settle(context.Context, string, Result) error
}

// EC2Client is the context-bound SDK seam. Implementations must disable SDK
// mutation retries and bind the exact account and region before Start/Stop. The
// returned ID must be the AWS service acknowledgement, never a local receipt.
// No legacy Background-context helper or termination capability is exposed here.
type EC2Client interface {
	StartInstances(context.Context, Resource) (serviceRequestID string, err error)
	StopInstances(context.Context, Resource) (serviceRequestID string, err error)
}

// Adapter is intentionally not registered or constructed at boot. Production
// wiring requires separate source-owned AWS SDK qualification and credentials.
type Adapter struct {
	Enabled bool
	Binding Binding
	Ledger  Ledger
	EC2     EC2Client
	Now     func() time.Time
}

func (a Adapter) Execute(ctx context.Context, g Grant, attemptID, settlementToken string) error {
	if !a.Enabled || !a.Binding.Enabled || a.Ledger == nil || a.EC2 == nil || a.Now == nil || ValidateGrant(g) != nil || Digest(a.Binding) != Digest(g.Binding) || len(settlementToken) < 32 || len(settlementToken) > 256 || !uuidString(attemptID) || ctx.Err() != nil {
		return ErrDenied
	}
	now := a.Now()
	if !now.Before(g.ExpiresAt) {
		return ErrDenied
	}
	claim := Claim{GrantID: g.ID, Action: g.Action, CommandID: g.CommandID, RequestSHA: g.RequestSHA, AttemptID: attemptID, SettlementSHA: Digest(settlementToken)}
	reply, err := a.Ledger.Redeem(ctx, claim)
	if err != nil || reply.Mode != "execute_once" || reply.GrantID != g.ID || !reply.Deadline.Equal(g.ExpiresAt) {
		return ErrUnknown
	}
	// No local retry after this point, including cancellation or a lost response.
	callCtx, cancel := context.WithDeadline(ctx, g.ExpiresAt)
	defer cancel()
	r := Result{GrantID: g.ID, AttemptID: attemptID, RequestSHA: g.RequestSHA, Outcome: "uncertain"}
	if callCtx.Err() == nil && a.Now().Before(g.ExpiresAt) {
		var serviceID string
		switch g.Action {
		case "start":
			serviceID, err = a.EC2.StartInstances(callCtx, g.Binding.Resource)
		case "stop":
			serviceID, err = a.EC2.StopInstances(callCtx, g.Binding.Resource)
		default:
			return ErrDenied
		}
		r.OriginalJoined = true
		if err == nil && serviceID != "" && len(serviceID) <= 256 {
			r.Outcome = "accepted"
			r.ServiceRequestID = serviceID
		}
	}
	if err = a.Ledger.Settle(ctx, settlementToken, r); err != nil {
		return ErrUnknown
	}
	if r.Outcome != "accepted" {
		return ErrUnknown
	}
	return nil
}
