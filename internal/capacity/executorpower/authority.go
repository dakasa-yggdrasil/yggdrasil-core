package executorpower

import (
	"context"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executoractivity"
	"strings"
	"time"
)

// Observer is a trusted, independently pinned adapter read. A workflow body must
// never instantiate it or supply its reply. No production factory is installed.
type Observer interface {
	Observe(context.Context, Resource) (Observation, error)
}

// Adopt is called after protected operator-workflow authorization. Observation
// must come from Observer outside the SQL transaction and is rechecked at DB time.
func Adopt(b Binding, operator, id string, o Observation, now time.Time, enabled bool) (Adoption, error) {
	if !enabled || !b.Enabled || ValidateBinding(b) != nil || !uuidString(id) || !slicesContains(b.Operators, operator) || CheckObservation(b, o, now) != nil {
		return Adoption{}, ErrDenied
	}
	return Adoption{Kind: AdoptionKind, ID: id, Resource: b.Resource, Operator: operator, ObservedAt: o.ObservedAt, AdoptedAt: now, BindingSHA: Digest(b)}, nil
}
func slicesContains(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}

// Current checks the persisted command and admission epoch under the shared
// dimension lock. Newly arrived demand vetoes an unredeemed stop. Once redeemed,
// unknown send custody is retained; no timeout authorizes another invocation.
func Current(b Binding, a Adoption, s executoractivity.ExecutorActivityState, commandID, action string, epoch uint64, now time.Time) bool {
	if s.PinnedPolicy == nil || s.Power == nil || s.Power.IssuedAt.IsZero() || s.Power.IssuedAt.After(now) || now.Sub(s.Power.IssuedAt) > s.PinnedPolicy.MaxObservationAge {
		return false
	}
	if a.Kind != AdoptionKind || !uuidString(a.ID) || a.BindingSHA != Digest(b) || !SameResource(a.Resource, b.Resource) || s.Power == nil || s.Power.ID != commandID || s.Power.Action != action || s.Power.Joined || s.Epoch != epoch {
		return false
	}
	r := s.Power.Resource
	if r.AccountID != b.Resource.AccountID || r.Region != b.Resource.Region || r.InstanceID != b.Resource.InstanceID || r.OwnershipBindingID != a.ID || s.BoundResource == nil || *s.BoundResource != r {
		return false
	}
	jobs := 0
	for _, j := range s.Jobs {
		if j.State != "finished" {
			jobs++
		}
	}
	demand := executoractivity.ExecutorActiveTasks(s, now) > 0 || jobs > 0
	if action == "start" {
		return demand && s.Stop == nil
	}
	if action != "stop" || demand || s.Stop == nil || s.Stop.ID != commandID || s.Stop.Epoch != epoch || s.Stop.Stage != "possible_send" {
		return false
	}
	return !s.Stop.SendAt.IsZero() && !s.Stop.SendAt.After(now) && now.Sub(s.Stop.SendAt) <= s.PinnedPolicy.MaxObservationAge && !s.IdleSince.IsZero() && now.Sub(s.IdleSince) >= s.PinnedPolicy.IdleAfter
}

func Issue(b Binding, a Adoption, scope Scope, principal, id, commandID, action string, s executoractivity.ExecutorActivityState, now time.Time, enabled bool) (Grant, error) {
	if !enabled || !b.Enabled || ValidateBinding(b) != nil || principal != "machine:"+b.ControllerPrincipal || !uuidString(id) || len(commandID) < 1 || len(commandID) > 128 || strings.TrimSpace(commandID) != commandID || Capability(action) == "" || !Current(b, a, s, commandID, action, s.Epoch, now) {
		return Grant{}, ErrDenied
	}
	g := Grant{Kind: Kind, ID: id, AdoptionID: a.ID, Action: action, CommandID: commandID, Epoch: s.Epoch, State: "issued", IssuedAt: now, ExpiresAt: now.Add(time.Duration(b.GrantSeconds) * time.Second), Binding: b, Scope: scope}
	g.RequestSHA = GrantSHA(g)
	if ValidateGrant(g) != nil {
		return Grant{}, ErrDenied
	}
	return g, nil
}

func ValidateGrant(g Grant) error {
	switch g.State {
	case "issued":
		if g.AttemptID != "" || g.SettlementSHA != "" || g.Outcome != "" || g.SettledAt != nil || g.ConfirmedAt != nil {
			return ErrDenied
		}
	case "redeemed":
		if !uuidString(g.AttemptID) || !hash(g.SettlementSHA) || g.Outcome != "" || g.SettledAt != nil || g.ConfirmedAt != nil {
			return ErrDenied
		}
	case "settled", "confirmed":
		if !uuidString(g.AttemptID) || !hash(g.SettlementSHA) || g.SettledAt == nil || g.SettledAt.Before(g.IssuedAt) || (g.Outcome != "accepted" && g.Outcome != "uncertain") {
			return ErrDenied
		}
		if g.Outcome == "accepted" && (!g.OriginalJoined || g.ServiceRequestID == "" || len(g.ServiceRequestID) > 256) {
			return ErrDenied
		}
		if g.State == "confirmed" && (g.ConfirmedAt == nil || g.ConfirmedAt.Before(*g.SettledAt) || g.Outcome != "accepted") {
			return ErrDenied
		}
	case "rejected", "expired":
		if g.Outcome != "rejected_before_send" || g.AttemptID != "" || g.SettlementSHA != "" || g.SettledAt != nil || g.ConfirmedAt != nil {
			return ErrDenied
		}
	default:
		return ErrDenied
	}

	if !uuidString(g.Scope.PolicyID) || !uuidString(g.Scope.WorkflowID) || g.Scope.PolicyChecksum == "" || g.Scope.Namespace == "" || g.Scope.Environment == "" || g.Scope.Domain == "" || g.Scope.Dimension == "" {
		return ErrDenied
	}
	if g.Kind != Kind || ValidateBinding(g.Binding) != nil || !g.Binding.Enabled || !uuidString(g.ID) || !uuidString(g.AdoptionID) || Capability(g.Action) == "" || g.CommandID == "" || len(g.CommandID) > 128 || g.RequestSHA != GrantSHA(g) || g.IssuedAt.IsZero() || !g.ExpiresAt.Equal(g.IssuedAt.Add(time.Duration(g.Binding.GrantSeconds)*time.Second)) {
		return ErrDenied
	}
	return nil
}
