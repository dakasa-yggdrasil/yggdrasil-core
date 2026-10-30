// Package executorpower implements the opt-in operator-adopted EC2 power variant
// of Core's mutation ledger. It cannot authorize creation or destruction.
package executorpower

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	powerwire "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/sdk/executorpower"
	"regexp"
	"slices"
	"strings"
	"time"
)

const Kind = "ec2_power_v1"
const AdoptionKind = "ec2_operator_adoption_v1"
const Running = "ensure_ec2_instance_running"
const Stopped = "ensure_ec2_instance_stopped"

var ErrDenied = errors.New("executor power authority denied")
var ErrUnknown = errors.New("original executor power outcome remains unknown")

type Resource = powerwire.Resource
type Workflow = powerwire.Workflow
type Binding = powerwire.Binding
type Scope = powerwire.Scope
type Observation = powerwire.Observation
type Adoption = powerwire.Adoption
type Grant = powerwire.Grant
type Claim = powerwire.Claim
type ClaimReply = powerwire.ClaimReply
type Result = powerwire.Result

func Capability(action string) string {
	switch action {
	case "start":
		return Running
	case "stop":
		return Stopped
	}
	return ""
}
func Digest(v any) string { raw, _ := json.Marshal(v); return fmt.Sprintf("%x", sha256.Sum256(raw)) }

// settlementTokenDigest preserves the JSON-string digest used by the wire protocol.
func settlementTokenDigest(token string) string {
	raw, _ := json.Marshal(token)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func Key(r Resource) string { return r.AccountID + "/" + r.Region + "/" + r.InstanceID }
func SameResource(a, b Resource) bool {
	return a.AccountID == b.AccountID && a.Region == b.Region && a.InstanceID == b.InstanceID && slices.Equal(a.Volumes, b.Volumes)
}
func ValidateResource(r Resource) error {
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(r.AccountID) || !regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]+$`).MatchString(r.Region) || !regexp.MustCompile(`^i-[a-f0-9]{17}$`).MatchString(r.InstanceID) || len(r.Volumes) < 1 || len(r.Volumes) > 16 {
		return ErrDenied
	}
	for i, v := range r.Volumes {
		if !regexp.MustCompile(`^vol-[a-f0-9]{17}$`).MatchString(v) || (i > 0 && r.Volumes[i-1] >= v) {
			return ErrDenied
		}
	}
	return nil
}
func ValidateBinding(b Binding) error {
	for _, v := range []string{b.AdapterPrincipal, b.ControllerPrincipal, b.AdoptionWorkflow.Namespace, b.AdoptionWorkflow.Name} {
		if len(v) < 1 || len(v) > 128 || strings.TrimSpace(v) != v || strings.ContainsAny(v, "\r\n\t") {
			return ErrDenied
		}
	}
	if b.Mode != Kind || ValidateResource(b.Resource) != nil || b.GrantSeconds < 5 || b.GrantSeconds > 60 || len(b.Operators) < 1 || len(b.Operators) > 32 || b.AdoptionWorkflow.Namespace == "" || b.AdoptionWorkflow.Name == "" || b.AdapterPrincipal == "" || b.ControllerPrincipal == "" || b.AdapterPrincipal == b.ControllerPrincipal {
		return ErrDenied
	}
	for _, v := range []string{b.IntegrationID, b.TypeID} {
		if !uuidString(v) {
			return ErrDenied
		}
	}
	for _, v := range []string{b.IntegrationChecksum, b.TypeChecksum} {
		if !hash(v) {
			return ErrDenied
		}
	}
	seen := map[string]bool{}
	for _, id := range b.Operators {
		if !uuidString(id) || seen[id] {
			return ErrDenied
		}
		seen[id] = true
	}
	return nil
}
func CheckObservation(b Binding, o Observation, now time.Time) error {
	if !SameResource(b.Resource, o.Resource) || o.ObservedAt.IsZero() || o.ObservedAt.After(now) || now.Sub(o.ObservedAt) > 30*time.Second || (o.State != "running" && o.State != "stopped") {
		return ErrDenied
	}
	return nil
}
func GrantSHA(g Grant) string {
	return Digest([]any{Kind, g.ID, g.AdoptionID, g.Action, g.CommandID, g.Epoch, g.Binding, g.Scope, g.IssuedAt, g.ExpiresAt})
}
func Redeem(g *Grant, principal string, c Claim, now time.Time, execution bool, activityCurrent bool) (ClaimReply, error) {
	r := ClaimReply{Mode: "read_only", GrantID: g.ID, Deadline: g.ExpiresAt}
	if ValidateGrant(*g) != nil || principal != g.Binding.AdapterPrincipal || c.GrantID != g.ID || c.Action != g.Action || c.CommandID != g.CommandID || c.RequestSHA != g.RequestSHA || !uuidString(c.AttemptID) || !hash(c.SettlementSHA) {
		return r, ErrDenied
	}
	if g.State != "issued" {
		return r, nil
	} // Even the original attempt never reacquires send.
	if !now.Before(g.ExpiresAt) {
		g.State = "expired"
		g.Outcome = "rejected_before_send"
		return r, nil
	}
	if !execution || !activityCurrent {
		g.State = "rejected"
		g.Outcome = "rejected_before_send"
		return r, nil
	}
	g.State = "redeemed"
	g.AttemptID = c.AttemptID
	g.SettlementSHA = c.SettlementSHA
	r.Mode = "execute_once"
	return r, nil
}
func Settle(g *Grant, principal, token string, r Result, now time.Time) error {
	if ValidateGrant(*g) != nil || principal != g.Binding.AdapterPrincipal || r.GrantID != g.ID || r.AttemptID != g.AttemptID || r.RequestSHA != g.RequestSHA || subtle.ConstantTimeCompare([]byte(settlementTokenDigest(token)), []byte(g.SettlementSHA)) != 1 || (g.State != "redeemed" && g.State != "settled") || (r.Outcome != "accepted" && r.Outcome != "uncertain") {
		return ErrDenied
	}
	if r.Outcome == "accepted" && (!r.OriginalJoined || r.ServiceRequestID == "" || len(r.ServiceRequestID) > 256) {
		return ErrDenied
	}
	if g.Outcome == "accepted" {
		if r.Outcome != g.Outcome || r.ServiceRequestID != g.ServiceRequestID || r.OriginalJoined != g.OriginalJoined {
			return ErrDenied
		}
		return nil
	}
	if now.Before(g.IssuedAt) {
		return ErrDenied
	}
	g.SettledAt = &now
	g.State = "settled"
	g.Outcome = r.Outcome
	g.ServiceRequestID = r.ServiceRequestID
	g.OriginalJoined = r.OriginalJoined
	return nil
}
func Confirm(g *Grant, o Observation, now time.Time) error {
	if ValidateGrant(*g) != nil || g.State != "settled" || g.SettledAt == nil || o.ObservedAt.Before(*g.SettledAt) || g.Outcome != "accepted" || !g.OriginalJoined || g.ServiceRequestID == "" || CheckObservation(g.Binding, o, now) != nil || o.ObservedAt.Before(g.IssuedAt) {
		return ErrUnknown
	}
	goal := "running"
	if g.Action == "stop" {
		goal = "stopped"
	} else if g.Action != "start" {
		return ErrDenied
	}
	if o.State != goal || (g.Action == "start" && (!o.WorkerReady || o.BootID == "")) {
		return ErrUnknown
	}
	g.State = "confirmed"
	g.ConfirmedAt = &now
	return nil
}
func uuidString(v string) bool {
	return regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(v) && v != "00000000-0000-0000-0000-000000000000"
}
func hash(v string) bool { return regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(v) }
