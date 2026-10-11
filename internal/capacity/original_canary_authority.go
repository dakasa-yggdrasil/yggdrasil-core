package capacity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const OriginalCanaryAuthoritySchema = "core_original_canary_authority_v1"
const MaxOriginalCanaryAuthorities = 128
const MaxOriginalCanaryAuthorityReads = 1024

var ErrOriginalCanaryAuthority = errors.New("original canary authority unavailable")

// This is one private permission scope, not a capacity or original business
// completion certificate. Only the original protected Core invocation creates
// it, after its durable possible-start transaction actually returned nil.
type OriginalCanaryAuthorityScope struct {
	WindowID           string    `json:"window_id"`
	ScopeSHA256        string    `json:"scope_sha256"`
	PolicyID           string    `json:"policy_id"`
	PolicyChecksum     string    `json:"policy_checksum"`
	WorkflowID         string    `json:"workflow_id"`
	WorkflowChecksum   string    `json:"workflow_checksum"`
	DispatchJobID      string    `json:"dispatch_job_id"`
	DispatchFence      int64     `json:"dispatch_fence"`
	IntentGeneration   int64     `json:"intent_generation"`
	IntentFence        int64     `json:"intent_fence"`
	LeaseOwner         string    `json:"lease_owner"`
	ExecutorID         string    `json:"executor_id"`
	MachinePrincipalID string    `json:"machine_principal_id"`
	Deadline           time.Time `json:"deadline"`
}

type OriginalCanaryAuthorityReply struct {
	Schema                     string                       `json:"schema"`
	Scope                      OriginalCanaryAuthorityScope `json:"scope"`
	ObservedAt                 time.Time                    `json:"observed_at"`
	OriginalLiveLeaseVerified  bool                         `json:"original_live_lease_verified"`
	CurrentMachineRBACVerified bool                         `json:"current_machine_rbac_verified"`
	HumanSessionVerified       bool                         `json:"human_session_verified"`
	UsefulCapacityKnown        bool                         `json:"useful_capacity_known"`
	FullTransitionQualified    bool                         `json:"full_transition_qualified"`
}

// The bearer is generated inside Core and retained only in this original
// invocation. Formatting or marshaling this value never reveals its bytes.
// HeaderValue is the explicit, private outbound HTTP seam; never log it.
type OriginalCanaryAuthorityToken struct{ raw string }

func (OriginalCanaryAuthorityToken) String() string               { return "[private canary authority]" }
func (OriginalCanaryAuthorityToken) GoString() string             { return "[private canary authority]" }
func (OriginalCanaryAuthorityToken) MarshalJSON() ([]byte, error) { return []byte("null"), nil }
func (OriginalCanaryAuthorityToken) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[private canary authority]")
}
func (t OriginalCanaryAuthorityToken) HeaderValue() string { return t.raw }

type originalCanaryAuthorityError struct{ cause error }

func (originalCanaryAuthorityError) Error() string    { return ErrOriginalCanaryAuthority.Error() }
func (originalCanaryAuthorityError) GoString() string { return ErrOriginalCanaryAuthority.Error() }
func (e originalCanaryAuthorityError) Unwrap() error  { return e.cause }
func (originalCanaryAuthorityError) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, ErrOriginalCanaryAuthority.Error())
}

func originalCanaryRefusal(causes ...error) error {
	return originalCanaryAuthorityError{cause: errors.Join(append([]error{ErrOriginalCanaryAuthority}, causes...)...)}
}

type originalCanaryAuthorityEntry struct {
	owner   context.Context
	scope   OriginalCanaryAuthorityScope
	guard   func(context.Context) error
	reads   int
	revoked bool
}

// This registry is deliberately process-local. A restarted Core cannot adopt
// the old original invocation, reconstruct a bearer or arm another window.
// The durable intent marker belongs to the capacity store, not this registry.
// There is no enabled environment fallback or wire method for registration.
type OriginalCanaryAuthorityRegistry struct {
	mu      sync.Mutex
	entries map[[sha256.Size]byte]*originalCanaryAuthorityEntry
}

func NewOriginalCanaryAuthorityRegistry() *OriginalCanaryAuthorityRegistry {
	return &OriginalCanaryAuthorityRegistry{entries: make(map[[sha256.Size]byte]*originalCanaryAuthorityEntry)}
}

func originalCanaryUUID(value string) bool {
	u, err := uuid.Parse(value)
	return err == nil && u != uuid.Nil && u.String() == value
}

func originalCanarySHA(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == value
}

func originalCanaryScopeValid(s OriginalCanaryAuthorityScope, now time.Time) bool {
	return originalCanaryUUID(s.WindowID) && originalCanarySHA(s.ScopeSHA256) &&
		originalCanaryUUID(s.PolicyID) && originalCanarySHA(s.PolicyChecksum) &&
		originalCanaryUUID(s.WorkflowID) && originalCanarySHA(s.WorkflowChecksum) &&
		originalCanaryUUID(s.DispatchJobID) && s.DispatchFence > 0 && s.IntentGeneration > 0 && s.IntentFence > 0 &&
		originalCanaryUUID(s.LeaseOwner) && originalCanaryUUID(s.ExecutorID) &&
		len(s.MachinePrincipalID) > 0 && len(s.MachinePrincipalID) <= 128 &&
		strings.TrimSpace(s.MachinePrincipalID) == s.MachinePrincipalID &&
		!strings.ContainsAny(s.MachinePrincipalID, "\r\n\x00") &&
		s.Deadline.After(now) && !s.Deadline.After(now.Add(90*time.Second))
}

func originalCanaryContext(ctx context.Context) error {
	if ctx == nil {
		return ErrOriginalCanaryAuthority
	}
	if deadline, ok := ctx.Deadline(); !ok || !time.Now().Before(deadline) {
		return errors.Join(ErrOriginalCanaryAuthority, context.DeadlineExceeded, context.Cause(ctx))
	}
	return errors.Join(ctx.Err(), context.Cause(ctx))
}

// Register receives a PRIVATE source callback that checks the actual original
// dispatch claim, current principal/RBAC/catalog and SAME native intent lease.
// Request fields or metadata cannot supply a callback or boolean authority.
// A failed/unknown guard cannot create a bearer; there is no replay API.
func (r *OriginalCanaryAuthorityRegistry) Register(owner context.Context, scope OriginalCanaryAuthorityScope, guard func(context.Context) error) (OriginalCanaryAuthorityToken, func(), error) {
	var token OriginalCanaryAuthorityToken
	if r == nil || guard == nil || originalCanaryContext(owner) != nil || !originalCanaryScopeValid(scope, time.Now().UTC()) {
		return token, nil, originalCanaryRefusal(originalCanaryContext(owner))
	}
	deadline, _ := owner.Deadline()
	if scope.Deadline.After(deadline) {
		return token, nil, originalCanaryRefusal()
	}
	if err := guard(owner); err != nil {
		return token, nil, originalCanaryRefusal(err, originalCanaryContext(owner))
	}
	var entropy [32]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return token, nil, originalCanaryRefusal(err)
	}
	token.raw = hex.EncodeToString(entropy[:])
	digest := sha256.Sum256([]byte(token.raw))
	entry := &originalCanaryAuthorityEntry{owner: owner, scope: scope, guard: guard}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		return OriginalCanaryAuthorityToken{}, nil, originalCanaryRefusal()
	}
	for key, old := range r.entries {
		if old.revoked || originalCanaryContext(old.owner) != nil || !time.Now().Before(old.scope.Deadline) {
			old.revoked = true
			delete(r.entries, key)
			continue
		}
		if old.scope.WindowID == scope.WindowID || old.scope.DispatchJobID == scope.DispatchJobID {
			return OriginalCanaryAuthorityToken{}, nil, originalCanaryRefusal()
		}
	}
	if len(r.entries) >= MaxOriginalCanaryAuthorities || r.entries[digest] != nil || originalCanaryContext(owner) != nil || !time.Now().Before(scope.Deadline) {
		return OriginalCanaryAuthorityToken{}, nil, originalCanaryRefusal(originalCanaryContext(owner))
	}
	r.entries[digest] = entry
	revoke := func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		entry.revoked = true
		if r.entries[digest] == entry {
			delete(r.entries, digest)
		}
	}
	return token, revoke, nil
}

// Observe runs the original guard before AND after constructing a reply. The
// incoming HTTP owner cannot renew the captured Core deadline. Every SQL/guard
// call must actually return; pending/failed calls never yield a permission.
// A permission does not imply that this HTTP response or any business writer
// returned to its original caller. The actual recipient separately joins that.
func (r *OriginalCanaryAuthorityRegistry) Observe(request context.Context, bearer, scopeSHA256 string) (reply OriginalCanaryAuthorityReply, result error) {
	if r == nil || originalCanaryContext(request) != nil || !originalCanarySHA(bearer) || !originalCanarySHA(scopeSHA256) {
		return reply, originalCanaryRefusal(originalCanaryContext(request))
	}
	digest := sha256.Sum256([]byte(bearer))
	r.mu.Lock()
	entry := r.entries[digest]
	if entry == nil || entry.revoked || entry.scope.ScopeSHA256 != scopeSHA256 || entry.reads >= MaxOriginalCanaryAuthorityReads {
		r.mu.Unlock()
		return reply, originalCanaryRefusal()
	}
	entry.reads++
	r.mu.Unlock()
	owner, cancel := context.WithDeadline(request, entry.scope.Deadline)
	defer cancel()
	check := func() error {
		r.mu.Lock()
		live := !entry.revoked && r.entries[digest] == entry
		r.mu.Unlock()
		if !live || !time.Now().Before(entry.scope.Deadline) {
			return ErrOriginalCanaryAuthority
		}
		return errors.Join(originalCanaryContext(owner), originalCanaryContext(entry.owner))
	}
	defer func() {
		if cause := check(); cause != nil {
			reply = OriginalCanaryAuthorityReply{}
			result = originalCanaryRefusal(result, cause)
		}
	}()
	if err := check(); err != nil {
		return reply, originalCanaryRefusal(err)
	}
	if err := entry.guard(owner); err != nil {
		return reply, originalCanaryRefusal(err)
	}
	if err := check(); err != nil {
		return reply, originalCanaryRefusal(err)
	}
	reply = OriginalCanaryAuthorityReply{Schema: OriginalCanaryAuthoritySchema, Scope: entry.scope, ObservedAt: time.Now().UTC(), OriginalLiveLeaseVerified: true, CurrentMachineRBACVerified: true}
	if err := entry.guard(owner); err != nil {
		return OriginalCanaryAuthorityReply{}, originalCanaryRefusal(err)
	}
	if err := check(); err != nil {
		return OriginalCanaryAuthorityReply{}, originalCanaryRefusal(err)
	}
	return reply, nil
}
