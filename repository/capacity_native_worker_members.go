package repository

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var errNativeMember = errors.New("native member operation unavailable")

// No admitted retirement implementation is supplied by this interface. Every
// read is independent, source-bound and GET-only; Send invokes one closed SDK
// capability, whose native one-send permission is redeemed separately here.
type NativeWorkerMemberRuntime interface {
	SourceCommit() string
	Target(context.Context, model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerPhaseReadObservation, error)
	Facts(context.Context, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerMemberContext) (capacity.NativeWorkerMemberFacts, error)
	Observe(context.Context, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerMemberContext) (model.CapacityNativeWorkerMemberObservation, error)
	AllocatorFence(context.Context, model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerAllocatorFenceContext, model.CapacityNativeWorkerAllocatorFenceObservation, error)
	Send(context.Context, model.CapacityNativeWorkerMemberContext) error
}

type NativeWorkerMemberStoreConfig struct {
	Workers         CapacityNativeWorkerStore
	Policy          model.Manifest
	Runtime         NativeWorkerMemberRuntime
	Abort           *CapacityNativeWorkerAbortStore
	Authority       capacity.NativeWorkerMemberAuthority
	Key             []byte
	Enabled         bool
	ScopeSHA256     string
	PrepareProvider NativeWorkerMemberPrepareProviderFunc
	Network         *NativeWorkerConcreteNetworkRuntime
}

func (NativeWorkerMemberStoreConfig) String() string {
	return "[private native member store configuration]"
}
func (c NativeWorkerMemberStoreConfig) GoString() string           { return c.String() }
func (NativeWorkerMemberStoreConfig) MarshalJSON() ([]byte, error) { return nil, errNativeMember }

type CapacityNativeWorkerMemberStore struct{ state *nativeMemberStoreState }
type nativeMemberStoreState struct {
	mu              sync.RWMutex
	closed          bool
	sealed          atomic.Bool
	readMu          sync.Mutex
	readActive      int
	readIdle        chan struct{}
	key             []byte
	workers         CapacityNativeWorkerStore
	policy          model.Manifest
	scope           string
	runtime         NativeWorkerMemberRuntime
	abort           *CapacityNativeWorkerAbortStore
	authority       capacity.NativeWorkerMemberAuthority
	prepareProvider NativeWorkerMemberPrepareProviderFunc
	network         *NativeWorkerConcreteNetworkRuntime
}

// Protected installed port. It resolves the exact original catalog before a
// durable dispatch; its returned closure performs one synchronous SDK call.
type NativeWorkerMemberPrepareProviderFunc func(context.Context, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerAbortPermit) (func() error, error)

func (CapacityNativeWorkerMemberStore) String() string               { return "[private native member store]" }
func (s CapacityNativeWorkerMemberStore) GoString() string           { return s.String() }
func (CapacityNativeWorkerMemberStore) MarshalJSON() ([]byte, error) { return nil, errNativeMember }

func NewCapacityNativeWorkerMemberStore(c NativeWorkerMemberStoreConfig) (*CapacityNativeWorkerMemberStore, error) {
	return newCapacityNativeWorkerMemberStore(c, capacity.CurrentGuestCoreSource())
}
func newCapacityNativeWorkerMemberStore(c NativeWorkerMemberStoreConfig, source string) (*CapacityNativeWorkerMemberStore, error) {
	p, e := parseCapacityPolicy(c.Policy)
	if !c.Enabled || !c.Workers.Enabled || !c.Workers.Capacity.ExecutionEnabled || c.Workers.Capacity.DB == nil || c.Runtime == nil || e != nil || capacity.ValidatePolicy(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.Members == nil || p.NativeWorkerLifecycleBinding.SourceCommit != source || c.Runtime.SourceCommit() != source || !nativeReadinessSHA(c.ScopeSHA256) || len(c.Key) != 32 || len(c.Authority.FenceObjects) == 0 || len(c.Authority.Enforcement) == 0 {
		return nil, ErrCapacityDisabled
	}
	raw, e := json.Marshal(c.Policy)
	var policy model.Manifest
	if e != nil || json.Unmarshal(raw, &policy) != nil {
		return nil, errNativeMember
	}
	policy.Spec = append(json.RawMessage(nil), c.Policy.Spec...)
	raw, e = json.Marshal(c.Authority)
	var own capacity.NativeWorkerMemberAuthority
	if e != nil || json.Unmarshal(raw, &own) != nil {
		return nil, errNativeMember
	}
	store := &CapacityNativeWorkerMemberStore{state: &nativeMemberStoreState{key: append([]byte(nil), c.Key...), workers: c.Workers, policy: policy, scope: c.ScopeSHA256, runtime: c.Runtime, abort: c.Abort, authority: own, prepareProvider: c.PrepareProvider, network: c.Network}}
	store.state.workers.Members = store
	return store, nil
}
func (s *CapacityNativeWorkerMemberStore) Close() error {
	if s == nil || s.state == nil {
		return nil
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	s.state.closed = true
	clear(s.state.key)
	s.state.key = nil
	return nil
}

// Stop new rights before draining originals. Historical reads and private
// receiving stay available until the owning listener and callers really join.
func (s *CapacityNativeWorkerMemberStore) Seal() {
	if s != nil && s.state != nil {
		s.state.sealed.Store(true)
	}
}
func (s *CapacityNativeWorkerMemberStore) acquire() (*nativeMemberStoreState, error) {
	if s == nil || s.state == nil {
		return nil, ErrCapacityDisabled
	}
	st := s.state
	st.mu.RLock()
	if st.closed || len(st.key) != 32 {
		st.mu.RUnlock()
		return nil, ErrCapacityDisabled
	}
	return st, nil
}

type nativeMemberCipher struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}
type nativeMemberPlanIdentity struct {
	Schema         string    `json:"schema"`
	PlanID         uuid.UUID `json:"plan_id"`
	AttemptID      uuid.UUID `json:"attempt_id"`
	PolicyID       uuid.UUID `json:"policy_id"`
	PolicyChecksum string    `json:"policy_checksum"`
	Namespace      string    `json:"namespace"`
	Kind           string    `json:"kind"`
	Mode           string    `json:"mode"`
	SubjectUID     string    `json:"subject_uid"`
	SourceCommit   string    `json:"source_commit"`
	BirthSHA256    string    `json:"birth_sha256"`
	Generation     int64     `json:"generation"`
	Fence          int64     `json:"fence"`
	ParentNotAfter time.Time `json:"parent_not_after"`
	ParentKind     string    `json:"parent_kind"`
	RealmUID       string    `json:"realm_uid"`
	PoolUID        string    `json:"pool_uid"`
	Epoch          int64     `json:"epoch"`
	ExecutorID     string    `json:"executor_id"`
	WorkflowID     uuid.UUID `json:"workflow_id"`
}
type nativeMemberPlanRecord struct {
	Identity                  nativeMemberPlanIdentity                     `json:"identity"`
	State                     string                                       `json:"state"`
	Revision                  int64                                        `json:"revision"`
	SealedFacts               *capacity.NativeWorkerMemberFacts            `json:"sealed_facts,omitempty"`
	PhysicalAbsence           *model.CapacityNativeWorkerAbortObservation  `json:"physical_absence,omitempty"`
	NodeAbsence               *model.CapacityNativeWorkerMemberObservation `json:"node_absence,omitempty"`
	ProviderPermitID          uuid.UUID                                    `json:"provider_permit_id,omitempty"`
	ProviderDispatchStartedAt *time.Time                                   `json:"provider_dispatch_started_at,omitempty"`
	NetworkPermitID           uuid.UUID                                    `json:"network_permit_id,omitempty"`
	NetworkDispatchStartedAt  *time.Time                                   `json:"network_dispatch_started_at,omitempty"`
}
type nativeMemberRecord struct {
	Context               model.CapacityNativeWorkerMemberContext      `json:"context"`
	State                 string                                       `json:"state"`
	Revision              int64                                        `json:"revision"`
	SeedID                uuid.UUID                                    `json:"seed_id"`
	Facts                 *capacity.NativeWorkerMemberFacts            `json:"facts,omitempty"`
	Original              *nativeMemberCipher                          `json:"original,omitempty"`
	SettlementTokenSHA256 string                                       `json:"settlement_token_sha256,omitempty"`
	Observed              *model.CapacityNativeWorkerMemberObservation `json:"observed,omitempty"`
	DispatchStartedAt     *time.Time                                   `json:"dispatch_started_at,omitempty"`
	RedeemedAt            *time.Time                                   `json:"redeemed_at,omitempty"`
}
type nativeMemberReadRecord struct {
	ReadID          uuid.UUID           `json:"read_id"`
	PermitID        uuid.UUID           `json:"permit_id"`
	ContextSHA256   string              `json:"context_sha256"`
	SubjectNodeUID  string              `json:"subject_node_uid"`
	SDKSourceCommit string              `json:"sdk_source_commit"`
	ScopeSHA256     string              `json:"scope_sha256"`
	Kind            string              `json:"kind"`
	CreatedAt       time.Time           `json:"created_at"`
	PrivateOriginal *nativeMemberCipher `json:"private_original,omitempty"`
}

func nativeMemberDigest(v any) string {
	raw, e := json.Marshal(v)
	if e != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func nativeMemberUUID(raw string) (uuid.UUID, error) {
	u, e := uuid.Parse(raw)
	if e != nil || u == uuid.Nil || u.String() != raw {
		return uuid.Nil, errNativeMember
	}
	return u, nil
}
func nativeMemberRecordBytes(v any) ([]byte, error) {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > model.CapacityNativeWorkerMemberMaxPrivateRecordBytes {
		return nil, errNativeMember
	}
	return raw, nil
}
func nativeMemberDecode(raw []byte, out any) error {
	return capacity.DecodeNativeWorkerMemberJournalJSON(raw, out)
}

func (st *nativeMemberStoreState) crypt(c model.CapacityNativeWorkerMemberContext, purpose string, sealed *nativeMemberCipher, raw []byte) (*nativeMemberCipher, []byte, error) {
	block, e := aes.NewCipher(st.key)
	if e != nil {
		return nil, nil, errNativeMember
	}
	g, e := cipher.NewGCM(block)
	if e != nil {
		return nil, nil, errNativeMember
	}
	aad := []byte("native-member-private-v1/" + c.CoreSourceCommit + "/" + capacity.NativeWorkerMemberContextSHA(c) + "/" + purpose)
	if sealed != nil {
		if len(sealed.Nonce) != g.NonceSize() || len(sealed.Ciphertext) > model.CapacityNativeWorkerMemberMaxPrivateRecordBytes {
			return nil, nil, errNativeMember
		}
		plain, e := g.Open(nil, sealed.Nonce, sealed.Ciphertext, aad)
		if e != nil {
			return nil, nil, errNativeMember
		}
		return nil, plain, nil
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = io.ReadFull(rand.Reader, nonce); e != nil {
		return nil, nil, errNativeMember
	}
	return &nativeMemberCipher{Nonce: nonce, Ciphertext: g.Seal(nil, nonce, raw, aad)}, nil, nil
}

func nativeMemberLoadTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, id uuid.UUID) (nativeMemberRecord, error) {
	var r nativeMemberRecord
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_permits WHERE id=$1 AND policy_id=$2 AND namespace=$3 FOR UPDATE`, id, policy.ID, policy.Metadata.Namespace).Scan(&raw)
	if e == nil {
		e = nativeMemberDecode(raw, &r)
	}
	if e != nil || r.Context.PermitID != id.String() {
		return nativeMemberRecord{}, errNativeMember
	}
	return r, nil
}
func nativeMemberPlanLoadTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, id uuid.UUID) (nativeMemberPlanRecord, error) {
	var r nativeMemberPlanRecord
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_plans WHERE id=$1 AND policy_id=$2 AND namespace=$3 FOR UPDATE`, id, policy.ID, policy.Metadata.Namespace).Scan(&raw)
	if e == nil {
		e = nativeMemberDecode(raw, &r)
	}
	if e != nil || r.Identity.PlanID != id {
		return nativeMemberPlanRecord{}, errNativeMember
	}
	return r, nil
}
func nativeMemberEventTx(ctx context.Context, tx *sql.Tx, p model.Manifest, plan, permit, read uuid.UUID, kind string, v any, now time.Time) error {
	raw, e := nativeMemberRecordBytes(v)
	if e != nil {
		return e
	}
	var pi, ri any
	if permit != uuid.Nil {
		pi = permit
	}
	if read != uuid.Nil {
		ri = read
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_member_events(plan_id,permit_id,read_id,policy_id,namespace,kind,record,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, plan, pi, ri, p.ID, p.Metadata.Namespace, kind, raw, now)
	return e
}
func nativeMemberWriteTx(ctx context.Context, tx *sql.Tx, p model.Manifest, r nativeMemberRecord, insert bool, now time.Time) error {
	raw, e := nativeMemberRecordBytes(r)
	if e != nil {
		return e
	}
	c := r.Context
	id, e := nativeMemberUUID(c.PermitID)
	if e != nil {
		return e
	}
	plan, e := nativeMemberUUID(c.PlanID)
	if e != nil {
		return e
	}
	attempt, e := nativeMemberUUID(c.AttemptID)
	if e != nil {
		return e
	}
	subject := c.Node.UID
	if c.Pod != nil {
		subject = c.Pod.UID
	}
	subjectID, e := nativeMemberUUID(subject)
	if e != nil {
		return e
	}
	if insert {
		cr, e := nativeMemberRecordBytes(c)
		if e != nil {
			return e
		}
		_, e = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_member_permits(id,plan_id,attempt_id,policy_id,namespace,action,capability,subject_uid,state,revision,context,record,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13)`, id, plan, attempt, p.ID, p.Metadata.Namespace, c.Action, c.Actor.Capability, subjectID, r.State, r.Revision, cr, raw, now)
		if e != nil {
			return e
		}
	} else {
		result, e := tx.ExecContext(ctx, `UPDATE public.capacity_native_worker_member_permits SET state=$2,revision=$3,record=$4,updated_at=$5 WHERE id=$1 AND revision=$6`, id, r.State, r.Revision, raw, now, r.Revision-1)
		if e != nil {
			return e
		}
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return errNativeMember
		}
	}
	return nativeMemberEventTx(ctx, tx, p, plan, id, uuid.Nil, r.State, r, now)
}

// Lock order is the existing dimension lock, Attempt, plan, effect/read. The
// record lookup before it is only a bounded selector, never permission.
func (st *nativeMemberStoreState) effect(ctx context.Context, id uuid.UUID, change func(*sql.Tx, model.CapacityPolicySpec, model.CapacityNativeWorkerAttempt, *nativeMemberRecord, time.Time) error) error {
	var attempt uuid.UUID
	if e := st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT attempt_id FROM public.capacity_native_worker_member_permits WHERE id=$1 AND policy_id=$2 AND namespace=$3`, id, st.policy.ID, st.policy.Metadata.Namespace).Scan(&attempt); e != nil {
		return errNativeMember
	}
	return st.workers.tx(ctx, st.policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		a, _, e := nativeAttemptLoadTx(ctx, tx, st.policy, attempt)
		if e != nil {
			return e
		}
		r, e := nativeMemberLoadTx(ctx, tx, st.policy, id)
		if e != nil {
			return e
		}
		if capacity.NativeWorkerMemberContextValid(p, a, r.Context, now, r.SeedID == uuid.Nil) != nil {
			return errNativeMember
		}
		return change(tx, p, a, &r, now)
	})
}

// Compare decrypted original bytes, not randomized ciphertext. Never overwrite
// a first capture and never return its token, raw body or digest to public code.
func (st *nativeMemberStoreState) capture(c model.CapacityNativeWorkerMemberContext, purpose string, old *nativeMemberCipher, raw []byte) (*nativeMemberCipher, error) {
	if old != nil {
		_, have, e := st.crypt(c, purpose, old, nil)
		defer clear(have)
		if e != nil || !bytes.Equal(have, raw) {
			return nil, errNativeMember
		}
		return old, nil
	}
	out, _, e := st.crypt(c, purpose, nil, raw)
	return out, e
}
