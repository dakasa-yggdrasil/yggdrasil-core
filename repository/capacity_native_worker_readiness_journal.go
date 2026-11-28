package repository

import (
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
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Private run custody precedes every diagnostic mutation. The journal owns no
// Kubernetes/provider client, cannot manufacture readiness and cannot renew an
// expired run. The producer must receive and verify each original effect.
var errNativeReadinessRun = errors.New("native readiness run unavailable")

type nativeReadinessRunIdentity struct {
	AttemptID      uuid.UUID `json:"attempt_id"`
	PolicyID       uuid.UUID `json:"policy_id"`
	PolicyChecksum string    `json:"policy_checksum"`
	Namespace      string    `json:"namespace"`
	SourceCommit   string    `json:"source_commit"`
	LaunchSHA256   string    `json:"launch_sha256"`
	BirthSHA256    string    `json:"birth_sha256"`
	NodeUID        string    `json:"node_uid"`
	ProviderID     string    `json:"provider_id"`
	Profile        string    `json:"profile"`
	Generation     int64     `json:"generation"`
	FencingToken   int64     `json:"fencing_token"`
	PoolUID        string    `json:"pool_uid"`
	PoolEpoch      int64     `json:"pool_epoch"`
	ProducerScope  string    `json:"producer_scope_sha256"`
	RunTemplate    string    `json:"run_template_sha256"`
}

type nativeReadinessEffect struct {
	Name           string    `json:"name"`
	Kind           string    `json:"kind"`
	TemplateSHA256 string    `json:"template_sha256"`
	State          string    `json:"state"`
	UID            string    `json:"uid,omitempty"`
	EvidenceSHA256 string    `json:"evidence_sha256,omitempty"`
	ObservedAt     time.Time `json:"observed_at,omitempty"`
	// These envelopes contain private request/original bytes, authenticated to
	// the immutable run plus purpose/slot. No raw Secret digest is public.
	PrivateRequest        *nativeReadinessCipher                  `json:"private_request,omitempty"`
	PrivateOriginal       *nativeReadinessCipher                  `json:"private_original,omitempty"`
	PrivateDeleteOriginal *nativeReadinessCipher                  `json:"private_delete_original,omitempty"`
	PrivateAbsence        *nativeReadinessCipher                  `json:"private_absence,omitempty"`
	SettlementTokenSHA256 string                                  `json:"settlement_token_sha256,omitempty"`
	CreateTokenSHA256     string                                  `json:"create_token_sha256,omitempty"`
	DeleteTokenSHA256     string                                  `json:"delete_token_sha256,omitempty"`
	ResourceVersion       string                                  `json:"resource_version,omitempty"`
	OperationExpiresAt    time.Time                               `json:"operation_expires_at,omitempty"`
	Context               *model.NativeWorkerProbeResourceContext `json:"context,omitempty"`
	DeleteContext         *model.NativeWorkerProbeResourceContext `json:"delete_context,omitempty"`
	StartupOrigin         *nativeReadinessOriginalStartupOrigin   `json:"startup_origin,omitempty"`
}

type nativeReadinessCipher struct {
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

type nativeReadinessRun struct {
	Schema       string                            `json:"schema"`
	ID           uuid.UUID                         `json:"id"`
	Identity     nativeReadinessRunIdentity        `json:"identity"`
	CreatedAt    time.Time                         `json:"created_at"`
	NotAfter     time.Time                         `json:"not_after"`
	Revision     int64                             `json:"revision"`
	Effects      []nativeReadinessEffect           `json:"effects"`
	Closed       bool                              `json:"closed"`
	Proof        *nativeReadinessProof             `json:"proof,omitempty"`
	PendingProof *nativeReadinessProof             `json:"pending_proof,omitempty"`
	Reads        map[string]*nativeReadinessCipher `json:"reads,omitempty"`
}

// Copies share key lifetime. Close excludes in-flight operations and wipes only
// this store's owned key, never the borrowed database or a global secret store.
type nativeReadinessRunKey struct {
	mu     sync.RWMutex
	closed bool
	key    []byte
}

type nativeReadinessRunJournal struct {
	db     *sql.DB
	policy model.Manifest
	source string
	scope  string
	tmpl   string
	key    *nativeReadinessRunKey
}

func newNativeReadinessRunJournal(db *sql.DB, policy model.Manifest, source, scope, tmpl string, key []byte) (*nativeReadinessRunJournal, error) {
	sourceBytes, se := hex.DecodeString(source)
	p, pe := parseCapacityPolicy(policy)
	if db == nil || policy.ID == uuid.Nil || policy.Checksum == "" || policy.Metadata.Namespace == "" || se != nil || len(sourceBytes) != 20 || hex.EncodeToString(sourceBytes) != source || pe != nil || capacity.ValidatePolicy(p) != nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.SourceCommit != source || !nativeReadinessSHA(scope) || !nativeReadinessSHA(tmpl) || len(key) != 32 {
		return nil, errNativeReadinessRun
	}
	var own model.Manifest
	raw, err := json.Marshal(policy)
	if err != nil || json.Unmarshal(raw, &own) != nil {
		return nil, errNativeReadinessRun
	}
	// Keep exact policy bytes, including JSONB spacing, for the normal guard.
	own.Spec = append(json.RawMessage(nil), policy.Spec...)
	return &nativeReadinessRunJournal{db: db, policy: own, source: source, scope: scope, tmpl: tmpl, key: &nativeReadinessRunKey{key: append([]byte(nil), key...)}}, nil
}

func (s *nativeReadinessRunJournal) close() {
	if s == nil || s.key == nil {
		return
	}
	s.key.mu.Lock()
	defer s.key.mu.Unlock()
	s.key.closed = true
	clear(s.key.key)
}

func nativeReadinessSHA(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

func nativeReadinessDigest(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", errNativeReadinessRun
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func (s *nativeReadinessRunJournal) identity(a model.CapacityNativeWorkerAttempt) (nativeReadinessRunIdentity, error) {
	if a.PolicyID != s.policy.ID || a.PolicyChecksum != s.policy.Checksum || a.Namespace != s.policy.Metadata.Namespace || a.SourceCommit != s.source || a.State != "registered" || a.Physical == nil || a.NodeUID == "" || !capacity.NativeWorkerPhysicalValid(a, *a.Physical) || !nativeReadinessSHA(a.LaunchSHA256) || !nativeReadinessSHA(a.BirthSHA256) {
		return nativeReadinessRunIdentity{}, errNativeReadinessRun
	}
	return nativeReadinessRunIdentity{AttemptID: a.ID, PolicyID: a.PolicyID, PolicyChecksum: a.PolicyChecksum, Namespace: a.Namespace, SourceCommit: s.source, LaunchSHA256: a.LaunchSHA256, BirthSHA256: a.BirthSHA256, NodeUID: a.NodeUID, ProviderID: a.Physical.ProviderID, Profile: a.Profile, Generation: a.Generation, FencingToken: a.FencingToken, PoolUID: a.PoolUID, PoolEpoch: a.PoolEpoch, ProducerScope: s.scope, RunTemplate: s.tmpl}, nil
}

func nativeReadinessAAD(r nativeReadinessRun) ([]byte, error) {
	return json.Marshal(struct {
		Schema string                     `json:"schema"`
		ID     uuid.UUID                  `json:"id"`
		Owner  nativeReadinessRunIdentity `json:"owner"`
		Start  time.Time                  `json:"start"`
		End    time.Time                  `json:"end"`
	}{r.Schema, r.ID, r.Identity, r.CreatedAt, r.NotAfter})
}

func (s *nativeReadinessRunJournal) crypt(r nativeReadinessRun, nonce, payload []byte, encrypt bool) ([]byte, []byte, error) {
	return s.cryptPurpose(r, "run-keys", nonce, payload, encrypt)
}

// The caller holds the shared key fence. Distinct purposes prevent an original
// ACK, a private Secret request, or another slot from becoming run key material.
func (s *nativeReadinessRunJournal) cryptPurpose(r nativeReadinessRun, purpose string, nonce, payload []byte, encrypt bool) ([]byte, []byte, error) {
	if purpose == "" || len(purpose) > 512 {
		return nil, nil, errNativeReadinessRun
	}
	block, err := aes.NewCipher(s.key.key)
	if err != nil {
		return nil, nil, errNativeReadinessRun
	}
	aead, err := cipher.NewGCM(block)
	identity, ae := nativeReadinessAAD(r)
	if err != nil || ae != nil {
		return nil, nil, errNativeReadinessRun
	}
	aad, ae := json.Marshal(struct {
		Run     json.RawMessage `json:"run"`
		Purpose string          `json:"purpose"`
	}{identity, purpose})
	if ae != nil {
		return nil, nil, errNativeReadinessRun
	}
	if encrypt {
		nonce = make([]byte, aead.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, nil, errNativeReadinessRun
		}
		return nonce, aead.Seal(nil, nonce, payload, aad), nil
	}
	if len(nonce) != aead.NonceSize() {
		return nil, nil, errNativeReadinessRun
	}
	plain, err := aead.Open(nil, nonce, payload, aad)
	if err != nil {
		return nil, nil, errNativeReadinessRun
	}
	return nil, plain, nil
}

// guard uses the immutable command and actual parent lease. It never adopts a
// different workflow, renews a lease, or infers useful capacity from a phase read.
func (s *nativeReadinessRunJournal) guard(ctx context.Context, tx *sql.Tx, a model.CapacityNativeWorkerAttempt, now time.Time) (time.Time, error) {
	var raw, launch, command []byte
	var checksum string
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND namespace=$2 FOR SHARE`, s.policy.ID, s.policy.Metadata.Namespace).Scan(&checksum, &active); err != nil || !active || checksum != s.policy.Checksum {
		return time.Time{}, errNativeReadinessRun
	}
	if err := tx.QueryRowContext(ctx, `SELECT attempt,launch_wire FROM public.capacity_native_worker_attempts WHERE id=$1 AND policy_id=$2 AND namespace=$3 FOR UPDATE`, a.ID, a.PolicyID, a.Namespace).Scan(&raw, &launch); err != nil {
		return time.Time{}, errNativeReadinessRun
	}
	var actual model.CapacityNativeWorkerAttempt
	want, err := json.Marshal(a)
	if err != nil || json.Unmarshal(raw, &actual) != nil {
		return time.Time{}, errNativeReadinessRun
	}
	have, err := json.Marshal(actual)
	sum := sha256.Sum256(launch)
	if err != nil || string(want) != string(have) || hex.EncodeToString(sum[:]) != a.LaunchSHA256 {
		return time.Time{}, errNativeReadinessRun
	}
	if err = tx.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_command_contexts WHERE attempt_id=$1`, a.ID).Scan(&command); err != nil {
		return time.Time{}, errNativeReadinessRun
	}
	var c nativeWorkerCommandContext
	p, pe := parseCapacityPolicy(s.policy)
	if pe != nil || json.Unmarshal(command, &c) != nil || c.AttemptID != a.ID || c.PolicyID != a.PolicyID || c.PolicyChecksum != a.PolicyChecksum || c.Namespace != a.Namespace || c.Generation != a.Generation || c.FencingToken != a.FencingToken || !validCapacityExecutor(c.ExecutorID) || c.WorkflowID == uuid.Nil || !c.ExpiresAt.After(now) {
		return time.Time{}, errNativeReadinessRun
	}
	if err = nativeMemberGrowthAllowedTx(ctx, tx, p, actual); err != nil {
		return time.Time{}, err
	}
	intent, err := loadCapacityIntent(ctx, tx, a.Namespace, p, true)
	if err != nil || intent.PolicyID != a.PolicyID || intent.PolicyChecksum != a.PolicyChecksum || intent.Generation != a.Generation || intent.FencingToken != a.FencingToken || intent.LeaseOwner == "" || intent.LeaseExecutorID != c.ExecutorID || intent.LeaseExpiresAt == nil || !intent.LeaseExpiresAt.After(now) || intent.RecoveryOnly || !intent.Decision.ExecutionPermitted || intent.Phase != "preparing" || intent.Assessment.NativeWorkerPool == nil || intent.Assessment.NativeWorkerPool.OwnerEpoch != a.PoolEpoch {
		return time.Time{}, errNativeReadinessRun
	}
	w := nativeCapacityWorkflow(p, false)
	if err = tx.QueryRowContext(ctx, `SELECT active FROM public.manifests WHERE id=$1 AND kind='workflow' AND namespace=$2 AND name=$3 AND jsonb_typeof(spec->'authorization')='object' FOR SHARE`, c.WorkflowID, w.Namespace, w.Name).Scan(&active); err != nil || !active {
		return time.Time{}, errNativeReadinessRun
	}
	commandExecution, ce := nativeReadinessDigest(c.Execution)
	attemptExecution, ae := nativeReadinessDigest(a.Execution)
	// Locks may have waited. Re-read the actual database clock after all joins;
	// no sender may inherit the timestamp from before a lock wait.
	if ce != nil || ae != nil || commandExecution != attemptExecution || tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil || !c.ExpiresAt.After(now) || !intent.LeaseExpiresAt.After(now) {
		return time.Time{}, errNativeReadinessRun
	}
	end := nativeReadinessRunEnd(now, c.ExpiresAt, *intent.LeaseExpiresAt, a.QualificationValidUntil)
	if !end.After(now) {
		return time.Time{}, errNativeReadinessRun
	}
	return end, nil
}

// open returns exactly the original encrypted run secret material on resume.
// generate is local cryptography only; it runs under SQL locks and MUST perform
// no network, provider/Secret lookup or diagnostic resource creation.
func (s *nativeReadinessRunJournal) open(ctx context.Context, a model.CapacityNativeWorkerAttempt, generate func(uuid.UUID, time.Time, time.Time) ([]byte, error)) (nativeReadinessRun, []byte, error) {
	var zero nativeReadinessRun
	if s == nil || s.key == nil || ctx == nil || ctx.Err() != nil || generate == nil {
		return zero, nil, errNativeReadinessRun
	}
	s.key.mu.RLock()
	defer s.key.mu.RUnlock()
	if s.key.closed {
		return zero, nil, errNativeReadinessRun
	}
	identity, err := s.identity(a)
	if err != nil {
		return zero, nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, nil, err
	}
	defer tx.Rollback()
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return zero, nil, err
	}
	// The same mutation-scope lock as the Native parent serializes first opens.
	p, err := parseCapacityPolicy(s.policy)
	if err != nil || lockMutationScope(ctx, tx, a.Namespace, p) != nil {
		return zero, nil, errNativeReadinessRun
	}
	end, err := s.guard(ctx, tx, a, now)
	if err != nil {
		return zero, nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return zero, nil, err
	}
	var raw, nonce, sealed []byte
	err = tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=50331648 THEN record END,key_nonce,key_ciphertext FROM public.capacity_native_worker_readiness_runs WHERE attempt_id=$1 FOR UPDATE`, a.ID).Scan(&raw, &nonce, &sealed)
	var r nativeReadinessRun
	if err == nil {
		// The row lock itself can wait past the run or current parent deadline.
		if tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil || !end.After(now) || capacity.DecodeNativeReadinessJournalJSON(raw, &r) != nil || r.Identity != identity || r.Closed || !r.NotAfter.After(now) || r.NotAfter.After(end) {
			return zero, nil, errNativeReadinessRun
		}
		_, plain, decryptErr := s.crypt(r, nonce, sealed, false)
		if decryptErr != nil {
			return zero, nil, decryptErr
		}
		if err = tx.Commit(); err != nil {
			clear(plain)
			return zero, nil, err
		}
		return r, plain, nil
	}
	if !errors.Is(err, sql.ErrNoRows) || !nativeReadinessNewRunHasBudget(now, end) {
		return zero, nil, errNativeReadinessRun
	}
	r = nativeReadinessRun{Schema: "native_worker_readiness_run_v1", ID: uuid.New(), Identity: identity, CreatedAt: now.UTC(), NotAfter: end.UTC(), Revision: 1, Effects: []nativeReadinessEffect{}}
	plain, err := generate(r.ID, r.CreatedAt, r.NotAfter)
	defer func() { clear(sealed) }()
	if err != nil || len(plain) < 32 || len(plain) > 32768 {
		clear(plain)
		return zero, nil, errNativeReadinessRun
	}
	nonce, sealed, err = s.crypt(r, nil, plain, true)
	if err != nil {
		clear(plain)
		return zero, nil, err
	}
	raw, err = json.Marshal(r)
	if err == nil && (tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil || !nativeReadinessNewRunHasBudget(now, end) || ctx.Err() != nil) {
		err = errNativeReadinessRun
	}
	if err == nil {
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_readiness_runs(attempt_id,id,revision,record,key_nonce,key_ciphertext,created_at,not_after) VALUES($1,$2,1,$3,$4,$5,$6,$7)`, a.ID, r.ID, raw, nonce, sealed, r.CreatedAt, r.NotAfter)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		clear(plain)
		return zero, nil, err
	}
	return r, plain, nil
}

// Resource slots are Source-closed. A workflow cannot use the journal as an
// arbitrary object writer. The producer independently validates each actual
// request/response UID, namespace, template, Source and original return closure.
func nativeReadinessSlot(r nativeReadinessRun, slot string) (string, string, bool) {
	prefix := "nwp-" + hex.EncodeToString(r.ID[:])[:20]
	type resource struct{ kind, suffix string }
	slots := map[string]resource{
		"floor_pod":         {"Pod", "fp"},
		"candidate_pod":     {"Pod", "cp"},
		"floor_service":     {"Service", "fs"},
		"candidate_service": {"Service", "cs"},
		"admission_secret":  {"Secret", "as"},
		"floor_secret":      {"Secret", "fc"},
		"candidate_secret":  {"Secret", "cc"},
		"network_policy":    {"NetworkPolicy", "np"},
		"floor_initial":     {"ProbeInitial", "fp"},
		"candidate_initial": {"ProbeInitial", "cp"},
		"floor_final":       {"ProbeFinal", "fp"},
		"candidate_final":   {"ProbeFinal", "cp"},
		"startup_challenge": {"StartupChallenge", "cp"},
	}
	v, ok := slots[slot]
	return prefix + "-" + v.suffix, v.kind, ok
}

func nativeReadinessObjectKind(kind string) bool {
	return kind == "Pod" || kind == "Service" || kind == "Secret" || kind == "NetworkPolicy"
}

func (s *nativeReadinessRunJournal) edit(ctx context.Context, expected nativeReadinessRun, grow *model.CapacityNativeWorkerAttempt, change func(*nativeReadinessRun, time.Time) error) (nativeReadinessRun, error) {
	return s.editEvent(ctx, expected, grow, nil, change)
}

func (s *nativeReadinessRunJournal) editEvent(ctx context.Context, expected nativeReadinessRun, grow *model.CapacityNativeWorkerAttempt, event *NativeWorkerProbeResourceEvent, change func(*nativeReadinessRun, time.Time) error) (nativeReadinessRun, error) {
	var zero nativeReadinessRun
	if s == nil || s.key == nil || ctx == nil || ctx.Err() != nil || change == nil || expected.ID == uuid.Nil || expected.Identity.SourceCommit != s.source || expected.Identity.PolicyID != s.policy.ID || expected.Identity.PolicyChecksum != s.policy.Checksum || expected.Identity.Namespace != s.policy.Metadata.Namespace || expected.Identity.ProducerScope != s.scope || expected.Identity.RunTemplate != s.tmpl {
		return zero, errNativeReadinessRun
	}
	s.key.mu.RLock()
	defer s.key.mu.RUnlock()
	if s.key.closed {
		return zero, errNativeReadinessRun
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	p, err := parseCapacityPolicy(s.policy)
	if err != nil || lockMutationScope(ctx, tx, expected.Identity.Namespace, p) != nil {
		return zero, errNativeReadinessRun
	}
	var raw []byte
	var growEnd time.Time
	if grow != nil {
		var now time.Time
		if tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil {
			return zero, errNativeReadinessRun
		}
		id, ie := s.identity(*grow)
		if ie != nil || id != expected.Identity {
			return zero, errNativeReadinessRun
		}
		if growEnd, err = s.guard(ctx, tx, *grow, now); err != nil {
			return zero, err
		}
	}
	if err = tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=50331648 THEN record END FROM public.capacity_native_worker_readiness_runs WHERE attempt_id=$1 AND id=$2 FOR UPDATE`, expected.Identity.AttemptID, expected.ID).Scan(&raw); err != nil {
		return zero, errNativeReadinessRun
	}
	var current nativeReadinessRun
	if capacity.DecodeNativeReadinessJournalJSON(raw, &current) != nil || current.Identity != expected.Identity || current.Revision != expected.Revision || current.Closed {
		return zero, errNativeReadinessRun
	}
	var now time.Time
	if tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now) != nil || (grow != nil && (!current.NotAfter.After(now) || !growEnd.After(now) || current.NotAfter.After(growEnd))) {
		return zero, errNativeReadinessRun
	}
	before, err := nativeReadinessAAD(current)
	if err != nil || change(&current, now.UTC()) != nil {
		return zero, errNativeReadinessRun
	}
	after, ae := nativeReadinessAAD(current)
	if ae != nil || string(before) != string(after) || current.Revision != expected.Revision {
		return zero, errNativeReadinessRun
	}
	current.Revision++
	raw, err = json.Marshal(current)
	if err == nil {
		_, err = tx.ExecContext(ctx, `UPDATE public.capacity_native_worker_readiness_runs SET revision=$3,record=$4 WHERE attempt_id=$1 AND id=$2`, current.Identity.AttemptID, current.ID, current.Revision, raw)
	}
	if err == nil && event != nil {
		err = nativeReadinessEmitEvent(ctx, tx, *event)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return zero, err
	}
	return current, nil
}

// The committed send_started row is the only initial dispatch right. Concurrent
// callers and process restarts observe it and perform GET-only receiving. There
// is no reset-to-planned state, including when the sender died before the RPC.
func (s *nativeReadinessRunJournal) begin(ctx context.Context, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun, slot, templateSHA string) (nativeReadinessRun, error) {
	name, kind, ok := nativeReadinessSlot(r, slot)
	if !ok || !nativeReadinessSHA(templateSHA) {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return s.edit(ctx, r, &a, func(current *nativeReadinessRun, now time.Time) error {
		if len(current.Effects) >= 13 {
			return errNativeReadinessRun
		}
		for _, effect := range current.Effects {
			if effect.Name == name && effect.Kind == kind {
				return errNativeReadinessRun
			}
		}
		current.Effects = append(current.Effects, nativeReadinessEffect{Name: name, Kind: kind, TemplateSHA256: templateSHA, State: "requested", ObservedAt: now, OperationExpiresAt: current.NotAfter})
		return nil
	})
}

// Receiving is allowed after a lease/run deadline: it grants no new effect and
// preserves facts about the original operation. An unknown create GET404 may
// never use this method as proof of absence; absence needs known original UID.
func (s *nativeReadinessRunJournal) receive(ctx context.Context, r nativeReadinessRun, slot, uid, templateSHA, evidence string, observed time.Time) (nativeReadinessRun, error) {
	name, kind, ok := nativeReadinessSlot(r, slot)
	_, ue := uuid.Parse(uid)
	if !ok || ue != nil || !nativeReadinessSHA(templateSHA) || !nativeReadinessSHA(evidence) || observed.IsZero() {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return s.edit(ctx, r, nil, func(current *nativeReadinessRun, now time.Time) error {
		if observed.Before(current.CreatedAt) || observed.After(now) {
			return errNativeReadinessRun
		}
		for i := range current.Effects {
			e := &current.Effects[i]
			if e.Name == name && e.Kind == kind && e.TemplateSHA256 == templateSHA && e.State == "received" && e.PrivateOriginal != nil && e.UID == "" {
				e.UID, e.EvidenceSHA256, e.State, e.ObservedAt = uid, evidence, "observed", observed
				return nil
			}
		}
		return errNativeReadinessRun
	})
}

func (s *nativeReadinessRunJournal) beginDelete(ctx context.Context, r nativeReadinessRun, slot string) (nativeReadinessRun, error) {
	name, kind, ok := nativeReadinessSlot(r, slot)
	if !ok || !nativeReadinessObjectKind(kind) {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return s.edit(ctx, r, nil, func(current *nativeReadinessRun, now time.Time) error {
		for i := range current.Effects {
			e := &current.Effects[i]
			if e.Name == name && e.Kind == kind && e.State == "observed" && e.UID != "" {
				e.State, e.ObservedAt = "delete_requested", now
				e.SettlementTokenSHA256 = ""
				e.OperationExpiresAt = now.Add(20 * time.Second)
				return nil
			}
		}
		return errNativeReadinessRun
	})
}

func (s *nativeReadinessRunJournal) finish(ctx context.Context, r nativeReadinessRun) (nativeReadinessRun, error) {
	return s.edit(ctx, r, nil, func(current *nativeReadinessRun, _ time.Time) error {
		for _, e := range current.Effects {
			if (nativeReadinessObjectKind(e.Kind) && e.State != "absent") || (!nativeReadinessObjectKind(e.Kind) && e.State != "observed") {
				return errNativeReadinessRun
			}
		}
		current.Closed = true
		return nil
	})
}

// GET-only recovery needs no new lease and no decryption. It preserves an
// expired run's footprint for exact cleanup instead of minting new identities.
func (s *nativeReadinessRunJournal) read(ctx context.Context, attempt uuid.UUID) (nativeReadinessRun, error) {
	var r nativeReadinessRun
	if s == nil || s.key == nil || ctx == nil || ctx.Err() != nil || attempt == uuid.Nil {
		return r, errNativeReadinessRun
	}
	s.key.mu.RLock()
	defer s.key.mu.RUnlock()
	if s.key.closed {
		return r, errNativeReadinessRun
	}
	var raw []byte
	if s.db.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=50331648 THEN record END FROM public.capacity_native_worker_readiness_runs WHERE attempt_id=$1`, attempt).Scan(&raw) != nil || capacity.DecodeNativeReadinessJournalJSON(raw, &r) != nil || r.Schema != "native_worker_readiness_run_v1" || r.Identity.AttemptID != attempt || r.Identity.PolicyID != s.policy.ID || r.Identity.PolicyChecksum != s.policy.Checksum || r.Identity.Namespace != s.policy.Metadata.Namespace || r.Identity.SourceCommit != s.source || r.Identity.ProducerScope != s.scope || r.Identity.RunTemplate != s.tmpl {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return r, nil
}
