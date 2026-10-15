package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityhostfactory"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrHostFactoryHold = errors.New("original host factory unavailable; same-original read only")

const hostFactoryClass = "original_source_owned_factory"

// This is a private, actual source capability. No JSON, context label, signing
// key argument or caller-built receipt can construct an OriginalFactoryRealm.
type hostOriginalClaim struct {
	mu                                                           sync.Mutex
	realm                                                        *capacityhostfactory.OriginalFactoryRealm
	invocation, rootID, attemptID, creatorOwnerID, registryClass string
	preparation, initial, assessment, intent, approval           []byte
	committed                                                    bool
	claimCalledAt, claimReturnedAt                               time.Time
	claimReturnReserved                                          bool
	claimReturnedProjection                                      []byte
	claimReturnErr                                               error
	rootRecords                                                  []hostOriginalRetainedRecord
	awaiting                                                     *hostOriginalAwaitingReturn
	preparationReturn                                            *hostOriginalPreparationReturn
}

// Private SQL carrier, never a Host signed body or public DTO. The exact field
// order/types are frozen in awaiting-owner-private-api-r2.json.
type hostOriginalAwaitingRecord struct {
	RootID                       string                        `json:"root_id"`
	NativeFactoryRootID          string                        `json:"native_factory_root_id"`
	StableTargetSHA256           string                        `json:"stable_target_sha256"`
	StableTargetWireBase64       string                        `json:"stable_target_wire_base64"`
	FactoryAttemptID             string                        `json:"factory_attempt_id"`
	CreatorOwnerID               string                        `json:"creator_owner_id"`
	FactoryClass                 string                        `json:"factory_class"`
	EntryClass                   string                        `json:"entry_class"`
	OriginalInvocationID         string                        `json:"original_invocation_id"`
	Namespace                    string                        `json:"namespace"`
	Environment                  string                        `json:"environment"`
	Domain                       string                        `json:"domain"`
	Dimension                    string                        `json:"dimension"`
	TargetIdentity               string                        `json:"target_identity"`
	MutationBindingName          string                        `json:"mutation_binding_name"`
	Slot                         int                           `json:"slot"`
	PolicyID                     string                        `json:"policy_id"`
	PolicyChecksum               string                        `json:"policy_checksum"`
	WorkflowID                   string                        `json:"workflow_id"`
	WorkflowChecksum             string                        `json:"workflow_checksum"`
	OriginalStepID               string                        `json:"original_step_id"`
	OriginalStepTimeoutSeconds   int                           `json:"original_step_timeout_seconds"`
	Generation                   int64                         `json:"generation"`
	Fence                        int64                         `json:"fence"`
	LeaseOwnerSHA256             string                        `json:"lease_owner_sha256"`
	ExecutorID                   string                        `json:"executor_id"`
	OriginalLeaseExpiresAt       time.Time                     `json:"original_lease_expires_at"`
	OriginalContextDeadline      time.Time                     `json:"original_context_deadline"`
	OriginalClaimIntentRawSHA256 string                        `json:"original_claim_intent_raw_sha256"`
	SourceApprovalSHA256         string                        `json:"source_approval_sha256"`
	CoreActualSourceCommit       string                        `json:"core_actual_source_commit"`
	Binding                      model.CapacityMutationBinding `json:"binding"`
}

type hostOriginalAwaitingReturn struct {
	raw                  []byte
	calledAt, returnedAt time.Time
	committed            bool
	originalErr          error
}

// Source-private ownership of the sole registration attempt. These buffers
// are original inputs/custody, never a signed native body or readiness flag.
type hostOriginalPreparationReturn struct {
	claim                                                                                                                       *hostOriginalClaim
	realm                                                                                                                       *capacityhostfactory.OriginalFactoryRealm
	db                                                                                                                          *sql.DB
	ctx                                                                                                                         context.Context
	entry, handle                                                                                                               string
	bindingRaw, preparedRaw, registrationRaw                                                                                    []byte
	stages                                                                                                                      map[string][]byte
	calledAt, commitCalledAt, commitReturnedAt, transactionReturnedAt, methodFinishedAt, externalCalledAt, returnedAt, deadline time.Time
	committed                                                                                                                   bool
	externalReturnReserved                                                                                                      bool
	postStart                                                                                                                   *hostOriginalPostStartCaptureReturn
	admissionErr                                                                                                                error
	originalErr                                                                                                                 error
}

func (s CapacityStore) beginOriginalHostPreparation(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, entry string, bindingRaw []byte, stages map[string][]byte) (*hostOriginalPreparationReturn, error) {
	h := s.hostOriginalClaim
	if ctx == nil || ctx.Err() != nil || h == nil || realm == nil || s.DB == nil || h.realm != realm || h.invocation != s.ExecutorID || (entry != "sealed_a0" && entry != "sealed_a1" && entry != "ordinary_original_create") {
		return nil, ErrHostFactoryHold
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) {
		return nil, ErrHostFactoryHold
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.committed || h.claimReturnErr != nil || h.claimReturnedAt.IsZero() || h.awaiting == nil || !h.awaiting.committed || h.awaiting.originalErr != nil || h.awaiting.returnedAt.IsZero() || h.preparationReturn != nil {
		return nil, ErrHostFactoryHold
	}
	var awaiting hostOriginalAwaitingRecord
	if hostOriginalStrictJSON(h.awaiting.raw, &awaiting, 65536) != nil || awaiting.EntryClass != entry || awaiting.RootID != h.rootID || awaiting.FactoryAttemptID != h.attemptID || awaiting.CreatorOwnerID != h.creatorOwnerID || awaiting.OriginalInvocationID != h.invocation || deadline.After(awaiting.OriginalContextDeadline) {
		return nil, ErrHostFactoryHold
	}
	original := &hostOriginalPreparationReturn{claim: h, realm: realm, db: s.DB, ctx: ctx, entry: entry, calledAt: time.Now().UTC(), deadline: deadline}
	h.preparationReturn = original // BEFORE input copying, Source getters or SQL
	if !original.calledAt.Before(deadline) || ctx.Err() != nil {
		original.originalErr = ErrHostFactoryHold
		return nil, ErrHostFactoryHold
	}
	if len(bindingRaw) == 0 || len(bindingRaw) > 65536 || len(stages) == 0 || len(stages) > 32768 {
		original.originalErr = ErrHostFactoryHold
		return nil, ErrHostFactoryHold
	}
	original.bindingRaw, original.stages = bytes.Clone(bindingRaw), make(map[string][]byte, len(stages))
	total := 0
	for selector, raw := range stages {
		if len(raw) == 0 || len(raw) > 65536 || total > 32*1024*1024-len(raw) {
			original.originalErr = ErrHostFactoryHold
			return nil, ErrHostFactoryHold
		}
		total += len(raw)
		original.stages[selector] = bytes.Clone(raw)
	}
	return original, nil
}

func (s CapacityStore) finishOriginalHostPreparation(original *hostOriginalPreparationReturn, runErr error) error {
	returnedAt := time.Now().UTC()
	h := s.hostOriginalClaim
	if h == nil || original == nil {
		return errors.Join(runErr, ErrHostFactoryHold)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.preparationReturn != original || original.claim != h || original.realm != h.realm || original.db != s.DB || !original.methodFinishedAt.IsZero() || !original.committed || original.calledAt.IsZero() || original.commitCalledAt.IsZero() || original.commitCalledAt.Before(original.calledAt) || original.commitReturnedAt.IsZero() || original.commitReturnedAt.Before(original.commitCalledAt) || original.transactionReturnedAt.IsZero() || original.transactionReturnedAt.Before(original.commitReturnedAt) || returnedAt.Before(original.transactionReturnedAt) || !returnedAt.Before(original.deadline) || original.ctx == nil || original.ctx.Err() != nil || original.originalErr != nil {
		runErr = errors.Join(runErr, original.originalErr, ErrHostFactoryHold)
	}
	// This defer marker precedes Register's GoReturn. Only its lexical
	// Source caller may capture the distinct returnedAt below.
	original.methodFinishedAt, original.originalErr = returnedAt, runErr
	return runErr
}

// CaptureOriginalHostPreparationReturn is called immediately AFTER the sole
// RegisterOriginal{Host,Ordinary}Preparation call returns, with calledAt sampled
// BEFORE that same call. It records a private original return, not permission
// supplied by a public DTO. No callback runs after a panic without a GoReturn.
func (s CapacityStore) CaptureOriginalHostPreparationReturn(ctx context.Context, calledAt, returnedAt time.Time, preparationErr error) error {
	h := s.hostOriginalClaim
	if h == nil {
		return errors.Join(preparationErr, ErrHostFactoryHold)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.preparationReturn
	if r == nil {
		return errors.Join(preparationErr, ErrHostFactoryHold)
	}
	if r.externalReturnReserved {
		r.admissionErr = errors.Join(r.admissionErr, ErrHostFactoryHold)
		return errors.Join(preparationErr, ErrHostFactoryHold)
	}
	r.externalReturnReserved = true // unknown/foreign/late can never retry
	r.externalCalledAt, r.returnedAt = calledAt, returnedAt
	r.originalErr = errors.Join(r.originalErr, preparationErr)
	if ctx == nil || ctx != r.ctx || ctx.Err() != nil || r.claim != h || r.realm != h.realm || r.db != s.DB || s.DB == nil || s.ExecutorID != h.invocation || calledAt.IsZero() || calledAt.After(r.calledAt) || returnedAt.IsZero() || returnedAt.Before(calledAt) || r.methodFinishedAt.IsZero() || returnedAt.Before(r.methodFinishedAt) || !returnedAt.Before(r.deadline) || !r.committed || r.originalErr != nil {
		r.originalErr = errors.Join(r.originalErr, ErrHostFactoryHold)
	}
	return r.originalErr
}

func originalHostPreparationCompleted(h *hostOriginalClaim, realm *capacityhostfactory.OriginalFactoryRealm, db *sql.DB, entry string, bindingRaw []byte, handle string) bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.preparationReturn
	return r != nil && r.claim == h && r.realm == realm && r.db == db && db != nil && r.ctx != nil && r.entry == entry && r.handle == handle && handle != "" && bytes.Equal(r.bindingRaw, bindingRaw) && len(r.preparedRaw) > 0 && len(r.registrationRaw) > 0 && r.committed && r.originalErr == nil && r.admissionErr == nil && r.externalReturnReserved && !r.externalCalledAt.IsZero() && !r.externalCalledAt.After(r.calledAt) && !r.calledAt.IsZero() && !r.commitCalledAt.IsZero() && !r.commitCalledAt.Before(r.calledAt) && !r.commitReturnedAt.IsZero() && !r.commitReturnedAt.Before(r.commitCalledAt) && !r.transactionReturnedAt.IsZero() && !r.transactionReturnedAt.Before(r.commitReturnedAt) && !r.methodFinishedAt.IsZero() && !r.methodFinishedAt.Before(r.transactionReturnedAt) && !r.returnedAt.IsZero() && !r.returnedAt.Before(r.methodFinishedAt) && r.returnedAt.Before(r.deadline) && (entry == "ordinary_original_create" || originalHostPostStartCaptureComplete(r))
}

func (s CapacityStore) captureOriginalHostPreparationCommit(original *hostOriginalPreparationReturn) func(time.Time, time.Time, error) {
	return func(calledAt, returnedAt time.Time, commitErr error) {
		h := s.hostOriginalClaim
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.preparationReturn != original || !original.commitCalledAt.IsZero() {
			original.originalErr = ErrHostFactoryHold
			return
		}
		original.commitCalledAt, original.commitReturnedAt, original.committed = calledAt, returnedAt, commitErr == nil
		original.originalErr = commitErr
	}
}

type hostOriginalRetainedRecord struct {
	selector             HostFactoryRecordSelector
	body                 any
	bodyRaw, envelopeRaw []byte
}

type hostOriginalFactoryScope struct {
	mu                             sync.Mutex
	realm                          *capacityhostfactory.OriginalFactoryRealm
	scope                          model.HostFactoryPreAuthorityScope
	scopeRaw                       []byte
	registration                   model.HostFactoryAliveRegistration
	prepared                       model.HostFactoryPreparedCreatePlan
	policy                         model.Manifest
	policySpec                     model.CapacityPolicySpec
	binding                        model.CapacityMutationBinding
	leaseOwner                     string
	grantRaw, preRaw               []byte
	attachmentRaw                  []byte
	grant                          model.CapacityMutationGrant
	pre                            model.CapacityGuestOriginalProvisioningPreregistration
	issueCommitted                 bool
	issueReserved                  bool
	issueContext                   context.Context
	issueDeadline                  time.Time
	issueCalledAt, issueReturnedAt time.Time
	issueReturnReserved            bool
	issueCaptured                  bool
	issueReturnErr                 error
}

// Ordinary registration retains its private early Source binding and the
// independent registrar leaf. It never borrows a Host scope/Alive body.
type hostOriginalOrdinaryFactory struct {
	mu                                       sync.Mutex
	realm                                    *capacityhostfactory.OriginalFactoryRealm
	claim                                    *hostOriginalClaim
	binding                                  model.FactoryOrdinarySourceBinding
	bindingRaw, preparedRaw, registrationRaw []byte
	prepared                                 model.HostFactoryPreparedCreatePlan
	policy, workflow                         model.Manifest
	policySpec                               model.CapacityPolicySpec
	mutationBinding                          model.CapacityMutationBinding
	leaseOwner                               string
	grant                                    model.CapacityMutationGrant
	pre                                      model.CapacityGuestOriginalProvisioningPreregistration
	grantRaw, preRaw                         []byte
	issueCommitted                           bool
	issueReserved                            bool
	issueContext                             context.Context
	issueDeadline                            time.Time
	issueCaptured                            bool
	issueCalledAt, issueReturnedAt           time.Time
	issueReturnReserved                      bool
	issueReturnErr                           error
	continued                                bool
	continueErr                              error
	proof                                    model.CapacityMutationProof
	nativeRaw                                []byte
}

var installedHostFactory struct {
	sync.Mutex
	realm             *capacityhostfactory.OriginalFactoryRealm
	approval          model.HostFactorySourceApproval
	ordinaryReads     map[string]*hostOrdinaryReadReservation
	ordinaryFactories map[string]*hostOriginalOrdinaryFactory
	closingSQL        *hostOriginalClosingSQLReturn
	prime             *hostOriginalPrimeReturn
}

type hostOriginalPrimeReturn struct {
	realm                            *capacityhostfactory.OriginalFactoryRealm
	db                               *sql.DB
	root, nativeRoot, attempt, owner string
	calledAt, returnedAt, deadline   time.Time
	committed                        bool
	originalErr                      error
	admissionErr                     error
}

// This checks the retained private owning return, not a serialized readiness
// flag. Callers must still pass the actual installed Source and policy gates.
func (r *hostOriginalPrimeReturn) completedFor(realm *capacityhostfactory.OriginalFactoryRealm, db *sql.DB, root string) bool {
	return r != nil && realm != nil && db != nil && r.realm == realm && r.db == db && r.root == root && root != "" && validCapacityExecutor(r.nativeRoot) && validCapacityExecutor(r.attempt) && validCapacityExecutor(r.owner) && r.committed && r.originalErr == nil && r.admissionErr == nil && !r.calledAt.IsZero() && !r.returnedAt.IsZero() && !r.deadline.IsZero() && !r.returnedAt.Before(r.calledAt) && r.returnedAt.Before(r.deadline)
}

func (r *hostOriginalPrimeReturn) completedWithin(realm *capacityhostfactory.OriginalFactoryRealm, db *sql.DB, root string, currentDeadline time.Time) bool {
	return r.completedFor(realm, db, root) && !currentDeadline.IsZero() && !currentDeadline.After(r.deadline)
}

// PrimeOriginalHostRoot persists only the original Source bookkeeping. It
// precedes public Assess/Claim effects so native readers can resolve actual
// SAME-SQL FIRST relations. Source/raw getters alone are never assessment
// authority. Unknown Commit/late return consumes the first attempt forever.
func (s CapacityStore) PrimeOriginalHostRoot(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, policy, workflow model.Manifest, assessStep, claimStep, provisionStep model.WorkflowStepSpec) (runErr error) {
	codec := originalHostSourceCodecRealm(ctx, realm)

	actual, approval, installed := OriginalHostFactoryRealm()
	deadline, bounded := time.Time{}, false
	if ctx != nil {
		deadline, bounded = ctx.Deadline()
	}
	if !installed || actual != realm || realm == nil || s.DB == nil || !bounded || ctx.Err() != nil || !time.Now().Before(deadline) || policy.ID.String() != approval.AllowedPolicyID || policy.Metadata.Namespace != approval.AllowedNamespace || realm.VerifyLive(ctx) != nil {
		return ErrHostFactoryHold
	}
	if realm.VerifyOriginalPolicyInput(ctx, policy, workflow, assessStep, claimStep, provisionStep) != nil {
		return ErrHostFactoryHold
	}
	installedHostFactory.Lock()
	if old := installedHostFactory.prime; old != nil {
		// Replay is only this original completed return, never fresh SQL or
		// a retry after a pending/error/unknown first attempt.
		ok := old.completedFor(realm, s.DB, approval.ScopeRootID)
		installedHostFactory.Unlock()
		if !ok {
			return ErrHostFactoryHold
		}
		return nil
	}
	original := &hostOriginalPrimeReturn{realm: realm, db: s.DB, root: approval.ScopeRootID, calledAt: time.Now().UTC(), deadline: deadline}
	installedHostFactory.prime = original // BEFORE every owning getter/SQL attempt
	installedHostFactory.Unlock()
	defer func() {
		if cause := recover(); cause != nil {
			installedHostFactory.Lock()
			original.originalErr = ErrHostFactoryHold
			// Unwinding is not the original owning Go return. Keep pending,
			// including any already committed rows, and never reopen FIRST.
			installedHostFactory.Unlock()
			panic(cause)
		}
		returned := time.Now().UTC()
		if ctx.Err() != nil || !returned.Before(deadline) {
			runErr = errors.Join(runErr, ErrHostFactoryHold)
		}
		installedHostFactory.Lock()
		original.returnedAt, original.originalErr = returned, runErr
		installedHostFactory.Unlock()
	}()
	if _, err := capacity.ApprovedHostFactorySource(); err != nil {
		return ErrHostFactoryHold
	}
	attempt, owner, class, err := realm.OriginalRootIdentity(ctx)
	stages, stageErr := realm.OriginalRootStages(ctx)
	if err != nil || stageErr != nil || !validCapacityExecutor(attempt) || !validCapacityExecutor(owner) || class != hostFactoryClass {
		return ErrHostFactoryHold
	}
	for _, name := range []string{"source-approval", "basal-owner-core", "bootstrap-return-core", "root-preparation", "basal-owner-registrar", "bootstrap-return-registrar", "native-leaf-core-by-registrar", "native-leaf-registrar-by-core", "initial-empty-realm-read", "bootstrap-write-registrar"} {
		if len(stages[name]) == 0 {
			return ErrHostFactoryHold
		}
	}
	records, err := prepareOriginalHostRecords(ctx, approval.ScopeRootID, "", stages)
	if err != nil {
		return err
	}
	var prep model.HostFactoryRootPreparation
	var initial model.HostFactoryInitialEmptyRealmRead
	var prepRaw, initialRaw []byte
	for _, record := range records {
		if record.selector.Family != "root" || record.selector.Stage == "root-completion" {
			return ErrHostFactoryHold
		}
		if record.selector.Stage == "root-preparation" {
			prepRaw = record.bodyRaw
			if codec.Decode(prepRaw, &prep) != nil {
				return ErrHostFactoryHold
			}
		}
		if record.selector.Stage == "initial-empty-realm-read" {
			initialRaw = record.bodyRaw
			if codec.Decode(initialRaw, &initial) != nil {
				return ErrHostFactoryHold
			}
		}
	}
	if len(prepRaw) == 0 || len(initialRaw) == 0 || initial.FactoryRootID != prep.FactoryRootID || initial.RootPreparationSHA256 != capacity.HostFactoryRawSHA256(prepRaw) || initial.SourceApprovalSHA256 != capacity.GuestRetirementSHA(approval) || prep.OriginalContextDeadline.Before(deadline) {
		return ErrHostFactoryHold
	}
	approvalRaw, err := codec.Canonical(approval)
	if err != nil {
		return err
	}
	rootKey, err := json.Marshal([]string{approval.ScopeRootID, prep.FactoryRootID, attempt, owner, class})
	if err != nil {
		return err
	}
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return err
	}
	// No existing/restored Root is adopted as a new first Source initializer.
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_roots(scope_root_id,factory_realm_id,factory_attempt_id,creator_owner_id,factory_registry_class,root_key_sha256,source_approval_sha256,source_approval_wire,root_preparation_sha256,root_preparation_wire,original_started_at,original_deadline,root_device,root_inode,source_closure_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, approval.ScopeRootID, prep.FactoryRootID, attempt, owner, class, capacity.HostFactoryRawSHA256(rootKey), capacity.HostFactoryRawSHA256(approvalRaw), approvalRaw, capacity.HostFactoryRawSHA256(prepRaw), prepRaw, prep.OriginalContextStartedAt, prep.OriginalContextDeadline, strconv.FormatUint(prep.RootDirectorySource.Device, 10), strconv.FormatUint(prep.RootDirectorySource.Inode, 10), approval.FactorySourceClosureSHA256)
	if err != nil {
		return err
	}
	// Establish actual FIRST/successor relations. In-TX graph checks may block
	// a bad commit; only the separate post-GoReturn guard admits an effect.
	if err = s.appendOriginalHostRecordsTx(ctx, tx, records); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	installedHostFactory.Lock()
	original.committed, original.nativeRoot, original.attempt, original.owner = true, prep.FactoryRootID, attempt, owner
	installedHostFactory.Unlock()
	return nil
}

// GuardOriginalHostPrimedRoot is the current admission read AFTER the primer's
// actual Commit and owning Go return. Provisional validation under the writing
// TX cannot substitute this read, and this method acquires no new native facts.
func (s CapacityStore) GuardOriginalHostPrimedRoot(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, policy, workflow model.Manifest, assessStep, claimStep, provisionStep model.WorkflowStepSpec) (runErr error) {
	codec := originalHostSourceCodecRealm(ctx, realm)

	actual, approval, installed := OriginalHostFactoryRealm()
	deadline, bounded := time.Time{}, false
	if ctx != nil {
		deadline, bounded = ctx.Deadline()
	}
	if !installed || actual != realm || realm == nil || s.DB == nil || !bounded || ctx.Err() != nil || !time.Now().Before(deadline) || realm.VerifyLive(ctx) != nil || realm.VerifyOriginalPolicyInput(ctx, policy, workflow, assessStep, claimStep, provisionStep) != nil {
		return ErrHostFactoryHold
	}
	installedHostFactory.Lock()
	original := installedHostFactory.prime
	complete := original.completedWithin(realm, s.DB, approval.ScopeRootID, deadline)
	installedHostFactory.Unlock()
	if !complete {
		return ErrHostFactoryHold
	}
	defer func() {
		if cause := recover(); cause != nil {
			installedHostFactory.Lock()
			original.admissionErr = ErrHostFactoryHold
			installedHostFactory.Unlock()
			panic(cause)
		}
		returnedAt := time.Now()
		if ctx.Err() != nil || !returnedAt.Before(deadline) || !returnedAt.Before(original.deadline) {
			runErr = errors.Join(runErr, ErrHostFactoryHold)
		}
		installedHostFactory.Lock()
		if !original.completedFor(realm, s.DB, approval.ScopeRootID) {
			runErr = errors.Join(runErr, ErrHostFactoryHold)
		}
		if runErr != nil {
			original.admissionErr = errors.Join(original.admissionErr, runErr)
		}
		installedHostFactory.Unlock()
	}()
	stages, err := realm.OriginalRootStages(ctx)
	if err != nil {
		return err
	}
	records, err := prepareOriginalHostRecords(ctx, approval.ScopeRootID, "", stages)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var nativeRoot, attempt, owner, class string
	var approvalRaw, preparationRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT factory_realm_id::text,factory_attempt_id::text,creator_owner_id::text,factory_registry_class,source_approval_wire,root_preparation_wire FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, approval.ScopeRootID).Scan(&nativeRoot, &attempt, &owner, &class, &approvalRaw, &preparationRaw); err != nil || nativeRoot != original.nativeRoot || attempt != original.attempt || owner != original.owner || class != hostFactoryClass {
		return ErrHostFactoryHold
	}
	var approved model.HostFactorySourceApproval
	var preparation model.HostFactoryRootPreparation
	if codec.Decode(approvalRaw, &approved) != nil || codec.Decode(preparationRaw, &preparation) != nil || capacity.GuestRetirementSHA(approved) != capacity.GuestRetirementSHA(approval) || preparation.FactoryRootID != nativeRoot {
		return ErrHostFactoryHold
	}
	matchedApproval, matchedPreparation := false, false
	for _, record := range records {
		if record.selector.Stage == "source-approval" {
			matchedApproval = bytes.Equal(record.bodyRaw, approvalRaw)
		}
		if record.selector.Stage == "root-preparation" {
			matchedPreparation = bytes.Equal(record.bodyRaw, preparationRaw)
		}
	}
	if !matchedApproval || !matchedPreparation {
		return ErrHostFactoryHold
	}
	if err = s.compareOriginalHostRecordsTx(ctx, tx, records); err != nil {
		return err
	}
	// SAME current compiled Source and actual logical policy guards remain
	// mandatory at the owning read's end. No snapshots/deadlines are renewed.
	if realm.VerifyLive(ctx) != nil || realm.VerifyOriginalPolicyInput(ctx, policy, workflow, assessStep, claimStep, provisionStep) != nil {
		return ErrHostFactoryHold
	}
	return tx.Commit()
}

type hostOrdinaryReadReservation struct {
	phase, attempt, grant, pre string
	signedReturned             bool
}

func reserveOriginalOrdinaryRead(realm *capacityhostfactory.OriginalFactoryRealm, selector HostFactoryRecordSelector, phase, attempt, grant, pre string) (*hostOrdinaryReadReservation, error) {
	keyRaw, _ := json.Marshal([]string{selector.RootID, selector.BindingSHA256})
	key := string(keyRaw)
	installedHostFactory.Lock()
	defer installedHostFactory.Unlock()
	if installedHostFactory.realm != realm {
		return nil, ErrHostFactoryHold
	}
	if installedHostFactory.ordinaryReads == nil {
		installedHostFactory.ordinaryReads = map[string]*hostOrdinaryReadReservation{}
	}
	old := installedHostFactory.ordinaryReads[key]
	if old == nil {
		if phase != "before_redeem" {
			return nil, ErrHostFactoryHold
		}
	} else {
		if !old.signedReturned || old.attempt != attempt || old.grant != grant || old.pre != pre || (old.phase == "before_redeem" && phase != "after_redeem") || (old.phase == "after_redeem" && phase != "before_start") || old.phase == "before_start" {
			return nil, ErrHostFactoryHold
		}
	}
	next := &hostOrdinaryReadReservation{phase: phase, attempt: attempt, grant: grant, pre: pre}
	installedHostFactory.ordinaryReads[key] = next
	return next, nil
}

func completeOriginalOrdinaryRead(realm *capacityhostfactory.OriginalFactoryRealm, reservation *hostOrdinaryReadReservation) error {
	installedHostFactory.Lock()
	defer installedHostFactory.Unlock()
	if installedHostFactory.realm != realm || reservation == nil || reservation.signedReturned {
		return ErrHostFactoryHold
	}
	reservation.signedReturned = true
	return nil
}

// Installation is once-only before API boot. Current compiled source approval
// is EMPTY in both builds; this operation installs no caller-supplied trust.
func InstallOriginalHostFactoryRealm(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm) error {
	codec := originalHostSourceCodecRealm(ctx, realm)

	approval, err := capacity.ApprovedHostFactorySource()
	if err != nil || realm == nil {
		return ErrHostFactoryHold
	}
	actual, err := realm.Approval(ctx)
	if err != nil {
		return ErrHostFactoryHold
	}
	a, e1 := codec.Canonical(approval)
	b, e2 := codec.Canonical(actual)
	if e1 != nil || e2 != nil || !bytes.Equal(a, b) || realm.VerifyLive(ctx) != nil {
		return ErrHostFactoryHold
	}
	installedHostFactory.Lock()
	defer installedHostFactory.Unlock()
	if installedHostFactory.realm != nil {
		return ErrHostFactoryHold
	}
	installedHostFactory.realm, installedHostFactory.approval = realm, approval
	return nil
}

func OriginalHostFactoryRealm() (*capacityhostfactory.OriginalFactoryRealm, model.HostFactorySourceApproval, bool) {
	installedHostFactory.Lock()
	defer installedHostFactory.Unlock()
	return installedHostFactory.realm, installedHostFactory.approval, installedHostFactory.realm != nil
}

func (s CapacityStore) WithOriginalHostClaim(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, invocation string) (CapacityStore, error) {
	codec := originalHostSourceCodecRealm(ctx, realm)

	actual, approval, installed := OriginalHostFactoryRealm()
	if !installed || realm != actual || invocation != s.ExecutorID || !validCapacityExecutor(invocation) || realm.VerifyLive(ctx) != nil {
		return s, ErrHostFactoryHold
	}
	root, preparation, initial, assessment, err := realm.OriginalClaimTransactionBinding(ctx, invocation)
	if err != nil || root != approval.ScopeRootID {
		return s, ErrHostFactoryHold
	}
	attempt, owner, class, err := realm.OriginalRootIdentity(ctx)
	if err != nil || !validCapacityExecutor(attempt) || !validCapacityExecutor(owner) || class != hostFactoryClass {
		return s, ErrHostFactoryHold
	}
	approvalRaw, err := codec.Canonical(approval)
	if err != nil {
		return s, ErrHostFactoryHold
	}
	rootStages, err := realm.OriginalRootStages(ctx)
	if err != nil {
		return s, ErrHostFactoryHold
	}
	rootRecords, err := prepareOriginalHostRecords(ctx, approval.ScopeRootID, "", rootStages)
	if err != nil {
		return s, ErrHostFactoryHold
	}
	for _, name := range []string{"source-approval", "basal-owner-core", "bootstrap-return-core", "root-preparation", "basal-owner-registrar", "bootstrap-return-registrar", "native-leaf-core-by-registrar", "native-leaf-registrar-by-core", "initial-empty-realm-read", "bootstrap-write-registrar"} {
		if len(rootStages[name]) == 0 {
			return s, ErrHostFactoryHold
		}
	}
	for _, record := range rootRecords {
		if record.selector.Family != "root" || record.selector.Stage == "root-completion" {
			return s, ErrHostFactoryHold
		}
		if record.selector.Stage == "root-preparation" && !bytes.Equal(record.bodyRaw, preparation) || record.selector.Stage == "initial-empty-realm-read" && !bytes.Equal(record.bodyRaw, initial) || record.selector.Stage == "source-approval" && !bytes.Equal(record.bodyRaw, approvalRaw) {
			return s, ErrHostFactoryHold
		}
	}
	s.hostOriginalClaim = &hostOriginalClaim{realm: realm, invocation: invocation, rootID: root, attemptID: attempt, creatorOwnerID: owner, registryClass: class, preparation: preparation, initial: initial, assessment: assessment, approval: approvalRaw}
	s.hostOriginalClaim.rootRecords = rootRecords
	return s, nil
}

// The exact original marshaled intent is associated before the SAME commit.
// Native, filesystem and WAN IO are forbidden under this transaction's locks.
func (s CapacityStore) attachOriginalHostClaimTx(ctx context.Context, tx *sql.Tx, next model.CapacityIntent, raw []byte) error {
	codec := originalHostInstalledSourceCodec(ctx, "")

	h := s.hostOriginalClaim
	if h == nil {
		return nil
	}
	if h.committed || h.intent != nil || next.LeaseExecutorID != h.invocation || h.realm.CheckOriginalClaimTransaction(ctx, h.invocation, next, raw) != nil {
		return ErrHostFactoryHold
	}
	approval, err := h.realm.Approval(ctx)
	if err != nil || approval.ScopeRootID != h.rootID {
		return ErrHostFactoryHold
	}
	var preparation model.HostFactoryRootPreparation
	var initial model.HostFactoryInitialEmptyRealmRead
	if codec.Decode(h.preparation, &preparation) != nil || codec.Decode(h.initial, &initial) != nil || initial.FactoryRootID != preparation.FactoryRootID || initial.RootPreparationSHA256 != capacity.HostFactoryRawSHA256(h.preparation) || initial.SourceApprovalSHA256 != capacity.GuestRetirementSHA(approval) || initial.OriginalReadCloseReturnedAt.After(next.UpdatedAt) {
		return ErrHostFactoryHold
	}
	installedHostFactory.Lock()
	prime := installedHostFactory.prime
	primed := prime.completedFor(h.realm, s.DB, h.rootID) && prime.nativeRoot == preparation.FactoryRootID && prime.attempt == h.attemptID && prime.owner == h.creatorOwnerID
	installedHostFactory.Unlock()
	if !primed {
		return ErrHostFactoryHold
	}
	assessment, err := json.Marshal(next.Assessment)
	if err != nil || !bytes.Equal(assessment, h.assessment) || next.LeaseExpiresAt == nil || next.LeaseExpiresAt.After(preparation.OriginalContextDeadline) {
		return ErrHostFactoryHold
	}
	approvalRaw, err := codec.Canonical(approval)
	if err != nil {
		return err
	}
	rootKey, err := json.Marshal([]string{approval.ScopeRootID, preparation.FactoryRootID, h.attemptID, h.creatorOwnerID, h.registryClass})
	if err != nil {
		return err
	}
	// The early owning primer already committed this exact Root. Claim only
	// compares its originals; absence never authorizes another initializer.
	var existing, existingApproval []byte
	var existingKey, existingRealm, existingAttempt, existingOwner, existingClass string
	err = tx.QueryRowContext(ctx, `SELECT root_preparation_wire,source_approval_wire,root_key_sha256,factory_realm_id::text,factory_attempt_id::text,creator_owner_id::text,factory_registry_class FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 FOR SHARE`, h.rootID).Scan(&existing, &existingApproval, &existingKey, &existingRealm, &existingAttempt, &existingOwner, &existingClass)
	if err == nil && (!bytes.Equal(existing, h.preparation) || !bytes.Equal(existingApproval, approvalRaw) || existingKey != capacity.HostFactoryRawSHA256(rootKey) || existingRealm != preparation.FactoryRootID || existingAttempt != h.attemptID || existingOwner != h.creatorOwnerID || existingClass != h.registryClass) {
		return ErrHostFactoryHold
	}
	if err != nil {
		return err
	}
	if err = s.compareOriginalHostRecordsTx(ctx, tx, h.rootRecords); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_leases(root_id,original_invocation_id,namespace,environment,domain,dimension,generation,fence,original_intent_sha256,original_intent_wire,original_assessment_sha256,original_assessment_wire,initial_empty_sha256,initial_empty_wire) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, h.rootID, h.invocation, next.Namespace, next.Environment, next.Domain, next.Dimension, next.Generation, next.FencingToken, capacity.HostFactoryRawSHA256(raw), raw, capacity.HostFactoryRawSHA256(h.assessment), h.assessment, capacity.HostFactoryRawSHA256(h.initial), h.initial)
	if err == nil {
		h.intent = bytes.Clone(raw)
	}
	return err
}

// Only called after the actual Claim Go return, before executor redaction. A
// failed callback cannot undo the already committed intent/lease association.
func (s CapacityStore) CaptureOriginalHostClaimReturn(ctx context.Context, next model.CapacityIntent, calledAt, returnedAt time.Time, callErr error) error {
	h := s.hostOriginalClaim
	if h == nil {
		return callErr
	}
	// A Go value projection is distinct from the exact SAMEtx intent BYTEA.
	// Copy it before caller redaction or mutation; keep both private.
	projection, projectionErr := json.Marshal(next)
	h.mu.Lock()
	if h.claimReturnReserved {
		h.mu.Unlock()
		return ErrHostFactoryHold
	}
	h.claimReturnReserved = true
	// The first actual Go return is retained even when Commit failed or its
	// result is unknown. Recording it supplies no committed/native permission.
	h.claimCalledAt, h.claimReturnedAt = calledAt, returnedAt
	h.claimReturnedProjection, h.claimReturnErr = bytes.Clone(projection), callErr
	committed, raw := h.committed, bytes.Clone(h.intent)
	h.mu.Unlock()
	if callErr != nil || projectionErr != nil || !committed || len(raw) == 0 || calledAt.IsZero() || returnedAt.Before(calledAt) {
		callErr = errors.Join(callErr, projectionErr, ErrHostFactoryHold)
	} else {
		callErr = h.realm.CaptureOriginalClaimReturn(ctx, h.invocation, next, raw, calledAt, returnedAt)
	}
	h.mu.Lock()
	h.claimReturnErr = callErr
	h.mu.Unlock()
	return callErr
}

// A distinct owning current lease read retains private executor and owner. Its
// real Go return is captured by the caller separately from the earlier Claim.
func (s CapacityStore) ReadOriginalHostCurrentLease(ctx context.Context, policy model.Manifest, generation, fence int64, owner string) (model.CapacityIntent, error) {
	var current model.CapacityIntent
	err := s.mutationTransaction(ctx, policy, false, generation, fence, owner, func(_ *sql.Tx, _ model.CapacityPolicySpec, intent model.CapacityIntent, _ time.Time) error {
		current = intent
		return nil
	})
	return current, err
}

func originalHostStableTarget(namespace string, p model.CapacityPolicySpec, binding string, slot int) ([]byte, string, error) {
	raw, err := json.Marshal([]any{namespace, p.Environment, p.Domain, p.Dimension, p.TargetIdentity, binding, slot, hostFactoryClass})
	return raw, capacity.HostFactoryRawSHA256(raw), err
}

func lockOriginalHostTarget(ctx context.Context, tx *sql.Tx, sha string) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "host-original-target/"+sha)
	return err
}

func guardOriginalHostCapacityTx(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec) error {
	var originals int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_leases WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, namespace, p.Environment, p.Domain, p.Dimension).Scan(&originals); err != nil {
		return err
	}
	if originals != 0 {
		return ErrHostFactoryHold
	}
	return nil
}

// Read/update/confirmation paths cannot use the A1-only Issue exception.
func (s CapacityStore) guardOriginalHostMutationTx(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec, b model.CapacityMutationBinding, slot int) error {
	s.hostOriginalFactory = nil
	s.hostOriginalOrdinary = nil
	return s.guardOriginalHostIssueTx(ctx, tx, namespace, p, b, slot)
}

// Durable exclusions are checked even when the private source context is
// omitted. Epoch/source/profile rotation never changes the canonical target.
func (s CapacityStore) guardOriginalHostIssueTx(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec, b model.CapacityMutationBinding, slot int) error {
	_, target, err := originalHostStableTarget(namespace, p, b.Name, slot)
	if err != nil {
		return err
	}
	if err = lockOriginalHostTarget(ctx, tx, target); err != nil {
		return err
	}
	var entry, root, owner, state, instance, typeID, checksum, typeChecksum, scopeChecksum, profile, handle, planSHA string
	var rootRaw, approvalRaw []byte
	err = tx.QueryRowContext(ctx, `SELECT t.entry_class,t.root_id::text,t.original_owner_id::text,o.state,t.integration_instance_id::text,t.integration_type_id::text,t.integration_checksum,t.integration_type_checksum,t.scope_checksum,t.profile_name,o.prepared_handle_id::text,o.prepared_plan_sha256,r.root_preparation_wire,r.source_approval_wire FROM public.capacity_host_factory_stable_targets t LEFT JOIN public.capacity_host_factory_owners o ON o.owner_id=t.original_owner_id LEFT JOIN public.capacity_host_factory_roots r ON r.scope_root_id=t.root_id WHERE t.stable_target_sha256=$1 FOR UPDATE OF t`, target).Scan(&entry, &root, &owner, &state, &instance, &typeID, &checksum, &typeChecksum, &scopeChecksum, &profile, &handle, &planSHA, &rootRaw, &approvalRaw)
	if err == nil {
		if entry == "ordinary_original_create" {
			h := s.hostOriginalOrdinary
			if h == nil || h.claim != s.hostOriginalClaim || root != h.claim.rootID || owner != h.claim.creatorOwnerID || target != h.binding.StableOriginalTargetSHA256 || state != "registered" || instance != b.IntegrationInstanceID || typeID != b.IntegrationTypeID || checksum != b.IntegrationChecksum || typeChecksum != b.IntegrationTypeChecksum || scopeChecksum != b.ScopeChecksum || profile != b.ProfileName || handle != h.prepared.OriginalCreateCommandHandleID || planSHA != capacity.HostFactoryRawSHA256(h.preparedRaw) || !bytes.Equal(rootRaw, h.claim.preparation) || !bytes.Equal(approvalRaw, h.claim.approval) {
				return ErrHostFactoryHold
			}
			h.mu.Lock()
			blocked := !h.issueReserved || h.issueCommitted || len(h.grantRaw) != 0
			h.mu.Unlock()
			if blocked {
				return ErrHostFactoryHold
			}
			if err := s.checkOriginalOrdinaryRegisteredTx(ctx, tx, h); err != nil {
				return err
			}
			var pending int
			if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_factory_original_grant_bindings WHERE stable_target_sha256=$1`, target).Scan(&pending); err != nil {
				return err
			}
			if pending != 0 {
				return ErrHostFactoryHold
			}
			return nil
		}
		// Only the original registered A1 may make its sole Issue. No other
		// factory target, missing context or previous attachment is reusable.
		h := s.hostOriginalFactory
		if h == nil || !h.issueReserved || entry != "sealed_a1" || h.scope.FactoryEntryClass != entry || state != "registered" || root != h.scope.ScopeRootID || owner != h.scope.CreatorOwnerID || target != h.scope.StableOriginalTargetSHA256 || h.issueCommitted || len(h.grantRaw) != 0 {
			return ErrHostFactoryHold
		}
		if instance != b.IntegrationInstanceID || typeID != b.IntegrationTypeID || checksum != b.IntegrationChecksum || typeChecksum != b.IntegrationTypeChecksum || scopeChecksum != b.ScopeChecksum || profile != b.ProfileName || handle != h.prepared.OriginalCreateCommandHandleID || planSHA != capacity.GuestRetirementSHA(h.prepared) || s.hostOriginalClaim == nil || !s.hostOriginalClaim.committed || !bytes.Equal(rootRaw, s.hostOriginalClaim.preparation) || !bytes.Equal(approvalRaw, s.hostOriginalClaim.approval) {
			return ErrHostFactoryHold
		}
		var pending int
		if err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_factory_original_grant_bindings WHERE stable_target_sha256=$1)+(SELECT count(*) FROM public.capacity_host_factory_sealed_reservations WHERE scope_sha256=$2)`, target, capacity.HostFactoryRawSHA256(h.scopeRaw)).Scan(&pending); err != nil {
			return err
		}
		if pending != 0 {
			return ErrHostFactoryHold
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, approval, installed := OriginalHostFactoryRealm()
	if s.hostOriginalClaim != nil || installed && approval.AllowedNamespace == namespace && approval.AllowedMutationBindingName == b.Name && approval.AllowedSlot == slot {
		return ErrHostFactoryHold
	}
	return nil
}

// Reserve the sole Source call before SQL begins. Failure/unknown Commit can
// never make an original invocation eligible for another Issue.
func (s CapacityStore) reserveOriginalFactoryIssue(ctx context.Context) error {
	if h := s.hostOriginalFactory; h != nil {
		if err := s.guardOriginalHostPostStartCurrent(ctx); err != nil {
			return err
		}
		if !originalHostPreparationCompleted(s.hostOriginalClaim, h.realm, s.DB, h.scope.FactoryEntryClass, h.scopeRaw, h.prepared.OriginalCreateCommandHandleID) {
			return ErrHostFactoryHold
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		deadline, bounded := originalHostIssueContextBound(ctx, h.scope.OriginalContextDeadline)
		if h.issueReserved || h.issueCommitted || len(h.grantRaw) != 0 || !bounded {
			return ErrHostFactoryHold
		}
		h.issueReserved, h.issueContext, h.issueDeadline = true, ctx, deadline
	}
	if h := s.hostOriginalOrdinary; h != nil {
		if !originalHostPreparationCompleted(h.claim, h.realm, s.DB, "ordinary_original_create", h.bindingRaw, h.prepared.OriginalCreateCommandHandleID) {
			return ErrHostFactoryHold
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		deadline, bounded := originalHostIssueContextBound(ctx, h.binding.OriginalContextDeadline)
		if h.issueReserved || h.issueCommitted || len(h.grantRaw) != 0 || !bounded {
			return ErrHostFactoryHold
		}
		h.issueReserved, h.issueContext, h.issueDeadline = true, ctx, deadline
	}
	return nil
}

func originalHostIssueContextBound(ctx context.Context, original time.Time) (time.Time, bool) {
	if ctx == nil || ctx.Err() != nil || original.IsZero() {
		return time.Time{}, false
	}
	deadline, bounded := ctx.Deadline()
	return deadline, bounded && !deadline.After(original) && time.Now().Before(deadline)
}

func originalHostIssueReturnedWithin(ctx, original context.Context, deadline, calledAt, returnedAt time.Time) bool {
	if ctx == nil || original == nil || ctx != original || original.Err() != nil || deadline.IsZero() || calledAt.IsZero() || returnedAt.Before(calledAt) || !returnedAt.Before(deadline) {
		return false
	}
	actual, bounded := original.Deadline()
	return bounded && actual.Equal(deadline)
}

// Called before grant FOR UPDATE, replay, expiry or write_once. SQL absence is
// never a substitute for an installed source root's missing target catalog.
type hostOriginalCallbackRequest struct {
	principal, nonce string
	redeem           *model.CapacityMutationRedeemRequest
	settle           *model.CapacityMutationSettleRequest
}

func (s CapacityStore) guardOriginalHostCallbackTx(ctx context.Context, tx *sql.Tx, record capacityMutationRecord, namespace string, p model.CapacityPolicySpec, originalRequest ...hostOriginalCallbackRequest) error {
	if err := lockNativeMutationSlot(ctx, tx, record.Binding, record.Grant.Slot); err != nil {
		return err
	}
	var policyRaw []byte
	if err := tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy'`, record.PolicyID).Scan(&policyRaw); err != nil {
		return err
	}
	var policy model.CapacityPolicySpec
	if json.Unmarshal(policyRaw, &policy) != nil {
		return ErrHostFactoryHold
	}
	if policy.Environment != p.Environment || policy.Domain != p.Domain || policy.Dimension != p.Dimension {
		return ErrHostFactoryHold
	}
	if handled, err := s.guardOriginalOrdinaryCallbackTx(ctx, tx, record, namespace, policy, originalRequest); handled {
		return err
	}
	if err := s.guardOriginalHostIssueTx(ctx, tx, namespace, policy, record.Binding, record.Grant.Slot); err != nil {
		return err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_factory_original_grant_bindings WHERE grant_id=$1`, record.Grant.GrantID).Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return ErrHostFactoryHold
	}
	return nil
}

// An ordinary callback is selected by the permanent SQL target and actual
// installed Source-private registration. DTO/principal/context labels never
// construct this exception; all absent/unknown source joins keep HOLD.
func (s CapacityStore) guardOriginalOrdinaryCallbackTx(ctx context.Context, tx *sql.Tx, record capacityMutationRecord, namespace string, p model.CapacityPolicySpec, requests []hostOriginalCallbackRequest) (bool, error) {
	codec := originalHostInstalledSourceCodec(ctx, "")

	_, target, err := originalHostStableTarget(namespace, p, record.Binding.Name, record.Grant.Slot)
	if err != nil {
		return true, err
	}
	if err = lockOriginalHostTarget(ctx, tx, target); err != nil {
		return true, err
	}
	var entry, root, owner string
	err = tx.QueryRowContext(ctx, `SELECT entry_class,root_id::text,original_owner_id::text FROM public.capacity_host_factory_stable_targets WHERE stable_target_sha256=$1 FOR UPDATE`, target).Scan(&entry, &root, &owner)
	if errors.Is(err, sql.ErrNoRows) {
		var count int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_factory_original_grant_bindings WHERE grant_id=$1`, record.Grant.GrantID).Scan(&count); err != nil {
			return true, err
		}
		if count != 0 {
			return true, ErrHostFactoryHold
		}
		return false, nil
	}
	if err != nil {
		return true, err
	}
	if entry != "ordinary_original_create" || len(requests) != 1 {
		return true, ErrHostFactoryHold
	}
	request := requests[0]
	if (request.redeem == nil) == (request.settle == nil) {
		return true, ErrHostFactoryHold
	}
	installedHostFactory.Lock()
	h := installedHostFactory.ordinaryFactories[target]
	realm := installedHostFactory.realm
	installedHostFactory.Unlock()
	if h == nil || realm == nil || realm != h.realm || h.claim == nil || h.claim.rootID != root || h.claim.creatorOwnerID != owner || !reflect.DeepEqual(h.policySpec, p) || !reflect.DeepEqual(h.mutationBinding, record.Binding) {
		return true, ErrHostFactoryHold
	}
	s.hostOriginalClaim, s.hostOriginalOrdinary = h.claim, h
	if err = s.checkOriginalOrdinaryRegisteredTx(ctx, tx, h); err != nil {
		return true, err
	}
	h.mu.Lock()
	ready := h.issueCommitted && h.issueCaptured && !h.issueReturnedAt.IsZero() && h.issueReturnErr == nil && h.grant.GrantID == record.Grant.GrantID
	grant, pre, grantRaw, preRaw := h.grant, h.pre, bytes.Clone(h.grantRaw), bytes.Clone(h.preRaw)
	h.mu.Unlock()
	if !ready || record.ExecutorID != h.claim.invocation || record.LeaseOwner != h.leaseOwner || record.PolicyID != h.policy.ID || record.PolicyChecksum != h.policy.Checksum || record.WorkflowID != h.workflow.ID || !record.Grant.ExpiresAt.Equal(grant.ExpiresAt) {
		return true, ErrHostFactoryHold
	}
	var actualGrant, actualPre []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_grant_wire,original_preregistration_wire FROM public.capacity_factory_original_grant_bindings WHERE grant_id=$1 AND preregistration_id=$2 AND root_id=$3 AND owner_id=$4 AND prepared_handle_id=$5 AND stable_target_sha256=$6 AND entry_class='ordinary_original_create' FOR SHARE`, grant.GrantID, pre.PreregistrationID, root, owner, h.prepared.OriginalCreateCommandHandleID, target).Scan(&actualGrant, &actualPre); err != nil {
		return true, err
	}
	if !bytes.Equal(actualGrant, grantRaw) || !bytes.Equal(actualPre, preRaw) {
		return true, ErrHostFactoryHold
	}
	phase, attempt := "before_redeem", ""
	if request.redeem != nil {
		attempt = request.redeem.AttemptID
		if record.Grant.State != "issued" || record.AttemptID != "" || request.redeem.GrantID != grant.GrantID || realm.VerifyOriginalOrdinaryRedeem(ctx, request.principal, *request.redeem, grantRaw, preRaw) != nil {
			return true, ErrHostFactoryHold
		}
	} else {
		phase, attempt = "before_start", request.settle.AttemptID
		if record.Grant.State != "redeemed" || record.AttemptID != attempt || request.settle.GrantID != grant.GrantID || realm.VerifyOriginalOrdinarySettle(ctx, request.principal, *request.settle, request.nonce, grantRaw, preRaw) != nil {
			return true, ErrHostFactoryHold
		}
	}
	if !validCapacityExecutor(attempt) || attempt == h.claim.attemptID {
		return true, ErrHostFactoryHold
	}
	guardEnvelope, err := realm.OriginalOrdinaryGuardEnvelope(ctx, phase, attempt, grant.GrantID, pre.PreregistrationID)
	var guard model.FactoryOrdinaryGuardRead
	if err != nil || len(guardEnvelope) == 0 || realm.VerifyOriginalStage(ctx, "ordinary-guard-read", guardEnvelope) != nil {
		return true, ErrHostFactoryHold
	}
	if _, err = originalOrdinaryStageBody(codec, guardEnvelope, &guard); err != nil {
		return true, err
	}
	var currentRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR UPDATE`, namespace, p.Environment, p.Domain, p.Dimension).Scan(&currentRaw); err != nil {
		return true, err
	}
	var intent, original model.CapacityIntent
	if json.Unmarshal(currentRaw, &intent) != nil || json.Unmarshal(h.claim.intent, &original) != nil || intent.LeaseExpiresAt == nil || original.LeaseExpiresAt == nil || intent.Generation != record.Generation || intent.FencingToken != record.FencingToken || intent.LeaseExecutorID != record.ExecutorID || intent.LeaseOwner != record.LeaseOwner || !intent.LeaseExpiresAt.Equal(*original.LeaseExpiresAt) || intent.RecoveryOnly || intent.PolicyID != record.PolicyID || intent.PolicyChecksum != record.PolicyChecksum {
		return true, ErrHostFactoryHold
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return true, err
	}
	now = now.UTC()
	if guard.OrdinarySourceBindingSHA256 != capacity.HostFactoryRawSHA256(h.bindingRaw) || guard.PreparedCreatePlanSHA256 != capacity.HostFactoryRawSHA256(h.preparedRaw) || guard.GrantID != grant.GrantID || guard.PreregistrationID != pre.PreregistrationID || guard.OriginalGrantRawSHA256 != capacity.HostFactoryRawSHA256(grantRaw) || guard.OriginalPreregistrationRawSHA256 != capacity.HostFactoryRawSHA256(preRaw) || guard.OriginalAttemptID != attempt || guard.OriginalRedeemRequestSHA256 != grant.RequestSHA256 || guard.GrantState != record.Grant.State || guard.Generation != intent.Generation || guard.Fence != intent.FencingToken || guard.LeaseOwnerSHA256 != capacity.HostFactoryRawSHA256([]byte(intent.LeaseOwner)) || guard.ExecutorID != intent.LeaseExecutorID || !guard.OriginalLeaseExpiresAt.Equal(*intent.LeaseExpiresAt) || !guard.OriginalGrantExpiresAt.Equal(grant.ExpiresAt) || !guard.OriginalContextDeadline.Equal(h.binding.OriginalContextDeadline) || guard.PolicyChecksum != h.policy.Checksum || guard.WorkflowChecksum != h.workflow.Checksum || guard.CoreActualSourceCommit != capacity.CurrentGuestCoreSource() || guard.ObservedAt.After(now) || now.Sub(guard.ObservedAt) > 30*time.Second || !now.Before(grant.ExpiresAt) || !now.Before(pre.OriginalDeadline) || !now.Before(*intent.LeaseExpiresAt) || !now.Before(h.binding.OriginalContextDeadline) || ctx.Err() != nil {
		return true, ErrHostFactoryHold
	}
	if err = checkMutationIntegration(ctx, tx, record.Binding); err != nil {
		return true, err
	}
	return true, nil
}

// Original bodies and envelopes remain separate. This key excludes body SHA
// for failure parts so a second different body cannot replace the same part.
type hostFactoryIOIdentity struct {
	codec                                                                            hostOriginalSourceCodec
	root, bindingSchema, bindingSHA, owner, role, primitive, kind, identity, bodySHA string
	handle, operation, collection                                                    *string
	first, last                                                                      *uint64
	part                                                                             *uint32
	previous                                                                         *string
}

func originalHostIOIdentity(codec hostOriginalSourceCodec, root string, body any, raw []byte) (hostFactoryIOIdentity, error) {
	x := hostFactoryIOIdentity{codec: codec, root: root, bodySHA: capacity.HostFactoryRawSHA256(raw)}
	var key []any
	switch v := body.(type) {
	case *model.HostFactoryCallVectorChunk:
		x.bindingSchema, x.bindingSHA, x.owner, x.role, x.primitive, x.kind = v.BindingSchema, v.BindingSHA256, v.OriginalOwnerID, v.OwnerRole, v.OwnerPrimitiveRawSHA256, "chunk"
		x.handle, x.operation, x.first, x.last = &v.OriginalHandleID, &v.Operation, &v.FirstOrdinal, &v.LastOrdinal
		key = []any{x.kind, v.OriginalHandleID, v.Operation, v.FirstOrdinal, v.LastOrdinal, x.bodySHA}
	case *model.HostFactoryCallVectorManifest:
		x.bindingSchema, x.bindingSHA, x.owner, x.role, x.primitive, x.kind = v.BindingSchema, v.BindingSHA256, v.OriginalOwnerID, v.OwnerRole, v.OwnerPrimitiveRawSHA256, "manifest"
		x.handle, x.operation, x.first, x.last = &v.OriginalHandleID, &v.Operation, &v.FirstOrdinal, &v.LastOrdinal
		key = []any{x.kind, v.OriginalHandleID, v.Operation, v.FirstOrdinal, v.LastOrdinal, x.bodySHA}
	case *model.HostFactoryHandleCallInventory:
		x.bindingSchema, x.bindingSHA, x.owner, x.role, x.kind = v.BindingSchema, v.BindingSHA256, v.OriginalOwnerID, v.OwnerRole, "handle-inventory"
		if v.OwnerPrimitiveRawSHA256 != nil {
			x.primitive = *v.OwnerPrimitiveRawSHA256
		}
		x.handle = &v.OriginalHandleID
		if v.OriginalCallCount != 0 {
			x.first, x.last = &v.FirstOrdinal, &v.LastOrdinal
		}
		key = []any{x.root, x.bindingSchema, x.bindingSHA, x.owner, v.OriginalHandleID, v.FirstOrdinal, v.LastOrdinal, x.bodySHA}
	case *model.HostFactoryFailureDiagnostic:
		x.bindingSchema, x.bindingSHA, x.kind = v.BindingSchema, v.BindingSHA256, "failure-part"
		x.collection, x.part, x.previous = &v.FailureCollectionID, &v.PartOrdinal, v.PreviousPartRawSHA256
		key = []any{x.kind, v.FailureCollectionID, v.PartOrdinal}
	default:
		return x, ErrHostFactoryHold
	}
	keyRaw, err := json.Marshal(key)
	x.identity = capacity.HostFactoryRawSHA256(keyRaw)
	return x, err
}

// Private SQL append follows separately verified source/key/native ownership.
// It is intentionally not an exported authority constructor.
func appendOriginalHostIOBodyTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, bodyRaw, envelopeRaw []byte) error {
	if len(bodyRaw) < 1 || len(bodyRaw) > 65536 || capacity.HostFactoryRawSHA256(bodyRaw) != x.bodySHA || len(envelopeRaw) < 1 || len(envelopeRaw) > 65536 {
		return ErrHostFactoryHold
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,record_identity_sha256,original_handle_id,operation,first_ordinal,last_ordinal,failure_collection_id,part_ordinal,previous_part_raw_sha256,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, x.root, x.bindingSchema, x.bindingSHA, x.owner, x.kind, x.identity, x.handle, x.operation, x.first, x.last, x.collection, x.part, x.previous, x.bodySHA, bodyRaw, capacity.HostFactoryRawSHA256(envelopeRaw), envelopeRaw)
	return err
}

// Every FIRST is an actual immutable relation, not absence converted to FIRST.
func originalHostPredecessorTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, current string, index uint32) ([]byte, uint32, error) {
	codec := x.codec

	var previous sql.NullString
	var previousIndex sql.NullInt64
	var kind, callID string
	err := tx.QueryRowContext(ctx, `SELECT version_kind,original_call_id,predecessor_chunk_raw_body_sha256,predecessor_fact_index FROM public.capacity_host_factory_call_snapshot_links WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND original_handle_id=$5 AND current_chunk_raw_body_sha256=$6 AND current_fact_index=$7`, x.root, x.bindingSchema, x.bindingSHA, x.owner, x.handle, current, index).Scan(&kind, &callID, &previous, &previousIndex)
	if err != nil {
		return nil, 0, ErrHostFactoryHold
	}
	var currentRaw []byte
	var consistent bool
	if err = tx.QueryRowContext(ctx, `SELECT r.raw_body_wire,l.original_called_at=(convert_from(r.raw_body_wire,'UTF8')::jsonb->'original_calls'->l.current_fact_index->>'original_called_at')::timestamptz AND l.original_operation_deadline=(convert_from(r.raw_body_wire,'UTF8')::jsonb->'original_calls'->l.current_fact_index->>'original_operation_deadline')::timestamptz FROM public.capacity_host_factory_io_returns r JOIN public.capacity_host_factory_call_snapshot_links l ON l.root_id=r.root_id AND l.binding_schema=r.binding_schema AND l.binding_sha256=r.binding_sha256 AND l.original_owner_id=r.original_owner_id AND l.current_chunk_raw_body_sha256=r.raw_body_sha256 WHERE r.root_id=$1 AND r.binding_schema=$2 AND r.binding_sha256=$3 AND r.original_owner_id=$4 AND r.record_kind='chunk' AND r.raw_body_sha256=$5 AND l.current_fact_index=$6`, x.root, x.bindingSchema, x.bindingSHA, x.owner, current, index).Scan(&currentRaw, &consistent); err != nil || !consistent {
		return nil, 0, ErrHostFactoryHold
	}
	var chunk model.HostFactoryCallVectorChunk
	if capacity.HostFactoryRawSHA256(currentRaw) != current || codec.Decode(currentRaw, &chunk) != nil || int(index) >= len(chunk.OriginalCalls) || chunk.OriginalHandleID != *x.handle || chunk.OriginalOwnerID != x.owner || chunk.OriginalCalls[index].OriginalCallID == nil || *chunk.OriginalCalls[index].OriginalCallID != callID {
		return nil, 0, ErrHostFactoryHold
	}
	if kind == "first" && !previous.Valid && !previousIndex.Valid {
		return nil, 0, nil
	}
	if kind != "pending_to_returned" || !previous.Valid || !previousIndex.Valid || previousIndex.Int64 != 0 || index != 0 {
		return nil, 0, ErrHostFactoryHold
	}
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT raw_body_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND record_kind='chunk' AND raw_body_sha256=$5`, x.root, x.bindingSchema, x.bindingSHA, x.owner, previous.String).Scan(&raw)
	if err != nil || capacity.HostFactoryRawSHA256(raw) != previous.String {
		return nil, 0, ErrHostFactoryHold
	}
	return raw, 0, nil
}

func resolveOriginalHostBodyTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, sha string) ([]byte, error) {
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT raw_body_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND record_kind IN ('chunk','manifest') AND original_handle_id=$5 AND raw_body_sha256=$6`, x.root, x.bindingSchema, x.bindingSHA, x.owner, x.handle, sha).Scan(&raw)
	if err != nil || capacity.HostFactoryRawSHA256(raw) != sha {
		return nil, ErrHostFactoryHold
	}
	return raw, nil
}

// A per-operation manifest can be sparse after interleaving on the SAME
// handle. Storage checks exact immutable children and known SQL FIRST links;
// only the full handle inventory can close the no-gap union for positive use.
func validateOriginalHostManifestTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, m model.HostFactoryCallVectorManifest) error {
	_, err := originalHostManifestFactsTx(ctx, tx, x, m)
	return err
}

func validateOriginalHostHistoricalManifestTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, m model.HostFactoryCallVectorManifest) error {
	return validateOriginalHostManifestTx(ctx, tx, x, m)
}

func originalHostManifestFactsTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, root model.HostFactoryCallVectorManifest) ([]model.HostFactoryPrimitiveIOReturn, error) {
	codec := x.codec

	seen, calls := map[string]bool{}, map[string]bool{}
	visits := 0
	facts := []model.HostFactoryPrimitiveIOReturn{}
	var walk func(model.HostFactoryCallVectorManifest, int) error
	walk = func(m model.HostFactoryCallVectorManifest, depth int) error {
		if depth > 4 || codec.Validate(m) != nil || x.handle == nil || x.operation == nil || m.BindingSchema != x.bindingSchema || m.BindingSHA256 != x.bindingSHA || m.OwnerRole != x.role || m.OriginalOwnerID != x.owner || m.OriginalHandleID != *x.handle || m.Operation != *x.operation || m.OwnerPrimitiveRawSHA256 != x.primitive {
			return ErrHostFactoryHold
		}
		var first, last, count uint64
		var priorReturn time.Time
		for _, sha := range m.ChildBodySHAs {
			visits++
			if visits > 69905 || seen[sha] {
				return ErrHostFactoryHold
			}
			seen[sha] = true
			raw, err := resolveOriginalHostBodyTx(ctx, tx, x, sha)
			if err != nil {
				return err
			}
			var f, l, n uint64
			var called, returned time.Time
			if m.Level == 0 {
				var c model.HostFactoryCallVectorChunk
				if codec.Decode(raw, &c) != nil || c.BindingSchema != x.bindingSchema || c.BindingSHA256 != x.bindingSHA || c.OwnerRole != x.role || c.OriginalOwnerID != x.owner || c.OriginalHandleID != *x.handle || c.Operation != *x.operation || c.OwnerPrimitiveRawSHA256 != x.primitive {
					return ErrHostFactoryHold
				}
				for i, fact := range c.OriginalCalls {
					if fact.OriginalCallID == nil || fact.OriginalCalledAt == nil || calls[*fact.OriginalCallID] || len(facts) >= 65536 {
						return ErrHostFactoryHold
					}
					calls[*fact.OriginalCallID] = true
					prior, index, e := originalHostPredecessorTx(ctx, tx, x, sha, uint32(i))
					if e != nil {
						return e
					}
					if prior != nil {
						var pending model.HostFactoryCallVectorChunk
						if index != 0 || codec.Decode(prior, &pending) != nil || originalHostSourcePendingTx(ctx, tx, x, pending, c, nil) != nil {
							return ErrHostFactoryHold
						}
					}
					if root.CollectionState == "complete_original_calls" && fact.OriginalState != "returned" {
						return ErrHostFactoryHold
					}
					facts = append(facts, fact)
				}
				f, l, n = c.FirstOrdinal, c.LastOrdinal, uint64(len(c.OriginalCalls))
				called = *c.OriginalCalls[0].OriginalCalledAt
				if at := c.OriginalCalls[len(c.OriginalCalls)-1].OriginalReturnedAt; at != nil {
					returned = *at
				}
			} else {
				var child model.HostFactoryCallVectorManifest
				if codec.Decode(raw, &child) != nil || child.Level+1 != m.Level {
					return ErrHostFactoryHold
				}
				start := len(facts)
				if err := walk(child, depth+1); err != nil {
					return err
				}
				f, l, n = child.FirstOrdinal, child.LastOrdinal, child.OriginalCallCount
				called = *facts[start].OriginalCalledAt
				if at := facts[len(facts)-1].OriginalReturnedAt; at != nil {
					returned = *at
				}
			}
			if count > 0 && (f <= last || priorReturn.IsZero() || called.Before(priorReturn)) {
				return ErrHostFactoryHold
			}
			if count == 0 {
				first = f
			}
			last, priorReturn = l, returned
			count += n
			if count > 65536 {
				return ErrHostFactoryHold
			}
		}
		if first != m.FirstOrdinal || last != m.LastOrdinal || count != m.OriginalCallCount {
			return ErrHostFactoryHold
		}
		return nil
	}
	if err := walk(root, 0); err != nil {
		return nil, err
	}
	return facts, nil
}

func validateOriginalHostInventoryTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, inventory model.HostFactoryHandleCallInventory) error {
	codec := x.codec

	if codec.Validate(inventory) != nil || inventory.BindingSchema != x.bindingSchema || inventory.BindingSHA256 != x.bindingSHA || inventory.OriginalOwnerID != x.owner || inventory.OwnerRole != x.role || x.handle == nil || inventory.OriginalHandleID != *x.handle {
		return ErrHostFactoryHold
	}
	resolve := func(sha string) ([]byte, error) { return resolveOriginalHostBodyTx(ctx, tx, x, sha) }
	prior := func(sha string, index uint32) ([]byte, uint32, error) {
		return originalHostPredecessorTx(ctx, tx, x, sha, index)
	}
	if inventory.CollectionState == "complete_original_calls" {
		if x.bindingSchema == "original_host_factory_pre_authority_scope_v4" {
			return validateOriginalHostSourceInventoryTx(ctx, tx, x, inventory)
		}
		return capacity.ValidateHostFactoryHandleInventory(inventory, resolve, prior)
	}
	// An incomplete inventory is retained, never admitted as native coverage.
	ids := map[string]bool{}
	var count uint64
	for _, ref := range inventory.OperationVectors {
		if ref.ManifestRootSHA256 == nil || ref.OriginalCallCount == 0 {
			return ErrHostFactoryHold
		}
		v := x
		v.operation = &ref.Operation
		raw, err := resolveOriginalHostBodyTx(ctx, tx, v, *ref.ManifestRootSHA256)
		var manifest model.HostFactoryCallVectorManifest
		if err != nil || codec.Decode(raw, &manifest) != nil || ref.OriginalOwnerID != x.owner || ref.OriginalHandleID != inventory.OriginalHandleID || ref.OwnerPrimitiveRawSHA256 == nil || manifest.OwnerPrimitiveRawSHA256 != *ref.OwnerPrimitiveRawSHA256 || manifest.FirstOrdinal != ref.FirstOrdinal || manifest.LastOrdinal != ref.LastOrdinal || manifest.OriginalCallCount != ref.OriginalCallCount || manifest.CollectionState != ref.CollectionState {
			return ErrHostFactoryHold
		}
		v.primitive = manifest.OwnerPrimitiveRawSHA256
		facts, err := originalHostManifestFactsTx(ctx, tx, v, manifest)
		if err != nil {
			return err
		}
		for _, fact := range facts {
			if fact.SubjectOwnerID != ref.SubjectOwnerID || fact.OriginalCallID == nil || ids[*fact.OriginalCallID] || fact.OriginalOperationDeadline.After(inventory.OriginalOperationDeadline) {
				return ErrHostFactoryHold
			}
			ids[*fact.OriginalCallID] = true
			count++
		}
	}
	if count != inventory.OriginalCallCount {
		return ErrHostFactoryHold
	}
	return nil
}

func appendOriginalHostFailureTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, failure model.HostFactoryFailureDiagnostic, bodyRaw, envelopeRaw []byte) error {
	codec := x.codec

	key, _ := json.Marshal([]string{"host-original-failure", x.root, x.bindingSchema, x.bindingSHA, x.owner, failure.FailureCollectionID})
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(key)); err != nil {
		return err
	}
	if failure.PartOrdinal > 1 {
		var previousRaw []byte
		if err := tx.QueryRowContext(ctx, `SELECT raw_body_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND record_kind='failure-part' AND failure_collection_id=$5 AND part_ordinal=$6`, x.root, x.bindingSchema, x.bindingSHA, x.owner, failure.FailureCollectionID, failure.PartOrdinal-1).Scan(&previousRaw); err != nil {
			return ErrHostFactoryHold
		}
		var previous model.HostFactoryFailureDiagnostic
		if failure.PreviousPartRawSHA256 == nil || capacity.HostFactoryRawSHA256(previousRaw) != *failure.PreviousPartRawSHA256 || codec.Decode(previousRaw, &previous) != nil || previous.FinalPart || previous.FailureCollectionID != failure.FailureCollectionID || previous.PartOrdinal+1 != failure.PartOrdinal || previous.BindingSchema != failure.BindingSchema || previous.BindingSHA256 != failure.BindingSHA256 || previous.OriginalStage != failure.OriginalStage || !previous.OriginalContextStartedAt.Equal(failure.OriginalContextStartedAt) || !previous.OriginalContextDeadline.Equal(failure.OriginalContextDeadline) {
			return ErrHostFactoryHold
		}
	}
	// Each reference retains its own handle and operation. A truthful
	// zero-vector failure creates no synthetic CallID or handle.
	for _, ref := range failure.Operations {
		if ref.OriginalOwnerID != x.owner || codec.Validate(ref) != nil {
			return ErrHostFactoryHold
		}
		if ref.OriginalCallCount == 0 {
			continue
		}
		if ref.ManifestRootSHA256 == nil {
			return ErrHostFactoryHold
		}
		v := x
		v.kind = "manifest"
		v.handle = &ref.OriginalHandleID
		v.operation = &ref.Operation
		if ref.OwnerPrimitiveRawSHA256 == nil {
			return ErrHostFactoryHold
		}
		v.primitive = *ref.OwnerPrimitiveRawSHA256
		basalOwner, err := originalHostPrimitiveOwnerTx(ctx, tx, x.root, v.primitive)
		if err != nil || basalOwner != ref.OriginalOwnerID {
			return ErrHostFactoryHold
		}
		raw, err := resolveOriginalHostBodyTx(ctx, tx, v, *ref.ManifestRootSHA256)
		var manifest model.HostFactoryCallVectorManifest
		if err != nil || codec.Decode(raw, &manifest) != nil || manifest.OriginalHandleID != ref.OriginalHandleID || manifest.OriginalOwnerID != ref.OriginalOwnerID || manifest.Operation != ref.Operation || manifest.BindingSchema != x.bindingSchema || manifest.BindingSHA256 != x.bindingSHA || manifest.CollectionState != ref.CollectionState || manifest.FirstOrdinal != ref.FirstOrdinal || manifest.LastOrdinal != ref.LastOrdinal || manifest.OriginalCallCount != ref.OriginalCallCount {
			return ErrHostFactoryHold
		}
		if ref.CollectionState == "complete_original_calls" {
			// Diagnostic retention permits a sparse per-operation sequence from
			// actual interleaving. Exact immutable children/FIRST remain required;
			// this supplies no contiguous whole-handle/native-positive proof.
			facts, err := originalHostManifestFactsTx(ctx, tx, v, manifest)
			if err != nil {
				return ErrHostFactoryHold
			}
			for _, fact := range facts {
				if fact.SubjectOwnerID != ref.SubjectOwnerID || ref.OwnerPrimitiveRawSHA256 == nil || fact.OwnerPrimitiveRawSHA256 == nil || *fact.OwnerPrimitiveRawSHA256 != *ref.OwnerPrimitiveRawSHA256 {
					return ErrHostFactoryHold
				}
			}
		}
	}
	// Source's exact cached envelope authenticates whole retained ledger
	// coverage. A FinalPart flag or a SQL relationship alone cannot do so.
	return appendOriginalHostIOBodyTx(ctx, tx, x, bodyRaw, envelopeRaw)
}

// A terminal prefix is published once. A pending publication and its returned
// successor are each singletons; every relation is atomic with its raw chunk.
func appendOriginalHostChunkTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, chunk model.HostFactoryCallVectorChunk, bodyRaw, envelopeRaw []byte) error {
	codec := x.codec

	canonical, err := codec.Canonical(chunk)
	if err != nil || !bytes.Equal(canonical, bodyRaw) || len(chunk.OriginalCalls) == 0 {
		return ErrHostFactoryHold
	}
	lockRaw, _ := json.Marshal([]string{"host-original-io", x.root, x.bindingSchema, x.bindingSHA, x.owner, chunk.OriginalHandleID})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(lockRaw)); err != nil {
		return err
	}
	var lastPublished uint64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(max((split_part(original_call_id,':',2))::bigint),0) FROM public.capacity_host_factory_call_snapshot_links WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND original_handle_id=$5 AND version_kind='first'`, x.root, x.bindingSchema, x.bindingSHA, x.owner, chunk.OriginalHandleID).Scan(&lastPublished); err != nil {
		return err
	}
	type link struct {
		kind          string
		previous      *string
		previousIndex *uint32
		previousKind  *string
	}
	links := make([]link, len(chunk.OriginalCalls))
	for index, fact := range chunk.OriginalCalls {
		if fact.OriginalCallID == nil || fact.OriginalCallOrdinal == nil || fact.OriginalCalledAt == nil {
			return ErrHostFactoryHold
		}
		var firstSHA string
		var firstIndex uint32
		err = tx.QueryRowContext(ctx, `SELECT current_chunk_raw_body_sha256,current_fact_index FROM public.capacity_host_factory_call_snapshot_links WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND original_handle_id=$5 AND original_call_id=$6 AND version_kind='first' FOR SHARE`, x.root, x.bindingSchema, x.bindingSHA, x.owner, chunk.OriginalHandleID, *fact.OriginalCallID).Scan(&firstSHA, &firstIndex)
		if errors.Is(err, sql.ErrNoRows) {
			if *fact.OriginalCallOrdinal != lastPublished+1 || *fact.OriginalCallID != chunk.OriginalHandleID+":"+strconv.FormatUint(*fact.OriginalCallOrdinal, 10) {
				return ErrHostFactoryHold
			}
			lastPublished++
			links[index].kind = "first"
			if fact.OriginalState == "called_pending" && len(chunk.OriginalCalls) != 1 {
				return ErrHostFactoryHold
			}
			if fact.OriginalState != "returned" && fact.OriginalState != "called_pending" {
				return ErrHostFactoryHold
			}
			// Earlier unfinished calls cannot be bypassed by later publication.
			var pending int
			err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_call_snapshot_links f JOIN public.capacity_host_factory_io_returns r ON r.root_id=f.root_id AND r.binding_schema=f.binding_schema AND r.binding_sha256=f.binding_sha256 AND r.original_owner_id=f.original_owner_id AND r.record_kind='chunk' AND r.raw_body_sha256=f.current_chunk_raw_body_sha256 WHERE f.root_id=$1 AND f.binding_schema=$2 AND f.binding_sha256=$3 AND f.original_owner_id=$4 AND f.original_handle_id=$5 AND f.version_kind='first' AND convert_from(r.raw_body_wire,'UTF8')::jsonb->'original_calls'->f.current_fact_index->>'original_state'='called_pending' AND NOT EXISTS (SELECT 1 FROM public.capacity_host_factory_call_snapshot_links s WHERE s.root_id=f.root_id AND s.binding_schema=f.binding_schema AND s.binding_sha256=f.binding_sha256 AND s.original_owner_id=f.original_owner_id AND s.original_handle_id=f.original_handle_id AND s.original_call_id=f.original_call_id AND s.version_kind='pending_to_returned')`, x.root, x.bindingSchema, x.bindingSHA, x.owner, chunk.OriginalHandleID).Scan(&pending)
			if err != nil {
				return err
			}
			if pending != 0 {
				return ErrHostFactoryHold
			}
			continue
		}
		if err != nil {
			return err
		}
		if len(chunk.OriginalCalls) != 1 || index != 0 || firstIndex != 0 || fact.OriginalState != "returned" {
			return ErrHostFactoryHold
		}
		priorRaw, err := resolveOriginalHostBodyTx(ctx, tx, x, firstSHA)
		if err != nil {
			return err
		}
		var prior model.HostFactoryCallVectorChunk
		if codec.Decode(priorRaw, &prior) != nil || originalHostSourcePendingTx(ctx, tx, x, prior, chunk, envelopeRaw) != nil {
			return ErrHostFactoryHold
		}
		var successors int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_call_snapshot_links WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND original_handle_id=$5 AND original_call_id=$6 AND version_kind='pending_to_returned'`, x.root, x.bindingSchema, x.bindingSHA, x.owner, chunk.OriginalHandleID, *fact.OriginalCallID).Scan(&successors); err != nil {
			return err
		}
		if successors != 0 {
			return ErrHostFactoryHold
		}
		zero, first := uint32(0), "first"
		links[index] = link{kind: "pending_to_returned", previous: &firstSHA, previousIndex: &zero, previousKind: &first}
	}
	if err = appendOriginalHostIOBodyTx(ctx, tx, x, bodyRaw, envelopeRaw); err != nil {
		return err
	}
	for index, fact := range chunk.OriginalCalls {
		l := links[index]
		var originalGetdents, originalGetdentsAudit []byte
		if fact.OriginalNativeReturn != nil && fact.OriginalNativeReturn.Kind == "unix_getdents64" && fact.OriginalState == "returned" && fact.OriginalNativeReturn.OriginalErrorPresent != nil && !*fact.OriginalNativeReturn.OriginalErrorPresent {
			realm, approval, installed := OriginalHostFactoryRealm()
			if !installed || realm == nil || approval.ScopeRootID != x.root {
				return ErrHostFactoryHold
			}
			originalGetdents, err = originalHostGetdentsBeforeLink(fact, func(callID string) ([]byte, error) { return realm.OriginalGetdentsBuffer(ctx, callID) })
			if err != nil {
				return err
			}
			originalGetdentsAudit, err = originalHostGetdentsCustodyFromSource(ctx, tx, x.root, chunk, bodyRaw, envelopeRaw, uint32(index), originalGetdents, realm.OriginalGetdentsSourceAuditCustody)
			if err != nil {
				return err
			}
		}
		finalSourceAudit, finalErr := originalHostFinalAuditBeforeLinkTx(ctx, tx, x.root, chunk, bodyRaw, envelopeRaw, uint32(index))
		if finalErr != nil {
			return finalErr
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_call_snapshot_links(root_id,binding_schema,binding_sha256,original_owner_id,original_handle_id,original_call_id,version_kind,current_chunk_raw_body_sha256,current_fact_index,predecessor_chunk_raw_body_sha256,predecessor_fact_index,predecessor_version_kind,original_called_at,original_operation_deadline,original_getdents_wire,original_getdents_source_audit_wire,original_final_source_audit_wire) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, x.root, x.bindingSchema, x.bindingSHA, x.owner, chunk.OriginalHandleID, *fact.OriginalCallID, l.kind, x.bodySHA, index, l.previous, l.previousIndex, l.previousKind, *fact.OriginalCalledAt, fact.OriginalOperationDeadline, originalGetdents, originalGetdentsAudit, finalSourceAudit)
		if err != nil {
			return err
		}
	}
	return nil
}

// The current compiled roster contains no stage verification keys or approved
// native supplier. A bare signature or a database row never fills this gap.
// Selectors are route/SQL keys, never proof of source approval or ownership.
type HostFactoryRecordSelector struct {
	Family, RootID, ScopeSHA256, OwnerID, Role, BindingSchema, BindingSHA256 string
	Stage, Kind, HandleID, CollectionID, RawBodySHA256, RawEnvelopeSHA256    string
	PartOrdinal                                                              uint32
}

type hostFactoryStageRule struct{ family, binding, signer, subject string }

var originalHostStageRules = map[string]hostFactoryStageRule{
	"source-approval":               {"root", "original_host_factory_source_approval_v4", "host_source_approver", "host_exterior"},
	"basal-owner-core":              {"root", "original_host_factory_source_approval_v4", "host_exterior", "host_exterior"},
	"bootstrap-return-core":         {"root", "original_host_factory_source_approval_v4", "host_exterior", "host_exterior"},
	"root-preparation":              {"root", "original_host_factory_source_approval_v4", "host_exterior", "host_exterior"},
	"basal-owner-registrar":         {"root", "original_host_factory_root_preparation_v4", "host_registrar", "host_registrar"},
	"bootstrap-return-registrar":    {"root", "original_host_factory_root_preparation_v4", "host_registrar", "host_registrar"},
	"native-leaf-core-by-registrar": {"root", "original_host_factory_root_preparation_v4", "host_registrar", "host_exterior"},
	"native-leaf-registrar-by-core": {"root", "original_host_factory_root_preparation_v4", "host_exterior", "host_registrar"},
	"initial-empty-realm-read":      {"root", "original_host_factory_root_preparation_v4", "host_registrar", "host_exterior"},
	"root-completion":               {"root", "original_host_factory_root_preparation_v4", "host_exterior", "host_exterior"},
	"ordinary-basal-owner":          {"root", "factory_ordinary_source_binding_v4", "factory_ordinary_worker", "factory_ordinary_worker"},
	"ordinary-bootstrap-return":     {"root", "factory_ordinary_source_binding_v4", "factory_ordinary_worker", "factory_ordinary_worker"},
	"ordinary-prepared-create-plan": {"root", "factory_ordinary_source_binding_v4", "factory_ordinary_worker", "factory_ordinary_worker"},
	"ordinary-native-leaf-worker":   {"root", "factory_ordinary_source_binding_v4", "host_registrar", "factory_ordinary_worker"},
	"ordinary-guard-read":           {"root", "factory_ordinary_source_binding_v4", "host_core_issuer", "factory_ordinary_worker"},
	"basal-owner-worker":            {"scope", "original_host_factory_pre_authority_scope_v4", "host_worker", "host_worker"},
	"bootstrap-return-worker":       {"scope", "original_host_factory_pre_authority_scope_v4", "host_worker", "host_worker"},
	"prepared-create-plan":          {"scope", "original_host_factory_pre_authority_scope_v4", "host_worker", "host_worker"},
	"native-leaf-worker":            {"scope", "original_host_factory_pre_authority_scope_v4", "host_registrar", "host_worker"},
	"original-start-return":         {"scope", "original_host_factory_pre_authority_scope_v4", "host_exterior", "host_worker"},
	"alive-native-read":             {"scope", "original_host_factory_pre_authority_scope_v4", "host_registrar", "host_worker"},
	"poststart-empty-realm-read":    {"scope", "original_host_factory_pre_authority_scope_v4", "host_registrar", "host_worker"},
	"choice-return":                 {"scope", "original_host_factory_pre_authority_scope_v4", "host_worker", "host_worker"},
	"exterior-join":                 {"scope", "original_host_factory_pre_authority_scope_v4", "host_exterior", "host_worker"},
	"terminal-read":                 {"scope", "original_host_factory_pre_authority_scope_v4", "host_registrar", "host_worker"},
	"bootstrap-write-registrar":     {"root", "original_host_factory_root_preparation_v4", "host_exterior", "host_registrar"},
	"bootstrap-write-worker":        {"scope", "original_host_factory_pre_authority_scope_v4", "host_exterior", "host_worker"},
	"ordinary-bootstrap-write":      {"root", "factory_ordinary_source_binding_v4", "host_exterior", "factory_ordinary_worker"},
	"original-lease-provenance":     {"root", "original_host_factory_root_preparation_v4", "host_core_issuer", "host_exterior"},
	"preauthority-scope":            {"root", "original_host_factory_root_preparation_v4", "host_core_issuer", "host_exterior"},
	"alive-registration":            {"scope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer", "host_worker"},
	"issued-attachment":             {"scope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer", "host_worker"},
	"unissued-choice-reservation":   {"scope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer", "host_worker"},
	"issued-choice-reservation":     {"scope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer", "host_worker"},
	"unissued-disposition":          {"scope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer", "host_worker"},
	"issued-disposition":            {"scope", "original_host_factory_pre_authority_scope_v4", "host_core_issuer", "host_worker"},
}

func originalHostStageTarget(stage string) any {
	switch stage {
	case "source-approval":
		return &model.HostFactorySourceApproval{}
	case "basal-owner-core", "basal-owner-registrar", "basal-owner-worker", "ordinary-basal-owner":
		return &model.HostFactoryBasalOwnerObservation{}
	case "bootstrap-return-core", "bootstrap-return-registrar", "bootstrap-return-worker", "ordinary-bootstrap-return":
		return &model.HostFactoryBootstrapReturn{}
	case "root-preparation":
		return &model.HostFactoryRootPreparation{}
	case "native-leaf-core-by-registrar", "native-leaf-registrar-by-core", "native-leaf-worker", "ordinary-native-leaf-worker":
		return &model.HostFactoryNativeLeaf{}
	case "initial-empty-realm-read":
		return &model.HostFactoryInitialEmptyRealmRead{}
	case "root-completion":
		return &model.HostFactoryRootCompletion{}
	case "original-lease-provenance":
		return &model.HostFactoryOriginalLeaseProvenance{}
	case "preauthority-scope":
		return &model.HostFactoryPreAuthorityScope{}
	case "original-start-return":
		return &model.HostFactoryOriginalStartReturn{}
	case "alive-native-read":
		return &model.HostFactoryAliveNativeRead{}
	case "poststart-empty-realm-read":
		return &model.HostFactoryOriginalEmptyRealmRead{}
	case "prepared-create-plan", "ordinary-prepared-create-plan":
		return &model.HostFactoryPreparedCreatePlan{}
	case "alive-registration":
		return &model.HostFactoryAliveRegistration{}
	case "issued-attachment":
		return &model.HostFactoryIssuedAttachment{}
	case "unissued-choice-reservation":
		return &model.HostFactoryUnissuedChoiceReservation{}
	case "issued-choice-reservation":
		return &model.HostFactoryIssuedChoiceReservation{}
	case "choice-return":
		return &model.HostFactoryChoiceReturn{}
	case "exterior-join":
		return &model.HostFactoryExteriorJoin{}
	case "terminal-read":
		return &model.HostFactoryTerminalRead{}
	case "unissued-disposition":
		return &model.HostFactoryUnissuedDisposition{}
	case "issued-disposition":
		return &model.HostFactoryIssuedDisposition{}
	case "bootstrap-write-registrar", "bootstrap-write-worker", "ordinary-bootstrap-write":
		return &model.HostFactoryBootstrapWriteReturn{}
	case "ordinary-guard-read":
		return &model.FactoryOrdinaryGuardRead{}
	case "io-call-vector-chunk":
		return &model.HostFactoryCallVectorChunk{}
	case "io-call-vector-manifest":
		return &model.HostFactoryCallVectorManifest{}
	case "io-handle-inventory":
		return &model.HostFactoryHandleCallInventory{}
	case "native-observation-record":
		return &model.HostFactoryNativeObservationRecord{}
	case "native-observation-manifest":
		return &model.HostFactoryNativeObservationManifest{}
	case "failure-diagnostic":
		return &model.HostFactoryFailureDiagnostic{}
	default:
		return nil
	}
}

func decodeOriginalHostEnvelope(codec hostOriginalSourceCodec, selector HostFactoryRecordSelector, raw []byte) (any, []byte, string, error) {
	stage := selector.Stage
	if selector.Kind == "native-record" {
		stage = "native-observation-record"
	}
	if selector.Kind == "native-manifest" {
		stage = "native-observation-manifest"
	}
	if selector.RawEnvelopeSHA256 != "" && capacity.HostFactoryRawSHA256(raw) != selector.RawEnvelopeSHA256 {
		return nil, nil, "", ErrHostFactoryHold
	}
	if selector.Kind == "chunk" {
		stage = "io-call-vector-chunk"
	}
	if selector.Kind == "manifest" {
		stage = "io-call-vector-manifest"
	}
	if selector.Kind == "inventory" {
		stage = "io-handle-inventory"
	}
	if selector.Kind == "failure-part" {
		stage = "failure-diagnostic"
	}
	target := originalHostStageTarget(stage)
	if target == nil {
		return nil, nil, "", ErrHostFactoryHold
	}
	body, role, bindingSchema, bindingSHA, err := codec.Envelope(raw)
	if err != nil || selector.Family == "root" && bindingSchema == "original_host_factory_pre_authority_scope_v4" || selector.Family == "scope" && bindingSchema != "original_host_factory_pre_authority_scope_v4" || selector.Family != "root" && selector.Family != "scope" || role != selector.Role || bindingSchema != selector.BindingSchema || bindingSHA != selector.BindingSHA256 || codec.Decode(body, target) != nil || selector.RawBodySHA256 != "" && capacity.HostFactoryRawSHA256(body) != selector.RawBodySHA256 {
		return nil, nil, "", ErrHostFactoryHold
	}
	if selector.Stage != "" {
		rule, exists := originalHostStageRules[selector.Stage]
		if !exists || rule.family != selector.Family || rule.binding != bindingSchema || rule.signer != role {
			return nil, nil, "", ErrHostFactoryHold
		}
	}
	envelopeType, err := capacity.HostFactoryEnvelopeSchema(target, role, bindingSchema)
	if err != nil || selector.Family == "root" && envelopeType != "HostFactoryRootSignedEnvelope" || selector.Family == "scope" && envelopeType != "HostFactorySignedEnvelope" {
		return nil, nil, "", ErrHostFactoryHold
	}
	if selector.Stage == "" {
		if selector.Kind == "native-record" || selector.Kind == "native-manifest" {
			kind := strings.TrimPrefix(selector.Kind, "native-")
			stage = "native-observations/" + kind + "/" + capacity.HostFactoryRawSHA256(body) + "/" + capacity.HostFactoryRawSHA256(raw)
		} else if selector.Kind == "failure-part" {
			stage = "failure-collections/" + selector.CollectionID + "/parts/" + strconv.FormatUint(uint64(selector.PartOrdinal), 10) + "?sha256=" + capacity.HostFactoryRawSHA256(body)
		} else {
			stage = "io-calls/" + selector.HandleID + "/" + selector.Kind + "/" + capacity.HostFactoryRawSHA256(body)
		}
	}
	return target, body, stage, nil
}

// Inputs are readonly copies from the actual installed Source realm. Every
// envelope is independently authenticated before any SQL transaction begins.
func prepareOriginalHostRecords(ctx context.Context, root, scope string, records map[string][]byte) ([]hostOriginalRetainedRecord, error) {
	codec := originalHostInstalledSourceCodec(ctx, root)

	if len(records) == 0 {
		return nil, ErrHostFactoryHold
	}
	out := make([]hostOriginalRetainedRecord, 0, len(records))
	for name, raw := range records {
		var header struct {
			Schema string `json:"schema"`
		}
		if json.Unmarshal(raw, &header) != nil {
			return nil, ErrHostFactoryHold
		}
		sel := HostFactoryRecordSelector{RootID: root}
		if header.Schema == "original_host_factory_root_signed_envelope_v4" {
			var e model.HostFactoryRootSignedEnvelope
			if codec.Decode(raw, &e) != nil {
				return nil, ErrHostFactoryHold
			}
			sel.Family, sel.Role, sel.BindingSchema, sel.BindingSHA256 = "root", e.Role, e.BindingSchema, e.BindingSHA256
		} else if header.Schema == "source_host_factory_signed_envelope_v1" {
			var e capacity.HostFactorySourceSignedEnvelope
			if codec.Decode(raw, &e) != nil || scope == "" || e.PreAuthorityScopeSHA256 != scope {
				return nil, ErrHostFactoryHold
			}
			sel.Family, sel.Role, sel.BindingSchema, sel.BindingSHA256, sel.ScopeSHA256 = "scope", e.Role, "original_host_factory_pre_authority_scope_v4", e.PreAuthorityScopeSHA256, scope
		} else {
			return nil, ErrHostFactoryHold
		}
		if strings.HasPrefix(name, "native-observations/") {
			kind, bodySHA, envelopeSHA, err := originalHostNativeSelector(name)
			if err != nil {
				return nil, err
			}
			sel.Kind, sel.RawBodySHA256, sel.RawEnvelopeSHA256 = kind, bodySHA, envelopeSHA
		} else if strings.HasPrefix(name, "io-calls/") {
			parts := strings.Split(name, "/")
			if len(parts) != 4 || !validCapacityExecutor(parts[1]) || (parts[2] != "chunk" && parts[2] != "manifest" && parts[2] != "inventory") || !capacity.ValidDigest(parts[3]) {
				return nil, ErrHostFactoryHold
			}
			sel.HandleID, sel.Kind, sel.RawBodySHA256 = parts[1], parts[2], parts[3]
		} else {
			if _, exists := originalHostStageRules[name]; !exists {
				return nil, ErrHostFactoryHold
			}
			sel.Stage = name
		}
		body, bodyRaw, stage, err := decodeOriginalHostEnvelope(codec, sel, raw)
		if err != nil || verifyOriginalHostRecord(ctx, sel, stage, raw) != nil {
			return nil, ErrHostFactoryHold
		}
		switch v := body.(type) {
		case *model.HostFactoryNativeObservationRecord:
			sel.OwnerID = v.ObserverOwnerID
		case *model.HostFactoryNativeObservationManifest:
			sel.OwnerID = v.ObserverOwnerID
		case *model.HostFactoryCallVectorChunk:
			sel.OwnerID = v.OriginalOwnerID
		case *model.HostFactoryCallVectorManifest:
			sel.OwnerID = v.OriginalOwnerID
		case *model.HostFactoryHandleCallInventory:
			sel.OwnerID = v.OriginalOwnerID
		}
		out = append(out, hostOriginalRetainedRecord{sel, body, bytes.Clone(bodyRaw), bytes.Clone(raw)})
	}
	return out, nil
}

func originalHostRecordOrder(r hostOriginalRetainedRecord) int {
	if r.selector.Stage == "basal-owner-core" || r.selector.Stage == "basal-owner-registrar" || r.selector.Stage == "basal-owner-worker" || r.selector.Stage == "ordinary-basal-owner" {
		return 0
	}
	if r.selector.Kind == "chunk" {
		return 1
	}
	if r.selector.Kind == "manifest" {
		return 2
	}
	if r.selector.Kind == "inventory" {
		return 3
	}
	if r.selector.Kind == "native-record" {
		return 5
	}
	if r.selector.Kind == "native-manifest" {
		return 6
	}
	switch r.body.(type) {
	case *model.HostFactoryNativeLeaf:
		return 7
	case *model.HostFactoryOriginalStartReturn:
		return 8
	case *model.HostFactoryAliveNativeRead:
		return 9
	case *model.HostFactoryInitialEmptyRealmRead, *model.HostFactoryOriginalEmptyRealmRead:
		return 10
	case *model.HostFactoryExteriorJoin:
		return 11
	case *model.HostFactoryTerminalRead:
		return 12
	}
	return 4
}

func (s CapacityStore) appendOriginalHostRecordsTx(ctx context.Context, tx *sql.Tx, records []hostOriginalRetainedRecord) error {
	ordered := append([]hostOriginalRetainedRecord(nil), records...)
	sort.Slice(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		ao, bo := originalHostRecordOrder(a), originalHostRecordOrder(b)
		if ao != bo {
			return ao < bo
		}
		if ao == 1 {
			ac, bc := a.body.(*model.HostFactoryCallVectorChunk), b.body.(*model.HostFactoryCallVectorChunk)
			if ac.OriginalHandleID != bc.OriginalHandleID {
				return ac.OriginalHandleID < bc.OriginalHandleID
			}
			if ac.FirstOrdinal != bc.FirstOrdinal {
				return ac.FirstOrdinal < bc.FirstOrdinal
			}
			return ac.RecordedAt.Before(bc.RecordedAt)
		}
		if ao == 2 {
			am, bm := a.body.(*model.HostFactoryCallVectorManifest), b.body.(*model.HostFactoryCallVectorManifest)
			if am.Level != bm.Level {
				return am.Level < bm.Level
			}
		}
		if ao == 6 {
			am, bm := a.body.(*model.HostFactoryNativeObservationManifest), b.body.(*model.HostFactoryNativeObservationManifest)
			if am.Level != bm.Level {
				return am.Level < bm.Level
			}
			if am.CollectionID != bm.CollectionID {
				return am.CollectionID < bm.CollectionID
			}
			return am.FirstOrdinal < bm.FirstOrdinal
		}
		if ao == 5 {
			return a.selector.RawBodySHA256 < b.selector.RawBodySHA256
		}
		return a.selector.Stage < b.selector.Stage
	})
	for _, r := range ordered {
		if err := s.appendOriginalHostRecordTx(ctx, tx, r.selector, r.body, r.bodyRaw, r.envelopeRaw); err != nil {
			return err
		}
	}
	return nil
}

// Read originals by their complete immutable identities. This performs no
// INSERT or replay repair: Claim and post-primer admission use the rows from
// the already returned original initializer transaction.
func (s CapacityStore) compareOriginalHostRecordsTx(ctx context.Context, tx *sql.Tx, records []hostOriginalRetainedRecord) error {
	if len(records) == 0 {
		return ErrHostFactoryHold
	}
	for _, record := range records {
		codec := originalHostSourceCodecTx(ctx, tx, record.selector.RootID)
		if codec.err != nil {
			return codec.err
		}
		if err := s.compareOriginalHostRecordStorageTx(ctx, tx, codec, record); err != nil {
			return err
		}
	}
	return nil
}

// SAME immutable bytes/FIRST algorithm after owning Source selection. This
// private helper cannot install a Source owner or authorize a native effect.
func (s CapacityStore) compareOriginalHostRecordStorageTx(ctx context.Context, tx *sql.Tx, codec hostOriginalSourceCodec, record hostOriginalRetainedRecord) error {
	if ctx == nil || ctx.Err() != nil || tx == nil || codec.err != nil || codec.profile == nil {
		return ErrHostFactoryHold
	}
	selector := record.selector
	var bodyRaw, envelopeRaw []byte
	var bodySHA, envelopeSHA string
	if selector.Stage != "" {
		if err := tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire,raw_body_sha256,raw_envelope_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage=$2 AND binding_schema=$3 AND binding_sha256=$4 AND signer_role=$5 AND raw_body_sha256=$6`, selector.RootID, selector.Stage, selector.BindingSchema, selector.BindingSHA256, selector.Role, capacity.HostFactoryRawSHA256(record.bodyRaw)).Scan(&bodyRaw, &envelopeRaw, &bodySHA, &envelopeSHA); err != nil {
			return ErrHostFactoryHold
		}
	} else {
		identity, err := originalHostIOIdentity(codec, selector.RootID, record.body, record.bodyRaw)
		kind := selector.Kind
		if kind == "inventory" {
			kind = "handle-inventory"
		}
		if err != nil || identity.owner != selector.OwnerID || identity.role != selector.Role || identity.bindingSchema != selector.BindingSchema || identity.bindingSHA != selector.BindingSHA256 || identity.kind != kind || identity.handle != nil && *identity.handle != selector.HandleID || identity.handle == nil && selector.HandleID != "" {
			return ErrHostFactoryHold
		}
		if err = tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire,raw_body_sha256,raw_envelope_sha256 FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND record_kind=$5 AND raw_body_sha256=$6`, selector.RootID, selector.BindingSchema, selector.BindingSHA256, selector.OwnerID, identity.kind, identity.bodySHA).Scan(&bodyRaw, &envelopeRaw, &bodySHA, &envelopeSHA); err != nil {
			return ErrHostFactoryHold
		}
	}
	if len(bodyRaw) == 0 || len(bodyRaw) > 65536 || len(envelopeRaw) == 0 || len(envelopeRaw) > 65536 || capacity.HostFactoryRawSHA256(bodyRaw) != bodySHA || capacity.HostFactoryRawSHA256(envelopeRaw) != envelopeSHA || !bytes.Equal(bodyRaw, record.bodyRaw) || !bytes.Equal(envelopeRaw, record.envelopeRaw) {
		return ErrHostFactoryHold
	}
	if selector.Stage != "" {
		if err := compareOriginalHostNativeAggregateTx(ctx, tx, selector, record.body, bodyRaw, envelopeRaw); err != nil {
			return err
		}
		if err := validateOriginalHostStageVectorsTx(ctx, tx, selector.RootID, record.body); err != nil {
			return err
		}
		if err := compareOriginalHostPostStartStoredTx(ctx, tx, selector, record.body, bodyRaw, envelopeRaw, true); err != nil {
			return err
		}
	} else {
		identity, err := originalHostIOIdentity(codec, selector.RootID, record.body, bodyRaw)
		if err != nil {
			return err
		}
		switch body := record.body.(type) {
		case *model.HostFactoryNativeObservationRecord:
			var relationRaw []byte
			if tx.QueryRowContext(ctx, `SELECT native_inventory_relations_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='native-record' AND raw_body_sha256=$2 AND raw_envelope_sha256=$3`, selector.RootID, bodySHA, envelopeSHA).Scan(&relationRaw) != nil || validateOriginalHostNativeStoredRecordTx(ctx, tx, selector.RootID, *body, relationRaw) != nil {
				return ErrHostFactoryHold
			}
		case *model.HostFactoryCallVectorChunk:
			if codec.Validate(*body) != nil {
				return ErrHostFactoryHold
			}
			for index := range body.OriginalCalls {
				pendingRaw, pendingIndex, err := originalHostPredecessorTx(ctx, tx, identity, bodySHA, uint32(index))
				if err != nil {
					return err
				}
				if pendingRaw != nil {
					var pending model.HostFactoryCallVectorChunk
					if pendingIndex != 0 || codec.Decode(pendingRaw, &pending) != nil || originalHostSourcePendingTx(ctx, tx, identity, pending, *body, envelopeRaw) != nil {
						return ErrHostFactoryHold
					}
				}
			}
		case *model.HostFactoryCallVectorManifest:
			if err = validateOriginalHostManifestTx(ctx, tx, identity, *body); err != nil {
				return err
			}
		case *model.HostFactoryHandleCallInventory:
			if body.CollectionState != "complete_original_calls" || validateOriginalHostInventoryTx(ctx, tx, identity, *body) != nil {
				return ErrHostFactoryHold
			}
		}
	}
	return nil
}

func verifyOriginalHostRecord(ctx context.Context, selector HostFactoryRecordSelector, stage string, raw []byte) error {
	codec := originalHostInstalledSourceCodec(ctx, "")

	realm, approval, installed := OriginalHostFactoryRealm()
	if !installed || realm == nil || approval.ScopeRootID != selector.RootID {
		return ErrHostFactoryHold
	}
	compiled, err := capacity.ApprovedHostFactorySource()
	a, e1 := codec.Canonical(approval)
	b, e2 := codec.Canonical(compiled)
	if err != nil || e1 != nil || e2 != nil || !bytes.Equal(a, b) || realm.VerifyOriginalStage(ctx, stage, raw) != nil {
		return ErrHostFactoryHold
	}
	return nil
}

func (s CapacityStore) GetOriginalHostRecord(ctx context.Context, selector HostFactoryRecordSelector) ([]byte, error) {
	codec := originalHostInstalledSourceCodec(ctx, "")

	if s.DB == nil || !capacity.ValidDigest(selector.RawBodySHA256) {
		return nil, ErrHostFactoryHold
	}
	var raw, body []byte
	var digest string
	var err error
	if selector.Stage != "" {
		err = s.DB.QueryRowContext(ctx, `SELECT raw_envelope_wire,raw_body_wire,raw_envelope_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage=$2 AND binding_schema=$3 AND binding_sha256=$4 AND signer_role=$5 AND raw_body_sha256=$6`, selector.RootID, selector.Stage, selector.BindingSchema, selector.BindingSHA256, selector.Role, selector.RawBodySHA256).Scan(&raw, &body, &digest)
	} else {
		query := `SELECT raw_envelope_wire,raw_body_wire,raw_envelope_sha256 FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND record_kind=$5 AND raw_body_sha256=$6`
		kind := selector.Kind
		if kind == "inventory" {
			kind = "handle-inventory"
		}
		args := []any{selector.RootID, selector.BindingSchema, selector.BindingSHA256, selector.OwnerID, kind, selector.RawBodySHA256}
		if selector.Kind == "native-record" || selector.Kind == "native-manifest" {
			if !capacity.ValidDigest(selector.RawEnvelopeSHA256) {
				return nil, ErrHostFactoryHold
			}
			query += ` AND raw_envelope_sha256=$7`
			args = append(args, selector.RawEnvelopeSHA256)
		} else if selector.Kind == "failure-part" {
			query += ` AND failure_collection_id=$7 AND part_ordinal=$8`
			args = append(args, selector.CollectionID, selector.PartOrdinal)
		} else {
			query += ` AND original_handle_id=$7`
			args = append(args, selector.HandleID)
		}
		err = s.DB.QueryRowContext(ctx, query, args...).Scan(&raw, &body, &digest)
	}
	if err != nil || capacity.HostFactoryRawSHA256(raw) != digest || capacity.HostFactoryRawSHA256(body) != selector.RawBodySHA256 {
		return nil, ErrHostFactoryHold
	}
	_, actual, stage, err := decodeOriginalHostEnvelope(codec, selector, raw)
	if err != nil || !bytes.Equal(actual, body) || verifyOriginalHostRecord(ctx, selector, stage, raw) != nil {
		return nil, ErrHostFactoryHold
	}
	return bytes.Clone(raw), nil
}

func (s CapacityStore) AppendOriginalHostRecord(ctx context.Context, selector HostFactoryRecordSelector, raw []byte) error {
	codec := originalHostInstalledSourceCodec(ctx, "")

	// Native selectors are readonly. Only the original private producer map
	// reaches the native appender; HTTP/caller DTOs cannot publish records.
	if selector.Kind == "native-record" || selector.Kind == "native-manifest" || selector.Stage == "poststart-empty-realm-read" {
		// PostEMPTY is written only by the preowned registration attempt.
		return ErrHostFactoryHold
	}
	if s.DB == nil {
		return ErrHostFactoryHold
	}
	target, body, stage, err := decodeOriginalHostEnvelope(codec, selector, raw)
	if err != nil || verifyOriginalHostRecord(ctx, selector, stage, raw) != nil {
		return ErrHostFactoryHold
	}
	selector.RawBodySHA256 = capacity.HostFactoryRawSHA256(body)
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.appendOriginalHostRecordTx(ctx, tx, selector, target, body, raw); err != nil {
		return err
	}
	return tx.Commit()
}

func originalHostPrimitiveOwnerTx(ctx context.Context, tx *sql.Tx, root, sha string) (string, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT raw_body_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND raw_body_sha256=$2 AND stage IN ('basal-owner-core','basal-owner-registrar','basal-owner-worker','ordinary-basal-owner')`, root, sha).Scan(&raw)
	var basal model.HostFactoryBasalOwnerObservation
	if err != nil || capacity.HostFactoryRawSHA256(raw) != sha || codec.Decode(raw, &basal) != nil {
		return "", ErrHostFactoryHold
	}
	return basal.OriginalOwnerID, nil
}

func originalHostSubjectTx(ctx context.Context, tx *sql.Tx, selector HostFactoryRecordSelector, body any) (string, error) {
	codec := originalHostSourceCodecTx(ctx, tx, selector.RootID)

	switch x := body.(type) {
	case *model.HostFactoryBasalOwnerObservation:
		return x.OriginalOwnerID, nil
	case *model.HostFactoryBootstrapReturn:
		return originalHostPrimitiveOwnerTx(ctx, tx, selector.RootID, x.OwnerPrimitiveRawSHA256)
	case *model.HostFactoryNativeLeaf:
		return originalHostPrimitiveOwnerTx(ctx, tx, selector.RootID, x.SubjectPrimitiveRawSHA256)
	case *model.HostFactoryPreparedCreatePlan:
		return originalHostPrimitiveOwnerTx(ctx, tx, selector.RootID, x.OwnerPrimitiveRawSHA256)
	case *model.HostFactoryBootstrapWriteReturn:
		return x.RecipientOwnerID, nil
	case *model.HostFactoryRootPreparation:
		return originalHostPrimitiveOwnerTx(ctx, tx, selector.RootID, x.CoreBasalOwnerRawSHA256)
	case *model.HostFactoryInitialEmptyRealmRead:
		return originalHostPrimitiveOwnerTx(ctx, tx, selector.RootID, x.CoreBasalOwnerRawSHA256)
	}
	if selector.BindingSchema == "factory_ordinary_source_binding_v4" {
		var owner string
		err := tx.QueryRowContext(ctx, `SELECT owner_id::text FROM public.capacity_host_factory_scopes WHERE root_id=$1 AND scope_sha256=$2 AND binding_schema='factory_ordinary_source_binding_v4'`, selector.RootID, selector.BindingSHA256).Scan(&owner)
		return owner, err
	}
	if selector.Family == "scope" {
		var owner string
		err := tx.QueryRowContext(ctx, `SELECT owner_id::text FROM public.capacity_host_factory_scopes WHERE root_id=$1 AND scope_sha256=$2`, selector.RootID, selector.ScopeSHA256).Scan(&owner)
		return owner, err
	}
	var prepRaw []byte
	if err := tx.QueryRowContext(ctx, `SELECT root_preparation_wire FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, selector.RootID).Scan(&prepRaw); err != nil {
		return "", err
	}
	var prep model.HostFactoryRootPreparation
	if codec.Decode(prepRaw, &prep) != nil {
		return "", ErrHostFactoryHold
	}
	return originalHostPrimitiveOwnerTx(ctx, tx, selector.RootID, prep.CoreBasalOwnerRawSHA256)
}

// Select a declared vector only through an authenticated immutable manifest
// and a complete SAME-handle inventory containing that exact vector. The
// inventory closes interleaved gaps; it never upgrades native/source authority.
func originalHostVectorFactsTx(ctx context.Context, tx *sql.Tx, root string, ref model.HostFactoryCallVectorReference) ([]model.HostFactoryPrimitiveIOReturn, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	if codec.Validate(ref) != nil || ref.CollectionState != "complete_original_calls" || ref.ManifestRootSHA256 == nil || ref.OwnerPrimitiveRawSHA256 == nil || ref.OriginalCallCount == 0 {
		return nil, ErrHostFactoryHold
	}
	owner, err := originalHostPrimitiveOwnerTx(ctx, tx, root, *ref.OwnerPrimitiveRawSHA256)
	if err != nil || owner != ref.OriginalOwnerID {
		return nil, ErrHostFactoryHold
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT raw_body_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND original_owner_id=$2 AND record_kind='manifest' AND original_handle_id=$3 AND raw_body_sha256=$4`, root, owner, ref.OriginalHandleID, *ref.ManifestRootSHA256).Scan(&raw); err != nil {
		return nil, ErrHostFactoryHold
	}
	var manifest model.HostFactoryCallVectorManifest
	if capacity.HostFactoryRawSHA256(raw) != *ref.ManifestRootSHA256 || codec.Decode(raw, &manifest) != nil || manifest.OwnerPrimitiveRawSHA256 != *ref.OwnerPrimitiveRawSHA256 || manifest.OriginalOwnerID != owner || manifest.OriginalHandleID != ref.OriginalHandleID || manifest.Operation != ref.Operation || manifest.FirstOrdinal != ref.FirstOrdinal || manifest.LastOrdinal != ref.LastOrdinal || manifest.OriginalCallCount != ref.OriginalCallCount || manifest.CollectionState != ref.CollectionState {
		return nil, ErrHostFactoryHold
	}
	x, err := originalHostIOIdentity(codec, root, &manifest, raw)
	if err != nil {
		return nil, err
	}
	facts, err := originalHostManifestFactsTx(ctx, tx, x, manifest)
	if err != nil {
		return nil, err
	}
	for _, fact := range facts {
		if fact.SubjectOwnerID != ref.SubjectOwnerID {
			return nil, ErrHostFactoryHold
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT raw_body_wire,raw_body_sha256 FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND original_handle_id=$5 AND record_kind='handle-inventory' ORDER BY raw_body_sha256 LIMIT 32769`, root, x.bindingSchema, x.bindingSHA, x.owner, ref.OriginalHandleID)
	if err != nil {
		return nil, err
	}
	var inventoryWires [][]byte
	total := 0
	for rows.Next() {
		var inventoryRaw []byte
		var sha string
		if err = rows.Scan(&inventoryRaw, &sha); err != nil {
			rows.Close()
			return nil, err
		}
		if len(inventoryWires) >= 32768 || len(inventoryRaw) == 0 || len(inventoryRaw) > 65536 || total > 32*1024*1024-len(inventoryRaw) || capacity.HostFactoryRawSHA256(inventoryRaw) != sha {
			rows.Close()
			return nil, ErrHostFactoryHold
		}
		total += len(inventoryRaw)
		inventoryWires = append(inventoryWires, bytes.Clone(inventoryRaw))
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrHostFactoryHold
	}
	// Nested reads begin only after this actual owning rows return/Close.
	found := false
	for _, wire := range inventoryWires {
		var inventory model.HostFactoryHandleCallInventory
		if codec.Decode(wire, &inventory) != nil {
			return nil, ErrHostFactoryHold
		}
		for _, selected := range inventory.OperationVectors {
			if reflect.DeepEqual(selected, ref) {
				found = true
				identity, e := originalHostIOIdentity(codec, root, &inventory, wire)
				if e != nil || inventory.CollectionState != "complete_original_calls" || validateOriginalHostInventoryTx(ctx, tx, identity, inventory) != nil {
					return nil, ErrHostFactoryHold
				}
			}
		}
	}
	if !found {
		return nil, ErrHostFactoryHold
	}
	return facts, nil
}

func originalHostSelectedFactTx(ctx context.Context, tx *sql.Tx, root string, ref model.HostFactoryCallVectorReference, callID, handle string, fd int, kind string) (model.HostFactoryPrimitiveIOReturn, error) {
	facts, err := originalHostVectorFactsTx(ctx, tx, root, ref)
	if err != nil {
		return model.HostFactoryPrimitiveIOReturn{}, err
	}
	for _, fact := range facts {
		if fact.OriginalCallID != nil && *fact.OriginalCallID == callID {
			native := fact.OriginalNativeReturn
			if fact.OriginalHandleID != handle || native == nil || native.Kind != kind || native.InputDescriptorNumber == nil || *native.InputDescriptorNumber != fd || fact.OriginalReturnedAt == nil || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || native.OriginalErrorPresent == nil || *native.OriginalErrorPresent {
				return model.HostFactoryPrimitiveIOReturn{}, ErrHostFactoryHold
			}
			return fact, nil
		}
	}
	return model.HostFactoryPrimitiveIOReturn{}, ErrHostFactoryHold
}

func validateOriginalHostDescriptorTx(ctx context.Context, tx *sql.Tx, root string, descriptor model.HostFactoryBootstrapDescriptorSource) error {
	stat, err := originalHostSelectedFactTx(ctx, tx, root, descriptor.OriginalFstatCallVector, descriptor.OriginalFstatCallID, descriptor.OriginalHandleID, descriptor.OriginalDescriptorNumber, "unix_fstat")
	if err != nil {
		return err
	}
	n := stat.OriginalNativeReturn.OriginalStat
	if n == nil || n.Device != descriptor.Device || n.Inode != descriptor.Inode || n.Mode != descriptor.Mode || n.LinkCount != descriptor.LinkCount || n.UID != descriptor.UID || n.GID != descriptor.GID || !stat.OriginalReturnedAt.Equal(descriptor.OriginalFstatReturnedAt) {
		return ErrHostFactoryHold
	}
	getfl, err := originalHostSelectedFactTx(ctx, tx, root, descriptor.OriginalGetflCallVector, descriptor.OriginalGetflCallID, descriptor.OriginalHandleID, descriptor.OriginalDescriptorNumber, "fcntl_getfl")
	if err != nil {
		return err
	}
	getfd, err := originalHostSelectedFactTx(ctx, tx, root, descriptor.OriginalGetfdCallVector, descriptor.OriginalGetfdCallID, descriptor.OriginalHandleID, descriptor.OriginalDescriptorNumber, "fcntl_getfd")
	if err != nil || getfl.OriginalNativeReturn.OriginalScalar == nil || *getfl.OriginalNativeReturn.OriginalScalar != int64(descriptor.Flags) || getfd.OriginalNativeReturn.OriginalScalar == nil || *getfd.OriginalNativeReturn.OriginalScalar != int64(descriptor.DescriptorFlags) {
		return ErrHostFactoryHold
	}
	if descriptor.OwnerPrimitiveRawSHA256 != "" && (descriptor.OriginalFstatCallVector.OwnerPrimitiveRawSHA256 == nil || *descriptor.OriginalFstatCallVector.OwnerPrimitiveRawSHA256 != descriptor.OwnerPrimitiveRawSHA256) {
		return ErrHostFactoryHold
	}
	return nil
}

func originalHostStatVectorTx(ctx context.Context, tx *sql.Tx, root string, ref model.HostFactoryCallVectorReference, fd int, stat model.HostFactoryNativeStatReturn) error {
	facts, err := originalHostVectorFactsTx(ctx, tx, root, ref)
	if err != nil {
		return err
	}
	if len(facts) == 0 {
		return ErrHostFactoryHold
	}
	for _, fact := range facts {
		if fact.OriginalCallID == nil {
			return ErrHostFactoryHold
		}
		selected, e := originalHostSelectedFactTx(ctx, tx, root, ref, *fact.OriginalCallID, ref.OriginalHandleID, fd, "unix_fstat")
		if e != nil || selected.OriginalNativeReturn.OriginalStat == nil || *selected.OriginalNativeReturn.OriginalStat != stat {
			return ErrHostFactoryHold
		}
	}
	return nil
}

func validateOriginalHostOriginalIOTx(ctx context.Context, tx *sql.Tx, root string, value model.HostFactoryOriginalIOFact) error {
	facts, err := originalHostVectorFactsTx(ctx, tx, root, value.OriginalCallVector)
	if err != nil || len(facts) == 0 {
		return ErrHostFactoryHold
	}
	var count int64
	for _, fact := range facts {
		if fact.OriginalCount == nil || fact.OriginalReturnedAt == nil || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || fact.SubjectOwnerID != value.SubjectOwnerID || fact.OriginalHandleID != value.OriginalHandleID {
			return ErrHostFactoryHold
		}
		count += *fact.OriginalCount
		if count > 65536 {
			return ErrHostFactoryHold
		}
	}
	last := facts[len(facts)-1]
	if count != value.OriginalCount || !facts[0].OriginalCalledAt.Equal(value.OriginalCalledAt) || !last.OriginalReturnedAt.Equal(value.OriginalReturnedAt) || last.OriginalEOF == nil || *last.OriginalEOF != value.OriginalEOF || value.OriginalEOF && last.OriginalReturnClass != "eof" {
		return ErrHostFactoryHold
	}
	if len(facts) == 1 && (last.OriginalSHA256 == nil || *last.OriginalSHA256 != value.OriginalSHA256) {
		return ErrHostFactoryHold
	}
	closes, err := originalHostVectorFactsTx(ctx, tx, root, value.OriginalCloseCallVector)
	if err != nil || len(closes) != 1 {
		return ErrHostFactoryHold
	}
	close := closes[0]
	if close.OriginalReturnedAt == nil || !close.OriginalReturnedAt.Equal(value.OriginalCloseReturnedAt) || close.OriginalCalledAt.Before(value.OriginalReturnedAt) || close.OriginalReturnClass != "success" || close.SubjectOwnerID != value.SubjectOwnerID || close.OriginalHandleID != value.OriginalHandleID || close.OriginalNativeReturn == nil || close.OriginalNativeReturn.OriginalErrorPresent == nil || *close.OriginalNativeReturn.OriginalErrorPresent || !close.OriginalReturnedAt.Before(close.OriginalOperationDeadline) {
		return ErrHostFactoryHold
	}
	return nil
}

func validateOriginalHostDeclaredInventoryTx(ctx context.Context, tx *sql.Tx, root, handle, sha string, value reflect.Value) error {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	if !capacity.ValidDigest(sha) || !validCapacityExecutor(handle) {
		return ErrHostFactoryHold
	}
	var raw []byte
	if err := tx.QueryRowContext(ctx, `SELECT raw_body_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='handle-inventory' AND original_handle_id=$2 AND raw_body_sha256=$3`, root, handle, sha).Scan(&raw); err != nil {
		return err
	}
	var inventory model.HostFactoryHandleCallInventory
	if len(raw) > 65536 || capacity.HostFactoryRawSHA256(raw) != sha || codec.Decode(raw, &inventory) != nil || inventory.OriginalHandleID != handle || inventory.CollectionState != "complete_original_calls" {
		return ErrHostFactoryHold
	}
	x, err := originalHostIOIdentity(codec, root, &inventory, raw)
	if err != nil || originalHostKnownBindingTx(ctx, tx, root, x.bindingSchema, x.bindingSHA) != nil || validateOriginalHostInventoryTx(ctx, tx, x, inventory) != nil {
		return ErrHostFactoryHold
	}
	// A valid inventory for the same handle is insufficient when the producer
	// named a different original inventory. Join every declared local vector.
	var join func(reflect.Value) error
	join = func(v reflect.Value) error {
		if !v.IsValid() {
			return nil
		}
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return nil
			}
			return join(v.Elem())
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryCallVectorReference{}) {
			ref := v.Interface().(model.HostFactoryCallVectorReference)
			if ref.OriginalHandleID != handle {
				return nil
			}
			for _, original := range inventory.OperationVectors {
				if reflect.DeepEqual(original, ref) {
					return nil
				}
			}
			return ErrHostFactoryHold
		}
		if v.Type() == reflect.TypeOf(time.Time{}) {
			return nil
		}
		switch v.Kind() {
		case reflect.Struct:
			for n := 0; n < v.NumField(); n++ {
				if err := join(v.Field(n)); err != nil {
					return err
				}
			}
		case reflect.Array, reflect.Slice:
			for n := 0; n < v.Len(); n++ {
				if err := join(v.Index(n)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return join(value)
}

func validateOriginalHostStageVectorsTx(ctx context.Context, tx *sql.Tx, root string, body any) error {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	var walk func(reflect.Value) error
	walk = func(v reflect.Value) error {
		if !v.IsValid() {
			return nil
		}
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return nil
			}
			return walk(v.Elem())
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryCallVectorReference{}) {
			ref := v.Interface().(model.HostFactoryCallVectorReference)
			if codec.Validate(ref) != nil {
				return ErrHostFactoryHold
			}
			if ref.OriginalCallCount == 0 {
				return nil
			}
			_, err := originalHostVectorFactsTx(ctx, tx, root, ref)
			return err
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryBootstrapDescriptorSource{}) {
			if err := validateOriginalHostDescriptorTx(ctx, tx, root, v.Interface().(model.HostFactoryBootstrapDescriptorSource)); err != nil {
				return err
			}
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryDescriptorSource{}) {
			d := v.Interface().(model.HostFactoryDescriptorSource)
			projection := model.HostFactoryBootstrapDescriptorSource{Device: d.Device, Inode: d.Inode, Mode: d.Mode, LinkCount: d.LinkCount, UID: d.UID, GID: d.GID, Flags: d.Flags, DescriptorFlags: d.DescriptorFlags, OriginalDescriptorNumber: d.OriginalDescriptorNumber, OriginalHandleID: d.OriginalHandleID, OriginalFstatReturnedAt: d.OriginalFstatReturnedAt, OriginalFstatCallVector: d.OriginalFstatCallVector, OriginalFstatCallID: d.OriginalFstatCallID, OriginalGetflCallVector: d.OriginalGetflCallVector, OriginalGetflCallID: d.OriginalGetflCallID, OriginalGetfdCallVector: d.OriginalGetfdCallVector, OriginalGetfdCallID: d.OriginalGetfdCallID}
			if err := validateOriginalHostDescriptorTx(ctx, tx, root, projection); err != nil {
				return err
			}
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryOriginalIOFact{}) {
			if err := validateOriginalHostOriginalIOTx(ctx, tx, root, v.Interface().(model.HostFactoryOriginalIOFact)); err != nil {
				return err
			}
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryHeldExecutableRead{}) {
			x := v.Interface().(model.HostFactoryHeldExecutableRead)
			for _, pair := range []struct {
				id   string
				stat model.HostFactoryNativeStatReturn
			}{{x.OriginalBeforeFstatCallID, x.OriginalBeforeStat}, {x.OriginalAfterFstatCallID, x.OriginalAfterStat}} {
				fact, err := originalHostSelectedFactTx(ctx, tx, root, x.OriginalFstatCallVector, pair.id, x.OriginalHandleID, x.OriginalDescriptorNumber, "unix_fstat")
				if err != nil || fact.OriginalNativeReturn.OriginalStat == nil || *fact.OriginalNativeReturn.OriginalStat != pair.stat {
					return ErrHostFactoryHold
				}
			}
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryProcessOwnerRead{}) {
			x := v.Interface().(model.HostFactoryProcessOwnerRead)
			if err := originalHostStatVectorTx(ctx, tx, root, x.OriginalFstatCallVector, x.OriginalDescriptorNumber, x.OriginalStat); err != nil {
				return err
			}
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryTaskDirectoryRead{}) {
			x := v.Interface().(model.HostFactoryTaskDirectoryRead)
			if err := originalHostStatVectorTx(ctx, tx, root, x.OriginalFstatCallVector, x.OriginalDescriptorNumber, x.OriginalDirectoryStat); err != nil {
				return err
			}
			facts, err := originalHostVectorFactsTx(ctx, tx, root, x.OriginalGetdentsCallVector)
			if err != nil {
				return err
			}
			var count uint64
			for _, fact := range facts {
				n := fact.OriginalNativeReturn
				if n == nil || n.Kind != "unix_getdents64" || n.InputDescriptorNumber == nil || *n.InputDescriptorNumber != x.OriginalDescriptorNumber || n.OriginalErrorPresent == nil || *n.OriginalErrorPresent || n.OriginalScalar == nil || *n.OriginalScalar < 0 || fact.OriginalCount == nil || *fact.OriginalCount != *n.OriginalScalar || fact.OriginalEOF == nil || *fact.OriginalEOF {
					return ErrHostFactoryHold
				}
				count += uint64(*n.OriginalScalar)
				if count > 65536 {
					return ErrHostFactoryHold
				}
			}
			last := facts[len(facts)-1]
			if last.OriginalCallID == nil || *last.OriginalCallID != x.OriginalTerminalCallID || last.OriginalNativeReturn.OriginalScalar == nil || *last.OriginalNativeReturn.OriginalScalar != 0 || count != x.OriginalRawBytes {
				return ErrHostFactoryHold
			}
		}
		if v.Type() == reflect.TypeOf(model.HostFactoryNativeSubjectPin{}) {
			x := v.Interface().(model.HostFactoryNativeSubjectPin)
			if err := originalHostStatVectorTx(ctx, tx, root, x.OriginalFstatCallVector, x.OriginalDescriptorNumber, x.OriginalStat); err != nil {
				return err
			}
			for _, id := range []string{x.OriginalBeforePollCallID, x.OriginalAfterPollCallID} {
				fact, err := originalHostSelectedFactTx(ctx, tx, root, x.OriginalAlivePollCallVector, id, x.OriginalHandleID, x.OriginalDescriptorNumber, "unix_poll")
				if err != nil || fact.OriginalNativeReturn.OriginalScalar == nil || *fact.OriginalNativeReturn.OriginalScalar != 0 || fact.OriginalNativeReturn.OriginalPollRevents == nil || *fact.OriginalNativeReturn.OriginalPollRevents != 0 {
					return ErrHostFactoryHold
				}
			}
		}
		if v.Type() == reflect.TypeOf(time.Time{}) {
			return nil
		}
		switch v.Kind() {
		case reflect.Struct:
			if inventory := v.FieldByName("OriginalHandleInventorySHA256"); inventory.IsValid() && inventory.Kind() == reflect.String {
				handle := v.FieldByName("OriginalHandleID")
				if !handle.IsValid() || handle.Kind() != reflect.String || validateOriginalHostDeclaredInventoryTx(ctx, tx, root, handle.String(), inventory.String(), v) != nil {
					return ErrHostFactoryHold
				}
			}
			for i := 0; i < v.NumField(); i++ {
				if err := walk(v.Field(i)); err != nil {
					return err
				}
			}
		case reflect.Array, reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if err := walk(v.Index(i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(reflect.ValueOf(body))
}

func (s CapacityStore) appendOriginalHostRecordTx(ctx context.Context, tx *sql.Tx, selector HostFactoryRecordSelector, body any, bodyRaw, envelopeRaw []byte) error {
	codec := originalHostSourceCodecTx(ctx, tx, selector.RootID)

	if selector.Stage != "" {
		if err := validateOriginalHostStageVectorsTx(ctx, tx, selector.RootID, body); err != nil {
			return err
		}
		nativePhase, err := validateOriginalHostNativeAggregateTx(ctx, tx, selector.RootID, selector.BindingSchema, selector.BindingSHA256, body, envelopeRaw)
		if err != nil {
			return err
		}
		subject, err := originalHostSubjectTx(ctx, tx, selector, body)
		if err != nil {
			return err
		}
		privatePostStart, err := s.captureOriginalHostPostStartOwnedTx(ctx, tx, selector, body, bodyRaw, envelopeRaw)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_stage_returns(root_id,subject_owner_id,stage,binding_schema,binding_sha256,signer_role,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire,native_phase_wire,original_poststart_ledger_wire) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, selector.RootID, subject, selector.Stage, selector.BindingSchema, selector.BindingSHA256, selector.Role, capacity.HostFactoryRawSHA256(bodyRaw), bodyRaw, capacity.HostFactoryRawSHA256(envelopeRaw), envelopeRaw, nativePhase, privatePostStart)
		return err
	}
	if selector.Kind == "native-record" || selector.Kind == "native-manifest" {
		return appendOriginalHostNativePublicationTx(ctx, tx, selector.RootID, body, bodyRaw, envelopeRaw)
	}
	x, err := originalHostIOIdentity(codec, selector.RootID, body, bodyRaw)
	if err != nil {
		return err
	}
	if x.bindingSchema != selector.BindingSchema || x.bindingSHA != selector.BindingSHA256 {
		return ErrHostFactoryHold
	}
	if x.kind == "failure-part" {
		failure, ok := body.(*model.HostFactoryFailureDiagnostic)
		if !ok || x.collection == nil || x.part == nil || *x.collection != selector.CollectionID || *x.part != selector.PartOrdinal || selector.HandleID != "" || !validCapacityExecutor(selector.OwnerID) {
			return ErrHostFactoryHold
		}
		x.owner, x.role = selector.OwnerID, selector.Role
		return appendOriginalHostFailureTx(ctx, tx, x, *failure, bodyRaw, envelopeRaw)
	}
	if x.owner != selector.OwnerID || x.role != selector.Role || x.handle == nil || *x.handle != selector.HandleID {
		return ErrHostFactoryHold
	}
	switch v := body.(type) {
	case *model.HostFactoryCallVectorChunk:
		return appendOriginalHostChunkTx(ctx, tx, x, *v, bodyRaw, envelopeRaw)
	case *model.HostFactoryCallVectorManifest:
		if err = appendOriginalHostIOBodyTx(ctx, tx, x, bodyRaw, envelopeRaw); err != nil {
			return err
		}
		return validateOriginalHostManifestTx(ctx, tx, x, *v)
	case *model.HostFactoryHandleCallInventory:
		if err = appendOriginalHostIOBodyTx(ctx, tx, x, bodyRaw, envelopeRaw); err != nil {
			return err
		}
		return validateOriginalHostInventoryTx(ctx, tx, x, *v)
	default:
		return ErrHostFactoryHold
	}
}

func (s CapacityStore) RecordOriginalHostPrivateStage(ctx context.Context, stage string, raw []byte) error {
	codec := originalHostInstalledSourceCodec(ctx, "")

	_, approval, installed := OriginalHostFactoryRealm()
	if !installed {
		return ErrHostFactoryHold
	}
	sel := HostFactoryRecordSelector{Family: "root", RootID: approval.ScopeRootID, Role: "host_core_issuer", BindingSchema: "original_host_factory_root_preparation_v4", Stage: stage}
	var envelope model.HostFactoryRootSignedEnvelope
	if codec.Decode(raw, &envelope) != nil {
		return ErrHostFactoryHold
	}
	sel.BindingSHA256 = envelope.BindingSHA256
	return s.AppendOriginalHostRecord(ctx, sel, raw)
}

// The server request context need not carry the worker's private deadlines.
// FIRST reads use only the actual registered Source cache; no public request
// field, row absence or fresh timeout supplies this original operation bound.
func originalOrdinaryGuardDeadline(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, selector HostFactoryRecordSelector, grant, pre string) (time.Time, error) {
	codec := originalHostSourceCodecRealm(ctx, realm)

	installedHostFactory.Lock()
	if installedHostFactory.realm != realm || realm == nil {
		installedHostFactory.Unlock()
		return time.Time{}, ErrHostFactoryHold
	}
	var owner *hostOriginalOrdinaryFactory
	for _, h := range installedHostFactory.ordinaryFactories {
		if h != nil && h.realm == realm && h.claim != nil && h.claim.rootID == selector.RootID && capacity.HostFactoryRawSHA256(h.bindingRaw) == selector.BindingSHA256 {
			if owner != nil {
				installedHostFactory.Unlock()
				return time.Time{}, ErrHostFactoryHold
			}
			owner = h
		}
	}
	installedHostFactory.Unlock()
	if owner == nil {
		return time.Time{}, ErrHostFactoryHold
	}
	owner.mu.Lock()
	ready := owner.issueCommitted && owner.issueCaptured && owner.issueReturnErr == nil && !owner.issueReturnedAt.IsZero() && owner.grant.GrantID == grant && owner.pre.PreregistrationID == pre
	deadline, grantDeadline, preDeadline := owner.binding.OriginalContextDeadline, owner.grant.ExpiresAt, owner.pre.OriginalDeadline
	claimRaw, preparationRaw := bytes.Clone(owner.claim.intent), bytes.Clone(owner.claim.preparation)
	owner.mu.Unlock()
	var intent model.CapacityIntent
	var root model.HostFactoryRootPreparation
	if !ready || json.Unmarshal(claimRaw, &intent) != nil || codec.Decode(preparationRaw, &root) != nil || intent.LeaseExpiresAt == nil || deadline.IsZero() || grantDeadline.IsZero() || preDeadline.IsZero() {
		return time.Time{}, ErrHostFactoryHold
	}
	for _, bound := range []time.Time{root.OriginalContextDeadline, *intent.LeaseExpiresAt, grantDeadline, preDeadline} {
		if bound.IsZero() {
			return time.Time{}, ErrHostFactoryHold
		}
		if bound.Before(deadline) {
			deadline = bound
		}
	}
	return deadline, nil
}

func (s CapacityStore) ReadOriginalOrdinaryHostGuard(ctx context.Context, selector HostFactoryRecordSelector, attempt, grant, pre, phase string) (_ []byte, runErr error) {
	codec := originalHostInstalledSourceCodec(ctx, "")

	realm, approval, installed := OriginalHostFactoryRealm()
	if ctx == nil || ctx.Err() != nil || !installed || realm == nil || s.DB == nil || selector.Role != "factory_ordinary_guard_reader" || selector.BindingSchema != "factory_ordinary_source_binding_v4" || selector.RootID != approval.ScopeRootID || !validCapacityExecutor(attempt) || !validCapacityExecutor(grant) || !validCapacityExecutor(pre) || (phase != "before_redeem" && phase != "after_redeem" && phase != "before_start") {
		return nil, ErrHostFactoryHold
	}
	retained, err := realm.OriginalOrdinaryGuardEnvelope(ctx, phase, attempt, grant, pre)
	if err != nil {
		return nil, ErrHostFactoryHold
	}
	if len(retained) > 0 {
		return bytes.Clone(retained), nil
	}
	if realm.VerifyLive(ctx) != nil {
		return nil, ErrHostFactoryHold
	}
	deadline, err := originalOrdinaryGuardDeadline(ctx, realm, selector, grant, pre)
	if err != nil {
		return nil, err
	}
	boundedCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	ctx = boundedCtx
	actualDeadline, bounded := boundedCtx.Deadline()
	if !bounded || !time.Now().Before(actualDeadline) {
		return nil, ErrHostFactoryHold
	}
	reservation, err := reserveOriginalOrdinaryRead(realm, selector, phase, attempt, grant, pre)
	if err != nil {
		return nil, ErrHostFactoryHold
	}
	if err = realm.ReserveOriginalOrdinaryGuardRead(ctx, phase, attempt, grant, pre); err != nil {
		return nil, err
	}
	// This owning return retains the exact SQL BYTEA buffers. No DTO supplied
	// by the HTTP caller, JSONB re-marshal or previous Claim return supplies it.
	calledAt := time.Now().UTC()
	var read originalOrdinaryGuardReturn
	var returnedAt time.Time
	defer func() {
		if recover() != nil {
			// The reserved read cannot acquire a later freshness attempt. A
			// panic before the helper returned leaves its return time unknown.
			runErr = ErrHostFactoryHold
		}
		if runErr != nil {
			runErr = errors.Join(runErr, realm.CaptureOriginalOrdinaryGuardFailure(ctx, phase, attempt, read.grantRaw, read.currentGrantRaw, read.preRaw, read.intentRaw, read.currentIntentRaw, calledAt, returnedAt, runErr))
		}
	}()
	read, err = s.readOriginalOrdinaryHostGuard(ctx, selector, attempt, grant, pre, phase)
	returnedAt = time.Now().UTC()
	if err != nil {
		return nil, err
	}
	if returnedAt.Before(calledAt) || !returnedAt.Before(actualDeadline) || !returnedAt.Before(deadline) || !returnedAt.Before(read.guard.OriginalContextDeadline) || !returnedAt.Before(read.guard.OriginalLeaseExpiresAt) || !returnedAt.Before(read.guard.OriginalGrantExpiresAt) {
		return nil, ErrHostFactoryHold
	}
	// The source/native supplier must join this actual owning read and cache
	// its original body before signing. The current EMPTY supplier refuses;
	// a body/key supplied by a caller never makes this available.
	guard, body, err := realm.CaptureOriginalOrdinaryGuardRead(ctx, phase, attempt, read.grantRaw, read.currentGrantRaw, read.preRaw, read.intentRaw, read.currentIntentRaw, calledAt, returnedAt)
	if err != nil || !guard.ObservedAt.Equal(returnedAt) {
		return nil, ErrHostFactoryHold
	}
	read.guard.ObservedAt = returnedAt
	expected, err := codec.Canonical(read.guard)
	if err != nil || !bytes.Equal(expected, body) || realm.VerifyOriginalOrdinaryGuard(ctx, guard, read.grantRaw, read.preRaw) != nil {
		return nil, ErrHostFactoryHold
	}
	raw, err := realm.SignOriginalAuthority(ctx, "ordinary-guard-read", body)
	if err != nil {
		return nil, ErrHostFactoryHold
	}
	if completeOriginalOrdinaryRead(realm, reservation) != nil {
		return nil, ErrHostFactoryHold
	}
	return raw, nil
}

type originalOrdinaryGuardReturn struct {
	guard                                                                                   model.FactoryOrdinaryGuardRead
	grantRaw, preRaw, bindingRaw, preparedRaw, intentRaw, currentGrantRaw, currentIntentRaw []byte
}

func (s CapacityStore) readOriginalOrdinaryHostGuard(ctx context.Context, selector HostFactoryRecordSelector, attempt, grant, pre, phase string) (out originalOrdinaryGuardReturn, err error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	codec := originalHostSourceCodecTx(ctx, tx, selector.RootID)
	var namespace string
	var scope model.CapacityPolicySpec
	if err = tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension FROM public.capacity_mutation_grants WHERE id=$1`, grant).Scan(&namespace, &scope.Environment, &scope.Domain, &scope.Dimension); err != nil {
		return out, err
	}
	if err = lockMutationScope(ctx, tx, namespace, scope); err != nil {
		return out, err
	}
	var currentGrantRaw, policyRaw []byte
	var current capacityMutationRecord
	err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, grant).Scan(&currentGrantRaw)
	out.currentGrantRaw = bytes.Clone(currentGrantRaw)
	if err != nil {
		return out, err
	}
	if json.Unmarshal(currentGrantRaw, &current) != nil {
		return out, ErrHostFactoryHold
	}
	if err = lockNativeMutationSlot(ctx, tx, current.Binding, current.Grant.Slot); err != nil {
		return out, err
	}
	var policyChecksum, workflowChecksum string
	var active bool
	if err = tx.QueryRowContext(ctx, `SELECT spec,checksum,active FROM public.manifests WHERE id=$1 AND kind='capacity_policy'`, current.PolicyID).Scan(&policyRaw, &policyChecksum, &active); err != nil {
		return out, err
	}
	var policy model.CapacityPolicySpec
	if !active || policyChecksum != current.PolicyChecksum || json.Unmarshal(policyRaw, &policy) != nil || policy.Environment != scope.Environment || policy.Domain != scope.Domain || policy.Dimension != scope.Dimension {
		return out, ErrHostFactoryHold
	}
	_, target, err := originalHostStableTarget(namespace, policy, current.Binding.Name, current.Grant.Slot)
	if err != nil {
		return out, err
	}
	if err = lockOriginalHostTarget(ctx, tx, target); err != nil {
		return out, err
	}
	var entry, root, owner, originalAttempt, state, handle, planSHA, preregistration string
	if err = tx.QueryRowContext(ctx, `SELECT t.entry_class,t.root_id::text,t.original_owner_id::text,t.factory_attempt_id::text,o.state,o.prepared_handle_id::text,o.prepared_plan_sha256,o.prepared_plan_wire,f.original_grant_wire,f.original_preregistration_wire,f.preregistration_id::text,s.original_wire FROM public.capacity_host_factory_stable_targets t JOIN public.capacity_host_factory_owners o ON o.owner_id=t.original_owner_id JOIN public.capacity_host_factory_scopes s ON s.owner_id=o.owner_id JOIN public.capacity_factory_original_grant_bindings f ON f.stable_target_sha256=t.stable_target_sha256 AND f.owner_id=o.owner_id AND f.prepared_handle_id=o.prepared_handle_id WHERE t.stable_target_sha256=$1 AND f.grant_id=$2 AND s.binding_schema='factory_ordinary_source_binding_v4' FOR SHARE OF t,o,s,f`, target, grant).Scan(&entry, &root, &owner, &originalAttempt, &state, &handle, &planSHA, &out.preparedRaw, &out.grantRaw, &out.preRaw, &preregistration, &out.bindingRaw); err != nil {
		return out, err
	}
	var binding model.FactoryOrdinarySourceBinding
	var prepared model.HostFactoryPreparedCreatePlan
	var original capacityMutationRecord
	var prereg model.CapacityGuestOriginalProvisioningPreregistration
	if entry != "ordinary_original_create" || root != selector.RootID || state != "registered" || originalAttempt == attempt || preregistration != pre || capacity.HostFactoryRawSHA256(out.bindingRaw) != selector.BindingSHA256 || codec.Decode(out.bindingRaw, &binding) != nil || codec.Decode(out.preparedRaw, &prepared) != nil || capacity.HostFactoryRawSHA256(out.preparedRaw) != planSHA || json.Unmarshal(out.grantRaw, &original) != nil || json.Unmarshal(out.preRaw, &prereg) != nil || binding.CreatorOwnerID != owner || binding.FactoryAttemptID != originalAttempt || binding.StableOriginalTargetSHA256 != target || prepared.OriginalCreateCommandHandleID != handle || prepared.BindingSHA256 != selector.BindingSHA256 || original.Grant.GrantID != grant || prereg.PreregistrationID != pre || prereg.OriginalCreateGrantID != grant || original.ExecutorID != prereg.ExecutorID || original.Generation != prereg.Generation || original.FencingToken != prereg.Fence || original.LeaseOwner != prereg.LeaseOwner {
		return out, ErrHostFactoryHold
	}
	err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR SHARE`, grant).Scan(&currentGrantRaw)
	out.currentGrantRaw = bytes.Clone(currentGrantRaw)
	if err != nil {
		return out, err
	}
	if json.Unmarshal(currentGrantRaw, &current) != nil || current.PolicyID != original.PolicyID || current.PolicyChecksum != original.PolicyChecksum || current.WorkflowID != original.WorkflowID || current.Generation != original.Generation || current.FencingToken != original.FencingToken || current.ExecutorID != original.ExecutorID || current.LeaseOwner != original.LeaseOwner || current.Grant.RequestSHA256 != original.Grant.RequestSHA256 || !current.Grant.ExpiresAt.Equal(original.Grant.ExpiresAt) {
		return out, ErrHostFactoryHold
	}
	if (phase == "before_redeem" && (current.Grant.State != "issued" || current.AttemptID != "")) || (phase != "before_redeem" && (current.Grant.State != "redeemed" || current.AttemptID != attempt)) {
		return out, ErrHostFactoryHold
	}
	if err = checkMutationIntegration(ctx, tx, current.Binding); err != nil {
		return out, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='workflow'`, current.WorkflowID).Scan(&workflowChecksum, &active); err != nil {
		return out, err
	}
	if !active {
		return out, ErrHostFactoryHold
	}
	if err = tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR UPDATE`, namespace, policy.Environment, policy.Domain, policy.Dimension).Scan(&out.currentIntentRaw); err != nil {
		return out, err
	}
	var intent model.CapacityIntent
	if json.Unmarshal(out.currentIntentRaw, &intent) != nil {
		return out, ErrHostFactoryHold
	}
	if intent.PolicyID != current.PolicyID || intent.PolicyChecksum != current.PolicyChecksum || intent.Generation != current.Generation || intent.FencingToken != current.FencingToken || intent.LeaseOwner != current.LeaseOwner || intent.LeaseExecutorID != current.ExecutorID || intent.LeaseExpiresAt == nil || intent.RecoveryOnly {
		return out, ErrHostFactoryHold
	}
	if err = tx.QueryRowContext(ctx, `SELECT original_intent_wire FROM public.capacity_host_factory_leases WHERE root_id=$1 AND original_invocation_id=$2 AND generation=$3 AND fence=$4`, root, current.ExecutorID, current.Generation, current.FencingToken).Scan(&out.intentRaw); err != nil {
		return out, err
	}
	var originalIntent model.CapacityIntent
	if json.Unmarshal(out.intentRaw, &originalIntent) != nil || originalIntent.LeaseExpiresAt == nil || !originalIntent.LeaseExpiresAt.Equal(*intent.LeaseExpiresAt) || originalIntent.LeaseExecutorID != intent.LeaseExecutorID || originalIntent.LeaseOwner != intent.LeaseOwner {
		return out, ErrHostFactoryHold
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	now = now.UTC()
	if !now.Before(binding.OriginalContextDeadline) || !now.Before(*intent.LeaseExpiresAt) || !now.Before(original.Grant.ExpiresAt) {
		return out, ErrHostFactoryHold
	}
	out.guard = model.FactoryOrdinaryGuardRead{Schema: "factory_ordinary_guard_read_v4", Purpose: "factory_ordinary_guard_read_v4", OrdinarySourceBindingSHA256: selector.BindingSHA256, PreparedCreatePlanSHA256: planSHA, GrantID: grant, PreregistrationID: pre, OriginalGrantRawSHA256: capacity.HostFactoryRawSHA256(out.grantRaw), OriginalPreregistrationRawSHA256: capacity.HostFactoryRawSHA256(out.preRaw), OriginalAttemptID: attempt, OriginalRedeemRequestSHA256: original.Grant.RequestSHA256, GrantState: current.Grant.State, Generation: current.Generation, Fence: current.FencingToken, LeaseOwnerSHA256: capacity.HostFactoryRawSHA256([]byte(current.LeaseOwner)), ExecutorID: current.ExecutorID, OriginalGrantExpiresAt: original.Grant.ExpiresAt, OriginalLeaseExpiresAt: *intent.LeaseExpiresAt, OriginalContextDeadline: binding.OriginalContextDeadline, PolicyChecksum: policyChecksum, WorkflowChecksum: workflowChecksum, CoreActualSourceCommit: capacity.CurrentGuestCoreSource(), ObservedAt: now}
	err = tx.Commit()
	return out, err
}

func originalHostStageBody(codec hostOriginalSourceCodec, expectedStage string, raw []byte, target any) ([]byte, error) {
	body, role, schema, _, err := codec.Envelope(raw)
	if err != nil || originalHostSourceStageTransport(expectedStage, role, schema) != nil || reflect.TypeOf(target) != reflect.TypeOf(originalHostStageTarget(expectedStage)) || codec.Decode(body, target) != nil {
		return nil, ErrHostFactoryHold
	}
	return body, nil
}

func (s CapacityStore) ReserveOriginalHostAwaitingOwner(ctx context.Context, policy, workflow model.Manifest, step model.WorkflowStepSpec, p model.CapacityPolicySpec, b model.CapacityMutationBinding, slot int, entry string) error {
	codec := originalHostInstalledSourceCodec(ctx, "")

	h := s.hostOriginalClaim
	if ctx == nil || ctx.Err() != nil || h == nil || !h.committed || len(h.intent) == 0 || h.invocation != s.ExecutorID || workflow.ID != s.WorkflowID || (entry != "sealed_a0" && entry != "sealed_a1" && entry != "ordinary_original_create") {
		return ErrHostFactoryHold
	}
	var original model.CapacityIntent
	var root model.HostFactoryRootPreparation
	deadline, bounded := ctx.Deadline()
	if !bounded || json.Unmarshal(h.intent, &original) != nil || codec.Decode(h.preparation, &root) != nil || original.LeaseExpiresAt == nil || original.LeaseExecutorID != s.ExecutorID || root.FactoryEntryClass != entry || deadline.After(root.OriginalContextDeadline) || deadline.After(*original.LeaseExpiresAt) {
		return ErrHostFactoryHold
	}
	targetRaw, target, err := originalHostStableTarget(policy.Metadata.Namespace, p, b.Name, slot)
	if err != nil {
		return err
	}
	proposal := hostOriginalAwaitingRecord{RootID: h.rootID, NativeFactoryRootID: root.FactoryRootID, StableTargetSHA256: target, StableTargetWireBase64: base64.StdEncoding.EncodeToString(targetRaw), FactoryAttemptID: h.attemptID, CreatorOwnerID: h.creatorOwnerID, FactoryClass: hostFactoryClass, EntryClass: entry, OriginalInvocationID: h.invocation, Namespace: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, TargetIdentity: p.TargetIdentity, MutationBindingName: b.Name, Slot: slot, PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: workflow.ID.String(), WorkflowChecksum: workflow.Checksum, OriginalStepID: step.ID, OriginalStepTimeoutSeconds: step.TimeoutSeconds, Generation: original.Generation, Fence: original.FencingToken, LeaseOwnerSHA256: capacity.HostFactoryRawSHA256([]byte(original.LeaseOwner)), ExecutorID: s.ExecutorID, OriginalLeaseExpiresAt: *original.LeaseExpiresAt, OriginalContextDeadline: deadline.UTC(), OriginalClaimIntentRawSHA256: capacity.HostFactoryRawSHA256(h.intent), SourceApprovalSHA256: capacity.HostFactoryRawSHA256(h.approval), CoreActualSourceCommit: capacity.CurrentGuestCoreSource(), Binding: b}
	raw, err := json.Marshal(proposal)
	if err != nil || len(raw) == 0 || len(raw) > 65536 {
		return ErrHostFactoryHold
	}
	// Reserve in Source memory BEFORE the transaction. Even rollback/unknown
	// Commit with no SQL row cannot restore this invocation to FIRST.
	h.mu.Lock()
	if h.awaiting != nil {
		h.mu.Unlock()
		return ErrHostFactoryHold
	}
	returned := &hostOriginalAwaitingReturn{raw: bytes.Clone(raw), calledAt: time.Now().UTC()}
	h.awaiting = returned
	h.mu.Unlock()
	err = s.mutationTransaction(ctx, policy, false, original.Generation, original.FencingToken, original.LeaseOwner, func(tx *sql.Tx, currentPolicy model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		resolved, resolveErr := capacity.VMObservationBinding(currentPolicy, b.Name)
		if resolveErr != nil || !reflect.DeepEqual(resolved, b) || !reflect.DeepEqual(currentPolicy, p) || current.LeaseExecutorID != s.ExecutorID || current.LeaseExpiresAt == nil || !current.LeaseExpiresAt.Equal(*original.LeaseExpiresAt) || !deadline.After(now) {
			return ErrHostFactoryHold
		}
		if err := lockNativeMutationSlot(ctx, tx, b, slot); err != nil {
			return err
		}
		if err := lockOriginalHostTarget(ctx, tx, target); err != nil {
			return err
		}
		var currentChecksum string
		var active bool
		if err := tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='workflow' FOR SHARE`, workflow.ID).Scan(&currentChecksum, &active); err != nil {
			return err
		}
		if !active || currentChecksum != workflow.Checksum || h.realm.CheckOriginalAwaitingOwnerTransaction(ctx, h.invocation, raw) != nil {
			return ErrHostFactoryHold
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_stable_targets(stable_target_sha256,target_wire,root_id,namespace,environment,domain,dimension,target_identity,mutation_binding_name,slot,factory_class,factory_attempt_id,original_owner_id,entry_class,integration_instance_id,integration_type_id,integration_checksum,integration_type_checksum,scope_checksum,profile_name) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, target, targetRaw, h.rootID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, p.TargetIdentity, b.Name, slot, hostFactoryClass, h.attemptID, h.creatorOwnerID, entry, b.IntegrationInstanceID, b.IntegrationTypeID, b.IntegrationChecksum, b.IntegrationTypeChecksum, b.ScopeChecksum, b.ProfileName)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_owners(owner_id,root_id,attempt_id,stable_target_sha256,state,awaiting_sha256,awaiting_wire) VALUES($1,$2,$3,$4,'awaiting_native_preparation',$5,$6)`, h.creatorOwnerID, h.rootID, h.attemptID, target, capacity.HostFactoryRawSHA256(raw), raw)
		return err
	})
	actualReturn := time.Now().UTC()
	h.mu.Lock()
	returned.returnedAt, returned.originalErr, returned.committed = actualReturn, err, err == nil
	h.mu.Unlock()
	if err != nil {
		return err
	}
	if ctx.Err() != nil || !actualReturn.Before(deadline) {
		h.mu.Lock()
		returned.originalErr = ErrHostFactoryHold
		h.mu.Unlock()
		return ErrHostFactoryHold
	}
	if err = h.realm.CaptureOriginalAwaitingOwnerReturn(ctx, h.invocation, raw, returned.calledAt, actualReturn); err != nil {
		h.mu.Lock()
		returned.originalErr = err
		h.mu.Unlock()
		return err
	}
	return nil
}

func (s CapacityStore) RegisterOriginalHostPreparation(ctx context.Context, policy model.Manifest, p model.CapacityPolicySpec, scope model.HostFactoryPreAuthorityScope, scopeRaw []byte, stages map[string][]byte) (out CapacityStore, runErr error) {
	out = s
	realm, approval, installed := OriginalHostFactoryRealm()
	if !installed || realm == nil {
		return s, ErrHostFactoryHold
	}
	originalReturn, err := s.beginOriginalHostPreparation(ctx, realm, scope.FactoryEntryClass, scopeRaw, stages)
	if err != nil {
		return s, err
	}
	defer func() {
		if cause := recover(); cause != nil {
			s.hostOriginalClaim.mu.Lock()
			originalReturn.originalErr = ErrHostFactoryHold
			s.hostOriginalClaim.mu.Unlock()
			panic(cause)
		}
		runErr = s.finishOriginalHostPreparation(originalReturn, runErr)
		if runErr != nil {
			out = s
			out.hostOriginalFactory = nil
			out.hostOriginalOrdinary = nil
		}
	}()
	scopeRaw, stages = originalReturn.bindingRaw, originalReturn.stages
	codec := originalHostInstalledSourceCodec(ctx, "")
	canonical, err := codec.Canonical(scope)
	if !installed || realm == nil || err != nil || !bytes.Equal(canonical, scopeRaw) || scope.ScopeRootID != approval.ScopeRootID || scope.PolicyID != policy.ID.String() || scope.PolicyChecksum != policy.Checksum || scope.WorkflowID != s.WorkflowID.String() || scope.ExecutorID != s.ExecutorID || scope.MutationBindingName != approval.AllowedMutationBindingName || scope.Slot != approval.AllowedSlot || scope.CoreActualSourceCommit != capacity.CurrentGuestCoreSource() || capacity.ValidateHostFactorySourceBinding(approval, scope) != nil {
		return s, ErrHostFactoryHold
	}
	var prepared model.HostFactoryPreparedCreatePlan
	var registration model.HostFactoryAliveRegistration
	preparedRaw, err := originalHostStageBody(codec, "prepared-create-plan", stages["prepared-create-plan"], &prepared)
	if err != nil {
		return s, ErrHostFactoryHold
	}
	registrationRaw, err := originalHostStageBody(codec, "alive-registration", stages["alive-registration"], &registration)
	if err != nil || registration.PreAuthorityScopeSHA256 != capacity.HostFactoryRawSHA256(scopeRaw) || registration.PreparedCreatePlanSHA256 != capacity.HostFactoryRawSHA256(preparedRaw) || prepared.BindingSHA256 != registration.PreAuthorityScopeSHA256 || prepared.StableOriginalTargetSHA256 != scope.StableOriginalTargetSHA256 {
		return s, ErrHostFactoryHold
	}
	var retainedScope model.HostFactoryPreAuthorityScope
	retainedScopeRaw, err := originalHostStageBody(codec, "preauthority-scope", stages["preauthority-scope"], &retainedScope)
	if err != nil || !bytes.Equal(retainedScopeRaw, scopeRaw) {
		return s, ErrHostFactoryHold
	}
	for name, raw := range stages {
		if realm.VerifyOriginalStage(ctx, name, raw) != nil {
			return s, ErrHostFactoryHold
		}
	}
	records, err := prepareOriginalHostRecords(ctx, scope.ScopeRootID, capacity.HostFactoryRawSHA256(scopeRaw), stages)
	if err != nil {
		return s, ErrHostFactoryHold
	}
	b, err := capacity.VMObservationBinding(p, scope.MutationBindingName)
	if err != nil {
		return s, err
	}
	targetRaw, target, err := originalHostStableTarget(policy.Metadata.Namespace, p, b.Name, scope.Slot)
	if err != nil || target != scope.StableOriginalTargetSHA256 {
		return s, ErrHostFactoryHold
	}
	if s.hostOriginalClaim == nil || !s.hostOriginalClaim.committed {
		return s, ErrHostFactoryHold
	}
	awaiting := s.hostOriginalClaim.awaiting
	if awaiting == nil || !awaiting.committed || awaiting.originalErr != nil || len(awaiting.raw) == 0 {
		return s, ErrHostFactoryHold
	}
	var rootPreparation model.HostFactoryRootPreparation
	if codec.Decode(s.hostOriginalClaim.preparation, &rootPreparation) != nil || scope.FactoryRealmID != rootPreparation.FactoryRootID || scope.FactoryAttemptID != s.hostOriginalClaim.attemptID || scope.CreatorOwnerID != s.hostOriginalClaim.creatorOwnerID || scope.FactoryEntryClass != rootPreparation.FactoryEntryClass || scope.Namespace != policy.Metadata.Namespace {
		return s, ErrHostFactoryHold
	}
	leaseRaw := bytes.Clone(s.hostOriginalClaim.intent)
	var original model.CapacityIntent
	if json.Unmarshal(leaseRaw, &original) != nil || capacity.HostFactoryRawSHA256([]byte(original.LeaseOwner)) != scope.LeaseOwnerSHA256 {
		return s, ErrHostFactoryHold
	}
	err = s.mutationTransactionWithCommitReturn(ctx, policy, false, scope.Generation, scope.Fence, original.LeaseOwner, func(tx *sql.Tx, _ model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if current.LeaseExecutorID != s.ExecutorID || current.LeaseExpiresAt == nil || !current.LeaseExpiresAt.Equal(scope.OriginalLeaseExpiresAt) || !scope.OriginalContextDeadline.After(now) {
			return ErrHostFactoryHold
		}
		if err := lockNativeMutationSlot(ctx, tx, b, scope.Slot); err != nil {
			return err
		}
		if err := lockOriginalHostTarget(ctx, tx, target); err != nil {
			return err
		}
		var actualRaw, actualTarget []byte
		var actualSHA, entry string
		err := tx.QueryRowContext(ctx, `SELECT o.awaiting_wire,o.awaiting_sha256,t.target_wire,t.entry_class FROM public.capacity_host_factory_owners o JOIN public.capacity_host_factory_stable_targets t ON t.stable_target_sha256=o.stable_target_sha256 WHERE o.owner_id=$1 AND o.root_id=$2 AND o.attempt_id=$3 AND o.stable_target_sha256=$4 AND o.state='awaiting_native_preparation' FOR UPDATE OF o,t`, scope.CreatorOwnerID, scope.ScopeRootID, scope.FactoryAttemptID, target).Scan(&actualRaw, &actualSHA, &actualTarget, &entry)
		if err != nil || !bytes.Equal(actualRaw, awaiting.raw) || actualSHA != capacity.HostFactoryRawSHA256(awaiting.raw) || !bytes.Equal(actualTarget, targetRaw) || entry != scope.FactoryEntryClass {
			return ErrHostFactoryHold
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_scopes(scope_sha256,root_id,attempt_id,owner_id,stable_target_sha256,binding_schema,original_wire) VALUES($1,$2,$3,$4,$5,'original_host_factory_pre_authority_scope_v4',$6)`, registration.PreAuthorityScopeSHA256, scope.ScopeRootID, scope.FactoryAttemptID, scope.CreatorOwnerID, target, scopeRaw)
		if err != nil {
			return err
		}
		if err = s.appendOriginalHostRecordsTx(ctx, tx, records); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE public.capacity_host_factory_owners SET state='registered',prepared_handle_id=$2,worker_primitive_sha256=$3,prepared_plan_sha256=$4,prepared_plan_wire=$5,native_registration_wire=$6 WHERE owner_id=$1 AND state='awaiting_native_preparation'`, scope.CreatorOwnerID, prepared.OriginalCreateCommandHandleID, prepared.OwnerPrimitiveRawSHA256, capacity.HostFactoryRawSHA256(preparedRaw), preparedRaw, registrationRaw)
		if err != nil {
			return err
		}
		filled, err := result.RowsAffected()
		if err != nil || filled != 1 {
			return ErrHostFactoryHold
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_registrations(scope_sha256,owner_id,prepared_handle_id,registration_sha256,original_wire) VALUES($1,$2,$3,$4,$5)`, registration.PreAuthorityScopeSHA256, scope.CreatorOwnerID, prepared.OriginalCreateCommandHandleID, capacity.HostFactoryRawSHA256(registrationRaw), registrationRaw)
		return err
	}, s.captureOriginalHostPreparationCommit(originalReturn))
	transactionReturnedAt := time.Now().UTC() // immediately AFTER helper GoReturn, BEFORE mutex waiting
	s.retainOriginalHostPreparationHelperReturn(originalReturn, transactionReturnedAt, err, prepared.OriginalCreateCommandHandleID, preparedRaw, registrationRaw)
	if err != nil {
		return s, err
	}
	s.hostOriginalFactory = &hostOriginalFactoryScope{realm: realm, scope: scope, scopeRaw: bytes.Clone(scopeRaw), registration: registration, prepared: prepared, policy: policy, policySpec: p, binding: b, leaseOwner: original.LeaseOwner}
	return s, nil
}

func (s CapacityStore) attachOriginalHostGrantTx(ctx context.Context, tx *sql.Tx, record capacityMutationRecord, grantRaw []byte, pre model.CapacityGuestOriginalProvisioningPreregistration, preRaw []byte) error {
	codec := originalHostInstalledSourceCodec(ctx, "")

	h := s.hostOriginalFactory
	if h == nil {
		return nil
	}
	if h.scope.FactoryEntryClass != "sealed_a1" || h.issueCommitted || len(h.grantRaw) != 0 || record.Grant.RequestSHA256 != h.scope.PlannedMutationRequestSHA256 || record.ExecutorID != h.scope.ExecutorID || pre.OriginalCreateGrantID != record.Grant.GrantID || pre.Generation != h.scope.Generation || pre.Fence != h.scope.Fence || pre.ExecutorID != h.scope.ExecutorID || pre.OriginalDeadline.After(h.scope.OriginalContextDeadline) || record.Grant.ExpiresAt.After(pre.OriginalDeadline) {
		return ErrHostFactoryHold
	}
	if len(grantRaw) == 0 || h.realm.CaptureOriginalGrantBinding(ctx, record.Grant, pre, grantRaw, preRaw) != nil {
		return ErrHostFactoryHold
	}
	bodyRaw, err := h.realm.OriginalAuthorityBody(ctx, "issued-attachment")
	var attachment model.HostFactoryIssuedAttachment
	if err != nil || codec.Decode(bodyRaw, &attachment) != nil || attachment.OriginalCreateGrantID != record.Grant.GrantID || attachment.PreregistrationID != pre.PreregistrationID || attachment.PreAuthorityScopeSHA256 != capacity.HostFactoryRawSHA256(h.scopeRaw) || attachment.AliveRegistrationSHA256 != capacity.GuestRetirementSHA(h.registration) || attachment.OriginalGrantRecordSHA256 != capacity.HostFactoryRawSHA256(grantRaw) || attachment.OriginalPreregistrationWireSHA256 != capacity.HostFactoryRawSHA256(preRaw) || !attachment.OriginalCreateGrantExpiresAt.Equal(record.Grant.ExpiresAt) || !attachment.OriginalProvisioningDeadline.Equal(pre.OriginalDeadline) {
		return ErrHostFactoryHold
	}
	envelope, err := h.realm.SignOriginalAuthority(ctx, "issued-attachment", bodyRaw)
	if err != nil {
		return ErrHostFactoryHold
	}
	attachmentRecords, err := prepareOriginalHostRecords(ctx, h.scope.ScopeRootID, capacity.HostFactoryRawSHA256(h.scopeRaw), map[string][]byte{"issued-attachment": envelope})
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_factory_original_grant_bindings(grant_id,preregistration_id,root_id,attempt_id,owner_id,prepared_handle_id,stable_target_sha256,entry_class,original_grant_sha256,original_grant_wire,original_preregistration_sha256,original_preregistration_wire,original_request_sha256,original_grant_expires_at,original_provisioning_deadline) VALUES($1,$2,$3,$4,$5,$6,$7,'sealed_a1',$8,$9,$10,$11,$12,$13,$14)`, record.Grant.GrantID, pre.PreregistrationID, h.scope.ScopeRootID, h.scope.FactoryAttemptID, h.scope.CreatorOwnerID, h.prepared.OriginalCreateCommandHandleID, h.scope.StableOriginalTargetSHA256, capacity.HostFactoryRawSHA256(grantRaw), grantRaw, capacity.HostFactoryRawSHA256(preRaw), preRaw, record.Grant.RequestSHA256, record.Grant.ExpiresAt, pre.OriginalDeadline)
	if err != nil {
		return err
	}
	if err = s.appendOriginalHostRecordsTx(ctx, tx, attachmentRecords); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_issued_attachments(grant_id,preregistration_id,scope_sha256,attachment_sha256,original_wire) VALUES($1,$2,$3,$4,$5)`, record.Grant.GrantID, pre.PreregistrationID, capacity.HostFactoryRawSHA256(h.scopeRaw), capacity.HostFactoryRawSHA256(bodyRaw), bodyRaw)
	if err == nil {
		h.grantRaw, h.preRaw, h.grant, h.pre, h.attachmentRaw = bytes.Clone(grantRaw), bytes.Clone(preRaw), record.Grant, pre, bytes.Clone(bodyRaw)
	}
	return err
}

func originalOrdinaryStageBody(codec hostOriginalSourceCodec, raw []byte, target any) ([]byte, error) {
	var envelope model.HostFactoryRootSignedEnvelope
	if codec.Decode(raw, &envelope) != nil || envelope.BindingSchema != "factory_ordinary_source_binding_v4" {
		return nil, ErrHostFactoryHold
	}
	body, err := base64.StdEncoding.Strict().DecodeString(envelope.BodyBase64)
	if err != nil || base64.StdEncoding.EncodeToString(body) != envelope.BodyBase64 || codec.Decode(body, target) != nil {
		return nil, ErrHostFactoryHold
	}
	return body, nil
}

func (s CapacityStore) RegisterOriginalOrdinaryPreparation(ctx context.Context, policy, workflow model.Manifest, p model.CapacityPolicySpec, b model.CapacityMutationBinding, binding model.FactoryOrdinarySourceBinding, bindingRaw []byte, stages map[string][]byte) (out CapacityStore, runErr error) {
	out = s
	realm, approval, installed := OriginalHostFactoryRealm()
	h := s.hostOriginalClaim
	if !installed || realm == nil {
		return s, ErrHostFactoryHold
	}
	originalReturn, err := s.beginOriginalHostPreparation(ctx, realm, "ordinary_original_create", bindingRaw, stages)
	if err != nil {
		return s, err
	}
	defer func() {
		if cause := recover(); cause != nil {
			h.mu.Lock()
			originalReturn.originalErr = ErrHostFactoryHold
			h.mu.Unlock()
			panic(cause)
		}
		runErr = s.finishOriginalHostPreparation(originalReturn, runErr)
		if runErr != nil {
			out = s
			out.hostOriginalFactory = nil
			out.hostOriginalOrdinary = nil
		}
	}()
	bindingRaw, stages = originalReturn.bindingRaw, originalReturn.stages
	codec := originalHostInstalledSourceCodec(ctx, "")
	canonical, err := codec.Canonical(binding)
	if !installed || realm == nil || h == nil || h.realm != realm || !h.committed || h.awaiting == nil || !h.awaiting.committed || h.awaiting.originalErr != nil || err != nil || !bytes.Equal(canonical, bindingRaw) || s.hostOriginalFactory != nil || s.hostOriginalOrdinary != nil || p.GuestRetirementBinding == nil {
		return s, ErrHostFactoryHold
	}
	var root model.HostFactoryRootPreparation
	var awaiting hostOriginalAwaitingRecord
	var original model.CapacityIntent
	if codec.Decode(h.preparation, &root) != nil || json.Unmarshal(h.awaiting.raw, &awaiting) != nil || json.Unmarshal(h.intent, &original) != nil || original.LeaseExpiresAt == nil || original.LeaseExecutorID != s.ExecutorID || root.FactoryEntryClass != "ordinary_original_create" || awaiting.EntryClass != root.FactoryEntryClass || !reflect.DeepEqual(awaiting.Binding, b) {
		return s, ErrHostFactoryHold
	}
	_, leaseRaw, err := realm.OriginalLeaseProvenance(ctx, s.ExecutorID)
	targetRaw, target, targetErr := originalHostStableTarget(policy.Metadata.Namespace, p, b.Name, binding.Slot)
	if err != nil || targetErr != nil || binding.FactoryRootID != root.FactoryRootID || binding.FactoryAttemptID != h.attemptID || binding.CreatorOwnerID != h.creatorOwnerID || binding.SourceApprovalSHA256 != capacity.HostFactoryRawSHA256(h.approval) || binding.OriginalLeaseProvenanceSHA256 != capacity.HostFactoryRawSHA256(leaseRaw) || binding.StableOriginalTargetSHA256 != target || binding.PolicyID != policy.ID.String() || binding.WorkflowID != workflow.ID.String() || workflow.ID != s.WorkflowID || binding.OriginalStepID != approval.AllowedOriginalStepID || binding.MutationBindingName != b.Name || b.Name != approval.AllowedMutationBindingName || binding.Slot != approval.AllowedSlot || binding.ProfileManifestSHA256 != p.GuestRetirementBinding.ProfileManifestSHA256 || policy.ID.String() != approval.AllowedPolicyID || workflow.ID.String() != approval.AllowedWorkflowID || policy.Metadata.Namespace != approval.AllowedNamespace || !binding.OriginalContextDeadline.Equal(awaiting.OriginalContextDeadline) || binding.OriginalContextDeadline.After(*original.LeaseExpiresAt) || binding.OriginalContextDeadline.After(root.OriginalContextDeadline) {
		return s, ErrHostFactoryHold
	}
	var basal model.HostFactoryBasalOwnerObservation
	var bootstrap model.HostFactoryBootstrapReturn
	var prepared model.HostFactoryPreparedCreatePlan
	var registrar model.HostFactoryNativeLeaf
	basalRaw, e1 := originalOrdinaryStageBody(codec, stages["ordinary-basal-owner"], &basal)
	bootstrapRaw, e2 := originalOrdinaryStageBody(codec, stages["ordinary-bootstrap-return"], &bootstrap)
	preparedRaw, e3 := originalOrdinaryStageBody(codec, stages["ordinary-prepared-create-plan"], &prepared)
	registrationRaw, e4 := originalOrdinaryStageBody(codec, stages["ordinary-native-leaf-worker"], &registrar)
	bindingSHA := capacity.HostFactoryRawSHA256(bindingRaw)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || basal.FactoryRootID != root.FactoryRootID || basal.OriginalOwnerID != h.creatorOwnerID || basal.Role != "factory_ordinary_worker" || bootstrap.OwnerPrimitiveRawSHA256 != capacity.HostFactoryRawSHA256(basalRaw) || prepared.OwnerPrimitiveRawSHA256 != capacity.HostFactoryRawSHA256(basalRaw) || prepared.BindingSchema != binding.Schema || prepared.BindingSHA256 != bindingSHA || prepared.StableOriginalTargetSHA256 != target || registrar.BindingSchema != binding.Schema || registrar.BindingSHA256 != bindingSHA || registrar.SubjectPrimitiveRawSHA256 != prepared.OwnerPrimitiveRawSHA256 || registrar.BootstrapReturnSHA256 != capacity.HostFactoryRawSHA256(bootstrapRaw) || registrar.Role != "factory_ordinary_worker" || registrar.ObserverRole != "host_registrar" {
		return s, ErrHostFactoryHold
	}
	records, err := prepareOriginalHostRecords(ctx, h.rootID, "", stages)
	if err != nil {
		return s, err
	}
	for _, r := range records {
		if r.selector.Family != "root" || r.selector.BindingSchema != binding.Schema || r.selector.BindingSHA256 != bindingSHA {
			return s, ErrHostFactoryHold
		}
	}
	err = s.mutationTransactionWithCommitReturn(ctx, policy, false, original.Generation, original.FencingToken, original.LeaseOwner, func(tx *sql.Tx, currentPolicy model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		resolved, err := capacity.VMObservationBinding(currentPolicy, b.Name)
		if err != nil || !reflect.DeepEqual(currentPolicy, p) || !reflect.DeepEqual(resolved, b) || current.LeaseExecutorID != s.ExecutorID || current.LeaseExpiresAt == nil || !current.LeaseExpiresAt.Equal(*original.LeaseExpiresAt) || !now.Before(binding.OriginalContextDeadline) {
			return ErrHostFactoryHold
		}
		if err = lockNativeMutationSlot(ctx, tx, b, binding.Slot); err != nil {
			return err
		}
		if err = lockOriginalHostTarget(ctx, tx, target); err != nil {
			return err
		}
		var currentWorkflow string
		var active bool
		if err = tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='workflow' FOR SHARE`, workflow.ID).Scan(&currentWorkflow, &active); err != nil {
			return err
		}
		if !active || currentWorkflow != workflow.Checksum {
			return ErrHostFactoryHold
		}
		var actualRaw, actualTarget []byte
		var actualSHA, entry string
		if err = tx.QueryRowContext(ctx, `SELECT o.awaiting_wire,o.awaiting_sha256,t.target_wire,t.entry_class FROM public.capacity_host_factory_owners o JOIN public.capacity_host_factory_stable_targets t ON t.stable_target_sha256=o.stable_target_sha256 WHERE o.owner_id=$1 AND o.root_id=$2 AND o.attempt_id=$3 AND o.stable_target_sha256=$4 AND o.state='awaiting_native_preparation' FOR UPDATE OF o,t`, h.creatorOwnerID, h.rootID, h.attemptID, target).Scan(&actualRaw, &actualSHA, &actualTarget, &entry); err != nil {
			return err
		}
		if !bytes.Equal(actualRaw, h.awaiting.raw) || actualSHA != capacity.HostFactoryRawSHA256(h.awaiting.raw) || !bytes.Equal(actualTarget, targetRaw) || entry != "ordinary_original_create" {
			return ErrHostFactoryHold
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_scopes(scope_sha256,root_id,attempt_id,owner_id,stable_target_sha256,binding_schema,original_wire) VALUES($1,$2,$3,$4,$5,'factory_ordinary_source_binding_v4',$6)`, bindingSHA, h.rootID, h.attemptID, h.creatorOwnerID, target, bindingRaw); err != nil {
			return err
		}
		if err = s.appendOriginalHostRecordsTx(ctx, tx, records); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE public.capacity_host_factory_owners SET state='registered',prepared_handle_id=$2,worker_primitive_sha256=$3,prepared_plan_sha256=$4,prepared_plan_wire=$5,native_registration_wire=$6 WHERE owner_id=$1 AND state='awaiting_native_preparation'`, h.creatorOwnerID, prepared.OriginalCreateCommandHandleID, prepared.OwnerPrimitiveRawSHA256, capacity.HostFactoryRawSHA256(preparedRaw), preparedRaw, registrationRaw)
		if err != nil {
			return err
		}
		filled, err := result.RowsAffected()
		if err != nil || filled != 1 {
			return ErrHostFactoryHold
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_registrations(scope_sha256,owner_id,prepared_handle_id,registration_sha256,original_wire) VALUES($1,$2,$3,$4,$5)`, bindingSHA, h.creatorOwnerID, prepared.OriginalCreateCommandHandleID, capacity.HostFactoryRawSHA256(registrationRaw), registrationRaw)
		return err
	}, s.captureOriginalHostPreparationCommit(originalReturn))
	transactionReturnedAt := time.Now().UTC() // immediately AFTER helper GoReturn, BEFORE mutex waiting
	s.retainOriginalHostPreparationHelperReturn(originalReturn, transactionReturnedAt, err, prepared.OriginalCreateCommandHandleID, preparedRaw, registrationRaw)
	if err != nil {
		return s, err
	}
	ordinary := &hostOriginalOrdinaryFactory{realm: realm, claim: h, binding: binding, bindingRaw: bytes.Clone(bindingRaw), prepared: prepared, preparedRaw: bytes.Clone(preparedRaw), registrationRaw: bytes.Clone(registrationRaw), policy: policy, workflow: workflow, policySpec: p, mutationBinding: b, leaseOwner: original.LeaseOwner}
	installedHostFactory.Lock()
	defer installedHostFactory.Unlock()
	if installedHostFactory.realm != realm {
		return s, ErrHostFactoryHold
	}
	if installedHostFactory.ordinaryFactories == nil {
		installedHostFactory.ordinaryFactories = map[string]*hostOriginalOrdinaryFactory{}
	}
	if installedHostFactory.ordinaryFactories[target] != nil {
		return s, ErrHostFactoryHold
	}
	installedHostFactory.ordinaryFactories[target] = ordinary
	s.hostOriginalOrdinary = ordinary
	return s, nil
}

func (s CapacityStore) CaptureOriginalHostIssueReturn(grant model.CapacityMutationGrant, calledAt, returnedAt time.Time, callErr error) error {
	h := s.hostOriginalFactory
	if h == nil {
		return ErrHostFactoryHold
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.issueReturnReserved {
		return ErrHostFactoryHold
	}
	h.issueReturnReserved = true
	h.issueCalledAt, h.issueReturnedAt = calledAt, returnedAt
	if callErr != nil || !h.issueCommitted || !h.issueReserved || len(h.grantRaw) == 0 || !reflect.DeepEqual(h.grant, grant) || !originalHostIssueReturnedWithin(h.issueContext, h.issueContext, h.issueDeadline, calledAt, returnedAt) || !returnedAt.Before(h.scope.OriginalContextDeadline) || !returnedAt.Before(grant.ExpiresAt) {
		callErr = errors.Join(callErr, ErrHostFactoryHold)
	}
	h.issueReturnErr, h.issueCaptured = callErr, callErr == nil
	return callErr
}

func (s CapacityStore) checkOriginalOrdinaryRegisteredTx(ctx context.Context, tx *sql.Tx, h *hostOriginalOrdinaryFactory) error {
	realm, approval, installed := OriginalHostFactoryRealm()
	if h == nil || !installed || realm != h.realm || h.claim == nil || !h.claim.committed || h.claim.awaiting == nil || !h.claim.awaiting.committed || h.claim.awaiting.originalErr != nil || approval.ScopeRootID != h.claim.rootID || approval.ActualBuildSourceCommit != capacity.CurrentGuestCoreSource() {
		return ErrHostFactoryHold
	}
	if !originalHostPreparationCompleted(h.claim, realm, s.DB, "ordinary_original_create", h.bindingRaw, h.prepared.OriginalCreateCommandHandleID) {
		return ErrHostFactoryHold
	}
	var checksum string
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='workflow' FOR SHARE`, h.workflow.ID).Scan(&checksum, &active); err != nil {
		return err
	}
	if !active || checksum != h.workflow.Checksum {
		return ErrHostFactoryHold
	}
	var bindingRaw, registrationRaw, planRaw, awaitingRaw, rootRaw, approvalRaw []byte
	var entry, state, handle string
	if err := tx.QueryRowContext(ctx, `SELECT t.entry_class,o.state,o.prepared_handle_id::text,o.prepared_plan_wire,o.awaiting_wire,s.original_wire,r.original_wire,root.root_preparation_wire,root.source_approval_wire FROM public.capacity_host_factory_stable_targets t JOIN public.capacity_host_factory_owners o ON o.owner_id=t.original_owner_id JOIN public.capacity_host_factory_scopes s ON s.owner_id=o.owner_id JOIN public.capacity_host_factory_registrations r ON r.scope_sha256=s.scope_sha256 JOIN public.capacity_host_factory_roots root ON root.scope_root_id=t.root_id WHERE t.stable_target_sha256=$1 AND t.root_id=$2 AND t.factory_attempt_id=$3 AND t.original_owner_id=$4 AND s.scope_sha256=$5 AND s.binding_schema='factory_ordinary_source_binding_v4' FOR SHARE OF t,o,s,r,root`, h.binding.StableOriginalTargetSHA256, h.claim.rootID, h.claim.attemptID, h.claim.creatorOwnerID, capacity.HostFactoryRawSHA256(h.bindingRaw)).Scan(&entry, &state, &handle, &planRaw, &awaitingRaw, &bindingRaw, &registrationRaw, &rootRaw, &approvalRaw); err != nil {
		return err
	}
	if entry != "ordinary_original_create" || state != "registered" || handle != h.prepared.OriginalCreateCommandHandleID || !bytes.Equal(bindingRaw, h.bindingRaw) || !bytes.Equal(registrationRaw, h.registrationRaw) || !bytes.Equal(planRaw, h.preparedRaw) || !bytes.Equal(awaitingRaw, h.claim.awaiting.raw) || !bytes.Equal(rootRaw, h.claim.preparation) || !bytes.Equal(approvalRaw, h.claim.approval) {
		return ErrHostFactoryHold
	}
	return nil
}

func (s CapacityStore) attachOriginalOrdinaryGrantTx(ctx context.Context, tx *sql.Tx, record capacityMutationRecord, grantRaw []byte, pre model.CapacityGuestOriginalProvisioningPreregistration, preRaw []byte) error {
	h := s.hostOriginalOrdinary
	if h == nil {
		return ErrHostFactoryHold
	}
	h.mu.Lock()
	blocked := !h.issueReserved || h.issueCommitted || len(h.grantRaw) != 0
	h.mu.Unlock()
	if blocked || record.ExecutorID != h.claim.invocation || record.Grant.RequestSHA256 == "" || record.Grant.Slot != h.binding.Slot || record.Binding.Name != h.binding.MutationBindingName || record.PolicyID != h.policy.ID || record.PolicyChecksum != h.policy.Checksum || record.WorkflowID != h.workflow.ID || pre.OriginalCreateGrantID != record.Grant.GrantID || pre.Generation != record.Generation || pre.Fence != record.FencingToken || pre.ExecutorID != record.ExecutorID || pre.LeaseOwner != record.LeaseOwner || pre.OriginalDeadline.After(h.binding.OriginalContextDeadline) || record.Grant.ExpiresAt.After(pre.OriginalDeadline) || len(grantRaw) == 0 || len(grantRaw) > 65536 || len(preRaw) == 0 || len(preRaw) > 65536 {
		return ErrHostFactoryHold
	}
	if err := s.checkOriginalOrdinaryRegisteredTx(ctx, tx, h); err != nil {
		return err
	}
	if h.realm.CaptureOriginalOrdinaryGrantBinding(ctx, record.Grant, pre, grantRaw, preRaw) != nil {
		return ErrHostFactoryHold
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_factory_original_grant_bindings(grant_id,preregistration_id,root_id,attempt_id,owner_id,prepared_handle_id,stable_target_sha256,entry_class,original_grant_sha256,original_grant_wire,original_preregistration_sha256,original_preregistration_wire,original_request_sha256,original_grant_expires_at,original_provisioning_deadline) VALUES($1,$2,$3,$4,$5,$6,$7,'ordinary_original_create',$8,$9,$10,$11,$12,$13,$14)`, record.Grant.GrantID, pre.PreregistrationID, h.claim.rootID, h.claim.attemptID, h.claim.creatorOwnerID, h.prepared.OriginalCreateCommandHandleID, h.binding.StableOriginalTargetSHA256, capacity.HostFactoryRawSHA256(grantRaw), grantRaw, capacity.HostFactoryRawSHA256(preRaw), preRaw, record.Grant.RequestSHA256, record.Grant.ExpiresAt, pre.OriginalDeadline)
	if err == nil {
		h.mu.Lock()
		h.grant, h.pre = record.Grant, pre
		h.grantRaw, h.preRaw = bytes.Clone(grantRaw), bytes.Clone(preRaw)
		h.mu.Unlock()
	}
	return err
}

func (s CapacityStore) CaptureOriginalOrdinaryIssueReturn(ctx context.Context, grant model.CapacityMutationGrant, calledAt, returnedAt time.Time, callErr error) error {
	h := s.hostOriginalOrdinary
	if h == nil {
		return ErrHostFactoryHold
	}
	h.mu.Lock()
	if h.issueReturnReserved {
		h.mu.Unlock()
		return ErrHostFactoryHold
	}
	h.issueReturnReserved = true
	h.issueCalledAt, h.issueReturnedAt = calledAt, returnedAt
	h.issueReturnErr = callErr
	valid := callErr == nil && h.issueCommitted && h.issueReserved && len(h.grantRaw) != 0 && reflect.DeepEqual(h.grant, grant) && originalHostIssueReturnedWithin(ctx, h.issueContext, h.issueDeadline, calledAt, returnedAt) && returnedAt.Before(h.binding.OriginalContextDeadline) && returnedAt.Before(grant.ExpiresAt)
	h.mu.Unlock()
	err := callErr
	if valid {
		err = h.realm.CaptureOriginalOrdinaryIssueReturn(ctx, grant, calledAt, returnedAt)
	} else {
		err = errors.Join(err, ErrHostFactoryHold)
	}
	if !originalHostIssueReturnedWithin(ctx, h.issueContext, h.issueDeadline, calledAt, returnedAt) {
		err = errors.Join(err, ErrHostFactoryHold)
	}
	h.mu.Lock()
	h.issueReturnErr = err
	h.issueCaptured = err == nil
	h.mu.Unlock()
	return err
}

func (s CapacityStore) ContinueOriginalOrdinaryCreate(ctx context.Context) (model.CapacityMutationProof, error) {
	var proof model.CapacityMutationProof
	h := s.hostOriginalOrdinary
	if h == nil {
		return proof, ErrHostFactoryHold
	}
	h.mu.Lock()
	if !h.issueCommitted || !h.issueCaptured || h.issueReturnedAt.IsZero() || h.issueReturnErr != nil || h.continued {
		h.mu.Unlock()
		return proof, ErrHostFactoryHold
	}
	h.continued = true
	grant, pre := h.grant, h.pre
	h.mu.Unlock()
	proof, raw, err := h.realm.ContinueOriginalOrdinary(ctx)
	h.mu.Lock()
	h.proof, h.nativeRaw, h.continueErr = proof, bytes.Clone(raw), err
	h.mu.Unlock()
	if err != nil {
		return proof, err
	}
	if len(raw) == 0 || len(raw) > 65536 || h.realm.VerifyOriginalOrdinaryCreateReturn(ctx, grant, pre, proof, raw) != nil {
		h.mu.Lock()
		h.continueErr = ErrHostFactoryHold
		h.mu.Unlock()
		return proof, ErrHostFactoryHold
	}
	if err = s.RecordGuestQualificationSourceReturn(ctx, pre.PreregistrationID, "native_read", raw); err != nil {
		h.mu.Lock()
		h.continueErr = err
		h.mu.Unlock()
		return proof, err
	}
	return proof, nil
}

func (s CapacityStore) verifyOriginalOrdinaryCreateTx(ctx context.Context, tx *sql.Tx, pre model.CapacityGuestOriginalProvisioningPreregistration, proof model.CapacityMutationProof) error {
	h := s.hostOriginalOrdinary
	if h == nil {
		return ErrHostFactoryHold
	}
	h.mu.Lock()
	valid := h.issueCommitted && h.issueCaptured && !h.issueReturnedAt.IsZero() && h.issueReturnErr == nil && h.continued && h.continueErr == nil && len(h.nativeRaw) != 0 && reflect.DeepEqual(proof, h.proof) && reflect.DeepEqual(pre, h.pre)
	grant, grantRaw, preRaw, nativeRaw := h.grant, bytes.Clone(h.grantRaw), bytes.Clone(h.preRaw), bytes.Clone(h.nativeRaw)
	h.mu.Unlock()
	if !valid {
		return ErrHostFactoryHold
	}
	realm, approval, installed := OriginalHostFactoryRealm()
	if !installed || realm != h.realm || approval.ScopeRootID != h.claim.rootID || approval.ActualBuildSourceCommit != capacity.CurrentGuestCoreSource() || h.realm.VerifyOriginalOrdinaryCreateReturn(ctx, grant, pre, proof, nativeRaw) != nil {
		return ErrHostFactoryHold
	}
	var actualGrant, actualPre, actualNative []byte
	var consistent bool
	if err := tx.QueryRowContext(ctx, `SELECT original_grant_wire,original_preregistration_wire FROM public.capacity_factory_original_grant_bindings WHERE grant_id=$1 AND preregistration_id=$2 AND root_id=$3 AND owner_id=$4 AND prepared_handle_id=$5 AND stable_target_sha256=$6 AND entry_class='ordinary_original_create'`, grant.GrantID, pre.PreregistrationID, h.claim.rootID, h.claim.creatorOwnerID, h.prepared.OriginalCreateCommandHandleID, h.binding.StableOriginalTargetSHA256).Scan(&actualGrant, &actualPre); err != nil {
		return err
	}
	if !bytes.Equal(actualGrant, grantRaw) || !bytes.Equal(actualPre, preRaw) {
		return ErrHostFactoryHold
	}
	var originalNativeRows int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read'`, pre.PreregistrationID).Scan(&originalNativeRows); err != nil {
		return err
	}
	if originalNativeRows != 1 {
		return ErrHostFactoryHold
	}
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,original_record=convert_from(original_wire,'UTF8')::jsonb FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read'`, pre.PreregistrationID).Scan(&actualNative, &consistent); err != nil {
		return err
	}
	if !consistent || !bytes.Equal(actualNative, nativeRaw) {
		return ErrHostFactoryHold
	}
	return nil
}

func (s CapacityStore) guardOriginalHostConfirmTx(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec, b model.CapacityMutationBinding, slot int, proof model.CapacityMutationProof) error {
	h := s.hostOriginalOrdinary
	if h == nil {
		return s.guardOriginalHostMutationTx(ctx, tx, namespace, p, b, slot)
	}
	_, target, err := originalHostStableTarget(namespace, p, b.Name, slot)
	if err != nil {
		return err
	}
	if target != h.binding.StableOriginalTargetSHA256 || !reflect.DeepEqual(p, h.policySpec) || !reflect.DeepEqual(b, h.mutationBinding) {
		return ErrHostFactoryHold
	}
	if err = lockOriginalHostTarget(ctx, tx, target); err != nil {
		return err
	}
	if err = s.checkOriginalOrdinaryRegisteredTx(ctx, tx, h); err != nil {
		return err
	}
	h.mu.Lock()
	pre := h.pre
	h.mu.Unlock()
	return s.verifyOriginalOrdinaryCreateTx(ctx, tx, pre, proof)
}

func (s CapacityStore) checkOriginalHostRegisteredTx(ctx context.Context, tx *sql.Tx, h *hostOriginalFactoryScope) error {
	if h == nil || !originalHostPreparationCompleted(s.hostOriginalClaim, h.realm, s.DB, h.scope.FactoryEntryClass, h.scopeRaw, h.prepared.OriginalCreateCommandHandleID) {
		return ErrHostFactoryHold
	}
	var checksum string
	var active bool
	if err := tx.QueryRowContext(ctx, `SELECT checksum,active FROM public.manifests WHERE id=$1 AND kind='workflow' FOR SHARE`, s.WorkflowID).Scan(&checksum, &active); err != nil {
		return err
	}
	if !active || checksum != h.scope.WorkflowChecksum || capacity.CurrentGuestCoreSource() != h.scope.CoreActualSourceCommit {
		return ErrHostFactoryHold
	}
	var scopeRaw, registrationRaw, planRaw, awaitingRaw []byte
	var entry, state, handle string
	if err := tx.QueryRowContext(ctx, `SELECT t.entry_class,o.state,o.prepared_handle_id::text,o.prepared_plan_wire,o.awaiting_wire,s.original_wire,r.original_wire FROM public.capacity_host_factory_stable_targets t JOIN public.capacity_host_factory_owners o ON o.owner_id=t.original_owner_id JOIN public.capacity_host_factory_scopes s ON s.owner_id=o.owner_id JOIN public.capacity_host_factory_registrations r ON r.scope_sha256=s.scope_sha256 WHERE t.stable_target_sha256=$1 AND t.root_id=$2 AND t.factory_attempt_id=$3 AND t.original_owner_id=$4 AND s.scope_sha256=$5 FOR SHARE OF t,o,s,r`, h.scope.StableOriginalTargetSHA256, h.scope.ScopeRootID, h.scope.FactoryAttemptID, h.scope.CreatorOwnerID, capacity.HostFactoryRawSHA256(h.scopeRaw)).Scan(&entry, &state, &handle, &planRaw, &awaitingRaw, &scopeRaw, &registrationRaw); err != nil {
		return err
	}
	if s.hostOriginalClaim == nil || s.hostOriginalClaim.awaiting == nil || !s.hostOriginalClaim.awaiting.committed || entry != h.scope.FactoryEntryClass || state != "registered" || handle != h.prepared.OriginalCreateCommandHandleID || !bytes.Equal(scopeRaw, h.scopeRaw) || capacity.HostFactoryRawSHA256(registrationRaw) != capacity.GuestRetirementSHA(h.registration) || capacity.HostFactoryRawSHA256(planRaw) != capacity.GuestRetirementSHA(h.prepared) || !bytes.Equal(awaitingRaw, s.hostOriginalClaim.awaiting.raw) {
		return ErrHostFactoryHold
	}
	if entry == "sealed_a1" {
		var grantRaw, preRaw, attachmentRaw []byte
		if !h.issueCommitted || h.issueReturnedAt.IsZero() {
			return ErrHostFactoryHold
		}
		if err := tx.QueryRowContext(ctx, `SELECT f.original_grant_wire,f.original_preregistration_wire,a.original_wire FROM public.capacity_factory_original_grant_bindings f JOIN public.capacity_host_factory_issued_attachments a ON a.grant_id=f.grant_id WHERE f.grant_id=$1 AND f.preregistration_id=$2 AND f.root_id=$3 AND f.owner_id=$4 AND f.entry_class='sealed_a1' AND a.scope_sha256=$5 FOR SHARE OF f,a`, h.grant.GrantID, h.pre.PreregistrationID, h.scope.ScopeRootID, h.scope.CreatorOwnerID, capacity.HostFactoryRawSHA256(h.scopeRaw)).Scan(&grantRaw, &preRaw, &attachmentRaw); err != nil {
			return err
		}
		if !bytes.Equal(grantRaw, h.grantRaw) || !bytes.Equal(preRaw, h.preRaw) || !bytes.Equal(attachmentRaw, h.attachmentRaw) {
			return ErrHostFactoryHold
		}
	}
	return nil
}

func (s CapacityStore) ReserveOriginalHostSealed(ctx context.Context, stage string, envelopeRaw []byte) error {
	if err := s.guardOriginalHostPostStartCurrent(ctx); err != nil {
		return err
	}
	codec := originalHostInstalledSourceCodec(ctx, "")

	h := s.hostOriginalFactory
	if h == nil || h.scope.FactoryEntryClass == "sealed_a1" && (!h.issueCommitted || !h.issueCaptured || h.issueReturnErr != nil || h.issueReturnedAt.IsZero()) {
		return ErrHostFactoryHold
	}
	var reservationID string
	var bodyRaw []byte
	var deadline time.Time
	var err error
	if stage == "unissued-choice-reservation" && h.scope.FactoryEntryClass == "sealed_a0" {
		var v model.HostFactoryUnissuedChoiceReservation
		bodyRaw, err = originalHostStageBody(codec, stage, envelopeRaw, &v)
		reservationID, deadline = v.ReservationID, v.OriginalChoiceDeadline
		if v.PreAuthorityScopeSHA256 != capacity.HostFactoryRawSHA256(h.scopeRaw) || v.AliveRegistrationSHA256 != capacity.GuestRetirementSHA(h.registration) {
			return ErrHostFactoryHold
		}
	} else if stage == "issued-choice-reservation" && h.scope.FactoryEntryClass == "sealed_a1" {
		var v model.HostFactoryIssuedChoiceReservation
		bodyRaw, err = originalHostStageBody(codec, stage, envelopeRaw, &v)
		reservationID, deadline = v.ReservationID, v.OriginalChoiceDeadline
		if v.PreAuthorityScopeSHA256 != capacity.HostFactoryRawSHA256(h.scopeRaw) || v.AliveRegistrationSHA256 != capacity.GuestRetirementSHA(h.registration) || v.IssuedAttachmentSHA256 != capacity.HostFactoryRawSHA256(h.attachmentRaw) {
			return ErrHostFactoryHold
		}
		if deadline.After(h.pre.OriginalDeadline) || deadline.After(h.grant.ExpiresAt) {
			return ErrHostFactoryHold
		}
	} else {
		return ErrHostFactoryHold
	}
	if err != nil || deadline.After(h.scope.OriginalContextDeadline) || deadline.After(h.scope.OriginalLeaseExpiresAt) || !time.Now().Before(deadline) || h.realm.VerifyOriginalStage(ctx, stage, envelopeRaw) != nil {
		return ErrHostFactoryHold
	}
	records, err := prepareOriginalHostRecords(ctx, h.scope.ScopeRootID, capacity.HostFactoryRawSHA256(h.scopeRaw), map[string][]byte{stage: envelopeRaw})
	if err != nil {
		return err
	}
	return s.mutationTransaction(ctx, h.policy, false, h.scope.Generation, h.scope.Fence, h.leaseOwner, func(tx *sql.Tx, _ model.CapacityPolicySpec, _ model.CapacityIntent, _ time.Time) error {
		if err := lockNativeMutationSlot(ctx, tx, h.binding, h.scope.Slot); err != nil {
			return err
		}
		if err := lockOriginalHostTarget(ctx, tx, h.scope.StableOriginalTargetSHA256); err != nil {
			return err
		}
		if err := s.checkOriginalHostRegisteredTx(ctx, tx, h); err != nil {
			return err
		}
		if err := s.appendOriginalHostRecordsTx(ctx, tx, records); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_sealed_reservations(scope_sha256,root_id,attempt_id,owner_id,reservation_id,branch,reservation_sha256,original_wire) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, capacity.HostFactoryRawSHA256(h.scopeRaw), h.scope.ScopeRootID, h.scope.FactoryAttemptID, h.scope.CreatorOwnerID, reservationID, h.scope.FactoryEntryClass, capacity.HostFactoryRawSHA256(bodyRaw), bodyRaw)
		return err
	})
}

func (s CapacityStore) RecordOriginalHostTerminalStages(ctx context.Context, stages map[string][]byte) error {
	codec := originalHostInstalledSourceCodec(ctx, "")

	h := s.hostOriginalFactory
	if h == nil || h.scope.FactoryEntryClass == "sealed_a1" && (!h.issueCommitted || !h.issueCaptured || h.issueReturnErr != nil || h.issueReturnedAt.IsZero()) {
		return ErrHostFactoryHold
	}
	for _, name := range []string{"choice-return", "exterior-join", "terminal-read"} {
		if len(stages[name]) == 0 {
			return ErrHostFactoryHold
		}
	}
	records, err := prepareOriginalHostRecords(ctx, h.scope.ScopeRootID, capacity.HostFactoryRawSHA256(h.scopeRaw), stages)
	if err != nil {
		return err
	}
	// The final issuer body remains unavailable until the actual full native
	// chain exists in the source cache. No caller final flag supplies it.
	stage := "unissued-disposition"
	if h.scope.FactoryEntryClass == "sealed_a1" {
		stage = "issued-disposition"
	}
	body, err := h.realm.OriginalAuthorityBody(ctx, stage)
	if err != nil {
		return ErrHostFactoryHold
	}
	envelope, err := h.realm.SignOriginalAuthority(ctx, stage, body)
	if err != nil {
		return ErrHostFactoryHold
	}
	var observedAt time.Time
	if stage == "unissued-disposition" {
		var v model.HostFactoryUnissuedDisposition
		if codec.Decode(body, &v) != nil {
			return ErrHostFactoryHold
		}
		observedAt = v.RecordedAt
	} else {
		var v model.HostFactoryIssuedDisposition
		if codec.Decode(body, &v) != nil {
			return ErrHostFactoryHold
		}
		observedAt = v.RecordedAt
	}
	if !observedAt.Before(h.scope.OriginalContextDeadline) || !observedAt.Before(h.scope.OriginalLeaseExpiresAt) || h.realm.VerifyOriginalStage(ctx, stage, envelope) != nil {
		return ErrHostFactoryHold
	}
	if h.scope.FactoryEntryClass == "sealed_a1" && (!observedAt.Before(h.pre.OriginalDeadline) || !observedAt.Before(h.grant.ExpiresAt)) {
		return ErrHostFactoryHold
	}
	dispositionRecords, err := prepareOriginalHostRecords(ctx, h.scope.ScopeRootID, capacity.HostFactoryRawSHA256(h.scopeRaw), map[string][]byte{stage: envelope})
	if err != nil {
		return err
	}
	return s.mutationTransaction(ctx, h.policy, false, h.scope.Generation, h.scope.Fence, h.leaseOwner, func(tx *sql.Tx, _ model.CapacityPolicySpec, _ model.CapacityIntent, _ time.Time) error {
		if err := lockNativeMutationSlot(ctx, tx, h.binding, h.scope.Slot); err != nil {
			return err
		}
		if err := lockOriginalHostTarget(ctx, tx, h.scope.StableOriginalTargetSHA256); err != nil {
			return err
		}
		if err := s.checkOriginalHostRegisteredTx(ctx, tx, h); err != nil {
			return err
		}
		if err := s.appendOriginalHostRecordsTx(ctx, tx, records); err != nil {
			return err
		}
		if err := validateOriginalHostDispositionTx(ctx, tx, h.scope, h.scopeRaw, h.registration, h.attachmentRaw, body, stage); err != nil {
			return err
		}
		if err := s.appendOriginalHostRecordsTx(ctx, tx, dispositionRecords); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_dispositions(scope_sha256,root_id,attempt_id,owner_id,branch,disposition_sha256,original_wire) VALUES($1,$2,$3,$4,$5,$6,$7)`, capacity.HostFactoryRawSHA256(h.scopeRaw), h.scope.ScopeRootID, h.scope.FactoryAttemptID, h.scope.CreatorOwnerID, h.scope.FactoryEntryClass, capacity.HostFactoryRawSHA256(body), body)
		return err
	})
}

func validateOriginalHostDispositionTx(ctx context.Context, tx *sql.Tx, scope model.HostFactoryPreAuthorityScope, scopeRaw []byte, registration model.HostFactoryAliveRegistration, attachmentRaw, body []byte, stage string) error {
	codec := originalHostSourceCodecTx(ctx, tx, scope.ScopeRootID)

	scopeSHA := capacity.HostFactoryRawSHA256(scopeRaw)
	var reservationRaw []byte
	var reservationSHA, branch string
	if err := tx.QueryRowContext(ctx, `SELECT original_wire,reservation_sha256,branch FROM public.capacity_host_factory_sealed_reservations WHERE scope_sha256=$1 AND root_id=$2 AND owner_id=$3`, scopeSHA, scope.ScopeRootID, scope.CreatorOwnerID).Scan(&reservationRaw, &reservationSHA, &branch); err != nil {
		return err
	}
	if branch != scope.FactoryEntryClass || capacity.HostFactoryRawSHA256(reservationRaw) != reservationSHA {
		return ErrHostFactoryHold
	}
	read := func(name string, target any) (string, error) {
		var raw []byte
		var sha string
		if err := tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_body_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND stage=$3 AND binding_schema='original_host_factory_pre_authority_scope_v4' AND binding_sha256=$4`, scope.ScopeRootID, scope.CreatorOwnerID, name, scopeSHA).Scan(&raw, &sha); err != nil {
			return "", err
		}
		if capacity.HostFactoryRawSHA256(raw) != sha || codec.Decode(raw, target) != nil {
			return "", ErrHostFactoryHold
		}
		return sha, nil
	}
	var choice model.HostFactoryChoiceReturn
	choiceSHA, err := read("choice-return", &choice)
	if err != nil {
		return err
	}
	var exterior model.HostFactoryExteriorJoin
	exteriorSHA, err := read("exterior-join", &exterior)
	if err != nil {
		return err
	}
	var terminal model.HostFactoryTerminalRead
	terminalSHA, err := read("terminal-read", &terminal)
	if err != nil {
		return err
	}
	registrationSHA := capacity.GuestRetirementSHA(registration)
	if choice.ChoiceReservationSHA256 != reservationSHA || choice.OriginalWrittenSHA256 != choice.ChoiceBodySHA256 || exterior.PreAuthorityScopeSHA256 != scopeSHA || terminal.PreAuthorityScopeSHA256 != scopeSHA || exterior.AliveRegistrationSHA256 != registrationSHA || terminal.AliveRegistrationSHA256 != registrationSHA || exterior.ChoiceReturnSHA256 != choiceSHA || terminal.ChoiceReturnSHA256 != choiceSHA || exterior.ChoiceBodySHA256 != choice.ChoiceBodySHA256 || terminal.ChoiceBodySHA256 != choice.ChoiceBodySHA256 || terminal.OriginalReadSHA256 != choice.ChoiceBodySHA256 || terminal.ExteriorJoinSHA256 != exteriorSHA || terminal.ObservedAt.Before(exterior.RecordedAt) || choice.OriginalGateSource.Device != terminal.OriginalGateSource.Device || choice.OriginalGateSource.Inode != terminal.OriginalGateSource.Inode {
		return ErrHostFactoryHold
	}
	var observed time.Time
	if stage == "unissued-disposition" && branch == "sealed_a0" {
		var v model.HostFactoryUnissuedDisposition
		if codec.Decode(body, &v) != nil || v.PreAuthorityScopeSHA256 != scopeSHA || v.AliveRegistrationSHA256 != registrationSHA || v.ChoiceReservationSHA256 != reservationSHA || v.ChoiceBodySHA256 != choice.ChoiceBodySHA256 || v.ChoiceReturnSHA256 != choiceSHA || v.ExteriorJoinSHA256 != exteriorSHA || v.TerminalReadSHA256 != terminalSHA || v.FactoryRegistrySHA256 != scope.FactoryRegistrySHA256 {
			return ErrHostFactoryHold
		}
		observed = v.RecordedAt
	} else if stage == "issued-disposition" && branch == "sealed_a1" {
		var v model.HostFactoryIssuedDisposition
		if codec.Decode(body, &v) != nil || v.PreAuthorityScopeSHA256 != scopeSHA || v.AliveRegistrationSHA256 != registrationSHA || v.IssuedAttachmentSHA256 != capacity.HostFactoryRawSHA256(attachmentRaw) || v.ChoiceReservationSHA256 != reservationSHA || v.ChoiceBodySHA256 != choice.ChoiceBodySHA256 || v.ChoiceReturnSHA256 != choiceSHA || v.ExteriorJoinSHA256 != exteriorSHA || v.TerminalReadSHA256 != terminalSHA || v.FactoryRegistrySHA256 != scope.FactoryRegistrySHA256 {
			return ErrHostFactoryHold
		}
		observed = v.RecordedAt
	} else {
		return ErrHostFactoryHold
	}
	if observed.Before(terminal.ObservedAt) || !observed.Before(scope.OriginalContextDeadline) || !observed.Before(scope.OriginalLeaseExpiresAt) {
		return ErrHostFactoryHold
	}
	return nil
}

// These private schemas project actual owning SQL returns. They are unsigned,
// do not install approval, and never export private raw buffers.
type hostOriginalSQLRawField struct {
	Column string  `json:"column"`
	Bytes  *int64  `json:"bytes"`
	SHA256 *string `json:"sha256"`
}
type hostOriginalSQLRecord struct {
	Table                string                    `json:"table"`
	RowKey               json.RawMessage           `json:"row_key"`
	RawFields            []hostOriginalSQLRawField `json:"raw_fields"`
	PublicEnvelopeBase64 *string                   `json:"public_envelope_base64"`
	original             map[string][]byte
	indices              map[string]json.RawMessage
}
type hostOriginalSQLSnapshot struct {
	Schema                    string                  `json:"schema"`
	RootID                    string                  `json:"root_id"`
	NativeFactoryRootID       string                  `json:"native_factory_root_id"`
	FactoryAttemptID          string                  `json:"factory_attempt_id"`
	CreatorOwnerID            string                  `json:"creator_owner_id"`
	EntryClass                string                  `json:"entry_class"`
	StableTargetSHA256        string                  `json:"stable_target_sha256"`
	SourceApprovalBodySHA256  string                  `json:"source_approval_body_sha256"`
	RootPreparationBodySHA256 string                  `json:"root_preparation_body_sha256"`
	PrivateBindingSchema      string                  `json:"private_binding_schema"`
	PrivateBindingSHA256      string                  `json:"private_binding_sha256"`
	OriginalInvocationID      string                  `json:"original_invocation_id"`
	PolicyID                  string                  `json:"policy_id"`
	PolicyChecksum            string                  `json:"policy_checksum"`
	WorkflowID                string                  `json:"workflow_id"`
	WorkflowChecksum          string                  `json:"workflow_checksum"`
	PublicRunID               string                  `json:"public_run_id"`
	PublicRunStatus           string                  `json:"public_run_status"`
	CoreActualSourceCommit    string                  `json:"core_actual_source_commit"`
	OriginalContextDeadline   time.Time               `json:"original_context_deadline"`
	SQLReadCalledAt           time.Time               `json:"sql_read_called_at"`
	SQLReadReturnedAt         time.Time               `json:"sql_read_returned_at"`
	Records                   []hostOriginalSQLRecord `json:"records"`
}
type hostOriginalSQLTable struct {
	table               string
	keys, raws, indices []string
	envelope, where     string
}

// PROPOSAL delta to literal e33b2b28: same13 tables, native private custody count/SHA only. No caller supplies SQL identifiers or expressions.
var originalHostSQLTables = []hostOriginalSQLTable{
	{"public.capacity_host_factory_roots", []string{"scope_root_id"}, []string{"source_approval_wire", "root_preparation_wire"}, []string{"factory_realm_id", "factory_attempt_id", "creator_owner_id", "factory_registry_class", "source_approval_sha256", "root_preparation_sha256", "original_started_at", "original_deadline", "root_device", "root_inode", "source_closure_sha256"}, "", "scope_root_id=$1"},
	{"public.capacity_host_factory_stable_targets", []string{"stable_target_sha256"}, []string{"target_wire"}, []string{"root_id", "factory_attempt_id", "original_owner_id", "entry_class", "integration_instance_id", "integration_type_id", "integration_checksum", "integration_type_checksum", "scope_checksum", "profile_name"}, "", "root_id=$1"},
	{"public.capacity_host_factory_owners", []string{"owner_id"}, []string{"awaiting_wire", "prepared_plan_wire", "native_registration_wire"}, []string{"root_id", "attempt_id", "stable_target_sha256", "state", "awaiting_sha256", "prepared_handle_id", "worker_primitive_sha256", "prepared_plan_sha256"}, "", "root_id=$1"},
	{"public.capacity_host_factory_scopes", []string{"scope_sha256"}, []string{"original_wire"}, []string{"root_id", "attempt_id", "owner_id", "stable_target_sha256", "binding_schema"}, "", "root_id=$1"},
	{"public.capacity_host_factory_leases", []string{"root_id", "original_invocation_id"}, []string{"original_intent_wire", "original_assessment_wire", "initial_empty_wire"}, []string{"namespace", "environment", "domain", "dimension", "generation", "fence", "original_intent_sha256", "original_assessment_sha256", "initial_empty_sha256"}, "", "root_id=$1"},
	{"public.capacity_host_factory_stage_returns", []string{"root_id", "subject_owner_id", "stage"}, []string{"raw_body_wire", "raw_envelope_wire", "native_phase_wire"}, []string{"binding_schema", "binding_sha256", "signer_role", "raw_body_sha256", "raw_envelope_sha256"}, "raw_envelope_wire", "root_id=$1"},
	{"public.capacity_host_factory_registrations", []string{"scope_sha256"}, []string{"original_wire"}, []string{"owner_id", "prepared_handle_id", "registration_sha256"}, "", "scope_sha256 IN (SELECT scope_sha256 FROM public.capacity_host_factory_scopes WHERE root_id=$1)"},
	{"public.capacity_factory_original_grant_bindings", []string{"grant_id"}, []string{"original_grant_wire", "original_preregistration_wire"}, []string{"preregistration_id", "root_id", "attempt_id", "owner_id", "prepared_handle_id", "stable_target_sha256", "entry_class", "original_grant_sha256", "original_preregistration_sha256", "original_request_sha256", "original_grant_expires_at", "original_provisioning_deadline"}, "", "root_id=$1"},
	{"public.capacity_host_factory_issued_attachments", []string{"grant_id"}, []string{"original_wire"}, []string{"preregistration_id", "scope_sha256", "attachment_sha256"}, "", "grant_id IN (SELECT grant_id FROM public.capacity_factory_original_grant_bindings WHERE root_id=$1)"},
	{"public.capacity_host_factory_sealed_reservations", []string{"scope_sha256"}, []string{"original_wire"}, []string{"root_id", "attempt_id", "owner_id", "reservation_id", "branch", "reservation_sha256"}, "", "root_id=$1"},
	{"public.capacity_host_factory_dispositions", []string{"scope_sha256"}, []string{"original_wire"}, []string{"root_id", "attempt_id", "owner_id", "branch", "disposition_sha256"}, "", "root_id=$1"},
	{"public.capacity_host_factory_io_returns", []string{"root_id", "binding_schema", "binding_sha256", "original_owner_id", "record_kind", "record_identity_sha256"}, []string{"raw_body_wire", "raw_envelope_wire", "native_inventory_relations_wire"}, []string{"original_handle_id", "operation", "first_ordinal", "last_ordinal", "failure_collection_id", "part_ordinal", "previous_part_raw_sha256", "raw_body_sha256", "raw_envelope_sha256", "native_factory_root_id", "native_observation_id", "native_observation_kind", "native_subject_owner_id", "native_observer_primitive_sha256", "native_subject_primitive_sha256", "native_collection_id", "native_census_ordinal", "native_manifest_level", "native_first_ordinal", "native_last_ordinal", "native_observation_count"}, "raw_envelope_wire", "root_id=$1"},
	{"public.capacity_host_factory_call_snapshot_links", []string{"root_id", "binding_schema", "binding_sha256", "original_owner_id", "original_handle_id", "original_call_id", "version_kind"}, []string{"original_getdents_wire", "original_getdents_source_audit_wire"}, []string{"current_chunk_raw_body_sha256", "current_fact_index", "predecessor_chunk_raw_body_sha256", "predecessor_fact_index", "predecessor_version_kind", "original_called_at", "original_operation_deadline"}, "", "root_id=$1"},
	{"public.capacity_guest_qualification_native_source_returns", []string{"id"}, []string{"original_wire"}, []string{"preregistration_id", "native_stage", "return_sha256", "recorded_at"}, "", "preregistration_id IN (SELECT preregistration_id FROM public.capacity_factory_original_grant_bindings WHERE root_id=$1) AND native_stage='native_read'"},
	{"public.workflow_runs", []string{"id"}, []string{}, []string{"workflow_id", "workflow_namespace", "workflow_name", "workflow_version", "status", "result"}, "", "id=$1"},
	{"public.capacity_guest_original_create_witnesses", []string{"preregistration_id"}, []string{"original_wire"}, []string{"original_create_attempt_id", "resource_tuple_sha256", "witness_sha256", "recorded_at"}, "", "preregistration_id IN (SELECT preregistration_id FROM public.capacity_factory_original_grant_bindings WHERE root_id=$1)"},
	{"public.capacity_vm_original_enrollments", []string{"preregistration_id"}, []string{"registration_wire", "receipt_wire"}, []string{"resource_tuple_sha256", "enrollment_sha256", "original_provisioning_sha256", "recorded_at"}, "", "preregistration_id IN (SELECT preregistration_id FROM public.capacity_factory_original_grant_bindings WHERE root_id=$1)"},
	{"public.capacity_vm_provisioning_preregistrations", []string{"id"}, []string{"original_wire", "binding_wire"}, []string{"create_grant_id", "nonce_sha256", "profile_manifest_sha256", "original_deadline", "created_at"}, "", "id IN (SELECT preregistration_id FROM public.capacity_factory_original_grant_bindings WHERE root_id=$1)"},
	{"public.capacity_mutation_grants", []string{"id"}, []string{}, []string{"grant_record", "state", "expires_at"}, "", "id IN (SELECT grant_id FROM public.capacity_factory_original_grant_bindings WHERE root_id=$1)"},
	{"public.manifests", []string{"id"}, []string{}, []string{"kind", "namespace", "name", "version", "checksum", "active", "spec"}, "", "id IN ($1,$2)"},
}

func originalHostSQLReadTable(ctx context.Context, tx *sql.Tx, table hostOriginalSQLTable, args []any, snapshot *hostOriginalSQLSnapshot, total *int) error {
	keyParts := strings.Join(table.keys, ",")
	indexParts := []string{}
	for _, column := range table.indices {
		indexParts = append(indexParts, "'"+column+"'", column)
	}
	selectParts := []string{"jsonb_build_array(" + keyParts + ")", "jsonb_build_object(" + strings.Join(indexParts, ",") + ")"}
	for _, column := range table.raws {
		selectParts = append(selectParts, column+" IS NULL", "octet_length("+column+")", "CASE WHEN octet_length("+column+")<=65536 THEN "+column+" ELSE NULL END")
	}
	privatePostStart := table.table == "public.capacity_host_factory_stage_returns"
	privateFinal := table.table == "public.capacity_host_factory_call_snapshot_links"
	if privatePostStart {
		selectParts = append(selectParts, "original_poststart_ledger_wire IS NULL", "octet_length(original_poststart_ledger_wire)", "CASE WHEN octet_length(original_poststart_ledger_wire)<=65536 THEN original_poststart_ledger_wire ELSE NULL END")
	}
	if privateFinal {
		selectParts = append(selectParts, "original_final_source_audit_wire IS NULL", "octet_length(original_final_source_audit_wire)", "CASE WHEN octet_length(original_final_source_audit_wire)<=1048576 THEN original_final_source_audit_wire ELSE NULL END")
	}
	query := "SELECT " + strings.Join(selectParts, ",") + " FROM " + table.table + " WHERE " + table.where + " ORDER BY " + keyParts + " LIMIT 32769"
	// Placeholder arity is fixed by this literal table, never by caller input.
	queryArgs := args[:1]
	if table.table == "public.workflow_runs" {
		queryArgs = args[1:2]
	}
	if table.table == "public.manifests" {
		queryArgs = args[2:4]
	}
	rows, err := tx.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var key, indices []byte
		wires := make([][]byte, len(table.raws))
		nulls := make([]bool, len(table.raws))
		counts := make([]sql.NullInt64, len(table.raws))
		values := []any{&key, &indices}
		for i := range table.raws {
			values = append(values, &nulls[i], &counts[i], &wires[i])
		}
		var privateNull bool
		var privateCount sql.NullInt64
		var privateWire []byte
		if privatePostStart || privateFinal {
			values = append(values, &privateNull, &privateCount, &privateWire)
		}
		if err = rows.Scan(values...); err != nil {
			rows.Close()
			return err
		}
		if len(snapshot.Records) >= 32768 || len(key) > 4096 || len(indices) > 65536 {
			rows.Close()
			return ErrHostFactoryHold
		}
		var pk []json.RawMessage
		if json.Unmarshal(key, &pk) != nil || len(pk) != len(table.keys) {
			rows.Close()
			return ErrHostFactoryHold
		}
		canonicalKey, keyErr := json.Marshal(pk)
		if keyErr != nil {
			rows.Close()
			return keyErr
		}
		record := hostOriginalSQLRecord{Table: table.table, RowKey: canonicalKey, RawFields: []hostOriginalSQLRawField{}, original: map[string][]byte{}, indices: map[string]json.RawMessage{}}
		if json.Unmarshal(indices, &record.indices) != nil {
			rows.Close()
			return ErrHostFactoryHold
		}
		for i, column := range table.keys {
			record.indices[column] = bytes.Clone(pk[i])
		}
		for i, column := range table.raws {
			field := hostOriginalSQLRawField{Column: column}
			if nulls[i] {
				if counts[i].Valid || wires[i] != nil {
					rows.Close()
					return ErrHostFactoryHold
				}
			} else {
				if !counts[i].Valid || counts[i].Int64 < 0 || counts[i].Int64 > 65536 || int64(len(wires[i])) != counts[i].Int64 || *total > 32*1024*1024-len(wires[i]) {
					rows.Close()
					return ErrHostFactoryHold
				}
				*total += len(wires[i])
				count := counts[i].Int64
				sha := capacity.HostFactoryRawSHA256(wires[i])
				field.Bytes, field.SHA256 = &count, &sha
				record.original[column] = bytes.Clone(wires[i])
				if column == table.envelope {
					encoded := base64.StdEncoding.EncodeToString(wires[i])
					record.PublicEnvelopeBase64 = &encoded
				}
			}
			record.RawFields = append(record.RawFields, field)
		}
		if privatePostStart {
			postStage := originalHostSQLString(record, "stage") == "poststart-empty-realm-read"
			if postStage {
				if privateNull || !privateCount.Valid || privateCount.Int64 < 1 || privateCount.Int64 > 65536 || int64(len(privateWire)) != privateCount.Int64 || *total > 32*1024*1024-len(privateWire) {
					rows.Close()
					return ErrHostFactoryHold
				}
				*total += len(privateWire)
				record.original["original_poststart_ledger_wire"] = bytes.Clone(privateWire)
			} else if !privateNull || privateCount.Valid || privateWire != nil {
				rows.Close()
				return ErrHostFactoryHold
			}
			// Deliberately NO public RawFields count/SHA or wrapper raw bytes.
		}
		if privateFinal {
			if privateNull {
				if privateCount.Valid || privateWire != nil {
					rows.Close()
					return ErrHostFactoryHold
				}
			} else {
				if !privateCount.Valid || privateCount.Int64 < 1 || privateCount.Int64 > 1048576 || int64(len(privateWire)) != privateCount.Int64 || *total > 32*1024*1024-len(privateWire) {
					rows.Close()
					return ErrHostFactoryHold
				}
				*total += len(privateWire)
				record.original["original_final_source_audit_wire"] = bytes.Clone(privateWire)
			}
			// NO public RawFields count/SHA or wrapper copy of this private column.
		}
		snapshot.Records = append(snapshot.Records, record)
	}
	return errors.Join(rows.Err(), rows.Close())
}

func originalHostSQLRecords(snapshot hostOriginalSQLSnapshot, table string) []hostOriginalSQLRecord {
	out := []hostOriginalSQLRecord{}
	for _, record := range snapshot.Records {
		if record.Table == table {
			out = append(out, record)
		}
	}
	return out
}
func originalHostSQLString(record hostOriginalSQLRecord, key string) string {
	var s string
	if json.Unmarshal(record.indices[key], &s) != nil {
		return ""
	}
	return s
}

// SAME live capability + original DB read only. The returned snapshot is
// PARTIAL_PRE_CLOSE even on success; Main owns the later outer returns.
func (s CapacityStore) VerifyOriginalHostLiveReadonlyCorpus(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, publicRunID string) ([]byte, error) {
	codec := originalHostSourceCodecRealm(ctx, realm)

	installed, approval, ok := OriginalHostFactoryRealm()
	if ctx == nil || ctx.Err() != nil || !ok || realm == nil || installed != realm || s.DB == nil || !validCapacityExecutor(publicRunID) || realm.VerifyLive(ctx) != nil {
		return nil, ErrHostFactoryHold
	}
	actual, e := realm.Approval(ctx)
	a, e1 := codec.Canonical(actual)
	b, e2 := codec.Canonical(approval)
	if e != nil || e1 != nil || e2 != nil || !bytes.Equal(a, b) {
		return nil, ErrHostFactoryHold
	}
	attempt, owner, class, e := realm.OriginalRootIdentity(ctx)
	if e != nil || class != hostFactoryClass {
		return nil, ErrHostFactoryHold
	}
	stages, e := realm.OriginalRootStages(ctx)
	if e != nil {
		return nil, e
	}
	prepRaw, e := originalHostStageBody(codec, "root-preparation", stages["root-preparation"], &model.HostFactoryRootPreparation{})
	var prep model.HostFactoryRootPreparation
	if e != nil || codec.Decode(prepRaw, &prep) != nil {
		return nil, ErrHostFactoryHold
	}
	snapshot := hostOriginalSQLSnapshot{Schema: "source_owned_host_factory_sql_read_snapshot_v1", RootID: approval.ScopeRootID, NativeFactoryRootID: prep.FactoryRootID, FactoryAttemptID: attempt, CreatorOwnerID: owner, EntryClass: prep.FactoryEntryClass, SourceApprovalBodySHA256: capacity.HostFactoryRawSHA256(a), RootPreparationBodySHA256: capacity.HostFactoryRawSHA256(prepRaw), PublicRunID: publicRunID, CoreActualSourceCommit: capacity.CurrentGuestCoreSource(), OriginalContextDeadline: prep.OriginalContextDeadline, Records: []hostOriginalSQLRecord{}}
	// The original private early binding is fixed BEFORE the first SQL read.
	if prep.FactoryEntryClass == "ordinary_original_create" {
		installedHostFactory.Lock()
		var held *hostOriginalOrdinaryFactory
		for _, candidate := range installedHostFactory.ordinaryFactories {
			if candidate != nil && candidate.realm == realm && candidate.binding.FactoryAttemptID == attempt {
				if held != nil {
					installedHostFactory.Unlock()
					return nil, ErrHostFactoryHold
				}
				held = candidate
			}
		}
		installedHostFactory.Unlock()
		if held == nil {
			return nil, ErrHostFactoryHold
		}
		held.mu.Lock()
		if !held.issueCommitted || !held.issueCaptured || held.issueReturnErr != nil || !held.continued || held.continueErr != nil || len(held.nativeRaw) == 0 {
			held.mu.Unlock()
			return nil, ErrHostFactoryHold
		}
		snapshot.StableTargetSHA256 = held.binding.StableOriginalTargetSHA256
		snapshot.PrivateBindingSchema = held.binding.Schema
		snapshot.PrivateBindingSHA256 = capacity.HostFactoryRawSHA256(held.bindingRaw)
		snapshot.OriginalInvocationID = held.claim.invocation
		snapshot.OriginalContextDeadline = held.binding.OriginalContextDeadline
		held.mu.Unlock()
	} else {
		body, e := realm.OriginalAuthorityBody(ctx, "preauthority-scope")
		var scope model.HostFactoryPreAuthorityScope
		if e != nil || codec.Decode(body, &scope) != nil || scope.FactoryAttemptID != attempt || scope.CreatorOwnerID != owner || scope.ScopeRootID != approval.ScopeRootID {
			return nil, ErrHostFactoryHold
		}
		snapshot.StableTargetSHA256 = scope.StableOriginalTargetSHA256
		snapshot.PrivateBindingSchema = scope.Schema
		snapshot.PrivateBindingSHA256 = capacity.HostFactoryRawSHA256(body)
		snapshot.OriginalInvocationID = scope.ExecutorID
		snapshot.OriginalContextDeadline = scope.OriginalContextDeadline
	}
	if snapshot.OriginalInvocationID == publicRunID {
		return nil, ErrHostFactoryHold
	}
	bounded, cancel := context.WithDeadline(ctx, snapshot.OriginalContextDeadline)
	defer cancel()
	owningDeadline, hasBound := bounded.Deadline()
	if !hasBound || !time.Now().Before(owningDeadline) {
		return nil, ErrHostFactoryHold
	}
	called := time.Now().UTC()
	err := s.readOriginalHostLiveSQLSnapshot(bounded, realm, &snapshot)
	returned := time.Now().UTC() // actual helper GoReturn, never a future Main return
	snapshot.SQLReadCalledAt, snapshot.SQLReadReturnedAt = called, returned
	if err != nil || returned.Before(called) || !returned.Before(snapshot.OriginalContextDeadline) || !returned.Before(owningDeadline) || bounded.Err() != nil {
		return nil, errors.Join(err, ErrHostFactoryHold)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil || len(raw) > 32*1024*1024 || bounded.Err() != nil || !time.Now().Before(owningDeadline) {
		return nil, ErrHostFactoryHold
	}
	return raw, nil
}

func (s CapacityStore) readOriginalHostLiveSQLSnapshot(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, snapshot *hostOriginalSQLSnapshot) error {
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	provenance, _, err := realm.OriginalLeaseProvenance(ctx, snapshot.OriginalInvocationID)
	if err != nil || provenance.FactoryRootID != snapshot.NativeFactoryRootID || provenance.RootPreparationSHA256 != snapshot.RootPreparationBodySHA256 || provenance.CoreActualSourceCommit != snapshot.CoreActualSourceCommit {
		return ErrHostFactoryHold
	}
	snapshot.PolicyID, snapshot.PolicyChecksum = provenance.ActualPolicyID, provenance.ActualPolicyChecksum
	snapshot.WorkflowID, snapshot.WorkflowChecksum = provenance.ActualWorkflowID, provenance.ActualWorkflowChecksum
	args := []any{snapshot.RootID, snapshot.PublicRunID, snapshot.PolicyID, snapshot.WorkflowID}
	total := 0
	for _, table := range originalHostSQLTables {
		if err = originalHostSQLReadTable(ctx, tx, table, args, snapshot, &total); err != nil {
			return err
		}
	}
	run, runErr := originalHostSnapshotSingleton(*snapshot, "public.workflow_runs")
	if runErr != nil {
		return runErr
	}
	snapshot.PublicRunStatus = originalHostSQLString(run, "status")
	if err = verifyOriginalHostSQLSnapshotTx(ctx, tx, realm, *snapshot, provenance); err != nil {
		return err
	}
	return tx.Commit()
}

func originalHostSnapshotSingleton(snapshot hostOriginalSQLSnapshot, table string) (hostOriginalSQLRecord, error) {
	rows := originalHostSQLRecords(snapshot, table)
	if len(rows) != 1 {
		return hostOriginalSQLRecord{}, ErrHostFactoryHold
	}
	return rows[0], nil
}

func verifyOriginalHostSQLSnapshotTx(ctx context.Context, tx *sql.Tx, realm *capacityhostfactory.OriginalFactoryRealm, snapshot hostOriginalSQLSnapshot, provenance model.HostFactoryOriginalLeaseProvenance) error {
	codec := originalHostSourceCodecTx(ctx, tx, snapshot.RootID)

	root, err := originalHostSnapshotSingleton(snapshot, "public.capacity_host_factory_roots")
	if err != nil {
		return err
	}
	var approval model.HostFactorySourceApproval
	var preparation model.HostFactoryRootPreparation
	if codec.Decode(root.original["source_approval_wire"], &approval) != nil || codec.Decode(root.original["root_preparation_wire"], &preparation) != nil || capacity.HostFactoryRawSHA256(root.original["source_approval_wire"]) != snapshot.SourceApprovalBodySHA256 || capacity.HostFactoryRawSHA256(root.original["root_preparation_wire"]) != snapshot.RootPreparationBodySHA256 || approval.ScopeRootID != snapshot.RootID || preparation.FactoryRootID != snapshot.NativeFactoryRootID || preparation.FactoryEntryClass != snapshot.EntryClass || originalHostSQLString(root, "factory_attempt_id") != snapshot.FactoryAttemptID || originalHostSQLString(root, "creator_owner_id") != snapshot.CreatorOwnerID || originalHostSQLString(root, "factory_registry_class") != hostFactoryClass {
		return ErrHostFactoryHold
	}
	lease, err := originalHostSnapshotSingleton(snapshot, "public.capacity_host_factory_leases")
	if err != nil {
		return err
	}
	var original model.CapacityIntent
	if json.Unmarshal(lease.original["original_intent_wire"], &original) != nil || capacity.HostFactoryRawSHA256(lease.original["original_intent_wire"]) != provenance.OriginalClaimIntentRawSHA256 || capacity.HostFactoryRawSHA256(lease.original["original_assessment_wire"]) != provenance.OriginalAssessmentSHA256 || capacity.HostFactoryRawSHA256(lease.original["initial_empty_wire"]) != provenance.InitialEmptyRealmReadSHA256 || original.PolicyID.String() != snapshot.PolicyID || original.PolicyChecksum != snapshot.PolicyChecksum || original.LeaseExecutorID != snapshot.OriginalInvocationID || original.Generation != provenance.Generation || original.FencingToken != provenance.Fence || original.LeaseExpiresAt == nil || !original.LeaseExpiresAt.Equal(provenance.OriginalLeaseExpiresAt) || capacity.HostFactoryRawSHA256([]byte(original.LeaseOwner)) != provenance.LeaseOwnerSHA256 {
		return ErrHostFactoryHold
	}
	var currentRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, original.Namespace, original.Environment, original.Domain, original.Dimension).Scan(&currentRaw); err != nil {
		return err
	}
	var current model.CapacityIntent
	if len(currentRaw) > 65536 || json.Unmarshal(currentRaw, &current) != nil || current.PolicyID != original.PolicyID || current.PolicyChecksum != original.PolicyChecksum || current.Generation != original.Generation || current.FencingToken != original.FencingToken || current.LeaseExecutorID != original.LeaseExecutorID || current.LeaseOwner != original.LeaseOwner || current.LeaseExpiresAt == nil || !current.LeaseExpiresAt.Equal(*original.LeaseExpiresAt) || current.RecoveryOnly {
		return ErrHostFactoryHold
	}
	owner, err := originalHostSnapshotSingleton(snapshot, "public.capacity_host_factory_owners")
	if err != nil {
		return err
	}
	var awaiting hostOriginalAwaitingRecord
	if len(owner.original["awaiting_wire"]) == 0 || len(owner.original["awaiting_wire"]) > 65536 || json.Unmarshal(owner.original["awaiting_wire"], &awaiting) != nil || awaiting.RootID != snapshot.RootID || awaiting.NativeFactoryRootID != snapshot.NativeFactoryRootID || awaiting.FactoryAttemptID != snapshot.FactoryAttemptID || awaiting.CreatorOwnerID != snapshot.CreatorOwnerID || awaiting.OriginalInvocationID != snapshot.OriginalInvocationID || awaiting.OriginalClaimIntentRawSHA256 != provenance.OriginalClaimIntentRawSHA256 || awaiting.StableTargetSHA256 != snapshot.StableTargetSHA256 || awaiting.EntryClass != snapshot.EntryClass || !awaiting.OriginalContextDeadline.Equal(snapshot.OriginalContextDeadline) || awaiting.ExecutorID != original.LeaseExecutorID || awaiting.Generation != original.Generation || awaiting.Fence != original.FencingToken || awaiting.LeaseOwnerSHA256 != provenance.LeaseOwnerSHA256 || !awaiting.OriginalLeaseExpiresAt.Equal(provenance.OriginalLeaseExpiresAt) || originalHostSQLString(owner, "state") != "registered" || capacity.HostFactoryRawSHA256(owner.original["awaiting_wire"]) != originalHostSQLString(owner, "awaiting_sha256") {
		return ErrHostFactoryHold
	}
	if capacity.HostFactoryRawSHA256(owner.original["prepared_plan_wire"]) != originalHostSQLString(owner, "prepared_plan_sha256") || len(owner.original["native_registration_wire"]) == 0 {
		return ErrHostFactoryHold
	}
	target, err := originalHostSnapshotSingleton(snapshot, "public.capacity_host_factory_stable_targets")
	if err != nil {
		return err
	}
	stable, e := base64.StdEncoding.Strict().DecodeString(awaiting.StableTargetWireBase64)
	if e != nil || !bytes.Equal(stable, target.original["target_wire"]) || capacity.HostFactoryRawSHA256(stable) != snapshot.StableTargetSHA256 {
		return ErrHostFactoryHold
	}
	binding, err := originalHostSnapshotSingleton(snapshot, "public.capacity_host_factory_scopes")
	if err != nil || capacity.HostFactoryRawSHA256(binding.original["original_wire"]) != snapshot.PrivateBindingSHA256 || originalHostSQLString(binding, "binding_schema") != snapshot.PrivateBindingSchema {
		return ErrHostFactoryHold
	}
	policy, err := scanManifest(tx.QueryRowContext(ctx, `SELECT id,api_version,kind,namespace,name,version,active,description,labels,spec,checksum,created_at,updated_at FROM public.manifests WHERE id=$1`, snapshot.PolicyID))
	if err != nil {
		return err
	}
	workflow, err := scanManifest(tx.QueryRowContext(ctx, `SELECT id,api_version,kind,namespace,name,version,active,description,labels,spec,checksum,created_at,updated_at FROM public.manifests WHERE id=$1`, snapshot.WorkflowID))
	if err != nil {
		return err
	}
	workflowSpec, err := manifest.ParseWorkflowSpec(workflow.Spec)
	if err != nil {
		return err
	}
	var assessStep, claimStep, provisionStep model.WorkflowStepSpec
	for _, step := range workflowSpec.Steps {
		switch step.ID {
		case approval.AllowedAssessStepID:
			assessStep = step
		case approval.AllowedClaimStepID:
			claimStep = step
		case approval.AllowedOriginalStepID:
			provisionStep = step
		}
	}
	if policy.Checksum != snapshot.PolicyChecksum || workflow.Checksum != snapshot.WorkflowChecksum || policy.ID.String() != approval.AllowedPolicyID || workflow.ID.String() != approval.AllowedWorkflowID || !policy.Metadata.Active || !workflow.Metadata.Active || policy.Metadata.Namespace != approval.AllowedNamespace || workflow.Metadata.Namespace != approval.AllowedNamespace {
		return ErrHostFactoryHold
	}
	if realm != nil {
		if realm.VerifyOriginalPolicyInput(ctx, policy, workflow, assessStep, claimStep, provisionStep) != nil {
			return ErrHostFactoryHold
		}
	} else {
		// Compare the full actual typed SQL returns with the same compiled
		// approved logical inventory. JSONB rendering is not original Source
		// bytes, and this cacheless comparison recreates no live capability.
		if capacityhostfactory.VerifyOriginalHistoricalPolicyInput(ctx, policy, workflow, assessStep, claimStep, provisionStep) != nil {
			return ErrHostFactoryHold
		}
	}
	run, err := originalHostSnapshotSingleton(snapshot, "public.workflow_runs")
	if err != nil {
		return err
	}
	var result model.RunWorkflowResponse
	if originalHostSQLString(run, "workflow_id") != snapshot.WorkflowID || json.Unmarshal(run.indices["result"], &result) != nil || result.Status != originalHostSQLString(run, "status") {
		return ErrHostFactoryHold
	}
	snapshotStatus := originalHostSQLString(run, "status")
	if snapshotStatus != "succeeded" && snapshotStatus != "failed" {
		return ErrHostFactoryHold
	}
	claimCount := 0
	original.LeaseExecutorID = ""
	for _, step := range result.Steps {
		if step.ID == approval.AllowedClaimStepID {
			claimCount++
			raw, e := json.Marshal(step.Metadata)
			var projected model.CapacityIntent
			if e != nil || step.Operation != "capacity.claim" || step.Kind != "yggdrasil" || step.Status != "succeeded" || step.Attempts != 1 || json.Unmarshal(raw, &projected) != nil || !reflect.DeepEqual(projected, original) || step.StartedAt.After(provenance.OriginalClaimReturnedAt) || step.FinishedAt.Before(provenance.OriginalClaimReturnedAt) {
				return ErrHostFactoryHold
			}
		}
	}
	if claimCount != 1 {
		return ErrHostFactoryHold
	}
	// Authenticate every actual retained envelope before graph/scalar use.
	for _, record := range snapshot.Records {
		if record.PublicEnvelopeBase64 == nil {
			continue
		}
		envelope := record.original["raw_envelope_wire"]
		var rootEnvelope model.HostFactoryRootSignedEnvelope
		var scopeEnvelope capacity.HostFactorySourceSignedEnvelope
		selector := HostFactoryRecordSelector{RootID: snapshot.RootID, Family: "root"}
		if codec.Decode(envelope, &rootEnvelope) == nil {
			selector.Role, selector.BindingSchema, selector.BindingSHA256 = rootEnvelope.Role, rootEnvelope.BindingSchema, rootEnvelope.BindingSHA256
		} else if codec.Decode(envelope, &scopeEnvelope) == nil {
			selector.Family = "scope"
			selector.ScopeSHA256 = scopeEnvelope.PreAuthorityScopeSHA256
			selector.Role = scopeEnvelope.Role
			selector.BindingSchema = "original_host_factory_pre_authority_scope_v4"
			selector.BindingSHA256 = scopeEnvelope.PreAuthorityScopeSHA256
		} else {
			return ErrHostFactoryHold
		}
		if record.Table == "public.capacity_host_factory_stage_returns" {
			selector.Stage = originalHostSQLString(record, "stage")
		}
		if record.Table == "public.capacity_host_factory_io_returns" {
			selector.Kind = originalHostSQLString(record, "record_kind")
			if selector.Kind == "handle-inventory" {
				selector.Kind = "inventory"
			}
			selector.OwnerID = originalHostSQLString(record, "original_owner_id")
			if selector.Kind == "native-record" || selector.Kind == "native-manifest" {
				selector.RawBodySHA256 = originalHostSQLString(record, "raw_body_sha256")
				selector.RawEnvelopeSHA256 = originalHostSQLString(record, "raw_envelope_sha256")
			}
			selector.HandleID = originalHostSQLString(record, "original_handle_id")
			selector.CollectionID = originalHostSQLString(record, "failure_collection_id")
			if part := record.indices["part_ordinal"]; string(part) != "null" {
				if json.Unmarshal(part, &selector.PartOrdinal) != nil {
					return ErrHostFactoryHold
				}
			}
		}
		body, raw, stage, e := decodeOriginalHostEnvelope(codec, selector, envelope)
		if e != nil || !bytes.Equal(raw, record.original["raw_body_wire"]) || capacity.HostFactoryRawSHA256(raw) != originalHostSQLString(record, "raw_body_sha256") || capacity.HostFactoryRawSHA256(envelope) != originalHostSQLString(record, "raw_envelope_sha256") {
			return ErrHostFactoryHold
		}
		if realm != nil {
			if realm.VerifyOriginalStage(ctx, stage, envelope) != nil {
				return ErrHostFactoryHold
			}
		} else {
			if selector.Kind == "failure-part" {
				stage = "failure-collections/" + selector.CollectionID + "/parts/" + strconv.FormatUint(uint64(selector.PartOrdinal), 10) + "/" + capacity.HostFactoryRawSHA256(raw)
			}
			if capacityhostfactory.VerifyOriginalHistoricalStage(ctx, stage, envelope) != nil {
				return ErrHostFactoryHold
			}
		}
		if selector.Stage != "" {
			if realm != nil {
				_, err = validateOriginalHostNativeAggregateTx(ctx, tx, snapshot.RootID, selector.BindingSchema, selector.BindingSHA256, body, envelope)
			} else {
				err = validateOriginalHostHistoricalNativeAggregateTx(ctx, tx, snapshot.RootID, selector.BindingSchema, selector.BindingSHA256, body, envelope)
			}
			if err != nil {
				return err
			}
			if err = validateOriginalHostStageVectorsTx(ctx, tx, snapshot.RootID, body); err != nil {
				return err
			}
			if err = compareOriginalHostPostStartStoredTx(ctx, tx, selector, body, raw, envelope, realm != nil); err != nil {
				return err
			}
		}
		if observation, ok := body.(*model.HostFactoryNativeObservationRecord); ok {
			if validateOriginalHostNativeStoredRecordTx(ctx, tx, snapshot.RootID, *observation, record.original["native_inventory_relations_wire"]) != nil {
				return ErrHostFactoryHold
			}
		}
		if inventory, ok := body.(*model.HostFactoryHandleCallInventory); ok {
			identity, e := originalHostIOIdentity(codec, snapshot.RootID, inventory, raw)
			if e != nil || inventory.CollectionState != "complete_original_calls" || validateOriginalHostInventoryTx(ctx, tx, identity, *inventory) != nil {
				return ErrHostFactoryHold
			}
		}
	}
	grants := originalHostSQLRecords(snapshot, "public.capacity_factory_original_grant_bindings")
	if snapshot.EntryClass == "sealed_a0" {
		if len(grants) != 0 {
			return ErrHostFactoryHold
		}
	} else {
		if len(grants) != 1 {
			return ErrHostFactoryHold
		}
		var originalGrant capacityMutationRecord
		var pre model.CapacityGuestOriginalProvisioningPreregistration
		if json.Unmarshal(grants[0].original["original_grant_wire"], &originalGrant) != nil || json.Unmarshal(grants[0].original["original_preregistration_wire"], &pre) != nil || originalGrant.ExecutorID != snapshot.OriginalInvocationID || originalGrant.PolicyID.String() != snapshot.PolicyID || originalGrant.WorkflowID.String() != snapshot.WorkflowID || originalGrant.Generation != provenance.Generation || originalGrant.FencingToken != provenance.Fence || pre.OriginalCreateGrantID != originalGrant.Grant.GrantID || capacity.HostFactoryRawSHA256(grants[0].original["original_grant_wire"]) != originalHostSQLString(grants[0], "original_grant_sha256") || capacity.HostFactoryRawSHA256(grants[0].original["original_preregistration_wire"]) != originalHostSQLString(grants[0], "original_preregistration_sha256") {
			return ErrHostFactoryHold
		}
		currentGrant, err := originalHostSnapshotSingleton(snapshot, "public.capacity_mutation_grants")
		if err != nil {
			return err
		}
		var grant capacityMutationRecord
		if json.Unmarshal(currentGrant.indices["grant_record"], &grant) != nil || grant.ExecutorID != originalGrant.ExecutorID || grant.Generation != originalGrant.Generation || grant.FencingToken != originalGrant.FencingToken || grant.LeaseOwner != originalGrant.LeaseOwner || !reflect.DeepEqual(grant.Binding, originalGrant.Binding) || grant.Grant.GrantID != originalGrant.Grant.GrantID {
			return ErrHostFactoryHold
		}
		if snapshot.EntryClass == "ordinary_original_create" {
			native, err := originalHostSnapshotSingleton(snapshot, "public.capacity_guest_qualification_native_source_returns")
			if err != nil {
				return err
			}
			if snapshotStatus != "succeeded" || grant.Grant.State != "confirmed" || grant.Proof == nil || grant.Settlement == nil || grant.AttemptID == "" || len(native.original["original_wire"]) == 0 || originalHostSQLString(native, "return_sha256") != capacity.HostFactoryRawSHA256(native.original["original_wire"]) {
				return ErrHostFactoryHold
			}
			if _, err = originalHostSnapshotSingleton(snapshot, "public.capacity_guest_original_create_witnesses"); err != nil {
				return err
			}
			if _, err = originalHostSnapshotSingleton(snapshot, "public.capacity_vm_original_enrollments"); err != nil {
				return err
			}
			if realm != nil {
				if realm.VerifyOriginalOrdinaryCreateReturn(ctx, grant.Grant, pre, *grant.Proof, native.original["original_wire"]) != nil {
					return ErrHostFactoryHold
				}
			} else if verifyOriginalHostHistoricalOrdinaryTx(ctx, tx, snapshot, grant, pre, native.original["original_wire"]) != nil {
				return ErrHostFactoryHold
			}
		} else if snapshotStatus != "failed" || grant.Grant.State != "issued" || grant.AttemptID != "" || grant.Settlement != nil || grant.Proof != nil {
			return ErrHostFactoryHold
		}
	}
	if snapshot.EntryClass != "ordinary_original_create" {
		if snapshotStatus != "failed" {
			return ErrHostFactoryHold
		}
		disposition, err := originalHostSnapshotSingleton(snapshot, "public.capacity_host_factory_dispositions")
		if err != nil {
			return err
		}
		reservation, err := originalHostSnapshotSingleton(snapshot, "public.capacity_host_factory_sealed_reservations")
		if err != nil || originalHostSQLString(reservation, "branch") != snapshot.EntryClass || originalHostSQLString(disposition, "branch") != snapshot.EntryClass {
			return ErrHostFactoryHold
		}
		var scope model.HostFactoryPreAuthorityScope
		var registration model.HostFactoryAliveRegistration
		registrationRow, err := originalHostSnapshotSingleton(snapshot, "public.capacity_host_factory_registrations")
		if err != nil {
			return err
		}
		if codec.Decode(binding.original["original_wire"], &scope) != nil || codec.Decode(registrationRow.original["original_wire"], &registration) != nil {
			return ErrHostFactoryHold
		}
		var attachment []byte
		stage := "unissued-disposition"
		if snapshot.EntryClass == "sealed_a1" {
			stage = "issued-disposition"
			attached, err := originalHostSnapshotSingleton(snapshot, "public.capacity_host_factory_issued_attachments")
			if err != nil {
				return err
			}
			attachment = attached.original["original_wire"]
		}
		if err = validateOriginalHostDispositionTx(ctx, tx, scope, binding.original["original_wire"], registration, attachment, disposition.original["original_wire"], stage); err != nil {
			return err
		}
	}
	return nil
}

// Closed private corpus handoff; these projections carry NO authority.
type hostOriginalSubjectIdentity struct {
	SubjectKind     string  `json:"subject_kind"`
	RequestIdentity *string `json:"request_identity"`
	PublicRunID     *string `json:"public_run_id"`
	Method          *string `json:"method"`
	PathFamily      *string `json:"path_family"`
}
type hostOriginalSourceAuditProjection struct {
	Family                 string                             `json:"family"`
	SubjectIdentity        hostOriginalSubjectIdentity        `json:"subject_identity"`
	Fact                   model.HostFactorySourceAuditReturn `json:"fact"`
	OriginalCloseReference *string                            `json:"original_close_reference"`
}
type hostOriginalMainReturn struct {
	Family                    string                      `json:"family"`
	Schema                    string                      `json:"schema"`
	Operation                 string                      `json:"operation"`
	OriginalOwnerID           string                      `json:"original_owner_id"`
	SubjectIdentity           hostOriginalSubjectIdentity `json:"subject_identity"`
	OriginalHandleID          string                      `json:"original_handle_id"`
	OriginalCallID            *string                     `json:"original_call_id"`
	OriginalState             string                      `json:"original_state"`
	OriginalCalledAt          *time.Time                  `json:"original_called_at"`
	OriginalReturnedAt        *time.Time                  `json:"original_returned_at"`
	OriginalOperationDeadline time.Time                   `json:"original_operation_deadline"`
	OriginalErrorPresent      *bool                       `json:"original_error_present"`
	OriginalReturnClass       *string                     `json:"original_return_class"`
	ActualOwnerJoinState      string                      `json:"actual_owner_join_state"`
	SourceAuditCallReferences []string                    `json:"source_audit_call_references"`
}
type hostOriginalCorpusSourceIdentity struct {
	ScopeRootID              string `json:"scope_root_id"`
	NativeFactoryRootID      string `json:"native_factory_root_id"`
	FactoryAttemptID         string `json:"factory_attempt_id"`
	CreatorOwnerID           string `json:"creator_owner_id"`
	EntryClass               string `json:"entry_class"`
	StableTargetSHA256       string `json:"stable_target_sha256"`
	SourceApprovalBodySHA256 string `json:"source_approval_body_sha256"`
	ApprovedPeerSourceCODE   string `json:"approved_peer_source_code"`
	ActualBuildSourceCommit  string `json:"actual_build_source_commit"`
}
type hostOriginalCorpusContext struct {
	OriginalStartedAt       time.Time `json:"original_started_at"`
	OriginalDeadline        time.Time `json:"original_deadline"`
	OriginalCleanupDeadline time.Time `json:"original_cleanup_deadline"`
}
type hostOriginalCorpusCaller struct {
	RequestID       *string `json:"request_id"`
	PublicRunID     string  `json:"public_run_id"`
	PublicRunStatus string  `json:"public_run_status"`
}
type hostOriginalFinalCorpus struct {
	Schema                      string                           `json:"schema"`
	EvidenceClass               string                           `json:"evidence_class"`
	SourceIdentity              hostOriginalCorpusSourceIdentity `json:"source_identity"`
	OriginalContext             hostOriginalCorpusContext        `json:"original_context"`
	PublicCallerIdentity        hostOriginalCorpusCaller         `json:"public_caller_identity"`
	PrecloseSQLSnapshotBase64   string                           `json:"preclose_sql_snapshot_base64"`
	PrecloseSQLSnapshotSHA256   string                           `json:"preclose_sql_snapshot_sha256"`
	RealmCompletionBundleBase64 string                           `json:"realm_completion_bundle_base64"`
	RealmCompletionBundleSHA256 string                           `json:"realm_completion_bundle_sha256"`
	MainOwnerReturns            []json.RawMessage                `json:"main_owner_returns"`
	PublicationReturnReference  *string                          `json:"publication_return_reference"`
}
type hostOriginalRealmFactReference struct {
	BindingSchema                     string                               `json:"binding_schema"`
	BindingSHA256                     string                               `json:"binding_sha256"`
	ChunkBodySHA256                   string                               `json:"chunk_body_sha256"`
	FactIndex                         uint32                               `json:"fact_index"`
	OriginalCallVector                model.HostFactoryCallVectorReference `json:"original_call_vector"`
	OriginalHandleInventoryBodySHA256 *string                              `json:"original_handle_inventory_body_sha256"`
}
type hostOriginalRealmLocalReturn struct {
	EvidenceClass             string                             `json:"evidence_class"`
	OriginalCallID            *string                            `json:"original_call_id"`
	OriginalCallOrdinal       *uint64                            `json:"original_call_ordinal"`
	OriginalCalledAt          *time.Time                         `json:"original_called_at"`
	OriginalReturnedAt        *time.Time                         `json:"original_returned_at"`
	OriginalOperationDeadline time.Time                          `json:"original_operation_deadline"`
	OriginalErrorPresent      *bool                              `json:"original_error_present"`
	OriginalReturnClass       *string                            `json:"original_return_class"`
	OriginalCount             *int64                             `json:"original_count"`
	OriginalSHA256            *string                            `json:"original_sha256"`
	OriginalHashState         string                             `json:"original_hash_state"`
	OriginalEOF               *bool                              `json:"original_eof"`
	OriginalScalar            *int64                             `json:"original_scalar"`
	OriginalErrno             *uint32                            `json:"original_errno"`
	OriginalStat              *model.HostFactoryNativeStatReturn `json:"original_stat"`
}
type hostOriginalRealmOwnerReturn struct {
	Schema                string                              `json:"schema"`
	OwnerRole             string                              `json:"owner_role"`
	SubjectRole           string                              `json:"subject_role"`
	OriginalOwnerID       string                              `json:"original_owner_id"`
	SubjectOwnerID        string                              `json:"subject_owner_id"`
	OriginalHandleID      string                              `json:"original_handle_id"`
	Operation             string                              `json:"operation"`
	OriginalState         string                              `json:"original_state"`
	OriginalFactReference *hostOriginalRealmFactReference     `json:"original_fact_reference"`
	OriginalFact          *model.HostFactoryPrimitiveIOReturn `json:"original_fact"`
	OriginalLocalReturn   *hostOriginalRealmLocalReturn       `json:"original_local_return"`
}
type hostOriginalRealmCorpus struct {
	Schema                       string                         `json:"schema"`
	RootCompletionBodyBase64     string                         `json:"root_completion_body_base64"`
	RootCompletionEnvelopeBase64 string                         `json:"root_completion_envelope_base64"`
	Stages                       map[string]string              `json:"stages"`
	OriginalRealmOwnerReturns    []hostOriginalRealmOwnerReturn `json:"original_realm_owner_returns"`
}

func hostOriginalStrictJSON(raw []byte, target any, limit int) error {
	if len(raw) == 0 || len(raw) > limit {
		return ErrHostFactoryHold
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 32 {
			return ErrHostFactoryHold
		}
		token, e := decoder.Token()
		if e != nil {
			return e
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				seen := map[string]bool{}
				for decoder.More() {
					key, e := decoder.Token()
					name, ok := key.(string)
					if e != nil || !ok || seen[name] {
						return ErrHostFactoryHold
					}
					seen[name] = true
					if e = scan(depth + 1); e != nil {
						return e
					}
				}
				end, e := decoder.Token()
				if e != nil || end != json.Delim('}') {
					return ErrHostFactoryHold
				}
			case '[':
				for decoder.More() {
					if e = scan(depth + 1); e != nil {
						return e
					}
				}
				end, e := decoder.Token()
				if e != nil || end != json.Delim(']') {
					return ErrHostFactoryHold
				}
			default:
				return ErrHostFactoryHold
			}
		}
		return nil
	}
	if scan(0) != nil {
		return ErrHostFactoryHold
	}
	if _, e := decoder.Token(); e != io.EOF {
		return ErrHostFactoryHold
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		return ErrHostFactoryHold
	}
	return hostOriginalJSONShape(raw, reflect.TypeOf(target).Elem(), 0)
}
func hostOriginalJSONShape(raw []byte, t reflect.Type, depth int) error {
	if depth > 32 {
		return ErrHostFactoryHold
	}
	if t == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	if t.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return hostOriginalJSONShape(raw, t.Elem(), depth+1)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return ErrHostFactoryHold
	}
	if t == reflect.TypeOf(time.Time{}) {
		var text string
		var at time.Time
		if json.Unmarshal(raw, &text) != nil || json.Unmarshal(raw, &at) != nil || at.IsZero() || text != at.UTC().Format(time.RFC3339Nano) {
			return ErrHostFactoryHold
		}
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			return ErrHostFactoryHold
		}
		expected := 0
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if field.PkgPath != "" {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")
			name := tag[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			value, ok := fields[name]
			if !ok {
				// Existing nested SDK bindings retain their literal omitempty
				// contract. The private wrapper/SourceAudit required nullable
				// fields have no such tag and still must be present.
				optional := false
				for _, option := range tag[1:] {
					optional = optional || option == "omitempty"
				}
				if optional {
					continue
				}
			}
			expected++
			if !ok || hostOriginalJSONShape(value, field.Type, depth+1) != nil {
				return ErrHostFactoryHold
			}
		}
		if len(fields) != expected {
			return ErrHostFactoryHold
		}
	case reflect.Slice, reflect.Array:
		var elements []json.RawMessage
		if json.Unmarshal(raw, &elements) != nil {
			return ErrHostFactoryHold
		}
		if t.Kind() == reflect.Array && len(elements) != t.Len() {
			return ErrHostFactoryHold
		}
		for _, value := range elements {
			if hostOriginalJSONShape(value, t.Elem(), depth+1) != nil {
				return ErrHostFactoryHold
			}
		}
	case reflect.Map:
		var values map[string]json.RawMessage
		if json.Unmarshal(raw, &values) != nil {
			return ErrHostFactoryHold
		}
		for key, value := range values {
			if len(key) > 4096 || hostOriginalJSONShape(value, t.Elem(), depth+1) != nil {
				return ErrHostFactoryHold
			}
		}
	case reflect.String:
		var text string
		if json.Unmarshal(raw, &text) != nil || len(text) > 64*1024*1024 {
			return ErrHostFactoryHold
		}
	}
	return nil
}

func hostOriginalCorpusBytes(encoded, sha string, limit int) ([]byte, error) {
	if len(encoded) > ((limit+2)/3)*4 || !capacity.ValidDigest(sha) {
		return nil, ErrHostFactoryHold
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) > limit || base64.StdEncoding.EncodeToString(raw) != encoded || capacity.HostFactoryRawSHA256(raw) != sha {
		return nil, ErrHostFactoryHold
	}
	return raw, nil
}

// Historical authentication creates no Realm, opens no private directory and
// installs no keys. The separate test binary must have the SAME actual clean
// compiled source epoch as the original fixture, never an artifact label.
func (s CapacityStore) VerifyOriginalHostHistoricalCorpus(ctx context.Context, raw []byte) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrHostFactoryHold
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || !time.Now().Before(deadline) {
		return ErrHostFactoryHold
	}
	approval, err := capacity.ApprovedHostFactorySource()
	if err != nil || s.DB == nil || approval.ActualBuildSourceCommit != capacity.CurrentGuestCoreSource() {
		return ErrHostFactoryHold
	}
	var wrapper hostOriginalFinalCorpus
	if hostOriginalStrictJSON(raw, &wrapper, 64*1024*1024) != nil || wrapper.Schema != "source_owned_host_factory_final_corpus_v1" || wrapper.EvidenceClass != "source_owned_historical_returns_no_native_permission_or_old45_closure" || wrapper.PublicationReturnReference != nil || len(wrapper.MainOwnerReturns) == 0 || len(wrapper.MainOwnerReturns) > 65536 {
		return ErrHostFactoryHold
	}
	identity := wrapper.SourceIdentity
	approvalRaw, err := capacity.CanonicalHostFactory(approval)
	if err != nil || identity.ScopeRootID != approval.ScopeRootID || identity.SourceApprovalBodySHA256 != capacity.HostFactoryRawSHA256(approvalRaw) || identity.ApprovedPeerSourceCODE != approval.ApprovedPeerSourceCODE || identity.ActualBuildSourceCommit != approval.ActualBuildSourceCommit || !validCapacityExecutor(identity.FactoryAttemptID) || !validCapacityExecutor(identity.CreatorOwnerID) || !validCapacityExecutor(identity.NativeFactoryRootID) || !capacity.ValidDigest(identity.StableTargetSHA256) {
		return ErrHostFactoryHold
	}
	snapshotRaw, err := hostOriginalCorpusBytes(wrapper.PrecloseSQLSnapshotBase64, wrapper.PrecloseSQLSnapshotSHA256, 32*1024*1024)
	if err != nil {
		return err
	}
	var snapshot hostOriginalSQLSnapshot
	if hostOriginalStrictJSON(snapshotRaw, &snapshot, 32*1024*1024) != nil || snapshot.Schema != "source_owned_host_factory_sql_read_snapshot_v1" || len(snapshot.Records) > 32768 || snapshot.RootID != identity.ScopeRootID || snapshot.NativeFactoryRootID != identity.NativeFactoryRootID || snapshot.FactoryAttemptID != identity.FactoryAttemptID || snapshot.CreatorOwnerID != identity.CreatorOwnerID || snapshot.EntryClass != identity.EntryClass || snapshot.StableTargetSHA256 != identity.StableTargetSHA256 || snapshot.SourceApprovalBodySHA256 != identity.SourceApprovalBodySHA256 || snapshot.CoreActualSourceCommit != identity.ActualBuildSourceCommit || snapshot.PublicRunID != wrapper.PublicCallerIdentity.PublicRunID || snapshot.PublicRunStatus != wrapper.PublicCallerIdentity.PublicRunStatus || snapshot.PublicRunID == snapshot.OriginalInvocationID || !validCapacityExecutor(snapshot.PublicRunID) || !validCapacityExecutor(snapshot.OriginalInvocationID) || snapshot.SQLReadReturnedAt.Before(snapshot.SQLReadCalledAt) || !snapshot.SQLReadReturnedAt.Before(snapshot.OriginalContextDeadline) {
		return ErrHostFactoryHold
	}
	bundleRaw, err := hostOriginalCorpusBytes(wrapper.RealmCompletionBundleBase64, wrapper.RealmCompletionBundleSHA256, 32*1024*1024)
	if err != nil {
		return err
	}
	var bundle hostOriginalRealmCorpus
	if hostOriginalStrictJSON(bundleRaw, &bundle, 32*1024*1024) != nil || bundle.Schema != "source_owned_host_factory_realm_completion_bundle_v1" || len(bundle.Stages) > 32768 || len(bundle.OriginalRealmOwnerReturns) == 0 || len(bundle.OriginalRealmOwnerReturns) > 65536 {
		return ErrHostFactoryHold
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	codec := originalHostSourceCodecTx(ctx, tx, snapshot.RootID)
	if codec.err != nil {
		return codec.err
	}
	actual := snapshot
	actual.Records = []hostOriginalSQLRecord{}
	args := []any{snapshot.RootID, snapshot.PublicRunID, snapshot.PolicyID, snapshot.WorkflowID}
	total := 0
	for _, table := range originalHostSQLTables {
		if err = originalHostSQLReadTable(ctx, tx, table, args, &actual, &total); err != nil {
			return err
		}
	}
	actualByKey := map[string]hostOriginalSQLRecord{}
	for _, record := range actual.Records {
		key := record.Table + ":" + string(record.RowKey)
		if _, ok := actualByKey[key]; ok {
			return ErrHostFactoryHold
		}
		actualByKey[key] = record
	}
	seen := map[string]bool{}
	for _, record := range snapshot.Records {
		key := record.Table + ":" + string(record.RowKey)
		stored, ok := actualByKey[key]
		if !ok || seen[key] || !reflect.DeepEqual(record.RawFields, stored.RawFields) || !reflect.DeepEqual(record.PublicEnvelopeBase64, stored.PublicEnvelopeBase64) {
			return ErrHostFactoryHold
		}
		seen[key] = true
	}
	bodies := map[string][]byte{}
	typed := map[string]any{}
	selectors := map[string]string{}
	owners := map[string]string{}
	for selector, encoded := range bundle.Stages {
		if len(encoded) > ((65536+2)/3)*4 {
			return ErrHostFactoryHold
		}
		envelope, e := base64.StdEncoding.Strict().DecodeString(encoded)
		if e != nil || len(envelope) > 65536 || base64.StdEncoding.EncodeToString(envelope) != encoded || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, selector, envelope) != nil {
			return ErrHostFactoryHold
		}
		body, value, e := decodeOriginalHistoricalHostStage(codec, selector, envelope)
		if e != nil {
			return e
		}
		sha := capacity.HostFactoryRawSHA256(body)
		if prior, ok := bodies[sha]; ok && !bytes.Equal(prior, body) {
			return ErrHostFactoryHold
		}
		bodies[sha] = body
		typed[selector] = value
		selectors[sha] = selector
		if basal, ok := value.(*model.HostFactoryBasalOwnerObservation); ok {
			if basal.FactoryRootID != snapshot.NativeFactoryRootID || basal.SourceApprovalSHA256 != snapshot.SourceApprovalBodySHA256 || basal.ActualBinarySourceCommit != snapshot.CoreActualSourceCommit {
				return ErrHostFactoryHold
			}
			owners[basal.OriginalOwnerID] = basal.Role
		}
	}
	completionEnvelope, e := base64.StdEncoding.Strict().DecodeString(bundle.RootCompletionEnvelopeBase64)
	if e != nil || len(completionEnvelope) > 65536 || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, "root-completion", completionEnvelope) != nil {
		return ErrHostFactoryHold
	}
	completionBody, value, e := decodeOriginalHistoricalHostStage(codec, "root-completion", completionEnvelope)
	if e != nil {
		return e
	}
	declaredCompletion, e := base64.StdEncoding.Strict().DecodeString(bundle.RootCompletionBodyBase64)
	completion, ok := value.(*model.HostFactoryRootCompletion)
	if e != nil || !ok || !bytes.Equal(completionBody, declaredCompletion) || completion.RootPreparationSHA256 != snapshot.RootPreparationBodySHA256 {
		return ErrHostFactoryHold
	}
	prep, ok := typed["root-preparation"].(*model.HostFactoryRootPreparation)
	if !ok || capacity.HostFactoryRawSHA256(bodies[snapshot.RootPreparationBodySHA256]) != snapshot.RootPreparationBodySHA256 || !prep.OriginalContextStartedAt.Equal(wrapper.OriginalContext.OriginalStartedAt) || !prep.OriginalContextDeadline.Equal(wrapper.OriginalContext.OriginalDeadline) || wrapper.OriginalContext.OriginalCleanupDeadline.After(prep.OriginalContextDeadline.Add(150*time.Second)) || wrapper.OriginalContext.OriginalCleanupDeadline.After(prep.OriginalContextStartedAt.Add(13*time.Minute)) {
		return ErrHostFactoryHold
	}
	lease, ok := typed["original-lease-provenance"].(*model.HostFactoryOriginalLeaseProvenance)
	if !ok || lease.OriginalProtectedInvocationID != snapshot.OriginalInvocationID {
		return ErrHostFactoryHold
	}
	if err = verifyOriginalHostSQLSnapshotTx(ctx, tx, nil, actual, *lease); err != nil {
		return err
	}
	// RootCompletion is signed after Main's actual resource returns. Its
	// closing call references resolve only against separately appended original
	// closing rows; no future row is inserted into the preclose snapshot.
	if err = validateOriginalHostStageVectorsTx(ctx, tx, snapshot.RootID, completion); err != nil {
		return err
	}
	seenInventories := map[string]bool{}
	for _, sha := range completion.OriginalHandleInventorySHAs {
		if seenInventories[sha] || !capacity.ValidDigest(sha) {
			return ErrHostFactoryHold
		}
		seenInventories[sha] = true
		var wire []byte
		if err = tx.QueryRowContext(ctx, `SELECT raw_body_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='handle-inventory' AND raw_body_sha256=$2`, snapshot.RootID, sha).Scan(&wire); err != nil {
			return ErrHostFactoryHold
		}
		var inventory model.HostFactoryHandleCallInventory
		if len(wire) > 65536 || capacity.HostFactoryRawSHA256(wire) != sha || codec.Decode(wire, &inventory) != nil {
			return ErrHostFactoryHold
		}
		x, e := originalHostIOIdentity(codec, snapshot.RootID, &inventory, wire)
		if e != nil || inventory.CollectionState != "complete_original_calls" || validateOriginalHostInventoryTx(ctx, tx, x, inventory) != nil {
			return ErrHostFactoryHold
		}
		if _, exists := selectors[sha]; !exists {
			return ErrHostFactoryHold
		}
	}
	if completion.InitialEmptyRealmReadSHA256 == nil || completion.OriginalLeaseProvenanceSHA256 == nil || completion.OriginalPublicWorkflowRunID != nil && *completion.OriginalPublicWorkflowRunID != snapshot.PublicRunID || *completion.OriginalLeaseProvenanceSHA256 != capacity.GuestRetirementSHA(*lease) {
		return ErrHostFactoryHold
	}
	initial, ok := typed["initial-empty-realm-read"].(*model.HostFactoryInitialEmptyRealmRead)
	if !ok || *completion.InitialEmptyRealmReadSHA256 != capacity.GuestRetirementSHA(*initial) {
		return ErrHostFactoryHold
	}
	for selector, body := range typed {
		if strings.HasPrefix(selector, "native-observations/") {
			_, bodySHA, envelopeSHA, e := originalHostNativeSelector(selector)
			if e != nil {
				return e
			}
			callbacks, e := originalHostNativeCallbacksTx(ctx, tx, snapshot.RootID)
			if e != nil {
				return e
			}
			raw, envelope, e := callbacks.resolveOriginal(bodySHA, envelopeSHA)
			encoded := bundle.Stages[selector]
			if e != nil || !bytes.Equal(raw, bodies[bodySHA]) || base64.StdEncoding.EncodeToString(envelope) != encoded {
				return ErrHostFactoryHold
			}
			if observation, ok := body.(*model.HostFactoryNativeObservationRecord); ok {
				var relations []byte
				if tx.QueryRowContext(ctx, `SELECT native_inventory_relations_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='native-record' AND raw_body_sha256=$2 AND raw_envelope_sha256=$3`, snapshot.RootID, bodySHA, envelopeSHA).Scan(&relations) != nil || validateOriginalHostNativeStoredRecordTx(ctx, tx, snapshot.RootID, *observation, relations) != nil {
					return ErrHostFactoryHold
				}
			}
		} else if strings.HasPrefix(selector, "io-calls/") {
			sha := strings.Split(selector, "/")[3]
			var storedBody []byte
			if err = tx.QueryRowContext(ctx, `SELECT raw_body_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND raw_body_sha256=$2`, snapshot.RootID, sha).Scan(&storedBody); err != nil || !bytes.Equal(storedBody, bodies[sha]) {
				return ErrHostFactoryHold
			}
			if inventory, ok := body.(*model.HostFactoryHandleCallInventory); ok {
				x, e := originalHostIOIdentity(codec, snapshot.RootID, inventory, bodies[sha])
				if e != nil || inventory.CollectionState != "complete_original_calls" || validateOriginalHostInventoryTx(ctx, tx, x, *inventory) != nil {
					return ErrHostFactoryHold
				}
			}
		} else if selector != "root-completion" && !strings.HasPrefix(selector, "ordinary-guard-read/") {
			var rootEnvelope model.HostFactoryRootSignedEnvelope
			var scopeEnvelope capacity.HostFactorySourceSignedEnvelope
			envelope, _ := base64.StdEncoding.Strict().DecodeString(bundle.Stages[selector])
			schema, sha := "", ""
			if codec.Decode(envelope, &rootEnvelope) == nil {
				schema, sha = rootEnvelope.BindingSchema, rootEnvelope.BindingSHA256
			} else if codec.Decode(envelope, &scopeEnvelope) == nil {
				schema, sha = "original_host_factory_pre_authority_scope_v4", scopeEnvelope.PreAuthorityScopeSHA256
			} else {
				return ErrHostFactoryHold
			}
			if err = validateOriginalHostHistoricalNativeAggregateTx(ctx, tx, snapshot.RootID, schema, sha, body, envelope); err != nil {
				return err
			}
			if err = validateOriginalHostStageVectorsTx(ctx, tx, snapshot.RootID, body); err != nil {
				return err
			}
		}
	}
	if err = verifyOriginalHostHistoricalRealmReturns(ctx, tx, snapshot, bundle, typed, bodies, owners); err != nil {
		return err
	}
	last, err := verifyOriginalHostHistoricalMainReturnsWithCustody(ctx, tx, wrapper, snapshot, owners, bundle)
	if err != nil || completion.OriginalCompletedAt.Before(last) || completion.OriginalCompletedAt.After(wrapper.OriginalContext.OriginalCleanupDeadline) {
		return ErrHostFactoryHold
	}
	if snapshot.EntryClass == "ordinary_original_create" {
		if err = verifyOriginalHostHistoricalGuardPhases(ctx, tx, snapshot, typed); err != nil {
			return err
		}
	}
	commitErr := tx.Commit()
	returnedAt := time.Now()
	if commitErr != nil {
		return commitErr
	}
	if ctx.Err() != nil || !returnedAt.Before(deadline) {
		return ErrHostFactoryHold
	}
	return nil
}

func decodeOriginalHistoricalHostStage(codec hostOriginalSourceCodec, selector string, envelope []byte) ([]byte, any, error) {
	body, _, _, _, err := codec.Envelope(envelope)
	if err != nil {
		return nil, nil, err
	}
	stage := selector
	if strings.HasPrefix(selector, "ordinary-guard-read/") {
		stage = "ordinary-guard-read"
	}
	if strings.HasPrefix(selector, "native-observations/") {
		kind, bodySHA, envelopeSHA, err := originalHostNativeSelector(selector)
		if err != nil || capacity.HostFactoryRawSHA256(body) != bodySHA || capacity.HostFactoryRawSHA256(envelope) != envelopeSHA {
			return nil, nil, ErrHostFactoryHold
		}
		if kind == "native-record" {
			stage = "native-observation-record"
		} else {
			stage = "native-observation-manifest"
		}
	}
	if strings.HasPrefix(selector, "io-calls/") {
		parts := strings.Split(selector, "/")
		if len(parts) != 4 {
			return nil, nil, ErrHostFactoryHold
		}
		switch parts[2] {
		case "chunk":
			stage = "io-call-vector-chunk"
		case "manifest":
			stage = "io-call-vector-manifest"
		case "inventory":
			stage = "io-handle-inventory"
		default:
			return nil, nil, ErrHostFactoryHold
		}
	}
	if strings.HasPrefix(selector, "failure-collections/") {
		stage = "failure-diagnostic"
	}
	target := originalHostStageTarget(stage)
	if target == nil || codec.Decode(body, target) != nil {
		return nil, nil, ErrHostFactoryHold
	}
	return body, target, nil
}

func verifyOriginalHostHistoricalRealmReturns(ctx context.Context, tx *sql.Tx, snapshot hostOriginalSQLSnapshot, bundle hostOriginalRealmCorpus, typed map[string]any, bodies map[string][]byte, owners map[string]string) error {
	codec := originalHostSourceCodecTx(ctx, tx, snapshot.RootID)

	seen := map[string]bool{}
	operations := map[string]bool{}
	for _, record := range bundle.OriginalRealmOwnerReturns {
		if record.Schema != "source_owned_host_factory_realm_owner_return_v1" || record.OriginalLocalReturn != nil || record.OriginalFactReference == nil || record.OriginalFact == nil || record.OriginalState != "returned" || owners[record.OriginalOwnerID] != record.OwnerRole || owners[record.SubjectOwnerID] != record.SubjectRole {
			return ErrHostFactoryHold
		}
		ref := record.OriginalFactReference
		if ref.FactIndex > 15 || ref.OriginalHandleInventoryBodySHA256 == nil {
			return ErrHostFactoryHold
		}
		chunk, ok := typed["io-calls/"+record.OriginalHandleID+"/chunk/"+ref.ChunkBodySHA256].(*model.HostFactoryCallVectorChunk)
		if !ok || int(ref.FactIndex) >= len(chunk.OriginalCalls) || chunk.BindingSchema != ref.BindingSchema || chunk.BindingSHA256 != ref.BindingSHA256 || chunk.OriginalOwnerID != record.OriginalOwnerID || chunk.OwnerRole != record.OwnerRole || chunk.OriginalHandleID != record.OriginalHandleID || capacity.HostFactoryRawSHA256(bodies[ref.ChunkBodySHA256]) != ref.ChunkBodySHA256 {
			return ErrHostFactoryHold
		}
		fact := chunk.OriginalCalls[ref.FactIndex]
		if !reflect.DeepEqual(fact, *record.OriginalFact) || fact.OriginalCallID == nil || seen[*fact.OriginalCallID] || fact.Operation != record.Operation || fact.SubjectOwnerID != record.SubjectOwnerID || fact.OriginalHandleID != record.OriginalHandleID || fact.OriginalReturnedAt == nil || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || fact.OriginalState != "returned" {
			return ErrHostFactoryHold
		}
		seen[*fact.OriginalCallID] = true
		x, err := originalHostIOIdentity(codec, snapshot.RootID, chunk, bodies[ref.ChunkBodySHA256])
		if err != nil {
			return err
		}
		if _, _, err = originalHostPredecessorTx(ctx, tx, x, ref.ChunkBodySHA256, ref.FactIndex); err != nil {
			return err
		}
		inventory, ok := typed["io-calls/"+record.OriginalHandleID+"/inventory/"+*ref.OriginalHandleInventoryBodySHA256].(*model.HostFactoryHandleCallInventory)
		if !ok || inventory.BindingSchema != ref.BindingSchema || inventory.BindingSHA256 != ref.BindingSHA256 || inventory.OriginalOwnerID != record.OriginalOwnerID || inventory.OriginalHandleID != record.OriginalHandleID || inventory.CollectionState != "complete_original_calls" {
			return ErrHostFactoryHold
		}
		found := false
		for _, selected := range inventory.OperationVectors {
			if reflect.DeepEqual(selected, ref.OriginalCallVector) {
				found = true
			}
		}
		if !found {
			return ErrHostFactoryHold
		}
		facts, err := originalHostVectorFactsTx(ctx, tx, snapshot.RootID, ref.OriginalCallVector)
		if err != nil {
			return err
		}
		selected := false
		for _, current := range facts {
			if reflect.DeepEqual(current, fact) {
				selected = true
			}
		}
		if !selected {
			return ErrHostFactoryHold
		}
		if fact.OriginalNativeReturn != nil && (fact.OriginalNativeReturn.OriginalErrorPresent == nil || *fact.OriginalNativeReturn.OriginalErrorPresent) {
			return ErrHostFactoryHold
		}
		if fact.OriginalReturnClass != "success" && fact.OriginalReturnClass != "eof" && fact.OriginalReturnClass != "full_write" && fact.OriginalReturnClass != "native_zero_return" {
			return ErrHostFactoryHold
		}
		if record.Operation == "stdout_read" || record.Operation == "stderr_read" {
			if fact.OriginalEOF == nil || !*fact.OriginalEOF {
				continue
			}
		}
		operations[record.Operation+":"+record.SubjectRole] = true
	}
	workerRole := "host_worker"
	if snapshot.EntryClass == "ordinary_original_create" {
		workerRole = "factory_ordinary_worker"
	}
	for _, key := range []string{"worker_wait:" + workerRole, "registrar_wait:host_registrar", "stdout_read:" + workerRole, "stderr_read:" + workerRole, "stdout_close:" + workerRole, "stderr_close:" + workerRole, "stdout_read:host_registrar", "stderr_read:host_registrar", "stdout_close:host_registrar", "stderr_close:host_registrar", "worker_pidfd_close:" + workerRole, "registrar_pidfd_close:host_registrar", "root_directory_close:host_exterior", "basal_self_pidfd_close:host_exterior", "basal_self_pidfd_close:host_registrar", "basal_self_pidfd_close:" + workerRole} {
		if !operations[key] {
			return ErrHostFactoryHold
		}
	}
	return nil
}

// io.ReadAll and Body.Read are two distinct original Go returns. The aggregate
// reservation precedes its nested subcalls, while its return follows them.
// Counts are conserved using only the subcalls, never aggregate+subcalls.
func verifyOriginalHostHistoricalHTTPAudits(audits map[string]hostOriginalSourceAuditProjection) error {
	groups := map[string][]hostOriginalSourceAuditProjection{}
	for _, record := range audits {
		if record.SubjectIdentity.SubjectKind == "public_workflow_http" {
			groups[record.Fact.OriginalAuditHandleID] = append(groups[record.Fact.OriginalAuditHandleID], record)
		}
	}
	acceptedPOST, completeGET := 0, 0
	for handle, rows := range groups {
		if len(rows) < 4 {
			return ErrHostFactoryHold
		}
		for _, row := range rows {
			fact := row.Fact
			if capacity.ValidateHostFactory(fact) != nil || fact.OriginalState != "returned" || fact.OriginalCallID == nil || fact.OriginalCalledAt == nil || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || fact.OriginalStatusCode == nil || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) {
				return ErrHostFactoryHold
			}
		}
		ordinal := func(row hostOriginalSourceAuditProjection) uint64 {
			parts := strings.Split(*row.Fact.OriginalCallID, ":")
			if len(parts) != 2 || parts[0] != handle {
				return 0
			}
			n, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil || parts[1] != strconv.FormatUint(n, 10) {
				return 0
			}
			return n
		}
		sort.Slice(rows, func(i, j int) bool { return ordinal(rows[i]) < ordinal(rows[j]) })
		for n, row := range rows {
			if ordinal(row) != uint64(n+1) || !reflect.DeepEqual(row.SubjectIdentity, rows[0].SubjectIdentity) || *row.Fact.OriginalStatusCode != *rows[0].Fact.OriginalStatusCode {
				return ErrHostFactoryHold
			}
		}
		do, aggregate, close := rows[0], rows[1], rows[len(rows)-1]
		if do.Fact.Operation != "public_workflow_http_do" || *do.Fact.OriginalErrorPresent || aggregate.Fact.Operation != "public_workflow_body_read" || aggregate.Fact.OriginalReadScope == nil || *aggregate.Fact.OriginalReadScope != "complete_original_body_read" || aggregate.Fact.OriginalCount == nil || aggregate.Fact.OriginalEOF == nil || !*aggregate.Fact.OriginalEOF || *aggregate.Fact.OriginalErrorPresent || close.Fact.Operation != "public_workflow_body_close" || *close.Fact.OriginalErrorPresent || aggregate.Fact.OriginalCalledAt.Before(*do.Fact.OriginalReturnedAt) || close.Fact.OriginalCalledAt.Before(*aggregate.Fact.OriginalReturnedAt) {
			return ErrHostFactoryHold
		}
		var subcount int64
		previousReturn := *aggregate.Fact.OriginalCalledAt
		for n, row := range rows[2 : len(rows)-1] {
			fact := row.Fact
			final := n == len(rows)-4
			if fact.Operation != "public_workflow_body_read" || fact.OriginalReadScope != nil || fact.RetainedPrefixBytes != nil || fact.RetainedPrefixSHA256 != nil || fact.OriginalCount == nil || fact.OriginalEOF == nil || row.OriginalCloseReference == nil || *row.OriginalCloseReference != *close.Fact.OriginalCallID || fact.OriginalCalledAt.Before(previousReturn) || fact.OriginalReturnedAt.After(*aggregate.Fact.OriginalReturnedAt) || *fact.OriginalEOF != final || *fact.OriginalErrorPresent != final || !final && *fact.OriginalCount == 0 || fact.OriginalHashState != aggregate.Fact.OriginalHashState {
				return ErrHostFactoryHold
			}
			subcount += *fact.OriginalCount
			if subcount > 65537 {
				return ErrHostFactoryHold
			}
			previousReturn = *fact.OriginalReturnedAt
		}
		if aggregate.OriginalCloseReference == nil || *aggregate.OriginalCloseReference != *close.Fact.OriginalCallID || subcount != *aggregate.Fact.OriginalCount || subcount > 65536 {
			return ErrHostFactoryHold
		}
		if do.SubjectIdentity.Method == nil {
			return ErrHostFactoryHold
		}
		switch *do.SubjectIdentity.Method {
		case "POST":
			if *do.Fact.OriginalStatusCode != 202 || aggregate.Fact.OriginalHashState != "actual_public_bytes" {
				return ErrHostFactoryHold
			}
			acceptedPOST++
		case "GET":
			if *do.Fact.OriginalStatusCode != 200 || aggregate.Fact.OriginalHashState != "private_withheld" {
				return ErrHostFactoryHold
			}
			completeGET++
		default:
			return ErrHostFactoryHold
		}
	}
	if acceptedPOST != 1 || completeGET == 0 {
		return ErrHostFactoryHold
	}
	return nil
}

// Policy and TLS inputs are actual per-File.Read calls, without a manufactured
// ReadAll scope. The three policy readers additionally own the original second
// Fstat after EOF. Logical inventory matching remains a separate compiled gate.
func verifyOriginalHostHistoricalSourceFileAudits(audits map[string]hostOriginalSourceAuditProjection, policyCallReferences []string) error {
	return verifyOriginalHostHistoricalSourceFileAuditsSelected(audits, policyCallReferences, nil)
}
func verifyOriginalHostHistoricalSourceFileAuditsSelected(audits map[string]hostOriginalSourceAuditProjection, policyCallReferences []string, zeroSourceFiles map[string]bool) error {
	if verifyOriginalHostHistoricalSourceDirectories(audits) != nil {
		return ErrHostFactoryHold
	}
	// Selection is the actual Source-owned policy3 cache copied by Main. A
	// Fstat count, artifact path or caller label cannot select those handles.
	if len(policyCallReferences) == 0 || len(policyCallReferences) > 4096 {
		return ErrHostFactoryHold
	}
	selected := map[string]bool{}
	policyHandles := map[string]bool{}
	for _, id := range policyCallReferences {
		row, exists := audits[id]
		if !exists || selected[id] || row.SubjectIdentity.SubjectKind != "source_file" {
			return ErrHostFactoryHold
		}
		selected[id] = true
		policyHandles[row.Fact.OriginalAuditHandleID] = true
	}
	if len(policyHandles) != 3 {
		return ErrHostFactoryHold
	}
	groups := map[string][]hostOriginalSourceAuditProjection{}
	for _, row := range audits {
		if row.SubjectIdentity.SubjectKind == "source_file" && !originalHostSourceDirectoryOperation(row.Fact.Operation) {
			groups[row.Fact.OriginalAuditHandleID] = append(groups[row.Fact.OriginalAuditHandleID], row)
		}
	}
	for handle, rows := range groups {
		if policyHandles[handle] {
			for _, row := range rows {
				if row.Fact.OriginalCallID == nil || !selected[*row.Fact.OriginalCallID] {
					return ErrHostFactoryHold
				}
			}
		}
		readCount := 0
		for _, row := range rows {
			if row.Fact.Operation == "source_file_read" {
				readCount++
			}
		}
		if readCount == 0 {
			if policyHandles[handle] {
				return ErrHostFactoryHold
			}
			writing := false
			for _, row := range rows {
				writing = writing || row.Fact.Operation == "source_file_write" || zeroSourceFiles[handle] && len(rows) == 4 && row.Fact.Operation == "source_file_sync"
			}
			if writing {
				if policyHandles[handle] || verifyOriginalHostSourcePublicationWriteSelected(rows, handle, zeroSourceFiles[handle]) != nil {
					return ErrHostFactoryHold
				}
				continue
			}
			if len(rows) == 2 {
				// Rename and directory Sync own a logical method handle, with
				// no acquired FD, byte return or manufactured Close.
				first, second := rows[0], rows[1]
				if first.Fact.OriginalCallID != nil && *first.Fact.OriginalCallID == handle+":2" {
					first, second = second, first
				}
				for n, row := range []hostOriginalSourceAuditProjection{first, second} {
					fact := row.Fact
					operation := []string{"source_file_rename_noreplace", "source_directory_sync"}[n]
					if capacity.ValidateHostFactory(fact) != nil || fact.Operation != operation || fact.OriginalCallID == nil || *fact.OriginalCallID != handle+":"+strconv.Itoa(n+1) || fact.OriginalState != "returned" || fact.OriginalCalledAt == nil || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || *fact.OriginalErrorPresent || row.OriginalCloseReference != nil || fact.OriginalHashState != "not_byte_operation" || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || !reflect.DeepEqual(row.SubjectIdentity, first.SubjectIdentity) || n == 1 && fact.OriginalCalledAt.Before(*first.Fact.OriginalReturnedAt) {
						return ErrHostFactoryHold
					}
				}
				continue
			}
			// An actual failed acquisition has no acquired FD or Close. Keep
			// that original diagnostic; a later fixed-file attempt has its own
			// reserved handle and cannot overwrite or reuse this original.
			if len(rows) != 1 {
				return ErrHostFactoryHold
			}
			row, fact := rows[0], rows[0].Fact
			if capacity.ValidateHostFactory(fact) != nil || fact.Operation != "source_file_open" || fact.OriginalState != "returned" || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || !*fact.OriginalErrorPresent || row.OriginalCloseReference != nil || fact.OriginalHashState != "not_byte_operation" || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) {
				return ErrHostFactoryHold
			}
			continue
		}
		if len(rows) < 4 {
			return ErrHostFactoryHold
		}
		ordinal := func(row hostOriginalSourceAuditProjection) uint64 {
			if row.Fact.OriginalCallID == nil {
				return 0
			}
			parts := strings.Split(*row.Fact.OriginalCallID, ":")
			if len(parts) != 2 || parts[0] != handle {
				return 0
			}
			n, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil || parts[1] != strconv.FormatUint(n, 10) {
				return 0
			}
			return n
		}
		sort.Slice(rows, func(i, j int) bool { return ordinal(rows[i]) < ordinal(rows[j]) })
		close := rows[len(rows)-1]
		if close.Fact.Operation != "source_file_close" || close.Fact.OriginalCallID == nil || rows[0].Fact.Operation != "source_file_open" || rows[1].Fact.Operation != "source_file_fstat" {
			return ErrHostFactoryHold
		}
		fstats, reads, eof, total := 0, 0, false, int64(0)
		var previousReturn time.Time
		for n, row := range rows {
			fact := row.Fact
			if capacity.ValidateHostFactory(fact) != nil || ordinal(row) != uint64(n+1) || fact.OriginalState != "returned" || fact.OriginalCalledAt == nil || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || fact.OriginalCalledAt.Before(previousReturn) || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || row.OriginalCloseReference == nil || *row.OriginalCloseReference != *close.Fact.OriginalCallID || !reflect.DeepEqual(row.SubjectIdentity, rows[0].SubjectIdentity) {
				return ErrHostFactoryHold
			}
			previousReturn = *fact.OriginalReturnedAt
			switch fact.Operation {
			case "source_file_open":
				if n != 0 || *fact.OriginalErrorPresent {
					return ErrHostFactoryHold
				}
			case "source_file_fstat":
				fstats++
				if *fact.OriginalErrorPresent || n != 1 && (n != len(rows)-2 || !eof) {
					return ErrHostFactoryHold
				}
			case "source_file_read":
				if eof || fstats != 1 || fact.OriginalCount == nil || fact.OriginalEOF == nil || *fact.OriginalErrorPresent != *fact.OriginalEOF || !*fact.OriginalEOF && *fact.OriginalCount == 0 || fact.OriginalReadScope != nil || fact.RetainedPrefixBytes != nil || fact.OriginalHashState != "private_withheld" || fact.OriginalSHA256 != nil || fact.RetainedPrefixSHA256 != nil {
					return ErrHostFactoryHold
				}
				reads++
				total += *fact.OriginalCount
				eof = *fact.OriginalEOF
			case "source_file_close":
				if n != len(rows)-1 || *fact.OriginalErrorPresent || !eof || reads != readCount || total == 0 && !zeroSourceFiles[handle] || total > 65536 || fstats != 1 && fstats != 2 {
					return ErrHostFactoryHold
				}
			default:
				return ErrHostFactoryHold
			}
		}
		if policyHandles[handle] && fstats != 2 {
			return ErrHostFactoryHold
		}
	}
	return nil
}

// A Source directory acquisition is distinct from every policy/file/native
// handle. These unsigned method returns cannot supply a native directory stat
// or an absence proof; actual Source checks the returned Fstat directory type.
func verifyOriginalHostHistoricalSourceDirectories(audits map[string]hostOriginalSourceAuditProjection) error {
	groups := map[string][]hostOriginalSourceAuditProjection{}
	for _, row := range audits {
		if row.SubjectIdentity.SubjectKind == "source_file" && originalHostSourceDirectoryOperation(row.Fact.Operation) {
			groups[row.Fact.OriginalAuditHandleID] = append(groups[row.Fact.OriginalAuditHandleID], row)
		}
	}
	for handle, rows := range groups {
		sort.Slice(rows, func(i, j int) bool {
			return rows[i].Fact.OriginalCallID != nil && rows[j].Fact.OriginalCallID != nil && *rows[i].Fact.OriginalCallID < *rows[j].Fact.OriginalCallID
		})
		if len(rows) == 1 {
			fact := rows[0].Fact
			if capacity.ValidateHostFactory(fact) != nil || fact.Operation != "source_directory_open" || fact.OriginalCallID == nil || *fact.OriginalCallID != handle+":1" || fact.OriginalState != "returned" || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || !*fact.OriginalErrorPresent || rows[0].OriginalCloseReference != nil || fact.OriginalHashState != "not_byte_operation" || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) {
				return ErrHostFactoryHold
			}
			continue
		}
		if len(rows) != 3 {
			return ErrHostFactoryHold
		}
		var prior time.Time
		for n, row := range rows {
			fact := row.Fact
			closeID := handle + ":3"
			if capacity.ValidateHostFactory(fact) != nil || fact.Operation != []string{"source_directory_open", "source_directory_fstat", "source_directory_close"}[n] || fact.OriginalCallID == nil || *fact.OriginalCallID != handle+":"+strconv.Itoa(n+1) || fact.OriginalState != "returned" || fact.OriginalCalledAt == nil || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || *fact.OriginalErrorPresent || fact.OriginalCalledAt.Before(prior) || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || row.OriginalCloseReference == nil || *row.OriginalCloseReference != closeID || !reflect.DeepEqual(row.SubjectIdentity, rows[0].SubjectIdentity) || fact.OriginalHashState != "not_byte_operation" || fact.OriginalCount != nil || fact.OriginalEOF != nil || fact.OriginalSHA256 != nil || fact.OriginalReadScope != nil || fact.RetainedPrefixBytes != nil || fact.RetainedPrefixSHA256 != nil {
				return ErrHostFactoryHold
			}
			prior = *fact.OriginalReturnedAt
		}
	}
	return nil
}

func originalHostSourceDirectoryOperation(operation string) bool {
	return operation == "source_directory_open" || operation == "source_directory_fstat" || operation == "source_directory_close"
}

func verifyOriginalHostSourcePublicationWrite(rows []hostOriginalSourceAuditProjection, handle string) error {
	return verifyOriginalHostSourcePublicationWriteSelected(rows, handle, false)
}
func verifyOriginalHostSourcePublicationWriteSelected(rows []hostOriginalSourceAuditProjection, handle string, knownOriginalEmpty bool) error {
	if len(rows) < 4 || len(rows) == 4 && !knownOriginalEmpty || knownOriginalEmpty && len(rows) != 4 {
		return ErrHostFactoryHold
	}
	ordered := make([]hostOriginalSourceAuditProjection, len(rows))
	for _, row := range rows {
		if row.Fact.OriginalCallID == nil {
			return ErrHostFactoryHold
		}
		parts := strings.Split(*row.Fact.OriginalCallID, ":")
		if len(parts) != 2 || parts[0] != handle {
			return ErrHostFactoryHold
		}
		n, err := strconv.Atoi(parts[1])
		if err != nil || n < 1 || n > len(rows) || parts[1] != strconv.Itoa(n) || ordered[n-1].Fact.OriginalCallID != nil {
			return ErrHostFactoryHold
		}
		ordered[n-1] = row
	}
	close := ordered[len(ordered)-1]
	var total int64
	var previousReturn time.Time
	for n, row := range ordered {
		fact := row.Fact
		if capacity.ValidateHostFactory(fact) != nil || fact.OriginalState != "returned" || fact.OriginalCalledAt == nil || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || *fact.OriginalErrorPresent || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || fact.OriginalCalledAt.Before(previousReturn) || !reflect.DeepEqual(row.SubjectIdentity, ordered[0].SubjectIdentity) || row.OriginalCloseReference == nil || close.Fact.OriginalCallID == nil || *row.OriginalCloseReference != *close.Fact.OriginalCallID {
			return ErrHostFactoryHold
		}
		previousReturn = *fact.OriginalReturnedAt
		switch {
		case n == 0:
			if fact.Operation != "source_file_open" {
				return ErrHostFactoryHold
			}
		case n == 1:
			if fact.Operation != "source_file_fstat" {
				return ErrHostFactoryHold
			}
		case n == len(ordered)-2:
			if fact.Operation != "source_file_sync" {
				return ErrHostFactoryHold
			}
		case n == len(ordered)-1:
			if fact.Operation != "source_file_close" {
				return ErrHostFactoryHold
			}
		default:
			if fact.Operation != "source_file_write" || fact.OriginalCount == nil || *fact.OriginalCount <= 0 || fact.OriginalHashState != "private_withheld" || fact.OriginalSHA256 != nil || fact.OriginalEOF != nil || fact.OriginalReadScope != nil || fact.RetainedPrefixBytes != nil || fact.RetainedPrefixSHA256 != nil {
				return ErrHostFactoryHold
			}
			total += *fact.OriginalCount
			if total > 65536 {
				return ErrHostFactoryHold
			}
		}
	}
	return nil
}

func verifyOriginalHostHistoricalMainReturns(wrapper hostOriginalFinalCorpus, snapshot hostOriginalSQLSnapshot, owners map[string]string) (time.Time, error) {
	return verifyOriginalHostHistoricalMainReturnsOriginal(nil, nil, wrapper, snapshot, owners, nil)
}
func verifyOriginalHostHistoricalMainReturnsWithCustody(ctx context.Context, tx *sql.Tx, wrapper hostOriginalFinalCorpus, snapshot hostOriginalSQLSnapshot, owners map[string]string, bundle hostOriginalRealmCorpus) (time.Time, error) {
	return verifyOriginalHostHistoricalMainReturnsOriginal(ctx, tx, wrapper, snapshot, owners, &bundle)
}
func verifyOriginalHostHistoricalMainReturnsOriginal(ctx context.Context, tx *sql.Tx, wrapper hostOriginalFinalCorpus, snapshot hostOriginalSQLSnapshot, owners map[string]string, bundle *hostOriginalRealmCorpus) (time.Time, error) {
	audits := map[string]hostOriginalSourceAuditProjection{}
	main := map[string]hostOriginalMainReturn{}
	last := snapshot.SQLReadReturnedAt
	handles := map[string]uint64{}
	for _, raw := range wrapper.MainOwnerReturns {
		var family struct {
			Family string `json:"family"`
		}
		if json.Unmarshal(raw, &family) != nil {
			return time.Time{}, ErrHostFactoryHold
		}
		switch family.Family {
		case "source_audit":
			var record hostOriginalSourceAuditProjection
			if hostOriginalStrictJSON(raw, &record, 65536) != nil || capacity.ValidateHostFactory(record.Fact) != nil || record.Fact.FactoryRootID != snapshot.NativeFactoryRootID || record.Fact.OriginalState != "returned" || record.Fact.OriginalCallID == nil || record.Fact.OriginalReturnedAt == nil || record.Fact.OriginalCalledAt == nil || record.Fact.OriginalErrorPresent == nil {
				return time.Time{}, ErrHostFactoryHold
			}
			fact := record.Fact
			id := *fact.OriginalCallID
			if _, exists := audits[id]; exists {
				return time.Time{}, ErrHostFactoryHold
			}
			parts := strings.Split(id, ":")
			if len(parts) != 2 || parts[0] != fact.OriginalAuditHandleID {
				return time.Time{}, ErrHostFactoryHold
			}
			ordinal, e := strconv.ParseUint(parts[1], 10, 64)
			if e != nil || ordinal != handles[parts[0]]+1 || parts[1] != strconv.FormatUint(ordinal, 10) {
				return time.Time{}, ErrHostFactoryHold
			}
			handles[parts[0]] = ordinal
			if fact.OriginalReturnedAt.After(wrapper.OriginalContext.OriginalCleanupDeadline) || fact.OriginalCalledAt.Before(wrapper.OriginalContext.OriginalStartedAt) {
				return time.Time{}, ErrHostFactoryHold
			}
			subject := record.SubjectIdentity
			if subject.SubjectKind == "public_workflow_http" {
				if subject.RequestIdentity == nil || !validCapacityExecutor(*subject.RequestIdentity) || subject.Method == nil || subject.PathFamily == nil {
					return time.Time{}, ErrHostFactoryHold
				}
				if *subject.Method == "GET" {
					if subject.PublicRunID == nil || *subject.PublicRunID != snapshot.PublicRunID || *subject.PathFamily != "same_original_workflow_run" || fact.OriginalSHA256 != nil || fact.RetainedPrefixSHA256 != nil || fact.Operation == "public_workflow_body_read" && fact.OriginalHashState != "private_withheld" {
						return time.Time{}, ErrHostFactoryHold
					}
				} else if *subject.Method == "POST" {
					if *subject.PathFamily != "workflow_run_collection" || wrapper.PublicCallerIdentity.RequestID != nil && *subject.RequestIdentity != *wrapper.PublicCallerIdentity.RequestID {
						return time.Time{}, ErrHostFactoryHold
					}
					if fact.Operation == "public_workflow_body_read" && fact.OriginalHashState == "actual_public_bytes" && fact.OriginalReadScope != nil && (*fact.OriginalReadScope != "complete_original_body_read" || fact.OriginalEOF == nil || !*fact.OriginalEOF || fact.OriginalStatusCode == nil || *fact.OriginalStatusCode != 202 || *fact.OriginalErrorPresent) {
						return time.Time{}, ErrHostFactoryHold
					}
				} else {
					return time.Time{}, ErrHostFactoryHold
				}
			} else {
				allowed := map[string]bool{"main_db": true, "main_broker": true, "main_api": true, "main_handlers": true, "main_workflows": true, "source_file": true, "source_directory": true}
				if !allowed[subject.SubjectKind] || subject.Method != nil || subject.PathFamily != nil || subject.RequestIdentity != nil || subject.PublicRunID != nil {
					return time.Time{}, ErrHostFactoryHold
				}
			}
			if fact.OriginalReturnedAt.After(last) {
				last = *fact.OriginalReturnedAt
			}
			audits[id] = record
		case "main_owner_return":
			var record hostOriginalMainReturn
			if hostOriginalStrictJSON(raw, &record, 65536) != nil || record.Schema != "source_owned_host_factory_main_owner_return_v1" || record.SubjectIdentity.SubjectKind != record.Operation || record.OriginalState != "returned" || record.OriginalCalledAt == nil || record.OriginalReturnedAt == nil || record.OriginalErrorPresent == nil || *record.OriginalErrorPresent || record.OriginalReturnClass == nil || *record.OriginalReturnClass != "nil_error" || record.OriginalReturnedAt.Before(*record.OriginalCalledAt) || !record.OriginalReturnedAt.Before(record.OriginalOperationDeadline) || record.OriginalCalledAt.Before(wrapper.OriginalContext.OriginalStartedAt) || record.OriginalReturnedAt.After(wrapper.OriginalContext.OriginalCleanupDeadline) || owners[record.OriginalOwnerID] != "host_exterior" || record.OriginalCallID == nil || !strings.HasPrefix(*record.OriginalCallID, record.OriginalHandleID+":") {
				return time.Time{}, ErrHostFactoryHold
			}
			if _, exists := main[record.Operation]; exists {
				return time.Time{}, ErrHostFactoryHold
			}
			switch record.Operation {
			case "public_caller_return", "preclose_verifier_return", "transport_close_idle":
				if record.ActualOwnerJoinState != "not_applicable" {
					return time.Time{}, ErrHostFactoryHold
				}
			case "realm_close_join", "main_cleanup_return":
				if record.ActualOwnerJoinState != "joined_actual" {
					return time.Time{}, ErrHostFactoryHold
				}
			default:
				return time.Time{}, ErrHostFactoryHold
			}
			if record.OriginalReturnedAt.After(last) {
				last = *record.OriginalReturnedAt
			}
			main[record.Operation] = record
		default:
			return time.Time{}, ErrHostFactoryHold
		}
	}
	if err := verifyOriginalHostHistoricalHTTPAudits(audits); err != nil {
		return time.Time{}, err
	}
	zeroFiles := map[string]bool{}
	if tx != nil {
		var err error
		zeroFiles, err = originalHostHistoricalZeroSourceFilesTx(ctx, tx, snapshot.RootID, audits)
		if err != nil {
			return time.Time{}, err
		}
	}
	if err := verifyOriginalHostHistoricalSourceFileAuditsSelected(audits, main["realm_close_join"].SourceAuditCallReferences, zeroFiles); err != nil {
		return time.Time{}, err
	}
	required := map[string]bool{"api_original_serve": false, "api_original_shutdown": false, "api_handler_owner_join": false, "workflow_owner_join": false, "broker_close": false, "db_close": false}
	for _, record := range audits {
		fact := record.Fact
		if _, requiredOp := required[fact.Operation]; requiredOp {
			// Serve's real http.ErrServerClosed is retained as an actual error;
			// completed Shutdown + actual handler/workflow joins close that owner.
			if required[fact.Operation] || *fact.OriginalErrorPresent && fact.Operation != "api_original_serve" {
				return time.Time{}, ErrHostFactoryHold
			}
			required[fact.Operation] = true
		}
	}
	for _, closed := range required {
		if !closed {
			return time.Time{}, ErrHostFactoryHold
		}
	}
	for _, operation := range []string{"public_caller_return", "realm_close_join", "transport_close_idle", "main_cleanup_return", "preclose_verifier_return"} {
		if _, ok := main[operation]; !ok {
			return time.Time{}, ErrHostFactoryHold
		}
	}
	if err := verifyOriginalHostHistoricalOwnerOrder(audits, main, snapshot.SQLReadReturnedAt); err != nil {
		return time.Time{}, err
	}
	for _, record := range main {
		for _, id := range record.SourceAuditCallReferences {
			if _, ok := audits[id]; !ok {
				return time.Time{}, ErrHostFactoryHold
			}
		}
	}
	if tx != nil {
		if bundle == nil || verifyOriginalHostFinalSourceAuditMainTx(ctx, tx, snapshot, *bundle, audits, main) != nil {
			return time.Time{}, ErrHostFactoryHold
		}
		if bundle == nil || verifyOriginalHostPostStartFinalCustodyTx(ctx, tx, snapshot, *bundle, audits, main) != nil {
			return time.Time{}, ErrHostFactoryHold
		}
	}
	return last, nil
}

// Closing an owning method can begin only after the dependent original owners
// returned. Comparing just two Close return times cannot establish that order.
// The one db_original_query is Main's actual closing-persistence Go return;
// it follows Realm join and precedes broker/DB Close, with no future SQL row.
func verifyOriginalHostHistoricalOwnerOrder(audits map[string]hostOriginalSourceAuditProjection, main map[string]hostOriginalMainReturn, precloseReturnedAt time.Time) error {
	subjects := map[string]string{"api_original_serve": "main_api", "api_original_shutdown": "main_api", "api_handler_owner_join": "main_handlers", "workflow_owner_join": "main_workflows", "db_original_query": "main_db", "broker_close": "main_broker", "db_close": "main_db"}
	selected := map[string]model.HostFactorySourceAuditReturn{}
	for _, row := range audits {
		expected, required := subjects[row.Fact.Operation]
		if !required {
			continue
		}
		fact := row.Fact
		if _, duplicate := selected[fact.Operation]; duplicate || row.SubjectIdentity.SubjectKind != expected || fact.OriginalCalledAt == nil || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || *fact.OriginalErrorPresent && fact.Operation != "api_original_serve" || fact.OriginalReturnedAt.Before(*fact.OriginalCalledAt) || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) {
			return ErrHostFactoryHold
		}
		selected[fact.Operation] = fact
	}
	if len(selected) != len(subjects) || precloseReturnedAt.IsZero() {
		return ErrHostFactoryHold
	}
	for _, operation := range []string{"public_caller_return", "realm_close_join", "transport_close_idle", "main_cleanup_return", "preclose_verifier_return"} {
		r, ok := main[operation]
		if !ok || r.OriginalCalledAt == nil || r.OriginalReturnedAt == nil || r.OriginalReturnedAt.Before(*r.OriginalCalledAt) || !r.OriginalReturnedAt.Before(r.OriginalOperationDeadline) {
			return ErrHostFactoryHold
		}
	}
	shutdown, broker, db, closing := selected["api_original_shutdown"], selected["broker_close"], selected["db_close"], selected["db_original_query"]
	if shutdown.OriginalCalledAt.Before(*main["public_caller_return"].OriginalReturnedAt) || main["public_caller_return"].OriginalReturnedAt.Before(*main["preclose_verifier_return"].OriginalReturnedAt) || main["preclose_verifier_return"].OriginalReturnedAt.Before(precloseReturnedAt) || closing.OriginalCalledAt.Before(*main["realm_close_join"].OriginalReturnedAt) || broker.OriginalCalledAt.Before(*closing.OriginalReturnedAt) || db.OriginalCalledAt.Before(*broker.OriginalReturnedAt) || main["main_cleanup_return"].OriginalReturnedAt.Before(*db.OriginalReturnedAt) {
		return ErrHostFactoryHold
	}
	for _, operation := range []string{"api_original_serve", "api_original_shutdown", "api_handler_owner_join", "workflow_owner_join"} {
		if main["realm_close_join"].OriginalCalledAt.Before(*selected[operation].OriginalReturnedAt) || broker.OriginalCalledAt.Before(*selected[operation].OriginalReturnedAt) {
			return ErrHostFactoryHold
		}
	}
	for _, operation := range []string{"realm_close_join", "transport_close_idle"} {
		if broker.OriginalCalledAt.Before(*main[operation].OriginalReturnedAt) {
			return ErrHostFactoryHold
		}
	}
	return nil
}

func verifyOriginalHostHistoricalGuardPhases(ctx context.Context, tx *sql.Tx, snapshot hostOriginalSQLSnapshot, typed map[string]any) error {
	codec := originalHostSourceCodecTx(ctx, tx, snapshot.RootID)

	phases := map[string]model.FactoryOrdinaryGuardRead{}
	attempt := ""
	bindingRow, err := originalHostSnapshotSingleton(snapshot, "public.capacity_host_factory_scopes")
	if err != nil {
		return err
	}
	var binding model.FactoryOrdinarySourceBinding
	if codec.Decode(bindingRow.original["original_wire"], &binding) != nil {
		return ErrHostFactoryHold
	}
	for selector, value := range typed {
		if !strings.HasPrefix(selector, "ordinary-guard-read/") {
			continue
		}
		parts := strings.Split(selector, "/")
		guard, ok := value.(*model.FactoryOrdinaryGuardRead)
		if len(parts) != 4 || !ok || guard.OriginalAttemptID != parts[2] || !validCapacityExecutor(parts[2]) || capacity.GuestRetirementSHA(*guard) != parts[3] || guard.OrdinarySourceBindingSHA256 != snapshot.PrivateBindingSHA256 || !guard.OriginalContextDeadline.Equal(binding.OriginalContextDeadline) || guard.ExecutorID != snapshot.OriginalInvocationID || guard.CoreActualSourceCommit != snapshot.CoreActualSourceCommit || guard.PolicyChecksum != snapshot.PolicyChecksum || guard.WorkflowChecksum != snapshot.WorkflowChecksum {
			return ErrHostFactoryHold
		}
		if attempt == "" {
			attempt = parts[2]
		} else if attempt != parts[2] {
			return ErrHostFactoryHold
		}
		if _, exists := phases[parts[1]]; exists {
			return ErrHostFactoryHold
		}
		if parts[1] != "before_redeem" && parts[1] != "after_redeem" && parts[1] != "before_start" {
			return ErrHostFactoryHold
		}
		phases[parts[1]] = *guard
	}
	before, b := phases["before_redeem"]
	after, a := phases["after_redeem"]
	start, s := phases["before_start"]
	if !b || !a || !s || before.GrantState != "issued" || after.GrantState != "redeemed" || start.GrantState != "redeemed" || after.ObservedAt.Before(before.ObservedAt) || start.ObservedAt.Before(after.ObservedAt) || !reflect.DeepEqual(before.OriginalGrantRawSHA256, after.OriginalGrantRawSHA256) || before.OriginalGrantRawSHA256 != start.OriginalGrantRawSHA256 || before.OriginalPreregistrationRawSHA256 != after.OriginalPreregistrationRawSHA256 || before.OriginalPreregistrationRawSHA256 != start.OriginalPreregistrationRawSHA256 || before.Generation != after.Generation || before.Fence != after.Fence || before.Generation != start.Generation || before.Fence != start.Fence {
		return ErrHostFactoryHold
	}
	var currentRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1`, before.GrantID).Scan(&currentRaw); err != nil {
		return err
	}
	var grant capacityMutationRecord
	if json.Unmarshal(currentRaw, &grant) != nil || grant.AttemptID != attempt || grant.Settlement == nil || grant.Settlement.AttemptID != attempt || grant.Settlement.RequestSHA256 != before.OriginalRedeemRequestSHA256 || grant.Settlement.RequestSHA256 != after.OriginalRedeemRequestSHA256 || grant.Settlement.RequestSHA256 != start.OriginalRedeemRequestSHA256 {
		return ErrHostFactoryHold
	}
	return nil
}

func verifyOriginalHostHistoricalOrdinaryTx(ctx context.Context, tx *sql.Tx, snapshot hostOriginalSQLSnapshot, grant capacityMutationRecord, pre model.CapacityGuestOriginalProvisioningPreregistration, nativeRaw []byte) error {
	// This PRIVATE projection joins the existing original ABI; it is not a
	// recreated native capability. The tagged reader checks the full raw ABI.
	var native guestNativeQEMUOriginalIdentity
	if json.Unmarshal(nativeRaw, &native) != nil || native.Schema != "core_independent_original_qemu_read_v1" || native.Original.OriginalSourceCommit != capacity.CurrentGuestCoreSource() || native.Original.Provider != "native-qemu" || native.Original.Slot != pre.Slot || native.Original.ResourceID != grant.Proof.ResourceID || native.Original.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano) != grant.Proof.ResourceCreatedAt || !native.CloseReturnedAt.Equal(grant.Proof.ObservedAt) || native.Original.OriginalCreateStartedAt.Before(pre.ReservedAt) || native.Original.OriginalCreateReturnedAt.Before(native.Original.OriginalCreateStartedAt) || native.Original.QEMU.PID < 2 || native.Original.QEMU.StartTicks == 0 || native.OriginalDisk.Device == 0 || native.OriginalDisk.Inode == 0 {
		return ErrHostFactoryHold
	}
	preRecord, err := originalHostSnapshotSingleton(snapshot, "public.capacity_vm_provisioning_preregistrations")
	if err != nil {
		return err
	}
	var stored guestOriginalStored
	if capacity.DecodeGuestLifecycle(preRecord.original["original_wire"], &stored.pre) != nil || capacity.DecodeGuestLifecycle(preRecord.original["binding_wire"], &stored.binding) != nil || !reflect.DeepEqual(stored.pre, pre) || !capacity.GuestOriginalProvisioningDeadlineMatches(pre, stored.binding.ProfileManifest) {
		return ErrHostFactoryHold
	}
	stored.member, err = guestMember(stored.binding, pre.Slot)
	if err != nil {
		return err
	}
	var policy model.CapacityPolicySpec
	var policyRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy'`, pre.PolicyID).Scan(&policyRaw); err != nil || json.Unmarshal(policyRaw, &policy) != nil || !capacity.GuestOriginalProfileEnabled(policy, stored.binding, native.Original.Provider) {
		return ErrHostFactoryHold
	}
	witnessRecord, err := originalHostSnapshotSingleton(snapshot, "public.capacity_guest_original_create_witnesses")
	if err != nil {
		return err
	}
	if capacity.DecodeGuestLifecycle(witnessRecord.original["original_wire"], &stored.witness) != nil || capacity.GuestRetirementSHA(stored.witness) != originalHostSQLString(witnessRecord, "witness_sha256") {
		return ErrHostFactoryHold
	}
	w := stored.witness
	if w.OriginalCreateAttemptID != grant.AttemptID || w.OriginalCreateGrantID != grant.Grant.GrantID || w.OriginalCreateRequestSHA256 != grant.Grant.RequestSHA256 || w.OriginalCreateSettlementSHA256 != capacity.GuestRetirementSHA(*grant.Settlement) || !w.OriginalCreateReturnedAt.Equal(native.Original.OriginalCreateReturnedAt) || w.Tuple.ResourceID != native.Original.ResourceID || w.Tuple.CreatedAt != grant.Proof.ResourceCreatedAt {
		return ErrHostFactoryHold
	}
	enrollmentRecord, err := originalHostSnapshotSingleton(snapshot, "public.capacity_vm_original_enrollments")
	if err != nil {
		return err
	}
	var receipt model.CapacityGuestOriginalProvisioningReceipt
	if capacity.DecodeGuestLifecycle(enrollmentRecord.original["receipt_wire"], &receipt) != nil || receipt.PreregistrationID != pre.PreregistrationID || receipt.OriginalProvisioningSHA256 != originalHostSQLString(enrollmentRecord, "original_provisioning_sha256") || capacity.GuestRetirementSHA(receipt.Enrollment) != originalHostSQLString(enrollmentRecord, "enrollment_sha256") {
		return ErrHostFactoryHold
	}
	registrationRaw := enrollmentRecord.original["registration_wire"]
	var registration model.CapacityGuestOriginalProvisioningRegistration
	if capacity.DecodeGuestLifecycle(registrationRaw, &registration) != nil || capacity.GuestRetirementSHA(registration) != receipt.OriginalProvisioningSHA256 || capacity.GuestRetirementEnrollment(policy, stored.binding, stored.member, receipt.Enrollment, receipt.RecordedAt) != nil || capacity.GuestOriginalCreateWitness(policy, stored.binding, stored.member, pre, w, receipt.Enrollment.Statement.CoreIntentPublicKey, w.ObservedAt) != nil || capacity.GuestOriginalRegistration(policy, stored.binding, stored.member, w, registration, receipt.RecordedAt) != nil {
		return ErrHostFactoryHold
	}
	return nil
}

// Private original closing persistence state. An uncertain Commit/return never
// resets this to FIRST, even when a database row cannot be read back.
type hostOriginalClosingSQLReturn struct {
	ctx                                                                                                                    context.Context
	realm                                                                                                                  *capacityhostfactory.OriginalFactoryRealm
	db                                                                                                                     *sql.DB
	root                                                                                                                   string
	calledAt, deadline, commitCalledAt, commitReturnedAt, helperReturnedAt, methodFinishedAt, externalCalledAt, returnedAt time.Time
	committed, externalReturnReserved                                                                                      bool
	originalErr                                                                                                            error
	originalRecords                                                                                                        []hostOriginalRetainedRecord
	finalSourceAuditRaw                                                                                                    []byte
}

func (s CapacityStore) PersistOriginalHostClosingIO(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm) (runErr error) {
	codec := originalHostSourceCodecRealm(ctx, realm)

	deadline, bounded := time.Time{}, false
	if ctx != nil {
		deadline, bounded = ctx.Deadline()
	}
	installed, approval, ok := OriginalHostFactoryRealm()
	compiled, err := capacity.ApprovedHostFactorySource()
	a, e1 := codec.Canonical(approval)
	b, e2 := codec.Canonical(compiled)
	if ctx == nil || ctx.Err() != nil || !bounded || !time.Now().Before(deadline) || !ok || installed != realm || realm == nil || s.DB == nil || err != nil || e1 != nil || e2 != nil || !bytes.Equal(a, b) {
		return ErrHostFactoryHold
	}
	// The first attempt is consumed BEFORE either cache-only getter or SQL.
	// A getter/SQL failure cannot obtain a fresh closing attempt on replay.
	installedHostFactory.Lock()
	if installedHostFactory.realm != realm || installedHostFactory.closingSQL != nil {
		installedHostFactory.Unlock()
		return ErrHostFactoryHold
	}
	state := &hostOriginalClosingSQLReturn{ctx: ctx, realm: realm, db: s.DB, root: approval.ScopeRootID, calledAt: time.Now().UTC(), deadline: deadline}
	installedHostFactory.closingSQL = state
	installedHostFactory.Unlock()
	defer func() {
		if cause := recover(); cause != nil {
			installedHostFactory.Lock()
			state.originalErr = errors.Join(state.originalErr, ErrHostFactoryHold)
			installedHostFactory.Unlock()
			panic(cause)
		}
		finishedAt := time.Now().UTC() // INTERNAL defer marker, not outer GoReturn
		installedHostFactory.Lock()
		state.methodFinishedAt = finishedAt
		runErr = errors.Join(runErr, state.originalErr)
		if ctx.Err() != nil || !finishedAt.Before(deadline) {
			runErr = errors.Join(runErr, ErrHostFactoryHold)
		}
		state.originalErr = runErr
		installedHostFactory.Unlock()
	}()
	if ctx.Err() != nil || !state.calledAt.Before(deadline) {
		return ErrHostFactoryHold
	}
	// Getter is cache-only after actual Realm joins, never VerifyLive or Sign.
	originals, err := realm.OriginalClosingIO(ctx)
	if err != nil || len(originals) == 0 || len(originals) > 32768 {
		return ErrHostFactoryHold
	}
	finalRaw, err := realm.OriginalFinalSourceAuditCustody(ctx)
	if err != nil {
		return errors.Join(err, ErrHostFactoryHold)
	}
	final, _, err := parseOriginalHostFinalSourceAuditCustody(finalRaw)
	if err != nil || final.LogicalScopeRootID != approval.ScopeRootID || final.SourceApprovalBodySHA256 != capacity.HostFactoryRawSHA256(a) || originalHostParentHeldAnchorFromSource(ctx, realm, final.OriginalParentHeldRootAnchor) != nil {
		return ErrHostFactoryHold
	}
	installedHostFactory.Lock()
	state.finalSourceAuditRaw = bytes.Clone(finalRaw)
	installedHostFactory.Unlock()
	records := []hostOriginalRetainedRecord{}
	total := 0
	for selector, raw := range originals {
		total += len(raw)
		if len(raw) == 0 || len(raw) > 65536 || total > 32*1024*1024 || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, selector, raw) != nil {
			return ErrHostFactoryHold
		}
		body, value, e := decodeOriginalHistoricalHostStage(codec, selector, raw)
		if e != nil {
			return e
		}
		var root model.HostFactoryRootSignedEnvelope
		var scope capacity.HostFactorySourceSignedEnvelope
		sel := HostFactoryRecordSelector{Family: "root", RootID: approval.ScopeRootID}
		if codec.Decode(raw, &root) == nil {
			sel.Role, sel.BindingSchema, sel.BindingSHA256 = root.Role, root.BindingSchema, root.BindingSHA256
		} else if codec.Decode(raw, &scope) == nil {
			sel.Family = "scope"
			sel.Role = scope.Role
			sel.ScopeSHA256 = scope.PreAuthorityScopeSHA256
			sel.BindingSchema = "original_host_factory_pre_authority_scope_v4"
			sel.BindingSHA256 = scope.PreAuthorityScopeSHA256
		} else {
			return ErrHostFactoryHold
		}
		identity, e := originalHostIOIdentity(codec, sel.RootID, value, body)
		if e != nil {
			return e
		}
		sel.Kind = identity.kind
		if sel.Kind == "handle-inventory" {
			sel.Kind = "inventory"
		}
		sel.OwnerID = identity.owner
		if identity.handle != nil {
			sel.HandleID = *identity.handle
		}
		if identity.kind == "failure-part" {
			parts := strings.Split(selector, "/")
			if len(parts) != 5 {
				return ErrHostFactoryHold
			}
			sel.CollectionID = parts[1]
			ordinal, e := strconv.ParseUint(parts[3], 10, 32)
			if e != nil {
				return ErrHostFactoryHold
			}
			sel.PartOrdinal = uint32(ordinal)
			// Failure collections retain their original signer role; the SAME
			// persisted basal owner is resolved inside the transaction. Never
			// infer an owner from map iteration or synthesize a handle.
		}
		records = append(records, hostOriginalRetainedRecord{selector: sel, body: value, bodyRaw: bytes.Clone(body), envelopeRaw: bytes.Clone(raw)})
	}
	installedHostFactory.Lock()
	state.originalRecords = records
	installedHostFactory.Unlock()
	runErr = s.persistOriginalHostClosingSQL(ctx, approval, state)
	helperReturnedAt := time.Now().UTC() // immediately AFTER helper GoReturn
	retainOriginalHostClosingHelperReturn(state, helperReturnedAt, runErr)
	return runErr
}

func originalHostKnownBindingTx(ctx context.Context, tx *sql.Tx, root, schema, sha string) error {
	var count int
	switch schema {
	case "original_host_factory_source_approval_v4":
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 AND source_approval_sha256=$2`, root, sha).Scan(&count)
		if err != nil {
			return err
		}
	case "original_host_factory_root_preparation_v4":
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 AND root_preparation_sha256=$2`, root, sha).Scan(&count)
		if err != nil {
			return err
		}
	case "original_host_factory_basal_owner_observation_v3":
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND raw_body_sha256=$2 AND stage IN ('basal-owner-core','basal-owner-registrar','basal-owner-worker','ordinary-basal-owner')`, root, sha).Scan(&count)
		if err != nil {
			return err
		}
	case "original_host_factory_pre_authority_scope_v4", "factory_ordinary_source_binding_v4":
		err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_scopes WHERE root_id=$1 AND scope_sha256=$2 AND binding_schema=$3`, root, sha, schema).Scan(&count)
		if err != nil {
			return err
		}
	default:
		return ErrHostFactoryHold
	}
	if count != 1 {
		return ErrHostFactoryHold
	}
	return nil
}

func (s CapacityStore) persistOriginalHostClosingSQL(ctx context.Context, approval model.HostFactorySourceApproval, state *hostOriginalClosingSQLReturn) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	codec := originalHostSourceCodecTx(ctx, tx, approval.ScopeRootID)
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT awaiting_wire FROM public.capacity_host_factory_owners WHERE root_id=$1 AND state='registered'`, approval.ScopeRootID).Scan(&raw); err != nil {
		return err
	}
	var awaiting hostOriginalAwaitingRecord
	if hostOriginalStrictJSON(raw, &awaiting, 65536) != nil || awaiting.RootID != approval.ScopeRootID || awaiting.FactoryClass != hostFactoryClass || awaiting.SourceApprovalSHA256 != capacity.GuestRetirementSHA(approval) || awaiting.CoreActualSourceCommit != capacity.CurrentGuestCoreSource() || awaiting.PolicyID != approval.AllowedPolicyID || awaiting.WorkflowID != approval.AllowedWorkflowID || awaiting.OriginalStepID != approval.AllowedOriginalStepID || awaiting.MutationBindingName != approval.AllowedMutationBindingName || awaiting.Slot != approval.AllowedSlot {
		return ErrHostFactoryHold
	}
	policyManifest, err := scanManifest(tx.QueryRowContext(ctx, `SELECT id,api_version,kind,namespace,name,version,active,description,labels,spec,checksum,created_at,updated_at FROM public.manifests WHERE id=$1`, awaiting.PolicyID))
	if err != nil {
		return err
	}
	workflow, err := scanManifest(tx.QueryRowContext(ctx, `SELECT id,api_version,kind,namespace,name,version,active,description,labels,spec,checksum,created_at,updated_at FROM public.manifests WHERE id=$1`, awaiting.WorkflowID))
	if err != nil {
		return err
	}
	policy, err := manifest.ParseCapacityPolicySpec(policyManifest.Spec)
	if err != nil {
		return err
	}
	workflowSpec, err := manifest.ParseWorkflowSpec(workflow.Spec)
	if err != nil {
		return err
	}
	var assessStep, claimStep, provisionStep model.WorkflowStepSpec
	for _, step := range workflowSpec.Steps {
		switch step.ID {
		case approval.AllowedAssessStepID:
			assessStep = step
		case approval.AllowedClaimStepID:
			claimStep = step
		case approval.AllowedOriginalStepID:
			provisionStep = step
		}
	}
	resolved, err := capacity.VMObservationBinding(policy, awaiting.MutationBindingName)
	if err != nil || policyManifest.Checksum != awaiting.PolicyChecksum || workflow.Checksum != awaiting.WorkflowChecksum || policyManifest.Metadata.Namespace != awaiting.Namespace || workflow.Metadata.Namespace != awaiting.Namespace || !reflect.DeepEqual(resolved, awaiting.Binding) || capacityhostfactory.VerifyOriginalHistoricalPolicyInput(ctx, policyManifest, workflow, assessStep, claimStep, provisionStep) != nil {
		return ErrHostFactoryHold
	}
	if err = lockMutationScope(ctx, tx, awaiting.Namespace, policy); err != nil {
		return err
	}
	if err = lockNativeMutationSlot(ctx, tx, awaiting.Binding, awaiting.Slot); err != nil {
		return err
	}
	if err = lockOriginalHostTarget(ctx, tx, awaiting.StableTargetSHA256); err != nil {
		return err
	}
	var sourceRaw, prepRaw []byte
	var rootAttempt, rootOwner, rootClass string
	var rootTimesConsistent bool
	if err = tx.QueryRowContext(ctx, `SELECT source_approval_wire,root_preparation_wire,factory_attempt_id::text,creator_owner_id::text,factory_registry_class,original_started_at=(convert_from(root_preparation_wire,'UTF8')::jsonb->>'original_context_started_at')::timestamptz AND original_deadline=(convert_from(root_preparation_wire,'UTF8')::jsonb->>'original_context_deadline')::timestamptz FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 FOR SHARE`, approval.ScopeRootID).Scan(&sourceRaw, &prepRaw, &rootAttempt, &rootOwner, &rootClass, &rootTimesConsistent); err != nil {
		return err
	}
	var preparation model.HostFactoryRootPreparation
	compiledRaw, err := codec.Canonical(approval)
	if err != nil || !rootTimesConsistent || !bytes.Equal(sourceRaw, compiledRaw) || len(prepRaw) > 65536 || codec.Decode(prepRaw, &preparation) != nil || preparation.FactoryRootID != awaiting.NativeFactoryRootID || preparation.FactoryEntryClass != awaiting.EntryClass || rootAttempt != awaiting.FactoryAttemptID || rootOwner != awaiting.CreatorOwnerID || rootClass != hostFactoryClass {
		return ErrHostFactoryHold
	}
	actualDeadline, hasDeadline := ctx.Deadline()
	// The immutable BYTEA retains nanoseconds. PostgreSQL's timestamp index
	// is checked by its own cast, never substituted for the original budget.
	if !hasDeadline || actualDeadline.After(preparation.OriginalContextDeadline.Add(150*time.Second)) || actualDeadline.After(preparation.OriginalContextStartedAt.Add(13*time.Minute)) || !state.calledAt.Before(actualDeadline) {
		return ErrHostFactoryHold
	}
	var owner, attempt, target string
	if err = tx.QueryRowContext(ctx, `SELECT owner_id::text,attempt_id::text,stable_target_sha256 FROM public.capacity_host_factory_owners WHERE root_id=$1 FOR SHARE`, approval.ScopeRootID).Scan(&owner, &attempt, &target); err != nil || owner != awaiting.CreatorOwnerID || attempt != awaiting.FactoryAttemptID || target != awaiting.StableTargetSHA256 {
		return ErrHostFactoryHold
	}
	var targetRaw []byte
	var targetRoot, targetAttempt, targetOwner, targetEntry string
	if err = tx.QueryRowContext(ctx, `SELECT target_wire,root_id,factory_attempt_id::text,original_owner_id::text,entry_class FROM public.capacity_host_factory_stable_targets WHERE stable_target_sha256=$1 FOR SHARE`, target).Scan(&targetRaw, &targetRoot, &targetAttempt, &targetOwner, &targetEntry); err != nil {
		return err
	}
	declaredTarget, err := base64.StdEncoding.Strict().DecodeString(awaiting.StableTargetWireBase64)
	if err != nil || len(targetRaw) > 65536 || !bytes.Equal(targetRaw, declaredTarget) || capacity.HostFactoryRawSHA256(targetRaw) != target || targetRoot != awaiting.RootID || targetAttempt != attempt || targetOwner != owner || targetEntry != awaiting.EntryClass {
		return ErrHostFactoryHold
	}
	var originalIntentRaw, currentIntentRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_intent_wire FROM public.capacity_host_factory_leases WHERE root_id=$1 AND original_invocation_id=$2`, awaiting.RootID, awaiting.OriginalInvocationID).Scan(&originalIntentRaw); err != nil {
		return err
	}
	var originalIntent, currentIntent model.CapacityIntent
	if len(originalIntentRaw) > 65536 || capacity.HostFactoryRawSHA256(originalIntentRaw) != awaiting.OriginalClaimIntentRawSHA256 || json.Unmarshal(originalIntentRaw, &originalIntent) != nil || originalIntent.PolicyID.String() != awaiting.PolicyID || originalIntent.PolicyChecksum != awaiting.PolicyChecksum || originalIntent.Namespace != awaiting.Namespace || originalIntent.Environment != awaiting.Environment || originalIntent.Domain != awaiting.Domain || originalIntent.Dimension != awaiting.Dimension || originalIntent.Generation != awaiting.Generation || originalIntent.FencingToken != awaiting.Fence || originalIntent.LeaseExecutorID != awaiting.ExecutorID || originalIntent.LeaseExecutorID != awaiting.OriginalInvocationID || capacity.HostFactoryRawSHA256([]byte(originalIntent.LeaseOwner)) != awaiting.LeaseOwnerSHA256 || originalIntent.LeaseExpiresAt == nil || !originalIntent.LeaseExpiresAt.Equal(awaiting.OriginalLeaseExpiresAt) {
		return ErrHostFactoryHold
	}
	if err = tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR SHARE`, awaiting.Namespace, awaiting.Environment, awaiting.Domain, awaiting.Dimension).Scan(&currentIntentRaw); err != nil {
		return err
	}
	if len(currentIntentRaw) > 65536 || json.Unmarshal(currentIntentRaw, &currentIntent) != nil || currentIntent.PolicyID != originalIntent.PolicyID || currentIntent.PolicyChecksum != originalIntent.PolicyChecksum || currentIntent.Generation != originalIntent.Generation || currentIntent.FencingToken != originalIntent.FencingToken || currentIntent.LeaseOwner != originalIntent.LeaseOwner || currentIntent.LeaseExecutorID != originalIntent.LeaseExecutorID || currentIntent.LeaseExpiresAt == nil || !currentIntent.LeaseExpiresAt.Equal(*originalIntent.LeaseExpiresAt) || currentIntent.RecoveryOnly {
		return ErrHostFactoryHold
	}
	// Closing retains original diagnostics under cleanup150. It compares the
	// same lease; expiry is neither renewed nor treated as new effect authority.
	var grantCount int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_factory_original_grant_bindings WHERE root_id=$1`, awaiting.RootID).Scan(&grantCount); err != nil {
		return err
	}
	if awaiting.EntryClass == "sealed_a0" {
		if grantCount != 0 {
			return ErrHostFactoryHold
		}
	} else {
		if grantCount != 1 {
			return ErrHostFactoryHold
		}
		var grantID, preID, grantRoot, grantAttempt, grantOwner, grantTarget, grantEntry string
		var grantRaw, preRaw, currentGrantRaw, currentPreRaw []byte
		if err = tx.QueryRowContext(ctx, `SELECT grant_id::text,preregistration_id::text,root_id,attempt_id::text,owner_id::text,stable_target_sha256,entry_class,original_grant_wire,original_preregistration_wire FROM public.capacity_factory_original_grant_bindings WHERE root_id=$1 FOR SHARE`, awaiting.RootID).Scan(&grantID, &preID, &grantRoot, &grantAttempt, &grantOwner, &grantTarget, &grantEntry, &grantRaw, &preRaw); err != nil {
			return err
		}
		if grantRoot != awaiting.RootID || grantAttempt != attempt || grantOwner != owner || grantTarget != target || grantEntry != awaiting.EntryClass || len(grantRaw) > 65536 || len(preRaw) > 65536 {
			return ErrHostFactoryHold
		}
		if err = tx.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 FOR SHARE`, grantID).Scan(&currentGrantRaw); err != nil {
			return err
		}
		if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1 FOR SHARE`, preID).Scan(&currentPreRaw); err != nil {
			return err
		}
		var originalGrant, currentGrant capacityMutationRecord
		var pre model.CapacityGuestOriginalProvisioningPreregistration
		if len(currentGrantRaw) > 65536 || json.Unmarshal(grantRaw, &originalGrant) != nil || json.Unmarshal(currentGrantRaw, &currentGrant) != nil || capacity.DecodeGuestLifecycle(preRaw, &pre) != nil || !bytes.Equal(preRaw, currentPreRaw) {
			return ErrHostFactoryHold
		}
		// State is the actual current mutable projection, separate from the
		// immutable Issue BODY. Compare all other original Grant fields without
		// relabeling a successful original as its later state.
		immutableCurrentGrant := currentGrant.Grant
		immutableCurrentGrant.State = originalGrant.Grant.State
		if originalGrant.Grant.State != "issued" || !reflect.DeepEqual(originalGrant.Grant, immutableCurrentGrant) || pre.PreregistrationID != preID || pre.OriginalCreateGrantID != grantID || pre.Generation != awaiting.Generation || pre.Fence != awaiting.Fence || pre.ExecutorID != awaiting.ExecutorID || !reflect.DeepEqual(originalGrant.Binding, awaiting.Binding) || !reflect.DeepEqual(originalGrant.Binding, currentGrant.Binding) || originalGrant.PolicyID.String() != awaiting.PolicyID || currentGrant.PolicyID != originalGrant.PolicyID || originalGrant.PolicyChecksum != awaiting.PolicyChecksum || currentGrant.PolicyChecksum != originalGrant.PolicyChecksum || originalGrant.WorkflowID.String() != awaiting.WorkflowID || currentGrant.WorkflowID != originalGrant.WorkflowID || originalGrant.Generation != awaiting.Generation || currentGrant.Generation != originalGrant.Generation || originalGrant.FencingToken != awaiting.Fence || currentGrant.FencingToken != originalGrant.FencingToken || originalGrant.ExecutorID != awaiting.ExecutorID || currentGrant.ExecutorID != awaiting.ExecutorID || originalGrant.LeaseOwner != originalIntent.LeaseOwner || currentGrant.LeaseOwner != originalIntent.LeaseOwner || originalGrant.Grant.GrantID != grantID || !currentGrant.CreatedAt.Equal(originalGrant.CreatedAt) {
			return ErrHostFactoryHold
		}
	}
	// Compare existing originals with exact read-only identity. New closing
	// rows are appended once; already-retained dependencies are never rewritten.
	pending := []hostOriginalRetainedRecord{}
	for _, record := range state.originalRecords {
		if err = originalHostKnownBindingTx(ctx, tx, approval.ScopeRootID, record.selector.BindingSchema, record.selector.BindingSHA256); err != nil {
			return err
		}
		var existingBody, existingEnvelope []byte
		err = tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND raw_body_sha256=$2`, approval.ScopeRootID, capacity.HostFactoryRawSHA256(record.bodyRaw)).Scan(&existingBody, &existingEnvelope)
		if err == nil {
			if !bytes.Equal(existingBody, record.bodyRaw) || !bytes.Equal(existingEnvelope, record.envelopeRaw) {
				return ErrHostFactoryHold
			}
			if chunk, ok := record.body.(*model.HostFactoryCallVectorChunk); ok {
				x, e := originalHostIOIdentity(codec, approval.ScopeRootID, chunk, record.bodyRaw)
				if e != nil {
					return e
				}
				for i := range chunk.OriginalCalls {
					if _, _, e = originalHostPredecessorTx(ctx, tx, x, capacity.HostFactoryRawSHA256(record.bodyRaw), uint32(i)); e != nil {
						return e
					}
				}
			}
			continue
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		pending = append(pending, record)
	}
	if err = s.appendOriginalHostRecordsTx(ctx, tx, pending); err != nil {
		return err
	}
	storedFinal, _, _, finalErr := readOriginalHostFinalSourceAuditTx(ctx, tx, approval.ScopeRootID)
	if finalErr != nil || !bytes.Equal(storedFinal, state.finalSourceAuditRaw) {
		return ErrHostFactoryHold
	}
	// Provisional SAMEtx authentication above is not Commit/GoReturn closure.
	commitCalledAt := time.Now().UTC()
	err = tx.Commit()
	commitReturnedAt := time.Now().UTC() // actual Commit GoReturn before mutex
	installedHostFactory.Lock()
	state.commitCalledAt, state.commitReturnedAt = commitCalledAt, commitReturnedAt
	state.committed = err == nil
	state.originalErr = errors.Join(state.originalErr, err)
	if ctx.Err() != nil || commitCalledAt.Before(state.calledAt) || commitReturnedAt.Before(commitCalledAt) || !commitReturnedAt.Before(state.deadline) {
		state.originalErr = errors.Join(state.originalErr, ErrHostFactoryHold)
	}
	result := state.originalErr
	installedHostFactory.Unlock()
	return result
}

// Isolated native representation component: native_callbacks.go
type hostOriginalNativeSQLCallbacks struct {
	resolveOriginal  func(string, string) ([]byte, []byte, error)
	resolveIO        func(string) ([]byte, []byte, error)
	predecessor      func(string, uint32) ([]byte, []byte, uint32, error)
	getdentsOriginal func(string) ([]byte, error)
	resolveInventory func(string, model.HostFactoryCallVectorReference) ([]byte, []byte, error)
	originalBasis    func(string, string, string, string, string) ([]byte, []byte, []byte, error)
	originalPhase    func(string, string) ([]byte, error)
}

// SQL callbacks carry original custody only. Guest owns both the live and
// cacheless historical wrappers and their actual compiled observer inventory.
// No SQL body, envelope key or caller flag supplies a trustedObserver key.
func originalHostNativeCallbacksTx(ctx context.Context, tx *sql.Tx, root string) (hostOriginalNativeSQLCallbacks, error) {
	out := hostOriginalNativeSQLCallbacks{}
	codec := originalHostSourceCodecTx(ctx, tx, root)
	if codec.err != nil {
		return out, codec.err
	}
	if ctx == nil || ctx.Err() != nil || tx == nil || !validCapacityExecutor(root) {
		return out, ErrHostFactoryHold
	}
	var nativeRoot string
	if err := tx.QueryRowContext(ctx, `SELECT factory_realm_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, root).Scan(&nativeRoot); err != nil || !validCapacityExecutor(nativeRoot) {
		return out, ErrHostFactoryHold
	}
	out.resolveOriginal = func(bodySHA, envelopeSHA string) ([]byte, []byte, error) {
		if !capacity.ValidDigest(bodySHA) || !capacity.ValidDigest(envelopeSHA) {
			return nil, nil, ErrHostFactoryHold
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind IN ('native-record','native-manifest') AND raw_body_sha256=$2 AND raw_envelope_sha256=$3`, root, bodySHA, envelopeSHA).Scan(&count); err != nil || count != 1 {
			return nil, nil, ErrHostFactoryHold
		}
		var body, envelope []byte
		var bindingSchema, bindingSHA, actualNativeRoot string
		if err := tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire,binding_schema,binding_sha256,native_factory_root_id::text FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind IN ('native-record','native-manifest') AND raw_body_sha256=$2 AND raw_envelope_sha256=$3`, root, bodySHA, envelopeSHA).Scan(&body, &envelope, &bindingSchema, &bindingSHA, &actualNativeRoot); err != nil || actualNativeRoot != nativeRoot || len(body) == 0 || len(body) > 65536 || len(envelope) == 0 || len(envelope) > 65536 || capacity.HostFactoryRawSHA256(body) != bodySHA || capacity.HostFactoryRawSHA256(envelope) != envelopeSHA || originalHostKnownBindingTx(ctx, tx, root, bindingSchema, bindingSHA) != nil {
			return nil, nil, ErrHostFactoryHold
		}
		return bytes.Clone(body), bytes.Clone(envelope), nil
	}
	out.resolveIO = func(sha string) ([]byte, []byte, error) {
		if !capacity.ValidDigest(sha) {
			return nil, nil, ErrHostFactoryHold
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind IN ('chunk','manifest','handle-inventory') AND raw_body_sha256=$2`, root, sha).Scan(&count); err != nil || count != 1 {
			return nil, nil, ErrHostFactoryHold
		}
		var raw, envelope []byte
		var bindingSchema, bindingSHA, handle, tag, envelopeSHA string
		if err := tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire,binding_schema,binding_sha256,original_handle_id::text,record_kind,raw_envelope_sha256 FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind IN ('chunk','manifest','handle-inventory') AND raw_body_sha256=$2`, root, sha).Scan(&raw, &envelope, &bindingSchema, &bindingSHA, &handle, &tag, &envelopeSHA); err != nil || len(raw) == 0 || len(raw) > 65536 || len(envelope) == 0 || len(envelope) > 65536 || capacity.HostFactoryRawSHA256(raw) != sha || capacity.HostFactoryRawSHA256(envelope) != envelopeSHA || originalHostKnownBindingTx(ctx, tx, root, bindingSchema, bindingSHA) != nil {
			return nil, nil, ErrHostFactoryHold
		}
		kind := tag
		if kind == "handle-inventory" {
			kind = "inventory"
		}
		selector := "io-calls/" + handle + "/" + kind + "/" + sha
		embedded, _, decodeErr := decodeOriginalHistoricalHostStage(codec, selector, envelope)
		if decodeErr != nil || !bytes.Equal(embedded, raw) || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, selector, envelope) != nil {
			return nil, nil, ErrHostFactoryHold
		}
		return bytes.Clone(raw), bytes.Clone(envelope), nil
	}
	out.predecessor = func(sha string, index uint32) ([]byte, []byte, uint32, error) {
		raw, _, err := out.resolveIO(sha)
		var chunk model.HostFactoryCallVectorChunk
		if err != nil || codec.Decode(raw, &chunk) != nil || index >= uint32(len(chunk.OriginalCalls)) {
			return nil, nil, 0, ErrHostFactoryHold
		}
		x, err := originalHostIOIdentity(codec, root, &chunk, raw)
		if err != nil {
			return nil, nil, 0, err
		}
		// nil pair is possible only through the actual verified immutable SQL
		// FIRST relation below. Missing rows/foreign indices never become FIRST.
		previous, previousIndex, err := originalHostPredecessorTx(ctx, tx, x, sha, index)
		if err != nil {
			return nil, nil, 0, err
		}
		if previous == nil {
			return nil, nil, previousIndex, nil
		}
		previousBody, previousEnvelope, err := out.resolveIO(capacity.HostFactoryRawSHA256(previous))
		if err != nil || !bytes.Equal(previousBody, previous) || previousIndex != 0 {
			return nil, nil, 0, ErrHostFactoryHold
		}
		return previousBody, previousEnvelope, previousIndex, nil
	}
	out.getdentsOriginal = func(callID string) ([]byte, error) {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_call_snapshot_links l JOIN public.capacity_host_factory_io_returns r ON r.root_id=l.root_id AND r.binding_schema=l.binding_schema AND r.binding_sha256=l.binding_sha256 AND r.original_owner_id=l.original_owner_id AND r.record_kind='chunk' AND r.raw_body_sha256=l.current_chunk_raw_body_sha256 WHERE l.root_id=$1 AND l.original_call_id=$2 AND convert_from(r.raw_body_wire,'UTF8')::jsonb->'original_calls'->l.current_fact_index->>'original_state'='returned'`, root, callID).Scan(&count); err != nil || count != 1 {
			return nil, ErrHostFactoryHold
		}
		var raw, chunkRaw []byte
		var isNull bool
		var index uint32
		if err := tx.QueryRowContext(ctx, `SELECT l.original_getdents_wire IS NULL,l.original_getdents_wire,r.raw_body_wire,l.current_fact_index FROM public.capacity_host_factory_call_snapshot_links l JOIN public.capacity_host_factory_io_returns r ON r.root_id=l.root_id AND r.binding_schema=l.binding_schema AND r.binding_sha256=l.binding_sha256 AND r.original_owner_id=l.original_owner_id AND r.record_kind='chunk' AND r.raw_body_sha256=l.current_chunk_raw_body_sha256 WHERE l.root_id=$1 AND l.original_call_id=$2 AND convert_from(r.raw_body_wire,'UTF8')::jsonb->'original_calls'->l.current_fact_index->>'original_state'='returned'`, root, callID).Scan(&isNull, &raw, &chunkRaw, &index); err != nil || isNull || len(raw) > 65536 || len(chunkRaw) > 65536 {
			return nil, ErrHostFactoryHold
		}
		var chunk model.HostFactoryCallVectorChunk
		if codec.Decode(chunkRaw, &chunk) != nil || index >= uint32(len(chunk.OriginalCalls)) {
			return nil, ErrHostFactoryHold
		}
		sha := capacity.HostFactoryRawSHA256(chunkRaw)
		if _, _, _, err := out.predecessor(sha, index); err != nil {
			return nil, err
		}
		fact := chunk.OriginalCalls[index]
		native := fact.OriginalNativeReturn
		if fact.OriginalCallID == nil || *fact.OriginalCallID != callID || fact.OriginalCount == nil || *fact.OriginalCount != int64(len(raw)) || fact.OriginalSHA256 == nil || *fact.OriginalSHA256 != capacity.HostFactoryRawSHA256(raw) || fact.OriginalEOF == nil || *fact.OriginalEOF || native == nil || native.Kind != "unix_getdents64" || native.OriginalScalar == nil || *native.OriginalScalar != int64(len(raw)) || native.OriginalErrorPresent == nil || *native.OriginalErrorPresent {
			return nil, ErrHostFactoryHold
		}
		if _, err := originalHostGetdentsStoredCustodyTx(ctx, tx, root, callID); err != nil {
			return nil, err
		}
		// Empty genuine terminal bytes remain nonnil; NULL is unknown.
		copyRaw := make([]byte, len(raw))
		copy(copyRaw, raw)
		return copyRaw, nil
	}
	out.resolveInventory = originalHostNativeInventoryResolverTx(ctx, tx, root)
	out.originalPhase = originalHostNativePhaseResolverTx(ctx, tx, root)
	out.originalBasis = func(role, owner, basalSHA, schema, bindingSHA string) ([]byte, []byte, []byte, error) {
		if !validCapacityExecutor(owner) || !capacity.ValidDigest(basalSHA) || originalHostKnownBindingTx(ctx, tx, root, schema, bindingSHA) != nil {
			return nil, nil, nil, ErrHostFactoryHold
		}
		var basalEnvelope, bootstrapEnvelope, basalRaw, bootstrapRaw []byte
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND raw_body_sha256=$3 AND convert_from(raw_body_wire,'UTF8')::jsonb->>'schema'='original_host_factory_basal_owner_observation_v3'`, root, owner, basalSHA).Scan(&count); err != nil || count != 1 {
			return nil, nil, nil, ErrHostFactoryHold
		}
		if err := tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND raw_body_sha256=$3`, root, owner, basalSHA).Scan(&basalRaw, &basalEnvelope); err != nil {
			return nil, nil, nil, err
		}
		var basal model.HostFactoryBasalOwnerObservation
		basalStage := originalHostBasalStage(role)
		if basalStage == "" || len(basalRaw) == 0 || len(basalRaw) > 65536 || len(basalEnvelope) == 0 || len(basalEnvelope) > 65536 || capacity.HostFactoryRawSHA256(basalRaw) != basalSHA || codec.Decode(basalRaw, &basal) != nil || basal.Role != role || basal.FactoryRootID != nativeRoot || basal.OriginalOwnerID != owner || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, basalStage, basalEnvelope) != nil {
			return nil, nil, nil, ErrHostFactoryHold
		}
		decodedBasalRaw, _, basalDecodeErr := decodeOriginalHistoricalHostStage(codec, basalStage, basalEnvelope)
		if basalDecodeErr != nil || !bytes.Equal(decodedBasalRaw, basalRaw) {
			return nil, nil, nil, ErrHostFactoryHold
		}
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND convert_from(raw_body_wire,'UTF8')::jsonb->>'schema'='original_host_factory_bootstrap_return_v4' AND convert_from(raw_body_wire,'UTF8')::jsonb->>'owner_primitive_raw_sha256'=$3`, root, owner, basalSHA).Scan(&count); err != nil || count != 1 {
			return nil, nil, nil, ErrHostFactoryHold
		}
		if err := tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND convert_from(raw_body_wire,'UTF8')::jsonb->>'schema'='original_host_factory_bootstrap_return_v4' AND convert_from(raw_body_wire,'UTF8')::jsonb->>'owner_primitive_raw_sha256'=$3`, root, owner, basalSHA).Scan(&bootstrapRaw, &bootstrapEnvelope); err != nil || len(bootstrapRaw) == 0 || len(bootstrapRaw) > 65536 || len(bootstrapEnvelope) == 0 || len(bootstrapEnvelope) > 65536 {
			return nil, nil, nil, ErrHostFactoryHold
		}
		bootstrapStage := originalHostBootstrapStage(role)
		decodedBootstrapRaw, _, bootstrapDecodeErr := decodeOriginalHistoricalHostStage(codec, bootstrapStage, bootstrapEnvelope)
		if bootstrapStage == "" || bootstrapDecodeErr != nil || !bytes.Equal(decodedBootstrapRaw, bootstrapRaw) || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, bootstrapStage, bootstrapEnvelope) != nil {
			return nil, nil, nil, ErrHostFactoryHold
		}
		var binding []byte
		switch schema {
		case "original_host_factory_basal_owner_observation_v3":
			if bindingSHA != basalSHA {
				return nil, nil, nil, ErrHostFactoryHold
			}
			binding = bytes.Clone(basalRaw)
		case "original_host_factory_source_approval_v4":
			err := tx.QueryRowContext(ctx, `SELECT source_approval_wire FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 AND source_approval_sha256=$2`, root, bindingSHA).Scan(&binding)
			if err != nil {
				return nil, nil, nil, err
			}
		case "original_host_factory_root_preparation_v4":
			err := tx.QueryRowContext(ctx, `SELECT root_preparation_wire FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 AND root_preparation_sha256=$2`, root, bindingSHA).Scan(&binding)
			if err != nil {
				return nil, nil, nil, err
			}
		case "original_host_factory_pre_authority_scope_v4", "factory_ordinary_source_binding_v4":
			err := tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_host_factory_scopes WHERE root_id=$1 AND binding_schema=$2 AND scope_sha256=$3`, root, schema, bindingSHA).Scan(&binding)
			if err != nil {
				return nil, nil, nil, err
			}
		default:
			return nil, nil, nil, ErrHostFactoryHold
		}
		if len(binding) == 0 || len(binding) > 65536 || capacity.HostFactoryRawSHA256(binding) != bindingSHA || !json.Valid(binding) {
			return nil, nil, nil, ErrHostFactoryHold
		}
		if authenticateOriginalHostNativeBindingTx(ctx, tx, root, schema, bindingSHA, binding) != nil {
			return nil, nil, nil, ErrHostFactoryHold
		}
		return bytes.Clone(basalEnvelope), bytes.Clone(bootstrapEnvelope), bytes.Clone(binding), nil
	}
	return out, nil
}

// Isolated native representation component: native_inventory_relations.go
type hostOriginalNativeInventoryRelation struct {
	OriginalCallVector              model.HostFactoryCallVectorReference `json:"original_call_vector"`
	OriginalInventoryBodySHA256     string                               `json:"original_inventory_body_sha256"`
	OriginalInventoryEnvelopeSHA256 string                               `json:"original_inventory_envelope_sha256"`
}

func originalHostNativePayloadVectors(record model.HostFactoryNativeObservationRecord) ([]model.HostFactoryCallVectorReference, error) {
	selected := []any{record.Process, record.TaskDirectory, record.ThreadChildren}
	var payload any
	for _, value := range selected {
		v := reflect.ValueOf(value)
		if v.IsValid() && !v.IsNil() {
			if payload != nil {
				return nil, ErrHostFactoryHold
			}
			payload = value
		}
	}
	if payload == nil {
		return nil, ErrHostFactoryHold
	}
	vectorType := reflect.TypeOf(model.HostFactoryCallVectorReference{})
	seen := map[string]bool{}
	var out []model.HostFactoryCallVectorReference
	var walk func(reflect.Value) error
	walk = func(v reflect.Value) error {
		if !v.IsValid() {
			return nil
		}
		if v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
			if v.IsNil() {
				return nil
			}
			return walk(v.Elem())
		}
		if v.Type() == vectorType {
			ref := v.Interface().(model.HostFactoryCallVectorReference)
			if capacity.ValidateHostFactory(ref) != nil {
				return ErrHostFactoryHold
			}
			identity, err := json.Marshal(ref)
			if err != nil {
				return ErrHostFactoryHold
			}
			if !seen[string(identity)] {
				seen[string(identity)] = true
				out = append(out, ref)
				if len(out) > 20 {
					return ErrHostFactoryHold
				}
			}
			return nil
		}
		switch v.Kind() {
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Type().Field(i).IsExported() {
					if err := walk(v.Field(i)); err != nil {
						return err
					}
				}
			}
		case reflect.Array, reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				if err := walk(v.Index(i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(reflect.ValueOf(payload)); err != nil || len(out) == 0 {
		return nil, ErrHostFactoryHold
	}
	return out, nil
}

// Raw input is preserved for INSERT/SHA. Structural encoding below identifies
// exact selected vectors only; it is never named an original raw publication.
func decodeOriginalHostNativeInventoryRelations(raw []byte, record model.HostFactoryNativeObservationRecord) ([]hostOriginalNativeInventoryRelation, error) {
	var relations []hostOriginalNativeInventoryRelation
	if hostOriginalStrictJSON(raw, &relations, 65536) != nil || len(relations) == 0 || len(relations) > 20 {
		return nil, ErrHostFactoryHold
	}
	vectors, err := originalHostNativePayloadVectors(record)
	if err != nil || len(relations) != len(vectors) {
		return nil, ErrHostFactoryHold
	}
	selected := map[string]bool{}
	for _, ref := range vectors {
		wire, _ := json.Marshal(ref)
		selected[string(wire)] = true
	}
	for _, relation := range relations {
		if !capacity.ValidDigest(relation.OriginalInventoryBodySHA256) || !capacity.ValidDigest(relation.OriginalInventoryEnvelopeSHA256) || capacity.ValidateHostFactory(relation.OriginalCallVector) != nil {
			return nil, ErrHostFactoryHold
		}
		wire, err := json.Marshal(relation.OriginalCallVector)
		if err != nil || !selected[string(wire)] {
			return nil, ErrHostFactoryHold
		}
		delete(selected, string(wire))
	}
	if len(selected) != 0 {
		return nil, ErrHostFactoryHold
	}
	return relations, nil
}

func originalHostNativeSelectedInventoryTx(ctx context.Context, tx *sql.Tx, root string, record model.HostFactoryNativeObservationRecord, relation hostOriginalNativeInventoryRelation) ([]byte, []byte, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)
	if codec.err != nil {
		return nil, nil, codec.err
	}
	ref := relation.OriginalCallVector
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='handle-inventory' AND raw_body_sha256=$2 AND raw_envelope_sha256=$3 AND original_owner_id=$4 AND original_handle_id=$5`, root, relation.OriginalInventoryBodySHA256, relation.OriginalInventoryEnvelopeSHA256, ref.OriginalOwnerID, ref.OriginalHandleID).Scan(&count); err != nil || count != 1 {
		return nil, nil, ErrHostFactoryHold
	}
	var raw, envelope []byte
	if err := tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='handle-inventory' AND raw_body_sha256=$2 AND raw_envelope_sha256=$3 AND original_owner_id=$4 AND original_handle_id=$5`, root, relation.OriginalInventoryBodySHA256, relation.OriginalInventoryEnvelopeSHA256, ref.OriginalOwnerID, ref.OriginalHandleID).Scan(&raw, &envelope); err != nil || len(raw) == 0 || len(raw) > 65536 || len(envelope) == 0 || len(envelope) > 65536 || capacity.HostFactoryRawSHA256(raw) != relation.OriginalInventoryBodySHA256 || capacity.HostFactoryRawSHA256(envelope) != relation.OriginalInventoryEnvelopeSHA256 {
		return nil, nil, ErrHostFactoryHold
	}
	selector := "io-calls/" + ref.OriginalHandleID + "/inventory/" + relation.OriginalInventoryBodySHA256
	embedded, _, decodeErr := decodeOriginalHistoricalHostStage(codec, selector, envelope)
	if decodeErr != nil || !bytes.Equal(embedded, raw) || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, selector, envelope) != nil {
		return nil, nil, ErrHostFactoryHold
	}
	var inventory model.HostFactoryHandleCallInventory
	if codec.Decode(raw, &inventory) != nil || inventory.CollectionState != "complete_original_calls" {
		return nil, nil, ErrHostFactoryHold
	}
	if validateOriginalHostNativeInventoryAncestryTx(ctx, tx, root, record, inventory) != nil {
		return nil, nil, ErrHostFactoryHold
	}
	x, err := originalHostIOIdentity(codec, root, &inventory, raw)
	if err != nil || originalHostKnownBindingTx(ctx, tx, root, inventory.BindingSchema, inventory.BindingSHA256) != nil || validateOriginalHostInventoryTx(ctx, tx, x, inventory) != nil {
		return nil, nil, ErrHostFactoryHold
	}
	matched := false
	for _, vector := range inventory.OperationVectors {
		if reflect.DeepEqual(vector, ref) {
			if matched {
				return nil, nil, ErrHostFactoryHold
			}
			matched = true
		}
	}
	if !matched {
		return nil, nil, ErrHostFactoryHold
	}
	// The authenticated exact record→inventory ancestor chain above preserves
	// the earlier namespace/counter. Source9 still owns actual approved Source
	// and live original cache/phase proofs; SQL/signature alone never supplies it.
	return bytes.Clone(raw), bytes.Clone(envelope), nil
}

func originalHostNativeInventoryResolverTx(ctx context.Context, tx *sql.Tx, root string) func(string, model.HostFactoryCallVectorReference) ([]byte, []byte, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)
	return func(observationID string, requested model.HostFactoryCallVectorReference) ([]byte, []byte, error) {
		if codec.err != nil || !validCapacityExecutor(observationID) {
			return nil, nil, ErrHostFactoryHold
		}
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='native-record' AND native_observation_id=$2`, root, observationID).Scan(&count); err != nil || count != 1 {
			return nil, nil, ErrHostFactoryHold
		}
		var recordRaw, relationRaw []byte
		if err := tx.QueryRowContext(ctx, `SELECT raw_body_wire,native_inventory_relations_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='native-record' AND native_observation_id=$2`, root, observationID).Scan(&recordRaw, &relationRaw); err != nil {
			return nil, nil, ErrHostFactoryHold
		}
		var record model.HostFactoryNativeObservationRecord
		if len(recordRaw) == 0 || len(recordRaw) > 65536 || codec.Decode(recordRaw, &record) != nil || record.ObservationID != observationID || originalHostKnownBindingTx(ctx, tx, root, record.BindingSchema, record.BindingSHA256) != nil {
			return nil, nil, ErrHostFactoryHold
		}
		relations, err := decodeOriginalHostNativeInventoryRelations(relationRaw, record)
		if err != nil {
			return nil, nil, err
		}
		for _, relation := range relations {
			if reflect.DeepEqual(relation.OriginalCallVector, requested) {
				return originalHostNativeSelectedInventoryTx(ctx, tx, root, record, relation)
			}
		}
		return nil, nil, ErrHostFactoryHold
	}
}

// Isolated native representation component: native_append.go
type hostOriginalNativePublication struct {
	tag, root, nativeRoot, bindingSchema, bindingSHA, role, owner, primitive, kind string
	observation, subject, subjectPrimitive, collection                             *string
	ordinal, level, first, last, count                                             *uint32
	identity                                                                       string
}

func originalHostNativePublication(codec hostOriginalSourceCodec, root string, value any) (hostOriginalNativePublication, error) {
	x := hostOriginalNativePublication{root: root}
	if codec.Validate(value) != nil || !validCapacityExecutor(root) {
		return x, ErrHostFactoryHold
	}
	switch v := value.(type) {
	case *model.HostFactoryNativeObservationRecord:
		x.tag, x.nativeRoot, x.bindingSchema, x.bindingSHA = "native-record", v.FactoryRootID, v.BindingSchema, v.BindingSHA256
		x.role, x.owner, x.primitive, x.kind = v.ObserverRole, v.ObserverOwnerID, v.ObserverPrimitiveRawSHA256, v.ObservationKind
		x.observation, x.subject, x.subjectPrimitive = &v.ObservationID, &v.SubjectOwnerID, &v.SubjectPrimitiveRawSHA256
		x.collection, x.ordinal = v.OriginalCensusCollectionID, v.OriginalCensusOrdinal
		// Same original publication UUID cannot get a second identity by a
		// changed payload/hash/subject/binding in this Root namespace.
		x.identity = capacity.GuestRetirementSHA([]string{x.tag, root, v.ObservationID})
	case *model.HostFactoryNativeObservationManifest:
		x.tag, x.nativeRoot, x.bindingSchema, x.bindingSHA = "native-manifest", v.FactoryRootID, v.BindingSchema, v.BindingSHA256
		x.role, x.owner, x.primitive, x.kind = v.ObserverRole, v.ObserverOwnerID, v.ObserverPrimitiveRawSHA256, v.ObservationKind
		x.collection, x.level, x.first, x.last, x.count = &v.CollectionID, &v.Level, &v.FirstOrdinal, &v.LastOrdinal, &v.OriginalObservationCount
		x.identity = capacity.GuestRetirementSHA([]any{x.tag, root, v.CollectionID, v.Level, v.FirstOrdinal})
	default:
		return x, ErrHostFactoryHold
	}
	return x, nil
}

// Envelope/cap/canonical checks preserve original bytes. The private map's
// genuine Source cache/crypto ownership is authenticated before this appender.
// Native positive admission belongs to the separate post-Commit/GoReturn
// current guard; structural storage or provisional TX checks never authorize.
func appendOriginalHostNativePublicationTx(ctx context.Context, tx *sql.Tx, root string, value any, bodyRaw, envelopeRaw []byte) error {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	canonical, err := codec.Canonical(value)
	if err != nil || !bytes.Equal(canonical, bodyRaw) || len(bodyRaw) == 0 || len(bodyRaw) > 65536 || len(envelopeRaw) == 0 || len(envelopeRaw) > 65536 {
		return ErrHostFactoryHold
	}
	x, err := originalHostNativePublication(codec, root, value)
	if err != nil || originalHostKnownBindingTx(ctx, tx, root, x.bindingSchema, x.bindingSHA) != nil {
		return ErrHostFactoryHold
	}
	var rootEnvelope model.HostFactoryRootSignedEnvelope
	var scopeEnvelope capacity.HostFactorySourceSignedEnvelope
	encoded := ""
	if codec.Decode(envelopeRaw, &rootEnvelope) == nil {
		if rootEnvelope.Role != x.role || rootEnvelope.BindingSchema != x.bindingSchema || rootEnvelope.BindingSHA256 != x.bindingSHA {
			return ErrHostFactoryHold
		}
		encoded = rootEnvelope.BodyBase64
	} else if codec.Decode(envelopeRaw, &scopeEnvelope) == nil {
		if scopeEnvelope.Role != x.role || x.bindingSchema != "original_host_factory_pre_authority_scope_v4" || scopeEnvelope.PreAuthorityScopeSHA256 != x.bindingSHA {
			return ErrHostFactoryHold
		}
		encoded = scopeEnvelope.BodyBase64
	} else {
		return ErrHostFactoryHold
	}
	actual, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(actual) != encoded || !bytes.Equal(actual, bodyRaw) {
		return ErrHostFactoryHold
	}
	var nativeRoot string
	if err = tx.QueryRowContext(ctx, `SELECT factory_realm_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 FOR SHARE`, root).Scan(&nativeRoot); err != nil || x.nativeRoot != nativeRoot {
		return ErrHostFactoryHold
	}
	observer, err := originalHostPrimitiveOwnerTx(ctx, tx, root, x.primitive)
	if err != nil || observer != x.owner {
		return ErrHostFactoryHold
	}
	if x.subject != nil {
		subject, err := originalHostPrimitiveOwnerTx(ctx, tx, root, *x.subjectPrimitive)
		if err != nil || subject != *x.subject {
			return ErrHostFactoryHold
		}
	}
	var relationRaw []byte
	if record, ok := value.(*model.HostFactoryNativeObservationRecord); ok {
		realm, approval, installed := OriginalHostFactoryRealm()
		if !installed || realm == nil || approval.ScopeRootID != root {
			return ErrHostFactoryHold
		}
		relationRaw, err = realm.OriginalNativeInventoryRelations(ctx, record.ObservationID)
		if err != nil {
			return ErrHostFactoryHold
		}
		relations, err := decodeOriginalHostNativeInventoryRelations(relationRaw, *record)
		if err != nil {
			return err
		}
		for _, relation := range relations {
			if _, _, err = originalHostNativeSelectedInventoryTx(ctx, tx, root, *record, relation); err != nil {
				return err
			}
		}
		if err = validateOriginalHostStageVectorsTx(ctx, tx, root, record); err != nil {
			return err
		}
	}
	// Exact publication serialization, independent of its raw SHA/range. It
	// never adopts old native results or grants another observation attempt.
	lock, _ := json.Marshal([]any{"host-original-native-publication", root, x.tag, x.observation, x.collection})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(lock)); err != nil {
		return err
	}
	if x.tag == "native-manifest" {
		var overlaps int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='native-manifest' AND native_collection_id=$2 AND native_manifest_level=$3 AND native_first_ordinal<=$4 AND native_last_ordinal>=$5`, root, x.collection, x.level, x.last, x.first).Scan(&overlaps); err != nil || overlaps != 0 {
			return ErrHostFactoryHold
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,record_identity_sha256,native_factory_root_id,native_observation_id,native_observation_kind,native_subject_owner_id,native_observer_primitive_sha256,native_subject_primitive_sha256,native_collection_id,native_census_ordinal,native_manifest_level,native_first_ordinal,native_last_ordinal,native_observation_count,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire,native_inventory_relations_wire) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`, root, x.bindingSchema, x.bindingSHA, x.owner, x.tag, x.identity, x.nativeRoot, x.observation, x.kind, x.subject, x.primitive, x.subjectPrimitive, x.collection, x.ordinal, x.level, x.first, x.last, x.count, capacity.HostFactoryRawSHA256(bodyRaw), bodyRaw, capacity.HostFactoryRawSHA256(envelopeRaw), envelopeRaw, relationRaw)
	return err
}

// This bounded source-owned callback is invoked before the immutable returned
// link INSERT, after the real original getdents GoReturn. Caller buffers cannot
// fill it. Pending/error-only calls stay SQL NULL, not SHA(empty) evidence.
func originalHostGetdentsBeforeLink(fact model.HostFactoryPrimitiveIOReturn, sourceOriginal func(string) ([]byte, error)) ([]byte, error) {
	native := fact.OriginalNativeReturn
	if native == nil || native.Kind != "unix_getdents64" || fact.OriginalState != "returned" || native.OriginalErrorPresent == nil || *native.OriginalErrorPresent {
		return nil, nil
	}
	if sourceOriginal == nil || fact.OriginalCallID == nil || fact.OriginalCount == nil || fact.OriginalSHA256 == nil || native.OriginalScalar == nil || fact.OriginalEOF == nil || *fact.OriginalEOF {
		return nil, ErrHostFactoryHold
	}
	raw, err := sourceOriginal(*fact.OriginalCallID)
	if err != nil || raw == nil || len(raw) > 65536 || int64(len(raw)) != *fact.OriginalCount || int64(len(raw)) != *native.OriginalScalar || capacity.HostFactoryRawSHA256(raw) != *fact.OriginalSHA256 {
		return nil, ErrHostFactoryHold
	}
	copyRaw := make([]byte, len(raw))
	copy(copyRaw, raw)
	return copyRaw, nil
}

func resolveOriginalHostNativeAggregateTx(ctx context.Context, tx *sql.Tx, root, schema, bindingSHA string, originalDeadline time.Time, body any, envelopeRaw, phaseRaw []byte) ([]model.HostFactoryNativeObservationRecord, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
	realm, approval, installed := OriginalHostFactoryRealm()
	if err != nil || !installed || realm == nil || approval.ScopeRootID != root || originalDeadline.IsZero() || originalHostKnownBindingTx(ctx, tx, root, schema, bindingSHA) != nil {
		return nil, ErrHostFactoryHold
	}
	var nativeRoot string
	if err = tx.QueryRowContext(ctx, `SELECT factory_realm_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, root).Scan(&nativeRoot); err != nil {
		return nil, err
	}
	bodyRaw, err := codec.Canonical(body)
	if err != nil || len(envelopeRaw) == 0 || len(envelopeRaw) > 65536 || validateOriginalHostNativePhaseTx(ctx, tx, root, schema, bindingSHA, body, capacity.HostFactoryRawSHA256(envelopeRaw), phaseRaw) != nil {
		return nil, ErrHostFactoryHold
	}
	bodySHA, envelopeSHA := capacity.HostFactoryRawSHA256(bodyRaw), capacity.HostFactoryRawSHA256(envelopeRaw)
	// First append has no future SQL stage row. This lexical closure owns only
	// the genuine Source getter's exact bytes and both original stage hashes.
	callbacks.originalPhase = func(b, e string) ([]byte, error) {
		if b != bodySHA || e != envelopeSHA {
			return nil, ErrHostFactoryHold
		}
		return bytes.Clone(phaseRaw), nil
	}
	observations, err := realm.ResolveOriginalSourceNativeAggregate(ctx, body, nativeRoot, schema, bindingSHA, originalDeadline, envelopeSHA, callbacks.resolveOriginal, callbacks.resolveIO, callbacks.predecessor, callbacks.getdentsOriginal, callbacks.resolveInventory, callbacks.originalBasis, callbacks.originalPhase)
	if err != nil {
		return nil, err
	}
	for _, observation := range observations {
		// Native payload selected through WHOLE original observation bytes.
		// Existing scalar/descriptor/pin/IO/FIRST guards still apply to payloads.
		if observation.FactoryRootID != nativeRoot || validateOriginalHostStageVectorsTx(ctx, tx, root, observation) != nil {
			return nil, fmt.Errorf("original native payload join: %w", ErrHostFactoryHold)
		}
	}
	if err = validateOriginalHostNativePriorRelationsTx(ctx, tx, root, body, observations); err != nil {
		return nil, err
	}
	return observations, nil
}

// A historical reader never installs/reconstructs a live Realm. The cacheless
// wrapper owns the exact compiled Source/observer inventory, independently of
// this readonly original SQL custody callback set.
func resolveOriginalHostHistoricalNativeAggregateTx(ctx context.Context, tx *sql.Tx, root, schema, bindingSHA string, originalDeadline time.Time, body any, envelopeSHA string) ([]model.HostFactoryNativeObservationRecord, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
	if err != nil || originalDeadline.IsZero() || originalHostKnownBindingTx(ctx, tx, root, schema, bindingSHA) != nil {
		return nil, ErrHostFactoryHold
	}
	var nativeRoot string
	if err = tx.QueryRowContext(ctx, `SELECT factory_realm_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, root).Scan(&nativeRoot); err != nil {
		return nil, err
	}
	observations, err := capacityhostfactory.ResolveOriginalHistoricalSourceNativeAggregate(ctx, codec.approvalRaw, codec.approvalEnvelope, body, nativeRoot, schema, bindingSHA, originalDeadline, envelopeSHA, callbacks.resolveOriginal, callbacks.resolveIO, callbacks.predecessor, callbacks.getdentsOriginal, callbacks.resolveInventory, callbacks.originalBasis, callbacks.originalPhase)
	if err != nil {
		return nil, err
	}
	for _, observation := range observations {
		if observation.FactoryRootID != nativeRoot || validateOriginalHostStageVectorsTx(ctx, tx, root, observation) != nil {
			return nil, fmt.Errorf("historical original native payload join: %w", ErrHostFactoryHold)
		}
	}
	if err = validateOriginalHostNativePriorRelationsTx(ctx, tx, root, body, observations); err != nil {
		return nil, err
	}
	return observations, nil
}

// Isolated native representation component: native_stage_integration.go
func originalHostNativeSelector(selector string) (kind, bodySHA, envelopeSHA string, err error) {
	parts := strings.Split(selector, "/")
	if len(parts) != 4 || parts[0] != "native-observations" || (parts[1] != "record" && parts[1] != "manifest") || !capacity.ValidDigest(parts[2]) || !capacity.ValidDigest(parts[3]) {
		return "", "", "", ErrHostFactoryHold
	}
	return "native-" + parts[1], parts[2], parts[3], nil
}

func originalHostNativePhaseOwner(body any) (model.HostFactoryNativeObservationReference, error) {
	if body == nil || reflect.ValueOf(body).Kind() == reflect.Pointer && reflect.ValueOf(body).IsNil() {
		return model.HostFactoryNativeObservationReference{}, ErrHostFactoryHold
	}
	switch x := body.(type) {
	case *model.HostFactoryOriginalStartReturn:
		return x.Exterior, nil
	case *model.HostFactoryAliveNativeRead:
		return x.Worker, nil
	case *model.HostFactoryExteriorJoin:
		return x.Exterior, nil
	case *model.HostFactoryTerminalRead:
		return x.ReaderBefore, nil
	case *model.HostFactoryNativeLeaf:
		return x.Process, nil
	case *model.HostFactoryInitialEmptyRealmRead:
		return x.ControlBefore, nil
	case *model.HostFactoryOriginalEmptyRealmRead:
		return x.ControlProcessBefore, nil
	default:
		return model.HostFactoryNativeObservationReference{}, ErrHostFactoryHold
	}
}

func originalHostNativePhaseDeadlineTx(ctx context.Context, tx *sql.Tx, root string, body any) (time.Time, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	ref, err := originalHostNativePhaseOwner(body)
	if err != nil || codec.Validate(ref) != nil {
		return time.Time{}, ErrHostFactoryHold
	}
	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
	if err != nil {
		return time.Time{}, err
	}
	raw, envelope, err := callbacks.resolveOriginal(ref.OriginalBodySHA256, ref.OriginalEnvelopeSHA256)
	selector := "native-observations/record/" + ref.OriginalBodySHA256 + "/" + ref.OriginalEnvelopeSHA256
	if err != nil || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, selector, envelope) != nil {
		return time.Time{}, ErrHostFactoryHold
	}
	var record model.HostFactoryNativeObservationRecord
	if codec.Decode(raw, &record) != nil || record.ObservationID != ref.ObservationID || record.ObservationKind != ref.ObservationKind || record.ObserverOwnerID != ref.ObserverOwnerID || record.ObserverPrimitiveRawSHA256 != ref.ObserverPrimitiveRawSHA256 || record.SubjectOwnerID != ref.SubjectOwnerID || record.SubjectPrimitiveRawSHA256 != ref.SubjectPrimitiveRawSHA256 || record.OriginalOperationDeadline.IsZero() {
		return time.Time{}, ErrHostFactoryHold
	}
	// Fixed Source phase-owner selection, not minimum dates/latest row/Now.
	// The wrapper authenticates current phase, lease and exact ancestor
	// bindings; inherited declarations retain their own original deadlines.
	return record.OriginalOperationDeadline, nil
}

func originalHostIsNativeAggregate(body any) bool {
	switch body.(type) {
	case *model.HostFactoryOriginalStartReturn, *model.HostFactoryAliveNativeRead, *model.HostFactoryExteriorJoin, *model.HostFactoryTerminalRead, *model.HostFactoryNativeLeaf, *model.HostFactoryInitialEmptyRealmRead, *model.HostFactoryOriginalEmptyRealmRead:
		return true
	default:
		return false
	}
}

func validateOriginalHostNativeAggregateTx(ctx context.Context, tx *sql.Tx, root, schema, sha string, body any, envelopeRaw []byte) ([]byte, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	if !originalHostIsNativeAggregate(body) {
		return nil, nil
	}
	deadline, err := originalHostNativePhaseDeadlineTx(ctx, tx, root, body)
	if err != nil {
		return nil, err
	}
	realm, approval, installed := OriginalHostFactoryRealm()
	bodyRaw, err := codec.Canonical(body)
	if err != nil || !installed || realm == nil || approval.ScopeRootID != root {
		return nil, ErrHostFactoryHold
	}
	phaseRaw, err := realm.OriginalNativePhaseContext(ctx, capacity.HostFactoryRawSHA256(bodyRaw))
	if err != nil {
		return nil, ErrHostFactoryHold
	}
	_, err = resolveOriginalHostNativeAggregateTx(ctx, tx, root, schema, sha, deadline, body, envelopeRaw, phaseRaw)
	if err != nil {
		return nil, err
	}
	return phaseRaw, nil
}

// This is the current post-primer-return admission path. The source-owned
// getter must equal the SAME immutable phase BYTEA from the committed stage;
// lexical first-append validation cannot stand in for the committed relation.
func compareOriginalHostNativeAggregateTx(ctx context.Context, tx *sql.Tx, selector HostFactoryRecordSelector, body any, bodyRaw, envelopeRaw []byte) error {
	phaseRaw, err := validateOriginalHostNativeAggregateTx(ctx, tx, selector.RootID, selector.BindingSchema, selector.BindingSHA256, body, envelopeRaw)
	if err != nil {
		return err
	}
	if !originalHostIsNativeAggregate(body) {
		var retained []byte
		if tx.QueryRowContext(ctx, `SELECT native_phase_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage=$2 AND binding_schema=$3 AND binding_sha256=$4 AND raw_body_sha256=$5 AND raw_envelope_sha256=$6`, selector.RootID, selector.Stage, selector.BindingSchema, selector.BindingSHA256, capacity.HostFactoryRawSHA256(bodyRaw), capacity.HostFactoryRawSHA256(envelopeRaw)).Scan(&retained) != nil || retained != nil {
			return ErrHostFactoryHold
		}
		return nil
	}
	retained, err := originalHostNativePhaseResolverTx(ctx, tx, selector.RootID)(capacity.HostFactoryRawSHA256(bodyRaw), capacity.HostFactoryRawSHA256(envelopeRaw))
	if err != nil || !bytes.Equal(retained, phaseRaw) {
		return ErrHostFactoryHold
	}
	return nil
}

func validateOriginalHostHistoricalNativeAggregateTx(ctx context.Context, tx *sql.Tx, root, schema, sha string, body any, envelopeRaw []byte) error {
	if !originalHostIsNativeAggregate(body) {
		return nil
	}
	deadline, err := originalHostNativePhaseDeadlineTx(ctx, tx, root, body)
	if err != nil {
		return err
	}
	_, err = resolveOriginalHostHistoricalNativeAggregateTx(ctx, tx, root, schema, sha, deadline, body, capacity.HostFactoryRawSHA256(envelopeRaw))
	return err
}

func validateOriginalHostNativeStoredRecordTx(ctx context.Context, tx *sql.Tx, root string, record model.HostFactoryNativeObservationRecord, relationRaw []byte) error {
	relations, err := decodeOriginalHostNativeInventoryRelations(relationRaw, record)
	if err != nil || validateOriginalHostStageVectorsTx(ctx, tx, root, record) != nil {
		return ErrHostFactoryHold
	}
	for _, relation := range relations {
		if _, _, err = originalHostNativeSelectedInventoryTx(ctx, tx, root, record, relation); err != nil {
			return err
		}
	}
	if record.TaskDirectory != nil {
		callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
		if err != nil {
			return err
		}
		facts, err := originalHostVectorFactsTx(ctx, tx, root, record.TaskDirectory.OriginalGetdentsCallVector)
		if err != nil {
			return err
		}
		for _, fact := range facts {
			if fact.OriginalCallID == nil {
				return ErrHostFactoryHold
			}
			if _, err = callbacks.getdentsOriginal(*fact.OriginalCallID); err != nil {
				return err
			}
		}
	}
	return nil
}

// Isolated native representation component: native_binding_custody.go
func originalHostAuthenticatedStageBodyTx(ctx context.Context, tx *sql.Tx, root, stage, bodySHA string, target any) ([]byte, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage=$2 AND raw_body_sha256=$3`, root, stage, bodySHA).Scan(&count) != nil || count != 1 {
		return nil, ErrHostFactoryHold
	}
	var raw, envelope []byte
	var envelopeSHA string
	if tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire,raw_envelope_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage=$2 AND raw_body_sha256=$3`, root, stage, bodySHA).Scan(&raw, &envelope, &envelopeSHA) != nil || len(raw) == 0 || len(raw) > 65536 || len(envelope) == 0 || len(envelope) > 65536 || capacity.HostFactoryRawSHA256(raw) != bodySHA || capacity.HostFactoryRawSHA256(envelope) != envelopeSHA || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, stage, envelope) != nil {
		return nil, ErrHostFactoryHold
	}
	body, _, err := decodeOriginalHistoricalHostStage(codec, stage, envelope)
	if err != nil || !bytes.Equal(body, raw) || codec.Decode(raw, target) != nil {
		return nil, ErrHostFactoryHold
	}
	return raw, nil
}

func authenticateOriginalHostNativeBindingTx(ctx context.Context, tx *sql.Tx, root, schema, sha string, raw []byte) error {
	if len(raw) == 0 || len(raw) > 65536 || capacity.HostFactoryRawSHA256(raw) != sha {
		return ErrHostFactoryHold
	}
	stage := ""
	var target any
	switch schema {
	case "original_host_factory_source_approval_v4":
		stage = "source-approval"
		target = &model.HostFactorySourceApproval{}
	case "original_host_factory_root_preparation_v4":
		stage = "root-preparation"
		target = &model.HostFactoryRootPreparation{}
	case "original_host_factory_pre_authority_scope_v4":
		stage = "preauthority-scope"
		target = &model.HostFactoryPreAuthorityScope{}
	case "factory_ordinary_source_binding_v4":
		return authenticateOriginalHostNativeOrdinaryBindingTx(ctx, tx, root, sha, raw)
	case "original_host_factory_basal_owner_observation_v3":
		// No current actual producer/native operation uses basal-v3 binding.
		return ErrHostFactoryHold
	default:
		return ErrHostFactoryHold
	}
	actual, err := originalHostAuthenticatedStageBodyTx(ctx, tx, root, stage, sha, target)
	if err != nil || !bytes.Equal(actual, raw) {
		return ErrHostFactoryHold
	}
	return nil
}

func authenticateOriginalHostNativeOrdinaryBindingTx(ctx context.Context, tx *sql.Tx, root, sha string, raw []byte) error {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	var binding model.FactoryOrdinarySourceBinding
	if codec.Decode(raw, &binding) != nil || capacity.HostFactoryRawSHA256(raw) != sha {
		return ErrHostFactoryHold
	}
	var parentSHA, basalSHA, bootstrapSHA string
	var count int
	query := `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage=$2 AND binding_schema='factory_ordinary_source_binding_v4' AND binding_sha256=$3`
	for _, stage := range []string{"ordinary-bootstrap-write", "ordinary-basal-owner", "ordinary-bootstrap-return"} {
		if tx.QueryRowContext(ctx, query, root, stage, sha).Scan(&count) != nil || count != 1 {
			return ErrHostFactoryHold
		}
	}
	for _, pick := range []struct {
		stage string
		sha   *string
	}{{"ordinary-bootstrap-write", &parentSHA}, {"ordinary-basal-owner", &basalSHA}, {"ordinary-bootstrap-return", &bootstrapSHA}} {
		if tx.QueryRowContext(ctx, `SELECT raw_body_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage=$2 AND binding_schema='factory_ordinary_source_binding_v4' AND binding_sha256=$3`, root, pick.stage, sha).Scan(pick.sha) != nil {
			return ErrHostFactoryHold
		}
	}
	var parent model.HostFactoryBootstrapWriteReturn
	var basal model.HostFactoryBasalOwnerObservation
	var bootstrap model.HostFactoryBootstrapReturn
	if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, root, "ordinary-bootstrap-write", parentSHA, &parent); err != nil {
		return err
	}
	if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, root, "ordinary-basal-owner", basalSHA, &basal); err != nil {
		return err
	}
	if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, root, "ordinary-bootstrap-return", bootstrapSHA, &bootstrap); err != nil {
		return err
	}
	if parent.BindingSchema != binding.Schema || parent.BindingSHA256 != sha || parent.RecipientOwnerID != binding.CreatorOwnerID || basal.Role != "factory_ordinary_worker" || basal.OriginalOwnerID != binding.CreatorOwnerID || basal.FactoryRootID != binding.FactoryRootID || bootstrap.Role != basal.Role || bootstrap.OwnerPrimitiveRawSHA256 != basalSHA || bootstrap.BootstrapBindingSchema != binding.Schema || bootstrap.BootstrapBindingSHA256 != sha {
		return ErrHostFactoryHold
	}
	for _, value := range []any{parent, basal, bootstrap} {
		if validateOriginalHostStageVectorsTx(ctx, tx, root, value) != nil {
			return ErrHostFactoryHold
		}
	}
	// Actual SAME parent pipe/ExtraFiles/Start/child-read segment joins remain
	// mandatory in Source9's source-owned wrapper/whole consumer. This chain
	// authenticates the private bare BODY hash; no signed ordinary-source-
	// binding stage is invented and no SQL/key/signature creates Source trust.
	return nil
}

// Isolated native representation component: native_prior_relations.go
func originalHostNativeReferenceRecordTx(ctx context.Context, tx *sql.Tx, root string, ref model.HostFactoryNativeObservationReference) (model.HostFactoryNativeObservationRecord, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	var record model.HostFactoryNativeObservationRecord
	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
	if err != nil || codec.Validate(ref) != nil {
		return record, ErrHostFactoryHold
	}
	raw, envelope, err := callbacks.resolveOriginal(ref.OriginalBodySHA256, ref.OriginalEnvelopeSHA256)
	if err != nil || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, "native-observations/record/"+ref.OriginalBodySHA256+"/"+ref.OriginalEnvelopeSHA256, envelope) != nil || codec.Decode(raw, &record) != nil || record.ObservationID != ref.ObservationID || record.ObservationKind != ref.ObservationKind || record.ObserverOwnerID != ref.ObserverOwnerID || record.ObserverPrimitiveRawSHA256 != ref.ObserverPrimitiveRawSHA256 || record.SubjectOwnerID != ref.SubjectOwnerID || record.SubjectPrimitiveRawSHA256 != ref.SubjectPrimitiveRawSHA256 {
		return record, ErrHostFactoryHold
	}
	return record, nil
}

func validateOriginalHostNativePriorRelationsTx(ctx context.Context, tx *sql.Tx, root string, body any, records []model.HostFactoryNativeObservationRecord) error {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	for _, record := range records {
		if record.ThreadChildren == nil {
			continue
		}
		thread := record.ThreadChildren
		var count int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND raw_body_sha256=$2 AND stage IN ('native-leaf-core-by-registrar','native-leaf-registrar-by-core','native-leaf-worker','ordinary-native-leaf-worker')`, root, thread.OwnerNativeReceiptSHA256).Scan(&count) != nil || count != 1 {
			return ErrHostFactoryHold
		}
		var stage string
		if tx.QueryRowContext(ctx, `SELECT stage FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND raw_body_sha256=$2 AND stage IN ('native-leaf-core-by-registrar','native-leaf-registrar-by-core','native-leaf-worker','ordinary-native-leaf-worker')`, root, thread.OwnerNativeReceiptSHA256).Scan(&stage) != nil {
			return ErrHostFactoryHold
		}
		var leaf model.HostFactoryNativeLeaf
		if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, root, stage, thread.OwnerNativeReceiptSHA256, &leaf); err != nil {
			return err
		}
		processRecord, err := originalHostNativeReferenceRecordTx(ctx, tx, root, leaf.Process)
		if err != nil || processRecord.Process == nil || leaf.Role != record.SubjectRole || leaf.SubjectPrimitiveRawSHA256 != record.SubjectPrimitiveRawSHA256 || processRecord.SubjectOwnerID != record.SubjectOwnerID || processRecord.SubjectPrimitiveRawSHA256 != record.SubjectPrimitiveRawSHA256 || processRecord.Process.PID != thread.PID || processRecord.Process.BootstrapReturnSHA256 != leaf.BootstrapReturnSHA256 || processRecord.Process.OriginalNativeCloseReturnedAt.After(thread.OriginalThreadStatBeforeRead.OriginalCalledAt) {
			return ErrHostFactoryHold
		}
		var bootstrapRaw []byte
		if tx.QueryRowContext(ctx, `SELECT raw_body_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND raw_body_sha256=$3`, root, record.SubjectOwnerID, leaf.BootstrapReturnSHA256).Scan(&bootstrapRaw) != nil {
			return ErrHostFactoryHold
		}
		var bootstrap model.HostFactoryBootstrapReturn
		if len(bootstrapRaw) == 0 || len(bootstrapRaw) > 65536 || capacity.HostFactoryRawSHA256(bootstrapRaw) != leaf.BootstrapReturnSHA256 || codec.Decode(bootstrapRaw, &bootstrap) != nil || bootstrap.OwnerPrimitiveRawSHA256 != record.SubjectPrimitiveRawSHA256 || bootstrap.Role != record.SubjectRole {
			return ErrHostFactoryHold
		}
		if authenticateOriginalHostNativeSubjectTx(ctx, tx, root, record.SubjectOwnerID, record.SubjectRole, record.SubjectPrimitiveRawSHA256, leaf.BootstrapReturnSHA256) != nil {
			return ErrHostFactoryHold
		}
	}
	empty, ok := body.(*model.HostFactoryOriginalEmptyRealmRead)
	if !ok {
		return nil
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='alive-native-read' AND binding_schema='original_host_factory_pre_authority_scope_v4' AND binding_sha256=$2`, root, empty.PreAuthorityScopeSHA256).Scan(&count) != nil || count != 1 {
		return ErrHostFactoryHold
	}
	var sha string
	if tx.QueryRowContext(ctx, `SELECT raw_body_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='alive-native-read' AND binding_schema='original_host_factory_pre_authority_scope_v4' AND binding_sha256=$2`, root, empty.PreAuthorityScopeSHA256).Scan(&sha) != nil {
		return ErrHostFactoryHold
	}
	var alive model.HostFactoryAliveNativeRead
	if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, root, "alive-native-read", sha, &alive); err != nil {
		return err
	}
	registrar, err := originalHostNativeReferenceRecordTx(ctx, tx, root, alive.Registrar)
	if err != nil || registrar.Process == nil || registrar.SubjectRole != "host_registrar" || alive.ObservedAt.After(empty.OriginalReadStartedAt) {
		return ErrHostFactoryHold
	}
	if authenticateOriginalHostNativeSubjectTx(ctx, tx, root, registrar.SubjectOwnerID, registrar.SubjectRole, registrar.SubjectPrimitiveRawSHA256, registrar.Process.BootstrapReturnSHA256) != nil {
		return ErrHostFactoryHold
	}
	for _, ref := range []model.HostFactoryNativeObservationReference{empty.TaskInventoriesBefore[1], empty.TaskInventoriesAfter[1]} {
		taskRecord, err := originalHostNativeReferenceRecordTx(ctx, tx, root, ref)
		if err != nil || taskRecord.TaskDirectory == nil || taskRecord.SubjectOwnerID != registrar.SubjectOwnerID || taskRecord.SubjectPrimitiveRawSHA256 != registrar.SubjectPrimitiveRawSHA256 || taskRecord.SubjectRole != registrar.SubjectRole || taskRecord.TaskDirectory.SubjectPID != registrar.Process.PID || taskRecord.TaskDirectory.SubjectStartTicks != registrar.Process.StartTicks || taskRecord.TaskDirectory.SubjectBootID != registrar.Process.HostBootID {
			return ErrHostFactoryHold
		}
	}
	return nil
}

func authenticateOriginalHostNativeSubjectTx(ctx context.Context, tx *sql.Tx, root, owner, role, basalSHA, bootstrapSHA string) error {
	var basalStage, bootstrapStage string
	for _, pick := range []struct {
		sha   string
		stage *string
	}{{basalSHA, &basalStage}, {bootstrapSHA, &bootstrapStage}} {
		var count int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND raw_body_sha256=$3`, root, owner, pick.sha).Scan(&count) != nil || count != 1 {
			return ErrHostFactoryHold
		}
		if tx.QueryRowContext(ctx, `SELECT stage FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND raw_body_sha256=$3`, root, owner, pick.sha).Scan(pick.stage) != nil {
			return ErrHostFactoryHold
		}
	}
	var basal model.HostFactoryBasalOwnerObservation
	var bootstrap model.HostFactoryBootstrapReturn
	if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, root, basalStage, basalSHA, &basal); err != nil {
		return err
	}
	if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, root, bootstrapStage, bootstrapSHA, &bootstrap); err != nil {
		return err
	}
	if basal.OriginalOwnerID != owner || basal.Role != role || bootstrap.Role != role || bootstrap.OwnerPrimitiveRawSHA256 != basalSHA {
		return ErrHostFactoryHold
	}
	return nil
}

// Isolated native representation component: native_inventory_ancestry.go
func originalHostNativeBindingRawTx(ctx context.Context, tx *sql.Tx, root, schema, sha string) ([]byte, error) {
	if originalHostKnownBindingTx(ctx, tx, root, schema, sha) != nil {
		return nil, ErrHostFactoryHold
	}
	var raw []byte
	var err error
	switch schema {
	case "original_host_factory_source_approval_v4":
		err = tx.QueryRowContext(ctx, `SELECT source_approval_wire FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 AND source_approval_sha256=$2`, root, sha).Scan(&raw)
	case "original_host_factory_root_preparation_v4":
		err = tx.QueryRowContext(ctx, `SELECT root_preparation_wire FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 AND root_preparation_sha256=$2`, root, sha).Scan(&raw)
	case "original_host_factory_pre_authority_scope_v4", "factory_ordinary_source_binding_v4":
		err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_host_factory_scopes WHERE root_id=$1 AND binding_schema=$2 AND scope_sha256=$3`, root, schema, sha).Scan(&raw)
	default:
		return nil, ErrHostFactoryHold
	}
	if err != nil || authenticateOriginalHostNativeBindingTx(ctx, tx, root, schema, sha, raw) != nil {
		return nil, ErrHostFactoryHold
	}
	return raw, nil
}

func validateOriginalHostNativeInventoryAncestryTx(ctx context.Context, tx *sql.Tx, root string, record model.HostFactoryNativeObservationRecord, inventory model.HostFactoryHandleCallInventory) error {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	// Every namespace is authenticated first, even equality; membership alone
	// cannot fill a missing Source/body/original parent proof.
	recordRaw, err := originalHostNativeBindingRawTx(ctx, tx, root, record.BindingSchema, record.BindingSHA256)
	if err != nil {
		return err
	}
	if _, err = originalHostNativeBindingRawTx(ctx, tx, root, inventory.BindingSchema, inventory.BindingSHA256); err != nil {
		return err
	}
	if record.BindingSchema == inventory.BindingSchema && record.BindingSHA256 == inventory.BindingSHA256 {
		return nil
	}
	var approvalRaw, prepRaw []byte
	var approvalSHA, prepSHA, nativeRoot string
	if tx.QueryRowContext(ctx, `SELECT source_approval_wire,source_approval_sha256,root_preparation_wire,root_preparation_sha256,factory_realm_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, root).Scan(&approvalRaw, &approvalSHA, &prepRaw, &prepSHA, &nativeRoot) != nil {
		return ErrHostFactoryHold
	}
	if authenticateOriginalHostNativeBindingTx(ctx, tx, root, "original_host_factory_source_approval_v4", approvalSHA, approvalRaw) != nil || authenticateOriginalHostNativeBindingTx(ctx, tx, root, "original_host_factory_root_preparation_v4", prepSHA, prepRaw) != nil {
		return ErrHostFactoryHold
	}
	var approval model.HostFactorySourceApproval
	var prep model.HostFactoryRootPreparation
	if codec.Decode(approvalRaw, &approval) != nil || codec.Decode(prepRaw, &prep) != nil || approval.ScopeRootID != root || prep.FactoryRootID != nativeRoot || record.FactoryRootID != nativeRoot || prep.SourceApprovalSHA256 != approvalSHA || prep.FactoryRegistrySHA256 != approval.FactoryRegistrySHA256 || prep.FactorySourceClosureSHA256 != approval.FactorySourceClosureSHA256 {
		return ErrHostFactoryHold
	}
	ancestorApproval := inventory.BindingSchema == "original_host_factory_source_approval_v4" && inventory.BindingSHA256 == approvalSHA
	ancestorRoot := inventory.BindingSchema == "original_host_factory_root_preparation_v4" && inventory.BindingSHA256 == prepSHA
	switch record.BindingSchema {
	case "original_host_factory_root_preparation_v4":
		if record.BindingSHA256 != prepSHA || !ancestorApproval {
			return ErrHostFactoryHold
		}
	case "original_host_factory_pre_authority_scope_v4":
		var scope model.HostFactoryPreAuthorityScope
		if codec.Decode(recordRaw, &scope) != nil || scope.ScopeRootID != root || scope.FactoryRealmID != nativeRoot || scope.FactoryRegistrySHA256 != prep.FactoryRegistrySHA256 || scope.FactorySourceClosureSHA256 != prep.FactorySourceClosureSHA256 || scope.CoreActualSourceCommit != approval.ActualBuildSourceCommit || scope.FactoryEntryClass != prep.FactoryEntryClass || (!ancestorApproval && !ancestorRoot) {
			return ErrHostFactoryHold
		}
	case "factory_ordinary_source_binding_v4":
		var binding model.FactoryOrdinarySourceBinding
		if codec.Decode(recordRaw, &binding) != nil || binding.FactoryRootID != nativeRoot || binding.SourceApprovalSHA256 != approvalSHA || prep.FactoryEntryClass != "ordinary_original_create" || (!ancestorApproval && !ancestorRoot) {
			return ErrHostFactoryHold
		}
	default:
		return ErrHostFactoryHold
	}
	// No foreign/sibling Scope/ordinary or unproduced basal-v3 alias; original
	// handle counter/acquisition and source/owner still join the whole inventory.
	return nil
}

// Isolated native representation component: native_phase_custody.go
type hostOriginalNativePhase struct {
	Schema                      string                                      `json:"schema"`
	FactoryRootID               string                                      `json:"factory_root_id"`
	SourceApprovalBodySHA256    string                                      `json:"source_approval_body_sha256"`
	OriginalPhaseID             string                                      `json:"original_phase_id"`
	StageSelector               string                                      `json:"stage_selector"`
	AggregateSchema             string                                      `json:"aggregate_schema"`
	AggregateBodySHA256         string                                      `json:"aggregate_body_sha256"`
	AggregateEnvelopeSHA256     string                                      `json:"aggregate_envelope_sha256"`
	PhaseAnchor                 model.HostFactoryNativeObservationReference `json:"phase_anchor"`
	ObserverOwnerID             string                                      `json:"observer_owner_id"`
	ObserverPrimitiveRawSHA256  string                                      `json:"observer_primitive_raw_sha256"`
	BindingSchema               string                                      `json:"binding_schema"`
	BindingSHA256               string                                      `json:"binding_sha256"`
	OriginalContextStartedAt    time.Time                                   `json:"original_context_started_at"`
	OriginalRootContextDeadline time.Time                                   `json:"original_root_context_deadline"`
	OriginalEffectiveDeadline   time.Time                                   `json:"original_effective_deadline"`
	OriginalCalledAt            time.Time                                   `json:"original_called_at"`
	OriginalReturnedAt          time.Time                                   `json:"original_returned_at"`
}

func originalHostNativePhaseStageSchema(stage string) string {
	switch stage {
	case "original-start-return":
		return "original_host_factory_original_start_return_v5"
	case "alive-native-read":
		return "original_host_factory_alive_native_read_v5"
	case "exterior-join":
		return "original_host_factory_exterior_join_v5"
	case "terminal-read":
		return "original_host_factory_terminal_read_v5"
	case "native-leaf-core-by-registrar", "native-leaf-registrar-by-core", "native-leaf-worker", "ordinary-native-leaf-worker":
		return "original_host_factory_native_leaf_v5"
	case "initial-empty-realm-read":
		return "original_host_factory_initial_empty_realm_read_v5"
	case "poststart-empty-realm-read":
		return "original_host_factory_original_empty_realm_read_v5"
	default:
		return ""
	}
}

func originalHostNativeAggregateStage(body any) (string, error) {
	switch x := body.(type) {
	case *model.HostFactoryOriginalStartReturn:
		return "original-start-return", nil
	case *model.HostFactoryAliveNativeRead:
		return "alive-native-read", nil
	case *model.HostFactoryExteriorJoin:
		return "exterior-join", nil
	case *model.HostFactoryTerminalRead:
		return "terminal-read", nil
	case *model.HostFactoryInitialEmptyRealmRead:
		return "initial-empty-realm-read", nil
	case *model.HostFactoryOriginalEmptyRealmRead:
		return "poststart-empty-realm-read", nil
	case *model.HostFactoryNativeLeaf:
		if x != nil {
			switch x.Role {
			case "host_exterior":
				return "native-leaf-core-by-registrar", nil
			case "host_registrar":
				return "native-leaf-registrar-by-core", nil
			case "host_worker":
				return "native-leaf-worker", nil
			case "factory_ordinary_worker":
				return "ordinary-native-leaf-worker", nil
			}
		}
	}
	return "", ErrHostFactoryHold
}

func decodeOriginalHostNativePhaseWire(raw []byte) (hostOriginalNativePhase, error) {
	var phase hostOriginalNativePhase
	if hostOriginalStrictJSON(raw, &phase, 65536) != nil {
		return phase, ErrHostFactoryHold
	}
	canonical, err := json.Marshal(phase)
	if err != nil || !bytes.Equal(canonical, raw) || phase.Schema != "source_private_original_native_phase_context_v1" || originalHostNativePhaseStageSchema(phase.StageSelector) == "" || phase.AggregateSchema != originalHostNativePhaseStageSchema(phase.StageSelector) || capacity.ValidateHostFactory(phase.PhaseAnchor) != nil || phase.OriginalPhaseID == phase.PhaseAnchor.ObservationID || phase.ObserverOwnerID != phase.PhaseAnchor.ObserverOwnerID || phase.ObserverPrimitiveRawSHA256 != phase.PhaseAnchor.ObserverPrimitiveRawSHA256 {
		return phase, ErrHostFactoryHold
	}
	switch phase.BindingSchema {
	case "original_host_factory_source_approval_v4", "original_host_factory_root_preparation_v4", "original_host_factory_pre_authority_scope_v4", "factory_ordinary_source_binding_v4":
	default:
		return phase, ErrHostFactoryHold
	}
	for _, id := range []string{phase.FactoryRootID, phase.OriginalPhaseID, phase.ObserverOwnerID} {
		if !validCapacityExecutor(id) || len(id) != 36 || strings.ToLower(id) != id {
			return phase, ErrHostFactoryHold
		}
	}
	for _, sha := range []string{phase.SourceApprovalBodySHA256, phase.ObserverPrimitiveRawSHA256, phase.AggregateBodySHA256, phase.AggregateEnvelopeSHA256, phase.BindingSHA256} {
		if !capacity.ValidDigest(sha) {
			return phase, ErrHostFactoryHold
		}
	}
	for _, at := range []time.Time{phase.OriginalContextStartedAt, phase.OriginalRootContextDeadline, phase.OriginalEffectiveDeadline, phase.OriginalCalledAt, phase.OriginalReturnedAt} {
		if at.IsZero() || at.Location() != time.UTC {
			return phase, ErrHostFactoryHold
		}
	}
	if phase.OriginalCalledAt.Before(phase.OriginalContextStartedAt) || phase.OriginalReturnedAt.Before(phase.OriginalCalledAt) || phase.OriginalReturnedAt.After(phase.OriginalEffectiveDeadline) || !phase.OriginalEffectiveDeadline.After(phase.OriginalCalledAt) || phase.OriginalEffectiveDeadline.After(phase.OriginalRootContextDeadline) {
		return phase, ErrHostFactoryHold
	}
	return phase, nil
}

func decodeOriginalHostNativePhase(codec hostOriginalSourceCodec, raw []byte, body any, bodySHA, envelopeSHA, schema, bindingSHA string) (hostOriginalNativePhase, error) {
	phase, err := decodeOriginalHostNativePhaseWire(raw)
	anchor, anchorErr := originalHostNativePhaseOwner(body)
	stage, stageErr := originalHostNativeAggregateStage(body)
	if err != nil || anchorErr != nil || stageErr != nil || phase.AggregateBodySHA256 != bodySHA || phase.AggregateEnvelopeSHA256 != envelopeSHA || phase.BindingSchema != schema || phase.BindingSHA256 != bindingSHA || phase.PhaseAnchor != anchor || phase.StageSelector != stage {
		return phase, ErrHostFactoryHold
	}
	var header struct {
		Schema string `json:"schema"`
	}
	bodyRaw, err := codec.Canonical(body)
	if err != nil || json.Unmarshal(bodyRaw, &header) != nil || phase.AggregateSchema != header.Schema || capacity.HostFactoryRawSHA256(bodyRaw) != bodySHA {
		return phase, ErrHostFactoryHold
	}
	return phase, nil
}

func validateOriginalHostNativePhaseTx(ctx context.Context, tx *sql.Tx, root, schema, bindingSHA string, body any, envelopeSHA string, raw []byte) error {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	bodyRaw, err := codec.Canonical(body)
	if err != nil {
		return ErrHostFactoryHold
	}
	phase, err := decodeOriginalHostNativePhase(codec, raw, body, capacity.HostFactoryRawSHA256(bodyRaw), envelopeSHA, schema, bindingSHA)
	if err != nil {
		return err
	}
	var approvalRaw, prepRaw []byte
	var approvalSHA, nativeRoot string
	if tx.QueryRowContext(ctx, `SELECT source_approval_wire,source_approval_sha256,root_preparation_wire,factory_realm_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, root).Scan(&approvalRaw, &approvalSHA, &prepRaw, &nativeRoot) != nil || nativeRoot != phase.FactoryRootID || approvalSHA != phase.SourceApprovalBodySHA256 {
		return ErrHostFactoryHold
	}
	var approval model.HostFactorySourceApproval
	var prep model.HostFactoryRootPreparation
	if codec.Decode(approvalRaw, &approval) != nil || codec.Decode(prepRaw, &prep) != nil || approval.ScopeRootID != root || prep.FactoryRootID != nativeRoot || prep.SourceApprovalSHA256 != approvalSHA || !phase.OriginalContextStartedAt.Equal(prep.OriginalContextStartedAt) || phase.OriginalRootContextDeadline.After(prep.OriginalContextDeadline) {
		return ErrHostFactoryHold
	}
	if _, err = originalHostNativeBindingRawTx(ctx, tx, root, schema, bindingSHA); err != nil {
		return err
	}
	anchor, err := originalHostNativeReferenceRecordTx(ctx, tx, root, phase.PhaseAnchor)
	if err != nil || !anchor.OriginalOperationDeadline.Equal(phase.OriginalEffectiveDeadline) {
		return ErrHostFactoryHold
	}
	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
	if err != nil {
		return err
	}
	basalEnvelope, _, _, err := callbacks.originalBasis(anchor.ObserverRole, anchor.ObserverOwnerID, anchor.ObserverPrimitiveRawSHA256, anchor.BindingSchema, anchor.BindingSHA256)
	var basal model.HostFactoryBasalOwnerObservation
	_, basalValue, errDecode := decodeOriginalHistoricalHostStage(codec, originalHostBasalStage(anchor.ObserverRole), basalEnvelope)
	if err != nil || errDecode != nil {
		return ErrHostFactoryHold
	}
	basalPtr, ok := basalValue.(*model.HostFactoryBasalOwnerObservation)
	if !ok {
		return ErrHostFactoryHold
	}
	basal = *basalPtr
	// Context origin belongs to the SAME first Core/Root request. The anchor
	// observer retains that transferred declaration, while its actual process
	// acquisition/syscall/return times remain independent native facts.
	if basal.OriginalOwnerID != phase.ObserverOwnerID || basal.FactoryRootID != nativeRoot || !basal.OriginalContextStartedAt.Equal(prep.OriginalContextStartedAt) || phase.OriginalRootContextDeadline.After(basal.OriginalContextDeadline) {
		return ErrHostFactoryHold
	}
	// Before Claim there is deliberately no future lease requirement. The
	// original root/source constructor/native graph is authenticated first.
	beforeClaim := schema == "original_host_factory_source_approval_v4" || schema == "original_host_factory_root_preparation_v4"
	if beforeClaim {
		if phase.StageSelector != "initial-empty-realm-read" && phase.StageSelector != "native-leaf-core-by-registrar" && phase.StageSelector != "native-leaf-registrar-by-core" {
			return ErrHostFactoryHold
		}
		// First live append deliberately precedes lease insertion. In a later
		// historical join, the actual signed Claim return must remain later.
		var count int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='original-lease-provenance'`, root).Scan(&count) != nil || count > 1 {
			return ErrHostFactoryHold
		}
		if count == 1 {
			var sha string
			var provenance model.HostFactoryOriginalLeaseProvenance
			if tx.QueryRowContext(ctx, `SELECT raw_body_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='original-lease-provenance'`, root).Scan(&sha) != nil {
				return ErrHostFactoryHold
			}
			if _, err = originalHostAuthenticatedStageBodyTx(ctx, tx, root, "original-lease-provenance", sha, &provenance); err != nil || phase.OriginalReturnedAt.After(provenance.OriginalClaimReturnedAt) {
				return ErrHostFactoryHold
			}
		}
		return nil
	}
	var provenanceRaw, bindingRaw []byte
	var provenanceSHA string
	if tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_body_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='original-lease-provenance'`, root).Scan(&provenanceRaw, &provenanceSHA) != nil {
		return ErrHostFactoryHold
	}
	var provenance model.HostFactoryOriginalLeaseProvenance
	if _, err = originalHostAuthenticatedStageBodyTx(ctx, tx, root, "original-lease-provenance", provenanceSHA, &provenance); err != nil || provenance.FactoryRootID != nativeRoot || provenance.CoreActualSourceCommit != approval.ActualBuildSourceCommit || phase.OriginalCalledAt.Before(provenance.CurrentLeaseReadReturnedAt) || phase.OriginalEffectiveDeadline.After(provenance.OriginalLeaseExpiresAt) {
		return ErrHostFactoryHold
	}
	var originalIntent []byte
	if tx.QueryRowContext(ctx, `SELECT original_intent_wire FROM public.capacity_host_factory_leases WHERE root_id=$1 AND original_invocation_id=$2 AND original_intent_sha256=$3`, root, provenance.OriginalProtectedInvocationID, provenance.OriginalClaimIntentRawSHA256).Scan(&originalIntent) != nil {
		return ErrHostFactoryHold
	}
	var intent model.CapacityIntent
	if json.Unmarshal(originalIntent, &intent) != nil || capacity.HostFactoryRawSHA256(originalIntent) != provenance.OriginalClaimIntentRawSHA256 || intent.Generation != provenance.Generation || intent.FencingToken != provenance.Fence || intent.LeaseExecutorID != provenance.ExecutorID || capacity.HostFactoryRawSHA256([]byte(intent.LeaseOwner)) != provenance.LeaseOwnerSHA256 || intent.LeaseExpiresAt == nil || !intent.LeaseExpiresAt.Equal(provenance.OriginalLeaseExpiresAt) {
		return ErrHostFactoryHold
	}
	if tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_host_factory_scopes WHERE root_id=$1 AND binding_schema=$2 AND scope_sha256=$3`, root, schema, bindingSHA).Scan(&bindingRaw) != nil {
		return ErrHostFactoryHold
	}
	var targetSHA, provenanceBindingSHA string
	var bindingDeadline time.Time
	switch schema {
	case "original_host_factory_pre_authority_scope_v4":
		var scope model.HostFactoryPreAuthorityScope
		if codec.Decode(bindingRaw, &scope) != nil || scope.PolicyID != provenance.ActualPolicyID || scope.WorkflowID != provenance.ActualWorkflowID || scope.OriginalStepID != provenance.OriginalProvisionStepID || scope.Generation != provenance.Generation || scope.Fence != provenance.Fence || scope.ExecutorID != provenance.ExecutorID || scope.LeaseOwnerSHA256 != provenance.LeaseOwnerSHA256 {
			return ErrHostFactoryHold
		}
		targetSHA, provenanceBindingSHA, bindingDeadline = scope.StableOriginalTargetSHA256, scope.OriginalLeaseProvenanceSHA256, scope.OriginalContextDeadline
	case "factory_ordinary_source_binding_v4":
		var binding model.FactoryOrdinarySourceBinding
		if codec.Decode(bindingRaw, &binding) != nil || binding.PolicyID != provenance.ActualPolicyID || binding.WorkflowID != provenance.ActualWorkflowID || binding.OriginalStepID != provenance.OriginalProvisionStepID {
			return ErrHostFactoryHold
		}
		targetSHA, provenanceBindingSHA, bindingDeadline = binding.StableOriginalTargetSHA256, binding.OriginalLeaseProvenanceSHA256, binding.OriginalContextDeadline
	default:
		return ErrHostFactoryHold
	}
	if provenanceBindingSHA != provenanceSHA || phase.OriginalEffectiveDeadline.After(bindingDeadline) {
		return ErrHostFactoryHold
	}
	var awaitingRaw []byte
	if tx.QueryRowContext(ctx, `SELECT awaiting_wire FROM public.capacity_host_factory_owners WHERE root_id=$1 AND stable_target_sha256=$2`, root, targetSHA).Scan(&awaitingRaw) != nil {
		return ErrHostFactoryHold
	}
	var awaiting hostOriginalAwaitingRecord
	if hostOriginalStrictJSON(awaitingRaw, &awaiting, 65536) != nil || awaiting.RootID != root || awaiting.NativeFactoryRootID != nativeRoot || awaiting.StableTargetSHA256 != targetSHA || awaiting.OriginalInvocationID != provenance.OriginalProtectedInvocationID || awaiting.Generation != provenance.Generation || awaiting.Fence != provenance.Fence || awaiting.LeaseOwnerSHA256 != provenance.LeaseOwnerSHA256 || awaiting.ExecutorID != provenance.ExecutorID || awaiting.PolicyID != provenance.ActualPolicyID || awaiting.PolicyChecksum != provenance.ActualPolicyChecksum || awaiting.WorkflowID != provenance.ActualWorkflowID || awaiting.WorkflowChecksum != provenance.ActualWorkflowChecksum || awaiting.OriginalStepID != provenance.OriginalProvisionStepID || awaiting.SourceApprovalSHA256 != approvalSHA || awaiting.OriginalClaimIntentRawSHA256 != provenance.OriginalClaimIntentRawSHA256 || awaiting.CoreActualSourceCommit != approval.ActualBuildSourceCommit || !awaiting.OriginalLeaseExpiresAt.Equal(provenance.OriginalLeaseExpiresAt) || phase.OriginalEffectiveDeadline.After(awaiting.OriginalContextDeadline) {
		return ErrHostFactoryHold
	}
	if prep.FactoryEntryClass == "sealed_a1" && (phase.StageSelector == "exterior-join" || phase.StageSelector == "terminal-read") {
		var grantRaw, preRaw []byte
		if tx.QueryRowContext(ctx, `SELECT original_grant_wire,original_preregistration_wire FROM public.capacity_factory_original_grant_bindings WHERE root_id=$1 AND stable_target_sha256=$2`, root, targetSHA).Scan(&grantRaw, &preRaw) != nil {
			return ErrHostFactoryHold
		}
		var grant capacityMutationRecord
		var pre model.CapacityGuestOriginalProvisioningPreregistration
		if json.Unmarshal(grantRaw, &grant) != nil || capacity.DecodeGuestLifecycle(preRaw, &pre) != nil || pre.OriginalCreateGrantID != grant.Grant.GrantID || grant.ExecutorID != provenance.ExecutorID || phase.OriginalEffectiveDeadline.After(grant.Grant.ExpiresAt) || phase.OriginalEffectiveDeadline.After(pre.OriginalDeadline) {
			return ErrHostFactoryHold
		}
	}
	return nil
}

func originalHostBasalStage(role string) string {
	switch role {
	case "host_exterior":
		return "basal-owner-core"
	case "host_registrar":
		return "basal-owner-registrar"
	case "host_worker":
		return "basal-owner-worker"
	case "factory_ordinary_worker":
		return "ordinary-basal-owner"
	}
	return ""
}

func originalHostBootstrapStage(role string) string {
	switch role {
	case "host_exterior":
		return "bootstrap-return-core"
	case "host_registrar":
		return "bootstrap-return-registrar"
	case "host_worker":
		return "bootstrap-return-worker"
	case "factory_ordinary_worker":
		return "ordinary-bootstrap-return"
	default:
		return ""
	}
}

func originalHostNativePhaseResolverTx(ctx context.Context, tx *sql.Tx, root string) func(string, string) ([]byte, error) {
	return func(bodySHA, envelopeSHA string) ([]byte, error) {
		if !capacity.ValidDigest(bodySHA) || !capacity.ValidDigest(envelopeSHA) {
			return nil, ErrHostFactoryHold
		}
		var count int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND raw_body_sha256=$2 AND raw_envelope_sha256=$3`, root, bodySHA, envelopeSHA).Scan(&count) != nil || count != 1 {
			return nil, ErrHostFactoryHold
		}
		var stage, schema, bindingSHA string
		var bodyRaw, envelopeRaw, phaseRaw []byte
		if tx.QueryRowContext(ctx, `SELECT stage,binding_schema,binding_sha256,raw_body_wire,raw_envelope_wire,native_phase_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND raw_body_sha256=$2 AND raw_envelope_sha256=$3`, root, bodySHA, envelopeSHA).Scan(&stage, &schema, &bindingSHA, &bodyRaw, &envelopeRaw, &phaseRaw) != nil || len(phaseRaw) == 0 || len(phaseRaw) > 65536 || capacity.HostFactoryRawSHA256(bodyRaw) != bodySHA || capacity.HostFactoryRawSHA256(envelopeRaw) != envelopeSHA {
			return nil, ErrHostFactoryHold
		}
		body := originalHostStageTarget(stage)
		if body == nil || !originalHostIsNativeAggregate(body) || originalHostAuthenticatedStageInto(ctx, tx, root, stage, bodySHA, body) != nil || validateOriginalHostNativePhaseTx(ctx, tx, root, schema, bindingSHA, body, envelopeSHA, phaseRaw) != nil {
			return nil, ErrHostFactoryHold
		}
		return bytes.Clone(phaseRaw), nil
	}
}

func originalHostAuthenticatedStageInto(ctx context.Context, tx *sql.Tx, root, stage, sha string, body any) error {
	_, err := originalHostAuthenticatedStageBodyTx(ctx, tx, root, stage, sha, body)
	return err
}

// Isolated native representation component: native_source_audit_custody.go
type hostOriginalGetdentsWriterAuditReference struct {
	Basename                          string   `json:"basename"`
	OriginalBytes                     int      `json:"original_bytes"`
	OriginalSHA256                    string   `json:"original_sha256"`
	RequestID                         string   `json:"request_id"`
	OriginalCallID                    string   `json:"original_call_id"`
	OriginalChunkBodySHA256           string   `json:"original_chunk_body_sha256"`
	OriginalChunkEnvelopeSHA256       string   `json:"original_chunk_envelope_sha256"`
	OriginalFactIndex                 uint32   `json:"original_fact_index"`
	OriginalOwnerID                   string   `json:"original_owner_id"`
	BindingSchema                     string   `json:"binding_schema"`
	BindingSHA256                     string   `json:"binding_sha256"`
	OriginalWriterHandleID            string   `json:"original_writer_handle_id"`
	OriginalWriterCloseCallID         string   `json:"original_writer_close_call_id"`
	OriginalPublicationMethodHandleID string   `json:"original_publication_method_handle_id"`
	OriginalWriterCallReferences      []string `json:"original_writer_call_references"`
	OriginalPublicationCallReferences []string `json:"original_publication_call_references"`
}

type hostOriginalGetdentsWriterAuditArtifact struct {
	Schema                            string                              `json:"schema"`
	FactoryRootID                     string                              `json:"factory_root_id"`
	RequestID                         string                              `json:"request_id"`
	Phase                             string                              `json:"phase"`
	OriginalCallID                    string                              `json:"original_call_id"`
	OriginalChunkBodySHA256           string                              `json:"original_chunk_body_sha256"`
	OriginalChunkEnvelopeSHA256       string                              `json:"original_chunk_envelope_sha256"`
	OriginalFactIndex                 uint32                              `json:"original_fact_index"`
	OriginalOwnerID                   string                              `json:"original_owner_id"`
	BindingSchema                     string                              `json:"binding_schema"`
	BindingSHA256                     string                              `json:"binding_sha256"`
	OriginalRawBytes                  int                                 `json:"original_raw_bytes"`
	OriginalRawSHA256                 string                              `json:"original_raw_sha256"`
	SourceAuditOwnerID                string                              `json:"source_audit_owner_id"`
	SourceAuditOwnerRole              string                              `json:"source_audit_owner_role"`
	SourceAuditBindingSchema          string                              `json:"source_audit_binding_schema"`
	SourceAuditBindingSHA256          string                              `json:"source_audit_binding_sha256"`
	OriginalWriterHandleID            string                              `json:"original_writer_handle_id"`
	OriginalWriterCloseCallID         string                              `json:"original_writer_close_call_id"`
	OriginalPublicationMethodHandleID string                              `json:"original_publication_method_handle_id"`
	OriginalWriterCallReferences      []string                            `json:"original_writer_call_references"`
	OriginalPublicationCallReferences []string                            `json:"original_publication_call_references"`
	OriginalSourceAuditProjections    []hostOriginalSourceAuditProjection `json:"original_source_audit_projections"`
}

type hostOriginalGetdentsSourceFileSelection struct {
	OriginalHandleID               string                              `json:"original_handle_id"`
	OriginalCloseCallID            string                              `json:"original_close_call_id"`
	OriginalCallReferences         []string                            `json:"original_call_references"`
	OriginalSourceAuditProjections []hostOriginalSourceAuditProjection `json:"original_source_audit_projections"`
}

type hostOriginalGetdentsSourceAuditCustody struct {
	Schema                            string                                    `json:"schema"`
	CustodyClass                      string                                    `json:"custody_class"`
	FactoryRootID                     string                                    `json:"factory_root_id"`
	RequestID                         string                                    `json:"request_id"`
	Phase                             string                                    `json:"phase"`
	OriginalCallID                    string                                    `json:"original_call_id"`
	OriginalChunkBodySHA256           string                                    `json:"original_chunk_body_sha256"`
	OriginalChunkEnvelopeSHA256       string                                    `json:"original_chunk_envelope_sha256"`
	OriginalFactIndex                 uint32                                    `json:"original_fact_index"`
	OriginalOwnerID                   string                                    `json:"original_owner_id"`
	BindingSchema                     string                                    `json:"binding_schema"`
	BindingSHA256                     string                                    `json:"binding_sha256"`
	OriginalRawBytes                  int                                       `json:"original_raw_bytes"`
	OriginalRawSHA256                 string                                    `json:"original_raw_sha256"`
	OriginalReaderAudit               *hostOriginalGetdentsSourceFileSelection  `json:"original_reader_audit"`
	OriginalWriterAudit               *hostOriginalGetdentsWriterAuditReference `json:"original_writer_audit"`
	OriginalWriterAuditRaw            *[]byte                                   `json:"original_writer_audit_raw"`
	OriginalWriterAuditArtifactReader *hostOriginalGetdentsSourceFileSelection  `json:"original_writer_audit_artifact_reader"`
}

// The identity comes from the actual immutable signed chunk/returned link;
// it is not decoded from the unsigned custody header or supplied by HTTP.
type hostOriginalGetdentsCustodyIdentity struct {
	nativeRoot, owner, schema, bindingSHA, chunkSHA, envelopeSHA string
	index                                                        uint32
	fact                                                         model.HostFactoryPrimitiveIOReturn
}

// Every nullable member is an explicit original NULL, never an omitted
// producer field. The closed pair also applies to nested projection4/5/20.
// Byte transport and timestamps remain opaque scalars to this presence check;
// hostOriginalStrictJSON and the semantic guards validate their actual types.
func originalHostSourceCustodyRequiredFields(raw []byte, kind reflect.Type, depth int) error {
	if depth > 32 {
		return ErrHostFactoryHold
	}
	if kind.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return originalHostSourceCustodyRequiredFields(raw, kind.Elem(), depth+1)
	}
	if kind == reflect.TypeOf(time.Time{}) {
		return nil
	}
	if kind == reflect.TypeOf(json.RawMessage(nil)) {
		return nil // raw JSON has its own existing typed decoding semantics
	}
	switch kind.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || len(fields) != kind.NumField() {
			return ErrHostFactoryHold
		}
		for n := 0; n < kind.NumField(); n++ {
			field := kind.Field(n)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			value, exists := fields[name]
			if name == "" || name == "-" || !exists || originalHostSourceCustodyRequiredFields(value, field.Type, depth+1) != nil {
				return ErrHostFactoryHold
			}
		}
	case reflect.Slice:
		if kind == reflect.TypeOf([]byte(nil)) {
			// encoding/json also accepts a numeric array for []byte. The
			// paired transport permits only the exact canonical base64 string.
			trimmed := bytes.TrimSpace(raw)
			if len(trimmed) < 2 || trimmed[0] != '"' || trimmed[len(trimmed)-1] != '"' {
				return ErrHostFactoryHold
			}
			var encoded string
			if json.Unmarshal(raw, &encoded) != nil {
				return ErrHostFactoryHold
			}
			original, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || base64.StdEncoding.EncodeToString(original) != encoded {
				return ErrHostFactoryHold
			}
			canonical, err := json.Marshal(encoded)
			if err != nil || !bytes.Equal(canonical, raw) {
				return ErrHostFactoryHold
			}
			return nil
		}
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || len(values) > 4096 {
			return ErrHostFactoryHold
		}
		for _, value := range values {
			if originalHostSourceCustodyRequiredFields(value, kind.Elem(), depth+1) != nil {
				return ErrHostFactoryHold
			}
		}
	}
	return nil
}

func originalHostSourceCustodyCallID(id, handle string) bool {
	parts := strings.Split(id, ":")
	if len(parts) != 2 || parts[0] != handle || !validCapacityExecutor(handle) {
		return false
	}
	n, err := strconv.ParseUint(parts[1], 10, 64)
	return err == nil && n > 0 && n <= 65536 && parts[1] == strconv.FormatUint(n, 10)
}

func originalHostGetdentsSourceSelection(selection hostOriginalGetdentsSourceFileSelection, nativeRoot string, writer bool, expectedCount int) error {
	rows := selection.OriginalSourceAuditProjections
	if !validCapacityExecutor(selection.OriginalHandleID) || !originalHostSourceCustodyCallID(selection.OriginalCloseCallID, selection.OriginalHandleID) || len(rows) < 4 || len(rows) > 4096 || len(selection.OriginalCallReferences) != len(rows) || expectedCount < 0 || expectedCount > 65536 {
		return ErrHostFactoryHold
	}
	var prior time.Time
	var count int64
	fstats, reads, writes, syncs, eof := 0, 0, 0, 0, false
	for n, row := range rows {
		fact := row.Fact
		id := selection.OriginalHandleID + ":" + strconv.Itoa(n+1)
		if row.Family != "source_audit" || row.SubjectIdentity.SubjectKind != "source_file" || row.SubjectIdentity.RequestIdentity != nil || row.SubjectIdentity.PublicRunID != nil || row.SubjectIdentity.Method != nil || row.SubjectIdentity.PathFamily != nil || capacity.ValidateHostFactory(fact) != nil || fact.FactoryRootID != nativeRoot || fact.OriginalAuditHandleID != selection.OriginalHandleID || fact.OriginalCallID == nil || *fact.OriginalCallID != id || selection.OriginalCallReferences[n] != id || row.OriginalCloseReference == nil || *row.OriginalCloseReference != selection.OriginalCloseCallID || fact.OriginalState != "returned" || fact.OriginalCalledAt == nil || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || fact.OriginalCalledAt.Before(prior) || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || fact.OriginalSHA256 != nil || fact.RetainedPrefixSHA256 != nil || fact.RetainedPrefixBytes != nil || fact.OriginalReadScope != nil {
			return ErrHostFactoryHold
		}
		prior = *fact.OriginalReturnedAt
		switch fact.Operation {
		case "source_file_open":
			if n != 0 || *fact.OriginalErrorPresent || fact.OriginalCount != nil || fact.OriginalEOF != nil || fact.OriginalHashState != "not_byte_operation" {
				return ErrHostFactoryHold
			}
		case "source_file_fstat":
			fstats++
			if *fact.OriginalErrorPresent || fact.OriginalCount != nil || fact.OriginalEOF != nil || fact.OriginalHashState != "not_byte_operation" || n != 1 && (writer || n != len(rows)-2 || !eof) {
				return ErrHostFactoryHold
			}
		case "source_file_read":
			if writer || eof || fstats != 1 || fact.OriginalCount == nil || fact.OriginalEOF == nil || *fact.OriginalErrorPresent != *fact.OriginalEOF || !*fact.OriginalEOF && *fact.OriginalCount == 0 || fact.OriginalHashState != "private_withheld" {
				return ErrHostFactoryHold
			}
			reads++
			count += *fact.OriginalCount
			eof = *fact.OriginalEOF
		case "source_file_write":
			if !writer || expectedCount == 0 || syncs != 0 || fstats != 1 || fact.OriginalCount == nil || *fact.OriginalCount <= 0 || *fact.OriginalErrorPresent || fact.OriginalEOF != nil || fact.OriginalHashState != "private_withheld" {
				return ErrHostFactoryHold
			}
			writes++
			count += *fact.OriginalCount
		case "source_file_sync":
			syncs++
			if !writer || n != len(rows)-2 || syncs != 1 || *fact.OriginalErrorPresent || fact.OriginalCount != nil || fact.OriginalEOF != nil || fact.OriginalHashState != "not_byte_operation" {
				return ErrHostFactoryHold
			}
		case "source_file_close":
			if n != len(rows)-1 || id != selection.OriginalCloseCallID || *fact.OriginalErrorPresent || fact.OriginalCount != nil || fact.OriginalEOF != nil || fact.OriginalHashState != "not_byte_operation" {
				return ErrHostFactoryHold
			}
		default:
			return ErrHostFactoryHold
		}
		if count > 65536 {
			return ErrHostFactoryHold
		}
	}
	if count != int64(expectedCount) || rows[0].Fact.Operation != "source_file_open" || rows[1].Fact.Operation != "source_file_fstat" || rows[len(rows)-1].Fact.Operation != "source_file_close" {
		return ErrHostFactoryHold
	}
	if writer {
		if fstats != 1 || syncs != 1 || reads != 0 || expectedCount == 0 && writes != 0 || expectedCount > 0 && writes == 0 {
			return ErrHostFactoryHold
		}
	} else if fstats != 2 || reads == 0 || !eof || writes != 0 || syncs != 0 {
		return ErrHostFactoryHold
	}
	return nil
}

func originalHostGetdentsSourceCustody(raw []byte, identity hostOriginalGetdentsCustodyIdentity, nativeRaw []byte) (hostOriginalGetdentsSourceAuditCustody, error) {
	var custody hostOriginalGetdentsSourceAuditCustody
	fact := identity.fact
	native := fact.OriginalNativeReturn
	if nativeRaw == nil || len(nativeRaw) > 65536 || fact.OriginalCallID == nil || fact.OriginalState != "returned" || fact.OriginalCount == nil || fact.OriginalSHA256 == nil || fact.OriginalEOF == nil || *fact.OriginalEOF || native == nil || native.Kind != "unix_getdents64" || native.OriginalScalar == nil || *native.OriginalScalar != int64(len(nativeRaw)) || native.OriginalErrorPresent == nil || *native.OriginalErrorPresent || native.OriginalErrno == nil || *native.OriginalErrno != 0 || int64(len(nativeRaw)) != *fact.OriginalCount || capacity.HostFactoryRawSHA256(nativeRaw) != *fact.OriginalSHA256 || hostOriginalStrictJSON(raw, &custody, 65536) != nil || originalHostSourceCustodyRequiredFields(raw, reflect.TypeOf(custody), 0) != nil {
		return custody, ErrHostFactoryHold
	}
	if custody.Schema != "source_private_original_getdents_source_audit_custody_v1" || custody.FactoryRootID != identity.nativeRoot || custody.OriginalOwnerID != identity.owner || custody.BindingSchema != identity.schema || custody.BindingSHA256 != identity.bindingSHA || custody.OriginalChunkBodySHA256 != identity.chunkSHA || custody.OriginalChunkEnvelopeSHA256 != identity.envelopeSHA || custody.OriginalFactIndex != identity.index || identity.index > 15 || custody.OriginalCallID != *fact.OriginalCallID || !originalHostSourceCustodyCallID(custody.OriginalCallID, fact.OriginalHandleID) || custody.OriginalRawBytes != len(nativeRaw) || custody.OriginalRawSHA256 != capacity.HostFactoryRawSHA256(nativeRaw) || !validCapacityExecutor(custody.RequestID) || custody.Phase == "" || len(custody.Phase) > 128 {
		return custody, ErrHostFactoryHold
	}
	if custody.CustodyClass == "local_kernel" {
		if custody.OriginalReaderAudit != nil || custody.OriginalWriterAudit != nil || custody.OriginalWriterAuditRaw != nil || custody.OriginalWriterAuditArtifactReader != nil {
			return custody, ErrHostFactoryHold
		}
		return custody, nil
	}
	if custody.CustodyClass != "transferred_file" || custody.OriginalReaderAudit == nil || custody.OriginalWriterAudit == nil || custody.OriginalWriterAuditRaw == nil || custody.OriginalWriterAuditArtifactReader == nil {
		return custody, ErrHostFactoryHold
	}
	writerRef := custody.OriginalWriterAudit
	writerRaw := *custody.OriginalWriterAuditRaw
	if custody.OriginalReaderAudit.OriginalHandleID == custody.OriginalWriterAuditArtifactReader.OriginalHandleID || custody.OriginalReaderAudit.OriginalHandleID == writerRef.OriginalWriterHandleID || custody.OriginalWriterAuditArtifactReader.OriginalHandleID == writerRef.OriginalWriterHandleID || writerRef.OriginalPublicationMethodHandleID == writerRef.OriginalWriterHandleID || writerRef.OriginalPublicationMethodHandleID == custody.OriginalReaderAudit.OriginalHandleID || writerRef.OriginalPublicationMethodHandleID == custody.OriginalWriterAuditArtifactReader.OriginalHandleID {
		return custody, ErrHostFactoryHold
	}
	var writer hostOriginalGetdentsWriterAuditArtifact
	if hostOriginalStrictJSON(writerRaw, &writer, 65536) != nil || originalHostSourceCustodyRequiredFields(writerRaw, reflect.TypeOf(writer), 0) != nil || len(writerRaw) != writerRef.OriginalBytes || capacity.HostFactoryRawSHA256(writerRaw) != writerRef.OriginalSHA256 || writerRef.Basename != custody.RequestID+"-"+capacity.HostFactoryRawSHA256([]byte(custody.OriginalCallID))+".writer-audit" || writer.Schema != "source_private_original_getdents_writer_audit_v1" || writer.FactoryRootID != custody.FactoryRootID || writer.RequestID != custody.RequestID || writer.Phase != custody.Phase || writer.OriginalCallID != custody.OriginalCallID || writer.OriginalChunkBodySHA256 != custody.OriginalChunkBodySHA256 || writer.OriginalChunkEnvelopeSHA256 != custody.OriginalChunkEnvelopeSHA256 || writer.OriginalFactIndex != custody.OriginalFactIndex || writer.OriginalOwnerID != custody.OriginalOwnerID || writer.BindingSchema != custody.BindingSchema || writer.BindingSHA256 != custody.BindingSHA256 || writer.OriginalRawBytes != custody.OriginalRawBytes || writer.OriginalRawSHA256 != custody.OriginalRawSHA256 {
		return custody, ErrHostFactoryHold
	}
	if writerRef.RequestID != writer.RequestID || writerRef.OriginalCallID != writer.OriginalCallID || writerRef.OriginalChunkBodySHA256 != writer.OriginalChunkBodySHA256 || writerRef.OriginalChunkEnvelopeSHA256 != writer.OriginalChunkEnvelopeSHA256 || writerRef.OriginalFactIndex != writer.OriginalFactIndex || writerRef.OriginalOwnerID != writer.OriginalOwnerID || writerRef.BindingSchema != writer.BindingSchema || writerRef.BindingSHA256 != writer.BindingSHA256 || writerRef.OriginalWriterHandleID != writer.OriginalWriterHandleID || writerRef.OriginalWriterCloseCallID != writer.OriginalWriterCloseCallID || writerRef.OriginalPublicationMethodHandleID != writer.OriginalPublicationMethodHandleID || !reflect.DeepEqual(writerRef.OriginalWriterCallReferences, writer.OriginalWriterCallReferences) || !reflect.DeepEqual(writerRef.OriginalPublicationCallReferences, writer.OriginalPublicationCallReferences) || !validCapacityExecutor(writer.SourceAuditOwnerID) || (writer.SourceAuditOwnerRole != "host_exterior" && writer.SourceAuditOwnerRole != "host_registrar") || writer.SourceAuditBindingSchema == "" || !capacity.ValidDigest(writer.SourceAuditBindingSHA256) {
		return custody, ErrHostFactoryHold
	}
	fileRows, methodRows := []hostOriginalSourceAuditProjection{}, []hostOriginalSourceAuditProjection{}
	if len(writer.OriginalSourceAuditProjections) == 0 || len(writer.OriginalSourceAuditProjections) > 4096 {
		return custody, ErrHostFactoryHold
	}
	for _, row := range writer.OriginalSourceAuditProjections {
		switch row.Fact.OriginalAuditHandleID {
		case writer.OriginalWriterHandleID:
			fileRows = append(fileRows, row)
		case writer.OriginalPublicationMethodHandleID:
			methodRows = append(methodRows, row)
		default:
			return custody, ErrHostFactoryHold
		}
	}
	selection := hostOriginalGetdentsSourceFileSelection{writer.OriginalWriterHandleID, writer.OriginalWriterCloseCallID, writer.OriginalWriterCallReferences, fileRows}
	if originalHostGetdentsSourceSelection(selection, identity.nativeRoot, true, len(nativeRaw)) != nil || originalHostGetdentsSourceSelection(*custody.OriginalReaderAudit, identity.nativeRoot, false, len(nativeRaw)) != nil || originalHostGetdentsSourceSelection(*custody.OriginalWriterAuditArtifactReader, identity.nativeRoot, false, len(writerRaw)) != nil || len(methodRows) != 2 || len(writer.OriginalPublicationCallReferences) != 2 || !validCapacityExecutor(writer.OriginalPublicationMethodHandleID) {
		return custody, ErrHostFactoryHold
	}
	for n, row := range methodRows {
		fact := row.Fact
		id := writer.OriginalPublicationMethodHandleID + ":" + strconv.Itoa(n+1)
		if row.Family != "source_audit" || row.SubjectIdentity.SubjectKind != "source_file" || row.SubjectIdentity.RequestIdentity != nil || row.SubjectIdentity.PublicRunID != nil || row.SubjectIdentity.Method != nil || row.SubjectIdentity.PathFamily != nil || row.OriginalCloseReference != nil || fact.FactoryRootID != identity.nativeRoot || capacity.ValidateHostFactory(fact) != nil || fact.OriginalCallID == nil || *fact.OriginalCallID != id || writer.OriginalPublicationCallReferences[n] != id || fact.Operation != []string{"source_file_rename_noreplace", "source_directory_sync"}[n] || fact.OriginalState != "returned" || fact.OriginalCalledAt == nil || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || *fact.OriginalErrorPresent || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || fact.OriginalHashState != "not_byte_operation" || fact.OriginalCount != nil || fact.OriginalEOF != nil || fact.OriginalSHA256 != nil || fact.OriginalReadScope != nil || fact.RetainedPrefixBytes != nil || fact.RetainedPrefixSHA256 != nil {
			return custody, ErrHostFactoryHold
		}
		if n == 0 && fact.OriginalCalledAt.Before(*fileRows[len(fileRows)-1].Fact.OriginalReturnedAt) || n == 1 && fact.OriginalCalledAt.Before(*methodRows[0].Fact.OriginalReturnedAt) {
			return custody, ErrHostFactoryHold
		}
	}
	// The native return exists before its private writer begins. Transfer
	// readers cannot precede publication of that same original file; the
	// writer-audit artifact is formed only after the raw publisher returned.
	if fact.OriginalReturnedAt == nil || fileRows[0].Fact.OriginalCalledAt.Before(*fact.OriginalReturnedAt) || custody.OriginalReaderAudit.OriginalSourceAuditProjections[0].Fact.OriginalCalledAt.Before(*methodRows[0].Fact.OriginalReturnedAt) || custody.OriginalWriterAuditArtifactReader.OriginalSourceAuditProjections[0].Fact.OriginalCalledAt.Before(*methodRows[1].Fact.OriginalReturnedAt) {
		return custody, ErrHostFactoryHold
	}
	return custody, nil
}

func originalHostGetdentsCustodyFromSource(ctx context.Context, tx *sql.Tx, root string, chunk model.HostFactoryCallVectorChunk, bodyRaw, envelopeRaw []byte, index uint32, nativeRaw []byte, getter func(context.Context, string) ([]byte, error)) ([]byte, error) {
	if getter == nil || index >= uint32(len(chunk.OriginalCalls)) || nativeRaw == nil {
		return nil, ErrHostFactoryHold
	}
	fact := chunk.OriginalCalls[index]
	if fact.OriginalCallID == nil {
		return nil, ErrHostFactoryHold
	}
	raw, err := getter(ctx, *fact.OriginalCallID)
	if err != nil {
		return nil, err
	}
	var nativeRoot string
	if tx.QueryRowContext(ctx, `SELECT factory_realm_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, root).Scan(&nativeRoot) != nil {
		return nil, ErrHostFactoryHold
	}
	identity := hostOriginalGetdentsCustodyIdentity{nativeRoot, chunk.OriginalOwnerID, chunk.BindingSchema, chunk.BindingSHA256, capacity.HostFactoryRawSHA256(bodyRaw), capacity.HostFactoryRawSHA256(envelopeRaw), index, fact}
	custody, err := originalHostGetdentsSourceCustody(raw, identity, nativeRaw)
	if err != nil || authenticateOriginalHostGetdentsAuditOwnerTx(ctx, tx, root, custody) != nil {
		return nil, ErrHostFactoryHold
	}
	return bytes.Clone(raw), nil
}

func authenticateOriginalHostGetdentsAuditOwnerTx(ctx context.Context, tx *sql.Tx, root string, custody hostOriginalGetdentsSourceAuditCustody) error {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	if custody.CustodyClass == "local_kernel" {
		return nil
	}
	if custody.OriginalWriterAuditRaw == nil {
		return ErrHostFactoryHold
	}
	var artifact hostOriginalGetdentsWriterAuditArtifact
	if hostOriginalStrictJSON(*custody.OriginalWriterAuditRaw, &artifact, 65536) != nil {
		return ErrHostFactoryHold
	}
	// Source-audit owner is its authentic original basal/namespace, which may
	// differ from the ancestral native observer. Never copy the native role.
	stage := originalHostBasalStage(artifact.SourceAuditOwnerRole)
	var raw, envelope []byte
	var count int
	if stage == "" || tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND stage=$3`, root, artifact.SourceAuditOwnerID, stage).Scan(&count) != nil || count != 1 || tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND stage=$3`, root, artifact.SourceAuditOwnerID, stage).Scan(&raw, &envelope) != nil {
		return ErrHostFactoryHold
	}
	var basal model.HostFactoryBasalOwnerObservation
	embedded, _, err := decodeOriginalHistoricalHostStage(codec, stage, envelope)
	if err != nil || !bytes.Equal(raw, embedded) || codec.Decode(raw, &basal) != nil || basal.OriginalOwnerID != artifact.SourceAuditOwnerID || basal.Role != artifact.SourceAuditOwnerRole || basal.FactoryRootID != custody.FactoryRootID || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, stage, envelope) != nil {
		return ErrHostFactoryHold
	}
	var binding []byte
	switch artifact.SourceAuditBindingSchema {
	case "original_host_factory_source_approval_v4":
		err = tx.QueryRowContext(ctx, `SELECT source_approval_wire FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 AND source_approval_sha256=$2`, root, artifact.SourceAuditBindingSHA256).Scan(&binding)
	case "original_host_factory_root_preparation_v4":
		err = tx.QueryRowContext(ctx, `SELECT root_preparation_wire FROM public.capacity_host_factory_roots WHERE scope_root_id=$1 AND root_preparation_sha256=$2`, root, artifact.SourceAuditBindingSHA256).Scan(&binding)
	case "original_host_factory_pre_authority_scope_v4", "factory_ordinary_source_binding_v4":
		err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_host_factory_scopes WHERE root_id=$1 AND binding_schema=$2 AND scope_sha256=$3`, root, artifact.SourceAuditBindingSchema, artifact.SourceAuditBindingSHA256).Scan(&binding)
	default:
		return ErrHostFactoryHold
	}
	if err != nil || authenticateOriginalHostNativeBindingTx(ctx, tx, root, artifact.SourceAuditBindingSchema, artifact.SourceAuditBindingSHA256, binding) != nil {
		return ErrHostFactoryHold
	}
	return nil
}

func originalHostGetdentsStoredCustodyTx(ctx context.Context, tx *sql.Tx, root, callID string) (hostOriginalGetdentsSourceAuditCustody, error) {
	codec := originalHostSourceCodecTx(ctx, tx, root)

	var zero hostOriginalGetdentsSourceAuditCustody
	var count int
	query := `FROM public.capacity_host_factory_call_snapshot_links l JOIN public.capacity_host_factory_io_returns r ON r.root_id=l.root_id AND r.binding_schema=l.binding_schema AND r.binding_sha256=l.binding_sha256 AND r.original_owner_id=l.original_owner_id AND r.record_kind='chunk' AND r.raw_body_sha256=l.current_chunk_raw_body_sha256 WHERE l.root_id=$1 AND l.original_call_id=$2 AND convert_from(r.raw_body_wire,'UTF8')::jsonb->'original_calls'->l.current_fact_index->>'original_state'='returned'`
	if tx.QueryRowContext(ctx, `SELECT count(*) `+query, root, callID).Scan(&count) != nil || count != 1 {
		return zero, ErrHostFactoryHold
	}
	var custodyRaw, nativeRaw, bodyRaw, envelopeRaw []byte
	var custodyNull, nativeNull bool
	var index uint32
	if tx.QueryRowContext(ctx, `SELECT l.original_getdents_source_audit_wire IS NULL,l.original_getdents_wire IS NULL,l.original_getdents_source_audit_wire,l.original_getdents_wire,r.raw_body_wire,r.raw_envelope_wire,l.current_fact_index `+query, root, callID).Scan(&custodyNull, &nativeNull, &custodyRaw, &nativeRaw, &bodyRaw, &envelopeRaw, &index) != nil || custodyNull || nativeNull || len(bodyRaw) > 65536 || len(envelopeRaw) > 65536 {
		return zero, ErrHostFactoryHold
	}
	var chunk model.HostFactoryCallVectorChunk
	if codec.Decode(bodyRaw, &chunk) != nil || index >= uint32(len(chunk.OriginalCalls)) {
		return zero, ErrHostFactoryHold
	}
	selector := "io-calls/" + chunk.OriginalHandleID + "/chunk/" + capacity.HostFactoryRawSHA256(bodyRaw)
	embedded, _, err := decodeOriginalHistoricalHostStage(codec, selector, envelopeRaw)
	if err != nil || !bytes.Equal(embedded, bodyRaw) || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, selector, envelopeRaw) != nil {
		return zero, ErrHostFactoryHold
	}
	x, err := originalHostIOIdentity(codec, root, &chunk, bodyRaw)
	if err != nil {
		return zero, err
	}
	if _, _, err = originalHostPredecessorTx(ctx, tx, x, x.bodySHA, index); err != nil {
		return zero, err
	}
	var nativeRoot string
	if tx.QueryRowContext(ctx, `SELECT factory_realm_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, root).Scan(&nativeRoot) != nil {
		return zero, ErrHostFactoryHold
	}
	if nativeRaw == nil {
		nativeRaw = make([]byte, 0)
	} // SQLnonNULL was independently observed.
	identity := hostOriginalGetdentsCustodyIdentity{nativeRoot, chunk.OriginalOwnerID, chunk.BindingSchema, chunk.BindingSHA256, x.bodySHA, capacity.HostFactoryRawSHA256(envelopeRaw), index, chunk.OriginalCalls[index]}
	custody, err := originalHostGetdentsSourceCustody(custodyRaw, identity, nativeRaw)
	if err != nil || authenticateOriginalHostGetdentsAuditOwnerTx(ctx, tx, root, custody) != nil {
		return zero, ErrHostFactoryHold
	}
	return custody, nil
}

// Whole final Source-audit facts must equal the original selected private
// custody. This reader returns ONLY specific acquired zero-file handle IDs;
// ordinary EOF/Fstat/count or a local_kernel record never selects a file zero.
func originalHostHistoricalZeroSourceFilesTx(ctx context.Context, tx *sql.Tx, root string, audits map[string]hostOriginalSourceAuditProjection) (map[string]bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT original_call_id FROM public.capacity_host_factory_call_snapshot_links WHERE root_id=$1 AND original_getdents_source_audit_wire IS NOT NULL ORDER BY original_call_id LIMIT 65537`, root)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) != nil || len(ids) >= 65536 {
			rows.Close()
			return nil, ErrHostFactoryHold
		}
		ids = append(ids, id)
	}
	if err = errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, id := range ids {
		custody, err := originalHostGetdentsStoredCustodyTx(ctx, tx, root, id)
		if err != nil {
			return nil, err
		}
		if custody.CustodyClass == "local_kernel" {
			continue
		}
		var artifact hostOriginalGetdentsWriterAuditArtifact
		if hostOriginalStrictJSON(*custody.OriginalWriterAuditRaw, &artifact, 65536) != nil {
			return nil, ErrHostFactoryHold
		}
		all := append([]hostOriginalSourceAuditProjection{}, artifact.OriginalSourceAuditProjections...)
		all = append(all, custody.OriginalReaderAudit.OriginalSourceAuditProjections...)
		all = append(all, custody.OriginalWriterAuditArtifactReader.OriginalSourceAuditProjections...)
		for _, row := range all {
			if row.Fact.OriginalCallID == nil {
				return nil, ErrHostFactoryHold
			}
			original, ok := audits[*row.Fact.OriginalCallID]
			if !ok || !reflect.DeepEqual(original, row) {
				return nil, ErrHostFactoryHold
			}
		}
		if custody.OriginalRawBytes == 0 {
			if allowed[custody.OriginalReaderAudit.OriginalHandleID] || allowed[artifact.OriginalWriterHandleID] {
				return nil, ErrHostFactoryHold
			}
			allowed[custody.OriginalReaderAudit.OriginalHandleID] = true
			allowed[artifact.OriginalWriterHandleID] = true
		}
	}
	return allowed, nil
}

// Isolated native representation component: native_source_profile.go
type hostOriginalSourceCodec struct {
	profile                       *capacity.HostFactorySourceProfile
	approvalRaw, approvalEnvelope []byte
	root, nativeRoot              string
	err                           error
}

const hostOriginalSourceProfileSHA = "d7e9eee68bb55faf70f9f524dbc777ef9389429bdfdd984ca9c9f6c45d01de6a"

func originalHostSourceCodecRealm(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm) hostOriginalSourceCodec {
	out := hostOriginalSourceCodec{err: ErrHostFactoryHold}
	if ctx == nil || ctx.Err() != nil || realm == nil {
		return out
	}
	p, err := realm.OriginalSourceProfile(ctx)
	if err != nil || p == nil {
		return out
	}
	identity, err := p.Identity()
	if err != nil || identity != hostOriginalSourceProfileSHA {
		return out
	}
	// After actual Realm Close the profile accessor is cache-only. Approval
	// was retained once by installation; calling its live getter here would
	// make the lawful closing-IO persistence path permanently unavailable.
	installedRealm, approval, installed := OriginalHostFactoryRealm()
	if !installed || installedRealm != realm {
		approval, err = realm.Approval(ctx)
	}
	raw, encodeErr := p.Canonical(approval)
	if err != nil || encodeErr != nil || !validCapacityExecutor(approval.ScopeRootID) {
		return out
	}
	out.profile, out.approvalRaw, out.root, out.err = p, bytes.Clone(raw), approval.ScopeRootID, nil
	return out
}

func originalHostInstalledSourceCodec(ctx context.Context, root string) hostOriginalSourceCodec {
	realm, approval, installed := OriginalHostFactoryRealm()
	if !installed || realm == nil || root != "" && approval.ScopeRootID != root {
		return hostOriginalSourceCodec{err: ErrHostFactoryHold}
	}
	return originalHostSourceCodecRealm(ctx, realm)
}

// Before the original Source approval stage INSERT, the initializer may use
// its genuine installed cached profile and the exact Root approval BYTEA.
// A cold consumer instead requires the SAME persisted original envelope.
// Neither branch treats a missing row as FIRST or reconstructs a Realm.
func originalHostSourceCodecTx(ctx context.Context, tx *sql.Tx, root string) hostOriginalSourceCodec {
	out := hostOriginalSourceCodec{err: ErrHostFactoryHold}
	if ctx == nil || ctx.Err() != nil || tx == nil || !validCapacityExecutor(root) {
		return out
	}
	var approvalRaw []byte
	var nativeRoot, approvalSHA string
	if tx.QueryRowContext(ctx, `SELECT source_approval_wire,source_approval_sha256,factory_realm_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, root).Scan(&approvalRaw, &approvalSHA, &nativeRoot) != nil || len(approvalRaw) == 0 || len(approvalRaw) > 65536 || capacity.HostFactoryRawSHA256(approvalRaw) != approvalSHA || !validCapacityExecutor(nativeRoot) {
		return out
	}
	realm, approval, installed := OriginalHostFactoryRealm()
	if installed && realm != nil && approval.ScopeRootID == root {
		out = originalHostSourceCodecRealm(ctx, realm)
		if out.err != nil || !bytes.Equal(out.approvalRaw, approvalRaw) {
			return hostOriginalSourceCodec{err: ErrHostFactoryHold}
		}
		out.nativeRoot = nativeRoot
		// The initializer's first retained basal stages precede source-approval
		// in the same transaction. Its genuine live profile is enough for that
		// preparatory grammar access; cold wrappers require the actual original
		// approval stage pair once it exists, never a manufactured envelope.
		var count int
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='source-approval' AND raw_body_sha256=$2`, root, approvalSHA).Scan(&count) != nil || count > 1 {
			return hostOriginalSourceCodec{err: ErrHostFactoryHold}
		}
		if count == 1 {
			var storedBody, envelope []byte
			var envelopeSHA string
			if tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire,raw_envelope_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='source-approval' AND raw_body_sha256=$2`, root, approvalSHA).Scan(&storedBody, &envelope, &envelopeSHA) != nil || !bytes.Equal(storedBody, approvalRaw) || len(envelope) == 0 || len(envelope) > 65536 || capacity.HostFactoryRawSHA256(envelope) != envelopeSHA {
				return hostOriginalSourceCodec{err: ErrHostFactoryHold}
			}
			selected, err := capacityhostfactory.VerifyOriginalHistoricalSourceProfile(ctx, approvalRaw, envelope)
			if err != nil || selected == nil {
				return hostOriginalSourceCodec{err: ErrHostFactoryHold}
			}
			identity, err := selected.Identity()
			if err != nil || identity != hostOriginalSourceProfileSHA {
				return hostOriginalSourceCodec{err: ErrHostFactoryHold}
			}
			out.approvalEnvelope = bytes.Clone(envelope)
		}
		return out
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='source-approval' AND raw_body_sha256=$2`, root, approvalSHA).Scan(&count) != nil || count != 1 {
		return out
	}
	var envelopeRaw, storedBody []byte
	var envelopeSHA string
	if tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire,raw_envelope_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='source-approval' AND raw_body_sha256=$2`, root, approvalSHA).Scan(&storedBody, &envelopeRaw, &envelopeSHA) != nil || !bytes.Equal(storedBody, approvalRaw) || len(envelopeRaw) == 0 || len(envelopeRaw) > 65536 || capacity.HostFactoryRawSHA256(envelopeRaw) != envelopeSHA {
		return out
	}
	p, err := capacityhostfactory.VerifyOriginalHistoricalSourceProfile(ctx, approvalRaw, envelopeRaw)
	if err != nil || p == nil {
		return out
	}
	identity, err := p.Identity()
	if err != nil || identity != hostOriginalSourceProfileSHA {
		return out
	}
	out.profile, out.root, out.nativeRoot, out.err = p, root, nativeRoot, nil
	out.approvalRaw, out.approvalEnvelope = bytes.Clone(approvalRaw), bytes.Clone(envelopeRaw)
	return out
}

func (c hostOriginalSourceCodec) Decode(raw []byte, target any) error {
	if c.err != nil || c.profile == nil {
		return ErrHostFactoryHold
	}
	return c.profile.Decode(raw, target)
}

func (c hostOriginalSourceCodec) Canonical(value any) ([]byte, error) {
	if c.err != nil || c.profile == nil {
		return nil, ErrHostFactoryHold
	}
	return c.profile.Canonical(value)
}

func (c hostOriginalSourceCodec) Validate(value any) error {
	if c.err != nil || c.profile == nil {
		return ErrHostFactoryHold
	}
	return c.profile.Validate(value)
}

// Stage families are fixed Source consumer rules. In particular the Scope
// BODY itself is issued under original RootPreparation; prepared/Alive and
// terminal Scope stages use the distinct new scoped transport.
func originalHostSourceStageTransport(stage, role, bindingSchema string) error {
	rule, exists := originalHostStageRules[stage]
	if !exists || rule.signer != role || rule.binding != bindingSchema || rule.family == "scope" && bindingSchema != "original_host_factory_pre_authority_scope_v4" || rule.family == "root" && bindingSchema == "original_host_factory_pre_authority_scope_v4" {
		return ErrHostFactoryHold
	}
	return nil
}

// This is explicit expected-profile transport decoding. Legacy Root and
// ordinary keep their original bytes; legacy Scope envelopes are refused.
// The closed schema identifies a transport, never a profile/trusted key.
func (c hostOriginalSourceCodec) Envelope(raw []byte) (body []byte, role, schema, sha string, err error) {
	if c.err != nil || c.profile == nil || len(raw) == 0 || len(raw) > 65536 {
		return nil, "", "", "", ErrHostFactoryHold
	}
	var header struct {
		Schema string `json:"schema"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return nil, "", "", "", ErrHostFactoryHold
	}
	var encoded string
	switch header.Schema {
	case "original_host_factory_root_signed_envelope_v4":
		var envelope model.HostFactoryRootSignedEnvelope
		if c.Decode(raw, &envelope) != nil || envelope.BindingSchema == "original_host_factory_pre_authority_scope_v4" {
			return nil, "", "", "", ErrHostFactoryHold
		}
		encoded, role, schema, sha = envelope.BodyBase64, envelope.Role, envelope.BindingSchema, envelope.BindingSHA256
	case "source_host_factory_signed_envelope_v1":
		var envelope capacity.HostFactorySourceSignedEnvelope
		if c.Decode(raw, &envelope) != nil || envelope.SourceProfileSHA256 != hostOriginalSourceProfileSHA {
			return nil, "", "", "", ErrHostFactoryHold
		}
		encoded, role, schema, sha = envelope.BodyBase64, envelope.Role, "original_host_factory_pre_authority_scope_v4", envelope.PreAuthorityScopeSHA256
	default:
		return nil, "", "", "", ErrHostFactoryHold
	}
	body, err = base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(body) == 0 || len(body) > 65536 || base64.StdEncoding.EncodeToString(body) != encoded {
		return nil, "", "", "", ErrHostFactoryHold
	}
	return body, role, schema, sha, nil
}

// Called only after the Source-owned stage authenticator accepted this exact
// envelope. The returned purposes are copies of original signed metadata;
// no phase/subject role is derived from the current aggregate or SQL DTO.
func (c hostOriginalSourceCodec) Purposes(ctx context.Context, selector string, raw, body []byte, schema string) ([]capacity.HostFactorySourceCallPurpose, error) {
	embedded, _, actualSchema, _, err := c.Envelope(raw)
	if err != nil || actualSchema != schema || !bytes.Equal(embedded, body) || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, selector, raw) != nil {
		return nil, ErrHostFactoryHold
	}
	if schema != "original_host_factory_pre_authority_scope_v4" {
		return []capacity.HostFactorySourceCallPurpose{}, nil
	}
	var envelope capacity.HostFactorySourceSignedEnvelope
	if c.Decode(raw, &envelope) != nil {
		return nil, ErrHostFactoryHold
	}
	purposeRaw, err := base64.StdEncoding.Strict().DecodeString(envelope.OriginalPurposeBase64)
	var purposes capacity.HostFactorySourcePurposeSet
	if err != nil || len(purposeRaw) == 0 || len(purposeRaw) > 65536 || base64.StdEncoding.EncodeToString(purposeRaw) != envelope.OriginalPurposeBase64 || c.Decode(purposeRaw, &purposes) != nil || purposes.OriginalBodySHA256 != capacity.HostFactoryRawSHA256(body) || purposes.OriginalCallPurposes == nil {
		return nil, ErrHostFactoryHold
	}
	return append([]capacity.HostFactorySourceCallPurpose{}, purposes.OriginalCallPurposes...), nil
}

func originalHostSourcePendingTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, previous, current model.HostFactoryCallVectorChunk, currentEnvelope []byte) error {
	if x.bindingSchema != "original_host_factory_pre_authority_scope_v4" {
		// Unchanged legacy structural relation. The source-owned full native
		// wrapper separately authenticates its exact original envelope pair.
		return capacity.ValidateHostFactoryPendingSuccessor(previous, current)
	}
	codec := x.codec
	priorRaw, e1 := codec.Canonical(previous)
	currentRaw, e2 := codec.Canonical(current)
	if e1 != nil || e2 != nil || tx == nil || x.handle == nil || previous.BindingSchema != x.bindingSchema || current.BindingSchema != x.bindingSchema || previous.BindingSHA256 != x.bindingSHA || current.BindingSHA256 != x.bindingSHA {
		return ErrHostFactoryHold
	}
	readEnvelope := func(raw []byte) ([]byte, error) {
		var body, envelope []byte
		var count int
		sha := capacity.HostFactoryRawSHA256(raw)
		if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND original_handle_id=$5 AND record_kind='chunk' AND raw_body_sha256=$6`, x.root, x.bindingSchema, x.bindingSHA, x.owner, x.handle, sha).Scan(&count) != nil || count != 1 {
			return nil, ErrHostFactoryHold
		}
		if tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND binding_schema=$2 AND binding_sha256=$3 AND original_owner_id=$4 AND original_handle_id=$5 AND record_kind='chunk' AND raw_body_sha256=$6`, x.root, x.bindingSchema, x.bindingSHA, x.owner, x.handle, sha).Scan(&body, &envelope) != nil || !bytes.Equal(body, raw) || len(envelope) == 0 || len(envelope) > 65536 {
			return nil, ErrHostFactoryHold
		}
		return envelope, nil
	}
	priorEnvelope, err := readEnvelope(priorRaw)
	if err != nil {
		return err
	}
	if currentEnvelope == nil {
		currentEnvelope, err = readEnvelope(currentRaw)
		if err != nil {
			return err
		}
	}
	priorSelector := "io-calls/" + *x.handle + "/chunk/" + capacity.HostFactoryRawSHA256(priorRaw)
	currentSelector := "io-calls/" + *x.handle + "/chunk/" + capacity.HostFactoryRawSHA256(currentRaw)
	priorPurposes, err := codec.Purposes(ctx, priorSelector, priorEnvelope, priorRaw, x.bindingSchema)
	if err != nil {
		return err
	}
	currentPurposes, err := codec.Purposes(ctx, currentSelector, currentEnvelope, currentRaw, x.bindingSchema)
	if err != nil {
		return err
	}
	return codec.profile.ValidatePendingSuccessor(previous, current, priorPurposes, currentPurposes)
}

// This branch is called only for expected new Source Scope. Earlier Root and
// ordinary retain their legacy structural reader. The Source9 wrapper owns
// key selection and the original Basal/bootstrap/actual binding chain.
func validateOriginalHostSourceInventoryTx(ctx context.Context, tx *sql.Tx, x hostFactoryIOIdentity, inventory model.HostFactoryHandleCallInventory) error {
	codec := x.codec
	if codec.err != nil || codec.profile == nil || codec.root != x.root || len(codec.approvalEnvelope) == 0 {
		return ErrHostFactoryHold
	}
	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, x.root)
	if err != nil {
		return err
	}
	return capacityhostfactory.ValidateOriginalHistoricalSourceHandleInventory(ctx, codec.approvalRaw, codec.approvalEnvelope, codec.nativeRoot, inventory, callbacks.resolveIO, callbacks.predecessor, callbacks.originalBasis)
}

// Bounded private custody R5 component: poststart_ledger_custody_types.go
type hostOriginalPostStartLedgerCustody struct {
	Schema                            string                                  `json:"schema"`
	LogicalScopeRootID                string                                  `json:"logical_scope_root_id"`
	FactoryRootID                     string                                  `json:"factory_root_id"`
	SourceApprovalBodySHA256          string                                  `json:"source_approval_body_sha256"`
	RootPreparationBodySHA256         string                                  `json:"root_preparation_body_sha256"`
	OriginalParentHeldRootAnchor      hostOriginalPostStartNativeAnchor       `json:"original_parent_held_root_anchor"`
	InitialEmptyBodySHA256            string                                  `json:"initial_empty_body_sha256"`
	InitialControlLedgerSHA256        string                                  `json:"initial_control_ledger_sha256"`
	InitialProtectedAdmissionSHA256   string                                  `json:"initial_protected_admission_sha256"`
	OriginalLeaseProvenanceBodySHA256 string                                  `json:"original_lease_provenance_body_sha256"`
	BindingSchema                     string                                  `json:"binding_schema"`
	ScopeBodySHA256                   string                                  `json:"scope_body_sha256"`
	ScopeEnvelopeSHA256               string                                  `json:"scope_envelope_sha256"`
	ScopeWire                         []byte                                  `json:"scope_wire"`
	CurrentJournalWire                []byte                                  `json:"current_journal_wire"`
	CurrentJournalSHA256              string                                  `json:"current_journal_sha256"`
	RequestID                         string                                  `json:"request_id"`
	OriginalPhaseID                   string                                  `json:"original_phase_id"`
	OriginalEffectivePhaseDeadline    time.Time                               `json:"original_effective_phase_deadline"`
	AggregateBodySHA256               string                                  `json:"aggregate_body_sha256"`
	AggregateEnvelopeSHA256           string                                  `json:"aggregate_envelope_sha256"`
	PreparedBodySHA256                string                                  `json:"prepared_body_sha256"`
	PreparedEnvelopeSHA256            string                                  `json:"prepared_envelope_sha256"`
	OriginalStartReference            hostOriginalPostStartNativeReference    `json:"original_start_reference"`
	OriginalPreparedFrame             hostOriginalPostStartPreparedFrame      `json:"original_prepared_frame"`
	OriginalPublicationReturn         hostOriginalPostStartSourceReturn       `json:"original_publication_return"`
	OriginalFileCustody               [2]hostOriginalPostStartFileCustody     `json:"original_file_custody"`
	OriginalDirectoryCustody          []hostOriginalPostStartDirectoryCustody `json:"original_directory_custody"`
	OriginalSourceAuditProjections    []hostOriginalSourceAuditProjection     `json:"original_source_audit_projections"`
}

type hostOriginalPostStartNativeReference struct {
	OriginalCallID              string `json:"original_call_id"`
	OriginalChunkBodySHA256     string `json:"original_chunk_body_sha256"`
	OriginalChunkEnvelopeSHA256 string `json:"original_chunk_envelope_sha256"`
	OriginalFactIndex           uint32 `json:"original_fact_index"`
}

type hostOriginalPostStartSourceReturn struct {
	Operation               string    `json:"operation"`
	OriginalOwnerID         string    `json:"original_owner_id"`
	OriginalOwnerRole       string    `json:"original_owner_role"`
	OriginalCalledAt        time.Time `json:"original_called_at"`
	OriginalReturnedAt      time.Time `json:"original_returned_at"`
	OriginalContextDeadline time.Time `json:"original_context_deadline"`
	OriginalState           string    `json:"original_state"`
	OriginalErrorPresent    bool      `json:"original_error_present"`
}

type hostOriginalPostStartPreparedFrame struct {
	FramingSchema                string                             `json:"framing_schema"`
	OriginalStreamHandleID       string                             `json:"original_stream_handle_id"`
	OriginalReadWire             []byte                             `json:"original_read_wire"`
	OriginalFrameOffset          uint32                             `json:"original_frame_offset"`
	OriginalFrameBytes           uint32                             `json:"original_frame_bytes"`
	OriginalReadSegments         []hostOriginalPostStartReadSegment `json:"original_read_segments"`
	OriginalReceiverReturn       hostOriginalPostStartSourceReturn  `json:"original_receiver_return"`
	OriginalAuthenticationReturn hostOriginalPostStartSourceReturn  `json:"original_authentication_return"`
}

type hostOriginalPostStartReadSegment struct {
	OriginalCallID              string `json:"original_call_id"`
	OriginalChunkBodySHA256     string `json:"original_chunk_body_sha256"`
	OriginalChunkEnvelopeSHA256 string `json:"original_chunk_envelope_sha256"`
	OriginalFactIndex           uint32 `json:"original_fact_index"`
	OriginalRawOffset           uint32 `json:"original_raw_offset"`
	OriginalRawBytes            uint32 `json:"original_raw_bytes"`
}

type hostOriginalPostStartSourceSelection struct {
	OriginalSourceOwnerID       string   `json:"original_source_owner_id"`
	OriginalSourceOwnerRole     string   `json:"original_source_owner_role"`
	OriginalSourceBindingSchema string   `json:"original_source_binding_schema"`
	OriginalSourceBindingSHA256 string   `json:"original_source_binding_sha256"`
	OriginalHandleID            string   `json:"original_handle_id"`
	OriginalAnchorHandleID      *string  `json:"original_anchor_handle_id"`
	OriginalCallReferences      []string `json:"original_call_references"`
	OriginalCloseCallID         *string  `json:"original_close_call_id"`
	OriginalStreamState         string   `json:"original_stream_state"`
}

type hostOriginalPostStartFileCustody struct {
	Basename                         string                               `json:"basename"`
	ContentKind                      string                               `json:"content_kind"`
	OriginalBytes                    uint32                               `json:"original_bytes"`
	OriginalWholeSHA256              string                               `json:"original_whole_sha256"`
	OriginalNativeRootAnchorHandleID string                               `json:"original_native_root_anchor_handle_id"`
	OriginalWriter                   hostOriginalPostStartSourceSelection `json:"original_writer"`
	OriginalPublicationMethod        hostOriginalPostStartSourceSelection `json:"original_publication_method"`
	OriginalExpectedReader           hostOriginalPostStartSourceSelection `json:"original_expected_reader"`
	OriginalFinalReader              hostOriginalPostStartSourceSelection `json:"original_final_reader"`
}

type hostOriginalPostStartDirectoryCustody struct {
	OriginalSourceDirectoryHandleID string                               `json:"original_source_directory_handle_id"`
	OriginalNativeRootAnchor        hostOriginalPostStartNativeAnchor    `json:"original_native_root_anchor"`
	OriginalPrefix                  hostOriginalPostStartSourceSelection `json:"original_prefix"`
}

type hostOriginalPostStartNativeAnchor struct {
	OriginalHandleID                string `json:"original_handle_id"`
	OriginalInventoryBodySHA256     string `json:"original_inventory_body_sha256"`
	OriginalInventoryEnvelopeSHA256 string `json:"original_inventory_envelope_sha256"`
	OriginalAcquisitionCallID       string `json:"original_acquisition_call_id"`
	OriginalFstatCallID             string `json:"original_fstat_call_id"`
}

type hostOriginalCurrentFactoryOwnerJournal struct {
	Schema                          string                                 `json:"schema"`
	FactoryRootID                   string                                 `json:"factory_root_id"`
	RootPreparationSHA256           string                                 `json:"root_preparation_sha256"`
	SourceApprovalSHA256            string                                 `json:"source_approval_sha256"`
	CoreBasalOwnerRawSHA256         string                                 `json:"core_basal_owner_raw_sha256"`
	FactoryRegistrySHA256           string                                 `json:"factory_registry_sha256"`
	FactorySourceClosureSHA256      string                                 `json:"factory_source_closure_sha256"`
	InitialControlLedgerSHA256      string                                 `json:"initial_control_ledger_sha256"`
	InitialProtectedAdmissionSHA256 string                                 `json:"initial_protected_admission_sha256"`
	PreAuthorityScopeSHA256         string                                 `json:"pre_authority_scope_sha256"`
	Phase                           string                                 `json:"phase"`
	RequestID                       string                                 `json:"request_id"`
	FactoryAttemptID                string                                 `json:"factory_attempt_id"`
	CreatorOwnerID                  string                                 `json:"creator_owner_id"`
	OriginalRootContextStartedAt    time.Time                              `json:"original_root_context_started_at"`
	OriginalRootContextDeadline     time.Time                              `json:"original_root_context_deadline"`
	OriginalEffectivePhaseDeadline  time.Time                              `json:"original_effective_phase_deadline"`
	OriginalPhaseCalledAt           time.Time                              `json:"original_phase_called_at"`
	FactoryOwnerEvents              []hostOriginalCurrentFactoryOwnerEvent `json:"factory_owner_events"`
}

type hostOriginalCurrentFactoryOwnerEvent struct {
	Ordinal                     uint32     `json:"ordinal"`
	EventID                     string     `json:"event_id"`
	Transition                  string     `json:"transition"`
	OriginalOwnerID             string     `json:"original_owner_id"`
	SourceOwnerKind             string     `json:"source_owner_kind"`
	OriginalCallID              *string    `json:"original_call_id"`
	OriginalBodySHA256          *string    `json:"original_body_sha256"`
	OriginalEnvelopeSHA256      *string    `json:"original_envelope_sha256"`
	OriginalChunkBodySHA256     *string    `json:"original_chunk_body_sha256"`
	OriginalChunkEnvelopeSHA256 *string    `json:"original_chunk_envelope_sha256"`
	OriginalFactIndex           *uint32    `json:"original_fact_index"`
	OriginalFrameCallIDs        []string   `json:"original_frame_call_ids"`
	OriginalCalledAt            time.Time  `json:"original_called_at"`
	OriginalReturnedAt          *time.Time `json:"original_returned_at"`
	OriginalContextDeadline     time.Time  `json:"original_context_deadline"`
	OriginalState               string     `json:"original_state"`
	OriginalErrorPresent        *bool      `json:"original_error_present"`
}

// Bounded private custody R5 component: poststart_ledger_custody_parser.go
func originalHostPostStartUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
func originalHostPostStartCallID(value string) (string, uint64, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 || !originalHostPostStartUUID(parts[0]) {
		return "", 0, false
	}
	n, err := strconv.ParseUint(parts[1], 10, 64)
	return parts[0], n, err == nil && n > 0 && n <= 65536 && strconv.FormatUint(n, 10) == parts[1]
}
func originalHostPostStartUTC(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC
}
func originalHostPostStartStrict(raw []byte, value any) error {
	if hostOriginalStrictJSON(raw, value, 65536) != nil || originalHostSourceCustodyRequiredFields(raw, reflect.TypeOf(value), 0) != nil {
		return ErrHostFactoryHold
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrHostFactoryHold
	}
	return nil
}
func originalHostPostStartSourceReturn(value hostOriginalPostStartSourceReturn, operation string, bound time.Time) error {
	if value.Operation != operation || !originalHostPostStartUUID(value.OriginalOwnerID) || value.OriginalOwnerRole != "host_exterior" || value.OriginalState != "returned" || value.OriginalErrorPresent || !originalHostPostStartUTC(value.OriginalCalledAt) || !originalHostPostStartUTC(value.OriginalReturnedAt) || !originalHostPostStartUTC(value.OriginalContextDeadline) || value.OriginalReturnedAt.Before(value.OriginalCalledAt) || !value.OriginalReturnedAt.Before(value.OriginalContextDeadline) || !value.OriginalReturnedAt.Before(bound) {
		return ErrHostFactoryHold
	}
	return nil
}
func originalHostPostStartNativeRef(value hostOriginalPostStartNativeReference) error {
	_, _, ok := originalHostPostStartCallID(value.OriginalCallID)
	if !ok || !capacity.ValidDigest(value.OriginalChunkBodySHA256) || !capacity.ValidDigest(value.OriginalChunkEnvelopeSHA256) || value.OriginalFactIndex >= 4096 {
		return ErrHostFactoryHold
	}
	return nil
}

func decodeOriginalHostPostStartLedgerCustody(raw []byte) (hostOriginalPostStartLedgerCustody, error) {
	var c hostOriginalPostStartLedgerCustody
	if originalHostPostStartStrict(raw, &c) != nil || c.Schema != "source_private_original_poststart_ledger_custody_v3" || originalHostParentHeldAnchorRef(c.OriginalParentHeldRootAnchor) != nil || !originalHostPostStartUUID(c.LogicalScopeRootID) || !originalHostPostStartUUID(c.FactoryRootID) || c.LogicalScopeRootID == c.FactoryRootID || !originalHostPostStartUUID(c.RequestID) || !originalHostPostStartUUID(c.OriginalPhaseID) || c.BindingSchema != "original_host_factory_pre_authority_scope_v4" || !originalHostPostStartUTC(c.OriginalEffectivePhaseDeadline) {
		return c, ErrHostFactoryHold
	}
	for _, sha := range []string{c.SourceApprovalBodySHA256, c.RootPreparationBodySHA256, c.InitialEmptyBodySHA256, c.InitialControlLedgerSHA256, c.InitialProtectedAdmissionSHA256, c.OriginalLeaseProvenanceBodySHA256, c.ScopeBodySHA256, c.ScopeEnvelopeSHA256, c.CurrentJournalSHA256, c.AggregateBodySHA256, c.AggregateEnvelopeSHA256, c.PreparedBodySHA256, c.PreparedEnvelopeSHA256} {
		if !capacity.ValidDigest(sha) {
			return c, ErrHostFactoryHold
		}
	}
	if len(c.ScopeWire) == 0 || len(c.ScopeWire) > 65536 || len(c.CurrentJournalWire) == 0 || len(c.CurrentJournalWire) > 65536 || capacity.HostFactoryRawSHA256(c.ScopeWire) != c.ScopeBodySHA256 || capacity.HostFactoryRawSHA256(c.CurrentJournalWire) != c.CurrentJournalSHA256 || originalHostPostStartNativeRef(c.OriginalStartReference) != nil {
		return c, ErrHostFactoryHold
	}
	if c.OriginalDirectoryCustody == nil || len(c.OriginalDirectoryCustody) != 1 || c.OriginalSourceAuditProjections == nil || len(c.OriginalSourceAuditProjections) == 0 || len(c.OriginalSourceAuditProjections) > 4096 {
		return c, ErrHostFactoryHold
	}
	var j hostOriginalCurrentFactoryOwnerJournal
	if originalHostPostStartStrict(c.CurrentJournalWire, &j) != nil || validateOriginalHostPostStartJournal(c, j) != nil || validateOriginalHostPostStartFrame(c, j) != nil || originalHostPostStartSourceReturn(c.OriginalPublicationReturn, "control_publish_original_current_ledgers", c.OriginalEffectivePhaseDeadline) != nil {
		return c, ErrHostFactoryHold
	}
	if c.OriginalPublicationReturn.OriginalCalledAt.Before(c.OriginalPreparedFrame.OriginalAuthenticationReturn.OriginalReturnedAt) {
		return c, ErrHostFactoryHold
	}
	for _, returned := range []hostOriginalPostStartSourceReturn{c.OriginalPublicationReturn, c.OriginalPreparedFrame.OriginalReceiverReturn, c.OriginalPreparedFrame.OriginalAuthenticationReturn} {
		if returned.OriginalOwnerID != c.OriginalPublicationReturn.OriginalOwnerID || returned.OriginalContextDeadline.After(j.OriginalRootContextDeadline) {
			return c, ErrHostFactoryHold
		}
	}
	audits, err := originalHostPostStartAuditMap(c)
	if err != nil {
		return c, err
	}
	selected := map[string]bool{}
	for n, f := range c.OriginalFileCustody {
		name, kind, sha, rawFile := "current-scope-ledger.json", "scope", c.ScopeBodySHA256, c.ScopeWire
		if n == 1 {
			name, kind, sha, rawFile = "current-control-operation-ledger.json", "current_control_journal", c.CurrentJournalSHA256, c.CurrentJournalWire
		}
		if f.Basename != name || f.ContentKind != kind || f.OriginalWholeSHA256 != sha || int(f.OriginalBytes) != len(rawFile) || !originalHostPostStartUUID(f.OriginalNativeRootAnchorHandleID) {
			return c, ErrHostFactoryHold
		}
		writer, err := originalHostPostStartSelection(c, f.OriginalWriter, "closed_file", audits, selected)
		if err != nil || validateOriginalHostPostStartFileStream(writer, true, f.OriginalBytes) != nil {
			return c, ErrHostFactoryHold
		}
		method, err := originalHostPostStartSelection(c, f.OriginalPublicationMethod, "closed_publication_method", audits, selected)
		if err != nil || len(method) != 2 || method[0].Fact.Operation != "source_file_rename_noreplace" || method[1].Fact.Operation != "source_directory_sync" || method[0].Fact.OriginalCalledAt.Before(*writer[len(writer)-1].Fact.OriginalReturnedAt) {
			return c, ErrHostFactoryHold
		}
		expected, err := originalHostPostStartSelection(c, f.OriginalExpectedReader, "closed_file", audits, selected)
		if err != nil || validateOriginalHostPostStartFileStream(expected, false, f.OriginalBytes) != nil || expected[0].Fact.OriginalCalledAt.Before(*method[1].Fact.OriginalReturnedAt) || expected[0].Fact.OriginalCalledAt.Before(c.OriginalPublicationReturn.OriginalReturnedAt) {
			return c, ErrHostFactoryHold
		}
		final, err := originalHostPostStartSelection(c, f.OriginalFinalReader, "closed_file", audits, selected)
		if err != nil || validateOriginalHostPostStartFileStream(final, false, f.OriginalBytes) != nil || final[0].Fact.OriginalCalledAt.Before(*expected[len(expected)-1].Fact.OriginalReturnedAt) {
			return c, ErrHostFactoryHold
		}
		if f.OriginalWriter.OriginalAnchorHandleID == nil || *f.OriginalWriter.OriginalAnchorHandleID != f.OriginalNativeRootAnchorHandleID || f.OriginalExpectedReader.OriginalAnchorHandleID == nil || f.OriginalFinalReader.OriginalAnchorHandleID == nil || *f.OriginalExpectedReader.OriginalAnchorHandleID != c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID || *f.OriginalFinalReader.OriginalAnchorHandleID != c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID {
			return c, ErrHostFactoryHold
		}
		if method[1].Fact.OriginalReturnedAt.After(c.OriginalPublicationReturn.OriginalReturnedAt) {
			return c, ErrHostFactoryHold
		}
		if writer[0].Fact.OriginalCalledAt.Before(c.OriginalPublicationReturn.OriginalCalledAt) || f.OriginalWriter.OriginalSourceOwnerID != c.OriginalPublicationReturn.OriginalOwnerID || f.OriginalPublicationMethod.OriginalSourceOwnerID != c.OriginalPublicationReturn.OriginalOwnerID || f.OriginalWriter.OriginalSourceOwnerRole != "host_exterior" || f.OriginalPublicationMethod.OriginalSourceOwnerRole != "host_exterior" || f.OriginalExpectedReader.OriginalSourceOwnerRole != "host_registrar" || f.OriginalFinalReader.OriginalSourceOwnerRole != "host_registrar" || f.OriginalExpectedReader.OriginalSourceOwnerID != c.OriginalDirectoryCustody[0].OriginalPrefix.OriginalSourceOwnerID || f.OriginalFinalReader.OriginalSourceOwnerID != c.OriginalDirectoryCustody[0].OriginalPrefix.OriginalSourceOwnerID {
			return c, ErrHostFactoryHold
		}
	}
	prefix := c.OriginalDirectoryCustody[0]
	anchor := prefix.OriginalNativeRootAnchor
	if prefix.OriginalSourceDirectoryHandleID != prefix.OriginalPrefix.OriginalHandleID || !originalHostPostStartUUID(anchor.OriginalHandleID) || anchor.OriginalHandleID == prefix.OriginalSourceDirectoryHandleID || anchor.OriginalHandleID == c.OriginalFileCustody[0].OriginalNativeRootAnchorHandleID || c.OriginalFileCustody[0].OriginalNativeRootAnchorHandleID != c.OriginalFileCustody[1].OriginalNativeRootAnchorHandleID || !capacity.ValidDigest(anchor.OriginalInventoryBodySHA256) || !capacity.ValidDigest(anchor.OriginalInventoryEnvelopeSHA256) || anchor.OriginalAcquisitionCallID != anchor.OriginalHandleID+":1" || anchor.OriginalFstatCallID != anchor.OriginalHandleID+":2" {
		return c, ErrHostFactoryHold
	}
	rows, err := originalHostPostStartSelection(c, prefix.OriginalPrefix, "open_directory_prefix", audits, selected)
	if err != nil || prefix.OriginalPrefix.OriginalSourceOwnerRole != "host_registrar" || len(rows) != 2 || rows[0].Fact.Operation != "source_directory_open" || rows[1].Fact.Operation != "source_directory_fstat" {
		return c, ErrHostFactoryHold
	}
	for _, f := range c.OriginalFileCustody {
		for _, reader := range []hostOriginalPostStartSourceSelection{f.OriginalExpectedReader, f.OriginalFinalReader} {
			if audits[reader.OriginalCallReferences[0]].Fact.OriginalCalledAt.Before(*rows[1].Fact.OriginalReturnedAt) {
				return c, ErrHostFactoryHold
			}
		}
	}
	firstFinal := audits[c.OriginalFileCustody[0].OriginalFinalReader.OriginalCallReferences[len(c.OriginalFileCustody[0].OriginalFinalReader.OriginalCallReferences)-1]]
	secondFinal := audits[c.OriginalFileCustody[1].OriginalFinalReader.OriginalCallReferences[0]]
	if secondFinal.Fact.OriginalCalledAt.Before(*firstFinal.Fact.OriginalReturnedAt) {
		return c, ErrHostFactoryHold
	}
	if len(selected) != len(audits) {
		return c, ErrHostFactoryHold
	}
	return c, nil
}

func validateOriginalHostPostStartJournal(c hostOriginalPostStartLedgerCustody, j hostOriginalCurrentFactoryOwnerJournal) error {
	if j.Schema != "source_private_original_current_factory_owner_journal_v1" || j.FactoryRootID != c.FactoryRootID || j.RootPreparationSHA256 != c.RootPreparationBodySHA256 || j.SourceApprovalSHA256 != c.SourceApprovalBodySHA256 || j.InitialControlLedgerSHA256 != c.InitialControlLedgerSHA256 || j.InitialProtectedAdmissionSHA256 != c.InitialProtectedAdmissionSHA256 || j.PreAuthorityScopeSHA256 != c.ScopeBodySHA256 || j.Phase != "worker" || j.RequestID != c.RequestID || !j.OriginalEffectivePhaseDeadline.Equal(c.OriginalEffectivePhaseDeadline) || !originalHostPostStartUUID(j.FactoryAttemptID) || !originalHostPostStartUUID(j.CreatorOwnerID) || !originalHostPostStartUTC(j.OriginalRootContextStartedAt) || !originalHostPostStartUTC(j.OriginalRootContextDeadline) || !originalHostPostStartUTC(j.OriginalPhaseCalledAt) || j.OriginalPhaseCalledAt.Before(j.OriginalRootContextStartedAt) || !j.OriginalPhaseCalledAt.Before(j.OriginalEffectivePhaseDeadline) || j.OriginalEffectivePhaseDeadline.After(j.OriginalRootContextDeadline) || j.FactoryOwnerEvents == nil || len(j.FactoryOwnerEvents) != 3 {
		return ErrHostFactoryHold
	}
	for _, sha := range []string{j.CoreBasalOwnerRawSHA256, j.FactoryRegistrySHA256, j.FactorySourceClosureSHA256} {
		if !capacity.ValidDigest(sha) {
			return ErrHostFactoryHold
		}
	}
	seen := map[string]bool{}
	for n, e := range j.FactoryOwnerEvents {
		if e.Ordinal != uint32(n+1) || !originalHostPostStartUUID(e.EventID) || seen[e.EventID] || e.OriginalOwnerID != c.OriginalPublicationReturn.OriginalOwnerID || e.OriginalState != "returned" || e.OriginalErrorPresent == nil || *e.OriginalErrorPresent || e.OriginalReturnedAt == nil || !originalHostPostStartUTC(e.OriginalCalledAt) || !originalHostPostStartUTC(*e.OriginalReturnedAt) || !originalHostPostStartUTC(e.OriginalContextDeadline) || e.OriginalReturnedAt.Before(e.OriginalCalledAt) || !e.OriginalReturnedAt.Before(e.OriginalContextDeadline) || !e.OriginalReturnedAt.Before(c.OriginalEffectivePhaseDeadline) || e.OriginalFrameCallIDs == nil || n > 0 && e.OriginalCalledAt.Before(*j.FactoryOwnerEvents[n-1].OriginalReturnedAt) {
			return ErrHostFactoryHold
		}
		seen[e.EventID] = true
		if e.OriginalCalledAt.Before(j.OriginalPhaseCalledAt) || e.OriginalContextDeadline.After(j.OriginalRootContextDeadline) {
			return ErrHostFactoryHold
		}
		switch n {
		case 0:
			if e.Transition != "scope_associated" || e.SourceOwnerKind != "owning_source_go_return" || e.OriginalCallID != nil || e.OriginalBodySHA256 == nil || *e.OriginalBodySHA256 != c.ScopeBodySHA256 || e.OriginalEnvelopeSHA256 == nil || *e.OriginalEnvelopeSHA256 != c.ScopeEnvelopeSHA256 || e.OriginalChunkBodySHA256 != nil || e.OriginalChunkEnvelopeSHA256 != nil || e.OriginalFactIndex != nil || len(e.OriginalFrameCallIDs) != 0 {
				return ErrHostFactoryHold
			}
		case 1:
			r := c.OriginalStartReference
			if e.Transition != "worker_start" || e.SourceOwnerKind != "original_native_call" || e.OriginalCallID == nil || *e.OriginalCallID != r.OriginalCallID || e.OriginalBodySHA256 != nil || e.OriginalEnvelopeSHA256 != nil || e.OriginalChunkBodySHA256 == nil || *e.OriginalChunkBodySHA256 != r.OriginalChunkBodySHA256 || e.OriginalChunkEnvelopeSHA256 == nil || *e.OriginalChunkEnvelopeSHA256 != r.OriginalChunkEnvelopeSHA256 || e.OriginalFactIndex == nil || *e.OriginalFactIndex != r.OriginalFactIndex || len(e.OriginalFrameCallIDs) != 0 {
				return ErrHostFactoryHold
			}
		case 2:
			a := c.OriginalPreparedFrame.OriginalAuthenticationReturn
			if e.Transition != "worker_prepared_plan" || e.SourceOwnerKind != "original_worker_frame" || e.OriginalCallID != nil || e.OriginalBodySHA256 == nil || *e.OriginalBodySHA256 != c.PreparedBodySHA256 || e.OriginalEnvelopeSHA256 == nil || *e.OriginalEnvelopeSHA256 != c.PreparedEnvelopeSHA256 || e.OriginalChunkBodySHA256 != nil || e.OriginalChunkEnvelopeSHA256 != nil || e.OriginalFactIndex != nil || !e.OriginalCalledAt.Equal(a.OriginalCalledAt) || !e.OriginalReturnedAt.Equal(a.OriginalReturnedAt) || !e.OriginalContextDeadline.Equal(a.OriginalContextDeadline) {
				return ErrHostFactoryHold
			}
		}
	}
	return nil
}

func validateOriginalHostPostStartFrame(c hostOriginalPostStartLedgerCustody, j hostOriginalCurrentFactoryOwnerJournal) error {
	f := c.OriginalPreparedFrame
	if f.FramingSchema != "source_private_original_worker_signed_frame_length_prefix_v1" || !originalHostPostStartUUID(f.OriginalStreamHandleID) || len(f.OriginalReadWire) < 5 || len(f.OriginalReadWire) > 65536 || f.OriginalFrameOffset != 4 || f.OriginalFrameBytes == 0 || f.OriginalFrameBytes > 65532 || binary.BigEndian.Uint32(f.OriginalReadWire[:4]) != f.OriginalFrameBytes || uint64(f.OriginalFrameBytes)+4 != uint64(len(f.OriginalReadWire)) || f.OriginalReadSegments == nil || len(f.OriginalReadSegments) == 0 || len(f.OriginalReadSegments) > 4096 || len(j.FactoryOwnerEvents[2].OriginalFrameCallIDs) != len(f.OriginalReadSegments) {
		return ErrHostFactoryHold
	}
	if originalHostPostStartSourceReturn(f.OriginalReceiverReturn, "read_original_parent_worker_frame", c.OriginalEffectivePhaseDeadline) != nil || originalHostPostStartSourceReturn(f.OriginalAuthenticationReturn, "control_retain_original_factory_prepared", c.OriginalEffectivePhaseDeadline) != nil || f.OriginalAuthenticationReturn.OriginalCalledAt.Before(f.OriginalReceiverReturn.OriginalReturnedAt) || f.OriginalReceiverReturn.OriginalCalledAt.Before(*j.FactoryOwnerEvents[1].OriginalReturnedAt) {
		return ErrHostFactoryHold
	}
	offset := uint64(0)
	seen := map[string]bool{}
	var previousOrdinal uint64
	for n, s := range f.OriginalReadSegments {
		h, ordinal, ok := originalHostPostStartCallID(s.OriginalCallID)
		if !ok || h != f.OriginalStreamHandleID || seen[s.OriginalCallID] || j.FactoryOwnerEvents[2].OriginalFrameCallIDs[n] != s.OriginalCallID || originalHostPostStartNativeRef(hostOriginalPostStartNativeReference{s.OriginalCallID, s.OriginalChunkBodySHA256, s.OriginalChunkEnvelopeSHA256, s.OriginalFactIndex}) != nil || uint64(s.OriginalRawOffset) != offset || s.OriginalRawBytes == 0 || offset+uint64(s.OriginalRawBytes) > uint64(len(f.OriginalReadWire)) || offset < 4 && offset+uint64(s.OriginalRawBytes) > 4 {
			return ErrHostFactoryHold
		}
		if n > 0 && ordinal != previousOrdinal+1 {
			return ErrHostFactoryHold
		}
		previousOrdinal = ordinal
		offset += uint64(s.OriginalRawBytes)
		seen[s.OriginalCallID] = true
	}
	if offset != uint64(len(f.OriginalReadWire)) {
		return ErrHostFactoryHold
	}
	var payload struct {
		Schema      string `json:"schema"`
		Selector    string `json:"selector"`
		EnvelopeRaw []byte `json:"envelope_raw"`
	}
	if originalHostPostStartStrict(f.OriginalReadWire[4:], &payload) != nil || payload.Schema != "source_private_original_worker_signed_frame_v1" || payload.Selector != "prepared-create-plan" || len(payload.EnvelopeRaw) == 0 || len(payload.EnvelopeRaw) > 65536 || capacity.HostFactoryRawSHA256(payload.EnvelopeRaw) != c.PreparedEnvelopeSHA256 {
		return ErrHostFactoryHold
	}
	return nil
}

func originalHostPostStartAuditMap(c hostOriginalPostStartLedgerCustody) (map[string]hostOriginalSourceAuditProjection, error) {
	result := map[string]hostOriginalSourceAuditProjection{}
	seenHandles := map[string]bool{}
	var currentHandle string
	var ordinal uint64
	var currentDeadline, previousReturned, lastAcquired time.Time
	for _, row := range c.OriginalSourceAuditProjections {
		f := row.Fact
		handle, n, ok := originalHostPostStartCallID(originalHostPostStartPointerString(f.OriginalCallID))
		if row.Family != "source_audit" || row.SubjectIdentity.SubjectKind != "source_file" || row.SubjectIdentity.RequestIdentity != nil || row.SubjectIdentity.PublicRunID != nil || row.SubjectIdentity.Method != nil || row.SubjectIdentity.PathFamily != nil || f.FactoryRootID != c.FactoryRootID || capacity.ValidateHostFactory(f) != nil || !ok || f.OriginalCalledAt == nil || f.OriginalReturnedAt == nil || f.OriginalErrorPresent == nil || f.OriginalState != "returned" || f.OriginalSHA256 != nil || f.RetainedPrefixSHA256 != nil || f.RetainedPrefixBytes != nil || f.OriginalReadScope != nil || f.OriginalStatusCode != nil || !f.OriginalReturnedAt.Before(f.OriginalOperationDeadline) {
			return nil, ErrHostFactoryHold
		}
		if f.FailureCode != nil || handle != f.OriginalAuditHandleID || !originalHostPostStartUTC(*f.OriginalCalledAt) || !originalHostPostStartUTC(*f.OriginalReturnedAt) || !originalHostPostStartUTC(f.OriginalOperationDeadline) || f.OriginalReturnedAt.Before(*f.OriginalCalledAt) || !f.OriginalReturnedAt.Before(c.OriginalEffectivePhaseDeadline) {
			return nil, ErrHostFactoryHold
		}
		if handle != currentHandle {
			if seenHandles[handle] || n != 1 || f.OriginalCalledAt.Before(lastAcquired) {
				return nil, ErrHostFactoryHold
			}
			seenHandles[handle] = true
			currentHandle, ordinal, currentDeadline = handle, 0, f.OriginalOperationDeadline
			lastAcquired = *f.OriginalCalledAt
		} else if f.OriginalCalledAt.Before(previousReturned) {
			return nil, ErrHostFactoryHold
		}
		if n != ordinal+1 || !f.OriginalOperationDeadline.Equal(currentDeadline) {
			return nil, ErrHostFactoryHold
		}
		ordinal, previousReturned = n, *f.OriginalReturnedAt
		if _, exists := result[*f.OriginalCallID]; exists {
			return nil, ErrHostFactoryHold
		}
		result[*f.OriginalCallID] = row
	}
	return result, nil
}
func originalHostPostStartPointerString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func originalHostPostStartSelection(c hostOriginalPostStartLedgerCustody, s hostOriginalPostStartSourceSelection, state string, audits map[string]hostOriginalSourceAuditProjection, selected map[string]bool) ([]hostOriginalSourceAuditProjection, error) {
	if s.OriginalStreamState != state || !originalHostPostStartUUID(s.OriginalHandleID) || !originalHostPostStartUUID(s.OriginalSourceOwnerID) || s.OriginalSourceOwnerRole != "host_exterior" && s.OriginalSourceOwnerRole != "host_registrar" || !capacity.ValidDigest(s.OriginalSourceBindingSHA256) || s.OriginalCallReferences == nil || len(s.OriginalCallReferences) == 0 || len(s.OriginalCallReferences) > 4096 {
		return nil, ErrHostFactoryHold
	}
	if s.OriginalSourceBindingSchema == "original_host_factory_pre_authority_scope_v4" {
		if s.OriginalSourceBindingSHA256 != c.ScopeBodySHA256 {
			return nil, ErrHostFactoryHold
		}
	} else if s.OriginalSourceBindingSchema == "original_host_factory_root_preparation_v4" {
		if s.OriginalSourceBindingSHA256 != c.RootPreparationBodySHA256 {
			return nil, ErrHostFactoryHold
		}
	} else if s.OriginalSourceBindingSchema != "original_host_factory_source_approval_v4" || s.OriginalSourceBindingSHA256 != c.SourceApprovalBodySHA256 {
		// The actual bootstrap Source audit directory was acquired under the
		// original approval ledger. Preserve that ancestor; never rebind it to
		// the later native RootPreparation or Scope ledger.
		return nil, ErrHostFactoryHold
	}
	if state == "closed_file" && (s.OriginalCloseCallID == nil || s.OriginalAnchorHandleID == nil) || state != "closed_file" && (s.OriginalCloseCallID != nil || s.OriginalAnchorHandleID != nil) {
		return nil, ErrHostFactoryHold
	}
	rows := make([]hostOriginalSourceAuditProjection, 0, len(s.OriginalCallReferences))
	for n, id := range s.OriginalCallReferences {
		row, ok := audits[id]
		if !ok || selected[id] || id != s.OriginalHandleID+":"+strconv.Itoa(n+1) || row.Fact.OriginalAuditHandleID != s.OriginalHandleID || !reflect.DeepEqual(row.OriginalCloseReference, s.OriginalCloseCallID) || n > 0 && row.Fact.OriginalCalledAt.Before(*rows[n-1].Fact.OriginalReturnedAt) {
			return nil, ErrHostFactoryHold
		}
		if state != "closed_file" && (*row.Fact.OriginalErrorPresent || row.Fact.OriginalCount != nil || row.Fact.OriginalEOF != nil || row.Fact.OriginalHashState != "not_byte_operation") {
			return nil, ErrHostFactoryHold
		}
		selected[id] = true
		rows = append(rows, row)
	}
	if state == "closed_file" && *s.OriginalCloseCallID != s.OriginalCallReferences[len(s.OriginalCallReferences)-1] {
		return nil, ErrHostFactoryHold
	}
	return rows, nil
}

func validateOriginalHostPostStartFileStream(rows []hostOriginalSourceAuditProjection, writer bool, expected uint32) error {
	if len(rows) < 5 || rows[0].Fact.Operation != "source_file_open" || rows[1].Fact.Operation != "source_file_fstat" || rows[len(rows)-1].Fact.Operation != "source_file_close" {
		return ErrHostFactoryHold
	}
	count := int64(0)
	eof := false
	for n, row := range rows {
		f := row.Fact
		if n == 0 || n == 1 || n == len(rows)-1 || writer && n == len(rows)-2 || !writer && n == len(rows)-2 {
			operation := "source_file_open"
			if n == 1 || !writer && n == len(rows)-2 {
				operation = "source_file_fstat"
			}
			if writer && n == len(rows)-2 {
				operation = "source_file_sync"
			}
			if n == len(rows)-1 {
				operation = "source_file_close"
			}
			if f.Operation != operation || *f.OriginalErrorPresent || f.OriginalCount != nil || f.OriginalEOF != nil || f.OriginalHashState != "not_byte_operation" {
				return ErrHostFactoryHold
			}
			continue
		}
		if f.OriginalCount == nil || *f.OriginalCount < 0 || *f.OriginalCount > 65536 || f.OriginalHashState != "private_withheld" {
			return ErrHostFactoryHold
		}
		if writer {
			if f.Operation != "source_file_write" || f.OriginalEOF != nil || *f.OriginalErrorPresent || *f.OriginalCount == 0 {
				return ErrHostFactoryHold
			}
		} else {
			if f.Operation != "source_file_read" || f.OriginalEOF == nil || eof || *f.OriginalErrorPresent != *f.OriginalEOF || !*f.OriginalEOF && *f.OriginalCount == 0 {
				return ErrHostFactoryHold
			}
			eof = *f.OriginalEOF
		}
		count += *f.OriginalCount
		if count > 65536 {
			return ErrHostFactoryHold
		}
	}
	if count != int64(expected) || !writer && !eof {
		return ErrHostFactoryHold
	}
	return nil
}

// Separate readonly prefix relation: never import this prefix into the merger
// of completed Source streams, and never rewrite the immutable custody BYTEA.
func compareOriginalHostPostStartDirectoryPrefix(c hostOriginalPostStartLedgerCustody, final map[string]hostOriginalSourceAuditProjection) error {
	// This is only an immutable structural relation. The owning historical
	// reader authenticates Source identity/SQL custody and actual actor/Main
	// return ordering separately; this function never installs that authority.
	before, err := originalHostPostStartAuditMap(c)
	if err != nil || len(c.OriginalDirectoryCustody) != 1 {
		return ErrHostFactoryHold
	}
	p := c.OriginalDirectoryCustody[0]
	s := p.OriginalPrefix
	if s.OriginalStreamState != "open_directory_prefix" || s.OriginalCloseCallID != nil || s.OriginalAnchorHandleID != nil || len(s.OriginalCallReferences) != 2 {
		return ErrHostFactoryHold
	}
	closeID := p.OriginalSourceDirectoryHandleID + ":3"
	closeRow, ok := final[closeID]
	prefix, present := before[p.OriginalSourceDirectoryHandleID+":1"]
	if !ok || !present || closeRow.Family != prefix.Family || !reflect.DeepEqual(closeRow.SubjectIdentity, prefix.SubjectIdentity) || closeRow.Fact.FactoryRootID != c.FactoryRootID || closeRow.Fact.OriginalAuditHandleID != p.OriginalSourceDirectoryHandleID || originalHostPostStartPointerString(closeRow.Fact.OriginalCallID) != closeID || closeRow.Fact.OriginalState != "returned" || closeRow.Fact.Operation != "source_directory_close" || closeRow.Fact.OriginalCalledAt == nil || closeRow.Fact.OriginalReturnedAt == nil || closeRow.Fact.OriginalErrorPresent == nil || *closeRow.Fact.OriginalErrorPresent || closeRow.OriginalCloseReference == nil || *closeRow.OriginalCloseReference != closeID || capacity.ValidateHostFactory(closeRow.Fact) != nil || !originalHostPostStartUTC(*closeRow.Fact.OriginalCalledAt) || !originalHostPostStartUTC(*closeRow.Fact.OriginalReturnedAt) || closeRow.Fact.OriginalReturnedAt.Before(*closeRow.Fact.OriginalCalledAt) || !closeRow.Fact.OriginalOperationDeadline.Equal(prefix.Fact.OriginalOperationDeadline) || !closeRow.Fact.OriginalReturnedAt.Before(closeRow.Fact.OriginalOperationDeadline) || closeRow.Fact.OriginalHashState != "not_byte_operation" || closeRow.Fact.OriginalCount != nil || closeRow.Fact.OriginalSHA256 != nil || closeRow.Fact.OriginalEOF != nil || closeRow.Fact.FailureCode != nil {
		return ErrHostFactoryHold
	}
	for n, id := range s.OriginalCallReferences {
		original, exists := before[id]
		actual, present := final[id]
		if !exists || !present || id != p.OriginalSourceDirectoryHandleID+":"+strconv.Itoa(n+1) || original.OriginalCloseReference != nil || actual.OriginalCloseReference == nil || *actual.OriginalCloseReference != closeID || original.Family != actual.Family || !reflect.DeepEqual(original.SubjectIdentity, actual.SubjectIdentity) || !reflect.DeepEqual(original.Fact, actual.Fact) || closeRow.Fact.OriginalCalledAt.Before(*original.Fact.OriginalReturnedAt) {
			return ErrHostFactoryHold
		}
	}
	for _, file := range c.OriginalFileCustody {
		for _, stream := range []hostOriginalPostStartSourceSelection{file.OriginalWriter, file.OriginalPublicationMethod, file.OriginalExpectedReader, file.OriginalFinalReader} {
			count := 0
			for key, row := range final {
				if row.Fact.OriginalAuditHandleID == stream.OriginalHandleID {
					if originalHostPostStartPointerString(row.Fact.OriginalCallID) != key {
						return ErrHostFactoryHold
					}
					count++
				}
			}
			if count != len(stream.OriginalCallReferences) {
				return ErrHostFactoryHold
			}
			for _, id := range stream.OriginalCallReferences {
				original, exists := before[id]
				actual, present := final[id]
				a, aErr := json.Marshal(original)
				b, bErr := json.Marshal(actual)
				if !exists || !present || aErr != nil || bErr != nil || !reflect.DeepEqual(original, actual) || !bytes.Equal(a, b) {
					return ErrHostFactoryHold
				}
			}
		}
		for _, reader := range []hostOriginalPostStartSourceSelection{file.OriginalExpectedReader, file.OriginalFinalReader} {
			row, ok := before[originalHostPostStartPointerString(reader.OriginalCloseCallID)]
			if !ok || closeRow.Fact.OriginalCalledAt.Before(*row.Fact.OriginalReturnedAt) {
				return ErrHostFactoryHold
			}
		}
	}
	count := 0
	for key, row := range final {
		if row.Fact.OriginalAuditHandleID == p.OriginalSourceDirectoryHandleID {
			if originalHostPostStartPointerString(row.Fact.OriginalCallID) != key {
				return ErrHostFactoryHold
			}
			count++
		}
	}
	if count != 3 {
		return ErrHostFactoryHold
	}
	return nil
}

// Bounded private custody R5 component: poststart_ledger_custody_sql.go
func captureOriginalHostPostStartLedgerCustodyTx(ctx context.Context, tx *sql.Tx, selector HostFactoryRecordSelector, body any, bodyRaw, envelopeRaw []byte) ([]byte, error) {
	if selector.Stage != "poststart-empty-realm-read" {
		return nil, nil
	}
	value, ok := body.(*model.HostFactoryOriginalEmptyRealmRead)
	realm, approval, installed := OriginalHostFactoryRealm()
	if !ok || ctx == nil || ctx.Err() != nil || tx == nil || !installed || realm == nil || approval.ScopeRootID != selector.RootID || selector.Family != "scope" || selector.Role != "host_registrar" || selector.BindingSchema != "original_host_factory_pre_authority_scope_v4" || realm.VerifyOriginalStage(ctx, selector.Stage, envelopeRaw) != nil {
		return nil, ErrHostFactoryHold
	}
	codec := originalHostSourceCodecTx(ctx, tx, selector.RootID)
	canonical, err := codec.Canonical(value)
	if err != nil || !bytes.Equal(canonical, bodyRaw) {
		return nil, ErrHostFactoryHold
	}
	raw, err := realm.OriginalPostStartLedgerCustody(ctx, capacity.HostFactoryRawSHA256(bodyRaw))
	if err != nil {
		return nil, ErrHostFactoryHold
	}
	c, err := decodeOriginalHostPostStartLedgerCustody(raw)
	if err != nil || originalHostParentHeldAnchorFromSource(ctx, realm, c.OriginalParentHeldRootAnchor) != nil {
		return nil, ErrHostFactoryHold
	}
	if validateOriginalHostPostStartIdentityTx(ctx, tx, selector, *value, bodyRaw, envelopeRaw, c) != nil {
		return nil, ErrHostFactoryHold
	}
	// This is provisional graph/storage validation. Its success inside the
	// transaction is not the required Commit + helper/outer GoReturn admission.
	phaseRaw, err := validateOriginalHostNativeAggregateTx(ctx, tx, selector.RootID, selector.BindingSchema, selector.BindingSHA256, body, envelopeRaw)
	if err != nil {
		return nil, err
	}
	if validateOriginalHostPostStartPhase(c, phaseRaw) != nil {
		return nil, ErrHostFactoryHold
	}
	observations, err := resolveOriginalHostNativeAggregateTx(ctx, tx, selector.RootID, selector.BindingSchema, selector.BindingSHA256, c.OriginalEffectivePhaseDeadline, body, envelopeRaw, phaseRaw)
	if err != nil || validateOriginalHostPostStartCensusCutoffTx(ctx, tx, selector.RootID, c, observations) != nil {
		return nil, ErrHostFactoryHold
	}
	if validateOriginalHostPostStartNativeRefsTx(ctx, tx, selector.RootID, c) != nil {
		return nil, ErrHostFactoryHold
	}
	return bytes.Clone(raw), nil
}

func validateOriginalHostPostStartIdentityTx(ctx context.Context, tx *sql.Tx, selector HostFactoryRecordSelector, body model.HostFactoryOriginalEmptyRealmRead, bodyRaw, envelopeRaw []byte, c hostOriginalPostStartLedgerCustody) error {
	if c.LogicalScopeRootID != selector.RootID || c.AggregateBodySHA256 != capacity.HostFactoryRawSHA256(bodyRaw) || c.AggregateEnvelopeSHA256 != capacity.HostFactoryRawSHA256(envelopeRaw) || c.ScopeBodySHA256 != selector.BindingSHA256 || body.PreAuthorityScopeSHA256 != c.ScopeBodySHA256 || body.ScopeRootID != c.LogicalScopeRootID || body.PreparedCreatePlanSHA256 != c.PreparedBodySHA256 || body.RegistrySourceApprovalSHA256 != c.SourceApprovalBodySHA256 || body.OriginalScopeLedgerSHA256 != c.ScopeBodySHA256 || body.OriginalControlOperationLedgerSHA256 != c.CurrentJournalSHA256 || body.InitialEmptyRealmReadSHA256 != c.InitialEmptyBodySHA256 || body.OriginalLeaseProvenanceSHA256 != c.OriginalLeaseProvenanceBodySHA256 {
		return ErrHostFactoryHold
	}
	var root model.HostFactoryRootPreparation
	if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, selector.RootID, "root-preparation", c.RootPreparationBodySHA256, &root); err != nil {
		return err
	}
	if root.FactoryRootID != c.FactoryRootID || root.SourceApprovalSHA256 != c.SourceApprovalBodySHA256 || root.InitialControlLedgerSHA256 != c.InitialControlLedgerSHA256 || root.InitialProtectedAdmissionSHA256 != c.InitialProtectedAdmissionSHA256 || c.OriginalParentHeldRootAnchor.OriginalHandleID != c.OriginalFileCustody[0].OriginalNativeRootAnchorHandleID {
		return ErrHostFactoryHold
	}
	var core model.HostFactoryBasalOwnerObservation
	if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, selector.RootID, "basal-owner-core", root.CoreBasalOwnerRawSHA256, &core); err != nil || core.FactoryRootID != c.FactoryRootID || core.OriginalOwnerID != c.OriginalPublicationReturn.OriginalOwnerID || core.Role != "host_exterior" || core.SourceApprovalSHA256 != c.SourceApprovalBodySHA256 {
		return ErrHostFactoryHold
	}
	if authenticateOriginalHostParentHeldAnchorTx(ctx, tx, selector.RootID, root, core, c.OriginalParentHeldRootAnchor) != nil {
		return ErrHostFactoryHold
	}
	var scope model.HostFactoryPreAuthorityScope
	scopeRaw, err := originalHostAuthenticatedStageBodyTx(ctx, tx, selector.RootID, "preauthority-scope", c.ScopeBodySHA256, &scope)
	if err != nil || !bytes.Equal(scopeRaw, c.ScopeWire) || scope.FactoryRealmID != c.FactoryRootID || scope.ScopeRootID != c.LogicalScopeRootID || scope.InitialEmptyRealmReadSHA256 != c.InitialEmptyBodySHA256 || scope.OriginalLeaseProvenanceSHA256 != c.OriginalLeaseProvenanceBodySHA256 || scope.FactoryRegistrySHA256 != root.FactoryRegistrySHA256 || scope.FactorySourceClosureSHA256 != root.FactorySourceClosureSHA256 || c.OriginalEffectivePhaseDeadline.After(scope.OriginalContextDeadline) || c.OriginalEffectivePhaseDeadline.After(scope.OriginalLeaseExpiresAt) {
		return ErrHostFactoryHold
	}
	var scopeEnvelope []byte
	if tx.QueryRowContext(ctx, `SELECT raw_envelope_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='preauthority-scope' AND raw_body_sha256=$2 AND raw_envelope_sha256=$3`, selector.RootID, c.ScopeBodySHA256, c.ScopeEnvelopeSHA256).Scan(&scopeEnvelope) != nil || capacity.HostFactoryRawSHA256(scopeEnvelope) != c.ScopeEnvelopeSHA256 {
		return ErrHostFactoryHold
	}
	var prepared model.HostFactoryPreparedCreatePlan
	_, err = originalHostAuthenticatedStageBodyTx(ctx, tx, selector.RootID, "prepared-create-plan", c.PreparedBodySHA256, &prepared)
	if err != nil || prepared.BindingSchema != selector.BindingSchema || prepared.BindingSHA256 != c.ScopeBodySHA256 || prepared.OwnerPrimitiveRawSHA256 == root.CoreBasalOwnerRawSHA256 {
		return ErrHostFactoryHold
	}
	var worker model.HostFactoryBasalOwnerObservation
	if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, selector.RootID, "basal-owner-worker", prepared.OwnerPrimitiveRawSHA256, &worker); err != nil || worker.FactoryRootID != c.FactoryRootID || worker.OriginalOwnerID != scope.CreatorOwnerID || worker.Role != "host_worker" || worker.SourceApprovalSHA256 != c.SourceApprovalBodySHA256 || prepared.FactoryRegistrySHA256 != scope.FactoryRegistrySHA256 || prepared.StableOriginalTargetSHA256 != scope.StableOriginalTargetSHA256 {
		return ErrHostFactoryHold
	}
	var registrarSHA string
	var registrar model.HostFactoryBasalOwnerObservation
	if tx.QueryRowContext(ctx, `SELECT raw_body_sha256 FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='basal-owner-registrar'`, selector.RootID).Scan(&registrarSHA) != nil {
		return ErrHostFactoryHold
	}
	if _, err := originalHostAuthenticatedStageBodyTx(ctx, tx, selector.RootID, "basal-owner-registrar", registrarSHA, &registrar); err != nil || registrar.FactoryRootID != c.FactoryRootID || registrar.Role != "host_registrar" || registrar.SourceApprovalSHA256 != c.SourceApprovalBodySHA256 || registrar.OriginalOwnerID != c.OriginalDirectoryCustody[0].OriginalPrefix.OriginalSourceOwnerID {
		return ErrHostFactoryHold
	}
	if validateOriginalHostPostStartNativeAnchorTx(ctx, tx, selector.RootID, c, root, registrarSHA) != nil {
		return ErrHostFactoryHold
	}
	var preparedEnvelope []byte
	if tx.QueryRowContext(ctx, `SELECT raw_envelope_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage='prepared-create-plan' AND raw_body_sha256=$2 AND raw_envelope_sha256=$3`, selector.RootID, c.PreparedBodySHA256, c.PreparedEnvelopeSHA256).Scan(&preparedEnvelope) != nil {
		return ErrHostFactoryHold
	}
	var frame struct {
		Schema      string `json:"schema"`
		Selector    string `json:"selector"`
		EnvelopeRaw []byte `json:"envelope_raw"`
	}
	if originalHostPostStartStrict(c.OriginalPreparedFrame.OriginalReadWire[4:], &frame) != nil || !bytes.Equal(frame.EnvelopeRaw, preparedEnvelope) {
		return ErrHostFactoryHold
	}
	var journal hostOriginalCurrentFactoryOwnerJournal
	if originalHostPostStartStrict(c.CurrentJournalWire, &journal) != nil || journal.FactoryAttemptID != scope.FactoryAttemptID || journal.CreatorOwnerID != scope.CreatorOwnerID || journal.CoreBasalOwnerRawSHA256 != root.CoreBasalOwnerRawSHA256 || journal.FactoryRegistrySHA256 != root.FactoryRegistrySHA256 || journal.FactorySourceClosureSHA256 != root.FactorySourceClosureSHA256 || !journal.OriginalRootContextStartedAt.Equal(root.OriginalContextStartedAt) || !journal.OriginalRootContextDeadline.Equal(root.OriginalContextDeadline) {
		return ErrHostFactoryHold
	}
	audits, err := originalHostPostStartAuditMap(c)
	if err != nil {
		return err
	}
	last := c.OriginalFileCustody[1].OriginalFinalReader
	closeRow, ok := audits[originalHostPostStartPointerString(last.OriginalCloseCallID)]
	if !ok || len(last.OriginalCallReferences) < 3 {
		return ErrHostFactoryHold
	}
	readRow, ok := audits[last.OriginalCallReferences[len(last.OriginalCallReferences)-3]]
	if !ok || readRow.Fact.Operation != "source_file_read" || !body.OriginalReadStartedAt.Equal(journal.OriginalPhaseCalledAt) || !body.OriginalReadReturnedAt.Equal(*readRow.Fact.OriginalReturnedAt) || !body.OriginalReadCloseReturnedAt.Equal(*closeRow.Fact.OriginalReturnedAt) || !body.ObservedAt.Equal(*closeRow.Fact.OriginalReturnedAt) {
		return ErrHostFactoryHold
	}
	// Native phase/source/lease/FIRST authenticators remain independently
	// mandatory in the live and historical callers, never from this JSON alone.
	return nil
}

func validateOriginalHostPostStartNativeAnchorTx(ctx context.Context, tx *sql.Tx, root string, c hostOriginalPostStartLedgerCustody, prep model.HostFactoryRootPreparation, registrarSHA string) error {
	if len(c.OriginalDirectoryCustody) != 1 {
		return ErrHostFactoryHold
	}
	directory := c.OriginalDirectoryCustody[0]
	ref := directory.OriginalNativeRootAnchor
	// BOTH immutable hashes select this once snapshot, never latest/handle-only.
	var raw, envelope []byte
	if tx.QueryRowContext(ctx, `SELECT raw_body_wire,raw_envelope_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='handle-inventory' AND binding_schema='original_host_factory_root_preparation_v4' AND binding_sha256=$2 AND original_owner_id=$3 AND original_handle_id=$4 AND raw_body_sha256=$5 AND raw_envelope_sha256=$6`, root, c.RootPreparationBodySHA256, directory.OriginalPrefix.OriginalSourceOwnerID, ref.OriginalHandleID, ref.OriginalInventoryBodySHA256, ref.OriginalInventoryEnvelopeSHA256).Scan(&raw, &envelope) != nil {
		return ErrHostFactoryHold
	}
	codec := originalHostSourceCodecTx(ctx, tx, root)
	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
	if err != nil || capacity.HostFactoryRawSHA256(raw) != ref.OriginalInventoryBodySHA256 || capacity.HostFactoryRawSHA256(envelope) != ref.OriginalInventoryEnvelopeSHA256 {
		return ErrHostFactoryHold
	}
	authBody, authEnvelope, err := callbacks.resolveIO(ref.OriginalInventoryBodySHA256)
	if err != nil || !bytes.Equal(authBody, raw) || !bytes.Equal(authEnvelope, envelope) {
		return ErrHostFactoryHold
	}
	var inventory model.HostFactoryHandleCallInventory
	if codec.Decode(raw, &inventory) != nil || inventory.OwnerRole != "host_registrar" || inventory.OriginalOwnerID != directory.OriginalPrefix.OriginalSourceOwnerID || inventory.OwnerPrimitiveRawSHA256 == nil || *inventory.OwnerPrimitiveRawSHA256 != registrarSHA || inventory.BindingSchema != "original_host_factory_root_preparation_v4" || inventory.BindingSHA256 != c.RootPreparationBodySHA256 || inventory.OriginalHandleID != ref.OriginalHandleID || inventory.FirstOrdinal != 1 || inventory.LastOrdinal != 2 || len(inventory.OperationVectors) != 2 {
		return ErrHostFactoryHold
	}
	x, err := originalHostIOIdentity(codec, root, &inventory, raw)
	if err != nil || validateOriginalHostInventoryTx(ctx, tx, x, inventory) != nil {
		return ErrHostFactoryHold
	}
	facts := []model.HostFactoryPrimitiveIOReturn{}
	for _, vector := range inventory.OperationVectors {
		selected, err := originalHostVectorFactsTx(ctx, tx, root, vector)
		if err != nil || len(selected) != 1 {
			return ErrHostFactoryHold
		}
		facts = append(facts, selected[0])
	}
	return validateOriginalHostPostStartNativeAnchorFacts(c, prep.RootDirectorySource, facts)
}

// Structural equality only; the caller above authenticates exact source-owned
// pairs, Root/basal/role/namespace and actual immutable SQL-FIRST relations.
func validateOriginalHostPostStartNativeAnchorFacts(c hostOriginalPostStartLedgerCustody, parent model.HostFactoryBootstrapDescriptorSource, facts []model.HostFactoryPrimitiveIOReturn) error {
	if len(c.OriginalDirectoryCustody) != 1 || len(facts) != 2 {
		return ErrHostFactoryHold
	}
	ref := c.OriginalDirectoryCustody[0].OriginalNativeRootAnchor
	if ref.OriginalHandleID == parent.OriginalHandleID || ref.OriginalHandleID == c.OriginalParentHeldRootAnchor.OriginalHandleID || ref.OriginalHandleID == c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID {
		return ErrHostFactoryHold
	}
	var acquisition, stat *model.HostFactoryPrimitiveIOReturn
	for n := range facts {
		f := &facts[n]
		if f.OriginalCallID == nil || f.OriginalHandleID != ref.OriginalHandleID || f.SubjectOwnerID != c.OriginalPublicationReturn.OriginalOwnerID || f.OriginalState != "returned" || f.OriginalReturnClass != "success" || f.OriginalCalledAt == nil || f.OriginalReturnedAt == nil || !originalHostPostStartUTC(*f.OriginalCalledAt) || !originalHostPostStartUTC(*f.OriginalReturnedAt) || f.OriginalReturnedAt.Before(*f.OriginalCalledAt) || f.OriginalNativeReturn == nil || f.OriginalNativeReturn.OriginalErrorPresent == nil || *f.OriginalNativeReturn.OriginalErrorPresent || f.OriginalNativeReturn.OriginalErrno == nil || *f.OriginalNativeReturn.OriginalErrno != 0 || !f.OriginalReturnedAt.Before(f.OriginalOperationDeadline) || !f.OriginalReturnedAt.Before(c.OriginalEffectivePhaseDeadline) {
			return ErrHostFactoryHold
		}
		if *f.OriginalCallID == ref.OriginalAcquisitionCallID && acquisition == nil {
			acquisition = f
		} else if *f.OriginalCallID == ref.OriginalFstatCallID && stat == nil {
			stat = f
		} else {
			return ErrHostFactoryHold
		}
	}
	if acquisition == nil || stat == nil || acquisition.Operation != "native_reader_open" || stat.Operation != "native_reader_fstat" || stat.OriginalCalledAt.Before(*acquisition.OriginalReturnedAt) || !stat.OriginalOperationDeadline.Equal(acquisition.OriginalOperationDeadline) {
		return ErrHostFactoryHold
	}
	open, fstat := acquisition.OriginalNativeReturn, stat.OriginalNativeReturn
	if open.Kind != "unix_open" || open.OriginalScalar == nil || *open.OriginalScalar < 0 || len(open.ReturnedDescriptors) != 1 || open.ReturnedDescriptors[0].OriginalHandleID != ref.OriginalHandleID || int64(open.ReturnedDescriptors[0].OriginalDescriptorNumber) != *open.OriginalScalar || fstat.Kind != "unix_fstat" || fstat.InputDescriptorNumber == nil || int64(*fstat.InputDescriptorNumber) != *open.OriginalScalar || fstat.OriginalStat == nil {
		return ErrHostFactoryHold
	}
	actual := fstat.OriginalStat
	if actual.Device != parent.Device || actual.Inode != parent.Inode || actual.Mode != parent.Mode || actual.LinkCount != parent.LinkCount || actual.UID != parent.UID || actual.GID != parent.GID {
		return ErrHostFactoryHold
	}
	// RequestedFlags are not observed F_GETFL/F_GETFD; do not synthesize them.
	return nil
}

func readOriginalHostPostStartLedgerCustodyTx(ctx context.Context, tx *sql.Tx, selector HostFactoryRecordSelector, body model.HostFactoryOriginalEmptyRealmRead, bodyRaw, envelopeRaw []byte) (hostOriginalPostStartLedgerCustody, error) {
	var raw, phaseRaw []byte
	var c hostOriginalPostStartLedgerCustody
	if ctx == nil || ctx.Err() != nil || tx == nil || selector.Stage != "poststart-empty-realm-read" || selector.Family != "scope" || selector.Role != "host_registrar" || selector.BindingSchema != "original_host_factory_pre_authority_scope_v4" {
		return c, ErrHostFactoryHold
	}
	if tx.QueryRowContext(ctx, `SELECT original_poststart_ledger_wire,native_phase_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage=$2 AND binding_schema=$3 AND binding_sha256=$4 AND signer_role=$5 AND raw_body_sha256=$6 AND raw_envelope_sha256=$7 AND subject_owner_id=(SELECT owner_id FROM public.capacity_host_factory_scopes WHERE root_id=$1 AND scope_sha256=$4)`, selector.RootID, selector.Stage, selector.BindingSchema, selector.BindingSHA256, selector.Role, capacity.HostFactoryRawSHA256(bodyRaw), capacity.HostFactoryRawSHA256(envelopeRaw)).Scan(&raw, &phaseRaw) != nil {
		return c, ErrHostFactoryHold
	}
	var err error
	c, err = decodeOriginalHostPostStartLedgerCustody(raw)
	if err != nil || validateOriginalHostPostStartIdentityTx(ctx, tx, selector, body, bodyRaw, envelopeRaw, c) != nil || validateOriginalHostPostStartPhase(c, phaseRaw) != nil {
		return c, ErrHostFactoryHold
	}
	observations, err := resolveOriginalHostHistoricalNativeAggregateTx(ctx, tx, selector.RootID, selector.BindingSchema, selector.BindingSHA256, c.OriginalEffectivePhaseDeadline, &body, capacity.HostFactoryRawSHA256(envelopeRaw))
	if err != nil || validateOriginalHostPostStartCensusCutoffTx(ctx, tx, selector.RootID, c, observations) != nil {
		return c, ErrHostFactoryHold
	}
	if validateOriginalHostPostStartNativeRefsTx(ctx, tx, selector.RootID, c) != nil {
		return c, ErrHostFactoryHold
	}
	return c, nil
}

// Direct Start/frame references retain the original signed pair and actual
// immutable returned link. Missing SQL relation never becomes RAM FIRST.
func validateOriginalHostPostStartNativeRefsTx(ctx context.Context, tx *sql.Tx, root string, c hostOriginalPostStartLedgerCustody) error {
	codec := originalHostSourceCodecTx(ctx, tx, root)
	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
	if err != nil {
		return err
	}
	var journal hostOriginalCurrentFactoryOwnerJournal
	if originalHostPostStartStrict(c.CurrentJournalWire, &journal) != nil {
		return ErrHostFactoryHold
	}
	type selected struct {
		ref     hostOriginalPostStartNativeReference
		segment *hostOriginalPostStartReadSegment
	}
	refs := []selected{{ref: c.OriginalStartReference}}
	for n := range c.OriginalPreparedFrame.OriginalReadSegments {
		s := &c.OriginalPreparedFrame.OriginalReadSegments[n]
		refs = append(refs, selected{hostOriginalPostStartNativeReference{s.OriginalCallID, s.OriginalChunkBodySHA256, s.OriginalChunkEnvelopeSHA256, s.OriginalFactIndex}, s})
	}
	for n, x := range refs {
		raw, env, err := callbacks.resolveIO(x.ref.OriginalChunkBodySHA256)
		var chunk model.HostFactoryCallVectorChunk
		if err != nil || capacity.HostFactoryRawSHA256(env) != x.ref.OriginalChunkEnvelopeSHA256 || codec.Decode(raw, &chunk) != nil || x.ref.OriginalFactIndex >= uint32(len(chunk.OriginalCalls)) || chunk.BindingSchema != c.BindingSchema || chunk.BindingSHA256 != c.ScopeBodySHA256 || chunk.OriginalOwnerID != c.OriginalPublicationReturn.OriginalOwnerID || chunk.OwnerPrimitiveRawSHA256 != journal.CoreBasalOwnerRawSHA256 {
			return ErrHostFactoryHold
		}
		previous, previousEnv, previousIndex, err := callbacks.predecessor(x.ref.OriginalChunkBodySHA256, x.ref.OriginalFactIndex)
		if err != nil || previous == nil && (previousEnv != nil || previousIndex != 0) {
			return ErrHostFactoryHold
		}
		if previous != nil {
			var pending model.HostFactoryCallVectorChunk
			identity, err := originalHostIOIdentity(codec, root, &chunk, raw)
			if err != nil || previousIndex != 0 || len(previousEnv) == 0 || codec.Decode(previous, &pending) != nil || originalHostSourcePendingTx(ctx, tx, identity, pending, chunk, env) != nil {
				return ErrHostFactoryHold
			}
		}
		f := chunk.OriginalCalls[x.ref.OriginalFactIndex]
		if f.OriginalCallID == nil || *f.OriginalCallID != x.ref.OriginalCallID || f.OriginalState != "returned" || f.OriginalCalledAt == nil || f.OriginalReturnedAt == nil || f.SubjectOwnerID != journal.CreatorOwnerID || !f.OriginalReturnedAt.Before(f.OriginalOperationDeadline) || !f.OriginalReturnedAt.Before(c.OriginalEffectivePhaseDeadline) {
			return ErrHostFactoryHold
		}
		if n == 0 {
			event := journal.FactoryOwnerEvents[1]
			if f.Operation != "worker_start" || f.OriginalReturnClass != "success" || f.OriginalNativeReturn == nil || f.OriginalNativeReturn.Kind != "original_cmd_start" || f.OriginalNativeReturn.OriginalErrorPresent == nil || *f.OriginalNativeReturn.OriginalErrorPresent || f.OriginalNativeReturn.OriginalErrno == nil || *f.OriginalNativeReturn.OriginalErrno != 0 || f.OriginalNativeReturn.ReturnedPID == nil || *f.OriginalNativeReturn.ReturnedPID <= 0 || !f.OriginalCalledAt.Equal(event.OriginalCalledAt) || !f.OriginalReturnedAt.Equal(*event.OriginalReturnedAt) {
				return ErrHostFactoryHold
			}
		} else {
			segment := x.segment
			frame := c.OriginalPreparedFrame
			start, end := uint64(segment.OriginalRawOffset), uint64(segment.OriginalRawOffset)+uint64(segment.OriginalRawBytes)
			// Chosen sealed collector waits SAME launchEffectsDone before the
			// lexical call; ordinary/registrar pre-Start LF reads are excluded.
			if f.Operation != "stdout_read" || f.OriginalReturnClass != "success" || f.OriginalCount == nil || *f.OriginalCount != int64(segment.OriginalRawBytes) || f.OriginalSHA256 == nil || f.OriginalHashState != "actual_public_bytes" || f.OriginalEOF == nil || *f.OriginalEOF || f.OriginalCalledAt.Before(frame.OriginalReceiverReturn.OriginalCalledAt) || f.OriginalReturnedAt.After(frame.OriginalReceiverReturn.OriginalReturnedAt) || end > uint64(len(frame.OriginalReadWire)) || *f.OriginalSHA256 != capacity.HostFactoryRawSHA256(frame.OriginalReadWire[start:end]) {
				return ErrHostFactoryHold
			}
		}
	}
	return nil
}

func validateOriginalHostPostStartPhase(c hostOriginalPostStartLedgerCustody, raw []byte) error {
	if len(c.OriginalDirectoryCustody) != 1 {
		return ErrHostFactoryHold
	}
	phase, err := decodeOriginalHostNativePhaseWire(raw)
	var journal hostOriginalCurrentFactoryOwnerJournal
	if err != nil || originalHostPostStartStrict(c.CurrentJournalWire, &journal) != nil || phase.StageSelector != "poststart-empty-realm-read" || phase.FactoryRootID != c.FactoryRootID || phase.SourceApprovalBodySHA256 != c.SourceApprovalBodySHA256 || phase.OriginalPhaseID != c.OriginalPhaseID || phase.BindingSchema != c.BindingSchema || phase.BindingSHA256 != c.ScopeBodySHA256 || phase.AggregateBodySHA256 != c.AggregateBodySHA256 || phase.AggregateEnvelopeSHA256 != c.AggregateEnvelopeSHA256 || phase.ObserverOwnerID != c.OriginalDirectoryCustody[0].OriginalPrefix.OriginalSourceOwnerID || !phase.OriginalEffectiveDeadline.Equal(c.OriginalEffectivePhaseDeadline) || !phase.OriginalCalledAt.Equal(journal.OriginalPhaseCalledAt) || !phase.OriginalContextStartedAt.Equal(journal.OriginalRootContextStartedAt) || !phase.OriginalRootContextDeadline.Equal(journal.OriginalRootContextDeadline) || !phase.OriginalReturnedAt.Before(phase.OriginalEffectiveDeadline) {
		return ErrHostFactoryHold
	}
	// The phase's real preIO origin/request and cached Source identity remain
	// separately authenticated by the live/cold original Source wrapper.
	return nil
}

func validateOriginalHostPostStartCensusCutoffTx(ctx context.Context, tx *sql.Tx, root string, c hostOriginalPostStartLedgerCustody, observations []model.HostFactoryNativeObservationRecord) error {
	if len(observations) == 0 {
		return ErrHostFactoryHold
	}
	audits, err := originalHostPostStartAuditMap(c)
	if err != nil {
		return err
	}
	first := audits[c.OriginalFileCustody[0].OriginalFinalReader.OriginalCallReferences[0]].Fact.OriginalCalledAt
	if first == nil {
		return ErrHostFactoryHold
	}
	for _, observation := range observations {
		vectors, err := originalHostNativePayloadVectors(observation)
		if err != nil || len(vectors) == 0 {
			return ErrHostFactoryHold
		}
		for _, vector := range vectors {
			facts, err := originalHostVectorFactsTx(ctx, tx, root, vector)
			if err != nil || len(facts) == 0 {
				return ErrHostFactoryHold
			}
			for _, fact := range facts {
				if fact.OriginalState != "returned" || fact.OriginalReturnedAt == nil || fact.OriginalReturnedAt.After(*first) || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || !fact.OriginalReturnedAt.Before(c.OriginalEffectivePhaseDeadline) {
					return ErrHostFactoryHold
				}
			}
		}
	}
	return nil
}

// Isolated R5 owning caller integration.

// Private original getter ownership lives inside the registration reservation.
// It is not serialized and cannot be installed by a caller BODY or SQL flag.
type hostOriginalPostStartCaptureReturn struct {
	ctx                  context.Context
	bodySHA, envelopeSHA string
	raw                  []byte
	calledAt, returnedAt time.Time
	originalErr          error
}

func originalHostPostStartCaptureComplete(r *hostOriginalPreparationReturn) bool {
	if r == nil || r.postStart == nil {
		return false
	}
	p := r.postStart
	return p.ctx == r.ctx && p.originalErr == nil && len(p.raw) > 0 && len(p.raw) <= 65536 && capacity.ValidDigest(p.bodySHA) && capacity.ValidDigest(p.envelopeSHA) && !p.calledAt.IsZero() && !p.calledAt.Before(r.calledAt) && !p.returnedAt.IsZero() && !p.returnedAt.Before(p.calledAt) && p.returnedAt.Before(r.deadline) && !r.commitCalledAt.IsZero() && !r.commitCalledAt.Before(p.returnedAt)
}

func (s CapacityStore) captureOriginalHostPostStartOwnedTx(ctx context.Context, tx *sql.Tx, selector HostFactoryRecordSelector, body any, bodyRaw, envelopeRaw []byte) ([]byte, error) {
	if selector.Stage != "poststart-empty-realm-read" {
		return nil, nil
	}
	h := s.hostOriginalClaim
	if h == nil || tx == nil || ctx == nil {
		return nil, ErrHostFactoryHold
	}
	h.mu.Lock()
	r := h.preparationReturn
	if r == nil || r.ctx != ctx || r.db != s.DB || r.realm != h.realm || r.entry != "sealed_a0" && r.entry != "sealed_a1" || r.postStart != nil || r.originalErr != nil || !r.commitCalledAt.IsZero() || !r.methodFinishedAt.IsZero() || selector.RootID != h.rootID || selector.BindingSHA256 != capacity.HostFactoryRawSHA256(r.bindingRaw) || ctx.Err() != nil {
		h.mu.Unlock()
		return nil, ErrHostFactoryHold
	}
	p := &hostOriginalPostStartCaptureReturn{ctx: ctx, bodySHA: capacity.HostFactoryRawSHA256(bodyRaw), envelopeSHA: capacity.HostFactoryRawSHA256(envelopeRaw), calledAt: time.Now().UTC()}
	r.postStart = p // BEFORE getter and its owning SQL validation; never reset
	h.mu.Unlock()
	if !p.calledAt.Before(r.deadline) {
		h.mu.Lock()
		p.originalErr, r.originalErr = ErrHostFactoryHold, ErrHostFactoryHold
		h.mu.Unlock()
		return nil, ErrHostFactoryHold
	}
	// These two samples belong to the caller of the actual capture helper.
	// Panic/no-return leaves returnedAt ZERO in the preowned reservation.
	raw, err := captureOriginalHostPostStartLedgerCustodyTx(ctx, tx, selector, body, bodyRaw, envelopeRaw)
	returnedAt := time.Now().UTC()
	h.mu.Lock()
	defer h.mu.Unlock()
	p.raw, p.returnedAt, p.originalErr = bytes.Clone(raw), returnedAt, err
	if h.preparationReturn != r || r.postStart != p || ctx != r.ctx || ctx.Err() != nil || !returnedAt.Before(r.deadline) || returnedAt.Before(p.calledAt) || len(raw) == 0 || len(raw) > 65536 {
		p.originalErr = errors.Join(p.originalErr, ErrHostFactoryHold)
	}
	r.originalErr = errors.Join(r.originalErr, p.originalErr)
	if p.originalErr != nil {
		return nil, p.originalErr
	}
	return bytes.Clone(p.raw), nil
}

// Exact private SQL bytes are read without adding raw/count/SHA to the public
// snapshot. The live branch additionally compares the genuine copy-only cache.
func compareOriginalHostPostStartStoredTx(ctx context.Context, tx *sql.Tx, selector HostFactoryRecordSelector, body any, bodyRaw, envelopeRaw []byte, live bool) error {
	var stored []byte
	if tx.QueryRowContext(ctx, `SELECT original_poststart_ledger_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage=$2 AND binding_schema=$3 AND binding_sha256=$4 AND signer_role=$5 AND raw_body_sha256=$6 AND raw_envelope_sha256=$7`, selector.RootID, selector.Stage, selector.BindingSchema, selector.BindingSHA256, selector.Role, capacity.HostFactoryRawSHA256(bodyRaw), capacity.HostFactoryRawSHA256(envelopeRaw)).Scan(&stored) != nil {
		return ErrHostFactoryHold
	}
	if selector.Stage != "poststart-empty-realm-read" {
		if stored != nil {
			return ErrHostFactoryHold
		}
		return nil
	}
	value, ok := body.(*model.HostFactoryOriginalEmptyRealmRead)
	if !ok || len(stored) == 0 || len(stored) > 65536 {
		return ErrHostFactoryHold
	}
	if _, err := readOriginalHostPostStartLedgerCustodyTx(ctx, tx, selector, *value, bodyRaw, envelopeRaw); err != nil {
		return err
	}
	if live {
		realm, approval, installed := OriginalHostFactoryRealm()
		if !installed || realm == nil || approval.ScopeRootID != selector.RootID || realm.VerifyLive(ctx) != nil {
			return ErrHostFactoryHold
		}
		original, err := realm.OriginalPostStartLedgerCustody(ctx, capacity.HostFactoryRawSHA256(bodyRaw))
		if err != nil || !bytes.Equal(original, stored) {
			return ErrHostFactoryHold
		}
	}
	return nil
}

// The writing transaction's validation is provisional. This separate readonly
// helper runs only AFTER the lexical registration caller captured its return.
// The outer caller below captures THIS helper's actual GoReturn as well.
func (s CapacityStore) readOriginalHostPostStartCurrent(ctx context.Context) error {
	h := s.hostOriginalFactory
	if h == nil || h.realm.VerifyLive(ctx) != nil {
		return ErrHostFactoryHold
	}
	s.hostOriginalClaim.mu.Lock()
	r := s.hostOriginalClaim.preparationReturn
	stages := make(map[string][]byte, len(r.stages))
	for name, raw := range r.stages {
		stages[name] = bytes.Clone(raw)
	}
	s.hostOriginalClaim.mu.Unlock()
	records, err := prepareOriginalHostRecords(ctx, h.scope.ScopeRootID, capacity.HostFactoryRawSHA256(h.scopeRaw), stages)
	if err != nil {
		return err
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = s.compareOriginalHostRecordsTx(ctx, tx, records); err != nil {
		return err
	}
	var currentRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, h.scope.Namespace, h.policySpec.Environment, h.policySpec.Domain, h.policySpec.Dimension).Scan(&currentRaw); err != nil {
		return err
	}
	var current model.CapacityIntent
	if len(currentRaw) == 0 || len(currentRaw) > 65536 || json.Unmarshal(currentRaw, &current) != nil || current.PolicyID.String() != h.scope.PolicyID || current.PolicyChecksum != h.scope.PolicyChecksum || current.Generation != h.scope.Generation || current.FencingToken != h.scope.Fence || current.LeaseExecutorID != s.ExecutorID || current.LeaseOwner != h.leaseOwner || current.LeaseExpiresAt == nil || !current.LeaseExpiresAt.Equal(h.scope.OriginalLeaseExpiresAt) || current.RecoveryOnly {
		return ErrHostFactoryHold
	}
	policy, err := scanManifest(tx.QueryRowContext(ctx, `SELECT id,api_version,kind,namespace,name,version,active,description,labels,spec,checksum,created_at,updated_at FROM public.manifests WHERE id=$1`, h.policy.ID))
	if err != nil {
		return err
	}
	workflow, err := scanManifest(tx.QueryRowContext(ctx, `SELECT id,api_version,kind,namespace,name,version,active,description,labels,spec,checksum,created_at,updated_at FROM public.manifests WHERE id=$1`, s.WorkflowID))
	if err != nil {
		return err
	}
	_, approval, installed := OriginalHostFactoryRealm()
	if !installed || !policy.Metadata.Active || !workflow.Metadata.Active || policy.Checksum != h.scope.PolicyChecksum || workflow.Checksum != h.scope.WorkflowChecksum || policy.Metadata.Namespace != h.scope.Namespace || workflow.Metadata.Namespace != h.scope.Namespace || capacity.CurrentGuestCoreSource() != h.scope.CoreActualSourceCommit {
		return ErrHostFactoryHold
	}
	workflowSpec, err := manifest.ParseWorkflowSpec(workflow.Spec)
	if err != nil {
		return err
	}
	var assessStep, claimStep, provisionStep model.WorkflowStepSpec
	for _, step := range workflowSpec.Steps {
		switch step.ID {
		case approval.AllowedAssessStepID:
			assessStep = step
		case approval.AllowedClaimStepID:
			claimStep = step
		case approval.AllowedOriginalStepID:
			provisionStep = step
		}
	}
	if h.realm.VerifyOriginalPolicyInput(ctx, policy, workflow, assessStep, claimStep, provisionStep) != nil || h.realm.VerifyLive(ctx) != nil {
		return ErrHostFactoryHold
	}
	return tx.Commit()
}

func (s CapacityStore) guardOriginalHostPostStartCurrent(ctx context.Context) (runErr error) {
	h := s.hostOriginalFactory
	if h == nil || !originalHostPreparationCompleted(s.hostOriginalClaim, h.realm, s.DB, h.scope.FactoryEntryClass, h.scopeRaw, h.prepared.OriginalCreateCommandHandleID) {
		return ErrHostFactoryHold
	}
	deadline, bounded := originalHostIssueContextBound(ctx, h.scope.OriginalContextDeadline)
	s.hostOriginalClaim.mu.Lock()
	r := s.hostOriginalClaim.preparationReturn
	valid := bounded && !deadline.After(r.deadline) && !deadline.After(h.scope.OriginalLeaseExpiresAt) && r.admissionErr == nil
	s.hostOriginalClaim.mu.Unlock()
	if !valid {
		return ErrHostFactoryHold
	}
	// Private immutable minima from the committed same original Issue, never
	// HTTP flags or a new timeout epoch. Native phase declarations stay intact.
	if h.scope.FactoryEntryClass == "sealed_a1" && h.issueCaptured {
		for _, bound := range []time.Time{h.pre.OriginalDeadline, h.grant.ExpiresAt} {
			if bound.IsZero() {
				return ErrHostFactoryHold
			}
			if bound.Before(deadline) {
				deadline = bound
			}
		}
	}
	readCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	defer func() {
		if cause := recover(); cause != nil {
			s.hostOriginalClaim.mu.Lock()
			r.admissionErr = ErrHostFactoryHold
			s.hostOriginalClaim.mu.Unlock()
			panic(cause)
		}
	}()
	calledAt := time.Now().UTC()
	runErr = s.readOriginalHostPostStartCurrent(readCtx)
	returnedAt := time.Now().UTC() // AFTER readonly helper's actual GoReturn
	if ctx.Err() != nil || readCtx.Err() != nil || returnedAt.Before(calledAt) || !returnedAt.Before(deadline) || !returnedAt.Before(r.deadline) || !returnedAt.Before(h.scope.OriginalLeaseExpiresAt) {
		runErr = errors.Join(runErr, ErrHostFactoryHold)
	}
	if runErr != nil {
		s.hostOriginalClaim.mu.Lock()
		r.admissionErr = errors.Join(r.admissionErr, runErr)
		s.hostOriginalClaim.mu.Unlock()
	}
	return runErr
}

// This bounded relation consumes already-authenticated native Realm originals.
// It is NOT the missing actor-helper-return authentication: the final Source9
// carrier pair must close that distinct boundary before whole integration.
// No actor helper GoReturn is inferred from Wait or from a signed report.
func validateOriginalHostPostStartFinalLifetime(c hostOriginalPostStartLedgerCustody, audits map[string]hostOriginalSourceAuditProjection, returns []hostOriginalRealmOwnerReturn, realmJoin hostOriginalMainReturn) error {
	if compareOriginalHostPostStartDirectoryPrefix(c, audits) != nil || realmJoin.Operation != "realm_close_join" || realmJoin.OriginalOwnerID != c.OriginalPublicationReturn.OriginalOwnerID || realmJoin.OriginalReturnedAt == nil || realmJoin.OriginalCalledAt == nil {
		return ErrHostFactoryHold
	}
	p := c.OriginalDirectoryCustody[0]
	closeRow := audits[p.OriginalSourceDirectoryHandleID+":3"]
	count := 0
	for _, r := range returns {
		if r.Operation != "registrar_wait" || r.SubjectOwnerID != p.OriginalPrefix.OriginalSourceOwnerID {
			continue
		}
		count++
		f := r.OriginalFact
		if r.SubjectRole != "host_registrar" || r.OwnerRole != "host_exterior" || r.OriginalOwnerID != c.OriginalPublicationReturn.OriginalOwnerID || r.OriginalFactReference == nil || r.OriginalLocalReturn != nil || f == nil || f.OriginalReturnedAt == nil || f.SubjectOwnerID != p.OriginalPrefix.OriginalSourceOwnerID || f.Operation != "registrar_wait" || f.OriginalState != "returned" || f.OriginalReturnClass != "success" || f.OriginalNativeReturn == nil || f.OriginalNativeReturn.OriginalErrorPresent == nil || *f.OriginalNativeReturn.OriginalErrorPresent || closeRow.Fact.OriginalReturnedAt.After(*f.OriginalReturnedAt) || realmJoin.OriginalReturnedAt.Before(*f.OriginalReturnedAt) {
			return ErrHostFactoryHold
		}
	}
	if count != 1 {
		return ErrHostFactoryHold
	}
	return nil
}

func verifyOriginalHostPostStartFinalCustodyTx(ctx context.Context, tx *sql.Tx, snapshot hostOriginalSQLSnapshot, bundle hostOriginalRealmCorpus, audits map[string]hostOriginalSourceAuditProjection, main map[string]hostOriginalMainReturn) error {
	encoded, exists := bundle.Stages["poststart-empty-realm-read"]
	if snapshot.EntryClass == "ordinary_original_create" {
		if exists {
			return ErrHostFactoryHold
		}
		return nil
	}
	if !exists || snapshot.EntryClass != "sealed_a0" && snapshot.EntryClass != "sealed_a1" {
		return ErrHostFactoryHold
	}
	envelope, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(envelope) != encoded || len(envelope) == 0 || len(envelope) > 65536 || capacityhostfactory.VerifyOriginalHistoricalStage(ctx, "poststart-empty-realm-read", envelope) != nil {
		return ErrHostFactoryHold
	}
	codec := originalHostSourceCodecTx(ctx, tx, snapshot.RootID)
	raw, value, err := decodeOriginalHistoricalHostStage(codec, "poststart-empty-realm-read", envelope)
	body, ok := value.(*model.HostFactoryOriginalEmptyRealmRead)
	if err != nil || !ok {
		return ErrHostFactoryHold
	}
	selector := HostFactoryRecordSelector{RootID: snapshot.RootID, Family: "scope", Stage: "poststart-empty-realm-read", Role: "host_registrar", BindingSchema: "original_host_factory_pre_authority_scope_v4", BindingSHA256: body.PreAuthorityScopeSHA256, ScopeSHA256: body.PreAuthorityScopeSHA256}
	c, err := readOriginalHostPostStartLedgerCustodyTx(ctx, tx, selector, *body, raw, envelope)
	if err != nil {
		return err
	}
	return validateOriginalHostPostStartFinalLifetime(c, audits, bundle.OriginalRealmOwnerReturns, main["realm_close_join"])
}

// The lexical registration caller samples AFTER the SQL helper returns and
// BEFORE invoking this method. This retention method has NO clock/IO/signing;
// mutex scheduling can delay storage, never replace the captured GoReturn.
func (s CapacityStore) retainOriginalHostPreparationHelperReturn(original *hostOriginalPreparationReturn, returnedAt time.Time, helperErr error, handle string, preparedRaw, registrationRaw []byte) {
	h := s.hostOriginalClaim
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.preparationReturn != original || original.claim != h || original.db != s.DB || !original.transactionReturnedAt.IsZero() || returnedAt.IsZero() {
		original.originalErr = errors.Join(original.originalErr, helperErr, ErrHostFactoryHold)
		return
	}
	original.transactionReturnedAt = returnedAt
	original.originalErr = errors.Join(original.originalErr, helperErr)
	original.handle, original.preparedRaw, original.registrationRaw = handle, bytes.Clone(preparedRaw), bytes.Clone(registrationRaw)
}

// Isolated final Source audit column/caller integration.
// Private final Source audit custody. Source9 carrier R3 and held-anchor typed pair R4.
// These parsers/relations retain original bytes; they cannot authenticate a
// Source capability, key, native absence, SQL FIRST or effect permission.

type hostOriginalFinalSourceAuditCustody struct {
	Schema                       string                               `json:"schema"`
	FactoryRootID                string                               `json:"factory_root_id"`
	LogicalScopeRootID           string                               `json:"logical_scope_root_id"`
	SourceApprovalBodySHA256     string                               `json:"source_approval_body_sha256"`
	RootPreparationBodySHA256    string                               `json:"root_preparation_body_sha256"`
	OriginalParentHeldRootAnchor hostOriginalPostStartNativeAnchor    `json:"original_parent_held_root_anchor"`
	OriginalActors               []hostOriginalFinalSourceAuditActor  `json:"original_actors"`
	OriginalParentSourceStreams  []hostOriginalFinalSourceAuditStream `json:"original_parent_source_streams"`
	OriginalAllSourceFacts       uint32                               `json:"original_all_source_facts"`
}

type hostOriginalFinalSourceAuditActor struct {
	Schema                      string                                     `json:"schema"`
	OriginalOwnerRole           string                                     `json:"original_owner_role"`
	OriginalOwnerID             string                                     `json:"original_owner_id"`
	OriginalBasalSHA256         string                                     `json:"original_basal_sha256"`
	OriginalCarrierBodyWire     []byte                                     `json:"original_carrier_body_wire"`
	OriginalCarrierEnvelopeWire []byte                                     `json:"original_carrier_envelope_wire"`
	OriginalTransport           hostOriginalFinalSourceAuditTransport      `json:"original_transport"`
	OriginalReceiverReturn      hostOriginalPostStartSourceReturn          `json:"original_receiver_return"`
	OriginalArtifacts           []hostOriginalFinalSourceAuditArtifactRead `json:"original_artifacts"`
}

type hostOriginalFinalSourceAuditTransport struct {
	Schema                 string                               `json:"schema"`
	OriginalStreamHandleID string                               `json:"original_stream_handle_id"`
	OriginalStdoutWire     []byte                               `json:"original_stdout_wire"`
	OriginalFrameOffset    uint32                               `json:"original_frame_offset"`
	OriginalFrameBytes     uint32                               `json:"original_frame_bytes"`
	OriginalReadSegments   []hostOriginalPostStartReadSegment   `json:"original_read_segments"`
	OriginalEOFReference   hostOriginalPostStartNativeReference `json:"original_eof_reference"`
	OriginalCloseReference hostOriginalPostStartNativeReference `json:"original_close_reference"`
}

type hostOriginalFinalSourceAuditArtifactRead struct {
	Schema                    string                                        `json:"schema"`
	OriginalReference         hostOriginalFinalSourceAuditArtifactReference `json:"original_reference"`
	OriginalBodyWire          []byte                                        `json:"original_body_wire"`
	OriginalReaderSelection   hostOriginalPostStartSourceSelection          `json:"original_reader_selection"`
	OriginalReaderProjections []hostOriginalSourceAuditProjection           `json:"original_reader_projections"`
}

type hostOriginalFinalSourceAuditStream struct {
	OriginalAcquisitionOrdinal     uint32                              `json:"original_acquisition_ordinal"`
	OriginalSourceOwnerID          string                              `json:"original_source_owner_id"`
	OriginalSourceOwnerRole        string                              `json:"original_source_owner_role"`
	OriginalSourceBindingSchema    string                              `json:"original_source_binding_schema"`
	OriginalSourceBindingSHA256    string                              `json:"original_source_binding_sha256"`
	OriginalHandleID               string                              `json:"original_handle_id"`
	OriginalSourceAuditProjections []hostOriginalSourceAuditProjection `json:"original_source_audit_projections"`
}

type hostOriginalFinalSourceAuditArtifactReference struct {
	Basename                string `json:"basename"`
	OriginalBytes           uint32 `json:"original_bytes"`
	OriginalSHA256          string `json:"original_sha256"`
	FirstAcquisitionOrdinal uint32 `json:"first_acquisition_ordinal"`
	LastAcquisitionOrdinal  uint32 `json:"last_acquisition_ordinal"`
	OriginalStreamCount     uint32 `json:"original_stream_count"`
}

type hostOriginalFinalSourceAuditArtifact struct {
	Schema                  string                               `json:"schema"`
	FactoryRootID           string                               `json:"factory_root_id"`
	OriginalOwnerID         string                               `json:"original_owner_id"`
	OriginalOwnerRole       string                               `json:"original_owner_role"`
	OriginalBasalSHA256     string                               `json:"original_basal_sha256"`
	SnapshotID              string                               `json:"snapshot_id"`
	FirstAcquisitionOrdinal uint32                               `json:"first_acquisition_ordinal"`
	LastAcquisitionOrdinal  uint32                               `json:"last_acquisition_ordinal"`
	OriginalStreamCount     uint32                               `json:"original_stream_count"`
	OriginalStreams         []hostOriginalFinalSourceAuditStream `json:"original_streams"`
}

type hostOriginalFinalSourceAuditCarrier struct {
	Schema                     string                                          `json:"schema"`
	FactoryRootID              string                                          `json:"factory_root_id"`
	SourceApprovalSHA256       string                                          `json:"source_approval_sha256"`
	RootPreparationSHA256      string                                          `json:"root_preparation_sha256"`
	OriginalOwnerID            string                                          `json:"original_owner_id"`
	OriginalOwnerRole          string                                          `json:"original_owner_role"`
	OriginalBasalSHA256        string                                          `json:"original_basal_sha256"`
	BindingSchema              string                                          `json:"binding_schema"`
	BindingSHA256              string                                          `json:"binding_sha256"`
	SnapshotID                 string                                          `json:"snapshot_id"`
	OriginalStreamCount        uint32                                          `json:"original_stream_count"`
	OriginalArtifactReferences []hostOriginalFinalSourceAuditArtifactReference `json:"original_artifact_references"`
	OriginalRemainingStreams   []hostOriginalFinalSourceAuditStream            `json:"original_remaining_streams"`
	OriginalHelperReturn       hostOriginalPostStartSourceReturn               `json:"original_helper_return"`
}

type hostOriginalFinalSourceAuditEnvelope struct {
	Schema          string `json:"schema"`
	KeyID           string `json:"key_id"`
	Role            string `json:"role"`
	ReportDomain    string `json:"report_domain"`
	BodyBase64      string `json:"body_base64"`
	SignatureBase64 string `json:"signature_base64"`
}

func originalHostFinalAuditStrict(raw []byte, value any, limit int) error {
	if hostOriginalStrictJSON(raw, value, limit) != nil || originalHostSourceCustodyRequiredFields(raw, reflect.TypeOf(value).Elem(), 0) != nil {
		return ErrHostFactoryHold
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrHostFactoryHold
	}
	return nil
}

// The structural complete census is independently compared with the Source9
// authenticator's result below. Neither a safe projection nor a hash installs
// that authenticator's compiled approval/original owner/key authority.
func originalHostFinalAuditStream(stream hostOriginalFinalSourceAuditStream, nativeRoot string, all map[string]hostOriginalSourceAuditProjection, handles map[string]bool) error {
	if stream.OriginalAcquisitionOrdinal == 0 || !validCapacityExecutor(stream.OriginalSourceOwnerID) || !validCapacityExecutor(stream.OriginalHandleID) || !capacity.ValidDigest(stream.OriginalSourceBindingSHA256) || stream.OriginalSourceAuditProjections == nil || len(stream.OriginalSourceAuditProjections) == 0 || len(stream.OriginalSourceAuditProjections) > 4096 || handles[stream.OriginalHandleID] {
		return ErrHostFactoryHold
	}
	switch stream.OriginalSourceOwnerRole {
	case "host_exterior", "host_worker", "host_registrar":
	default:
		return ErrHostFactoryHold
	}
	switch stream.OriginalSourceBindingSchema {
	case "original_host_factory_source_approval_v4", "original_host_factory_root_preparation_v4", "original_host_factory_pre_authority_scope_v4":
	default:
		return ErrHostFactoryHold
	}
	handles[stream.OriginalHandleID] = true
	var previous time.Time
	for n, row := range stream.OriginalSourceAuditProjections {
		f := row.Fact
		id := stream.OriginalHandleID + ":" + strconv.Itoa(n+1)
		if row.Family != "source_audit" || row.SubjectIdentity.SubjectKind != "source_file" || row.SubjectIdentity.RequestIdentity != nil || row.SubjectIdentity.PublicRunID != nil || row.SubjectIdentity.Method != nil || row.SubjectIdentity.PathFamily != nil || capacity.ValidateHostFactory(f) != nil || f.FactoryRootID != nativeRoot || f.OriginalAuditHandleID != stream.OriginalHandleID || f.OriginalCallID == nil || *f.OriginalCallID != id || f.OriginalState != "returned" || f.OriginalCalledAt == nil || f.OriginalReturnedAt == nil || f.OriginalErrorPresent == nil || f.OriginalCalledAt.Before(previous) || f.OriginalReturnedAt.Before(*f.OriginalCalledAt) || !f.OriginalReturnedAt.Before(f.OriginalOperationDeadline) || f.OriginalStatusCode != nil || f.OriginalSHA256 != nil || f.RetainedPrefixSHA256 != nil || f.RetainedPrefixBytes != nil || f.OriginalReadScope != nil {
			return ErrHostFactoryHold
		}
		if _, exists := all[id]; exists || len(all) >= 4096 {
			return ErrHostFactoryHold
		}
		if !reflect.DeepEqual(row.SubjectIdentity, stream.OriginalSourceAuditProjections[0].SubjectIdentity) || !reflect.DeepEqual(row.OriginalCloseReference, stream.OriginalSourceAuditProjections[0].OriginalCloseReference) {
			return ErrHostFactoryHold
		}
		switch f.Operation {
		case "source_file_read":
			if f.OriginalCount == nil || *f.OriginalCount < 0 || *f.OriginalCount > 65537 || f.OriginalEOF == nil || f.OriginalHashState != "private_withheld" {
				return ErrHostFactoryHold
			}
		case "source_file_write":
			if f.OriginalCount == nil || *f.OriginalCount < 0 || *f.OriginalCount > 65537 || f.OriginalEOF != nil || f.OriginalHashState != "private_withheld" {
				return ErrHostFactoryHold
			}
		default:
			if f.OriginalCount != nil || f.OriginalEOF != nil || f.OriginalHashState != "not_byte_operation" {
				return ErrHostFactoryHold
			}
		}
		previous = *f.OriginalReturnedAt
		all[id] = row
	}
	closeRef := stream.OriginalSourceAuditProjections[0].OriginalCloseReference
	if closeRef != nil {
		last := stream.OriginalSourceAuditProjections[len(stream.OriginalSourceAuditProjections)-1]
		if *closeRef != originalHostPostStartPointerString(last.Fact.OriginalCallID) || last.Fact.Operation != "source_file_close" && last.Fact.Operation != "source_directory_close" {
			return ErrHostFactoryHold
		}
	}
	return nil
}

func originalHostFinalAuditSourceReturn(v hostOriginalPostStartSourceReturn, operation, owner, role string) error {
	if v.Operation != operation || v.OriginalOwnerID != owner || v.OriginalOwnerRole != role || !validCapacityExecutor(owner) || v.OriginalState != "returned" || !originalHostPostStartUTC(v.OriginalCalledAt) || !originalHostPostStartUTC(v.OriginalReturnedAt) || !originalHostPostStartUTC(v.OriginalContextDeadline) || v.OriginalReturnedAt.Before(v.OriginalCalledAt) || !v.OriginalReturnedAt.Before(v.OriginalContextDeadline) {
		return ErrHostFactoryHold
	}
	return nil
}

func parseOriginalHostFinalSourceAuditCustody(raw []byte) (hostOriginalFinalSourceAuditCustody, map[string]hostOriginalSourceAuditProjection, error) {
	var out hostOriginalFinalSourceAuditCustody
	all := map[string]hostOriginalSourceAuditProjection{}
	if originalHostFinalAuditStrict(raw, &out, 1048576) != nil || out.Schema != "source_private_original_final_source_audit_custody_v2" || !validCapacityExecutor(out.FactoryRootID) || !validCapacityExecutor(out.LogicalScopeRootID) || !capacity.ValidDigest(out.SourceApprovalBodySHA256) || !capacity.ValidDigest(out.RootPreparationBodySHA256) || originalHostParentHeldAnchorRef(out.OriginalParentHeldRootAnchor) != nil || len(out.OriginalActors) != 2 || out.OriginalParentSourceStreams == nil || out.OriginalAllSourceFacts == 0 || out.OriginalAllSourceFacts > 4096 {
		return out, nil, ErrHostFactoryHold
	}
	handles := map[string]bool{}
	for n, actor := range out.OriginalActors {
		role := []string{"host_worker", "host_registrar"}[n]
		receiverOperation := []string{"read_original_parent_worker_frame", "collect_original_parent_registrar_source_audit_frame"}[n]
		helperOperation := []string{"receive_original_sealed_worker", "serve_original_registrar"}[n]
		if actor.Schema != "source_private_original_final_source_audit_actor_custody_v1" || actor.OriginalOwnerRole != role || !validCapacityExecutor(actor.OriginalOwnerID) || !capacity.ValidDigest(actor.OriginalBasalSHA256) || actor.OriginalArtifacts == nil || n > 0 && actor.OriginalOwnerID == out.OriginalActors[0].OriginalOwnerID {
			return out, nil, ErrHostFactoryHold
		}
		var carrier hostOriginalFinalSourceAuditCarrier
		var envelope hostOriginalFinalSourceAuditEnvelope
		if originalHostFinalAuditStrict(actor.OriginalCarrierBodyWire, &carrier, 65536) != nil || originalHostFinalAuditStrict(actor.OriginalCarrierEnvelopeWire, &envelope, 65536) != nil || carrier.Schema != "source_private_original_final_source_audit_carrier_v1" || carrier.FactoryRootID != out.FactoryRootID || carrier.SourceApprovalSHA256 != out.SourceApprovalBodySHA256 || carrier.RootPreparationSHA256 != out.RootPreparationBodySHA256 || carrier.OriginalOwnerID != actor.OriginalOwnerID || carrier.OriginalOwnerRole != role || carrier.OriginalBasalSHA256 != actor.OriginalBasalSHA256 || !validCapacityExecutor(carrier.SnapshotID) || !capacity.ValidDigest(carrier.BindingSHA256) || carrier.OriginalArtifactReferences == nil || carrier.OriginalRemainingStreams == nil || carrier.OriginalStreamCount == 0 || carrier.OriginalStreamCount > 4096 || envelope.Schema != "source_private_original_final_source_audit_envelope_v1" || envelope.ReportDomain != "source_private_original_final_source_audit_carrier_domain_v1" || envelope.Role != role || envelope.KeyID == "" || envelope.SignatureBase64 == "" {
			return out, nil, ErrHostFactoryHold
		}
		body, err := base64.StdEncoding.Strict().DecodeString(envelope.BodyBase64)
		signature, signatureErr := base64.StdEncoding.Strict().DecodeString(envelope.SignatureBase64)
		if err != nil || signatureErr != nil || len(signature) != 64 || base64.StdEncoding.EncodeToString(body) != envelope.BodyBase64 || base64.StdEncoding.EncodeToString(signature) != envelope.SignatureBase64 || !bytes.Equal(body, actor.OriginalCarrierBodyWire) {
			return out, nil, ErrHostFactoryHold
		}
		if n == 0 && carrier.BindingSchema != "original_host_factory_pre_authority_scope_v4" || n == 1 && (carrier.BindingSchema != "original_host_factory_root_preparation_v4" || carrier.BindingSHA256 != out.RootPreparationBodySHA256) || originalHostFinalAuditSourceReturn(carrier.OriginalHelperReturn, helperOperation, actor.OriginalOwnerID, role) != nil {
			return out, nil, ErrHostFactoryHold
		}
		receiver := actor.OriginalReceiverReturn
		if originalHostFinalAuditSourceReturn(receiver, receiverOperation, receiver.OriginalOwnerID, "host_exterior") != nil {
			return out, nil, ErrHostFactoryHold
		}
		transport := actor.OriginalTransport
		if transport.Schema != "source_private_original_final_source_audit_transport_custody_v1" || !validCapacityExecutor(transport.OriginalStreamHandleID) || len(transport.OriginalStdoutWire) == 0 || len(transport.OriginalStdoutWire) > 65536 || len(transport.OriginalReadSegments) == 0 || len(transport.OriginalReadSegments) > 4096 || transport.OriginalFrameBytes == 0 || uint64(transport.OriginalFrameOffset)+uint64(transport.OriginalFrameBytes) > uint64(len(transport.OriginalStdoutWire)) {
			return out, nil, ErrHostFactoryHold
		}
		consumed := uint64(0)
		selectedCalls := map[string]bool{}
		for _, segment := range transport.OriginalReadSegments {
			if uint64(segment.OriginalRawOffset) != consumed || segment.OriginalRawBytes == 0 || !originalHostSourceCustodyCallID(segment.OriginalCallID, transport.OriginalStreamHandleID) || !capacity.ValidDigest(segment.OriginalChunkBodySHA256) || !capacity.ValidDigest(segment.OriginalChunkEnvelopeSHA256) || segment.OriginalFactIndex > 15 || selectedCalls[segment.OriginalCallID] {
				return out, nil, ErrHostFactoryHold
			}
			consumed += uint64(segment.OriginalRawBytes)
			if consumed > uint64(len(transport.OriginalStdoutWire)) {
				return out, nil, ErrHostFactoryHold
			}
			selectedCalls[segment.OriginalCallID] = true
		}
		if consumed != uint64(len(transport.OriginalStdoutWire)) {
			return out, nil, ErrHostFactoryHold
		}
		for _, ref := range []hostOriginalPostStartNativeReference{transport.OriginalEOFReference, transport.OriginalCloseReference} {
			if !originalHostSourceCustodyCallID(ref.OriginalCallID, transport.OriginalStreamHandleID) || !capacity.ValidDigest(ref.OriginalChunkBodySHA256) || !capacity.ValidDigest(ref.OriginalChunkEnvelopeSHA256) || ref.OriginalFactIndex > 15 || selectedCalls[ref.OriginalCallID] {
				return out, nil, ErrHostFactoryHold
			}
			selectedCalls[ref.OriginalCallID] = true
		}
		var frame struct {
			Schema      string `json:"schema"`
			Selector    string `json:"selector"`
			EnvelopeRaw []byte `json:"envelope_raw"`
		}
		start, end := uint64(transport.OriginalFrameOffset), uint64(transport.OriginalFrameOffset)+uint64(transport.OriginalFrameBytes)
		if originalHostFinalAuditStrict(transport.OriginalStdoutWire[start:end], &frame, 65536) != nil || frame.Schema != "source_private_original_final_source_audit_signed_frame_v1" || frame.Selector != []string{"final-source-audit-worker", "final-source-audit-registrar"}[n] || !bytes.Equal(frame.EnvelopeRaw, actor.OriginalCarrierEnvelopeWire) {
			return out, nil, ErrHostFactoryHold
		}
		ordinals := map[uint32]bool{}
		actorStreams := uint32(0)
		add := func(stream hostOriginalFinalSourceAuditStream) error {
			if stream.OriginalAcquisitionOrdinal > carrier.OriginalStreamCount || ordinals[stream.OriginalAcquisitionOrdinal] || stream.OriginalSourceOwnerID != actor.OriginalOwnerID || stream.OriginalSourceOwnerRole != role || originalHostFinalAuditStream(stream, out.FactoryRootID, all, handles) != nil {
				return ErrHostFactoryHold
			}
			ordinals[stream.OriginalAcquisitionOrdinal] = true
			actorStreams++
			for _, row := range stream.OriginalSourceAuditProjections {
				if row.Fact.OriginalReturnedAt.After(carrier.OriginalHelperReturn.OriginalReturnedAt) {
					return ErrHostFactoryHold
				}
			}
			return nil
		}
		if len(actor.OriginalArtifacts) != len(carrier.OriginalArtifactReferences) {
			return out, nil, ErrHostFactoryHold
		}
		var previousRange uint32
		for j, artifactRead := range actor.OriginalArtifacts {
			ref := artifactRead.OriginalReference
			var artifact hostOriginalFinalSourceAuditArtifact
			if artifactRead.Schema != "source_private_original_final_source_audit_artifact_read_custody_v1" || !reflect.DeepEqual(ref, carrier.OriginalArtifactReferences[j]) || ref.OriginalBytes == 0 || ref.OriginalBytes > 65536 || uint32(len(artifactRead.OriginalBodyWire)) != ref.OriginalBytes || capacity.HostFactoryRawSHA256(artifactRead.OriginalBodyWire) != ref.OriginalSHA256 || ref.FirstAcquisitionOrdinal == 0 || ref.LastAcquisitionOrdinal < ref.FirstAcquisitionOrdinal || ref.FirstAcquisitionOrdinal <= previousRange || ref.OriginalStreamCount == 0 || ref.OriginalStreamCount > 4096 || ref.Basename != carrier.SnapshotID+"-source-audit-"+strconv.FormatUint(uint64(ref.FirstAcquisitionOrdinal), 10)+"-"+strconv.FormatUint(uint64(ref.LastAcquisitionOrdinal), 10)+".json" || originalHostFinalAuditStrict(artifactRead.OriginalBodyWire, &artifact, 65536) != nil || artifact.Schema != "source_private_original_final_source_audit_artifact_v1" || artifact.FactoryRootID != out.FactoryRootID || artifact.OriginalOwnerID != actor.OriginalOwnerID || artifact.OriginalOwnerRole != role || artifact.OriginalBasalSHA256 != actor.OriginalBasalSHA256 || artifact.SnapshotID != carrier.SnapshotID || artifact.FirstAcquisitionOrdinal != ref.FirstAcquisitionOrdinal || artifact.LastAcquisitionOrdinal != ref.LastAcquisitionOrdinal || artifact.OriginalStreamCount != ref.OriginalStreamCount || uint32(len(artifact.OriginalStreams)) != ref.OriginalStreamCount {
				return out, nil, ErrHostFactoryHold
			}
			previousRange = ref.LastAcquisitionOrdinal
			var priorStream uint32
			for k, stream := range artifact.OriginalStreams {
				if stream.OriginalAcquisitionOrdinal <= priorStream || k == 0 && stream.OriginalAcquisitionOrdinal != ref.FirstAcquisitionOrdinal || k == len(artifact.OriginalStreams)-1 && stream.OriginalAcquisitionOrdinal != ref.LastAcquisitionOrdinal || add(stream) != nil {
					return out, nil, ErrHostFactoryHold
				}
				priorStream = stream.OriginalAcquisitionOrdinal
			}
			selection := artifactRead.OriginalReaderSelection
			projections := artifactRead.OriginalReaderProjections
			if selection.OriginalSourceOwnerRole != "host_exterior" || !validCapacityExecutor(selection.OriginalSourceOwnerID) || selection.OriginalStreamState != "closed_file" || selection.OriginalAnchorHandleID == nil || selection.OriginalCloseCallID == nil || len(selection.OriginalCallReferences) != len(projections) {
				return out, nil, ErrHostFactoryHold
			}
			fileSelection := hostOriginalGetdentsSourceFileSelection{selection.OriginalHandleID, *selection.OriginalCloseCallID, selection.OriginalCallReferences, projections}
			if originalHostGetdentsSourceSelection(fileSelection, out.FactoryRootID, false, len(artifactRead.OriginalBodyWire)) != nil {
				return out, nil, ErrHostFactoryHold
			}
			// The exact parent reader stream must also appear, unchanged, in the
			// parent's complete census; it is not an extra copy counted here.
		}
		var previousRemaining uint32
		for _, stream := range carrier.OriginalRemainingStreams {
			if stream.OriginalAcquisitionOrdinal <= previousRemaining || add(stream) != nil {
				return out, nil, ErrHostFactoryHold
			}
			previousRemaining = stream.OriginalAcquisitionOrdinal
		}
		if actorStreams != carrier.OriginalStreamCount {
			return out, nil, ErrHostFactoryHold
		}
		for ordinal := uint32(1); ordinal <= carrier.OriginalStreamCount; ordinal++ {
			if !ordinals[ordinal] {
				return out, nil, ErrHostFactoryHold
			}
		}
	}
	for n, stream := range out.OriginalParentSourceStreams {
		if stream.OriginalAcquisitionOrdinal != uint32(n+1) || stream.OriginalSourceOwnerRole != "host_exterior" || originalHostFinalAuditStream(stream, out.FactoryRootID, all, handles) != nil {
			return out, nil, ErrHostFactoryHold
		}
	}
	if uint32(len(all)) != out.OriginalAllSourceFacts {
		return out, nil, ErrHostFactoryHold
	}
	for _, actor := range out.OriginalActors {
		for _, artifact := range actor.OriginalArtifacts {
			for _, row := range artifact.OriginalReaderProjections {
				actual, ok := all[originalHostPostStartPointerString(row.Fact.OriginalCallID)]
				a, ae := json.Marshal(row)
				b, be := json.Marshal(actual)
				if !ok || ae != nil || be != nil || !reflect.DeepEqual(row, actual) || !bytes.Equal(a, b) {
					return out, nil, ErrHostFactoryHold
				}
			}
		}
	}
	return out, all, nil
}

func compareOriginalHostFinalAuditMap(expected, actual map[string]hostOriginalSourceAuditProjection) error {
	sourceCount := 0
	for id, row := range actual {
		if row.SubjectIdentity.SubjectKind != "source_file" {
			continue
		}
		sourceCount++
		original, exists := expected[id]
		a, ae := json.Marshal(row)
		b, be := json.Marshal(original)
		if !exists || ae != nil || be != nil || !reflect.DeepEqual(row, original) || !bytes.Equal(a, b) {
			return ErrHostFactoryHold
		}
	}
	if sourceCount != len(expected) {
		return ErrHostFactoryHold
	}
	return nil
}

// Main owns seven independently acquired private TLS/credential read streams:
// three return before the protected caller begins, four within that actual
// caller. Its cleanup return copies the exact registered CallIDs; it does not
// authenticate Realm custody or select unknown rows by their absence there.
// Every other source_file row must still equal the complete authenticated
// Realm map, byte for byte. Neither partition supplies Native permission.
func compareOriginalHostFinalSourceAuditPartition(expected, actual map[string]hostOriginalSourceAuditProjection, main map[string]hostOriginalMainReturn) error {
	cleanup, caller := main["main_cleanup_return"], main["public_caller_return"]
	if len(expected) == 0 || cleanup.Operation != "main_cleanup_return" || caller.Operation != "public_caller_return" || cleanup.OriginalCalledAt == nil || caller.OriginalCalledAt == nil || caller.OriginalReturnedAt == nil || caller.OriginalReturnedAt.Before(*caller.OriginalCalledAt) || cleanup.OriginalCalledAt.Before(*caller.OriginalReturnedAt) || len(cleanup.SourceAuditCallReferences) < 28 {
		return ErrHostFactoryHold
	}
	selected, handles := map[string]bool{}, map[string]bool{}
	for _, id := range cleanup.SourceAuditCallReferences {
		row, exists := actual[id]
		_, realmOwned := expected[id]
		if !exists || realmOwned || selected[id] || row.SubjectIdentity.SubjectKind != "source_file" || row.Fact.OriginalCallID == nil || *row.Fact.OriginalCallID != id {
			return ErrHostFactoryHold
		}
		selected[id], handles[row.Fact.OriginalAuditHandleID] = true, true
	}
	if len(handles) != 7 {
		return ErrHostFactoryHold
	}
	groups := map[string][]hostOriginalSourceAuditProjection{}
	realm := map[string]hostOriginalSourceAuditProjection{}
	for id, row := range actual {
		if handles[row.Fact.OriginalAuditHandleID] {
			if !selected[id] || row.SubjectIdentity.SubjectKind != "source_file" {
				return ErrHostFactoryHold
			}
			groups[row.Fact.OriginalAuditHandleID] = append(groups[row.Fact.OriginalAuditHandleID], row)
		} else {
			realm[id] = row
		}
	}
	beforeCaller, withinCaller := 0, 0
	for handle, rows := range groups {
		if len(rows) < 4 {
			return ErrHostFactoryHold
		}
		ordered := make([]hostOriginalSourceAuditProjection, len(rows))
		for _, row := range rows {
			fact := row.Fact
			if capacity.ValidateHostFactory(fact) != nil || fact.OriginalCallID == nil || fact.OriginalCalledAt == nil || fact.OriginalReturnedAt == nil || fact.OriginalErrorPresent == nil || fact.OriginalState != "returned" || fact.OriginalReturnedAt.Before(*fact.OriginalCalledAt) || !fact.OriginalReturnedAt.Before(fact.OriginalOperationDeadline) || fact.OriginalReturnedAt.After(*cleanup.OriginalCalledAt) || !fact.OriginalOperationDeadline.Equal(caller.OriginalOperationDeadline) || fact.OriginalStatusCode != nil || row.SubjectIdentity.RequestIdentity != nil || row.SubjectIdentity.PublicRunID != nil || row.SubjectIdentity.Method != nil || row.SubjectIdentity.PathFamily != nil {
				return ErrHostFactoryHold
			}
			ordinal, err := strconv.ParseUint(strings.TrimPrefix(*fact.OriginalCallID, handle+":"), 10, 64)
			if err != nil || ordinal == 0 || ordinal > uint64(len(rows)) || *fact.OriginalCallID != handle+":"+strconv.FormatUint(ordinal, 10) || ordered[ordinal-1].Fact.OriginalCallID != nil {
				return ErrHostFactoryHold
			}
			ordered[ordinal-1] = row
		}
		closeID := handle + ":" + strconv.Itoa(len(ordered))
		eof, total := false, int64(0)
		var previous time.Time
		for n, row := range ordered {
			fact := row.Fact
			if fact.OriginalCalledAt.Before(previous) || row.OriginalCloseReference == nil || *row.OriginalCloseReference != closeID {
				return ErrHostFactoryHold
			}
			previous = *fact.OriginalReturnedAt
			switch {
			case n == 0, n == 1, n == len(ordered)-1:
				operation := "source_file_close"
				if n == 0 {
					operation = "source_file_open"
				} else if n == 1 {
					operation = "source_file_fstat"
				}
				if fact.Operation != operation || *fact.OriginalErrorPresent || fact.OriginalHashState != "not_byte_operation" || n == len(ordered)-1 && (!eof || total == 0 || total > 65536) {
					return ErrHostFactoryHold
				}
			default:
				if fact.Operation != "source_file_read" || eof || fact.OriginalCount == nil || fact.OriginalEOF == nil || *fact.OriginalErrorPresent != *fact.OriginalEOF || !*fact.OriginalEOF && *fact.OriginalCount == 0 || fact.OriginalHashState != "private_withheld" || fact.OriginalSHA256 != nil || fact.OriginalReadScope != nil || fact.RetainedPrefixBytes != nil || fact.RetainedPrefixSHA256 != nil {
					return ErrHostFactoryHold
				}
				total += *fact.OriginalCount
				eof = *fact.OriginalEOF
			}
		}
		first, last := ordered[0].Fact, ordered[len(ordered)-1].Fact
		if !last.OriginalReturnedAt.After(*caller.OriginalCalledAt) {
			beforeCaller++
		} else if !first.OriginalCalledAt.Before(*caller.OriginalCalledAt) && !last.OriginalReturnedAt.After(*caller.OriginalReturnedAt) {
			withinCaller++
		} else {
			return ErrHostFactoryHold
		}
	}
	if beforeCaller != 3 || withinCaller != 4 {
		return ErrHostFactoryHold
	}
	return compareOriginalHostFinalAuditMap(expected, realm)
}

func originalHostFinalRootCloseIdentity(prep model.HostFactoryRootPreparation, ref hostOriginalPostStartNativeAnchor, core model.HostFactoryBasalOwnerObservation, chunk model.HostFactoryCallVectorChunk, index uint32) bool {
	if index >= uint32(len(chunk.OriginalCalls)) {
		return false
	}
	f := chunk.OriginalCalls[index]
	native := f.OriginalNativeReturn
	_, closeOrdinal, closeIDValid := originalHostPostStartCallID(originalHostPostStartPointerString(f.OriginalCallID))
	return closeIDValid && closeOrdinal > 4 && originalHostParentHeldInventoryMember(prep, ref) == nil && chunk.OriginalHandleID == ref.OriginalHandleID && chunk.OriginalOwnerID == core.OriginalOwnerID && chunk.OwnerPrimitiveRawSHA256 == prep.CoreBasalOwnerRawSHA256 && core.FactoryRootID == prep.FactoryRootID && core.Role == "host_exterior" && chunk.OwnerRole == "host_exterior" && (chunk.BindingSchema == "original_host_factory_source_approval_v4" && chunk.BindingSHA256 == prep.SourceApprovalSHA256) && f.Operation == "root_directory_close" && f.SubjectOwnerID == core.OriginalOwnerID && f.OwnerPrimitiveRawSHA256 != nil && *f.OwnerPrimitiveRawSHA256 == prep.CoreBasalOwnerRawSHA256 && f.OriginalState == "returned" && f.OriginalCallID != nil && originalHostSourceCustodyCallID(*f.OriginalCallID, chunk.OriginalHandleID) && f.OriginalCalledAt != nil && f.OriginalReturnedAt != nil && !f.OriginalReturnedAt.Before(*f.OriginalCalledAt) && f.OriginalReturnedAt.Before(f.OriginalOperationDeadline) && f.OriginalReturnClass == "success" && native != nil && native.Kind == "original_file_close" && native.OriginalErrorPresent != nil && !*native.OriginalErrorPresent && native.OriginalErrno != nil && *native.OriginalErrno == 0
}

type hostOriginalFinalAuditBasis struct {
	approval                                                           model.HostFactorySourceApproval
	preparation                                                        model.HostFactoryRootPreparation
	core                                                               model.HostFactoryBasalOwnerObservation
	approvalRaw, approvalEnvelope, preparationRaw, preparationEnvelope []byte
}

func originalHostFinalAuditBasisTx(ctx context.Context, tx *sql.Tx, root string) (hostOriginalFinalAuditBasis, error) {
	var out hostOriginalFinalAuditBasis
	var approvalSHA, preparationSHA string
	if tx == nil || ctx == nil || ctx.Err() != nil || !validCapacityExecutor(root) || tx.QueryRowContext(ctx, `SELECT source_approval_sha256,root_preparation_sha256 FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, root).Scan(&approvalSHA, &preparationSHA) != nil {
		return out, ErrHostFactoryHold
	}
	var err error
	out.approvalRaw, err = originalHostAuthenticatedStageBodyTx(ctx, tx, root, "source-approval", approvalSHA, &out.approval)
	if err != nil {
		return out, err
	}
	out.preparationRaw, err = originalHostAuthenticatedStageBodyTx(ctx, tx, root, "root-preparation", preparationSHA, &out.preparation)
	if err != nil || out.approval.ScopeRootID != root || out.preparation.SourceApprovalSHA256 != approvalSHA || out.preparation.FactoryEntryClass != "sealed_a0" && out.preparation.FactoryEntryClass != "sealed_a1" {
		return out, ErrHostFactoryHold
	}
	if _, err = originalHostAuthenticatedStageBodyTx(ctx, tx, root, "basal-owner-core", out.preparation.CoreBasalOwnerRawSHA256, &out.core); err != nil || out.core.Role != "host_exterior" || out.core.FactoryRootID != out.preparation.FactoryRootID || out.core.SourceApprovalSHA256 != approvalSHA {
		return out, ErrHostFactoryHold
	}
	for _, stage := range []struct {
		name, sha string
		dest      *[]byte
	}{{"source-approval", approvalSHA, &out.approvalEnvelope}, {"root-preparation", preparationSHA, &out.preparationEnvelope}} {
		if tx.QueryRowContext(ctx, `SELECT raw_envelope_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND stage=$2 AND raw_body_sha256=$3`, root, stage.name, stage.sha).Scan(stage.dest) != nil || len(*stage.dest) == 0 || len(*stage.dest) > 65536 {
			return out, ErrHostFactoryHold
		}
	}
	return out, nil
}

// Capture only the installed closing attempt's original getter. There is no
// public BODY parameter or post-insert repair/backfill path for this column.
func originalHostFinalAuditBeforeLinkTx(ctx context.Context, tx *sql.Tx, root string, chunk model.HostFactoryCallVectorChunk, bodyRaw, envelopeRaw []byte, index uint32) ([]byte, error) {
	if index >= uint32(len(chunk.OriginalCalls)) {
		return nil, ErrHostFactoryHold
	}
	if chunk.OriginalCalls[index].Operation != "root_directory_close" {
		return nil, nil
	}
	realm, approval, installed := OriginalHostFactoryRealm()
	if ctx == nil || ctx.Err() != nil || !installed || realm == nil || approval.ScopeRootID != root {
		return nil, ErrHostFactoryHold
	}
	anchorRaw, err := realm.OriginalParentHeldRootAnchor(ctx)
	var sourceHeld hostOriginalPostStartNativeAnchor
	if err != nil || originalHostFinalAuditStrict(anchorRaw, &sourceHeld, 65536) != nil || originalHostParentHeldAnchorRef(sourceHeld) != nil {
		return nil, ErrHostFactoryHold
	}
	// During the primer the earlier fresh RootDirectorySource may Close before
	// SQL RootPrep stage insertion. It is a different actual handle: do not
	// require late closing state or backfill its existing returned link.
	if chunk.OriginalHandleID != sourceHeld.OriginalHandleID || chunk.OriginalCalls[index].OriginalState != "returned" {
		return nil, nil
	}
	basis, err := originalHostFinalAuditBasisTx(ctx, tx, root)
	if err != nil {
		return nil, err
	}
	installedHostFactory.Lock()
	state := installedHostFactory.closingSQL
	if state == nil || state.ctx != ctx || ctx.Err() != nil || !time.Now().Before(state.deadline) || state.realm != installedHostFactory.realm || state.db == nil || state.root != root || state.originalErr != nil || state.committed || len(state.finalSourceAuditRaw) == 0 {
		installedHostFactory.Unlock()
		return nil, ErrHostFactoryHold
	}
	raw := bytes.Clone(state.finalSourceAuditRaw)
	installedHostFactory.Unlock()
	parsed, _, err := parseOriginalHostFinalSourceAuditCustody(raw)
	if err != nil {
		return nil, err
	}
	ref := parsed.OriginalParentHeldRootAnchor
	if !reflect.DeepEqual(ref, sourceHeld) {
		return nil, ErrHostFactoryHold
	}
	if chunk.OriginalHandleID != ref.OriginalHandleID || chunk.OriginalOwnerID != basis.core.OriginalOwnerID || chunk.OriginalCalls[index].OriginalState != "returned" {
		return nil, nil
	}
	if !originalHostFinalRootCloseIdentity(basis.preparation, ref, basis.core, chunk, index) || originalHostParentHeldAnchorFromSource(ctx, state.realm, ref) != nil || authenticateOriginalHostParentHeldAnchorTx(ctx, tx, root, basis.preparation, basis.core, ref) != nil {
		return nil, ErrHostFactoryHold
	}

	codec := originalHostSourceCodecTx(ctx, tx, root)
	canonical, canonicalErr := codec.Canonical(chunk)
	if canonicalErr != nil || !bytes.Equal(canonical, bodyRaw) {
		return nil, ErrHostFactoryHold
	}
	if err != nil || parsed.FactoryRootID != basis.preparation.FactoryRootID || parsed.LogicalScopeRootID != root || parsed.SourceApprovalBodySHA256 != capacity.HostFactoryRawSHA256(basis.approvalRaw) || parsed.RootPreparationBodySHA256 != capacity.HostFactoryRawSHA256(basis.preparationRaw) || len(envelopeRaw) == 0 || len(envelopeRaw) > 65536 {
		return nil, ErrHostFactoryHold
	}
	return raw, nil
}

func authenticateOriginalHostFinalSourceAuditTx(ctx context.Context, tx *sql.Tx, root string, raw []byte) (hostOriginalFinalSourceAuditCustody, map[string]hostOriginalSourceAuditProjection, error) {
	parsed, expected, err := parseOriginalHostFinalSourceAuditCustody(raw)
	if err != nil {
		return parsed, nil, err
	}
	basis, err := originalHostFinalAuditBasisTx(ctx, tx, root)
	if err != nil || parsed.LogicalScopeRootID != root || parsed.FactoryRootID != basis.preparation.FactoryRootID || parsed.SourceApprovalBodySHA256 != capacity.HostFactoryRawSHA256(basis.approvalRaw) || parsed.RootPreparationBodySHA256 != capacity.HostFactoryRawSHA256(basis.preparationRaw) {
		return parsed, nil, ErrHostFactoryHold
	}
	if authenticateOriginalHostParentHeldAnchorTx(ctx, tx, root, basis.preparation, basis.core, parsed.OriginalParentHeldRootAnchor) != nil {
		return parsed, nil, ErrHostFactoryHold
	}
	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
	if err != nil {
		return parsed, nil, err
	}
	// Source9 owns compiled approval/key selection and the actual original
	// source/native transport/basis/custody authentication. No supplied key.
	projectionsRaw, err := capacityhostfactory.VerifyOriginalHistoricalFinalSourceAuditCustody(ctx, basis.approvalRaw, basis.approvalEnvelope, basis.preparationRaw, basis.preparationEnvelope, raw, callbacks.resolveIO, callbacks.predecessor, callbacks.originalBasis)
	var projections []hostOriginalSourceAuditProjection
	if err != nil || originalHostFinalAuditStrict(projectionsRaw, &projections, 1048576) != nil || len(projections) != len(expected) {
		return parsed, nil, ErrHostFactoryHold
	}
	authenticated := map[string]hostOriginalSourceAuditProjection{}
	for _, row := range projections {
		id := originalHostPostStartPointerString(row.Fact.OriginalCallID)
		if id == "" {
			return parsed, nil, ErrHostFactoryHold
		}
		if _, duplicate := authenticated[id]; duplicate {
			return parsed, nil, ErrHostFactoryHold
		}
		authenticated[id] = row
	}
	if compareOriginalHostFinalAuditMap(expected, authenticated) != nil {
		return parsed, nil, ErrHostFactoryHold
	}
	return parsed, authenticated, nil
}

func readOriginalHostFinalSourceAuditTx(ctx context.Context, tx *sql.Tx, root string) ([]byte, hostOriginalFinalSourceAuditCustody, map[string]hostOriginalSourceAuditProjection, error) {
	var zero hostOriginalFinalSourceAuditCustody
	basis, err := originalHostFinalAuditBasisTx(ctx, tx, root)
	if err != nil {
		return nil, zero, nil, err
	}
	var count int
	if tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_host_factory_call_snapshot_links WHERE root_id=$1 AND original_final_source_audit_wire IS NOT NULL`, root).Scan(&count) != nil || count != 1 {
		return nil, zero, nil, ErrHostFactoryHold
	}
	var raw, body, envelope []byte
	var index uint32
	var kind, callID string
	if tx.QueryRowContext(ctx, `SELECT l.original_final_source_audit_wire,r.raw_body_wire,r.raw_envelope_wire,l.current_fact_index,l.version_kind,l.original_call_id FROM public.capacity_host_factory_call_snapshot_links l JOIN public.capacity_host_factory_io_returns r ON r.root_id=l.root_id AND r.binding_schema=l.binding_schema AND r.binding_sha256=l.binding_sha256 AND r.original_owner_id=l.original_owner_id AND r.record_kind='chunk' AND r.raw_body_sha256=l.current_chunk_raw_body_sha256 WHERE l.root_id=$1 AND l.original_final_source_audit_wire IS NOT NULL AND l.original_owner_id=$2`, root, basis.core.OriginalOwnerID).Scan(&raw, &body, &envelope, &index, &kind, &callID) != nil || kind != "first" && kind != "pending_to_returned" || len(raw) == 0 || len(raw) > 1048576 || len(body) == 0 || len(body) > 65536 || len(envelope) == 0 || len(envelope) > 65536 {
		return nil, zero, nil, ErrHostFactoryHold
	}
	parsedRaw, _, parseErr := parseOriginalHostFinalSourceAuditCustody(raw)
	if parseErr != nil {
		return nil, zero, nil, parseErr
	}
	codec := originalHostSourceCodecTx(ctx, tx, root)
	var chunk model.HostFactoryCallVectorChunk
	if codec.Decode(body, &chunk) != nil || !originalHostFinalRootCloseIdentity(basis.preparation, parsedRaw.OriginalParentHeldRootAnchor, basis.core, chunk, index) || callID != originalHostPostStartPointerString(chunk.OriginalCalls[index].OriginalCallID) {
		return nil, zero, nil, ErrHostFactoryHold
	}
	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
	if err != nil {
		return nil, zero, nil, err
	}
	exactBody, exactEnvelope, err := callbacks.resolveIO(capacity.HostFactoryRawSHA256(body))
	if err != nil || !bytes.Equal(exactBody, body) || !bytes.Equal(exactEnvelope, envelope) {
		return nil, zero, nil, ErrHostFactoryHold
	}
	if _, _, _, err = callbacks.predecessor(capacity.HostFactoryRawSHA256(body), index); err != nil {
		return nil, zero, nil, err
	}
	parsed, audits, err := authenticateOriginalHostFinalSourceAuditTx(ctx, tx, root, raw)
	return bytes.Clone(raw), parsed, audits, err
}

func validateOriginalHostFinalSourceActorLifetime(c hostOriginalFinalSourceAuditCustody, audits map[string]hostOriginalSourceAuditProjection, returns []hostOriginalRealmOwnerReturn, realmJoin hostOriginalMainReturn) error {
	if len(c.OriginalActors) != 2 || realmJoin.Operation != "realm_close_join" || realmJoin.OriginalCalledAt == nil || realmJoin.OriginalReturnedAt == nil || realmJoin.OriginalReturnedAt.Before(*realmJoin.OriginalCalledAt) {
		return ErrHostFactoryHold
	}
	for n, actor := range c.OriginalActors {
		var carrier hostOriginalFinalSourceAuditCarrier
		if originalHostFinalAuditStrict(actor.OriginalCarrierBodyWire, &carrier, 65536) != nil {
			return ErrHostFactoryHold
		}
		helper := carrier.OriginalHelperReturn
		if helper.OriginalErrorPresent || actor.OriginalReceiverReturn.OriginalErrorPresent || actor.OriginalReceiverReturn.OriginalReturnedAt.After(*realmJoin.OriginalReturnedAt) {
			return ErrHostFactoryHold
		}
		waitOperation := []string{"worker_wait", "registrar_wait"}[n]
		waits := 0
		for _, r := range returns {
			if r.Operation != waitOperation || r.SubjectOwnerID != actor.OriginalOwnerID {
				continue
			}
			waits++
			f := r.OriginalFact
			if r.SubjectRole != actor.OriginalOwnerRole || r.OwnerRole != "host_exterior" || r.OriginalOwnerID != realmJoin.OriginalOwnerID || r.OriginalFactReference == nil || r.OriginalLocalReturn != nil || f == nil || f.OriginalCallID == nil || f.OriginalState != "returned" || f.Operation != waitOperation || f.SubjectOwnerID != actor.OriginalOwnerID || f.OriginalReturnedAt == nil || f.OriginalReturnedAt.Before(helper.OriginalReturnedAt) || f.OriginalReturnedAt.After(*realmJoin.OriginalReturnedAt) || !f.OriginalReturnedAt.Before(f.OriginalOperationDeadline) || f.OriginalReturnClass != "success" || f.OriginalNativeReturn == nil || f.OriginalNativeReturn.OriginalErrorPresent == nil || *f.OriginalNativeReturn.OriginalErrorPresent {
				return ErrHostFactoryHold
			}
		}
		if waits != 1 {
			return ErrHostFactoryHold
		}
		// ALL actor facts, including real final directory Close, precede the
		// authenticated actor helper GoReturn. WaitCalled may be earlier.
		for _, artifact := range actor.OriginalArtifacts {
			var a hostOriginalFinalSourceAuditArtifact
			if originalHostFinalAuditStrict(artifact.OriginalBodyWire, &a, 65536) != nil {
				return ErrHostFactoryHold
			}
			for _, stream := range a.OriginalStreams {
				for _, row := range stream.OriginalSourceAuditProjections {
					if row.Fact.OriginalReturnedAt == nil || row.Fact.OriginalReturnedAt.After(helper.OriginalReturnedAt) {
						return ErrHostFactoryHold
					}
				}
			}
		}
		for _, stream := range carrier.OriginalRemainingStreams {
			for _, row := range stream.OriginalSourceAuditProjections {
				actual, exists := audits[originalHostPostStartPointerString(row.Fact.OriginalCallID)]
				if !exists || !reflect.DeepEqual(row, actual) || row.Fact.OriginalReturnedAt == nil || row.Fact.OriginalReturnedAt.After(helper.OriginalReturnedAt) {
					return ErrHostFactoryHold
				}
			}
		}
	}
	for _, stream := range c.OriginalParentSourceStreams {
		for _, row := range stream.OriginalSourceAuditProjections {
			if row.Fact.OriginalReturnedAt == nil || row.Fact.OriginalReturnedAt.After(*realmJoin.OriginalReturnedAt) {
				return ErrHostFactoryHold
			}
		}
	}
	return nil
}

func verifyOriginalHostFinalSourceAuditMainTx(ctx context.Context, tx *sql.Tx, snapshot hostOriginalSQLSnapshot, bundle hostOriginalRealmCorpus, audits map[string]hostOriginalSourceAuditProjection, main map[string]hostOriginalMainReturn) error {
	if snapshot.EntryClass != "sealed_a0" && snapshot.EntryClass != "sealed_a1" {
		return ErrHostFactoryHold
	}
	_, parsed, authenticated, err := readOriginalHostFinalSourceAuditTx(ctx, tx, snapshot.RootID)
	if err != nil || parsed.FactoryRootID != snapshot.NativeFactoryRootID || parsed.SourceApprovalBodySHA256 != snapshot.SourceApprovalBodySHA256 || parsed.RootPreparationBodySHA256 != snapshot.RootPreparationBodySHA256 || compareOriginalHostFinalSourceAuditPartition(authenticated, audits, main) != nil || validateOriginalHostFinalSourceActorLifetime(parsed, audits, bundle.OriginalRealmOwnerReturns, main["realm_close_join"]) != nil {
		return ErrHostFactoryHold
	}
	return nil
}

func (s CapacityStore) CaptureOriginalHostClosingReturn(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, calledAt, returnedAt time.Time, closingErr error) error {
	installedHostFactory.Lock()
	defer installedHostFactory.Unlock()
	state := installedHostFactory.closingSQL
	if state == nil {
		return errors.Join(closingErr, ErrHostFactoryHold)
	}
	if state.externalReturnReserved {
		state.originalErr = errors.Join(state.originalErr, ErrHostFactoryHold)
		return errors.Join(closingErr, ErrHostFactoryHold)
	}
	state.externalReturnReserved = true
	state.externalCalledAt, state.returnedAt = calledAt, returnedAt
	state.originalErr = errors.Join(state.originalErr, closingErr)
	if ctx == nil || ctx != state.ctx || ctx.Err() != nil || realm == nil || realm != state.realm || realm != installedHostFactory.realm || state.db != s.DB || s.DB == nil || calledAt.IsZero() || calledAt.After(state.calledAt) || returnedAt.IsZero() || returnedAt.Before(calledAt) || !state.committed || state.commitReturnedAt.IsZero() || state.helperReturnedAt.Before(state.commitReturnedAt) || state.methodFinishedAt.Before(state.helperReturnedAt) || returnedAt.Before(state.methodFinishedAt) || !returnedAt.Before(state.deadline) || state.originalErr != nil {
		state.originalErr = errors.Join(state.originalErr, ErrHostFactoryHold)
	}
	return state.originalErr
}

// Lexical helper return retention accepts an already sampled timestamp. It
// does not take a clock sample after mutex scheduling.
func retainOriginalHostClosingHelperReturn(state *hostOriginalClosingSQLReturn, returnedAt time.Time, helperErr error) {
	installedHostFactory.Lock()
	defer installedHostFactory.Unlock()
	if state == nil || installedHostFactory.closingSQL != state || !state.helperReturnedAt.IsZero() {
		if state != nil {
			state.originalErr = errors.Join(state.originalErr, ErrHostFactoryHold)
		}
		return
	}
	state.helperReturnedAt = returnedAt
	state.originalErr = errors.Join(state.originalErr, helperErr)
	if returnedAt.IsZero() || returnedAt.Before(state.calledAt) || !returnedAt.Before(state.deadline) || state.ctx == nil || state.ctx.Err() != nil || !state.committed || state.commitReturnedAt.IsZero() || returnedAt.Before(state.commitReturnedAt) {
		state.originalErr = errors.Join(state.originalErr, ErrHostFactoryHold)
	}
}

// Private currentv3/finalv2 reference to the actual c.fresh.anchor. Earlier
// RootDirectorySource and its already-returned Close remain different facts.
func originalHostParentHeldAnchorRef(ref hostOriginalPostStartNativeAnchor) error {
	if !validCapacityExecutor(ref.OriginalHandleID) || !capacity.ValidDigest(ref.OriginalInventoryBodySHA256) || !capacity.ValidDigest(ref.OriginalInventoryEnvelopeSHA256) || ref.OriginalAcquisitionCallID != ref.OriginalHandleID+":1" || ref.OriginalFstatCallID != ref.OriginalHandleID+":2" {
		return ErrHostFactoryHold
	}
	return nil
}

func originalHostParentHeldAnchorFromSource(ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm, expected hostOriginalPostStartNativeAnchor) error {
	if ctx == nil || ctx.Err() != nil || realm == nil || originalHostParentHeldAnchorRef(expected) != nil {
		return ErrHostFactoryHold
	}
	raw, err := realm.OriginalParentHeldRootAnchor(ctx)
	var original hostOriginalPostStartNativeAnchor
	if err != nil || originalHostFinalAuditStrict(raw, &original, 65536) != nil || !reflect.DeepEqual(original, expected) || originalHostParentHeldAnchorRef(original) != nil {
		return ErrHostFactoryHold
	}
	return nil
}

func originalHostParentHeldInventoryMember(prep model.HostFactoryRootPreparation, ref hostOriginalPostStartNativeAnchor) error {
	if originalHostParentHeldAnchorRef(ref) != nil || ref.OriginalHandleID == prep.RootDirectorySource.OriginalHandleID {
		return ErrHostFactoryHold
	}
	count := 0
	for _, sha := range prep.OriginalHandleInventorySHAs {
		if sha == ref.OriginalInventoryBodySHA256 {
			count++
		}
	}
	if count != 1 {
		return ErrHostFactoryHold
	}
	return nil
}

// Structural comparison of four authenticated original native returns. It
// grants no Source/native permission; SQL/source wrappers authenticate below.
func validateOriginalHostParentHeldAnchorFacts(prep model.HostFactoryRootPreparation, core model.HostFactoryBasalOwnerObservation, ref hostOriginalPostStartNativeAnchor, facts []model.HostFactoryPrimitiveIOReturn) error {
	if originalHostParentHeldInventoryMember(prep, ref) != nil || len(facts) != 4 || core.Role != "host_exterior" || core.FactoryRootID != prep.FactoryRootID {
		return ErrHostFactoryHold
	}
	operations := []string{"root_directory_open", "descriptor_fstat", "fcntl_getfl", "fcntl_getfd"}
	var previous time.Time
	for n, f := range facts {
		native := f.OriginalNativeReturn
		if f.Operation != operations[n] || f.OriginalHandleID != ref.OriginalHandleID || f.OriginalCallID == nil || *f.OriginalCallID != ref.OriginalHandleID+":"+strconv.Itoa(n+1) || f.SubjectOwnerID != core.OriginalOwnerID || f.OwnerPrimitiveRawSHA256 == nil || *f.OwnerPrimitiveRawSHA256 != prep.CoreBasalOwnerRawSHA256 || f.OriginalState != "returned" || f.OriginalReturnClass != "success" || f.OriginalCalledAt == nil || f.OriginalReturnedAt == nil || f.OriginalCalledAt.Before(previous) || f.OriginalReturnedAt.Before(*f.OriginalCalledAt) || !f.OriginalReturnedAt.Before(f.OriginalOperationDeadline) || !f.OriginalReturnedAt.Before(prep.OriginalContextDeadline) || f.OriginalCalledAt.Before(prep.OriginalContextStartedAt) || native == nil || native.OriginalErrorPresent == nil || *native.OriginalErrorPresent || native.OriginalErrno == nil || *native.OriginalErrno != 0 {
			return ErrHostFactoryHold
		}
		if n > 0 && !f.OriginalOperationDeadline.Equal(facts[0].OriginalOperationDeadline) {
			return ErrHostFactoryHold
		}
		previous = *f.OriginalReturnedAt
	}
	open, stat := facts[0].OriginalNativeReturn, facts[1].OriginalNativeReturn
	if open.Kind != "unix_openat" || open.OriginalScalar == nil || *open.OriginalScalar < 0 || open.RequestedFlags == nil || len(open.ReturnedDescriptors) != 1 || open.ReturnedDescriptors[0].OriginalHandleID != ref.OriginalHandleID || int64(open.ReturnedDescriptors[0].OriginalDescriptorNumber) != *open.OriginalScalar || stat.Kind != "unix_fstat" || stat.InputDescriptorNumber == nil || int64(*stat.InputDescriptorNumber) != *open.OriginalScalar || stat.OriginalStat == nil {
		return ErrHostFactoryHold
	}
	actual := stat.OriginalStat
	expected := prep.RootDirectorySource
	if actual.Device != expected.Device || actual.Inode != expected.Inode || actual.Mode != expected.Mode || actual.LinkCount != expected.LinkCount || actual.UID != expected.UID || actual.GID != expected.GID {
		return ErrHostFactoryHold
	}
	for n := 2; n < 4; n++ {
		native := facts[n].OriginalNativeReturn
		if native.Kind != operations[n] || native.InputDescriptorNumber == nil || int64(*native.InputDescriptorNumber) != *open.OriginalScalar || native.RequestedFcntlCommand == nil || *native.RequestedFcntlCommand != []int{3, 1}[n-2] || native.RequestedArgument == nil || *native.RequestedArgument != 0 || native.OriginalScalar == nil || *native.OriginalScalar < 0 {
			return ErrHostFactoryHold
		}
	}
	// Requested Open flags are never relabeled as F_GETFL/F_GETFD observations.
	return nil
}

func authenticateOriginalHostParentHeldAnchorTx(ctx context.Context, tx *sql.Tx, root string, prep model.HostFactoryRootPreparation, core model.HostFactoryBasalOwnerObservation, ref hostOriginalPostStartNativeAnchor) error {
	if originalHostParentHeldInventoryMember(prep, ref) != nil {
		return ErrHostFactoryHold
	}
	callbacks, err := originalHostNativeCallbacksTx(ctx, tx, root)
	if err != nil {
		return err
	}
	raw, envelope, err := callbacks.resolveIO(ref.OriginalInventoryBodySHA256)
	var inventory model.HostFactoryHandleCallInventory
	codec := originalHostSourceCodecTx(ctx, tx, root)
	if err != nil || capacity.HostFactoryRawSHA256(envelope) != ref.OriginalInventoryEnvelopeSHA256 || codec.Decode(raw, &inventory) != nil || inventory.BindingSchema != "original_host_factory_source_approval_v4" || inventory.BindingSHA256 != prep.SourceApprovalSHA256 || inventory.OwnerRole != "host_exterior" || inventory.OriginalOwnerID != core.OriginalOwnerID || inventory.OwnerPrimitiveRawSHA256 == nil || *inventory.OwnerPrimitiveRawSHA256 != prep.CoreBasalOwnerRawSHA256 || inventory.OriginalHandleID != ref.OriginalHandleID || inventory.FirstOrdinal != 1 || inventory.LastOrdinal != 4 || inventory.OriginalCallCount != 4 || len(inventory.OperationVectors) != 4 || inventory.CollectionState != "complete_original_calls" {
		return ErrHostFactoryHold
	}
	x, err := originalHostIOIdentity(codec, root, &inventory, raw)
	if err != nil || validateOriginalHostInventoryTx(ctx, tx, x, inventory) != nil {
		return ErrHostFactoryHold
	}
	// Exact saved pair, not a later same-handle snapshot. Source-owned wrapper
	// authenticates the original Basal/bootstrap/SourceApproval trusted owner.
	if capacityhostfactory.ValidateOriginalHistoricalSourceHandleInventory(ctx, codec.approvalRaw, codec.approvalEnvelope, codec.nativeRoot, inventory, callbacks.resolveIO, callbacks.predecessor, callbacks.originalBasis) != nil {
		return ErrHostFactoryHold
	}
	ordered := make([]model.HostFactoryPrimitiveIOReturn, 4)
	present := make([]bool, 4)
	for _, vector := range inventory.OperationVectors {
		selected, err := originalHostVectorFactsTx(ctx, tx, root, vector)
		if err != nil || len(selected) != 1 || selected[0].OriginalCallID == nil {
			return ErrHostFactoryHold
		}
		handle, ordinal, ok := originalHostPostStartCallID(*selected[0].OriginalCallID)
		if !ok || handle != ref.OriginalHandleID || ordinal < 1 || ordinal > 4 || present[ordinal-1] {
			return ErrHostFactoryHold
		}
		ordered[ordinal-1] = selected[0]
		present[ordinal-1] = true
	}
	for _, yes := range present {
		if !yes {
			return ErrHostFactoryHold
		}
	}
	if validateOriginalHostParentHeldAnchorFacts(prep, core, ref, ordered) != nil {
		return ErrHostFactoryHold
	}
	// The original RootPrep diagnostic graph must contain these SAME returned
	// calls. A typed ref or stat equality cannot manufacture Source history.
	for _, selected := range ordered {
		found := false
		for _, operation := range prep.OriginalRootOperations {
			if operation.Operation != selected.Operation || operation.OriginalHandleID != ref.OriginalHandleID {
				continue
			}
			facts, err := originalHostVectorFactsTx(ctx, tx, root, operation.OriginalCallVector)
			if err != nil {
				return ErrHostFactoryHold
			}
			for _, fact := range facts {
				if reflect.DeepEqual(fact, selected) {
					found = true
				}
			}
		}
		if !found {
			return ErrHostFactoryHold
		}
	}
	return nil
}

// This Source-private preflight owns no transaction. A matching original grant
// selects the same installed Realm, never a caller flag/principal/DTO label.
// Channel completion grants no settlement permission: all durable and native
// checks still run in guardOriginalOrdinaryCallbackTx inside callbackTransaction.
func (s CapacityStore) waitOriginalOrdinarySettleBeforeTx(ctx context.Context, principal string, request model.CapacityMutationSettleRequest) error {
	installedHostFactory.Lock()
	realm, approval := installedHostFactory.realm, installedHostFactory.approval
	factories := make(map[string]*hostOriginalOrdinaryFactory, len(installedHostFactory.ordinaryFactories))
	for target, h := range installedHostFactory.ordinaryFactories {
		factories[target] = h
	}
	installedHostFactory.Unlock()

	var selected *hostOriginalOrdinaryFactory
	var selectedTarget string
	for target, h := range factories {
		if h == nil {
			continue
		}
		h.mu.Lock()
		matches := h.grant.GrantID != "" && h.grant.GrantID == request.GrantID
		known := realm != nil && h.realm == realm && h.claim != nil && h.claim.realm == realm && approval.ScopeRootID != "" && h.claim.rootID == approval.ScopeRootID && h.issueCommitted && h.issueCaptured && h.issueReturnErr == nil && !h.issueReturnedAt.IsZero()
		h.mu.Unlock()
		if matches {
			if selected != nil || !known {
				return ErrHostFactoryHold
			}
			selected, selectedTarget = h, target
		}
	}
	if selected == nil {
		// No private match is not proof of SQL absence. The unchanged durable
		// callback guard still refuses orphaned/unknown original targets.
		return nil
	}
	installedHostFactory.Lock()
	same := installedHostFactory.realm == realm && installedHostFactory.ordinaryFactories[selectedTarget] == selected
	installedHostFactory.Unlock()
	if !same {
		return ErrHostFactoryHold
	}
	// All repository locks are released before the real Source-owned channel
	// wait. SAME caller context/request/principal pass through unchanged; no
	// timeout, native observation, SQL transaction or readiness flag is made.
	if err := realm.WaitOriginalOrdinarySettle(ctx, principal, request); err != nil {
		return errors.Join(ErrHostFactoryHold, err)
	}
	return nil
}
