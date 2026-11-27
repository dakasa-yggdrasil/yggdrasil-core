package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Only protected server composition installs these read-only callbacks. Neither
// an adapter receive nor a workflow DTO supplies readiness/admission assertions.
type NativeWorkerPhaseRuntime interface {
	PreparePhase(context.Context, model.CapacityNativeWorkerAttempt, string) (model.CapacityNativeWorkerPhasePreparation, error)
	ObservePhase(context.Context, model.CapacityNativeWorkerPhasePermit) (model.CapacityNativeWorkerPhaseObservation, error)
}

type CapacityNativeWorkerPhaseStore struct {
	Workers CapacityNativeWorkerStore
	Runtime NativeWorkerPhaseRuntime
	Enabled bool
}

// This record and its event stream are private database custody. Public reads
// return only Context, with no token, raw return, raw hash or executor identity.
type nativeWorkerPhaseRecord struct {
	Observed              *model.CapacityNativeWorkerPhaseObservation     `json:"observed,omitempty"`
	MaxReadAgeSeconds     int                                             `json:"max_read_age_seconds"`
	NoEffectReason        string                                          `json:"no_effect_reason,omitempty"`
	Context               model.CapacityNativeWorkerPhasePermit           `json:"context"`
	Writer                model.CapacityNativeWorkerRegistryWriterBinding `json:"writer"`
	PolicyChecksum        string                                          `json:"policy_checksum"`
	ExecutorID            string                                          `json:"executor_id"`
	WorkflowID            uuid.UUID                                       `json:"workflow_id"`
	Revision              int64                                           `json:"revision"`
	SettlementTokenSHA256 string                                          `json:"settlement_token_sha256,omitempty"`
	Original              *model.CapacityNativeWorkerPhaseReceive         `json:"original,omitempty"`
	ReceivedAt            *time.Time                                      `json:"received_at,omitempty"`
}

var nativePhaseSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)
var nativePhaseDNS = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)

func phaseContext(r nativeWorkerPhaseRecord) model.CapacityNativeWorkerPhasePermit {
	c := r.Context
	c.MutationPermitted, c.Redeemable, c.SettlementToken = false, false, ""
	return c
}

func phaseCaller(r nativeWorkerPhaseRecord, c model.CapacityNativeWorkerPhaseCaller) bool {
	return c.Adapter == r.Writer.Adapter && c.PrincipalID == r.Writer.PrincipalID &&
		c.BindingName == r.Writer.BindingName && c.SourceCommit == r.Writer.SourceCommit
}

func nativePhaseLoadTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, id uuid.UUID) (nativeWorkerPhaseRecord, error) {
	var r nativeWorkerPhaseRecord
	var raw []byte
	err := tx.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_phase_permits WHERE id=$1 AND policy_id=$2 AND namespace=$3 FOR UPDATE`, id, policy.ID, policy.Metadata.Namespace).Scan(&raw)
	if err == nil {
		err = json.Unmarshal(raw, &r)
	}
	return r, err
}

func nativePhaseWriteTx(ctx context.Context, tx *sql.Tx, r nativeWorkerPhaseRecord, now time.Time) error {
	// Never persist a plaintext bearer or a public mutation permission.
	if r.Context.SettlementToken != "" || r.Context.MutationPermitted || r.Context.Redeemable {
		return ErrCapacityConflict
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.capacity_native_worker_phase_permits SET state=$2,revision=$3,record=$4,updated_at=$5 WHERE id=$1 AND revision=$6`, r.Context.PermitID, r.Context.PhaseState, r.Revision, raw, now, r.Revision-1)
	if err == nil {
		n, e := result.RowsAffected()
		if e != nil || n != 1 {
			return ErrCapacityConflict
		}
	}
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_phase_permit_events(permit_id,revision,record,recorded_at) VALUES($1,$2,$3,$4)`, r.Context.PermitID, r.Revision, raw, now)
	return err
}

// currentPhase uses the private controller identity saved at issuance. A caller
// cannot choose another workflow/executor by supplying an adapter request.
func (s CapacityNativeWorkerPhaseStore) currentPhase(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, r nativeWorkerPhaseRecord, now time.Time) error {
	if !s.Enabled || s.Runtime == nil || p.NativeWorkerLifecycleBinding == nil || p.NativeWorkerLifecycleBinding.RegistryWriter == nil ||
		p.NativeWorkerPoolBinding == nil ||
		r.Writer != *p.NativeWorkerLifecycleBinding.RegistryWriter || policy.Checksum != r.PolicyChecksum ||
		!r.Context.ExpiresAt.After(now) || r.Context.Epoch != p.NativeWorkerPoolBinding.ExpectedPoolEpoch {
		return ErrCapacityDisabled
	}
	w := s.Workers
	w.Capacity.ExecutorID, w.Capacity.WorkflowID = r.ExecutorID, r.WorkflowID
	_, err := w.current(ctx, tx, policy, p, model.CapacityNativeWorkerAuthority{Generation: r.Context.IntentGeneration, FencingToken: r.Context.FencingToken}, now)
	if err != nil {
		return err
	}
	a, _, err := nativeAttemptLoadTx(ctx, tx, policy, r.Context.AttemptID)
	if err != nil {
		return err
	}
	if a.PolicyID != policy.ID || a.PolicyChecksum != policy.Checksum || a.Generation != r.Context.IntentGeneration ||
		a.FencingToken != r.Context.FencingToken || a.PoolUID != r.Context.PoolUID || a.PoolEpoch != r.Context.Epoch ||
		!phaseAttemptMatches(p, a, r.Context, now) {
		return ErrCapacityConflict
	}
	b := model.CapacityMutationBinding{IntegrationInstanceID: r.Writer.Adapter.ManifestID, IntegrationChecksum: r.Writer.Adapter.Checksum, IntegrationTypeID: r.Writer.Adapter.IntegrationTypeID, IntegrationTypeChecksum: r.Writer.Adapter.TypeChecksum}
	if err = checkMutationIntegration(ctx, tx, b); err != nil {
		return err
	}
	var version int
	if err = tx.QueryRowContext(ctx, `SELECT version FROM public.manifests WHERE id=$1`, r.Writer.Adapter.ManifestID).Scan(&version); err != nil {
		return err
	}
	if version != r.Writer.Adapter.Version {
		return ErrCapacityConflict
	}
	return nil
}

func phaseAttemptMatches(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, c model.CapacityNativeWorkerPhasePermit, now time.Time) bool {
	if p.NativeWorkerPoolBinding == nil || p.NativeWorkerLifecycleBinding == nil || a.Physical == nil ||
		!nativePhaseSHA.MatchString(a.BirthSHA256) || c.Node.UID == "" || (a.NodeUID != "" && c.Node.UID != a.NodeUID) ||
		c.Node.ProviderID != a.Physical.ProviderID || c.Node.Profile != a.Profile || c.Node.PhysicalSpecSHA256 != a.PhysicalSpecSHA256 ||
		c.Node.CapacityPolicyID != a.PolicyID.String() || c.Node.IntentGeneration != a.Generation || c.Node.FencingToken != a.FencingToken || c.Node.CreationProofSHA256 != a.BirthSHA256 ||
		!nativePhaseDNS.MatchString(c.Node.Name) || c.Node.ResourceVersion == "" || !nativePhaseDNS.MatchString(c.RealmNamespace) || c.RealmUID != p.NativeWorkerPoolBinding.RealmUID ||
		c.Registry != a.Registry || c.ExpectedRegistryResourceVersion == "" || !nativePhaseSHA.MatchString(c.ExpectedRegistrySHA256) {
		return false
	}
	for _, n := range p.NativeWorkerPoolBinding.ProtectedNodes {
		if n.NodeUID == c.Node.UID || n.ProviderID == c.Node.ProviderID {
			return false
		}
	}
	registration := ""
	for _, profile := range p.NativeWorkerPoolBinding.Profiles {
		if profile.Profile == a.Profile {
			registration = profile.RegistrationBindingSHA
		}
	}
	if registration == "" || c.Node.RegistrationBindingSHA256 != registration {
		return false
	}
	if c.Action == "register" {
		return a.State == "acknowledged"
	}
	if c.Action != "admit_registry" && c.Action != "release_quarantine" {
		return false
	}
	return a.State == "registered" && a.NodeUID == c.Node.UID &&
		c.Admission.NetworkBindingSHA256 == a.NetworkBindingSHA256 && nativePhaseSHA.MatchString(c.Admission.WarmupEvidenceSHA256) &&
		c.Admission.PhysicalQualificationSHA256 == a.QualificationEvidenceSHA256 && a.QualificationValidUntil.After(now)
}

func phasePrepared(p model.CapacityPolicySpec, a model.CapacityNativeWorkerAttempt, action string, v model.CapacityNativeWorkerPhasePreparation, now time.Time) bool {
	c := v.Context
	c.Action = action
	if !phaseAttemptMatches(p, a, c, now) || v.ObservedAt.IsZero() || v.ObservedAt.After(now) ||
		now.Sub(v.ObservedAt) > time.Duration(p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds)*time.Second {
		return false
	}
	return action == "register" || (v.NodeReady && v.NetworkVerified && v.WarmupVerified && v.PhysicalQualified)
}

func (s CapacityNativeWorkerPhaseStore) Issue(ctx context.Context, policy model.Manifest, authority model.CapacityNativeWorkerAuthority, attemptID uuid.UUID, action string) (model.CapacityNativeWorkerPhasePermit, error) {
	var out model.CapacityNativeWorkerPhasePermit
	if !s.Enabled || s.Runtime == nil {
		return out, ErrCapacityDisabled
	}
	authenticated, err := s.Workers.authenticate(ctx, policy)
	if err != nil {
		return out, err
	}
	s.Workers = authenticated
	a, err := s.Workers.Read(ctx, policy, attemptID)
	if err != nil {
		return out, err
	}
	prepared, err := s.Runtime.PreparePhase(ctx, a, action) // All external reads precede the transaction.
	if err != nil {
		return out, err
	}
	err = s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		if capacity.ValidateNativeWorkerRegistryWriterBinding(p) != nil || p.NativeWorkerLifecycleBinding.RegistryWriter == nil {
			return ErrCapacityDisabled
		}
		parent, e := s.Workers.current(ctx, tx, policy, p, authority, now)
		if e != nil {
			return e
		}
		actual, _, e := nativeAttemptLoadTx(ctx, tx, policy, attemptID)
		if e != nil {
			return e
		}
		if actual.Revision != a.Revision || actual.PolicyChecksum != policy.Checksum || actual.Generation != authority.Generation || actual.FencingToken != authority.FencingToken || !phasePrepared(p, actual, action, prepared, now) {
			return ErrCapacityConflict
		}
		// An expired issuance that was never redeemed has never authorized a
		// PATCH. Serialize with Redeem and retain its cancellation event before
		// minting a successor. Redeemed/unknown/observed permits never expire free.
		var priorRaw []byte
		e = tx.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_phase_permits WHERE attempt_id=$1 AND action=$2 AND state <> 'no_effect' FOR UPDATE`, actual.ID, action).Scan(&priorRaw)
		if e == nil {
			var prior nativeWorkerPhaseRecord
			if json.Unmarshal(priorRaw, &prior) != nil || prior.Context.PhaseState != "issued" || prior.Context.ExpiresAt.After(now) || prior.SettlementTokenSHA256 != "" || prior.Original != nil {
				return ErrCapacityConflict
			}
			prior.Context.PhaseState, prior.NoEffectReason = "no_effect", "expired_unredeemed"
			prior.Revision++
			if e = nativePhaseWriteTx(ctx, tx, prior, now); e != nil {
				return e
			}
		} else if e != sql.ErrNoRows {
			return e
		}
		c := prepared.Context
		b := *p.NativeWorkerLifecycleBinding.RegistryWriter
		c.Schema, c.PermitID, c.AttemptID = model.CapacityNativeWorkerPhasePermitSchema, uuid.New(), attemptID
		c.BindingName, c.Operation, c.Action = b.BindingName, b.Capability, action
		c.PolicyID, c.IntentGeneration, c.FencingToken = policy.ID, authority.Generation, authority.FencingToken
		c.PoolUID, c.Owner, c.Epoch = actual.PoolUID, p.Owner, actual.PoolEpoch
		c.ExpiresAt = now.Add(time.Duration(b.MaxPermitSeconds) * time.Second)
		if parent.LeaseExpiresAt.Before(c.ExpiresAt) {
			c.ExpiresAt = *parent.LeaseExpiresAt
		}
		if action != "register" && actual.QualificationValidUntil.Before(c.ExpiresAt) {
			c.ExpiresAt = actual.QualificationValidUntil
		}
		c.MutationPermitted, c.Redeemable, c.SettlementToken, c.PhaseState = false, false, "", "issued"
		if action == "register" {
			c.Admission = model.CapacityNativeWorkerPhaseAdmission{}
		} else {
			// Root records the safe admission evidence before any registry CAS.
			proof, _ := json.Marshal(struct {
				Attempt   uuid.UUID
				Birth     string
				Node      model.CapacityNativeWorkerPhaseNode
				Admission model.CapacityNativeWorkerPhaseAdmission
			}{actual.ID, actual.BirthSHA256, c.Node, model.CapacityNativeWorkerPhaseAdmission{NetworkBindingSHA256: c.Admission.NetworkBindingSHA256, WarmupEvidenceSHA256: c.Admission.WarmupEvidenceSHA256, PhysicalQualificationSHA256: c.Admission.PhysicalQualificationSHA256}})
			if action == "admit_registry" {
				c.Admission.ReceiptSHA256 = fmt.Sprintf("%x", sha256.Sum256(proof))
			} else {
				var priorRaw []byte
				if e = tx.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_phase_permits WHERE attempt_id=$1 AND action='admit_registry' AND state='observed' ORDER BY issued_at DESC LIMIT 1`, actual.ID).Scan(&priorRaw); e != nil {
					return ErrCapacityConflict
				}
				var prior nativeWorkerPhaseRecord
				if json.Unmarshal(priorRaw, &prior) != nil || prior.Context.Epoch != c.Epoch || prior.Context.IntentGeneration != c.IntentGeneration || prior.Context.FencingToken != c.FencingToken || prior.Context.Node.UID != c.Node.UID || prior.Context.Admission != c.Admission {
					return ErrCapacityConflict
				}
			}
		}
		r := nativeWorkerPhaseRecord{Context: c, Writer: b, MaxReadAgeSeconds: p.NativeWorkerLifecycleBinding.MaxReadAgeSeconds, PolicyChecksum: policy.Checksum, ExecutorID: s.Workers.Capacity.ExecutorID, WorkflowID: s.Workers.Capacity.WorkflowID, Revision: 1}
		// Scope is persisted independently from caller-controlled input.
		if e = nativePhaseInsertTx(ctx, tx, r, policy.Metadata.Namespace, now); e != nil {
			return e
		}
		out = phaseContext(r)
		return nil
	})
	return out, err
}

func nativePhaseInsertTx(ctx context.Context, tx *sql.Tx, r nativeWorkerPhaseRecord, namespace string, now time.Time) error {
	if r.Context.SettlementToken != "" || r.Context.MutationPermitted || r.Context.Redeemable {
		return ErrCapacityConflict
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_phase_permits(id,attempt_id,policy_id,namespace,action,state,revision,record,issued_at,expires_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$9)`, r.Context.PermitID, r.Context.AttemptID, r.Context.PolicyID, namespace, r.Context.Action, r.Context.PhaseState, r.Revision, raw, now, r.Context.ExpiresAt)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_worker_phase_permit_events(permit_id,revision,record,recorded_at) VALUES($1,$2,$3,$4)`, r.Context.PermitID, r.Revision, raw, now)
	return err
}

func (s CapacityNativeWorkerPhaseStore) Read(ctx context.Context, policy model.Manifest, id uuid.UUID, caller model.CapacityNativeWorkerPhaseCaller) (model.CapacityNativeWorkerPhasePermit, error) {
	var out model.CapacityNativeWorkerPhasePermit
	// Failure to refresh authority must not hide historical truth. It only
	// removes redeemability; no mutation grant is obtained by this read.
	authenticated, authErr := s.Workers.authenticate(ctx, policy)
	if authErr == nil {
		s.Workers = authenticated
	}
	err := s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		r, e := nativePhaseLoadTx(ctx, tx, policy, id)
		if e != nil {
			return e
		}
		if !phaseCaller(r, caller) {
			return ErrCapacityMutationAuthorization
		}
		out = phaseContext(r)
		out.Redeemable = authErr == nil && r.Context.PhaseState == "issued" && s.currentPhase(ctx, tx, policy, p, r, now) == nil
		return nil
	})
	return out, err
}

func (s CapacityNativeWorkerPhaseStore) Redeem(ctx context.Context, policy model.Manifest, id uuid.UUID, caller model.CapacityNativeWorkerPhaseCaller) (model.CapacityNativeWorkerPhasePermit, error) {
	var out model.CapacityNativeWorkerPhasePermit
	authenticated, err := s.Workers.authenticate(ctx, policy)
	if err != nil {
		return out, err
	}
	s.Workers = authenticated
	err = s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		r, e := nativePhaseLoadTx(ctx, tx, policy, id)
		if e != nil {
			return e
		}
		if !phaseCaller(r, caller) {
			return ErrCapacityMutationAuthorization
		}
		if r.Context.PhaseState != "issued" {
			return ErrCapacityConflict
		}
		if e = s.currentPhase(ctx, tx, policy, p, r, now); e != nil {
			return e
		}
		nonce := make([]byte, 32)
		if _, e = rand.Read(nonce); e != nil {
			return e
		}
		token := base64.RawURLEncoding.EncodeToString(nonce)
		r.SettlementTokenSHA256 = fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
		r.Context.PhaseState = "redeemed"
		r.Revision++
		if e = nativePhaseWriteTx(ctx, tx, r, now); e != nil {
			return e
		}
		out = phaseContext(r)
		out.MutationPermitted, out.SettlementToken = true, token
		return nil
	})
	// A failed/unknown commit never returns a possibly consumed mutation token.
	if err != nil {
		return model.CapacityNativeWorkerPhasePermit{}, err
	}
	return out, nil
}

// A complete native Status failure is evidence of an atomic PATCH rejection.
// Ambiguous JSON, non-native error envelopes and truncated bytes stay unknown.
func nativePhaseDefinitiveNoEffect(code int, raw []byte) bool {
	if code != 409 && code != 422 {
		return false
	}
	var status struct {
		APIVersion string          `json:"apiVersion"`
		Kind       string          `json:"kind"`
		Metadata   json.RawMessage `json:"metadata"`
		Status     string          `json:"status"`
		Message    string          `json:"message,omitempty"`
		Reason     string          `json:"reason"`
		Details    json.RawMessage `json:"details,omitempty"`
		Code       int             `json:"code"`
	}
	if capacity.DecodeNativeCapacity(json.RawMessage(raw), &status) != nil || status.APIVersion != "v1" ||
		status.Kind != "Status" || status.Status != "Failure" || status.Code != code ||
		len(status.Metadata) == 0 || strings.TrimSpace(string(status.Metadata))[0] != '{' {
		return false
	}
	if len(status.Details) != 0 && string(status.Details) != "null" && strings.TrimSpace(string(status.Details))[0] != '{' {
		return false
	}
	return code == 409 && status.Reason == "Conflict" || code == 422 && status.Reason == "Invalid"
}

func (s CapacityNativeWorkerPhaseStore) Receive(ctx context.Context, policy model.Manifest, caller model.CapacityNativeWorkerPhaseCaller, received model.CapacityNativeWorkerPhaseReceive) (model.CapacityNativeWorkerPhasePermit, error) {
	var out model.CapacityNativeWorkerPhasePermit
	if len(received.OriginalReturn) > 2<<20 || received.SettlementToken == "" || received.HTTPStatus < 0 || received.HTTPStatus > 599 {
		return out, ErrCapacityConflict
	}
	err := s.Workers.tx(ctx, policy, func(tx *sql.Tx, _ model.CapacityPolicySpec, now time.Time) error {
		r, e := nativePhaseLoadTx(ctx, tx, policy, received.PermitID)
		if e != nil {
			return e
		}
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(received.SettlementToken)))
		if !phaseCaller(r, caller) || received.BindingName != r.Context.BindingName || subtle.ConstantTimeCompare([]byte(hash), []byte(r.SettlementTokenSHA256)) != 1 {
			return ErrCapacityMutationAuthorization
		}
		if r.Original != nil {
			if r.Original.HTTPStatus != received.HTTPStatus || r.Original.TransportCompleted != received.TransportCompleted || string(r.Original.OriginalReturn) != string(received.OriginalReturn) {
				return ErrCapacityConflict
			}
			out = phaseContext(r)
			return nil
		}
		if r.Context.PhaseState != "redeemed" && r.Context.PhaseState != "observed" {
			return ErrCapacityConflict
		}
		priorState := r.Context.PhaseState
		copyReturn := received
		copyReturn.SettlementToken = ""
		r.Original = &copyReturn
		r.ReceivedAt = &now
		r.Context.PhaseState = "unknown"
		if received.TransportCompleted && received.HTTPStatus >= 200 && received.HTTPStatus < 300 {
			r.Context.PhaseState = "received"
		}
		if received.TransportCompleted && nativePhaseDefinitiveNoEffect(received.HTTPStatus, received.OriginalReturn) {
			r.Context.PhaseState = "no_effect"
			r.NoEffectReason = "native_atomic_patch_rejected"
		}
		if priorState == "observed" {
			r.Context.PhaseState = priorState
		}
		r.Revision++
		if e = nativePhaseWriteTx(ctx, tx, r, now); e != nil {
			return e
		}
		out = phaseContext(r)
		return nil
	})
	return out, err
}

// Reconcile reads actual API state only. It preserves unknown original returns
// and never sends another PATCH, manufactures an ACK or drops a reservation.
func (s CapacityNativeWorkerPhaseStore) Reconcile(ctx context.Context, policy model.Manifest, id uuid.UUID, caller model.CapacityNativeWorkerPhaseCaller) (model.CapacityNativeWorkerPhasePermit, error) {
	context, e := s.Read(ctx, policy, id, caller)
	if e != nil {
		return context, e
	}
	if s.Runtime == nil {
		return context, ErrCapacityDisabled
	}
	observed, e := s.Runtime.ObservePhase(ctx, context)
	if e != nil {
		return context, e
	}
	err := s.Workers.tx(ctx, policy, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		r, e := nativePhaseLoadTx(ctx, tx, policy, id)
		if e != nil {
			return e
		}
		if !phaseCaller(r, caller) {
			return ErrCapacityMutationAuthorization
		}
		if r.Context.PhaseState == "observed" {
			context = phaseContext(r)
			return nil
		}
		if r.Context.PhaseState != "redeemed" && r.Context.PhaseState != "received" && r.Context.PhaseState != "unknown" {
			return ErrCapacityConflict
		}
		if !observed.Applied || r.MaxReadAgeSeconds < 1 || observed.ObservedAt.IsZero() || observed.ObservedAt.After(now) || now.Sub(observed.ObservedAt) > time.Duration(r.MaxReadAgeSeconds)*time.Second ||
			observed.RealmUID != r.Context.RealmUID || observed.PoolUID != r.Context.PoolUID || observed.Owner != r.Context.Owner || observed.Epoch != r.Context.Epoch || observed.RegistryUID != r.Context.Registry.UID || observed.NodeUID != r.Context.Node.UID || observed.ProviderID != r.Context.Node.ProviderID ||
			observed.RegistryResourceVersion == "" || !nativePhaseSHA.MatchString(observed.RegistrySHA256) {
			return ErrCapacityConflict
		}
		if r.Context.Action != "register" && observed.AdmissionReceiptSHA256 != r.Context.Admission.ReceiptSHA256 {
			return ErrCapacityConflict
		}
		if r.Context.Action == "release_quarantine" && (!observed.QuarantineAbsent || !observed.Ready) {
			return ErrCapacityConflict
		}
		r.Context.PhaseState = "observed"
		copyObservation := observed
		r.Observed = &copyObservation
		r.Revision++
		if e = nativePhaseWriteTx(ctx, tx, r, now); e != nil {
			return e
		}
		context = phaseContext(r)
		return nil
	})
	return context, err
}

// ResolvePhaseCaller joins an already authenticated machine identity to a
// private issuance. No request chooses a policy, namespace, version or proof.
func (s CapacityNativeWorkerPhaseStore) ResolvePhaseCaller(ctx context.Context, id uuid.UUID, binding, principalID, instanceID string) (model.Manifest, model.CapacityNativeWorkerPhaseCaller, error) {
	var policy model.Manifest
	var caller model.CapacityNativeWorkerPhaseCaller
	if s.Workers.Capacity.DB == nil {
		return policy, caller, ErrCapacityDisabled
	}
	var raw []byte
	if err := s.Workers.Capacity.DB.QueryRowContext(ctx, `SELECT record FROM public.capacity_native_worker_phase_permits WHERE id=$1`, id).Scan(&raw); err != nil {
		return policy, caller, ErrCapacityMutationAuthorization
	}
	var r nativeWorkerPhaseRecord
	if json.Unmarshal(raw, &r) != nil || r.Context.PermitID != id || r.Context.BindingName != binding ||
		r.Writer.BindingName != binding || r.Writer.PrincipalID != principalID || r.Writer.Adapter.ManifestID != instanceID {
		return policy, caller, ErrCapacityMutationAuthorization
	}
	var err error
	policy, err = GetManifestByID(ctx, s.Workers.Capacity.DB, r.Context.PolicyID)
	if err != nil || policy.Kind != "capacity_policy" {
		return model.Manifest{}, caller, ErrCapacityMutationAuthorization
	}
	caller = model.CapacityNativeWorkerPhaseCaller{Adapter: r.Writer.Adapter, PrincipalID: principalID, BindingName: binding, SourceCommit: r.Writer.SourceCommit}
	return policy, caller, nil
}
