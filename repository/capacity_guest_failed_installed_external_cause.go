package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// ADR-0091. An external-cause admission lets the failed-installed replacement
// gate accept the UNCHANGED blocked binding of exactly one terminal historical
// disposal (no replacement_mode). Its only proof of the Guest build is a peer
// Guest of the same build in a different dimension that reached an accepted
// canary read after the disposed Guest's original failed run finished and is
// still a current member of a promoted intent. The operator's cause evidence is
// opaque text with its SHA-256; Core never reads it as authority.
const (
	FailedInstalledExternalCauseSchema      = "failed_installed_external_cause_replacement_admission_v1"
	FailedInstalledExternalCauseReason      = "external_cause_same_build_replacement"
	FailedInstalledExternalCauseEvidenceMax = 8192
)

var (
	errFailedInstalledExternalCauseRequest = errors.New("closed external-cause replacement admission request required")
	failedInstalledExternalCauseIssuer     = regexp.MustCompile(`^collaborator:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	failedInstalledExternalCauseLockName   = regexp.MustCompile(`^[ -~]+$`)
)

// FailedInstalledExternalCauseReplacementRequest carries only identities and
// opaque evidence. Every build, binding, time and membership fact is derived.
type FailedInstalledExternalCauseReplacementRequest struct {
	PreregistrationID     string
	PeerPreregistrationID string
	CauseEvidence         string
	Issuer                string
}

type FailedInstalledExternalCauseAdmission struct {
	ID                          string    `json:"id"`
	Schema                      string    `json:"schema"`
	DisposalID                  string    `json:"disposal_id"`
	DisposalStage               string    `json:"disposal_stage"`
	PreregistrationID           string    `json:"preregistration_id"`
	Namespace                   string    `json:"namespace"`
	Environment                 string    `json:"environment"`
	Domain                      string    `json:"domain"`
	Dimension                   string    `json:"dimension"`
	BlockedGuestSource          string    `json:"blocked_guest_source"`
	BlockedProfileSHA256        string    `json:"blocked_profile_sha256"`
	AdmittedBindingSHA256       string    `json:"admitted_binding_sha256"`
	AdmittedPolicyID            string    `json:"admitted_policy_id"`
	AdmittedPolicyChecksum      string    `json:"admitted_policy_checksum"`
	OriginalFailedRunID         string    `json:"original_failed_run_id"`
	OriginalFailedRunFinishedAt time.Time `json:"original_failed_run_finished_at"`
	PeerPreregistrationID       string    `json:"peer_preregistration_id"`
	PeerNamespace               string    `json:"peer_namespace"`
	PeerEnvironment             string    `json:"peer_environment"`
	PeerDomain                  string    `json:"peer_domain"`
	PeerDimension               string    `json:"peer_dimension"`
	PeerGuestSource             string    `json:"peer_guest_source"`
	PeerProfileSHA256           string    `json:"peer_profile_sha256"`
	PeerReadChallengeID         string    `json:"peer_read_challenge_id"`
	PeerReadRecordedAt          time.Time `json:"peer_read_recorded_at"`
	PeerReadReturnRecordedAt    time.Time `json:"peer_read_return_recorded_at"`
	PeerIntentGeneration        int64     `json:"peer_intent_generation"`
	PeerIntentFencingToken      int64     `json:"peer_intent_fencing_token"`
	PeerResourceID              string    `json:"peer_resource_id"`
	AdmittingCoreSource         string    `json:"admitting_core_source"`
	Issuer                      string    `json:"issuer"`
	Reason                      string    `json:"reason"`
	CauseEvidenceSHA256         string    `json:"cause_evidence_sha256"`
	CauseEvidenceBytes          int       `json:"cause_evidence_bytes"`
	RecordedAt                  time.Time `json:"recorded_at"`
}

// guestBindingAuthority is the compiled-registry approval of a binding. The
// production path always passes capacity.GuestBindingAuthorityCurrent.
type guestBindingAuthority func(model.CapacityPolicySpec, model.CapacityGuestRetirementBinding) bool

// ValidFailedInstalledExternalCauseEvidence accepts non-empty valid UTF-8 of
// at most 8 KiB with no control character other than tab, CR and LF.
func ValidFailedInstalledExternalCauseEvidence(evidence string) bool {
	if evidence == "" || len(evidence) > FailedInstalledExternalCauseEvidenceMax || !utf8.ValidString(evidence) || strings.TrimSpace(evidence) == "" {
		return false
	}
	for _, r := range evidence {
		if (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			return false
		}
	}
	return true
}

func failedInstalledExternalCauseEvidenceSHA(evidence string) string {
	sum := sha256.Sum256([]byte(evidence))
	return hex.EncodeToString(sum[:])
}

func canonicalFailedInstalledUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func failedInstalledExternalCauseLockable(names ...string) bool {
	for _, n := range names {
		if !failedInstalledExternalCauseLockName.MatchString(n) || strings.ContainsAny(n, "<>&") {
			return false
		}
	}
	return true
}

// AdmitFailedInstalledExternalCauseReplacement records the ADR-0091 admission.
// It never moves an intent, fence, grant or slot and never calls a provider.
func (s CapacityStore) AdmitFailedInstalledExternalCauseReplacement(ctx context.Context, request FailedInstalledExternalCauseReplacementRequest) (FailedInstalledExternalCauseAdmission, error) {
	return s.admitFailedInstalledExternalCauseReplacement(ctx, request, capacity.CurrentGuestCoreSource(), capacity.GuestBindingAuthorityCurrent)
}

func (s CapacityStore) admitFailedInstalledExternalCauseReplacement(ctx context.Context, request FailedInstalledExternalCauseReplacementRequest, currentCore string, authority guestBindingAuthority) (FailedInstalledExternalCauseAdmission, error) {
	var out FailedInstalledExternalCauseAdmission
	if s.DB == nil || authority == nil || !canonicalFailedInstalledUUID(request.PreregistrationID) || !canonicalFailedInstalledUUID(request.PeerPreregistrationID) ||
		request.PreregistrationID == request.PeerPreregistrationID || !ValidFailedInstalledExternalCauseEvidence(request.CauseEvidence) ||
		!failedInstalledExternalCauseIssuer.MatchString(request.Issuer) || (currentCore != "" && !failedInstalledCoreSource.MatchString(currentCore)) {
		return out, errFailedInstalledExternalCauseRequest
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return out, err
	}

	// 1. The single disposal of the disposed preregistration: terminal, with an
	// immutable requested admission, both historical (no replacement_mode).
	var disposalID string
	if err = tx.QueryRowContext(ctx, `SELECT id::text FROM public.capacity_guest_failed_installed_disposals WHERE preregistration_id=$1 AND stage='terminal'`, request.PreregistrationID).Scan(&disposalID); err != nil {
		return out, ErrCapacityConflict
	}
	requested, _, err := loadFailedInstalledDisposalTx(ctx, tx, disposalID, "requested")
	if err != nil {
		return out, ErrCapacityConflict
	}
	terminal, _, err := loadFailedInstalledDisposalTx(ctx, tx, disposalID, "terminal")
	if err != nil {
		return out, ErrCapacityConflict
	}
	if requested.ReplacementMode != "" || terminal.ReplacementMode != "" || requested.PreregistrationID != request.PreregistrationID || terminal.PreregistrationID != request.PreregistrationID ||
		terminal.BlockedGuestSource != requested.BlockedGuestSource || terminal.BlockedProfileSHA256 != requested.BlockedProfileSHA256 ||
		terminal.Namespace != requested.Namespace || terminal.Environment != requested.Environment || terminal.Domain != requested.Domain || terminal.Dimension != requested.Dimension ||
		!failedInstalledExternalCauseLockable(requested.Namespace, requested.Environment, requested.Domain, requested.Dimension) {
		return out, ErrCapacityConflict
	}
	scope := model.CapacityPolicySpec{Environment: requested.Environment, Domain: requested.Domain, Dimension: requested.Dimension}
	if err = lockMutationScope(ctx, tx, requested.Namespace, scope); err != nil {
		return out, err
	}
	var existing int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_failed_installed_external_cause_admissions WHERE disposal_id=$1 OR preregistration_id=$2`, disposalID, request.PreregistrationID).Scan(&existing); err != nil {
		return out, err
	}
	if existing != 0 {
		return out, ErrCapacityConflict
	}
	current, err := loadCapacityIntent(ctx, tx, requested.Namespace, scope, true)
	if err != nil || current.FailedInstalledDisposal == nil || current.FailedInstalledDisposal.ID != disposalID || current.FailedInstalledDisposal.Stage != "terminal" ||
		current.FailedInstalledDisposal.PreregistrationID != request.PreregistrationID {
		return out, ErrCapacityConflict
	}

	// 2. The disposed Guest's own original failed run and its finish time.
	var originalRun struct {
		ID uuid.UUID `json:"id"`
	}
	if json.Unmarshal([]byte(requested.OriginalRun), &originalRun) != nil || originalRun.ID == uuid.Nil {
		return out, ErrCapacityConflict
	}
	var runWire string
	var finishedAt time.Time
	if err = tx.QueryRowContext(ctx, `SELECT row_to_json(w)::text,w.finished_at FROM public.workflow_runs w WHERE w.id=$1 AND w.status='failed' AND w.finished_at IS NOT NULL FOR SHARE`, originalRun.ID).Scan(&runWire, &finishedAt); err != nil ||
		capacity.BusinessCreationSHA256([]byte(runWire)) != capacity.BusinessCreationSHA256([]byte(requested.OriginalRun)) {
		return out, ErrCapacityConflict
	}

	// 3. The blocked build is the disposed Guest's own binding, and the current
	// policy of that dimension carries it unchanged with its compiled approval.
	disposed, err := loadGuestOriginalTx(ctx, tx, request.PreregistrationID)
	if err != nil || disposed.binding.GuestSourceCommit != requested.BlockedGuestSource || disposed.binding.ProfileManifestSHA256 != requested.BlockedProfileSHA256 {
		return out, ErrCapacityConflict
	}
	policy, p, err := failedInstalledExternalCauseCurrentPolicyTx(ctx, tx, disposed.pre.PolicyID, requested)
	if err != nil {
		return out, err
	}
	// The admitted digest is the SHA-256 of the disposed Guest's own stored
	// binding_wire, the same digest migration 85 re-derives in SQL; the gate
	// later re-reads that wire and requires the policy binding to equal it.
	disposedWire, err := failedInstalledExternalCauseBindingWireTx(ctx, tx, request.PreregistrationID)
	if err != nil {
		return out, ErrCapacityConflict
	}
	binding := p.GuestRetirementBinding
	if binding == nil || p.GuestNotifyReconcileBinding == nil || !failedInstalledExternalCauseBindingAdmitted(binding, requested, originalDispositionDigest(disposedWire), disposedWire) || binding.GuestSourceCommit != requested.BlockedGuestSource || binding.ProfileManifestSHA256 != requested.BlockedProfileSHA256 ||
		!reflect.DeepEqual(*binding, disposed.binding) || !authority(p, *binding) {
		return out, ErrCapacityConflict
	}

	// 4. The peer: a different dimension, the same Guest build, an accepted read
	// after the original failure, and still a member of a promoted intent.
	peer, err := loadGuestOriginalTx(ctx, tx, request.PeerPreregistrationID)
	if err != nil || peer.binding.GuestSourceCommit != requested.BlockedGuestSource {
		return out, ErrCapacityConflict
	}
	if err = loadGuestWitnessTx(ctx, tx, &peer); err != nil {
		return out, ErrCapacityConflict
	}
	if _, _, err = loadGuestReceiptTx(ctx, tx, request.PeerPreregistrationID); err != nil {
		return out, ErrCapacityConflict
	}
	peerNamespace, peerP, err := failedInstalledExternalCausePeerPolicyTx(ctx, tx, peer)
	if err != nil {
		return out, err
	}
	if peerNamespace == requested.Namespace && peerP.Environment == requested.Environment && peerP.Domain == requested.Domain && peerP.Dimension == requested.Dimension {
		return out, ErrCapacityConflict
	}
	var grantNamespace, grantEnvironment, grantDomain, grantDimension string
	if err = tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension FROM public.capacity_mutation_grants WHERE id=$1 FOR SHARE`, peer.pre.OriginalCreateGrantID).Scan(&grantNamespace, &grantEnvironment, &grantDomain, &grantDimension); err != nil ||
		grantNamespace != peerNamespace || grantEnvironment != peerP.Environment || grantDomain != peerP.Domain || grantDimension != peerP.Dimension {
		return out, ErrCapacityConflict
	}
	var peerIntentRaw []byte
	if err = tx.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR SHARE`, peerNamespace, peerP.Environment, peerP.Domain, peerP.Dimension).Scan(&peerIntentRaw); err != nil {
		return out, ErrCapacityConflict
	}
	var peerIntent model.CapacityIntent
	if json.Unmarshal(peerIntentRaw, &peerIntent) != nil || peerIntent.Phase != "promoted" || peerIntent.FailedInstalledDisposal != nil ||
		peerIntent.Generation < peer.pre.Generation || peerIntent.Generation < 1 || peerIntent.FencingToken < 1 || peerIntent.FencingToken >= maxCapacityGeneration {
		return out, ErrCapacityConflict
	}
	if err = failedInstalledExternalCausePeerMemberTx(ctx, tx, peerNamespace, peerP, peer); err != nil {
		return out, err
	}
	readID, readAt, returnAt, err := failedInstalledExternalCausePeerReadTx(ctx, tx, peer, finishedAt)
	if err != nil {
		return out, err
	}

	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return out, err
	}
	out = FailedInstalledExternalCauseAdmission{
		ID: uuid.NewString(), Schema: FailedInstalledExternalCauseSchema, DisposalID: disposalID, DisposalStage: "terminal", PreregistrationID: request.PreregistrationID,
		Namespace: requested.Namespace, Environment: requested.Environment, Domain: requested.Domain, Dimension: requested.Dimension,
		BlockedGuestSource: requested.BlockedGuestSource, BlockedProfileSHA256: requested.BlockedProfileSHA256,
		AdmittedBindingSHA256: originalDispositionDigest(disposedWire), AdmittedPolicyID: policy.ID.String(), AdmittedPolicyChecksum: policy.Checksum,
		OriginalFailedRunID: originalRun.ID.String(), OriginalFailedRunFinishedAt: finishedAt.UTC(),
		PeerPreregistrationID: request.PeerPreregistrationID, PeerNamespace: peerNamespace, PeerEnvironment: peerP.Environment, PeerDomain: peerP.Domain, PeerDimension: peerP.Dimension,
		PeerGuestSource: peer.binding.GuestSourceCommit, PeerProfileSHA256: peer.binding.ProfileManifestSHA256,
		PeerReadChallengeID: readID, PeerReadRecordedAt: readAt.UTC(), PeerReadReturnRecordedAt: returnAt.UTC(),
		PeerIntentGeneration: peerIntent.Generation, PeerIntentFencingToken: peerIntent.FencingToken, PeerResourceID: peer.witness.Tuple.ResourceID,
		AdmittingCoreSource: currentCore, Issuer: request.Issuer, Reason: FailedInstalledExternalCauseReason,
		CauseEvidenceSHA256: failedInstalledExternalCauseEvidenceSHA(request.CauseEvidence), CauseEvidenceBytes: len(request.CauseEvidence), RecordedAt: now.UTC(),
	}
	if !capacity.ValidDigest(out.AdmittedBindingSHA256) {
		return FailedInstalledExternalCauseAdmission{}, ErrCapacityConflict
	}
	if err = insertFailedInstalledExternalCauseAdmissionTx(ctx, tx, out, request.CauseEvidence); err != nil {
		return FailedInstalledExternalCauseAdmission{}, err
	}
	if err = tx.Commit(); err != nil {
		return FailedInstalledExternalCauseAdmission{}, err
	}
	return out, nil
}

// The INSERT guard (migration 85) re-derives every row fact recorded here.
func insertFailedInstalledExternalCauseAdmissionTx(ctx context.Context, tx *sql.Tx, out FailedInstalledExternalCauseAdmission, evidence string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_failed_installed_external_cause_admissions(
 id,schema,disposal_id,disposal_stage,preregistration_id,namespace,environment,domain,dimension,blocked_guest_source,blocked_profile_sha256,
 admitted_binding_sha256,admitted_policy_id,admitted_policy_checksum,original_failed_run_id,original_failed_run_finished_at,
 peer_preregistration_id,peer_namespace,peer_environment,peer_domain,peer_dimension,peer_guest_source,peer_profile_sha256,
 peer_read_challenge_id,peer_read_recorded_at,peer_read_return_recorded_at,peer_intent_generation,peer_intent_fencing_token,peer_resource_id,
 admitting_core_source,issuer,reason,cause_evidence,cause_evidence_sha256,original_failure_preserved,original_failure_cause_claimed_by_core,recorded_at)
 VALUES($1,$2,$3,'terminal',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,true,false,$34)`,
		out.ID, out.Schema, out.DisposalID, out.PreregistrationID, out.Namespace, out.Environment, out.Domain, out.Dimension, out.BlockedGuestSource, out.BlockedProfileSHA256,
		out.AdmittedBindingSHA256, out.AdmittedPolicyID, out.AdmittedPolicyChecksum, out.OriginalFailedRunID, out.OriginalFailedRunFinishedAt,
		out.PeerPreregistrationID, out.PeerNamespace, out.PeerEnvironment, out.PeerDomain, out.PeerDimension, out.PeerGuestSource, out.PeerProfileSHA256,
		out.PeerReadChallengeID, out.PeerReadRecordedAt, out.PeerReadReturnRecordedAt, out.PeerIntentGeneration, out.PeerIntentFencingToken, out.PeerResourceID,
		out.AdmittingCoreSource, out.Issuer, out.Reason, evidence, out.CauseEvidenceSHA256, out.RecordedAt)
	return err
}

// The current policy of the disposal's dimension is the single active version
// of the policy that admitted the disposed Guest. Its scope must be the
// disposal's scope; a renamed or duplicated active policy refuses.
func failedInstalledExternalCauseCurrentPolicyTx(ctx context.Context, tx *sql.Tx, originalPolicyID string, r FailedInstalledGuestDisposal) (model.Manifest, model.CapacityPolicySpec, error) {
	var policy model.Manifest
	var p model.CapacityPolicySpec
	var namespace, name string
	if err := tx.QueryRowContext(ctx, `SELECT namespace,name FROM public.manifests WHERE id=$1 AND kind='capacity_policy'`, originalPolicyID).Scan(&namespace, &name); err != nil || namespace != r.Namespace {
		return policy, p, ErrCapacityConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,version,checksum,spec FROM public.manifests WHERE kind='capacity_policy' AND namespace=$1 AND name=$2 AND active ORDER BY version FOR SHARE`, namespace, name)
	if err != nil {
		return policy, p, err
	}
	count := 0
	for rows.Next() {
		count++
		if err = rows.Scan(&policy.ID, &policy.Version, &policy.Checksum, &policy.Spec); err != nil {
			break
		}
	}
	rowErr, closeErr := rows.Err(), rows.Close()
	if err != nil || rowErr != nil || closeErr != nil || count != 1 {
		return policy, p, ErrCapacityConflict
	}
	policy.Kind = "capacity_policy"
	policy.Metadata.Namespace, policy.Metadata.Name = namespace, name
	p, err = parseCapacityPolicy(policy)
	if err != nil || p.Environment != r.Environment || p.Domain != r.Domain || p.Dimension != r.Dimension {
		return policy, p, ErrCapacityConflict
	}
	return policy, p, nil
}

// The peer's scope is the exact policy revision that admitted its Guest.
func failedInstalledExternalCausePeerPolicyTx(ctx context.Context, tx *sql.Tx, peer guestOriginalStored) (string, model.CapacityPolicySpec, error) {
	var policy model.Manifest
	var p model.CapacityPolicySpec
	var err error
	policy.ID, err = uuid.Parse(peer.pre.PolicyID)
	if err != nil {
		return "", p, ErrCapacityConflict
	}
	policy.Kind = "capacity_policy"
	if err = tx.QueryRowContext(ctx, `SELECT namespace,name,version,checksum,spec FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND checksum=$2 FOR SHARE`, policy.ID, peer.pre.PolicyChecksum).Scan(&policy.Metadata.Namespace, &policy.Metadata.Name, &policy.Version, &policy.Checksum, &policy.Spec); err != nil {
		return "", p, ErrCapacityConflict
	}
	p, err = parseCapacityPolicy(policy)
	if err != nil {
		return "", p, ErrCapacityConflict
	}
	return policy.Metadata.Namespace, p, nil
}

// A current member is read from Core's own durable state only: the enrolled
// tuple still occupies its non-tombstone slot, and it has neither a retirement
// intent nor a failed-installed disposal. No provider is read.
func failedInstalledExternalCausePeerMemberTx(ctx context.Context, tx *sql.Tx, namespace string, p model.CapacityPolicySpec, peer guestOriginalStored) error {
	b, err := capacity.VMObservationBinding(p, peer.binding.MutationBindingName)
	if err != nil || peer.witness.Tuple.ResourceID == "" {
		return ErrCapacityConflict
	}
	var ns, env, domain, dimension string
	var raw []byte
	if err = tx.QueryRowContext(ctx, `SELECT namespace,environment,domain,dimension,slot_record FROM public.capacity_resource_slots WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4 FOR SHARE`, b.IntegrationInstanceID, b.ScopeChecksum, b.ProfileName, peer.pre.Slot).Scan(&ns, &env, &domain, &dimension, &raw); err != nil {
		return ErrCapacityConflict
	}
	var slot capacityResourceSlot
	if ns != namespace || env != p.Environment || domain != p.Domain || dimension != p.Dimension || json.Unmarshal(raw, &slot) != nil ||
		slot.Tombstone || slot.ResourceID != peer.witness.Tuple.ResourceID || slot.ResourceCreatedAt != peer.witness.Tuple.CreatedAt {
		return ErrCapacityConflict
	}
	var retired, disposed int
	if err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_vm_retirement_intents WHERE preregistration_id=$1),(SELECT count(*) FROM public.capacity_guest_failed_installed_disposals WHERE preregistration_id=$1)`, peer.pre.PreregistrationID).Scan(&retired, &disposed); err != nil {
		return err
	}
	if retired != 0 || disposed != 0 {
		return ErrCapacityConflict
	}
	return nil
}

// The first accepted peer read whose challenge AND accepted return were both
// recorded strictly after the original failed run finished. The stored signed
// challenge must belong to the peer's own lifetime and Guest profile.
func failedInstalledExternalCausePeerReadTx(ctx context.Context, tx *sql.Tx, peer guestOriginalStored, finishedAt time.Time) (string, time.Time, time.Time, error) {
	var id string
	var readAt, returnAt time.Time
	if err := tx.QueryRowContext(ctx, `SELECT c.id::text,c.recorded_at,x.recorded_at FROM public.capacity_guest_notify_canary_challenges c
 JOIN public.capacity_guest_notify_canary_returns x ON x.challenge_id=c.id AND x.outcome='accepted'
 WHERE c.preregistration_id=$1 AND c.phase='read' AND c.recorded_at>$2 AND x.recorded_at>$2
 ORDER BY x.recorded_at,c.id LIMIT 1`, peer.pre.PreregistrationID, finishedAt).Scan(&id, &readAt, &returnAt); err != nil {
		return "", readAt, returnAt, ErrCapacityConflict
	}
	read, err := loadGuestNotifyPreflightTx(ctx, tx, id)
	if err != nil || read.ChallengeID != id || read.PreregistrationID != peer.pre.PreregistrationID || read.PolicyID != peer.pre.PolicyID ||
		read.ProfileManifestSHA256 != peer.binding.ProfileManifestSHA256 || read.Tuple != peer.witness.Tuple || read.Generation < 1 {
		return "", readAt, returnAt, ErrCapacityConflict
	}
	return id, readAt, returnAt, nil
}

// failedInstalledExternalCauseAdmittedTx reports whether the ADR-0091
// admission of this exact historical disposal names exactly this binding.
// Absence is false; a malformed or divergent row is a conflict.
func failedInstalledExternalCauseAdmittedTx(ctx context.Context, tx *sql.Tx, r FailedInstalledGuestDisposal, binding *model.CapacityGuestRetirementBinding) (bool, error) {
	if binding == nil || r.ReplacementMode != "" {
		return false, nil
	}
	var pre, namespace, environment, domain, dimension, source, profile, bindingSHA string
	err := tx.QueryRowContext(ctx, `SELECT preregistration_id::text,namespace,environment,domain,dimension,blocked_guest_source,blocked_profile_sha256,admitted_binding_sha256 FROM public.capacity_guest_failed_installed_external_cause_admissions WHERE disposal_id=$1 AND disposal_stage='terminal' FOR SHARE`, r.ID).Scan(&pre, &namespace, &environment, &domain, &dimension, &source, &profile, &bindingSHA)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if pre != r.PreregistrationID || namespace != r.Namespace || environment != r.Environment || domain != r.Domain || dimension != r.Dimension ||
		source != r.BlockedGuestSource || profile != r.BlockedProfileSHA256 {
		return false, ErrCapacityConflict
	}
	wire, err := failedInstalledExternalCauseBindingWireTx(ctx, tx, r.PreregistrationID)
	if err != nil {
		return false, ErrCapacityConflict
	}
	return failedInstalledExternalCauseBindingAdmitted(binding, r, bindingSHA, wire), nil
}

// The disposed Guest's own stored binding bytes, exactly as preregistered.
func failedInstalledExternalCauseBindingWireTx(ctx context.Context, tx *sql.Tx, preID string) ([]byte, error) {
	var wire []byte
	if err := tx.QueryRowContext(ctx, `SELECT binding_wire FROM public.capacity_vm_provisioning_preregistrations WHERE id=$1 AND binding_wire IS NOT NULL FOR SHARE`, preID).Scan(&wire); err != nil {
		return nil, err
	}
	return wire, nil
}

// Only the exact unchanged blocked binding is admitted: same Guest source,
// same profile SHA, and equal to the disposed Guest's stored binding_wire
// whose SHA-256 is the admitted digest (migration 85 re-derives that digest
// from the same bytes, so a row cannot name any other binding).
func failedInstalledExternalCauseBindingAdmitted(binding *model.CapacityGuestRetirementBinding, r FailedInstalledGuestDisposal, admittedBindingSHA string, disposedWire []byte) bool {
	if binding == nil || r.ReplacementMode != "" || !capacity.ValidDigest(admittedBindingSHA) || len(disposedWire) == 0 ||
		originalDispositionDigest(disposedWire) != admittedBindingSHA ||
		binding.GuestSourceCommit != r.BlockedGuestSource || binding.ProfileManifestSHA256 != r.BlockedProfileSHA256 {
		return false
	}
	var disposed model.CapacityGuestRetirementBinding
	return capacity.DecodeGuestLifecycle(disposedWire, &disposed) == nil && reflect.DeepEqual(*binding, disposed)
}

// ReadFailedInstalledExternalCauseAdmission returns the admission of one
// disposed preregistration without its evidence body.
func (s CapacityStore) ReadFailedInstalledExternalCauseAdmission(ctx context.Context, preID string) (FailedInstalledExternalCauseAdmission, error) {
	var v FailedInstalledExternalCauseAdmission
	if s.DB == nil || !canonicalFailedInstalledUUID(preID) {
		return v, errFailedInstalledExternalCauseRequest
	}
	err := s.DB.QueryRowContext(ctx, `SELECT id::text,schema,disposal_id::text,disposal_stage,preregistration_id::text,namespace,environment,domain,dimension,
 blocked_guest_source,blocked_profile_sha256,admitted_binding_sha256,admitted_policy_id::text,admitted_policy_checksum,original_failed_run_id::text,original_failed_run_finished_at,
 peer_preregistration_id::text,peer_namespace,peer_environment,peer_domain,peer_dimension,peer_guest_source,peer_profile_sha256,
 peer_read_challenge_id::text,peer_read_recorded_at,peer_read_return_recorded_at,peer_intent_generation,peer_intent_fencing_token,peer_resource_id,
 admitting_core_source,issuer,reason,cause_evidence_sha256,octet_length(cause_evidence),recorded_at
 FROM public.capacity_guest_failed_installed_external_cause_admissions WHERE preregistration_id=$1`, preID).Scan(
		&v.ID, &v.Schema, &v.DisposalID, &v.DisposalStage, &v.PreregistrationID, &v.Namespace, &v.Environment, &v.Domain, &v.Dimension,
		&v.BlockedGuestSource, &v.BlockedProfileSHA256, &v.AdmittedBindingSHA256, &v.AdmittedPolicyID, &v.AdmittedPolicyChecksum, &v.OriginalFailedRunID, &v.OriginalFailedRunFinishedAt,
		&v.PeerPreregistrationID, &v.PeerNamespace, &v.PeerEnvironment, &v.PeerDomain, &v.PeerDimension, &v.PeerGuestSource, &v.PeerProfileSHA256,
		&v.PeerReadChallengeID, &v.PeerReadRecordedAt, &v.PeerReadReturnRecordedAt, &v.PeerIntentGeneration, &v.PeerIntentFencingToken, &v.PeerResourceID,
		&v.AdmittingCoreSource, &v.Issuer, &v.Reason, &v.CauseEvidenceSHA256, &v.CauseEvidenceBytes, &v.RecordedAt)
	return v, err
}
