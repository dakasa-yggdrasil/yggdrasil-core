//go:build linux && nativequalification

package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"reflect"
	"time"
)

type CanonicalPostlossFreshFailureRead struct {
	Schema                       string                                       `json:"schema"`
	Scope                        string                                       `json:"scope"`
	NativeCase                   string                                       `json:"native_case"`
	SourceCommit                 string                                       `json:"source_commit"`
	PreregistrationID            string                                       `json:"preregistration_id"`
	FailureSHA256                string                                       `json:"failure_sha256"`
	ReadNonceSHA256              string                                       `json:"read_nonce_sha256"`
	ReadStartedAt                time.Time                                    `json:"read_started_at"`
	Census                       model.CapacityGuestRetirementProtectedCensus `json:"census"`
	ReturnedAt                   time.Time                                    `json:"returned_at"`
	OriginalProvisioningDeadline time.Time                                    `json:"original_provisioning_deadline"`
	ProducerPublicKey            string                                       `json:"producer_public_key"`
	Signature                    string                                       `json:"signature"`
}

// A revision appends authentic current reads. It does not rewrite the old
// failure/eligibility, old child, accepted/uncertain settlement or any clock.
func (s CapacityStore) PrepareCanonicalPostlossReadChallenge(ctx context.Context, policy model.Manifest, parentID, oldID, nonceSHA string) error {
	return s.compensationTransaction(ctx, policy, false, func(tx *sql.Tx, p model.CapacityPolicySpec, now time.Time) error {
		e, handled, err := s.canonicalEligibilityTx(ctx, tx, parentID, now)
		if !handled || err != nil || !canonicalPostlossCase(e.NativeCase) || !capacity.ValidDigest(nonceSHA) {
			return ErrCapacityConflict
		}
		old, err := loadCompensationRecord(ctx, tx, policy, p, oldID)
		if err != nil {
			return err
		}
		if !postlossUnusedExpiredChild(old, parentID, s.ExecutorID, now) {
			return ErrCapacityConflict
		}
		_, b, t, err := canonicalCleanupHistory(ctx, s, tx, e.PreregistrationID)
		if err != nil || t.TerminalSHA256 != "" || !now.Before(b.CleanupDeadline) || !now.Before(b.OriginalProvisioningDeadline) {
			return ErrCapacityConflict
		}
		if _, err = tx.ExecContext(ctx, `CREATE TABLE public.capacity_canonical_postloss_read_challenges(parent_grant_id uuid PRIMARY KEY,expired_child_id uuid UNIQUE NOT NULL,nonce_sha256 text UNIQUE NOT NULL,prepared_at timestamptz NOT NULL);CREATE TRIGGER postloss_challenge_immutable BEFORE UPDATE OR DELETE ON public.capacity_canonical_postloss_read_challenges FOR EACH ROW EXECUTE FUNCTION public.postloss_original_immutable()`); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_canonical_postloss_read_challenges VALUES($1,$2,$3,$4)`, parentID, oldID, nonceSHA, now)
		return err
	})
}
func (s CapacityStore) AppendCanonicalPostlossFreshRead(ctx context.Context, policy model.Manifest, parentID, expiredChildID, nonceSHA string, nativeWire, failureWire []byte) (CanonicalSourceEligibility, error) {
	var e CanonicalSourceEligibility
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return e, err
	}
	defer tx.Rollback()
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return e, err
	}
	if err = lockMutationScope(ctx, tx, policy.Metadata.Namespace, p); err != nil {
		return e, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return e, err
	}
	e, handled, err := s.canonicalEligibilityTx(ctx, tx, parentID, now)
	if !handled || err != nil || !canonicalPostlossCase(e.NativeCase) {
		return e, ErrCapacityConflict
	}
	parent, err := loadCompensationRecord(ctx, tx, policy, p, parentID)
	if err != nil {
		return e, err
	}
	old, err := loadCompensationRecord(ctx, tx, policy, p, expiredChildID)
	if err != nil {
		return e, err
	}
	if parent.Grant.State != "compensating" || !postlossUnusedExpiredChild(old, parentID, s.ExecutorID, now) || old.PolicyID != policy.ID || old.PolicyChecksum != policy.Checksum || old.ExecutorID != s.ExecutorID {
		return e, ErrCapacityConflict
	}
	var preparedAt time.Time
	if err = tx.QueryRowContext(ctx, `SELECT prepared_at FROM public.capacity_canonical_postloss_read_challenges WHERE parent_grant_id=$1 AND expired_child_id=$2 AND nonce_sha256=$3`, parentID, expiredChildID, nonceSHA).Scan(&preparedAt); err != nil || preparedAt.Before(old.Grant.ExpiresAt) || preparedAt.After(now) {
		return e, ErrCapacityConflict
	}
	stored, b, terminal, err := canonicalCleanupHistory(ctx, s, tx, e.PreregistrationID)
	if err != nil || terminal.TerminalSHA256 != "" || !now.Before(b.CleanupDeadline) || !now.Before(b.OriginalProvisioningDeadline) {
		return e, ErrCapacityConflict
	}
	current, err := loadCapacityIntent(ctx, tx, policy.Metadata.Namespace, p, true)
	if err != nil {
		return e, err
	}
	owner := s
	owner.ExecutorID = parent.ExecutorID
	if err = owner.checkLease(p, policy, &current, parent.Generation, parent.FencingToken, parent.LeaseOwner, now); err != nil {
		return e, err
	}
	var native struct {
		Schema                               string          `json:"schema"`
		OriginalCreatorSHA256                string          `json:"original_creator_sha256"`
		Original                             json.RawMessage `json:"original"`
		Before                               json.RawMessage `json:"before"`
		After                                json.RawMessage `json:"after"`
		QMPPeerPID                           int32           `json:"qmp_peer_pid"`
		ExecutableSHA256                     string          `json:"executable_sha256"`
		CommandLineSHA256                    string          `json:"command_line_sha256"`
		OriginalDisk                         json.RawMessage `json:"original_disk"`
		OriginalDiskFD                       int             `json:"original_disk_fd"`
		OriginalDiskReadReturnedAt           time.Time       `json:"original_disk_read_returned_at"`
		OriginalDiskDirectoryCloseReturnedAt time.Time       `json:"original_disk_directory_close_returned_at"`
		UUID                                 json.RawMessage `json:"uuid"`
		Status                               json.RawMessage `json:"status"`
		StartedAt                            time.Time       `json:"started_at"`
		ReadReturnedAt                       time.Time       `json:"read_returned_at"`
		CloseReturnedAt                      time.Time       `json:"close_returned_at"`
		IO                                   json.RawMessage `json:"io"`
	}
	// Decode the same original native schema without importing provider package
	// (which already imports repository). Exact original stable identity is
	// checked against the immutable original native row, all refreshed IO is real.
	if capacity.DecodeGuestLifecycle(nativeWire, &native) != nil || native.Schema != "core_independent_original_qemu_read_v1" || native.OriginalCreatorSHA256 != b.CreatorSHA256 || native.StartedAt.IsZero() || native.ReadReturnedAt.Before(native.StartedAt) || native.CloseReturnedAt.Before(native.ReadReturnedAt) || !capacity.Fresh(native.CloseReturnedAt, now, p.MaxEvidenceAgeSeconds) {
		return e, ErrCapacityConflict
	}
	var originalNativeWire []byte
	if err = tx.QueryRowContext(ctx, `SELECT original_wire FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1 AND native_stage='native_read'`, e.PreregistrationID).Scan(&originalNativeWire); err != nil {
		return e, err
	}
	var prior map[string]json.RawMessage
	if json.Unmarshal(originalNativeWire, &prior) != nil {
		return e, ErrCapacityConflict
	}
	for key, raw := range map[string]json.RawMessage{"original": native.Original, "original_disk": native.OriginalDisk} {
		var a, c any
		if json.Unmarshal(raw, &a) != nil || json.Unmarshal(prior[key], &c) != nil || !reflect.DeepEqual(a, c) {
			return e, ErrCapacityConflict
		}
	}

	for _, raw := range []json.RawMessage{native.Before, native.After} {
		var actual, original struct {
			PID        int    `json:"pid"`
			PPID       int    `json:"ppid"`
			StartTicks uint64 `json:"start_ticks"`
			StatSHA256 string `json:"stat_sha256"`
		}
		if json.Unmarshal(raw, &actual) != nil || json.Unmarshal(prior["after"], &original) != nil || actual.PID != original.PID || actual.PPID != original.PPID || actual.StartTicks != original.StartTicks || !capacity.ValidDigest(actual.StatSHA256) {
			return e, ErrCapacityConflict
		}
	}
	var fresh CanonicalPostlossFreshFailureRead
	if capacity.DecodeGuestLifecycle(failureWire, &fresh) != nil || !postlossFreshFailureMatches(fresh, e, b, nonceSHA, now, p.MaxEvidenceAgeSeconds) {
		return e, ErrCapacityConflict
	}
	sig := fresh.Signature
	fresh.Signature = ""
	if fresh.ProducerPublicKey != stored.binding.ProvisionerPublicKey || !capacity.GuestQualificationSignature(stored.binding.ProvisionerPublicKey, sig, fresh) {
		return e, ErrCapacityConflict
	}
	// Current proof freshness is the later, actually returned independent
	// native observation. The two original action returns remain historical.
	observed := native.CloseReturnedAt
	if fresh.ReturnedAt.Before(observed) {
		observed = fresh.ReturnedAt
	}
	e.Aggregate.ObservedAt = observed
	e.Aggregate.ReceiptRef = "canonical-postloss-current:" + nonceSHA
	if !validFailedCreationProof(p, parent, e.Aggregate, now) {
		return e, ErrCapacityConflict
	}
	wire, err := canonicalSign(ctx, s, stored, e)
	if err != nil {
		return e, err
	}
	if _, err = tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS public.capacity_canonical_postloss_fresh_reads(read_id uuid PRIMARY KEY,parent_grant_id uuid UNIQUE NOT NULL,expired_child_id uuid UNIQUE NOT NULL,prior_eligibility_sha256 text NOT NULL,eligibility_wire bytea NOT NULL,eligibility_sha256 text UNIQUE NOT NULL,native_wire bytea NOT NULL,failure_read_wire bytea NOT NULL,observed_at timestamptz NOT NULL); DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='postloss_fresh_read_immutable') THEN CREATE TRIGGER postloss_fresh_read_immutable BEFORE UPDATE OR DELETE ON public.capacity_canonical_postloss_fresh_reads FOR EACH ROW EXECUTE FUNCTION public.postloss_original_immutable(); END IF; END $$`); err != nil {
		return e, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_canonical_postloss_fresh_reads VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, uuid.NewString(), parentID, expiredChildID, e.EligibilityWireSHA256, wire, capacity.BusinessCreationSHA256(wire), nativeWire, failureWire, now); err != nil {
		return e, err
	}
	e.EligibilityWireSHA256 = capacity.BusinessCreationSHA256(wire)
	return e, tx.Commit()
}

func postlossUnusedExpiredChild(old capacityMutationRecord, parentID, executor string, now time.Time) bool {
	return old.Grant.CompensationOf == parentID && old.Grant.State == "expired" && old.AttemptID == "" && old.SettlementTokenSHA256 == "" && old.Settlement == nil && old.Proof == nil && old.ExecutorID == executor && !old.Grant.ExpiresAt.IsZero() && !now.Before(old.Grant.ExpiresAt)
}

func postlossFreshFailureMatches(fresh CanonicalPostlossFreshFailureRead, e CanonicalSourceEligibility, b SourceFailureCleanupBody, nonceSHA string, now time.Time, maxAge int) bool {
	return !(fresh.Schema != "canonical_postloss_fresh_failure_read_v1" || fresh.Scope != "READONLY_CURRENT_CENSUS_OLD_FAILURE_UNCHANGED_NOT_QUIESCENCE" || fresh.NativeCase != e.NativeCase || fresh.SourceCommit != e.GuestSource || fresh.PreregistrationID != e.PreregistrationID || fresh.FailureSHA256 != e.FailureSHA256 || fresh.ReadNonceSHA256 != nonceSHA || !capacity.ValidDigest(nonceSHA) || len(fresh.Census.Processes) != 0 || fresh.Census.Schema != "guest_retirement_protected_cgroup_v1" || fresh.Census.Scope != "fixed_protected_cgroup_v2" || !capacity.ValidDigest(fresh.Census.RawCensusSHA256) || fresh.Census.SourceCommit != e.GuestSource || fresh.ReadStartedAt.IsZero() || fresh.Census.ObservedAt.Before(fresh.ReadStartedAt) || fresh.ReturnedAt.Before(fresh.Census.ObservedAt) || !fresh.ReturnedAt.Before(b.OriginalProvisioningDeadline) || !fresh.OriginalProvisioningDeadline.Equal(b.OriginalProvisioningDeadline) || !capacity.Fresh(fresh.ReturnedAt, now, maxAge))
}
