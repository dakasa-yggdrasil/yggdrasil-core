package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const (
	CapacityDispatchSupersededHTTPMaintenanceState      = "superseded_http_maintenance_disposed"
	CapacityDispatchSupersededHTTPMaintenanceReason     = "superseded_equivalent_policy_http_maintenance_dispatch_disposed"
	CapacityDispatchSupersededHTTPMaintenanceScanSchema = "superseded_equivalent_policy_http_maintenance_dispatch_effect_scan_v1"
	capacityDispatchSupersededHTTPMaintenanceError      = "capacity dispatch original workflow returned error"
)

var ErrCapacityDispatchSupersededHTTPMaintenanceDisposition = errors.New("superseded equivalent-policy HTTP maintenance disposition refused")

// All twelve public fields are CAS expectations. No caller supplies evidence,
// a policy replacement, a clock, an executor barrier or a successful ACK.
type CapacityDispatchSupersededHTTPMaintenanceDispositionRequest struct {
	CapacityDispatchUnknownMaintenanceDispositionRequest
	ExpectedReplacementPolicyID       uuid.UUID `json:"expected_replacement_policy_id"`
	ExpectedReplacementPolicyVersion  int       `json:"expected_replacement_policy_version"`
	ExpectedReplacementPolicyChecksum string    `json:"expected_replacement_policy_checksum"`
}

type CapacityDispatchSupersededHTTPMaintenanceCanaryEvidence struct {
	PublishID              uuid.UUID `json:"publish_id"`
	ReadID                 uuid.UUID `json:"read_id"`
	PublishChallengeSHA256 string    `json:"publish_challenge_sha256"`
	ReadChallengeSHA256    string    `json:"read_challenge_sha256"`
	PublishReturnSHA256    string    `json:"publish_return_sha256"`
}

// This separate scan does not relabel any migration91 failure as tolerable.
// Challenge hashes retain producer-wire identity; publish_return_sha256 is the
// normalized PostgreSQL whole-row hash, not a claim about original wire bytes.
type CapacityDispatchSupersededHTTPMaintenanceEffectScan struct {
	Schema                string                                                  `json:"schema"`
	Base                  CapacityDispatchFinalizationLostEffectScan              `json:"base"`
	CurrentMembers        json.RawMessage                                         `json:"current_members"`
	CurrentMembersSHA256  string                                                  `json:"current_members_sha256"`
	CurrentMemberCount    int                                                     `json:"current_member_count"`
	EquivalentPolicyValid bool                                                    `json:"equivalent_policy_valid"`
	OtherCatalogPinsValid bool                                                    `json:"other_catalog_pins_valid"`
	StableEpochValid      bool                                                    `json:"stable_epoch_valid"`
	ReadonlyResultValid   bool                                                    `json:"readonly_result_valid"`
	InvalidCanaryPairRows int                                                     `json:"invalid_canary_pair_rows"`
	CurrentIntentSHA256   string                                                  `json:"current_intent_sha256"`
	CanaryEvidence        CapacityDispatchSupersededHTTPMaintenanceCanaryEvidence `json:"canary_evidence"`
}

func decodeSupersededHTTPMaintenanceScan(raw []byte) (CapacityDispatchSupersededHTTPMaintenanceEffectScan, error) {
	var scan CapacityDispatchSupersededHTTPMaintenanceEffectScan
	if capacity.DecodeNativeCapacity(json.RawMessage(raw), &scan) != nil {
		return scan, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	// Missing/null counters cannot become Go zero values. This fixed, new ABI
	// has no optional fields, including its inherited flat scan and pair keys.
	canonical, err := json.Marshal(scan)
	var actual, expected map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &actual) != nil || json.Unmarshal(canonical, &expected) != nil || len(actual) != len(expected) {
		return scan, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	for name := range expected {
		if value, ok := actual[name]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return scan, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
		}
	}
	for _, name := range []string{"base", "canary_evidence"} {
		var a, e map[string]json.RawMessage
		if json.Unmarshal(actual[name], &a) != nil || json.Unmarshal(expected[name], &e) != nil || len(a) != len(e) {
			return scan, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
		}
		for key := range e {
			if value, ok := a[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return scan, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
			}
		}
	}
	var pair map[string]json.RawMessage
	_ = json.Unmarshal(actual["canary_evidence"], &pair)
	for key, expected := range map[string]string{"publish_id": scan.CanaryEvidence.PublishID.String(), "read_id": scan.CanaryEvidence.ReadID.String()} {
		var value string
		if json.Unmarshal(pair[key], &value) != nil || value != expected {
			return scan, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
		}
	}
	if !scan.tolerable() {
		return scan, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	return scan, nil
}

func (s CapacityDispatchSupersededHTTPMaintenanceEffectScan) tolerable() bool {
	b := s.Base
	c := s.CanaryEvidence
	if s.Schema != CapacityDispatchSupersededHTTPMaintenanceScanSchema || !s.EquivalentPolicyValid || !s.OtherCatalogPinsValid ||
		!s.StableEpochValid || !s.ReadonlyResultValid || s.InvalidCanaryPairRows != 0 || s.CurrentMemberCount != 1 ||
		!capacityDispatchDigest(s.CurrentMembersSHA256) || !capacityDispatchDigest(s.CurrentIntentSHA256) ||
		c.PublishID == uuid.Nil || c.ReadID == uuid.Nil || c.PublishID == c.ReadID ||
		!capacityDispatchDigest(c.PublishChallengeSHA256) || !capacityDispatchDigest(c.ReadChallengeSHA256) || !capacityDispatchDigest(c.PublishReturnSHA256) ||
		b.CanaryChallengesSinceStart != 2 || b.CanaryNoncesSinceStart != 2 || b.CanaryPossibleSendsSinceStart != 2 || b.CanaryReturnsSinceStart != 1 ||
		b.PureAssessmentIntentUpdates != 1 || b.ObservationRefreshSlotUpdates != 1 {
		return false
	}
	if members, err := httpMaintenanceMembers(s.CurrentMembers); err != nil || len(members) != 1 {
		return false
	}
	// Only the exact independently authenticated pair is removed from a COPY.
	// Every provider/grant/queue/authority counter remains subject to old zero().
	b.CanaryChallengesSinceStart, b.CanaryNoncesSinceStart, b.CanaryPossibleSendsSinceStart, b.CanaryReturnsSinceStart = 0, 0, 0, 0
	return b.tolerable()
}

type CapacityDispatchSupersededHTTPMaintenanceDisposition struct {
	ID                        uuid.UUID                                           `json:"id"`
	JobID                     uuid.UUID                                           `json:"job_id"`
	RunID                     uuid.UUID                                           `json:"run_id"`
	OriginalDispatchSHA256    string                                              `json:"original_dispatch_sha256"`
	OriginalDispatchUpdatedAt time.Time                                           `json:"original_dispatch_updated_at"`
	OriginalRunSHA256         string                                              `json:"original_run_sha256"`
	OriginalReturnedAt        time.Time                                           `json:"original_returned_at"`
	CurrentMembersSHA256      string                                              `json:"current_members_sha256"`
	ExecutorBarrier           string                                              `json:"executor_barrier"`
	CoreProcessStartedAt      time.Time                                           `json:"disposing_core_process_started_at"`
	CoreHostname              string                                              `json:"disposing_core_hostname"`
	CorePID                   int                                                 `json:"disposing_core_pid"`
	CoreSourceCommit          string                                              `json:"disposing_core_source_commit"`
	Issuer                    string                                              `json:"issuer"`
	Reason                    string                                              `json:"reason"`
	HistoricalReturn          string                                              `json:"historical_return"`
	RecordedAt                time.Time                                           `json:"recorded_at"`
	EffectScan                CapacityDispatchSupersededHTTPMaintenanceEffectScan `json:"provider_mutation_evidence"`
	OriginalPolicyID          uuid.UUID                                           `json:"original_policy_id"`
	OriginalPolicyVersion     int                                                 `json:"original_policy_version"`
	OriginalPolicyChecksum    string                                              `json:"original_policy_checksum"`
	ReplacementPolicyID       uuid.UUID                                           `json:"replacement_policy_id"`
	ReplacementPolicyVersion  int                                                 `json:"replacement_policy_version"`
	ReplacementPolicyChecksum string                                              `json:"replacement_policy_checksum"`
	State                     string                                              `json:"dispatch_state"`
}

func validSupersededHTTPMaintenanceRequest(r CapacityDispatchSupersededHTTPMaintenanceDispositionRequest) bool {
	return validCapacityDispatchUnknownMaintenanceRequest(r.CapacityDispatchUnknownMaintenanceDispositionRequest) &&
		r.ExpectedReplacementPolicyID != uuid.Nil && r.ExpectedReplacementPolicyVersion > 0 && r.ExpectedReplacementPolicyVersion <= 2147483647 && capacityDispatchDigest(r.ExpectedReplacementPolicyChecksum)
}

// Preserve checkCapacityDispatchOriginal unchanged: its active-policy contract
// remains authoritative everywhere else. This separate predicate accepts ONLY
// the archived inactive policy and independently checks every other old pin.
func supersededHTTPMaintenanceOriginalTx(ctx context.Context, tx *sql.Tx, job CapacityDispatchJob) error {
	var namespace, name string
	var version sql.NullInt32
	var started, finished sql.NullTime
	var status, runError string
	var inputs, metadata []byte
	if err := tx.QueryRowContext(ctx, `SELECT workflow_namespace,workflow_name,workflow_version,started_at,finished_at,status,error,inputs,metadata FROM public.workflow_runs WHERE id=$1`, job.RunID).Scan(&namespace, &name, &version, &started, &finished, &status, &runError, &inputs, &metadata); err != nil ||
		namespace != job.Workflow.Namespace || name != job.Workflow.Name || !version.Valid || int(version.Int32) != job.Workflow.Version ||
		!started.Valid || job.StartedAt == nil || !started.Time.Equal(*job.StartedAt) || !finished.Valid || job.ReturnedAt == nil || !finished.Time.Equal(*job.ReturnedAt) ||
		status != "failed" || runError != capacityDispatchSupersededHTTPMaintenanceError {
		return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	var i, m map[string]any
	if json.Unmarshal(inputs, &i) != nil || json.Unmarshal(metadata, &m) != nil {
		return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	ih, mh, err := CapacityDispatchEnvelopeHashes(CapacityDispatchEnvelope{Inputs: i, Metadata: m})
	if err != nil || ih != job.InputsSHA256 || mh != job.MetadataSHA256 {
		return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	pins := []struct {
		kind   string
		pin    CapacityDispatchManifestPin
		active bool
	}{
		{"capacity_policy", job.Policy, false}, {"workflow", job.Workflow, true}, {"rbac", job.RBAC, true},
	}
	if job.AuthorizationPolicy != nil {
		pins = append(pins, struct {
			kind   string
			pin    CapacityDispatchManifestPin
			active bool
		}{"policy", *job.AuthorizationPolicy, true})
	}
	for _, p := range pins {
		var exact bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.manifests WHERE id=$1 AND kind=$2 AND namespace=$3 AND name=$4 AND version=$5 AND checksum=$6 AND active=$7)`, p.pin.ID, p.kind, p.pin.Namespace, p.pin.Name, p.pin.Version, p.pin.Checksum, p.active).Scan(&exact); err != nil || !exact {
			return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
		}
	}
	return nil
}

func supersededHTTPMaintenancePolicyTx(ctx context.Context, tx *sql.Tx, job CapacityDispatchJob, r CapacityDispatchSupersededHTTPMaintenanceDispositionRequest, scan CapacityDispatchSupersededHTTPMaintenanceEffectScan) error {
	var oldSpec, replacementSpec []byte
	var namespace, name, checksum string
	if err := tx.QueryRowContext(ctx, `SELECT p.spec::text,c.spec::text,c.namespace,c.name,c.checksum FROM public.manifests p JOIN public.manifests c ON c.kind=p.kind AND c.namespace=p.namespace AND c.name=p.name WHERE p.id=$1 AND NOT p.active AND c.id=$2 AND c.active AND c.version=$3 AND c.checksum=$4 AND c.version>p.version AND c.spec=p.spec AND c.checksum=p.checksum AND NOT EXISTS(SELECT 1 FROM public.manifests v WHERE v.kind=c.kind AND v.namespace=c.namespace AND v.name=c.name AND ((v.active AND v.id<>c.id) OR v.version>c.version))`, job.Policy.ID, r.ExpectedReplacementPolicyID, r.ExpectedReplacementPolicyVersion, r.ExpectedReplacementPolicyChecksum).Scan(&oldSpec, &replacementSpec, &namespace, &name, &checksum); err != nil || !bytes.Equal(oldSpec, replacementSpec) || checksum != job.Policy.Checksum {
		return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	policy := model.Manifest{ID: r.ExpectedReplacementPolicyID, Kind: "capacity_policy", Version: r.ExpectedReplacementPolicyVersion, Checksum: checksum, Metadata: model.ManifestMetadata{Namespace: namespace, Name: name}, Spec: replacementSpec}
	p, err := parseCapacityPolicy(policy)
	if err != nil || p.Environment != job.Environment || p.Domain != job.Domain || p.Dimension != job.Dimension || p.Workflow.Namespace != job.Workflow.Namespace || p.Workflow.Name != job.Workflow.Name || !capacity.ValidDigest(capacity.GuestPolicyContinuitySHA256(p)) {
		return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	members, err := httpMaintenanceMembers(scan.CurrentMembers)
	if err != nil {
		return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	for _, member := range members {
		if guestPolicyContinuityTx(ctx, tx, policy, p, member.PolicyID, member.PolicyChecksum) != nil {
			return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
		}
		// Authenticate the complete immutable birth/provisioning/enrollment and
		// installation with the existing validators, not merely projected hashes.
		// They retain original signed authority and do not require birth G/F to
		// equal this later stable maintenance epoch.
		stored, loadErr := loadGuestOriginalTx(ctx, tx, member.PreregistrationID)
		if loadErr != nil || loadGuestWitnessTx(ctx, tx, &stored) != nil {
			return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
		}
		receipt, _, receiptErr := loadGuestReceiptTx(ctx, tx, member.PreregistrationID)
		if receiptErr != nil || !guestNotifyHistoricalEnrollmentMatches(p, stored, receipt) ||
			stored.witness.Tuple.ResourceID != member.ResourceID || capacity.GuestRetirementSHA(receipt.Enrollment) != member.EnrollmentSHA256 {
			return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
		}
		installation, installationErr := loadGuestInstallationTx(ctx, tx, stored, receipt)
		if installationErr != nil || capacity.GuestRetirementSHA(installation) != member.InstallationSHA256 {
			return ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
		}
	}
	return nil
}

func DisposeSupersededHTTPMaintenanceDispatch(ctx context.Context, db *sql.DB, r CapacityDispatchSupersededHTTPMaintenanceDispositionRequest, barrier CapacityDispatchExecutorBarrier, revalidate func(context.Context) error) (CapacityDispatchSupersededHTTPMaintenanceDisposition, error) {
	refused := CapacityDispatchSupersededHTTPMaintenanceDisposition{}
	if db == nil || ctx == nil || revalidate == nil || !validSupersededHTTPMaintenanceRequest(r) || !validCapacityDispatchExecutorBarrier(barrier) || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return refused, err
	}
	initial, err := readCapacityDispatchJob(ctx, tx, r.JobID, false)
	if err != nil || !httpMaintenanceScope(initial) || !capacityDispatchAbandonedLockSafe(initial.Realm, initial.Environment, initial.Domain, initial.Dimension) {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	scope, _ := json.Marshal([]string{initial.Realm, initial.Environment, initial.Domain, initial.Dimension})
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, string(scope)); err != nil {
		return refused, err
	}
	job, err := readCapacityDispatchJob(ctx, tx, r.JobID, true)
	if err != nil || job.Realm != initial.Realm || job.Environment != initial.Environment || job.Domain != initial.Domain || job.Dimension != initial.Dimension ||
		job.State != "unknown" || job.StartedAt == nil || job.ReturnedAt == nil || job.LeaseExpiresAt == nil || job.FinalizationAckAt != nil ||
		job.RunID != r.ExpectedRunID || job.EnvelopeSHA256 != r.ExpectedEnvelopeSHA256 || job.FencingToken != r.ExpectedFencingToken || job.LeaseOwner != r.ExpectedLeaseOwner || job.PendingWakeCount != r.ExpectedPendingWakeCount || !job.ReturnedAt.Equal(r.ExpectedReturnedAt) {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	authorizationID := uuid.Nil
	if job.AuthorizationPolicy != nil {
		authorizationID = job.AuthorizationPolicy.ID
	}
	if _, err = tx.ExecContext(ctx, `SELECT id FROM public.manifests WHERE id IN($1,$2,$3,$4,$5) ORDER BY id FOR SHARE`, job.Policy.ID, job.Workflow.ID, job.RBAC.ID, authorizationID, r.ExpectedReplacementPolicyID); err != nil {
		return refused, err
	}
	for _, query := range []string{
		`SELECT namespace FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 FOR SHARE`,
		`SELECT slot FROM public.capacity_resource_slots WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 ORDER BY integration_instance_id,scope_checksum,profile_name,slot FOR SHARE`,
		`SELECT id FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 ORDER BY id FOR SHARE`,
	} {
		if _, err = tx.ExecContext(ctx, query, job.Realm, job.Environment, job.Domain, job.Dimension); err != nil {
			return refused, err
		}
	}
	var now time.Time
	var runSHA string
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp(),encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') FROM public.workflow_runs w WHERE id=$1 FOR UPDATE`, job.RunID).Scan(&now, &runSHA); err != nil || runSHA != r.ExpectedRunSHA256 || now.Before(job.LeaseExpiresAt.Add(CapacityDispatchAbandonedMinimumAge)) || !barrier.ProcessStartedAt.After(*job.LeaseExpiresAt) || barrier.ProcessStartedAt.After(now) || supersededHTTPMaintenanceOriginalTx(ctx, tx, job) != nil {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	var raw string
	var admission, accepted bool
	if err = tx.QueryRowContext(ctx, `WITH s AS MATERIALIZED(SELECT public.superseded_http_maintenance_dispatch_effect_scan($1) AS evidence) SELECT evidence::text,public.superseded_http_maintenance_dispatch_effect_scan_tolerable(evidence),public.superseded_http_maintenance_dispatch_admissible($1,$2,clock_timestamp()) FROM s`, job.JobID, barrier.ProcessStartedAt).Scan(&raw, &accepted, &admission); err != nil || !accepted || !admission {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	scan, decodeErr := decodeSupersededHTTPMaintenanceScan([]byte(raw))
	if decodeErr != nil || scan.CurrentMembersSHA256 != r.ExpectedMembersSHA256 || supersededHTTPMaintenancePolicyTx(ctx, tx, job, r, scan) != nil {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	if err = revalidate(ctx); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	id := uuid.New()
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_dispatch_superseded_http_maintenance_dispositions(id,job_id,run_id,original_dispatch_sha256,original_dispatch_updated_at,original_run_sha256,original_returned_at,current_members_sha256,executor_barrier,disposing_core_process_started_at,disposing_core_hostname,disposing_core_pid,disposing_core_source_commit,issuer,reason,historical_return,recorded_at,provider_mutation_evidence,original_policy_id,original_policy_version,original_policy_checksum,replacement_policy_id,replacement_policy_version,replacement_policy_checksum,original_dispatch_wire,original_run_wire,original_policy_wire,replacement_policy_wire,current_intent_wire,current_members_wire,canary_evidence_wire)
 SELECT $1,j.id,j.run_id,encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex'),j.updated_at,$3,j.returned_at,$4,$5,$6,$7,$8,$9,$10,$11,'unknown',clock_timestamp(),$12::jsonb,p.id,p.version,p.checksum,c.id,c.version,c.checksum,convert_to(to_jsonb(j)::text,'UTF8'),convert_to(to_jsonb(w)::text,'UTF8'),convert_to(to_jsonb(p)::text,'UTF8'),convert_to(to_jsonb(c)::text,'UTF8'),convert_to(i.intent::text,'UTF8'),convert_to(($12::jsonb->'current_members')::text,'UTF8'),convert_to(($12::jsonb->'canary_evidence')::text,'UTF8')
 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id JOIN public.manifests p ON p.id=$13 JOIN public.manifests c ON c.id=$14 JOIN public.capacity_intents i ON i.namespace=j.realm AND i.environment=j.environment AND i.domain=j.domain AND i.dimension=j.dimension WHERE j.id=$2`, id, job.JobID, runSHA, r.ExpectedMembersSHA256, CapacityDispatchAbandonedBarrier, barrier.ProcessStartedAt, barrier.Hostname, barrier.PID, barrier.SourceCommit, r.Issuer, CapacityDispatchSupersededHTTPMaintenanceReason, raw, job.Policy.ID, r.ExpectedReplacementPolicyID)
	if err != nil {
		return refused, errors.Join(ErrCapacityDispatchSupersededHTTPMaintenanceDisposition, err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE public.capacity_dispatch_jobs SET state='superseded_http_maintenance_disposed',updated_at=(SELECT recorded_at FROM public.capacity_dispatch_superseded_http_maintenance_dispositions WHERE job_id=$1) WHERE id=$1 AND state='unknown' AND finalization_ack_at IS NULL`, job.JobID)
	if err != nil {
		return refused, err
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	d, err := readSupersededHTTPMaintenanceDisposition(ctx, tx, job.JobID)
	if err != nil || d.ID != id || d.OriginalRunSHA256 != runSHA {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	if err = revalidate(ctx); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	if err = tx.Commit(); err != nil {
		return refused, errors.Join(ErrCapacityDispatchSupersededHTTPMaintenanceDisposition, err)
	}
	if capacityDispatchContextFailure(ctx) != nil {
		return refused, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	return d, nil
}

func GetSupersededHTTPMaintenanceDispatchDisposition(ctx context.Context, db *sql.DB, jobID uuid.UUID) (CapacityDispatchSupersededHTTPMaintenanceDisposition, error) {
	if db == nil || ctx == nil || jobID == uuid.Nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchSupersededHTTPMaintenanceDisposition{}, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return CapacityDispatchSupersededHTTPMaintenanceDisposition{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return CapacityDispatchSupersededHTTPMaintenanceDisposition{}, err
	}
	d, err := readSupersededHTTPMaintenanceDisposition(ctx, tx, jobID)
	if err != nil {
		return d, err
	}
	if err = tx.Commit(); err != nil || capacityDispatchContextFailure(ctx) != nil {
		return CapacityDispatchSupersededHTTPMaintenanceDisposition{}, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	return d, nil
}

// Historical reads authenticate the immutable archive and untouched job/run.
// They intentionally do not require its replacement to remain the active policy
// or the member/epoch to remain current after a later ordinary cycle.
func readSupersededHTTPMaintenanceDisposition(ctx context.Context, db capacityDispatchQueryer, jobID uuid.UUID) (CapacityDispatchSupersededHTTPMaintenanceDisposition, error) {
	var d CapacityDispatchSupersededHTTPMaintenanceDisposition
	var raw, jobSHA, runSHA, runStatus, runError, returnStatus, returnError string
	var finalization sql.NullString
	var returned, ack, started, expires, workflowStarted, workflowFinished sql.NullTime
	var pointersAbsent, pureTolerable, snapshotsValid bool
	err := db.QueryRowContext(ctx, `SELECT d.id,d.job_id,d.run_id,d.original_dispatch_sha256,d.original_dispatch_updated_at,d.original_run_sha256,d.original_returned_at,d.current_members_sha256,d.executor_barrier,d.disposing_core_process_started_at,d.disposing_core_hostname,d.disposing_core_pid,d.disposing_core_source_commit,d.issuer,d.reason,d.historical_return,d.recorded_at,d.provider_mutation_evidence::text,d.original_policy_id,d.original_policy_version,d.original_policy_checksum,d.replacement_policy_id,d.replacement_policy_version,d.replacement_policy_checksum,j.state,j.returned_at,j.finalization_ack_at,
 encode(sha256(convert_to((to_jsonb(j)||jsonb_build_object('state','unknown','updated_at',d.original_dispatch_updated_at))::text,'UTF8')),'hex'),encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex'),w.status,w.error,j.return_status,j.return_error,j.finalization_error,j.started_at,j.lease_expires_at,w.started_at,w.finished_at,
 num_nonnulls(j.failed_original_disposition_id,j.native_denied_disposition_id,j.enrolled_failed_disposition_id,j.abandoned_disposition_id,j.finalization_lost_disposition_id,j.unknown_maintenance_disposition_id)=0,
 public.superseded_http_maintenance_dispatch_effect_scan_tolerable(d.provider_mutation_evidence),
 public.superseded_http_maintenance_dispatch_receipt_valid(d) AND j.updated_at=d.recorded_at AND d.original_dispatch_wire=convert_to((to_jsonb(j)||jsonb_build_object('state','unknown','updated_at',d.original_dispatch_updated_at))::text,'UTF8') AND d.original_run_wire=convert_to(to_jsonb(w)::text,'UTF8') AND encode(sha256(d.current_members_wire),'hex')=d.current_members_sha256 AND encode(sha256(d.current_intent_wire),'hex')=d.provider_mutation_evidence->>'current_intent_sha256' AND convert_from(d.current_members_wire,'UTF8')::jsonb=d.provider_mutation_evidence->'current_members' AND convert_from(d.canary_evidence_wire,'UTF8')::jsonb=d.provider_mutation_evidence->'canary_evidence' AND convert_from(d.original_policy_wire,'UTF8')::jsonb->>'id'=d.original_policy_id::text AND convert_from(d.replacement_policy_wire,'UTF8')::jsonb->>'id'=d.replacement_policy_id::text AND convert_from(d.original_policy_wire,'UTF8')::jsonb->'spec'=convert_from(d.replacement_policy_wire,'UTF8')::jsonb->'spec'
 FROM public.capacity_dispatch_superseded_http_maintenance_dispositions d JOIN public.capacity_dispatch_jobs j ON j.id=d.job_id AND j.run_id=d.run_id JOIN public.workflow_runs w ON w.id=d.run_id WHERE d.job_id=$1`, jobID).Scan(&d.ID, &d.JobID, &d.RunID, &d.OriginalDispatchSHA256, &d.OriginalDispatchUpdatedAt, &d.OriginalRunSHA256, &d.OriginalReturnedAt, &d.CurrentMembersSHA256, &d.ExecutorBarrier, &d.CoreProcessStartedAt, &d.CoreHostname, &d.CorePID, &d.CoreSourceCommit, &d.Issuer, &d.Reason, &d.HistoricalReturn, &d.RecordedAt, &raw, &d.OriginalPolicyID, &d.OriginalPolicyVersion, &d.OriginalPolicyChecksum, &d.ReplacementPolicyID, &d.ReplacementPolicyVersion, &d.ReplacementPolicyChecksum, &d.State, &returned, &ack, &jobSHA, &runSHA, &runStatus, &runError, &returnStatus, &returnError, &finalization, &started, &expires, &workflowStarted, &workflowFinished, &pointersAbsent, &pureTolerable, &snapshotsValid)
	scan, decodeErr := decodeSupersededHTTPMaintenanceScan([]byte(raw))
	d.EffectScan = scan
	if err != nil || decodeErr != nil || !pureTolerable || !snapshotsValid || !pointersAbsent ||
		d.ID == uuid.Nil || d.JobID != jobID || d.RunID == uuid.Nil || !capacityDispatchDigest(d.OriginalDispatchSHA256) || !capacityDispatchDigest(d.OriginalRunSHA256) || d.OriginalDispatchSHA256 != jobSHA || d.OriginalRunSHA256 != runSHA ||
		d.OriginalDispatchUpdatedAt.IsZero() || d.OriginalDispatchUpdatedAt.After(d.RecordedAt) || d.CurrentMembersSHA256 != d.EffectScan.CurrentMembersSHA256 ||
		d.OriginalPolicyID == uuid.Nil || d.ReplacementPolicyID == uuid.Nil || d.OriginalPolicyID == d.ReplacementPolicyID || d.OriginalPolicyVersion < 1 || d.ReplacementPolicyVersion <= d.OriginalPolicyVersion || !capacityDispatchDigest(d.OriginalPolicyChecksum) || d.OriginalPolicyChecksum != d.ReplacementPolicyChecksum ||
		!validCapacityDispatchExecutorBarrier(CapacityDispatchExecutorBarrier{ProcessStartedAt: d.CoreProcessStartedAt, Hostname: d.CoreHostname, PID: d.CorePID, SourceCommit: d.CoreSourceCommit}) ||
		d.State != CapacityDispatchSupersededHTTPMaintenanceState || !returned.Valid || !returned.Time.Equal(d.OriginalReturnedAt) || ack.Valid || !started.Valid || !expires.Valid || !workflowStarted.Valid || !workflowFinished.Valid ||
		!started.Time.Before(returned.Time) || !returned.Time.Before(expires.Time) || !workflowStarted.Time.Equal(started.Time) || !workflowFinished.Time.Equal(returned.Time) ||
		d.RecordedAt.Before(expires.Time.Add(CapacityDispatchAbandonedMinimumAge)) || !d.CoreProcessStartedAt.After(expires.Time) || d.CoreProcessStartedAt.After(d.RecordedAt) ||
		runStatus != "failed" || returnStatus != "failed" || runError != capacityDispatchSupersededHTTPMaintenanceError || returnError != runError || finalization.Valid ||
		d.Reason != CapacityDispatchSupersededHTTPMaintenanceReason || d.HistoricalReturn != "unknown" || d.ExecutorBarrier != CapacityDispatchAbandonedBarrier {
		return CapacityDispatchSupersededHTTPMaintenanceDisposition{}, ErrCapacityDispatchSupersededHTTPMaintenanceDisposition
	}
	return d, nil
}
