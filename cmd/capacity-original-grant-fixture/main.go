//go:build capacitytest

// Command capacity-original-grant-fixture exercises real Core grant issuance
// and redemption in a separately prepared, isolated PostgreSQL fixture. It
// performs no adapter, provider or Guest mutation.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

const contenders = 20

var testDatabase = regexp.MustCompile(`^ci_capacity_[a-z0-9_]{1,40}$`)

type request struct {
	Schema      string    `json:"schema"`
	SourceRoot  string    `json:"source_root"`
	PolicyID    uuid.UUID `json:"policy_id"`
	WorkflowID  uuid.UUID `json:"workflow_id"`
	Generation  int64     `json:"generation"`
	Fence       int64     `json:"fence"`
	LeaseOwner  string    `json:"lease_owner"`
	ExecutorID  string    `json:"executor_id"`
	BindingName string    `json:"binding_name"`
	Slot        int       `json:"slot"`
	NonceSHA256 string    `json:"nonce_sha256"`
}

type report struct {
	Schema                       string `json:"schema"`
	CoreSource                   string `json:"core_source"`
	PostgresVersionNum           int    `json:"postgres_version_num"`
	Provider                     string `json:"provider"`
	Slot                         int    `json:"slot"`
	BaselineUnits                int    `json:"baseline_units"`
	Floor                        int    `json:"floor"`
	RegisteredBaseline           int    `json:"registered_baseline"`
	IssuanceReturns              int    `json:"issuance_returns"`
	SerializedIssueMatches       bool   `json:"serialized_issue_matches"`
	RejectedIssueRollsBack       bool   `json:"rejected_issue_rolls_back"`
	ActiveGrantRows              int    `json:"active_grant_rows"`
	PreregistrationRows          int    `json:"preregistration_rows"`
	RedeemReturns                int    `json:"redeem_returns"`
	WriteOnce                    int    `json:"write_once"`
	ReadOnly                     int    `json:"read_only"`
	WinningReplayReadOnly        bool   `json:"winning_replay_read_only"`
	PersistedWinnerMatches       bool   `json:"persisted_winner_matches"`
	RejectedBeforeSendReplay     bool   `json:"rejected_before_send_replay"`
	RejectedBeforeSendNewGrant   bool   `json:"rejected_before_send_new_grant"`
	UnresolvedBlocksPromotion    bool   `json:"unresolved_blocks_promotion"`
	ExpiredRedemptionReadOnly    bool   `json:"expired_redemption_read_only"`
	NativeReadRequiresSettlement bool   `json:"native_read_requires_settlement"`
	SyntheticConfirmationOnce    bool   `json:"synthetic_confirmation_once"`
	SettlementScopePrivacyPassed bool   `json:"settlement_scope_privacy_passed"`
	RepositoryLostReply          bool   `json:"repository_lost_reply"`
	RepositoryUnresolved         bool   `json:"repository_unresolved"`
	RepositoryNativeConfirmation bool   `json:"repository_native_confirmation"`
	SyntheticHTTPCallbacksPassed bool   `json:"synthetic_http_callbacks_passed"`
	ProviderSendAttempted        bool   `json:"provider_send_attempted"`
	NativeOrProductionQualified  bool   `json:"native_or_production_qualified"`
}

func decodeRequest(r io.Reader) (request, error) {
	var out request
	body, err := io.ReadAll(io.LimitReader(r, 8193))
	if err != nil || len(body) == 0 || len(body) > 8192 {
		return out, errors.New("bounded request required")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	var members map[string]json.RawMessage
	keys := json.NewDecoder(bytes.NewReader(body))
	if tok, err := keys.Token(); err != nil || tok != json.Delim('{') {
		return out, errors.New("closed request required")
	}
	members = make(map[string]json.RawMessage)
	for keys.More() {
		tok, err := keys.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return out, errors.New("closed request required")
		}
		if _, exists := members[key]; exists {
			return out, errors.New("duplicate request member")
		}
		var value json.RawMessage
		if keys.Decode(&value) != nil {
			return out, errors.New("closed request required")
		}
		members[key] = value
	}
	if _, err := keys.Token(); err != nil {
		return out, errors.New("closed request required")
	}
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF {
		return out, errors.New("closed request required")
	}
	if out.Schema != "ci_original_grant_concurrency_v1" || !filepath.IsAbs(out.SourceRoot) || out.PolicyID == uuid.Nil || out.WorkflowID == uuid.Nil || out.Generation < 1 || out.Fence < 1 || out.Slot < 1 || out.Slot > 64 || out.BindingName == "" || len(out.NonceSHA256) != 64 {
		return out, errors.New("fixture scope required")
	}
	if id, err := uuid.Parse(out.LeaseOwner); err != nil || id.String() != out.LeaseOwner || id == uuid.Nil {
		return out, errors.New("lease owner UUID required")
	}
	if id, err := uuid.Parse(out.ExecutorID); err != nil || id.String() != out.ExecutorID || id == uuid.Nil {
		return out, errors.New("executor UUID required")
	}
	if _, err := hex.DecodeString(out.NonceSHA256); err != nil || strings.ToLower(out.NonceSHA256) != out.NonceSHA256 {
		return out, errors.New("nonce digest required")
	}
	return out, nil
}

func checkDSN(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "postgres" || u.Host != "" || u.Fragment != "" || !testDatabase.MatchString(strings.TrimPrefix(u.Path, "/")) || os.Getenv("CAPACITY_TEST_ALLOW") != "isolated-postgresql-only" {
		return "", errors.New("isolated Unix-socket test database required")
	}
	if u.User == nil || u.User.Username() != "postgres" {
		return "", errors.New("isolated fixture role required")
	}
	if _, hasPassword := u.User.Password(); hasPassword {
		return "", errors.New("fixture credentials prohibited")
	}
	query, err := url.ParseQuery(u.RawQuery)
	socketDir := os.Getenv("CAPACITY_TEST_SOCKET_DIR")
	if err != nil || len(query) != 3 || len(query["sslmode"]) != 1 || query.Get("sslmode") != "disable" || len(query["host"]) != 1 || len(query["port"]) != 1 || query.Get("host") != socketDir || !filepath.IsAbs(socketDir) || filepath.Clean(socketDir) != socketDir || query.Get("port") == "" {
		return "", errors.New("isolated Unix-socket test database parameters required")
	}
	info, err := os.Lstat(socketDir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", errors.New("private owned socket directory required")
	}
	return strings.TrimPrefix(u.Path, "/"), nil
}

// checkOwnedPostgres verifies the server actually belongs to the private local
// cluster created for this test before any fixture or grant mutation occurs.
func checkOwnedPostgres(ctx context.Context, db *sql.DB, dbName, socketDir string) error {
	data := os.Getenv("CAPACITY_TEST_PGDATA")
	pgBin := os.Getenv("CAPACITY_TEST_PG_BIN")
	owner := filepath.Dir(socketDir)
	if !filepath.IsAbs(data) || filepath.Clean(data) != data || filepath.Dir(data) != owner || filepath.Base(data) != "data" || filepath.Base(socketDir) != "socket" || !strings.HasPrefix(filepath.Base(owner), "dk-pg-") || !filepath.IsAbs(pgBin) {
		return errors.New("fixture-owned PostgreSQL paths required")
	}
	for _, path := range []string{owner, data, socketDir} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			return errors.New("private fixture directories required")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Geteuid()) {
			return errors.New("fixture directory owner mismatch")
		}
	}
	pidfile, err := os.ReadFile(filepath.Join(data, "postmaster.pid"))
	if err != nil || len(pidfile) > 4096 {
		return errors.New("fixture postmaster identity unavailable")
	}
	lines := strings.Split(string(pidfile), "\n")
	if len(lines) < 6 || lines[1] != data || lines[4] != socketDir || lines[5] != "" {
		return errors.New("fixture postmaster identity mismatch")
	}
	pid, err := strconv.Atoi(lines[0])
	if err != nil || pid < 2 {
		return errors.New("fixture postmaster PID required")
	}
	process, err := os.FindProcess(pid)
	if err != nil || process.Signal(syscall.Signal(0)) != nil {
		return errors.New("fixture postmaster not running")
	}
	if err = exec.CommandContext(ctx, filepath.Join(pgBin, "pg_ctl"), "-D", data, "status").Run(); err != nil {
		return errors.New("fixture postmaster status mismatch")
	}
	control, err := exec.CommandContext(ctx, filepath.Join(pgBin, "pg_controldata"), data).Output()
	if err != nil || len(control) > 65536 {
		return errors.New("fixture control identity unavailable")
	}
	systemID := ""
	for _, line := range strings.Split(string(control), "\n") {
		if strings.HasPrefix(line, "Database system identifier:") {
			systemID = strings.TrimSpace(strings.TrimPrefix(line, "Database system identifier:"))
		}
	}
	if _, err = strconv.ParseUint(systemID, 10, 64); err != nil || systemID != os.Getenv("CAPACITY_TEST_PG_SYSTEM_ID") {
		return errors.New("fixture control identity mismatch")
	}
	var actual, listen, actualData, actualID string
	var version int
	var unixSocket bool
	major, majorErr := strconv.Atoi(os.Getenv("CAPACITY_TEST_PG_MAJOR"))
	if majorErr != nil || (major != 16 && major != 17) {
		return errors.New("explicit isolated PostgreSQL major 16 or 17 required")
	}
	if err = db.QueryRowContext(ctx, `SELECT current_database(), current_setting('server_version_num')::int, inet_server_addr() IS NULL, current_setting('listen_addresses'), current_setting('data_directory'), system_identifier::text FROM pg_control_system()`).Scan(&actual, &version, &unixSocket, &listen, &actualData, &actualID); err != nil || actual != dbName || version/10000 != major || !unixSocket || listen != "" || actualData != data || actualID != systemID {
		return errors.New("fixture server identity mismatch")
	}
	return nil
}

func checkSource(ctx context.Context, root string) (string, error) {
	source := capacity.CurrentGuestCoreSource()
	if source == "" {
		return "", errors.New("clean native VCS build identity required")
	}
	call := func(args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "git", append([]string{"-C", root}, args...)...).Output()
	}
	top, err := call("rev-parse", "--show-toplevel")
	if err != nil {
		return "", errors.New("source root unavailable")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || strings.TrimSpace(string(top)) != resolved {
		return "", errors.New("exact source root required")
	}
	head, err := call("rev-parse", "HEAD")
	if err != nil || strings.TrimSpace(string(head)) != source {
		return "", errors.New("source revision differs from binary")
	}
	status, err := call("status", "--porcelain", "--untracked-files=normal")
	if err != nil || len(status) != 0 {
		return "", errors.New("clean source checkout required")
	}
	return source, nil
}

func approved(policy model.Manifest, workflow model.Manifest, input request, source string) (model.CapacityMutationBinding, model.WorkflowStepSpec, string, error) {
	var p model.CapacityPolicySpec
	var empty model.CapacityMutationBinding
	var step model.WorkflowStepSpec
	if policy.Kind != "capacity_policy" || !policy.Metadata.Active || workflow.Kind != "workflow" || !workflow.Metadata.Active || json.Unmarshal(policy.Spec, &p) != nil || !p.ExecutionEnabled || p.GuestRetirementBinding == nil || p.GuestRetirementBinding.MutationBindingName != input.BindingName {
		return empty, step, "", errors.New("active guest policy and workflow required")
	}
	var binding *model.CapacityMutationBinding
	for i := range p.MutationBindings {
		if p.MutationBindings[i].Name == input.BindingName {
			if binding != nil {
				return empty, step, "", errors.New("ambiguous binding")
			}
			binding = &p.MutationBindings[i]
		}
	}
	if binding == nil {
		return empty, step, "", errors.New("approved binding required")
	}
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == binding.ProfileName {
			if provider != "" {
				return empty, step, "", errors.New("ambiguous profile")
			}
			provider = profile.Provider
		}
	}
	if (provider != "aws" && provider != "hetzner" && !capacity.GuestOriginalNativeQEMUProviderEnabled(provider)) || !capacity.GuestBindingAuthorityCurrent(p, *p.GuestRetirementBinding) || !capacity.GuestOriginalProfileEnabled(p, *p.GuestRetirementBinding, provider) || source != capacity.CurrentGuestCoreSource() {
		return empty, step, "", errors.New("compiled profile approval required")
	}
	wf, err := manifest.ParseWorkflowSpec(workflow.Spec)
	if err != nil || wf.Authorization == nil {
		return empty, step, "", errors.New("authorized workflow required")
	}
	found := false
	for _, candidate := range wf.Steps {
		if candidate.ID == p.GuestRetirementBinding.ProfileManifest.OriginalProvisioningStepID {
			if found {
				return empty, step, "", errors.New("ambiguous provisioning step")
			}
			step = candidate
			found = true
		}
	}
	if !found || step.Use.Kind != "yggdrasil" || step.Use.Operation != capacity.ProvisionOriginalGuestOperation {
		return empty, step, "", errors.New("original provisioning step required")
	}
	return *binding, step, provider, nil
}

func run(ctx context.Context, db *sql.DB, input request, source string) (report, error) {
	out := report{Schema: "ci_original_grant_concurrency_result_v1", CoreSource: source, Slot: input.Slot}
	policy, err := repository.GetManifestByID(ctx, db, input.PolicyID)
	if err != nil {
		return out, err
	}
	workflow, err := repository.GetManifestByID(ctx, db, input.WorkflowID)
	if err != nil {
		return out, err
	}
	binding, step, provider, err := approved(policy, workflow, input, source)
	if err != nil {
		return out, err
	}
	out.Provider = provider
	var desired *model.CapacityMutationSpecV1
	for _, slot := range binding.Slots {
		if slot.Slot == input.Slot {
			if desired != nil {
				return out, errors.New("duplicate approved slot")
			}
			desired = slot.DesiredSpec
		}
	}
	if desired == nil || desired.Capability != binding.EnsureCapability {
		return out, errors.New("approved create slot required")
	}
	spec, err := json.Marshal(desired)
	if err != nil {
		return out, err
	}
	var before int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4`, binding.IntegrationInstanceID, binding.ScopeChecksum, binding.ProfileName, input.Slot).Scan(&before); err != nil || before != 0 {
		return out, errors.New("fresh isolated slot required")
	}
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: input.WorkflowID, ExecutorID: input.ExecutorID}.WithOriginalGuestProvisioning(step, source, input.NonceSHA256)
	issue := model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: spec}
	// Exercise the real issuance transaction through its insert and then fail
	// original preregistration validation. The synthetic nonce is deliberately
	// invalid, so this path must not issue authority or contact a provider.
	invalid := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: input.WorkflowID, ExecutorID: input.ExecutorID}.WithOriginalGuestProvisioning(step, source, "not-a-digest")
	_, err = invalid.IssueMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, issue)
	if !errors.Is(err, repository.ErrCapacityConflict) || !strings.Contains(err.Error(), "complete original protected Guest preregistration required") {
		return out, errors.New("invalid original preregistration did not reach its transaction guard")
	}
	var grantsAfterReject, preregistrationsAfterReject int
	if err = db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM public.capacity_mutation_grants WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4), (SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations WHERE preregistration_record->>'policy_id'=$5)`, binding.IntegrationInstanceID, binding.ScopeChecksum, binding.ProfileName, input.Slot, policy.ID.String()).Scan(&grantsAfterReject, &preregistrationsAfterReject); err != nil || grantsAfterReject != 0 || preregistrationsAfterReject != 0 {
		return out, errors.New("invalid original preregistration left transactional state")
	}
	out.RejectedIssueRollsBack = true
	type issued struct {
		grant model.CapacityMutationGrant
		err   error
	}
	issuedRows := make(chan issued, contenders)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := 0; i < contenders; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			grant, e := store.IssueMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, issue)
			issuedRows <- issued{grant, e}
		}()
	}
	close(start)
	workers.Wait()
	close(issuedRows)
	var grant model.CapacityMutationGrant
	var first []byte
	for row := range issuedRows {
		if row.err != nil {
			return out, fmt.Errorf("issuance contender: %w", row.err)
		}
		wire, e := json.Marshal(row.grant)
		if e != nil {
			return out, e
		}
		if first == nil {
			first, grant = wire, row.grant
		} else if !bytes.Equal(first, wire) {
			return out, errors.New("issuance produced distinct grants")
		}
		out.IssuanceReturns++
	}
	if out.IssuanceReturns != contenders || grant.GrantID == "" || grant.Slot != input.Slot || grant.State != "issued" {
		return out, errors.New("issuance census incomplete")
	}
	serialGrant, err := store.IssueMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, issue)
	if err != nil {
		return out, errors.New("serialized issuance failed")
	}
	serialWire, err := json.Marshal(serialGrant)
	if err != nil || !bytes.Equal(first, serialWire) {
		return out, errors.New("serialized issuance differs")
	}
	out.SerializedIssueMatches = true
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE integration_instance_id=$1 AND scope_checksum=$2 AND profile_name=$3 AND slot=$4 AND state='issued'`, binding.IntegrationInstanceID, binding.ScopeChecksum, binding.ProfileName, input.Slot).Scan(&out.ActiveGrantRows); err != nil {
		return out, err
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1 AND preregistration_record->>'policy_id'=$2 AND preregistration_record->>'workflow_id'=$3`, grant.GrantID, policy.ID.String(), workflow.ID.String()).Scan(&out.PreregistrationRows); err != nil {
		return out, err
	}
	if out.ActiveGrantRows != 1 || out.PreregistrationRows != 1 {
		return out, errors.New("grant or preregistration census differs")
	}
	type redeemed struct {
		request  model.CapacityMutationRedeemRequest
		response model.CapacityMutationRedeemResponse
		nonce    string
		err      error
	}
	redemptionRows := make(chan redeemed, contenders)
	start = make(chan struct{})
	for i := 0; i < contenders; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			nonce := uuid.NewString()
			token := sha256.Sum256([]byte(nonce))
			r := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: uuid.NewString(), SettlementTokenSHA256: hex.EncodeToString(token[:]), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256}
			<-start
			response, e := store.RedeemMutation(ctx, binding.AdapterPrincipalID, r)
			redemptionRows <- redeemed{r, response, nonce, e}
		}()
	}
	close(start)
	workers.Wait()
	close(redemptionRows)
	var winner model.CapacityMutationRedeemRequest
	var winnerNonce string
	for row := range redemptionRows {
		if row.err != nil || row.response.GrantID != grant.GrantID || row.response.AttemptID != row.request.AttemptID || row.response.RequestSHA256 != grant.RequestSHA256 {
			return out, errors.New("redemption contender returned invalid result")
		}
		switch row.response.Mode {
		case "write_once":
			out.WriteOnce++
			winner = row.request
			winnerNonce = row.nonce
		case "read_only":
			out.ReadOnly++
		default:
			return out, errors.New("unexpected redemption mode")
		}
		out.RedeemReturns++
	}
	if out.RedeemReturns != contenders || out.WriteOnce != 1 || out.ReadOnly != contenders-1 {
		return out, errors.New("redemption census incomplete")
	}
	replay, err := store.RedeemMutation(ctx, binding.AdapterPrincipalID, winner)
	if err != nil || replay.Mode != "read_only" || replay.GrantID != grant.GrantID || replay.AttemptID != winner.AttemptID {
		return out, errors.New("winning attempt replay not read-only")
	}
	out.WinningReplayReadOnly = true
	var storedWinnerMatches bool
	if err = db.QueryRowContext(ctx, `SELECT state='redeemed' AND grant_record->'grant'->>'state'='redeemed' AND grant_record->>'attempt_id'=$2 AND grant_record->>'settlement_token_sha256'=$3 FROM public.capacity_mutation_grants WHERE id=$1`, grant.GrantID, winner.AttemptID, winner.SettlementTokenSHA256).Scan(&storedWinnerMatches); err != nil || !storedWinnerMatches {
		return out, errors.New("stored winner differs from first authorization")
	}
	out.PersistedWinnerMatches = true
	// This mirrors the original repository scenario's explicit before-send
	// rejection and idempotent settlement. It does not simulate a provider call
	// or a lost reply after a provider accepted one.
	settle := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: winner.AttemptID, RequestSHA256: grant.RequestSHA256, Outcome: "rejected_before_send", TransportCompleted: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	settled, err := store.SettleMutation(ctx, binding.AdapterPrincipalID, winnerNonce, settle)
	if err != nil || settled.GrantID != grant.GrantID || settled.State != "rejected" {
		return out, errors.New("original before-send rejection failed")
	}
	repeated, err := store.SettleMutation(ctx, binding.AdapterPrincipalID, winnerNonce, settle)
	if err != nil || repeated.GrantID != grant.GrantID || repeated.State != "rejected" {
		return out, errors.New("exact before-send settlement replay failed")
	}
	out.RejectedBeforeSendReplay = true
	nextNonce := sha256.Sum256([]byte(uuid.NewString()))
	nextStore := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: input.WorkflowID, ExecutorID: input.ExecutorID}.WithOriginalGuestProvisioning(step, source, hex.EncodeToString(nextNonce[:]))
	next, err := nextStore.IssueMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, issue)
	if err != nil || next.GrantID == "" || next.GrantID == grant.GrantID || next.State != "issued" {
		return out, errors.New("before-send rejection did not yield distinct new grant")
	}
	var nextPreregistrationCount int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations WHERE create_grant_id=$1`, next.GrantID).Scan(&nextPreregistrationCount); err != nil || nextPreregistrationCount != 1 {
		return out, errors.New("successor grant lacks its distinct preregistration")
	}
	out.RejectedBeforeSendNewGrant = true
	// A fresh real grant is redeemed once, with no simulated provider send.
	// Until there is a transport settlement, expiry cannot reauthorize it and
	// the unresolved permission must prevent terminal promotion.
	nextSettlementNonce := uuid.NewString()
	nextSettlementDigest := sha256.Sum256([]byte(nextSettlementNonce))
	nextRedeem := model.CapacityMutationRedeemRequest{GrantID: next.GrantID, AttemptID: uuid.NewString(), SettlementTokenSHA256: hex.EncodeToString(nextSettlementDigest[:]), Capability: next.Capability, IntegrationInstanceID: next.IntegrationInstanceID, ScopeChecksum: next.ScopeChecksum, ProfileName: next.ProfileName, Slot: next.Slot, RequestSHA256: next.RequestSHA256}
	permission, err := nextStore.RedeemMutation(ctx, binding.AdapterPrincipalID, nextRedeem)
	if err != nil || permission.Mode != "write_once" {
		return out, errors.New("successor first redemption failed")
	}
	same, err := nextStore.IssueMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, issue)
	if err != nil || same.GrantID != next.GrantID || same.State != "redeemed" {
		return out, errors.New("unresolved successor was reissued")
	}
	current, err := nextStore.Observe(ctx, policy)
	if err != nil {
		return out, errors.New("unresolved intent read failed")
	}
	zero := 0
	proof := model.CapacityTransitionProof{Assessment: current.Assessment, ObservedAt: time.Now().UTC(), ReceiptRef: "synthetic:unresolved-no-provider-send", Healthy: true, Inflight: &zero}
	for _, phase := range []string{"prepared", "canary"} {
		if _, err = nextStore.Advance(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, phase, proof); err != nil {
			return out, fmt.Errorf("unresolved transition %s: %w", phase, err)
		}
	}
	proof.Assessment.Snapshot.Units = current.Decision.Units
	if _, err = nextStore.Advance(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, "promoted", proof); !errors.Is(err, repository.ErrCapacityConflict) || !strings.Contains(err.Error(), "unresolved provider mutation authority") {
		return out, errors.New("unsettled authority did not block promotion")
	}
	out.UnresolvedBlocksPromotion = true
	if _, err = db.ExecContext(ctx, `UPDATE public.capacity_mutation_grants SET expires_at=clock_timestamp()-interval '1 hour' WHERE id=$1`, next.GrantID); err != nil {
		return out, errors.New("failed to age isolated grant")
	}
	late, err := nextStore.RedeemMutation(ctx, binding.AdapterPrincipalID, nextRedeem)
	if err != nil || late.Mode != "read_only" {
		return out, errors.New("expired redeemed attempt authorized another send")
	}
	var nextState string
	if err = db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, next.GrantID).Scan(&nextState); err != nil || nextState != "redeemed" {
		return out, errors.New("expired unresolved grant changed state")
	}
	out.ExpiredRedemptionReadOnly = true
	// Synthetic ledger projections below are test inputs, not native provider
	// receipts, Guest enrollment or a claim of useful capacity.
	created := time.Now().UTC().Format(time.RFC3339Nano)
	nativeProof := model.CapacityMutationProof{BindingName: binding.Name, Slot: next.Slot, GrantID: next.GrantID, RequestSHA256: next.RequestSHA256, ResourceID: "synthetic-resource", ResourceCreatedAt: created, ObservedCreationGrantID: next.GrantID, ObservedAt: time.Now().UTC(), ReceiptRef: "synthetic:no-provider-read", OwnerVerified: true, SpecVerified: true, ActionsTerminal: true, ActionsSuccessful: true, ActionIDs: []string{"synthetic-action", "synthetic-next-action"}}
	if _, err = nextStore.ConfirmMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, nativeProof); !errors.Is(err, repository.ErrCapacityConflict) {
		return out, errors.New("synthetic native read replaced transport settlement")
	}
	out.NativeReadRequiresSettlement = true
	accepted := model.CapacityMutationSettleRequest{GrantID: next.GrantID, AttemptID: nextRedeem.AttemptID, RequestSHA256: next.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: nativeProof.ResourceID, ResourceCreatedAt: created, ActionID: "synthetic-action", NextActionIDs: []string{"synthetic-next-action"}, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if _, err = nextStore.SettleMutation(ctx, binding.AdapterPrincipalID, nextSettlementNonce, accepted); err != nil {
		return out, errors.New("synthetic accepted settlement failed")
	}
	var eventCount int
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+next.GrantID).Scan(&eventCount); err != nil || eventCount != 0 {
		return out, errors.New("transport settlement alone emitted an applied event")
	}
	incomplete := nativeProof
	incomplete.ActionIDs = []string{"synthetic-action"}
	if _, err = nextStore.ConfirmMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, incomplete); !errors.Is(err, repository.ErrCapacityConflict) {
		return out, errors.New("incomplete synthetic native actions confirmed")
	}
	wrongIdentity := nativeProof
	wrongIdentity.ResourceID = "synthetic-replacement"
	if _, err = nextStore.ConfirmMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, wrongIdentity); !errors.Is(err, repository.ErrCapacityConflict) {
		return out, errors.New("replacement native identity was accepted")
	}
	for _, wrongGrant := range []string{"", uuid.NewString()} {
		wrongIdentity = nativeProof
		wrongIdentity.ObservedCreationGrantID = wrongGrant
		if _, err = nextStore.ConfirmMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, wrongIdentity); !errors.Is(err, repository.ErrCapacityConflict) {
			return out, errors.New("native creation grant identity was not enforced")
		}
	}
	confirmed, err := nextStore.ConfirmMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, nativeProof)
	if err != nil || confirmed.GrantID != next.GrantID || confirmed.State != "confirmed" {
		return out, errors.New("exact synthetic native confirmation failed")
	}
	confirmed, err = nextStore.ConfirmMutation(ctx, policy, input.Generation, input.Fence, input.LeaseOwner, nativeProof)
	if err != nil || confirmed.State != "confirmed" {
		return out, errors.New("exact synthetic confirmation replay failed")
	}
	var eventType, aggregateType, resourceID, instanceID string
	if err = db.QueryRowContext(ctx, `SELECT type,aggregate_type,payload->>'resource_id',payload->>'instance_id' FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+next.GrantID).Scan(&eventType, &aggregateType, &resourceID, &instanceID); err != nil || eventType != "native-qemu.server.ensured" || aggregateType != "native-qemu_server" || resourceID != nativeProof.ResourceID || instanceID != binding.IntegrationInstanceID {
		return out, errors.New("synthetic canonical event differs")
	}
	if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+next.GrantID).Scan(&eventCount); err != nil || eventCount != 1 {
		return out, errors.New("synthetic confirmation emitted duplicate events")
	}
	out.SyntheticConfirmationOnce = true
	return out, nil
}

func main() {
	if err := mainError(); err != nil {
		fmt.Fprintln(os.Stderr, "original grant fixture failed:", err)
		os.Exit(1)
	}
}
func mainError() error {
	if len(os.Args) == 2 && os.Args[1] == "--synthetic-seed-run" {
		return seedAndRun(false)
	}
	if len(os.Args) == 2 && os.Args[1] == "--synthetic-repository-run" {
		return seedAndRun(true)
	}
	if len(os.Args) != 1 {
		return errors.New("unsupported fixture mode")
	}
	input, err := decodeRequest(os.Stdin)
	if err != nil {
		return err
	}
	dbName, err := checkDSN(os.Getenv("DB_URL"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	source, err := checkSource(ctx, input.SourceRoot)
	if err != nil {
		return err
	}
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		return errors.New("fixture DB open failed")
	}
	defer db.Close()
	db.SetMaxOpenConns(contenders + 4)
	if err = checkOwnedPostgres(ctx, db, dbName, os.Getenv("CAPACITY_TEST_SOCKET_DIR")); err != nil {
		return err
	}
	result, err := run(ctx, db, input, source)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
