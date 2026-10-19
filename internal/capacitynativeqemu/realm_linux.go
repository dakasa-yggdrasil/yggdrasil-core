//go:build linux && nativequalification

package capacitynativeqemu

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

const FixtureSchema = "core_original_guest_native_qemu_fixture_v1"

type SlotRequest struct {
	Slot        int    `json:"slot"`
	ResourceID  string `json:"resource_id"`
	ActorOrigin string `json:"actor_origin"`
}
type SourceRequest struct {
	Schema                            string        `json:"schema"`
	NativeCase                        string        `json:"native_case"`
	SourceCommit                      string        `json:"source_commit"`
	CreatorSourceSHA256               string        `json:"creator_source_sha256"`
	OriginalSourcePreparationSHA256   string        `json:"original_source_preparation_sha256"`
	OriginalStepStartedAt             time.Time     `json:"original_step_started_at"`
	OriginalContextDeadline           time.Time     `json:"original_context_deadline"`
	OriginalStepTimeoutSeconds        int           `json:"original_step_timeout_seconds"`
	OriginalProvisioningBudgetSeconds int           `json:"original_provisioning_budget_seconds"`
	ApprovedProfilePath               string        `json:"approved_profile_path"`
	NativeProvider                    string        `json:"native_provider"`
	Slots                             []SlotRequest `json:"slots"`
	GatewayOrigin                     string        `json:"gateway_origin"`
	Listen                            string        `json:"listen"`
}
type PreCreateRequest struct {
	Schema                            string    `json:"schema"`
	Stage                             string    `json:"stage"`
	NativeCase                        string    `json:"native_case"`
	Slot                              int       `json:"slot"`
	ResourceID                        string    `json:"resource_id"`
	CreatorSourceSHA256               string    `json:"creator_source_sha256"`
	OriginalContextDeadline           time.Time `json:"original_context_deadline"`
	OriginalProvisioningBudgetSeconds int       `json:"original_provisioning_budget_seconds"`
	SourceConfigStageSHA256           string    `json:"source_config_stage_sha256"`
	SourceISOSHA256                   string    `json:"source_iso_sha256"`
	BootstrapSHA256                   string    `json:"bootstrap_sha256"`
}
type Stage struct {
	Schema                 string    `json:"schema"`
	Stage                  string    `json:"stage"`
	Slot                   int       `json:"slot"`
	CoreActualSourceCommit string    `json:"core_actual_source_commit"`
	SourceCommit           string    `json:"source_commit"`
	OriginalDeadline       time.Time `json:"original_deadline"`
	RecordedAt             time.Time `json:"recorded_at"`
	OriginalRecordSHA256   string    `json:"original_record_sha256"`
}
type Realm struct {
	PrivateDirectory string
	Request          SourceRequest
	Profile          model.CapacityGuestProtectedProfileManifest
	MutationToken    string
	CoreOrigin       string
	Client           *http.Client
	QEMUBinarySHA256 string
	mu               sync.Mutex
	started          map[int]bool
	prepared         map[int]PreCreateRequest
	originals        map[int]IndependentReturn
	preregistrations map[int]model.CapacityGuestOriginalProvisioningPreregistration
	enrollments      map[int]model.CapacityGuestOriginalProvisioningReceipt
	retirementPins   map[int]*OriginalPIDFD
	disks            map[int]OriginalDisk
	deleteDirectory  OriginalDisk
	deleted          bool
	recoveryCleanup  *SourceRecoveryCleanupSession
}

func FileSHA(ctx context.Context, path string, limit int64) (string, error) {
	raw, err := readOpened(ctx, path, limit, false, false)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}
func SlotDirectory(private string, slot int) string {
	if slot == 1 {
		return filepath.Join(private, "slot-1")
	}
	if slot == 2 {
		return filepath.Join(private, "slot-2")
	}
	return ""
}

func NewRealm(private string, request SourceRequest, profile model.CapacityGuestProtectedProfileManifest, mutationToken string, ca, certificate, key []byte) (*Realm, error) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("REQUIRE_GUEST_PROVISIONING_NATIVE") != "true" || !filepath.IsAbs(private) || request.Schema != FixtureSchema || (!AllowedCase(request.NativeCase) && !SourceContractCase(request.NativeCase) && !SourceLivePartialCase(request.NativeCase) && !SourceHistoricalConfirmCase(request.NativeCase) && !SourceTerminalCase(request.NativeCase) && !SourceFailedFloorCase(request.NativeCase)) || request.NativeProvider != "native-qemu" || request.Listen != "127.0.0.1:18447" || request.GatewayOrigin != "https://10.0.2.2:18447" || request.ApprovedProfilePath != "approved-profile.json" || request.OriginalStepTimeoutSeconds != 600 || request.OriginalProvisioningBudgetSeconds != 420 || len(request.Slots) != 2 || request.Slots[0].Slot != 1 || request.Slots[1].Slot != 2 || request.Slots[0].ResourceID == request.Slots[1].ResourceID || !validUUID(request.Slots[0].ResourceID) || !validUUID(request.Slots[1].ResourceID) || request.Slots[0].ActorOrigin != "https://127.0.0.1:19447" || request.Slots[1].ActorOrigin != "https://127.0.0.1:20447" || !validSHA(request.CreatorSourceSHA256) || profile.Profile != capacity.GuestQualificationProfile || profile.OwnerSourceCommit != request.SourceCommit || profile.OriginalProvisioningBudgetSeconds != 420 || profile.OriginalProvisioningStepID != "original-native-qemu-create" || !request.OriginalContextDeadline.After(time.Now().UTC()) || request.OriginalStepStartedAt.IsZero() || !request.OriginalContextDeadline.Equal(request.OriginalStepStartedAt.Add(600*time.Second)) || !validSHA(request.OriginalSourcePreparationSHA256) || len(mutationToken) != 64 {
		return nil, ErrOriginalUnknown
	}
	info, err := os.Lstat(private)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, ErrOriginalUnknown
	}
	pair, err := tls.X509KeyPair(certificate, key)
	pool := x509.NewCertPool()
	if err != nil || !pool.AppendCertsFromPEM(ca) {
		return nil, ErrOriginalUnknown
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}}, DisableCompression: true}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrOriginalUnknown }}
	ctx, cancel := context.WithDeadline(context.Background(), request.OriginalContextDeadline)
	defer cancel()
	binarySHA, err := FileSHA(ctx, "/usr/bin/qemu-system-x86_64", 128<<20)
	if err != nil {
		return nil, err
	}
	return &Realm{PrivateDirectory: private, Request: request, Profile: profile, MutationToken: mutationToken, CoreOrigin: "https://127.0.0.1:18447", Client: client, QEMUBinarySHA256: binarySHA, started: map[int]bool{}, prepared: map[int]PreCreateRequest{}, originals: map[int]IndependentReturn{}, preregistrations: map[int]model.CapacityGuestOriginalProvisioningPreregistration{}, enrollments: map[int]model.CapacityGuestOriginalProvisioningReceipt{}}, nil
}

// Prepare reads the ORIGINAL final ISO/bootstrap body BEFORE grant issuance.
// It never changes static config/user-data after create or learns a tuple here.
func (r *Realm) Prepare(ctx context.Context, slot int) error {
	if slot < 1 || slot > 2 {
		return ErrOriginalUnknown
	}
	dir := SlotDirectory(r.PrivateDirectory, slot)
	if err := r.verifySourceUnits(ctx, slot); err != nil {
		return err
	}
	var pre PreCreateRequest
	if _, err := Await(ctx, filepath.Join(dir, "pre-create-request.json"), &pre); err != nil {
		return err
	}
	stageSHA, err := FileSHA(ctx, filepath.Join(dir, "source-config-ready.json"), 65536)
	if err != nil {
		return err
	}
	isoSHA, err := FileSHA(ctx, filepath.Join(dir, "source.iso"), 512<<20)
	if err != nil {
		return err
	}
	bootstrapSHA, err := FileSHA(ctx, filepath.Join(dir, "user-data"), 1<<20)
	if err != nil {
		return err
	}
	selected := r.Request.NativeCase
	if slot == 1 {
		selected = "positive_original_lifecycle"
	}
	if pre.Schema != FixtureSchema || pre.Stage != "pre-create-request.json" || pre.NativeCase != selected || pre.Slot != slot || pre.ResourceID != r.Request.Slots[slot-1].ResourceID || pre.CreatorSourceSHA256 != r.Request.CreatorSourceSHA256 || !pre.OriginalContextDeadline.Equal(r.Request.OriginalContextDeadline) || pre.OriginalProvisioningBudgetSeconds != 420 || pre.SourceConfigStageSHA256 != stageSHA || pre.SourceISOSHA256 != isoSHA || pre.BootstrapSHA256 != bootstrapSHA || bootstrapSHA != r.Profile.BootstrapSHA256 {
		return ErrOriginalUnknown
	}
	if err = r.rememberOriginalDisk(ctx, slot); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started[slot] {
		return ErrOriginalUnknown
	}
	r.prepared[slot] = pre
	return nil
}

func (r *Realm) api(ctx context.Context, path, nonce string, input, out any) error {
	if path != "/api/v1/capacity/mutations/redeem" && path != "/api/v1/capacity/mutations/settle" {
		return ErrOriginalUnknown
	}
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.CoreOrigin+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.MutationToken)
	if nonce != "" {
		req.Header.Set("X-Capacity-Mutation-Settlement", nonce)
	}
	response, err := r.Client.Do(req)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return ErrOriginalUnknown
	}
	if response == nil || response.Body == nil {
		return ErrOriginalUnknown
	}
	raw, re := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	ce := response.Body.Close()
	if re != nil || ce != nil || len(raw) == 2<<20 || response.StatusCode != 200 || ctx.Err() != nil || closedJSON(raw, out) != nil {
		return ErrOriginalUnknown
	}
	return nil
}

// RejectOriginalUnsent exercises real callbacks before this realm has called
// Create for the slot. It never invents a failed native attempt or a resource.
func (r *Realm) RejectOriginalUnsent(ctx context.Context, grant model.CapacityMutationGrant) error {
	r.mu.Lock()
	started := r.started[grant.Slot]
	r.mu.Unlock()
	if started || grant.Slot < 1 || grant.Slot > 2 {
		return ErrOriginalUnknown
	}
	var nonceRaw [32]byte
	if _, err := rand.Read(nonceRaw[:]); err != nil {
		return err
	}
	nonce, attempt := hex.EncodeToString(nonceRaw[:]), uuid.NewString()
	request := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: attempt, SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(nonce)), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256}
	var first, replay model.CapacityMutationRedeemResponse
	if r.api(ctx, "/api/v1/capacity/mutations/redeem", "", request, &first) != nil || first.Mode != "write_once" || first.GrantID != grant.GrantID || first.AttemptID != attempt || first.RequestSHA256 != grant.RequestSHA256 {
		return ErrOriginalUnknown
	}
	if r.api(ctx, "/api/v1/capacity/mutations/redeem", "", request, &replay) != nil || replay.Mode != "read_only" || replay.GrantID != grant.GrantID || replay.AttemptID != attempt || replay.RequestSHA256 != grant.RequestSHA256 {
		return ErrOriginalUnknown
	}
	settlement := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: attempt, RequestSHA256: grant.RequestSHA256, Outcome: "rejected_before_send", TransportCompleted: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	type settledReturn struct {
		GrantID       string `json:"grant_id"`
		AttemptID     string `json:"attempt_id"`
		RequestSHA256 string `json:"request_sha256"`
		Status        string `json:"status"`
	}
	var settled, repeated settledReturn
	if r.api(ctx, "/api/v1/capacity/mutations/settle", nonce, settlement, &settled) != nil || settled.GrantID != grant.GrantID || settled.AttemptID != attempt || settled.RequestSHA256 != grant.RequestSHA256 || settled.Status != "settled" {
		return ErrOriginalUnknown
	}
	if r.api(ctx, "/api/v1/capacity/mutations/settle", nonce, settlement, &repeated) != nil || repeated != settled {
		return ErrOriginalUnknown
	}
	r.mu.Lock()
	started = r.started[grant.Slot]
	r.mu.Unlock()
	if started || ctx.Err() != nil {
		return ErrOriginalUnknown
	}
	contract := struct {
		Schema               string `json:"schema"`
		CoreSource           string `json:"core_source"`
		Slot                 int    `json:"slot"`
		GrantID              string `json:"grant_id"`
		FirstMode            string `json:"first_mode"`
		ReplayMode           string `json:"replay_mode"`
		Outcome              string `json:"outcome"`
		SettlementSHA256     string `json:"settlement_sha256"`
		FirstReturnSHA256    string `json:"first_return_sha256"`
		RepeatedSHA256       string `json:"repeated_return_sha256"`
		ProviderCreateCalled bool   `json:"provider_create_called"`
	}{"original_guest_unsent_terminal_contract_v1", capacity.CurrentGuestCoreSource(), grant.Slot, grant.GrantID, first.Mode, replay.Mode, settlement.Outcome, capacity.GuestRetirementSHA(settlement), capacity.GuestRetirementSHA(settled), capacity.GuestRetirementSHA(repeated), started}
	_, err := Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, grant.Slot), "unsent-terminal-contract.json"), contract)
	return err
}

func (r *Realm) Create(ctx context.Context, store repository.CapacityStore, policy model.Manifest, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityMutationProof, error) {
	var proof model.CapacityMutationProof
	slot := grant.Slot
	if slot < 1 || slot > 2 {
		return proof, ErrOriginalUnknown
	}
	dir := SlotDirectory(r.PrivateDirectory, slot)
	r.mu.Lock()
	prepared, exists := r.prepared[slot]
	if !exists || r.started[slot] {
		r.mu.Unlock()
		return proof, ErrOriginalUnknown
	}
	r.started[slot] = true
	r.preregistrations[slot] = pre
	r.mu.Unlock()
	if prepared.ResourceID != r.Request.Slots[slot-1].ResourceID || grant.Capability != "ensure_server" || pre.OriginalCreateGrantID != grant.GrantID || pre.Slot != slot {
		return proof, ErrOriginalUnknown
	}
	// All contenders are genuine authenticated callbacks for this SAME original
	// grant. A logical race cannot authorize additional native creates.
	type redemption struct {
		attempt      string
		nonce        string
		response     model.CapacityMutationRedeemResponse
		httpOriginal PG17HTTPRedeemReturn
		started      time.Time
		returned     time.Time
		err          error
	}
	const contenders = 20
	results := make(chan redemption, contenders)
	start := make(chan struct{})
	var owners sync.WaitGroup
	for n := 0; n < contenders; n++ {
		owners.Add(1)
		go func() {
			defer owners.Done()
			<-start
			var original redemption
			original.started = time.Now().UTC()
			var nonceRaw [32]byte
			if _, original.err = rand.Read(nonceRaw[:]); original.err == nil {
				original.nonce = hex.EncodeToString(nonceRaw[:])
				original.attempt = uuid.NewString()
				request := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: original.attempt, SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(original.nonce)), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: slot, RequestSHA256: grant.RequestSHA256}
				if r.Request.NativeCase == "positive_original_lifecycle" && slot == 2 {
					original.httpOriginal, original.err = r.PG17RedeemHTTP(ctx, request)
					original.response = original.httpOriginal.Returned
				} else {
					original.err = r.api(ctx, "/api/v1/capacity/mutations/redeem", "", request, &original.response)
				}
			}
			original.returned = time.Now().UTC()
			results <- original
		}()
	}
	close(start)
	owners.Wait()
	close(results)
	type returnedFact struct {
		AttemptID           string    `json:"attempt_id"`
		Mode                string    `json:"mode"`
		StartedAt           time.Time `json:"started_at"`
		ReturnedAt          time.Time `json:"returned_at"`
		TypedResponseSHA256 string    `json:"typed_response_sha256"`
	}
	facts := make([]returnedFact, 0, contenders)
	attempt, nonce := "", ""
	var redeemed model.CapacityMutationRedeemResponse
	var pg17First, pg17Replay PG17HTTPRedeemReturn
	pg17HTTPFacts := []PG17HTTPReturn{}
	writes, reads := 0, 0
	var invalid bool
	for original := range results {
		response := original.response
		if original.err != nil || response.GrantID != grant.GrantID || response.AttemptID != original.attempt || response.RequestSHA256 != grant.RequestSHA256 {
			invalid = true
			continue
		}
		switch response.Mode {
		case "write_once":
			writes++
			attempt, nonce, redeemed = original.attempt, original.nonce, response
			pg17First = original.httpOriginal
		case "read_only":
			reads++
		default:
			invalid = true
		}
		facts = append(facts, returnedFact{original.attempt, response.Mode, original.started, original.returned, capacity.GuestRetirementSHA(response)})
		if r.Request.NativeCase == "positive_original_lifecycle" && slot == 2 {
			pg17HTTPFacts = append(pg17HTTPFacts, original.httpOriginal.HTTP)
		}
	}
	if invalid || writes != 1 || reads != contenders-1 || len(facts) != contenders || ctx.Err() != nil {
		return proof, ErrOriginalUnknown
	}
	// Losing the first reply never grants a second send, even to its exact
	// winning attempt. The original repository callback must return read_only.
	replayRequest := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: attempt, SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(nonce)), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: slot, RequestSHA256: grant.RequestSHA256}
	var replayBefore originalReplaySQLSnapshot
	if r.Request.NativeCase == "positive_original_lifecycle" && slot == 2 {
		var snapshotErr error
		replayBefore, snapshotErr = readOriginalReplaySQLSnapshot(ctx, store, policy, grant, attempt, nonce)
		if snapshotErr != nil {
			return proof, snapshotErr
		}
	}
	var replay model.CapacityMutationRedeemResponse
	var replayErr error
	if r.Request.NativeCase == "positive_original_lifecycle" && slot == 2 {
		pg17Replay, replayErr = r.PG17RedeemHTTP(ctx, replayRequest)
		replay = pg17Replay.Returned
	} else {
		replayErr = r.api(ctx, "/api/v1/capacity/mutations/redeem", "", replayRequest, &replay)
	}
	if replayErr != nil || replay.Mode != "read_only" || replay.GrantID != grant.GrantID || replay.AttemptID != attempt || replay.RequestSHA256 != grant.RequestSHA256 {
		return proof, ErrOriginalUnknown
	}
	if r.Request.NativeCase == "positive_original_lifecycle" && slot == 2 {
		replayAfter, snapshotErr := readOriginalReplaySQLSnapshot(ctx, store, policy, grant, attempt, nonce)
		if snapshotErr != nil || !originalReplaySQLUnchanged(replayBefore, replayAfter) {
			return proof, ErrOriginalUnknown
		}
	}
	contract := struct {
		Schema     string         `json:"schema"`
		CoreSource string         `json:"core_source"`
		Slot       int            `json:"slot"`
		GrantID    string         `json:"grant_id"`
		WriteOnce  int            `json:"write_once"`
		ReadOnly   int            `json:"read_only"`
		Facts      []returnedFact `json:"facts"`
		ReplayMode string         `json:"same_attempt_replay_mode"`
		ReplaySHA  string         `json:"same_attempt_typed_response_sha256"`
	}{"original_guest_redemption_concurrency_v1", capacity.CurrentGuestCoreSource(), slot, grant.GrantID, writes, reads, facts, replay.Mode, capacity.GuestRetirementSHA(replay)}
	if _, err := Publish(ctx, filepath.Join(dir, "redemption-concurrency-contract.json"), contract); err != nil {
		return proof, err
	}
	if r.Request.NativeCase == "positive_original_lifecycle" && slot == 2 {
		if len(pg17HTTPFacts) != 20 {
			return proof, ErrOriginalUnknown
		}
		httpCustody := struct {
			Schema     string           `json:"schema"`
			CoreSource string           `json:"core_source"`
			GrantID    string           `json:"grant_id"`
			Slot       int              `json:"slot"`
			Returns    []PG17HTTPReturn `json:"returns"`
		}{"pg17_original_redemption_http_custody_v1", capacity.CurrentGuestCoreSource(), grant.GrantID, slot, pg17HTTPFacts}
		if _, err := Publish(ctx, filepath.Join(dir, "pg17-redemption-http-custody.json"), httpCustody); err != nil {
			return proof, err
		}
	}
	redeemedAt := time.Now().UTC()
	ready := Stage{FixtureSchema, "ready.json", slot, capacity.CurrentGuestCoreSource(), r.Request.SourceCommit, pre.OriginalDeadline, redeemedAt, capacity.GuestRetirementSHA(redeemed)}
	readyWire, err := Publish(ctx, filepath.Join(dir, "ready.json"), ready)
	if err != nil {
		return proof, err
	}
	if _, err = Publish(ctx, filepath.Join(dir, "preregistration.json"), pre); err != nil {
		return proof, err
	}
	var creator CreatorReturn
	creatorPath := filepath.Join(dir, "creator-original.json")
	if slot == 2 && (SourceLostCreateCase(r.Request.NativeCase) || PostlossSourceCase(r.Request.NativeCase)) {
		if err := readSourceLostCreateReply(ctx, dir); err != nil {
			return proof, err
		}
		creatorPath = filepath.Join(dir, "creator-original-independent-read.json")
	}
	creatorWire, err := Await(ctx, creatorPath, &creator)
	if err != nil {
		return proof, err
	}
	if CheckCreator(creator, slot, prepared.ResourceID, r.Request.SourceCommit, r.Request.CreatorSourceSHA256, digest(readyWire), redeemedAt, grant.ExpiresAt, pre.OriginalDeadline) != nil {
		return proof, ErrOriginalUnknown
	}
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	native, err := Observe(readCtx, dir, creator, r.QEMUBinarySHA256)
	cancel()
	if err != nil {
		return proof, err
	}
	r.mu.Lock()
	originalDisk, diskKnown := r.disks[slot]
	r.mu.Unlock()
	if !diskKnown || native.OriginalDisk != originalDisk {
		return proof, ErrOriginalUnknown
	}
	native.OriginalCreatorSHA256 = digest(creatorWire)
	if err = r.verifyFixedCommand(ctx, slot, native); err != nil {
		return proof, err
	}
	nativeWire, err := Publish(ctx, filepath.Join(dir, "core-native-original-read.json"), native)
	if err != nil {
		return proof, err
	}
	if err = store.RecordGuestQualificationSourceReturn(ctx, pre.PreregistrationID, "native_read", nativeWire); err != nil {
		return proof, err
	}
	actionID := "qemu-original-create:" + capacity.GuestRetirementSHA(creator)
	created := creator.OriginalCreateReturnedAt.UTC().Format(time.RFC3339Nano)
	settlement := model.CapacityMutationSettleRequest{GrantID: grant.GrantID, AttemptID: attempt, RequestSHA256: grant.RequestSHA256, Outcome: "accepted", TransportCompleted: true, ResourceID: creator.ResourceID, ResourceCreatedAt: created, ActionID: actionID, ObservedAt: native.CloseReturnedAt.UTC().Format(time.RFC3339Nano)}
	if slot == 2 && (SourceLostCreateCase(r.Request.NativeCase) || PostlossSourceCase(r.Request.NativeCase)) {
		// Actual original owning reply was empty EOF. Independent native
		// identity is retained separately; no accepted identity is invented.
		settlement.Outcome, settlement.ResourceID, settlement.ResourceCreatedAt, settlement.ActionID = "uncertain", "", "", ""
	}
	proof = model.CapacityMutationProof{GrantID: grant.GrantID, BindingName: grant.BindingName, Slot: slot, ResourceID: creator.ResourceID, ResourceCreatedAt: created, RequestSHA256: grant.RequestSHA256, ObservedAt: native.CloseReturnedAt, ReceiptRef: "original-native-qemu:" + capacity.GuestRetirementSHA(native), OwnerVerified: true, SpecVerified: true, ActionIDs: []string{actionID}, ActionsTerminal: true, ActionsSuccessful: true, ObservedCreationGrantID: grant.GrantID}
	if PositiveCase(r.Request.NativeCase) {
		if err := r.originalNativeBeforeSettlementContract(ctx, store, policy, grant, pre, proof); err != nil {
			return proof, err
		}
	}
	var settled struct {
		GrantID       string `json:"grant_id"`
		AttemptID     string `json:"attempt_id"`
		RequestSHA256 string `json:"request_sha256"`
		Status        string `json:"status"`
	}
	if r.Request.NativeCase == "positive_original_lifecycle" && slot == 2 {
		if err := r.AssertPG17HTTPCallbacks(ctx, store, policy, grant, pre, nonce, settlement, pg17First, pg17Replay); err != nil {
			return proof, err
		}
	}
	if PositiveCase(r.Request.NativeCase) {
		if err := r.originalSettlementScopeContract(ctx, store, policy, grant, pre, nonce, settlement); err != nil {
			return proof, err
		}
	}
	if r.api(ctx, "/api/v1/capacity/mutations/settle", nonce, settlement, &settled) != nil || settled.GrantID != grant.GrantID || settled.AttemptID != attempt || settled.RequestSHA256 != grant.RequestSHA256 || settled.Status != "settled" {
		return proof, ErrOriginalUnknown
	}
	r.mu.Lock()
	r.originals[slot] = native
	r.mu.Unlock()
	if slot == 2 && SourceLostCreateCase(r.Request.NativeCase) {
		stage := Stage{FixtureSchema, "original-create-settled.json", slot, capacity.CurrentGuestCoreSource(), r.Request.SourceCommit, pre.OriginalDeadline, time.Now().UTC(), capacity.GuestRetirementSHA(settlement)}
		if _, err := Publish(ctx, filepath.Join(dir, stage.Stage), stage); err != nil {
			return proof, err
		}
	}
	// These assertions are derived only after the actual independent native
	// returns above. They refer to the qualification's fixed QEMU projection,
	// never Hetzner image/labels/provider CAS or production useful capacity.
	return proof, nil
}

func (r *Realm) verifyFixedCommand(ctx context.Context, slot int, native IndependentReturn) error {
	raw, err := readOpened(ctx, filepath.Join("/proc", strconvPID(native.After.PID), "cmdline"), 65536, false, true)
	if err != nil {
		return err
	}
	dir := SlotDirectory(r.PrivateDirectory, slot)
	arguments := bytes.Split(bytes.TrimSuffix(raw, []byte{0}), []byte{0})
	if len(arguments) < 2 {
		return ErrOriginalUnknown
	}
	expected := []string{"-machine", "accel=kvm", "-cpu", "max", "-m", "1536", "-smp", "2", "-display", "none", "-no-reboot", "-uuid", r.Request.Slots[slot-1].ResourceID, "-qmp", "unix:" + filepath.Join(dir, "original-qmp.sock") + ",server=on,wait=off", "-serial", "file:" + r.publicSerial(slot), "-drive", "file=" + filepath.Join(dir, "original.qcow2") + ",format=qcow2", "-drive", "file=" + filepath.Join(dir, "seed.img") + ",format=raw,media=cdrom,readonly=on", "-drive", "file=" + filepath.Join(dir, "source.iso") + ",format=raw,media=cdrom,readonly=on", "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:" + actorPort(slot) + "-:9447", "-device", "virtio-net-pci,netdev=net0"}
	if len(arguments) != len(expected)+1 || digest(raw) != native.CommandLineSHA256 {
		return ErrOriginalUnknown
	}
	for n, value := range expected {
		if string(arguments[n+1]) != value {
			return ErrOriginalUnknown
		}
	}
	return nil
}

func strconvPID(pid int) string { return strconv.Itoa(pid) }
func actorPort(slot int) string {
	if slot == 1 {
		return "19447"
	}
	return "20447"
}
func (r *Realm) publicSerial(slot int) string {
	return filepath.Join(os.Getenv("GUEST_NATIVE_SOURCE_ROOT"), "artifacts", "guest-provisioning-native", "slot-"+strconv.Itoa(slot)+"-original-qemu-serial.log")
}

func (r *Realm) Enrolled(ctx context.Context, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, receipt model.CapacityGuestOriginalProvisioningReceipt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.preregistrations[grant.Slot] != pre || receipt.PreregistrationID != pre.PreregistrationID {
		return ErrOriginalUnknown
	}
	r.enrollments[grant.Slot] = receipt
	stage := Stage{FixtureSchema, "original-enrollment-recorded.json", grant.Slot, capacity.CurrentGuestCoreSource(), r.Request.SourceCommit, pre.OriginalDeadline, time.Now().UTC(), capacity.GuestRetirementSHA(receipt)}
	_, err := Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, grant.Slot), stage.Stage), stage)
	return err
}

func (r *Realm) Witnessed(ctx context.Context, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, witness model.CapacityGuestOriginalCreateWitness) error {
	if witness.PreregistrationID != pre.PreregistrationID || witness.OriginalCreateGrantID != grant.GrantID || witness.Tuple.Slot != grant.Slot || witness.Tuple.ResourceID != r.Request.Slots[grant.Slot-1].ResourceID {
		return ErrOriginalUnknown
	}
	if PostlossSourceCase(r.Request.NativeCase) && pre.Slot == 2 {
		if witness.SourceObservation == nil {
			return ErrOriginalUnknown
		}
		if _, err := Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, 2), "core-postloss-observed-create-witness.json"), witness); err != nil {
			return err
		}
	}
	stage := Stage{FixtureSchema, "original-create-settled.json", grant.Slot, capacity.CurrentGuestCoreSource(), r.Request.SourceCommit, pre.OriginalDeadline, time.Now().UTC(), capacity.GuestRetirementSHA(witness)}
	_, err := Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, grant.Slot), stage.Stage), stage)
	return err
}

func (r *Realm) Close() {
	if transport, ok := r.Client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

// originalSettlementScopeContract runs only on the already-created original
// tuple. The first accepted settlement uses the SAME real store with execution
// paused, then Create retains its unchanged authenticated HTTP settlement call.
// No native mutation, nonce, lease, timestamp or proof is synthesized here.
func (r *Realm) originalSettlementScopeContract(ctx context.Context, store repository.CapacityStore, policy model.Manifest, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, nonce string, settlement model.CapacityMutationSettleRequest) error {
	var p model.CapacityPolicySpec
	if json.Unmarshal(policy.Spec, &p) != nil || ctx.Err() != nil || settlement.Outcome != "accepted" || settlement.GrantID != grant.GrantID || len(nonce) < 32 || grant.Slot < 1 || grant.Slot > 2 {
		return ErrOriginalUnknown
	}
	binding, err := capacity.VMObservationBinding(p, grant.BindingName)
	if err != nil || binding.AdapterPrincipalID == "" || binding.IntegrationInstanceID != grant.IntegrationInstanceID || binding.ScopeChecksum != grant.ScopeChecksum || binding.ProfileName != grant.ProfileName {
		return ErrOriginalUnknown
	}
	// Observe intentionally redacts private lease fields. Use only the same
	// durable preregistration already loaded by the original source Create.
	if pre.OriginalCreateGrantID != grant.GrantID || pre.PolicyID != policy.ID.String() || pre.ExecutorID != store.ExecutorID || pre.LeaseOwner == "" || store.ExecutorID == "" {
		return ErrOriginalUnknown
	}
	foreignPrincipal := uuid.NewString()
	if foreignPrincipal == binding.AdapterPrincipalID {
		return ErrOriginalUnknown
	}
	if _, err = store.SettleMutation(ctx, foreignPrincipal, nonce, settlement); !errors.Is(err, repository.ErrCapacityMutationAuthorization) {
		return ErrOriginalUnknown
	}
	wrongNonce := "0" + nonce[1:]
	if wrongNonce == nonce {
		wrongNonce = "1" + nonce[1:]
	}
	if _, err = store.SettleMutation(ctx, binding.AdapterPrincipalID, wrongNonce, settlement); !errors.Is(err, repository.ErrCapacityMutationAuthorization) {
		return ErrOriginalUnknown
	}
	paused := store
	paused.ExecutionEnabled = false
	settled, err := paused.SettleMutation(ctx, binding.AdapterPrincipalID, nonce, settlement)
	if err != nil || settled.GrantID != grant.GrantID || settled.State != "settled" {
		return ErrOriginalUnknown
	}
	receipt, err := paused.MutationReceipt(ctx, binding.AdapterPrincipalID, grant.GrantID)
	if err != nil || receipt.Grant.GrantID != grant.GrantID || receipt.Outcome != settlement.Outcome || receipt.ResourceID != settlement.ResourceID || receipt.ResourceCreatedAt != settlement.ResourceCreatedAt || receipt.ActionID != settlement.ActionID || !receipt.TransportCompleted {
		return ErrOriginalUnknown
	}
	wire, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	for _, private := range []string{nonce, capacity.BusinessCreationSHA256([]byte(nonce)), pre.LeaseOwner, pre.ExecutorID} {
		if private == "" || strings.Contains(string(wire), private) {
			return ErrOriginalUnknown
		}
	}
	if _, err = paused.MutationReceipt(ctx, foreignPrincipal, grant.GrantID); !errors.Is(err, repository.ErrCapacityMutationAuthorization) {
		return ErrOriginalUnknown
	}
	conflicting := settlement
	conflicting.ActionID += "-conflicting-replay"
	if _, err = paused.SettleMutation(ctx, binding.AdapterPrincipalID, nonce, conflicting); !errors.Is(err, repository.ErrCapacityConflict) {
		return ErrOriginalUnknown
	}
	after, err := paused.MutationReceipt(ctx, binding.AdapterPrincipalID, grant.GrantID)
	if err != nil {
		return err
	}
	afterWire, err := json.Marshal(after)
	if err != nil || !bytes.Equal(wire, afterWire) || ctx.Err() != nil {
		return ErrOriginalUnknown
	}
	contract := struct {
		Schema                           string `json:"schema"`
		CoreSource                       string `json:"core_source"`
		Slot                             int    `json:"slot"`
		GrantID                          string `json:"grant_id"`
		SettlementSHA256                 string `json:"settlement_sha256"`
		ReceiptSHA256                    string `json:"receipt_sha256"`
		WrongPrincipalRefused            bool   `json:"wrong_principal_refused"`
		WrongNonceRefused                bool   `json:"wrong_nonce_refused"`
		PausedOriginalSettlementAccepted bool   `json:"paused_original_settlement_accepted"`
		PrivateFieldsAbsent              bool   `json:"private_fields_absent"`
		ForeignReceiptRefused            bool   `json:"foreign_receipt_refused"`
		ConflictRefused                  bool   `json:"conflict_refused"`
		ReceiptUnchanged                 bool   `json:"receipt_unchanged"`
	}{"original_guest_settlement_scope_contract_v1", capacity.CurrentGuestCoreSource(), grant.Slot, grant.GrantID, capacity.GuestRetirementSHA(settlement), capacity.BusinessCreationSHA256(wire), true, true, true, true, true, true, true}
	_, err = Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, grant.Slot), "settlement-scope-contract.json"), contract)
	return err
}

// SourceFenceHTTPReturn contains only closed response metadata, never an error
// body, bearer, settlement nonce or a fabricated native observation.
type SourceFenceHTTPReturn struct {
	Status          int       `json:"status"`
	BodyBytes       int       `json:"body_bytes"`
	BodySHA256      string    `json:"body_sha256"`
	StartedAt       time.Time `json:"started_at"`
	DoReturnedAt    time.Time `json:"do_returned_at"`
	ReadReturnedAt  time.Time `json:"read_returned_at"`
	CloseReturnedAt time.Time `json:"close_returned_at"`
	Mode            string    `json:"mode"`
	ProblemCode     string    `json:"problem_code"`
}

type SourceFenceContract struct {
	Schema                 string                `json:"schema"`
	Scope                  string                `json:"scope"`
	Case                   string                `json:"case"`
	CoreSource             string                `json:"core_source"`
	GuestSource            string                `json:"guest_source"`
	Namespace              string                `json:"namespace"`
	PolicyID               string                `json:"policy_id"`
	WorkflowID             string                `json:"workflow_id"`
	GrantID                string                `json:"grant_id"`
	PreregistrationID      string                `json:"preregistration_id"`
	Slot                   int                   `json:"slot"`
	Generation             int64                 `json:"generation"`
	FenceBefore            int64                 `json:"fence_before"`
	FenceAfter             int64                 `json:"fence_after"`
	RevokedID              string                `json:"revoked_id"`
	RevokedKind            string                `json:"revoked_kind"`
	RevocationRows         int64                 `json:"revocation_rows"`
	RevokedActiveAfter     bool                  `json:"revoked_active_after"`
	RecoveryOnly           bool                  `json:"recovery_only"`
	ExecutorChanged        bool                  `json:"executor_changed"`
	LeaseOwnerChanged      bool                  `json:"lease_owner_changed"`
	OriginalGrantExpired   bool                  `json:"original_grant_expired"`
	OldIssueRefused        bool                  `json:"old_issue_refused"`
	RepositoryRedeemResult string                `json:"repository_redeem_result"`
	GrantBeforeSHA256      string                `json:"grant_before_sha256"`
	GrantAfterSHA256       string                `json:"grant_after_sha256"`
	GrantTransition        string                `json:"grant_transition"`
	HTTP                   SourceFenceHTTPReturn `json:"http"`
	OriginalDeadline       time.Time             `json:"original_deadline"`
	CheckedAt              time.Time             `json:"checked_at"`
	NativeQualified        bool                  `json:"native_qualified"`
}

type SourceFenceCompletion struct {
	Schema              string `json:"schema"`
	Stage               string `json:"stage"`
	Scope               string `json:"scope"`
	Case                string `json:"case"`
	CoreSource          string `json:"core_source"`
	GuestSource         string `json:"guest_source"`
	WorkflowRunID       string `json:"workflow_run_id"`
	ContractSHA256      string `json:"contract_sha256"`
	PublicReturnsSHA256 string `json:"public_returns_sha256"`
	NativeQualified     bool   `json:"native_qualified"`
}

func (r *Realm) sourceFenceRedeem(ctx context.Context, request model.CapacityMutationRedeemRequest, executorCase bool) (SourceFenceHTTPReturn, error) {
	fact := SourceFenceHTTPReturn{StartedAt: time.Now().UTC()}
	body, err := json.Marshal(request)
	if err != nil {
		return fact, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.CoreOrigin+"/api/v1/capacity/mutations/redeem", bytes.NewReader(body))
	if err != nil {
		return fact, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.MutationToken)
	response, doErr := r.Client.Do(req)
	fact.DoReturnedAt = time.Now().UTC()
	if doErr != nil || response == nil || response.Body == nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return fact, ErrOriginalUnknown
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	fact.ReadReturnedAt = time.Now().UTC()
	closeErr := response.Body.Close()
	fact.CloseReturnedAt = time.Now().UTC()
	fact.Status, fact.BodyBytes, fact.BodySHA256 = response.StatusCode, len(raw), digest(raw)
	if readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) == 2<<20 || fact.DoReturnedAt.Before(fact.StartedAt) || fact.ReadReturnedAt.Before(fact.DoReturnedAt) || fact.CloseReturnedAt.Before(fact.ReadReturnedAt) || ctx.Err() != nil {
		return fact, ErrOriginalUnknown
	}
	if executorCase {
		var returned model.CapacityMutationRedeemResponse
		if response.StatusCode != 200 || closedJSON(raw, &returned) != nil || returned.Mode != "read_only" || returned.GrantID != request.GrantID || returned.AttemptID != request.AttemptID || returned.RequestSHA256 != request.RequestSHA256 {
			return fact, ErrOriginalUnknown
		}
		fact.Mode = returned.Mode
	} else {
		var problem struct {
			Type   string `json:"type"`
			Title  string `json:"title"`
			Status int    `json:"status"`
			Detail string `json:"detail"`
			Code   string `json:"code"`
		}
		if closedJSON(raw, &problem) != nil || problem.Status != response.StatusCode || problem.Type != "https://yggdrasil.dakasa.me/problems/"+problem.Code || problem.Title != problem.Code {
			return fact, ErrOriginalUnknown
		}
		if (response.StatusCode != 403 || problem.Code != "capacity.mutation_scope_denied") && (response.StatusCode != 409 || problem.Code != "capacity.mutation_conflict") {
			return fact, ErrOriginalUnknown
		}
		fact.ProblemCode = problem.Code
	}
	return fact, nil
}

// OriginalSourceFence is called only after the ACTUAL resolved source step has
// prepared slot1, minted its private nonce and issued its original grant. These
// are terminal administrative contract cases in disposable original namespaces.
// No private authority is supplied by the workflow input and no Create follows.
func (r *Realm) OriginalSourceFence(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) (SourceFenceContract, error) {
	contract := SourceFenceContract{}
	if !SourceContractCase(r.Request.NativeCase) || grant.Slot != 1 || grant.State != "issued" || pre.OriginalCreateGrantID != grant.GrantID || pre.CoreSourceCommit != capacity.CurrentGuestCoreSource() || pre.PolicyID != policy.ID.String() || pre.ExecutorID != store.ExecutorID || pre.OriginalWorkflowStepTimeoutSeconds != 600 || !grant.ExpiresAt.After(time.Now().UTC()) || ctx.Err() != nil {
		return contract, ErrOriginalUnknown
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(pre.OriginalDeadline) || deadline.After(r.Request.OriginalContextDeadline) {
		return contract, ErrOriginalUnknown
	}
	persistedPre, err := store.OriginalGuestProvisioning(ctx, grant.GrantID)
	if err != nil || capacity.GuestRetirementSHA(persistedPre) != capacity.GuestRetirementSHA(pre) {
		return contract, ErrOriginalUnknown
	}
	current, err := sourceFencePrivateIntent(ctx, store, policy, p)
	if err != nil || current.Generation != pre.Generation || current.FencingToken != pre.Fence || current.LeaseOwner != pre.LeaseOwner || current.LeaseExecutorID != pre.ExecutorID || current.LeaseExpiresAt == nil || current.Phase != "preparing" {
		return contract, ErrOriginalUnknown
	}
	var before []byte
	if err = store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, grant.GrantID, policy.Metadata.Namespace).Scan(&before); err != nil {
		return contract, err
	}
	contract = SourceFenceContract{Schema: "core_original_source_fence_contract_v1", Scope: "SOURCE_CONTRACT_ONLY_NO_NATIVE_AUTHORITY", Case: r.Request.NativeCase, CoreSource: capacity.CurrentGuestCoreSource(), GuestSource: r.Request.SourceCommit, Namespace: policy.Metadata.Namespace, PolicyID: policy.ID.String(), WorkflowID: store.WorkflowID.String(), GrantID: grant.GrantID, PreregistrationID: pre.PreregistrationID, Slot: 1, Generation: pre.Generation, FenceBefore: pre.Fence, FenceAfter: pre.Fence, GrantBeforeSHA256: digest(before), OriginalDeadline: deadline, NativeQualified: false}
	executorCase := r.Request.NativeCase == "source_contract_executor_fence"
	if executorCase {
		// Real DB lease expiry, no SQL timestamp edit and no renewal. The original
		// provisioning context (<=420s) still bounds the wait and all later I/O.
		wait := time.Until(*current.LeaseExpiresAt)
		if wait < 0 {
			wait = 0
		}
		if !current.LeaseExpiresAt.Before(deadline) {
			return contract, ErrOriginalUnknown
		}
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return contract, ctx.Err()
		case <-timer.C:
		}
		// Poll only the real PostgreSQL clock; wall-clock disagreement never
		// manufactures expiry or mutates authority to make recovery succeed.
		for {
			var now time.Time
			if err = store.DB.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
				return contract, err
			}
			if !now.Before(*current.LeaseExpiresAt) {
				break
			}
			select {
			case <-ctx.Done():
				return contract, ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
		recovery := store
		recovery.ExecutionEnabled, recovery.ExecutorID = false, uuid.NewString()
		assessment := QualificationAssessment(p, 0, 0.9, time.Now().UTC())
		lease, err := recovery.Recover(ctx, policy, pre.Generation, assessment)
		if err != nil || !lease.RecoveryOnly || lease.FencingToken != pre.Fence+1 || lease.LeaseOwner == pre.LeaseOwner || lease.LeaseExecutorID == pre.ExecutorID || lease.LeaseExecutorID != recovery.ExecutorID || lease.Decision.ExecutionPermitted {
			return contract, ErrOriginalUnknown
		}
		persisted, err := sourceFencePrivateIntent(ctx, recovery, policy, p)
		if err != nil || persisted.FencingToken != lease.FencingToken || persisted.LeaseExecutorID != lease.LeaseExecutorID || persisted.LeaseOwner != lease.LeaseOwner || !persisted.RecoveryOnly {
			return contract, ErrOriginalUnknown
		}
		var issue model.CapacityMutationIssue
		for _, slot := range binding.Slots {
			if slot.Slot == 1 && slot.DesiredSpec != nil {
				issue = model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: jsonBytesSourceFence(slot.DesiredSpec)}
			}
		}
		if len(issue.DesiredSpec) == 0 {
			return contract, ErrOriginalUnknown
		}
		if _, err = store.IssueMutation(ctx, policy, pre.Generation, pre.Fence, pre.LeaseOwner, issue); !errors.Is(err, repository.ErrCapacityConflict) {
			return contract, ErrOriginalUnknown
		}
		contract.FenceAfter, contract.RecoveryOnly, contract.ExecutorChanged, contract.LeaseOwnerChanged, contract.OldIssueRefused = lease.FencingToken, true, true, true, true
		contract.OriginalGrantExpired = !grant.ExpiresAt.After(time.Now().UTC())
		if !contract.OriginalGrantExpired {
			return contract, ErrOriginalUnknown
		}
	} else {
		id, kind := policy.ID, "capacity_policy"
		if r.Request.NativeCase == "source_contract_instance_fence" {
			id, err = uuid.Parse(binding.IntegrationInstanceID)
			kind = "integration_instance"
		}
		if r.Request.NativeCase == "source_contract_type_fence" {
			id, err = uuid.Parse(binding.IntegrationTypeID)
			kind = "integration_type"
		}
		if err != nil || id == uuid.Nil {
			return contract, ErrOriginalUnknown
		}
		original, err := repository.GetManifestByID(ctx, store.DB, id)
		if err != nil || original.Kind != kind || original.Metadata.Namespace != policy.Metadata.Namespace || !original.Metadata.Active {
			return contract, ErrOriginalUnknown
		}
		changed, err := repository.MarkManifestInactiveByID(ctx, store.DB, id)
		if err != nil || changed != 1 {
			return contract, ErrOriginalUnknown
		}
		revoked, err := repository.GetManifestByID(ctx, store.DB, id)
		if err != nil || revoked.ID != original.ID || revoked.Kind != original.Kind || revoked.Metadata.Namespace != original.Metadata.Namespace || revoked.Checksum != original.Checksum || revoked.Metadata.Active {
			return contract, ErrOriginalUnknown
		}
		contract.RevokedID, contract.RevokedKind, contract.RevocationRows, contract.RevokedActiveAfter = id.String(), kind, changed, revoked.Metadata.Active
		if !grant.ExpiresAt.After(time.Now().UTC()) {
			return contract, ErrOriginalUnknown
		}
	}
	var nonceRaw [32]byte
	if _, err = rand.Read(nonceRaw[:]); err != nil {
		return contract, err
	}
	nonce, attempt := hex.EncodeToString(nonceRaw[:]), uuid.NewString()
	request := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: attempt, SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(nonce)), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: 1, RequestSHA256: grant.RequestSHA256}
	redeemed, redeemErr := store.RedeemMutation(ctx, binding.AdapterPrincipalID, request)
	if executorCase {
		if redeemErr != nil || redeemed.Mode != "read_only" {
			return contract, ErrOriginalUnknown
		}
		contract.RepositoryRedeemResult, contract.GrantTransition = "read_only_after_real_expiry", "issued_to_expired_only"
	} else {
		if !errors.Is(redeemErr, repository.ErrCapacityConflict) && !errors.Is(redeemErr, repository.ErrCapacityDisabled) {
			return contract, ErrOriginalUnknown
		}
		contract.RepositoryRedeemResult, contract.GrantTransition = "revoked_scope_refused", "byte_exact_unchanged"
	}
	contract.HTTP, err = r.sourceFenceRedeem(ctx, request, executorCase)
	if err != nil {
		return contract, err
	}
	var after []byte
	if err = store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, grant.GrantID, policy.Metadata.Namespace).Scan(&after); err != nil {
		return contract, err
	}
	if executorCase {
		var original, retained map[string]json.RawMessage
		if json.Unmarshal(before, &original) != nil || json.Unmarshal(after, &retained) != nil {
			return contract, ErrOriginalUnknown
		}
		expected := grant
		expected.State = "expired"
		original["grant"] = jsonBytesSourceFence(expected)
		expectedCanonical, err := canonicalSourceFenceJSON(jsonBytesSourceFence(original))
		if err != nil {
			return contract, err
		}
		actual, err := canonicalSourceFenceJSON(jsonBytesSourceFence(retained))
		if err != nil || !bytes.Equal(expectedCanonical, actual) {
			return contract, ErrOriginalUnknown
		}
	} else if !bytes.Equal(before, after) || !grant.ExpiresAt.After(time.Now().UTC()) {
		return contract, ErrOriginalUnknown
	}
	contract.GrantAfterSHA256 = digest(after)
	// The ledger census is only a Source contract check. It is explicitly NOT
	// a no-start/off/native-provider observation or native-capacity authority.
	var grants, preregistrations, witnesses, nativeReturns, members int
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&grants); err != nil {
		return contract, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations p JOIN public.capacity_mutation_grants g ON p.create_grant_id=g.id WHERE g.namespace=$1`, policy.Metadata.Namespace).Scan(&preregistrations); err != nil {
		return contract, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`, pre.PreregistrationID).Scan(&witnesses); err != nil {
		return contract, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1`, pre.PreregistrationID).Scan(&nativeReturns); err != nil {
		return contract, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&members); err != nil {
		return contract, err
	}
	if grants != 1 || preregistrations != 1 || witnesses != 0 || nativeReturns != 0 || members != 0 {
		return contract, ErrOriginalUnknown
	}
	contract.CheckedAt = time.Now().UTC()
	if !contract.CheckedAt.Before(deadline) || ctx.Err() != nil {
		return contract, ErrOriginalUnknown
	}
	if _, err = Publish(ctx, filepath.Join(r.PrivateDirectory, "source-fence-contract.json"), contract); err != nil {
		return contract, err
	}
	if ctx.Err() != nil || !time.Now().UTC().Before(deadline) {
		return contract, ErrOriginalUnknown
	}
	return contract, nil
}

func jsonBytesSourceFence(value any) []byte { wire, _ := json.Marshal(value); return wire }

// Private source-owned identity read only. Public Observe remains redacted.
// No caller can supply an owner/executor or mutate a persisted lease here.
func sourceFencePrivateIntent(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec) (model.CapacityIntent, error) {
	var intent model.CapacityIntent
	var wire []byte
	if err := store.DB.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension).Scan(&wire); err != nil {
		return intent, err
	}
	if closedJSON(wire, &intent) != nil || intent.Namespace != policy.Metadata.Namespace || intent.PolicyID != policy.ID || intent.PolicyChecksum != policy.Checksum || intent.Environment != p.Environment || intent.Domain != p.Domain || intent.Dimension != p.Dimension || intent.Generation < 1 || intent.FencingToken < 1 || ctx.Err() != nil {
		return intent, ErrOriginalUnknown
	}
	return intent, nil
}

// Canonical JSON comparison retains number lexemes and Boolean types while
// normalizing PostgreSQL jsonb nested-object ordering. It cannot accept false
// as 0 or depend on encoding/json struct-field ordering versus jsonb ordering.
func canonicalSourceFenceJSON(wire []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, ErrOriginalUnknown
	}
	return json.Marshal(value)
}

// SourceRecoveryContract deliberately distinguishes durable logical permission
// facts from a protected provider-health/quiescence proof, which these cases
// do not possess. It cannot be consumed as a Native or no-start receipt.
type SourceRecoveryContract struct {
	Schema                  string    `json:"schema"`
	Scope                   string    `json:"scope"`
	Case                    string    `json:"case"`
	CoreSource              string    `json:"core_source"`
	GuestSource             string    `json:"guest_source"`
	Namespace               string    `json:"namespace"`
	PolicyID                string    `json:"policy_id"`
	WorkflowID              string    `json:"workflow_id"`
	GrantID                 string    `json:"grant_id"`
	PreregistrationID       string    `json:"preregistration_id"`
	Slot                    int       `json:"slot"`
	Generation              int64     `json:"generation"`
	FenceBefore             int64     `json:"fence_before"`
	FenceAfter              int64     `json:"fence_after"`
	GrantExpiresAt          time.Time `json:"grant_expires_at"`
	LeaseExpiresAt          time.Time `json:"lease_expires_at"`
	OriginalDeadline        time.Time `json:"original_deadline"`
	DBExpiryObservedAt      time.Time `json:"db_expiry_observed_at"`
	CheckedAt               time.Time `json:"checked_at"`
	GrantBeforeSHA256       string    `json:"grant_before_sha256"`
	GrantAfterSHA256        string    `json:"grant_after_sha256"`
	StateAfter              string    `json:"state_after"`
	FirstMode               string    `json:"first_mode"`
	ReplayMode              string    `json:"replay_mode"`
	FirstTypedReturnSHA256  string    `json:"first_typed_return_sha256"`
	ReplayTypedReturnSHA256 string    `json:"replay_typed_return_sha256"`
	IssueReturnedOriginal   bool      `json:"issue_returned_original"`
	RecoveryAttempted       bool      `json:"recovery_attempted"`
	RecoveryOnly            bool      `json:"recovery_only"`
	ExecutorChanged         bool      `json:"executor_changed"`
	LeaseOwnerChanged       bool      `json:"lease_owner_changed"`
	ReconcileAttempted      bool      `json:"reconcile_attempted"`
	ReconcileAccepted       bool      `json:"reconcile_accepted"`
	ReconcileErrorClass     string    `json:"reconcile_error_class"`
	ReconcileErrorBytes     int       `json:"reconcile_error_bytes"`
	ReconcileErrorSHA256    string    `json:"reconcile_error_sha256"`
	PhaseBefore             string    `json:"phase_before"`
	PhaseAfter              string    `json:"phase_after"`
	ProofBoundary           string    `json:"proof_boundary"`
	PolicyPauseApplied      bool      `json:"policy_pause_applied"`
	PolicyPauseRows         int64     `json:"policy_pause_rows"`
	PolicyActiveAfter       bool      `json:"policy_active_after"`
	PauseMode               string    `json:"pause_mode"`
	CallbackFactScope       string    `json:"callback_fact_scope"`
	NativeQualified         bool      `json:"native_qualified"`
}

// waitSourceDBExpiry never advances a clock or edits a row. Context bounds
// both host scheduling and repeated reads of the actual PostgreSQL clock.
func waitSourceDBExpiry(ctx context.Context, store repository.CapacityStore, target, originalDeadline time.Time) (time.Time, error) {
	var now time.Time
	if !target.Before(originalDeadline) {
		return now, ErrOriginalUnknown
	}
	wait := time.Until(target)
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return now, ctx.Err()
	case <-timer.C:
	}
	for {
		if err := store.DB.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return now, err
		}
		if !now.Before(target) {
			return now.UTC(), nil
		}
		tick := time.NewTimer(20 * time.Millisecond)
		select {
		case <-ctx.Done():
			tick.Stop()
			return now, ctx.Err()
		case <-tick.C:
		}
	}
}

func sourceRecoveryGrantWire(ctx context.Context, store repository.CapacityStore, policy model.Manifest, grantID string) ([]byte, error) {
	var wire []byte
	err := store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, grantID, policy.Metadata.Namespace).Scan(&wire)
	return wire, err
}

func (r *Realm) OriginalRecoveryContract(ctx context.Context, store repository.CapacityStore, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityMutationBinding, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) (SourceRecoveryContract, error) {
	contract := SourceRecoveryContract{}
	if !SourceRecoveryCase(r.Request.NativeCase) || grant.Slot != 1 || grant.State != "issued" || pre.OriginalCreateGrantID != grant.GrantID || pre.PolicyID != policy.ID.String() || pre.CoreSourceCommit != capacity.CurrentGuestCoreSource() || pre.ExecutorID != store.ExecutorID || ctx.Err() != nil {
		return contract, ErrOriginalUnknown
	}
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(pre.OriginalDeadline) || deadline.After(r.Request.OriginalContextDeadline) || !time.Now().UTC().Before(grant.ExpiresAt) {
		return contract, ErrOriginalUnknown
	}
	persistedPre, err := store.OriginalGuestProvisioning(ctx, grant.GrantID)
	if err != nil || capacity.GuestRetirementSHA(persistedPre) != capacity.GuestRetirementSHA(pre) {
		return contract, ErrOriginalUnknown
	}
	current, err := sourceFencePrivateIntent(ctx, store, policy, p)
	if err != nil || current.Phase != "preparing" || current.Generation != pre.Generation || current.FencingToken != pre.Fence || current.LeaseOwner != pre.LeaseOwner || current.LeaseExecutorID != pre.ExecutorID || current.LeaseExpiresAt == nil || current.RecoveryOnly {
		return contract, ErrOriginalUnknown
	}
	contract = SourceRecoveryContract{Schema: "core_original_source_recovery_contract_v1", Scope: "SOURCE_CONTRACT_ONLY_NO_NATIVE_AUTHORITY", Case: r.Request.NativeCase, CoreSource: capacity.CurrentGuestCoreSource(), GuestSource: r.Request.SourceCommit, Namespace: policy.Metadata.Namespace, PolicyID: policy.ID.String(), WorkflowID: store.WorkflowID.String(), GrantID: grant.GrantID, PreregistrationID: pre.PreregistrationID, Slot: 1, Generation: pre.Generation, FenceBefore: pre.Fence, FenceAfter: pre.Fence, GrantExpiresAt: grant.ExpiresAt, LeaseExpiresAt: *current.LeaseExpiresAt, OriginalDeadline: deadline, PhaseBefore: current.Phase, CallbackFactScope: "typed_original_api_returns_200_bounded_full_read_and_close_not_raw_body", NativeQualified: false}
	actualPolicy, err := repository.GetManifestByID(ctx, store.DB, policy.ID)
	if err != nil || actualPolicy.ID != policy.ID || actualPolicy.Kind != "capacity_policy" || actualPolicy.Checksum != policy.Checksum || actualPolicy.Metadata.Namespace != policy.Metadata.Namespace || !actualPolicy.Metadata.Active {
		return contract, ErrOriginalUnknown
	}
	contract.PolicyActiveAfter, contract.PauseMode = true, "none"
	if r.Request.NativeCase == "source_contract_unredeemed_expiry_recovery" {
		// Real administrative revocation of this disposable version. This is
		// not a write to spec.executionEnabled and is never restored by SQL.
		rows, err := repository.MarkManifestInactiveByID(ctx, store.DB, policy.ID)
		if err != nil || rows != 1 {
			return contract, ErrOriginalUnknown
		}
		paused, err := repository.GetManifestByID(ctx, store.DB, policy.ID)
		if err != nil || paused.ID != actualPolicy.ID || paused.Kind != actualPolicy.Kind || paused.Checksum != actualPolicy.Checksum || paused.Metadata.Namespace != actualPolicy.Metadata.Namespace || paused.Metadata.Active {
			return contract, ErrOriginalUnknown
		}
		contract.PolicyPauseApplied, contract.PolicyPauseRows, contract.PolicyActiveAfter = true, rows, false
		contract.PauseMode = "persisted_policy_manifest_inactive_and_recovery_store_execution_disabled"
	}
	var nonceRaw [32]byte
	if _, err = rand.Read(nonceRaw[:]); err != nil {
		return contract, err
	}
	nonce, attempt := hex.EncodeToString(nonceRaw[:]), uuid.NewString()
	request := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: attempt, SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(nonce)), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: grant.Slot, RequestSHA256: grant.RequestSHA256}
	if r.Request.NativeCase == "source_contract_unresolved_expiry" {
		var first model.CapacityMutationRedeemResponse
		if r.api(ctx, "/api/v1/capacity/mutations/redeem", "", request, &first) != nil || first.Mode != "write_once" || first.GrantID != grant.GrantID || first.AttemptID != attempt || first.RequestSHA256 != grant.RequestSHA256 {
			return contract, ErrOriginalUnknown
		}
		contract.FirstMode, contract.FirstTypedReturnSHA256 = first.Mode, capacity.GuestRetirementSHA(first)
		before, err := sourceRecoveryGrantWire(ctx, store, policy, grant.GrantID)
		if err != nil {
			return contract, err
		}
		contract.GrantBeforeSHA256 = digest(before)
		contract.DBExpiryObservedAt, err = waitSourceDBExpiry(ctx, store, grant.ExpiresAt, deadline)
		if err != nil || !contract.DBExpiryObservedAt.Before(*current.LeaseExpiresAt) {
			return contract, ErrOriginalUnknown
		}
		var replay model.CapacityMutationRedeemResponse
		if r.api(ctx, "/api/v1/capacity/mutations/redeem", "", request, &replay) != nil || replay.Mode != "read_only" || replay.GrantID != grant.GrantID || replay.AttemptID != attempt || replay.RequestSHA256 != grant.RequestSHA256 {
			return contract, ErrOriginalUnknown
		}
		contract.ReplayMode, contract.ReplayTypedReturnSHA256 = replay.Mode, capacity.GuestRetirementSHA(replay)
		var issue model.CapacityMutationIssue
		for _, slot := range binding.Slots {
			if slot.Slot == grant.Slot && slot.DesiredSpec != nil {
				issue = model.CapacityMutationIssue{BindingName: binding.Name, DesiredSpec: jsonBytesSourceFence(slot.DesiredSpec)}
			}
		}
		if len(issue.DesiredSpec) == 0 {
			return contract, ErrOriginalUnknown
		}
		repeated, err := store.IssueMutation(ctx, policy, pre.Generation, pre.Fence, pre.LeaseOwner, issue)
		if err != nil || repeated.GrantID != grant.GrantID || repeated.State != "redeemed" || !repeated.ExpiresAt.Equal(grant.ExpiresAt) || repeated.RequestSHA256 != grant.RequestSHA256 {
			return contract, ErrOriginalUnknown
		}
		contract.IssueReturnedOriginal = true
		after, err := sourceRecoveryGrantWire(ctx, store, policy, grant.GrantID)
		if err != nil || !bytes.Equal(before, after) {
			return contract, ErrOriginalUnknown
		}
		contract.GrantAfterSHA256, contract.StateAfter = digest(after), repeated.State
		// Source-only preparation has no genuine healthy canary/protected
		// transition proof. Do not set Healthy/ReceiptRef or skip to promoted
		// just to reach a later unresolved-guard predicate.
		contract.ProofBoundary = "TERMINAL_UNRESOLVED_GUARD_NOT_EXERCISED_MISSING_GENUINE_PROTECTED_TRANSITION_PROOF"
	} else {
		before, err := sourceRecoveryGrantWire(ctx, store, policy, grant.GrantID)
		if err != nil {
			return contract, err
		}
		contract.GrantBeforeSHA256 = digest(before)
		target := *current.LeaseExpiresAt
		if grant.ExpiresAt.After(target) {
			target = grant.ExpiresAt
		}
		contract.DBExpiryObservedAt, err = waitSourceDBExpiry(ctx, store, target, deadline)
		if err != nil {
			return contract, err
		}
		recovery := store
		recovery.ExecutionEnabled, recovery.ExecutorID = false, uuid.NewString()
		contract.RecoveryAttempted = true
		lease, err := recovery.Recover(ctx, policy, pre.Generation, QualificationAssessment(p, 0, 0.9, time.Now().UTC()))
		if err != nil || !lease.RecoveryOnly || lease.Decision.ExecutionPermitted || lease.FencingToken != pre.Fence+1 || lease.LeaseOwner == pre.LeaseOwner || lease.LeaseExecutorID == pre.ExecutorID || lease.LeaseExecutorID != recovery.ExecutorID {
			return contract, ErrOriginalUnknown
		}
		contract.FenceAfter, contract.RecoveryOnly, contract.ExecutorChanged, contract.LeaseOwnerChanged = lease.FencingToken, true, true, true
		// The original never-redeemed grant expires through its real callback;
		// no new grant, provider send or permission is obtained by this read.
		var expired model.CapacityMutationRedeemResponse
		if r.api(ctx, "/api/v1/capacity/mutations/redeem", "", request, &expired) != nil || expired.Mode != "read_only" || expired.GrantID != grant.GrantID || expired.AttemptID != attempt || expired.RequestSHA256 != grant.RequestSHA256 {
			return contract, ErrOriginalUnknown
		}
		contract.ReplayMode, contract.ReplayTypedReturnSHA256 = expired.Mode, capacity.GuestRetirementSHA(expired)
		receipt, err := store.MutationReceipt(ctx, binding.AdapterPrincipalID, grant.GrantID)
		if err != nil || receipt.Grant.State != "expired" || receipt.AttemptID != "" || receipt.Outcome != "" || receipt.TransportCompleted {
			return contract, ErrOriginalUnknown
		}
		after, err := sourceRecoveryGrantWire(ctx, store, policy, grant.GrantID)
		if err != nil {
			return contract, err
		}
		var expected, retained map[string]json.RawMessage
		if json.Unmarshal(before, &expected) != nil || json.Unmarshal(after, &retained) != nil {
			return contract, ErrOriginalUnknown
		}
		expiredGrant := grant
		expiredGrant.State = "expired"
		expected["grant"] = jsonBytesSourceFence(expiredGrant)
		expectedCanonical, err := canonicalSourceFenceJSON(jsonBytesSourceFence(expected))
		if err != nil {
			return contract, err
		}
		actualCanonical, err := canonicalSourceFenceJSON(jsonBytesSourceFence(retained))
		if err != nil || !bytes.Equal(expectedCanonical, actualCanonical) {
			return contract, ErrOriginalUnknown
		}
		contract.GrantAfterSHA256, contract.StateAfter = digest(after), "expired"
		// No invented receipt, healthy assertion, provider fence or noMutation
		// flag is passed. The real method must retain its proof requirement.
		contract.ReconcileAttempted = true
		_, refusal := recovery.Reconcile(ctx, policy, pre.Generation, lease.FencingToken, lease.LeaseOwner, "aborted", model.CapacityTransitionProof{})
		const missing = "capacity recovery requires fresh healthy proof, current provider fencing and explicitly zero outstanding mutations"
		if refusal == nil || refusal.Error() != missing {
			return contract, ErrOriginalUnknown
		}
		contract.ReconcileErrorClass, contract.ReconcileErrorBytes, contract.ReconcileErrorSHA256 = "missing_genuine_recovery_proof", len(refusal.Error()), capacity.BusinessCreationSHA256([]byte(refusal.Error()))
		persisted, err := sourceFencePrivateIntent(ctx, recovery, policy, p)
		if err != nil || capacity.GuestRetirementSHA(persisted) != capacity.GuestRetirementSHA(lease) {
			return contract, ErrOriginalUnknown
		}
		contract.ProofBoundary = "ABORT_NOT_ADMITTED_MISSING_GENUINE_HEALTH_AND_NO_MUTATION_PROOF"
	}
	post, err := sourceFencePrivateIntent(ctx, store, policy, p)
	if err != nil || post.Phase != current.Phase {
		return contract, ErrOriginalUnknown
	}
	contract.PhaseAfter = post.Phase
	var grants, preregistrations, witnesses, nativeReturns, members int
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&grants); err != nil {
		return contract, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_vm_provisioning_preregistrations p JOIN public.capacity_mutation_grants g ON p.create_grant_id=g.id WHERE g.namespace=$1`, policy.Metadata.Namespace).Scan(&preregistrations); err != nil {
		return contract, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_original_create_witnesses WHERE preregistration_id=$1`, pre.PreregistrationID).Scan(&witnesses); err != nil {
		return contract, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_qualification_native_source_returns WHERE preregistration_id=$1`, pre.PreregistrationID).Scan(&nativeReturns); err != nil {
		return contract, err
	}
	if err = store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1`, policy.Metadata.Namespace).Scan(&members); err != nil {
		return contract, err
	}
	if grants != 1 || preregistrations != 1 || witnesses != 0 || nativeReturns != 0 || members != 0 {
		return contract, ErrOriginalUnknown
	}
	contract.CheckedAt = time.Now().UTC()
	if !contract.CheckedAt.Before(deadline) || ctx.Err() != nil {
		return contract, ErrOriginalUnknown
	}
	if _, err = Publish(ctx, filepath.Join(r.PrivateDirectory, "source-recovery-contract.json"), contract); err != nil {
		return contract, err
	}
	if ctx.Err() != nil || !time.Now().UTC().Before(deadline) {
		return contract, ErrOriginalUnknown
	}
	return contract, nil
}

// This SAME actual native proof exists before transport settlement. The refusal
// is a pre-settlement state assertion, not a claim of exclusive error ordering:
// original enrollment/witness predicates are still required later as before.
func (r *Realm) originalNativeBeforeSettlementContract(ctx context.Context, store repository.CapacityStore, policy model.Manifest, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, proof model.CapacityMutationProof) error {
	if ctx.Err() != nil || grant.Slot < 1 || grant.Slot > 2 || pre.OriginalCreateGrantID != grant.GrantID || pre.PolicyID != policy.ID.String() || pre.ExecutorID != store.ExecutorID || pre.LeaseOwner == "" || proof.GrantID != grant.GrantID || proof.ResourceID != r.Request.Slots[grant.Slot-1].ResourceID {
		return ErrOriginalUnknown
	}
	read := func() ([]byte, error) {
		var raw []byte
		if err := store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2 AND generation=$3`, grant.GrantID, policy.Metadata.Namespace, pre.Generation).Scan(&raw); err != nil {
			return nil, err
		}
		var record struct {
			Grant      model.CapacityMutationGrant          `json:"grant"`
			Settlement *model.CapacityMutationSettleRequest `json:"settlement"`
		}
		if json.Unmarshal(raw, &record) != nil || record.Grant.GrantID != grant.GrantID || record.Grant.State != "redeemed" || record.Settlement != nil {
			return nil, ErrOriginalUnknown
		}
		var events, members int
		if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1 AND metadata->>'namespace'=$2`, "capacity-mutation/"+grant.GrantID, policy.Metadata.Namespace).Scan(&events); err != nil {
			return nil, err
		}
		if err := store.DB.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND integration_instance_id=$2 AND scope_checksum=$3 AND profile_name=$4 AND slot=$5 AND resource_id=$6`, policy.Metadata.Namespace, grant.IntegrationInstanceID, grant.ScopeChecksum, grant.ProfileName, grant.Slot, proof.ResourceID).Scan(&members); err != nil {
			return nil, err
		}
		if events != 0 || members != 0 || ctx.Err() != nil {
			return nil, ErrOriginalUnknown
		}
		return raw, nil
	}
	before, err := read()
	if err != nil {
		return err
	}
	if _, err := store.ConfirmMutation(ctx, policy, pre.Generation, pre.Fence, pre.LeaseOwner, proof); !errors.Is(err, repository.ErrCapacityConflict) {
		return errors.Join(ErrOriginalUnknown, err)
	}
	after, err := read()
	if err != nil || !bytes.Equal(before, after) {
		return errors.Join(ErrOriginalUnknown, err)
	}
	contract := struct {
		Schema                    string `json:"schema"`
		CoreSource                string `json:"core_source"`
		GrantID                   string `json:"grant_id"`
		Slot                      int    `json:"slot"`
		OriginalNativeProofSHA256 string `json:"original_native_proof_sha256"`
		GrantRecordSHA256         string `json:"grant_record_sha256"`
		State                     string `json:"state"`
		CanonicalEvents           int    `json:"canonical_events"`
		CanonicalMembers          int    `json:"canonical_members"`
		RecordUnchanged           bool   `json:"record_unchanged"`
	}{"original_guest_native_before_settlement_contract_v1", capacity.CurrentGuestCoreSource(), grant.GrantID, grant.Slot, capacity.GuestRetirementSHA(proof), capacity.BusinessCreationSHA256(before), "redeemed", 0, 0, true}
	_, err = Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, grant.Slot), "native-before-settlement-contract.json"), contract)
	return err
}

type SourceLivePartialContract struct {
	Schema                 string    `json:"schema"`
	Scope                  string    `json:"scope"`
	Case                   string    `json:"case"`
	PolicyID               string    `json:"policy_id"`
	WorkflowID             string    `json:"workflow_id"`
	CoreSource             string    `json:"core_source"`
	GuestSource            string    `json:"guest_source"`
	NativeQualified        bool      `json:"native_qualified"`
	BaselineUnits          int       `json:"baseline_units"`
	TargetUnits            int       `json:"target_units"`
	PartialUnits           int       `json:"partial_units"`
	OutstandingMutations   int       `json:"outstanding_mutations"`
	Slot2Grants            int       `json:"slot2_grants"`
	MemberRows             int       `json:"member_rows"`
	ProbeSHA256            string    `json:"probe_sha256"`
	PhysicalSHA256         string    `json:"physical_sha256"`
	PartialSHA256          string    `json:"partial_sha256"`
	NextGeneration         int64     `json:"next_generation"`
	NextIntentSHA256       string    `json:"next_intent_sha256"`
	PriorGeneration        int64     `json:"prior_generation"`
	RecoveryFence          int64     `json:"recovery_fence"`
	Refused                []string  `json:"refused"`
	StaleMemberDeadline    time.Time `json:"stale_member_deadline"`
	LeaseExpiredObservedAt time.Time `json:"lease_expired_observed_at"`
	CheckedAt              time.Time `json:"checked_at"`
	OriginalDeadline       time.Time `json:"original_deadline"`
}

type SourceHistoricalConfirmContract struct {
	Schema                   string    `json:"schema"`
	Scope                    string    `json:"scope"`
	Case                     string    `json:"case"`
	CoreSource               string    `json:"core_source"`
	GuestSource              string    `json:"guest_source"`
	PolicyID                 string    `json:"policy_id"`
	GrantID                  string    `json:"grant_id"`
	PreregistrationID        string    `json:"preregistration_id"`
	Generation               int64     `json:"generation"`
	RecoveryFence            int64     `json:"recovery_fence"`
	PauseRows                int64     `json:"pause_rows"`
	PolicyActiveAfter        bool      `json:"policy_active_after"`
	RecoveryExecutionEnabled bool      `json:"recovery_execution_enabled"`
	OriginalProofSHA256      string    `json:"original_proof_sha256"`
	FreshPhysicalSHA256      string    `json:"fresh_physical_sha256"`
	FreshConfirmSHA256       string    `json:"fresh_confirm_sha256"`
	OriginalReceiptSHA256    string    `json:"original_receipt_sha256"`
	ConfirmedReceiptSHA256   string    `json:"confirmed_receipt_sha256"`
	DiagnosticSHA256         string    `json:"diagnostic_sha256"`
	StateAfter               string    `json:"state_after"`
	CanonicalEvents          int       `json:"canonical_events"`
	OldObservationRefused    bool      `json:"old_observation_refused"`
	LeaseExpiredObservedAt   time.Time `json:"lease_expired_observed_at"`
	CheckedAt                time.Time `json:"checked_at"`
	OriginalDeadline         time.Time `json:"original_deadline"`
	NativeQualified          bool      `json:"native_qualified"`
}
