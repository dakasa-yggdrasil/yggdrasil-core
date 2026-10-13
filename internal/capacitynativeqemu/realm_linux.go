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
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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
	deleted          bool
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
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("REQUIRE_GUEST_PROVISIONING_NATIVE") != "true" || !filepath.IsAbs(private) || request.Schema != FixtureSchema || !AllowedCase(request.NativeCase) || request.NativeProvider != "native-qemu" || request.Listen != "127.0.0.1:18447" || request.GatewayOrigin != "https://10.0.2.2:18447" || request.ApprovedProfilePath != "approved-profile.json" || request.OriginalStepTimeoutSeconds != 600 || request.OriginalProvisioningBudgetSeconds != 420 || len(request.Slots) != 2 || request.Slots[0].Slot != 1 || request.Slots[1].Slot != 2 || request.Slots[0].ResourceID == request.Slots[1].ResourceID || !validUUID(request.Slots[0].ResourceID) || !validUUID(request.Slots[1].ResourceID) || request.Slots[0].ActorOrigin != "https://127.0.0.1:19447" || request.Slots[1].ActorOrigin != "https://127.0.0.1:20447" || !validSHA(request.CreatorSourceSHA256) || profile.Profile != capacity.GuestQualificationProfile || profile.OwnerSourceCommit != request.SourceCommit || profile.OriginalProvisioningBudgetSeconds != 420 || profile.OriginalProvisioningStepID != "original-native-qemu-create" || !request.OriginalContextDeadline.After(time.Now().UTC()) || request.OriginalStepStartedAt.IsZero() || !request.OriginalContextDeadline.Equal(request.OriginalStepStartedAt.Add(600*time.Second)) || !validSHA(request.OriginalSourcePreparationSHA256) || len(mutationToken) != 64 {
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
		return ErrOriginalUnknown
	}
	raw, re := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	ce := response.Body.Close()
	if re != nil || ce != nil || len(raw) == 2<<20 || response.StatusCode != 200 || ctx.Err() != nil || closedJSON(raw, out) != nil {
		return ErrOriginalUnknown
	}
	return nil
}

func (r *Realm) Create(ctx context.Context, store repository.CapacityStore, _ model.Manifest, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration) (model.CapacityMutationProof, error) {
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
	var nonceRaw [32]byte
	if _, err := rand.Read(nonceRaw[:]); err != nil {
		return proof, err
	}
	nonce := hex.EncodeToString(nonceRaw[:])
	attempt := uuid.NewString()
	redeem := model.CapacityMutationRedeemRequest{GrantID: grant.GrantID, AttemptID: attempt, SettlementTokenSHA256: capacity.BusinessCreationSHA256([]byte(nonce)), Capability: grant.Capability, IntegrationInstanceID: grant.IntegrationInstanceID, ScopeChecksum: grant.ScopeChecksum, ProfileName: grant.ProfileName, Slot: slot, RequestSHA256: grant.RequestSHA256}
	var redeemed model.CapacityMutationRedeemResponse
	if r.api(ctx, "/api/v1/capacity/mutations/redeem", "", redeem, &redeemed) != nil || redeemed.Mode != "write_once" || redeemed.GrantID != grant.GrantID || redeemed.AttemptID != attempt || redeemed.RequestSHA256 != grant.RequestSHA256 {
		return proof, ErrOriginalUnknown
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
	creatorWire, err := Await(ctx, filepath.Join(dir, "creator-original.json"), &creator)
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
	var settled struct {
		GrantID       string `json:"grant_id"`
		AttemptID     string `json:"attempt_id"`
		RequestSHA256 string `json:"request_sha256"`
		Status        string `json:"status"`
	}
	if r.api(ctx, "/api/v1/capacity/mutations/settle", nonce, settlement, &settled) != nil || settled.GrantID != grant.GrantID || settled.AttemptID != attempt || settled.RequestSHA256 != grant.RequestSHA256 || settled.Status != "settled" {
		return proof, ErrOriginalUnknown
	}
	r.mu.Lock()
	r.originals[slot] = native
	r.mu.Unlock()
	// These assertions are derived only after the actual independent native
	// returns above. They refer to the qualification's fixed QEMU projection,
	// never Hetzner image/labels/provider CAS or production useful capacity.
	proof = model.CapacityMutationProof{GrantID: grant.GrantID, BindingName: grant.BindingName, Slot: slot, ResourceID: creator.ResourceID, ResourceCreatedAt: created, RequestSHA256: grant.RequestSHA256, ObservedAt: native.CloseReturnedAt, ReceiptRef: "original-native-qemu:" + capacity.GuestRetirementSHA(native), OwnerVerified: true, SpecVerified: true, ActionIDs: []string{actionID}, ActionsTerminal: true, ActionsSuccessful: true, ObservedCreationGrantID: grant.GrantID}
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
	stage := Stage{FixtureSchema, "original-create-settled.json", grant.Slot, capacity.CurrentGuestCoreSource(), r.Request.SourceCommit, pre.OriginalDeadline, time.Now().UTC(), capacity.GuestRetirementSHA(witness)}
	_, err := Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, grant.Slot), stage.Stage), stage)
	return err
}

func (r *Realm) Close() {
	if transport, ok := r.Client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
