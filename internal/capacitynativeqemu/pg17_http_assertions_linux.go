//go:build linux && nativequalification

package capacitynativeqemu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// PG17HTTPReturn is closed custody of the actual existing authenticated caller.
// Neither raw response text nor request, bearer, nonce or private authority is public.
type PG17HTTPReturn struct {
	Method             string    `json:"method"`
	Route              string    `json:"route"`
	CallbackOwnerLabel string    `json:"callback_owner_label"`
	Status             int       `json:"status"`
	BodyBytes          int       `json:"body_bytes"`
	BodySHA256         string    `json:"body_sha256"`
	PrivateBodyFile    string    `json:"private_body_file"`
	StartedAt          time.Time `json:"started_at"`
	DoReturnedAt       time.Time `json:"do_returned_at"`
	ReadReturnedAt     time.Time `json:"read_returned_at"`
	CloseReturnedAt    time.Time `json:"close_returned_at"`
}

type PG17HTTPRedeemReturn struct {
	Returned model.CapacityMutationRedeemResponse `json:"returned"`
	HTTP     PG17HTTPReturn                       `json:"http"`
}

// PG17HTTPContract retains only typed returns and hashes of private originals.
type PG17HTTPContract struct {
	Schema              string               `json:"schema"`
	CaseID              int                  `json:"case_id"`
	SourceCase          string               `json:"source_case"`
	CoreSource          string               `json:"core_source"`
	GrantID             string               `json:"grant_id"`
	PolicyID            string               `json:"policy_id"`
	WorkflowID          string               `json:"workflow_id"`
	First               PG17HTTPRedeemReturn `json:"first"`
	Replay              PG17HTTPRedeemReturn `json:"replay"`
	WrongNonce          PG17HTTPReturn       `json:"wrong_nonce"`
	Settlement          PG17HTTPReturn       `json:"settlement"`
	Receipt             PG17HTTPReturn       `json:"receipt"`
	CurrentGrantSHA256  string               `json:"current_grant_sha256"`
	ServerPaused        bool                 `json:"server_paused"`
	PrivateFieldsAbsent bool                 `json:"private_fields_absent"`
	NativeQualified     bool                 `json:"native_qualified"`
}

// pg17HTTP uses only this Realm's original client, origin and owned credentials.
// Only the three original routes are admitted. It adds no endpoint or retry.
func (r *Realm) pg17HTTP(ctx context.Context, method, route, nonce string, input any) ([]byte, PG17HTTPReturn, error) {
	fact := PG17HTTPReturn{Method: method, Route: route, StartedAt: time.Now().UTC()}
	if ctx.Err() != nil || r.Client == nil || r.MutationToken == "" || r.CoreOrigin == "" {
		return nil, fact, ErrOriginalUnknown
	}
	if !((method == http.MethodPost && (route == "/api/v1/capacity/mutations/redeem" || route == "/api/v1/capacity/mutations/settle")) || (method == http.MethodGet && strings.HasPrefix(route, "/api/v1/capacity/mutations/") && strings.Count(strings.TrimPrefix(route, "/api/v1/capacity/mutations/"), "/") == 0)) {
		return nil, fact, ErrOriginalUnknown
	}
	var body []byte
	var err error
	if method == http.MethodPost {
		body, err = json.Marshal(input)
		if err != nil {
			return nil, fact, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, r.CoreOrigin+route, bytes.NewReader(body))
	if err != nil {
		return nil, fact, err
	}
	req.Header.Set("Authorization", "Bearer "+r.MutationToken)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	if nonce != "" {
		req.Header.Set("X-Capacity-Mutation-Settlement", nonce)
	}
	// Deny-only lifetime label, never permission: the original main wrapper
	// tracks these exact mutation routes independently of env and refuses any
	// late request after owner seal BEFORE calling the unchanged auth/handler.
	if (method == http.MethodPost && route == "/api/v1/capacity/mutations/settle") || method == http.MethodGet {
		req.Header.Set("X-Original-PG17-Callback", "1")
		fact.CallbackOwnerLabel = "pg17-paused-callback-v1"
	}
	response, doErr := r.Client.Do(req)
	fact.DoReturnedAt = time.Now().UTC()
	if response == nil || response.Body == nil {
		return nil, fact, ErrOriginalUnknown
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	fact.ReadReturnedAt = time.Now().UTC()
	closeErr := response.Body.Close()
	fact.CloseReturnedAt = time.Now().UTC()
	fact.Status, fact.BodyBytes, fact.BodySHA256 = response.StatusCode, len(raw), capacity.BusinessCreationSHA256(raw)
	if doErr != nil || readErr != nil || closeErr != nil || len(raw) == 0 || len(raw) >= 2<<20 || fact.DoReturnedAt.Before(fact.StartedAt) || fact.ReadReturnedAt.Before(fact.DoReturnedAt) || fact.CloseReturnedAt.Before(fact.ReadReturnedAt) || ctx.Err() != nil {
		return nil, fact, ErrOriginalUnknown
	}
	fact.PrivateBodyFile = "pg17-HTTP-original-" + uuid.NewString() + ".json"
	if _, err = PublishBytes(ctx, filepath.Join(r.PrivateDirectory, fact.PrivateBodyFile), raw); err != nil {
		return nil, fact, err
	}
	return raw, fact, nil
}

// PG17RedeemHTTP replaces (never repeats) an original Redeem invocation. The
// real caller retains its own first/replay returns; no boolean can supply them.
func (r *Realm) PG17RedeemHTTP(ctx context.Context, request model.CapacityMutationRedeemRequest) (PG17HTTPRedeemReturn, error) {
	out := PG17HTTPRedeemReturn{}
	raw, fact, err := r.pg17HTTP(ctx, http.MethodPost, "/api/v1/capacity/mutations/redeem", "", request)
	out.HTTP = fact
	if err != nil || fact.Status != 200 || closedJSON(raw, &out.Returned) != nil || out.Returned.GrantID != request.GrantID || out.Returned.AttemptID != request.AttemptID || out.Returned.RequestSHA256 != request.RequestSHA256 || (out.Returned.Mode != "write_once" && out.Returned.Mode != "read_only") {
		return out, ErrOriginalUnknown
	}
	return out, nil
}

// PG17CallbackOwner is implemented by the original Core HTTP lifetime owner.
// The fixture main installs its dedicated paused-MUTATION-only owner; the outer
// workflow request must never enter it, or joining it here would self-deadlock.
type PG17CallbackOwner interface{ Join(context.Context) error }
type pg17HTTPInstallation struct {
	owner PG17CallbackOwner
	mu    sync.Mutex
	used  bool
	pid   int
}

var pg17HTTPOwners sync.Map
var pg17HTTPPauseOwner sync.Mutex

// InstallPG17CallbackOwner runs once in the actual fixture main BEFORE serving
// workflow/create requests. No workflow input, environment or callback supplies
// this object. The original main wrapper owns Begin/finish for paused mutations.
func (r *Realm) InstallPG17CallbackOwner(owner PG17CallbackOwner) error {
	if owner == nil || r.CoreOrigin != "https://127.0.0.1:18447" || r.Request.Listen != "127.0.0.1:18447" || r.Request.NativeCase != "positive_original_lifecycle" {
		return ErrOriginalUnknown
	}
	r.mu.Lock()
	fresh := len(r.started) == 0
	r.mu.Unlock()
	if !fresh {
		return ErrOriginalUnknown
	}
	_, loaded := pg17HTTPOwners.LoadOrStore(r, &pg17HTTPInstallation{owner: owner, pid: os.Getpid()})
	if loaded {
		return ErrOriginalUnknown
	}
	return nil
}

// AssertPG17HTTPCallbacks pauses ONLY the same isolated Source Core process's
// actual HTTP execution switch, as the original test does. The original fixture
// main owns its loopback TLS listener at Request.Listen and constructs this Realm
// in that process. No provider/profile/Actions identity or authority is changed.
// Every synchronous HTTP Do/Read/Close returns before exact env restoration.
// Invoke after actual creation and before the original accepted settlement.
func (r *Realm) AssertPG17HTTPCallbacks(ctx context.Context, store repository.CapacityStore, policy model.Manifest, grant model.CapacityMutationGrant, pre model.CapacityGuestOriginalProvisioningPreregistration, nonce string, settlement model.CapacityMutationSettleRequest, first, replay PG17HTTPRedeemReturn) (returnErr error) {
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || r.CoreOrigin != "https://127.0.0.1:18447" || r.Request.Listen != "127.0.0.1:18447" || os.Getenv("YGGDRASIL_ENV") != "test" || r.Request.NativeCase != "positive_original_lifecycle" || grant.Slot != 2 || grant.GrantID != pre.OriginalCreateGrantID || pre.PolicyID != policy.ID.String() || pre.WorkflowID != store.WorkflowID.String() || pre.ExecutorID != store.ExecutorID || deadline.After(pre.OriginalDeadline) || len(nonce) < 32 || settlement.GrantID != grant.GrantID || settlement.RequestSHA256 != grant.RequestSHA256 || settlement.Outcome != "accepted" || !settlement.TransportCompleted || settlement.ResourceID == "" || settlement.ResourceCreatedAt == "" || settlement.ActionID == "" || settlement.AttemptID == "" {
		return ErrOriginalUnknown
	}
	for i, returned := range []PG17HTTPRedeemReturn{first, replay} {
		mode := "write_once"
		if i == 1 {
			mode = "read_only"
		}
		if returned.Returned.Mode != mode || returned.Returned.GrantID != grant.GrantID || returned.Returned.AttemptID != settlement.AttemptID || returned.Returned.RequestSHA256 != grant.RequestSHA256 || returned.HTTP.Method != http.MethodPost || returned.HTTP.Route != "/api/v1/capacity/mutations/redeem" || returned.HTTP.Status != 200 || returned.HTTP.CallbackOwnerLabel != "" || returned.HTTP.BodyBytes <= 0 || returned.HTTP.BodySHA256 == "" || returned.HTTP.PrivateBodyFile == "" || returned.HTTP.StartedAt.IsZero() || returned.HTTP.DoReturnedAt.Before(returned.HTTP.StartedAt) || returned.HTTP.ReadReturnedAt.Before(returned.HTTP.DoReturnedAt) || returned.HTTP.CloseReturnedAt.Before(returned.HTTP.ReadReturnedAt) || returned.HTTP.CloseReturnedAt.After(time.Now().UTC()) {
			return ErrOriginalUnknown
		}
	}
	if replay.HTTP.StartedAt.Before(first.HTTP.CloseReturnedAt) {
		return ErrOriginalUnknown
	}
	// Prove the same source-created preregistration and actual slot owner BEFORE
	// changing the process-local switch. The switch is not new mutation authority.
	persisted, err := store.OriginalGuestProvisioning(ctx, grant.GrantID)
	if err != nil || capacity.GuestRetirementSHA(persisted) != capacity.GuestRetirementSHA(pre) {
		return ErrOriginalUnknown
	}
	r.mu.Lock()
	started := r.started[grant.Slot]
	ownedPre, preOwned := r.preregistrations[grant.Slot]
	r.mu.Unlock()
	if !started || !preOwned || capacity.GuestRetirementSHA(ownedPre) != capacity.GuestRetirementSHA(pre) {
		return ErrOriginalUnknown
	}
	value, installed := pg17HTTPOwners.Load(r)
	if !installed {
		return ErrOriginalUnknown
	}
	owned, valid := value.(*pg17HTTPInstallation)
	if !valid || owned.pid != os.Getpid() {
		return ErrOriginalUnknown
	}
	owned.mu.Lock()
	if owned.used {
		owned.mu.Unlock()
		return ErrOriginalUnknown
	}
	owned.used = true // original attempt only: an uncertain return never resends.
	owned.mu.Unlock()
	pg17HTTPPauseOwner.Lock()
	defer pg17HTTPPauseOwner.Unlock()
	prior, present := os.LookupEnv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED")
	if !present || prior != "true" || ctx.Err() != nil {
		return ErrOriginalUnknown
	}
	if err = os.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "false"); err != nil {
		return err
	}
	defer func() {
		// Save/restore the exact actual value, even after a failed request. Never
		// restore before an original synchronous caller/Read/Close has returned.
		joined := owned.owner.Join(context.WithoutCancel(ctx))
		returnErr = errors.Join(returnErr, joined)
		if joined != nil {
			return
		} // remain paused on unknown ownership.
		returnErr = errors.Join(returnErr, os.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", prior))
	}()
	if os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") != "false" {
		return ErrOriginalUnknown
	}
	wrong := "0" + nonce[1:]
	if wrong == nonce {
		wrong = "1" + nonce[1:]
	}
	wrongRaw, wrongFact, err := r.pg17HTTP(ctx, http.MethodPost, "/api/v1/capacity/mutations/settle", wrong, settlement)
	if err != nil || wrongFact.Status != http.StatusForbidden {
		return ErrOriginalUnknown
	}
	var denied struct {
		Type   string `json:"type"`
		Title  string `json:"title"`
		Status int    `json:"status"`
		Detail string `json:"detail"`
		Code   string `json:"code"`
	}
	if closedJSON(wrongRaw, &denied) != nil || denied.Status != http.StatusForbidden || denied.Code != "capacity.mutation_scope_denied" {
		return ErrOriginalUnknown
	}
	settledRaw, settleFact, err := r.pg17HTTP(ctx, http.MethodPost, "/api/v1/capacity/mutations/settle", nonce, settlement)
	if err != nil || settleFact.Status != http.StatusOK {
		return ErrOriginalUnknown
	}
	var settled struct {
		GrantID       string `json:"grant_id"`
		AttemptID     string `json:"attempt_id"`
		RequestSHA256 string `json:"request_sha256"`
		Status        string `json:"status"`
	}
	if closedJSON(settledRaw, &settled) != nil || settled.GrantID != grant.GrantID || settled.AttemptID != settlement.AttemptID || settled.RequestSHA256 != grant.RequestSHA256 || settled.Status != "settled" {
		return ErrOriginalUnknown
	}
	receiptRaw, receiptFact, err := r.pg17HTTP(ctx, http.MethodGet, "/api/v1/capacity/mutations/"+grant.GrantID, "", nil)
	if err != nil || receiptFact.Status != http.StatusOK {
		return ErrOriginalUnknown
	}
	var receipt model.CapacityMutationReceipt
	if closedJSON(receiptRaw, &receipt) != nil || receipt.Grant.GrantID != grant.GrantID || receipt.AttemptID != settlement.AttemptID || receipt.ActionID != settlement.ActionID || receipt.ResourceID != settlement.ResourceID || receipt.ResourceCreatedAt != settlement.ResourceCreatedAt || !receipt.TransportCompleted || receipt.Outcome != "accepted" {
		return ErrOriginalUnknown
	}
	for _, secret := range []string{r.MutationToken, nonce, capacity.BusinessCreationSHA256([]byte(nonce)), pre.LeaseOwner, store.ExecutorID} {
		if secret == "" || bytes.Contains(receiptRaw, []byte(secret)) {
			return ErrOriginalUnknown
		}
	}
	// SAME current DB row must agree with the exact authenticated HTTP receipt.
	if os.Getenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED") != "false" {
		return ErrOriginalUnknown
	}
	var stored []byte
	if err := store.DB.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, grant.GrantID, policy.Metadata.Namespace).Scan(&stored); err != nil {
		return err
	}
	var current struct {
		Grant      model.CapacityMutationGrant          `json:"grant"`
		Settlement *model.CapacityMutationSettleRequest `json:"settlement"`
	}
	if json.Unmarshal(stored, &current) != nil || current.Grant.GrantID != grant.GrantID || current.Grant.State != "settled" || current.Settlement == nil || capacity.GuestRetirementSHA(*current.Settlement) != capacity.GuestRetirementSHA(settlement) || ctx.Err() != nil {
		return ErrOriginalUnknown
	}
	contract := PG17HTTPContract{"pg17_actual_HTTP_callbacks_v1", 20, r.Request.NativeCase, capacity.CurrentGuestCoreSource(), grant.GrantID, policy.ID.String(), store.WorkflowID.String(), first, replay, wrongFact, settleFact, receiptFact, capacity.BusinessCreationSHA256(stored), true, true, false}
	_, err = Publish(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, grant.Slot), "pg17-http-callback-contract.json"), contract)
	return err
}
