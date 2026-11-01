//go:build !nativequalification

package message

import (
	"context"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func unpublishedAWSFixture() (model.CapacityPolicySpec, model.CapacityMutationBinding, model.CapacityMutationReceipt, originalAWSStatusObservation, time.Time) {
	now := time.Now().UTC()
	digest := func(s string) string {
		b, _ := hex.DecodeString(s)
		return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
	}
	b := model.CapacityMutationBinding{Name: "vm", IntegrationInstanceID: "instance", ScopeChecksum: strings.Repeat("a", 64), ProfileName: "workers", EnsureCapability: "ensure_ec2_instance", DestroyCapability: "terminate_ec2_instance", OriginalProviderSourceCommit: strings.Repeat("e", 40), ProtectedSlots: 1, MaxSlots: 1}
	spec := &model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: b.EnsureCapability, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, ProfileChecksum: strings.Repeat("b", 64), AdmissionChecksum: strings.Repeat("c", 64), Slot: 1, NativeName: "workers-1", BootstrapSHA256: strings.Repeat("d", 64)}
	slot := model.CapacityMutationSlotBinding{Slot: 1, DesiredSpec: spec, DesiredSpecSHA256: strings.Repeat("1", 64)}
	b.Slots = []model.CapacityMutationSlotBinding{slot}
	id := "i-1234567890abcdef0"
	created := now.Add(-time.Minute).Format(time.RFC3339Nano)
	g := model.CapacityMutationGrant{GrantID: "grant", BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 1, Capability: b.EnsureCapability, RequestSHA256: slot.DesiredSpecSHA256, State: "settled"}
	receipt := model.CapacityMutationReceipt{Grant: g, Outcome: "accepted", TransportCompleted: true, ResourceID: id, ResourceCreatedAt: created, ActionID: "original-request"}
	server := &model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: id, CreatedAt: created}, Name: spec.NativeName, Status: "pending", Labels: map[string]string{"yggdrasil.io/owner": "owner", "yggdrasil.io/scope": digest(b.ScopeChecksum), "yggdrasil.io/spec": digest(spec.ProfileChecksum), "yggdrasil.io/profile": b.ProfileName, "yggdrasil.io/slot": "1", "yggdrasil.io/intent": g.GrantID}, PhysicalSpecVerified: true, ObservedAt: now.Format(time.RFC3339Nano)}
	read := *spec
	read.Capability = "observe_ec2_instance"
	read.ExpectedResourceID = id
	read.ExpectedResourceCreatedAt = created
	plan := model.CapacityVMFleetPlan{DesiredSpec: read, RequestSHA256: g.RequestSHA256, Protected: true, Server: server, ObservedAt: now.Format(time.RFC3339Nano)}
	obs := originalAWSStatusObservation{Plan: plan, Lifecycle: model.CapacityAWSInstanceLifecycle{Schema: "aws_original_instance_status_unpublished_v1", RequestID: receipt.ActionID, EC2State: "pending", ObservedAt: now}}
	return model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 60}, b, receipt, obs, now
}

func TestOriginalAWSUnpublishedIsPendingOnlyAfterExactProof(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, b, r, o, now := unpublishedAWSFixture()
	proof, err := classifyOriginalAWSStatus(ctx, p, b, r, "observed", o, now)
	if !errors.Is(err, errOriginalGuestProviderPending) || proof.ResourceID != "" || proof.AWSInstanceLifecycle != nil {
		t.Fatalf("pending became proof or failed: %+v %v", proof, err)
	}
	o.Plan.Server.Status = "running"
	o.Lifecycle.EC2State = "running"
	_, err = classifyOriginalAWSStatus(ctx, p, b, r, "observed", o, now)
	if !errors.Is(err, errOriginalGuestProviderPending) {
		t.Fatal("running unpublished refused", err)
	}
}
func TestOriginalAWSUnpublishedRefusesForeignTerminalAndExpired(t *testing.T) {
	for _, mode := range []string{"foreign_id", "foreign_birth", "foreign_request", "foreign_action", "foreign_grant", "unverified", "fencing", "terminal", "invented_system", "invented_instance", "wrong_schema", "stale", "expired", "unbounded", "uncertain"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			p, b, r, o, now := unpublishedAWSFixture()
			switch mode {
			case "foreign_id":
				o.Plan.Server.ID = "i-fffffffffffffffff"
			case "foreign_birth":
				o.Plan.Server.CreatedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
			case "foreign_request":
				o.Plan.RequestSHA256 = strings.Repeat("2", 64)
			case "foreign_action":
				o.Lifecycle.RequestID = "foreign"
			case "foreign_grant":
				o.Plan.Server.Labels["yggdrasil.io/intent"] = "foreign"
			case "unverified":
				o.Plan.Server.PhysicalSpecVerified = false
			case "fencing":
				o.Plan.ProviderFencingEvidence = true
			case "terminal":
				o.Plan.Server.Status = "stopped"
				o.Lifecycle.EC2State = "stopped"
			case "invented_system":
				o.Lifecycle.SystemStatus = "ok"
			case "invented_instance":
				o.Lifecycle.InstanceStatus = "initializing"
			case "wrong_schema":
				o.Lifecycle.Schema = "unknown"
			case "stale":
				o.Plan.ObservedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
			case "expired":
				cancel()
			case "unbounded":
				ctx = context.Background()
			case "uncertain":
				r.Outcome = "uncertain"
			}
			proof, err := classifyOriginalAWSStatus(ctx, p, b, r, "observed", o, now)
			if err == nil || errors.Is(err, errOriginalGuestProviderPending) || proof.ResourceID != "" {
				t.Fatalf("unsafe pending accepted: %+v %v", proof, err)
			}
		})
	}
}

func TestOriginalAWSTopologyPendingStrictlyBound(t *testing.T) {
	for _, mode := range []string{"valid", "id", "birth", "request", "action", "grant", "scope", "spec", "slot", "server", "authority", "quote", "health", "reason", "duplicate", "terminal", "stale", "expired", "unbounded"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			p, b, r, o, now := unpublishedAWSFixture()
			o.Plan.Server = nil
			o.Lifecycle.Schema = "aws_original_topology_pending_v1"
			o.Lifecycle.PendingReasons = []string{"metadata_pending"}
			switch mode {
			case "id":
				o.Plan.DesiredSpec.ExpectedResourceID = "i-foreign"
			case "birth":
				o.Plan.DesiredSpec.ExpectedResourceCreatedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
			case "request":
				o.Plan.RequestSHA256 = strings.Repeat("2", 64)
			case "action":
				o.Lifecycle.RequestID = "foreign"
			case "grant":
				r.Grant.GrantID = ""
			case "scope":
				r.Grant.ScopeChecksum = "foreign"
			case "spec":
				o.Plan.DesiredSpec.NativeName = "foreign"
			case "slot":
				r.Grant.Slot = 2
			case "server":
				o.Plan.Server = &model.CapacityVMServerObservation{}
			case "authority":
				o.Plan.WarmReadinessEvidence = true
			case "quote":
				o.Plan.Quote = &model.CapacityVMFleetQuote{}
			case "health":
				o.Lifecycle.SystemStatus = "ok"
			case "reason":
				o.Lifecycle.PendingReasons = []string{"provider_timeout"}
			case "duplicate":
				o.Lifecycle.PendingReasons = []string{"metadata_pending", "metadata_pending"}
			case "terminal":
				o.Lifecycle.EC2State = "stopped"
			case "stale":
				o.Plan.ObservedAt = now.Add(-time.Hour).Format(time.RFC3339Nano)
			case "expired":
				cancel()
			case "unbounded":
				ctx = context.Background()
			}
			proof, err := classifyOriginalAWSStatus(ctx, p, b, r, "observed", o, now)
			if mode == "valid" {
				if !errors.Is(err, errOriginalGuestProviderPending) || proof.ResourceID != "" {
					t.Fatalf("expected pending without proof: %+v %v", proof, err)
				}
				return
			}
			if err == nil || errors.Is(err, errOriginalGuestProviderPending) || proof.ResourceID != "" {
				t.Fatalf("accepted invalid pending: %+v %v", proof, err)
			}
		})
	}
}

type originalAWSAlreadyExpiredContext struct{ context.Context }

func (originalAWSAlreadyExpiredContext) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}
func (originalAWSAlreadyExpiredContext) Err() error { return nil }
func TestOriginalAWSTopologyDeadlineBoundary(t *testing.T) {
	p, b, r, o, now := unpublishedAWSFixture()
	o.Plan.Server = nil
	o.Lifecycle.Schema = "aws_original_topology_pending_v1"
	o.Lifecycle.PendingReasons = []string{"metadata_pending"}
	proof, err := classifyOriginalAWSStatus(originalAWSAlreadyExpiredContext{context.Background()}, p, b, r, "observed", o, now)
	if err == nil || errors.Is(err, errOriginalGuestProviderPending) || proof.ResourceID != "" {
		t.Fatalf("expired deadline accepted: %+v %v", proof, err)
	}
}

func TestOriginalAWSTopologyDecodeRealAdapterFixture(t *testing.T) {
	path := os.Getenv("ORIGINAL_PENDING_WIRE_PATH")
	if path == "" {
		t.Skip("cross-repository fixture path not requested")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var payload any
	if err := json.Unmarshal(wire, &payload); err != nil {
		t.Fatal(err)
	}
	var obs originalAWSStatusObservation
	if err := capacity.DecodeVMObservation(payload, &obs); err != nil {
		t.Fatalf("actual adapter wire rejected: %v", err)
	}
	p, b, r, _, now := unpublishedAWSFixture()
	r.ResourceID = obs.Plan.DesiredSpec.ExpectedResourceID
	r.ResourceCreatedAt = obs.Plan.DesiredSpec.ExpectedResourceCreatedAt
	r.Grant.GrantID = "22222222-2222-4222-8222-222222222222"
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	proof, err := classifyOriginalAWSStatus(ctx, p, b, r, "observed", obs, now)
	if !errors.Is(err, errOriginalGuestProviderPending) || proof.ResourceID != "" {
		t.Fatalf("actual adapter wire did not yield safe pending: %+v %v", proof, err)
	}
}

func TestOriginalAWSCreateOwnerPendingAndNoReplay(t *testing.T) {
	for _, mode := range []string{"pending_then_success", "identity_error", "transport_timeout", "original_deadline"} {
		t.Run(mode, func(t *testing.T) {
			p, b, r, o, now := unpublishedAWSFixture()
			o.Plan.Server = nil
			o.Lifecycle.Schema = "aws_original_topology_pending_v1"
			o.Lifecycle.PendingReasons = []string{"metadata_pending"}
			deadline := 2500 * time.Millisecond
			if mode == "original_deadline" {
				deadline = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()
			s := &originalProductionGuestSupplier{provider: "aws", p: p, binding: b}
			creates, reads, receipts := 0, 0, 0
			call := func(c context.Context, op string, fixed map[string]any, output any) (string, error) {
				creates++
				if c != ctx || op != b.EnsureCapability || fixed["grant_id"] != r.Grant.GrantID || fixed["dry_run"] != false {
					t.Fatal("create escaped original owner")
				}
				value, ok := output.(*originalGuestEnsureResult)
				if !ok {
					t.Fatal("unexpected create result type")
				}
				value.Plan = model.CapacityVMFleetPlan{RequestSHA256: r.Grant.RequestSHA256, Server: &model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: r.ResourceID, CreatedAt: r.ResourceCreatedAt}}}
				value.ActionID = r.ActionID
				return "accepted", nil
			}
			receipt := func(c context.Context, id string) (model.CapacityMutationReceipt, error) {
				receipts++
				if c != ctx || id != r.Grant.GrantID {
					t.Fatal("foreign receipt")
				}
				return r, nil
			}
			read := func(c context.Context, g model.CapacityMutationGrant) (model.CapacityMutationProof, error) {
				reads++
				if c != ctx || g != r.Grant {
					t.Fatal("observe changed original owner or grant")
				}
				if mode == "transport_timeout" {
					return model.CapacityMutationProof{}, context.DeadlineExceeded
				}
				if mode == "identity_error" {
					o.Plan.DesiredSpec.ExpectedResourceID = "foreign"
				}
				if reads == 1 {
					return classifyOriginalAWSStatus(c, p, b, r, "observed", o, now)
				}
				return model.CapacityMutationProof{GrantID: g.GrantID, ResourceID: r.ResourceID}, nil
			}
			proof, err := s.createOwned(ctx, r.Grant, model.CapacityGuestOriginalProvisioningPreregistration{}, call, receipt, read)
			if creates != 1 || receipts != 1 {
				t.Fatalf("create or receipt replay: create=%d receipt=%d", creates, receipts)
			}
			if mode == "pending_then_success" {
				if err != nil || reads != 2 || proof.ResourceID != r.ResourceID {
					t.Fatalf("pending did not lead to observe: reads=%d proof=%+v err=%v", reads, proof, err)
				}
				return
			}
			if err == nil || proof.ResourceID != "" || reads != 1 {
				t.Fatalf("unsafe continuation: mode=%s reads=%d proof=%+v err=%v", mode, reads, proof, err)
			}
		})
	}
}
