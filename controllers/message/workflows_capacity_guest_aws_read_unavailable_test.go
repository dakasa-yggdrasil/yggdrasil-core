//go:build !nativequalification

package message

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	"github.com/google/uuid"
)

// A declared SQL/HTTP orchestration fixture, not an original provider or a
// production qualification. The actual supplier, HTTP framing, closed decoder,
// immutable receipt join and native proof predicates run without replacements.
func TestOriginalAWSReadUnavailableSupplier(t *testing.T) {
	for _, fault := range []string{"eventual_native_proof", "original_deadline", "cancelled", "unknown_core_dto", "wrong_request", "foreign_lifetime", "physical_spec_failed", "impaired", "ordinary_rpc_error"} {
		t.Run(fault, func(t *testing.T) {
			budget := 5 * time.Second
			if fault == "original_deadline" {
				budget = 1600 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			deadline, _ := ctx.Deadline()
			f := newAWSReadUnavailableFixture(t, ctx)
			var ensures, observes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/rpc/execute" {
					t.Error("supplier left its single existing execute route")
					http.NotFound(w, r)
					return
				}
				var req model.AdapterExecuteIntegrationRequest
				if json.NewDecoder(r.Body).Decode(&req) != nil || req.Capability != req.Operation || len(req.Auth) != 0 || len(req.Metadata) != 0 {
					t.Error("closed original supplier request changed")
					return
				}
				var body []byte
				switch req.Operation {
				case "ensure_ec2_instance":
					ensures.Add(1)
					if req.Input["grant_id"] != f.grant.GrantID || req.Input["dry_run"] != false {
						t.Error("original create grant changed")
					}
					body = f.reply(t, req.Operation, "accepted", map[string]any{"plan": f.plan(time.Now().UTC()), "action_id": f.action})
				case "observe_ec2_instance":
					n := observes.Add(1)
					if req.Input["grant_id"] != f.grant.GrantID || req.Input["expected_resource_id"] != f.resource || req.Input["expected_resource_created_at"] != f.created {
						t.Error("read left the single settled lifetime")
					}
					if fault == "original_deadline" || fault == "cancelled" || fault == "eventual_native_proof" && n == 1 {
						body = []byte(`{"ok":false,"error":{"code":"execute_failed","message":"original_ec2_readiness_native_read_failed"}}`)
						if fault == "cancelled" {
							cancel()
						}
					} else if fault == "ordinary_rpc_error" {
						body = []byte(`{"ok":false,"error":{"code":"execute_failed","message":"other_read_failure"}}`)
					} else {
						at := time.Now().UTC()
						plan := f.plan(at)
						lifecycle := model.CapacityAWSInstanceLifecycle{Schema: "aws_original_request_and_instance_status_v1", RequestID: f.action, EC2State: "running", SystemStatus: "ok", InstanceStatus: "ok", ObservedAt: at}
						switch fault {
						case "wrong_request":
							lifecycle.RequestID = "foreign-request"
						case "foreign_lifetime":
							plan.Server.ID = "i-00000000000000000"
						case "physical_spec_failed":
							plan.Server.PhysicalSpecVerified = false
						case "impaired":
							lifecycle.InstanceStatus = "impaired"
						}
						output := map[string]any{"plan": plan, "lifecycle": lifecycle}
						if fault == "unknown_core_dto" {
							output["future_authority"] = true
						}
						body = f.reply(t, req.Operation, "observed", output)
					}
				default:
					t.Error("unexpected create retry, retirement or provider operation", req.Operation)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(rpc.Envelope{ContentType: "application/json", Body: body}); err != nil && fault != "cancelled" {
					t.Error(err)
				}
			}))
			defer server.Close()
			f.supplier.resolved.instanceSpec.Config = map[string]any{"base_url": server.URL}

			// Exactly one ensure, then immutable receipt reads and existing lease
			// checks only. No Issue/Redeem/Settle or lease-update SQL is expected.
			f.guard()
			f.guard()
			f.receipt()
			reads := 1
			if fault == "eventual_native_proof" || fault == "original_deadline" {
				reads = 2
			}
			for n := 0; n < reads; n++ {
				f.receipt()
				f.guard()
				if fault == "cancelled" {
					continue
				}
				f.guard()
				if fault == "original_deadline" || fault == "eventual_native_proof" && n == 0 {
					f.guard()
				}
			}
			started := time.Now()
			proof, err := f.supplier.Create(ctx, f.grant, model.CapacityGuestOriginalProvisioningPreregistration{})
			if got, _ := ctx.Deadline(); !got.Equal(deadline) {
				t.Fatal("read polling changed the original context deadline")
			}
			if ensures.Load() != 1 || observes.Load() != int32(reads) {
				t.Fatal("read-unavailable repeated create or stopped/expanded the wrong reads", ensures.Load(), observes.Load())
			}
			if fault == "eventual_native_proof" {
				if err != nil || proof.ProviderNativeIdentity == nil || proof.ProviderNativeIdentity.Provider != "aws" || proof.ResourceID != f.resource || proof.ResourceCreatedAt != f.created || proof.ObservedCreationGrantID != f.grant.GrantID || proof.AWSInstanceLifecycle == nil || proof.AWSInstanceLifecycle.RequestID != f.action || proof.AWSInstanceLifecycle.InstanceStatus != "ok" || len(proof.ActionIDs) != 0 || proof.ActionsTerminal || proof.ActionsSuccessful {
					t.Fatal("temporary unavailability did not reach the full unchanged native proof", err)
				}
				if !reflect.DeepEqual(f.supplier.createdProof, proof) || f.supplier.createdGrant.GrantID != f.grant.GrantID {
					t.Fatal("supplier did not retain the one original successful proof")
				}
			} else if !errors.Is(err, errOriginalGuestStep) || !reflect.DeepEqual(proof, model.CapacityMutationProof{}) || f.supplier.createdGrant.GrantID != "" {
				t.Fatal("a cancellation, deadline or failed proof acquired native identity", err)
			}
			if fault == "original_deadline" && (!errors.Is(ctx.Err(), context.DeadlineExceeded) || time.Since(started) > 4*time.Second) {
				t.Fatal("repeated class extended the original provisioning deadline", ctx.Err())
			}
			if fault == "cancelled" && time.Since(started) > time.Second {
				t.Fatal("cancellation waited for another poll")
			}
			if err := f.mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type awsReadUnavailableFixture struct {
	t                         *testing.T
	mock                      sqlmock.Sqlmock
	supplier                  *originalProductionGuestSupplier
	grant                     model.CapacityMutationGrant
	intent                    model.CapacityIntent
	record                    []byte
	action, resource, created string
}

func newAWSReadUnavailableFixture(t *testing.T, ctx context.Context) *awsReadUnavailableFixture {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	p, b, inventory, _ := capacityVMNodeProtocolFixture(t)
	p.VMNodeMembershipBinding = nil
	p.Profiles[0].Provider = "aws"
	b.EnsureCapability, b.DestroyCapability = "ensure_ec2_instance", "terminate_ec2_instance"
	b.OriginalProviderSourceCommit = originalAWS1655SupplierSource
	for n := range b.Slots {
		b.Slots[n].DesiredSpec.Capability = b.EnsureCapability
		b.Slots[n].DesiredSpecSHA256 = capacityGuestFixtureSHA(capacityVMNodeProtocolCanonicalSpec(t, b.Slots[n].DesiredSpec))
	}
	p.MutationBindings = []model.CapacityMutationBinding{b}
	if err := capacity.ValidatePolicy(p); err != nil {
		t.Fatal("declared unit policy", err)
	}
	raw, _ := json.Marshal(p)
	policy := model.Manifest{ID: uuid.New(), APIVersion: "yggdrasil.io/v1alpha1", Version: 1, Kind: "capacity_policy", Checksum: strings.Repeat("7", 64), Metadata: model.ManifestMetadata{Namespace: "declared-http-fixture", Name: "workers", Active: true}, Spec: raw}
	executor, owner := uuid.NewString(), uuid.NewString()
	wf := uuid.New()
	until := time.Now().Add(time.Minute).UTC()
	f := &awsReadUnavailableFixture{t: t, mock: mock, action: "declared-original-sdk-request", resource: "i-1234567890abcdef0", created: inventory.Members[1].Server.CreatedAt}
	f.grant = model.CapacityMutationGrant{GrantID: uuid.NewString(), State: "issued", BindingName: b.Name, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileName: b.ProfileName, Slot: 2, Capability: b.EnsureCapability, RequestSHA256: b.Slots[1].DesiredSpecSHA256}
	f.intent = model.CapacityIntent{PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Generation: 7, FencingToken: 9, Phase: "preparing", LeaseOwner: owner, LeaseExecutorID: executor, LeaseExpiresAt: &until}
	instance := model.Manifest{ID: uuid.MustParse(b.IntegrationInstanceID), APIVersion: "yggdrasil.io/v1alpha1", Version: 1, Kind: "integration_instance", Checksum: b.IntegrationChecksum, Metadata: model.ManifestMetadata{Namespace: "declared-http-fixture", Name: "aws", Active: true}}
	typ := model.Manifest{ID: uuid.MustParse(b.IntegrationTypeID), APIVersion: "yggdrasil.io/v1alpha1", Version: 1, Kind: "integration_type", Checksum: b.IntegrationTypeChecksum, Metadata: model.ManifestMetadata{Namespace: "declared-http-fixture", Name: "aws-type", Active: true}}
	typeRaw, err := os.ReadFile("../../repository/testdata/capacity_aws_denied_source_expected_1655_type_spec.json")
	if err != nil {
		t.Fatal(err)
	}
	typeSpec, err := manifest.ParseIntegrationTypeSpec(typeRaw)
	if err != nil {
		t.Fatal(err)
	}
	f.supplier = &originalProductionGuestSupplier{provider: "aws", parent: ctx, policy: policy, p: p, binding: b, input: guestOriginalStepInput{Generation: 7, FencingToken: 9, LeaseOwner: owner}, store: repository.CapacityStore{DB: db, WorkflowID: wf, ExecutorID: executor, ExecutionEnabled: true}, resolved: capacityResolvedObservationAdapter{instance: instance, typ: typ, instanceSpec: model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}, Status: "active"}, typeSpec: typeSpec}}
	settled := f.grant
	settled.State = "settled"
	f.record, _ = json.Marshal(map[string]any{"grant": settled, "binding": b, "workflow_id": wf, "settlement": model.CapacityMutationSettleRequest{Outcome: "accepted", TransportCompleted: true, ResourceID: f.resource, ResourceCreatedAt: f.created, ActionID: f.action}})
	return f
}

func (f *awsReadUnavailableFixture) receipt() {
	f.mock.ExpectQuery(`SELECT grant_record FROM public.capacity_mutation_grants`).WithArgs(f.grant.GrantID, f.supplier.policy.Metadata.Namespace, f.supplier.p.Environment, f.supplier.p.Domain, f.supplier.p.Dimension).WillReturnRows(sqlmock.NewRows([]string{"grant_record"}).AddRow(f.record))
}

func (f *awsReadUnavailableFixture) guard() {
	f.mock.ExpectBegin()
	f.mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 1))
	f.mock.ExpectExec(`SELECT pg_advisory_xact_lock`).WillReturnResult(sqlmock.NewResult(0, 1))
	f.mock.ExpectQuery(`SELECT checksum,active FROM public.manifests`).WillReturnRows(sqlmock.NewRows([]string{"checksum", "active"}).AddRow(f.supplier.policy.Checksum, true))
	f.mock.ExpectQuery(`SELECT active FROM public.manifests`).WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(true))
	f.mock.ExpectQuery(`SELECT clock_timestamp\(\)`).WillReturnRows(sqlmock.NewRows([]string{"now"}).AddRow(time.Now().UTC()))
	raw, _ := json.Marshal(f.intent)
	f.mock.ExpectQuery(`SELECT intent FROM public.capacity_intents`).WillReturnRows(sqlmock.NewRows([]string{"intent"}).AddRow(raw))
	f.mock.ExpectCommit()
	for _, m := range []model.Manifest{f.supplier.resolved.instance, f.supplier.resolved.typ} {
		f.mock.ExpectQuery(`(?s)FROM public\.manifests\s+WHERE id = \$1`).WithArgs(m.ID).WillReturnRows(sqlmock.NewRows(workflowManifestColumns()).AddRow(m.ID, "yggdrasil.io/v1alpha1", m.Kind, m.Metadata.Namespace, m.Metadata.Name, 1, true, "", []byte(`{}`), []byte(`{}`), m.Checksum, time.Now().UTC(), time.Now().UTC()))
	}
}

func (f *awsReadUnavailableFixture) plan(at time.Time) model.CapacityVMFleetPlan {
	spec := *f.supplier.binding.Slots[1].DesiredSpec
	spec.Capability = "observe_ec2_instance"
	_, _, inventory, _ := capacityVMNodeProtocolFixture(f.t)
	server := inventory.Members[1].Server
	server.ID, server.CreatedAt, server.Name, server.ObservedAt = f.resource, f.created, spec.NativeName, at.Format(time.RFC3339Nano)
	// Use the exact scope/spec labels of this supplier, not the fresh helper's UUIDs.
	server.Labels = map[string]string{"yggdrasil.io/owner": f.supplier.p.Owner, "yggdrasil.io/scope": inventory.Members[1].Server.Labels["yggdrasil.io/scope"], "yggdrasil.io/spec": inventory.Members[1].Server.Labels["yggdrasil.io/spec"], "yggdrasil.io/profile": f.supplier.binding.ProfileName, "yggdrasil.io/slot": "2", "yggdrasil.io/intent": f.grant.GrantID}
	server.Location, server.NetworkZone, server.ProviderAccountID, server.ProviderHostname, server.TypeID, server.ImageID = "us-east-1", "us-east-1a", "153828470928", "ip-10-0-0-2.ec2.internal", "t3.small", "ami-12345678"
	return model.CapacityVMFleetPlan{DesiredSpec: spec, RequestSHA256: f.grant.RequestSHA256, Server: &server, ObservedAt: at.Format(time.RFC3339Nano)}
}

func (f *awsReadUnavailableFixture) reply(t *testing.T, op, status string, output any) []byte {
	t.Helper()
	data := model.AdapterExecuteIntegrationResponse{Operation: op, Capability: op, Status: status, Output: output}
	raw, err := json.Marshal(map[string]any{"ok": true, "data": data})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
