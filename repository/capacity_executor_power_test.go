package repository

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executoractivity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executorpower"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

const powerOperator = "11111111-1111-4111-8111-111111111111"

type powerObserverMock struct {
	o     executorpower.Observation
	calls int
}

func (o *powerObserverMock) Observe(_ context.Context, _ executorpower.Resource) (executorpower.Observation, error) {
	o.calls++
	return o.o, nil
}
func powerPolicy(t *testing.T) (model.Manifest, model.CapacityPolicySpec, executorpower.Binding, time.Time) {
	policy := executorActivityRepositoryPolicy(t)
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(policy.Spec, &p); err != nil {
		t.Fatal(err)
	}
	b := executorpower.Binding{Mode: executorpower.Kind, Enabled: true, Resource: executorpower.Resource{AccountID: "123456789012", Region: "us-east-1", InstanceID: "i-0123456789abcdef0", Volumes: []string{"vol-0123456789abcdef0"}}, IntegrationID: uuid.NewString(), IntegrationChecksum: strings.Repeat("a", 64), TypeID: uuid.NewString(), TypeChecksum: strings.Repeat("b", 64), AdapterPrincipal: "adapter", ControllerPrincipal: "controller", Operators: []string{powerOperator}, AdoptionWorkflow: executorpower.Workflow{Namespace: "ops", Name: "adopt-lab"}, GrantSeconds: 30}
	p.ExecutorPowerBinding = &b
	policy.Spec, _ = json.Marshal(p)
	return policy, p, b, time.Now().UTC().Truncate(time.Second)
}
func powerTxExpect(m sqlmock.Sqlmock, policy model.Manifest, p model.CapacityPolicySpec, wf uuid.UUID, adopt bool, now time.Time) {
	b := *p.ExecutorPowerBinding
	workflow := p.Workflow
	if adopt {
		workflow = model.ManifestSelector{Namespace: b.AdoptionWorkflow.Namespace, Name: b.AdoptionWorkflow.Name}
	}
	m.ExpectBegin()
	m.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("capacity-power-instance/" + b.Resource.InstanceID).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery(`SELECT checksum,active FROM public.manifests`).WithArgs(policy.ID, policy.Metadata.Namespace, policy.Metadata.Name).WillReturnRows(sqlmock.NewRows([]string{"checksum", "active"}).AddRow(policy.Checksum, true))
	m.ExpectQuery(`SELECT active FROM public.manifests`).WithArgs(wf, workflow.Namespace, workflow.Name).WillReturnRows(sqlmock.NewRows([]string{"active"}).AddRow(true))
	ref, _ := json.Marshal(model.ManifestSelector{ManifestID: b.TypeID})
	m.ExpectQuery(`SELECT checksum,active,spec`).WithArgs(b.IntegrationID).WillReturnRows(sqlmock.NewRows([]string{"checksum", "active", "type_ref"}).AddRow(b.IntegrationChecksum, true, ref))
	m.ExpectQuery(`SELECT checksum,active,namespace,name,version`).WithArgs(b.TypeID).WillReturnRows(sqlmock.NewRows([]string{"checksum", "active", "namespace", "name", "version"}).AddRow(b.TypeChecksum, true, "ops", "aws", 1))
	m.ExpectQuery(`SELECT spec FROM public.manifests`).WithArgs(b.TypeID, b.TypeChecksum).WillReturnRows(sqlmock.NewRows([]string{"spec"}).AddRow([]byte(powerCatalogJSON)))
	m.ExpectQuery(`SELECT clock_timestamp`).WillReturnRows(sqlmock.NewRows([]string{"now"}).AddRow(now))
}
func TestCapacityExecutorPowerAuthenticatedAdoptionAndCommitAmbiguity(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprint(unknown), func(t *testing.T) {
			policy, p, b, now := powerPolicy(t)
			db, m, _ := sqlmock.New()
			defer db.Close()
			o := &powerObserverMock{o: executorpower.Observation{Resource: b.Resource, State: "stopped", ObservedAt: now}}
			store := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorPowerEnabled: true, ExecutorPowerOperator: powerOperator, WorkflowID: uuid.New(), ExecutorPowerObserver: o}
			powerTxExpect(m, policy, p, store.WorkflowID, true, now)
			m.ExpectQuery(`SELECT count\(\*\) FROM public.capacity_resource_slots`).WithArgs(executorpower.Key(b.Resource), b.Resource.InstanceID).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			m.ExpectQuery(`SELECT count\(\*\) FROM public.capacity_mutation_grants WHERE NOT`).WithArgs(b.Resource.InstanceID).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
			m.ExpectExec(`INSERT INTO public.capacity_resource_slots`).WithArgs(b.IntegrationID, executorpower.Digest(b.Resource), executorPowerProfile, "ops", p.Environment, p.Domain, p.Dimension, b.Resource.InstanceID, sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
			if unknown {
				m.ExpectCommit().WillReturnError(errors.New("lost commit response"))
			} else {
				m.ExpectCommit()
			}
			a, err := store.AdoptExecutorPower(context.Background(), policy)
			if unknown {
				if !errors.Is(err, executorpower.ErrUnknown) || a.ID != "" {
					t.Fatal("ambiguous commit returned adoption", err)
				}
			} else if err != nil || a.Operator != powerOperator || a.Kind != executorpower.AdoptionKind || a.BindingSHA != executorpower.Digest(b) {
				t.Fatal(err, a)
			}
			if o.calls != 1 {
				t.Fatal("independent observation missing")
			}
			if err = m.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestCapacityExecutorPowerAdoptionDefaultOffAndWrongOperator(t *testing.T) {
	policy, _, b, now := powerPolicy(t)
	o := &powerObserverMock{o: executorpower.Observation{Resource: b.Resource, State: "stopped", ObservedAt: now}}
	for _, s := range []CapacityStore{{}, {ExecutionEnabled: true, ExecutorPowerEnabled: true, ExecutorPowerOperator: "foreign", ExecutorPowerObserver: o}, {ExecutionEnabled: true, ExecutorPowerOperator: powerOperator, ExecutorPowerObserver: o}, {ExecutionEnabled: true, ExecutorPowerEnabled: true, ExecutorPowerOperator: powerOperator}} {
		if _, err := s.AdoptExecutorPower(context.Background(), policy); err == nil {
			t.Fatal("unqualified adoption admitted")
		}
	}
	if o.calls != 0 {
		t.Fatal("unauthorized caller reached provider")
	}
}
func TestCapacityExecutorPowerNeverOverwritesAdoption(t *testing.T) {
	policy, p, b, now := powerPolicy(t)
	db, m, _ := sqlmock.New()
	defer db.Close()
	o := &powerObserverMock{o: executorpower.Observation{Resource: b.Resource, State: "stopped", ObservedAt: now}}
	s := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorPowerEnabled: true, ExecutorPowerOperator: powerOperator, WorkflowID: uuid.New(), ExecutorPowerObserver: o}
	powerTxExpect(m, policy, p, s.WorkflowID, true, now)
	m.ExpectQuery(`SELECT count\(\*\) FROM public.capacity_resource_slots`).WithArgs(executorpower.Key(b.Resource), b.Resource.InstanceID).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	m.ExpectRollback()
	if _, err := s.AdoptExecutorPower(context.Background(), policy); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal(err)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestCapacityExecutorPowerIssuesInExistingLedgerWithActivityFence(t *testing.T) {
	policy, p, b, now := powerPolicy(t)
	db, m, _ := sqlmock.New()
	defer db.Close()
	s := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorPowerEnabled: true, ExecutorID: "invocation", ExecutorActivityPrincipal: "machine:controller", WorkflowID: uuid.New()}
	powerTxExpect(m, policy, p, s.WorkflowID, false, now)
	adoption, _ := executorpower.Adopt(b, powerOperator, uuid.NewString(), executorpower.Observation{Resource: b.Resource, State: "stopped", ObservedAt: now}, now, true)
	raw, _ := json.Marshal(adoption)
	m.ExpectQuery(`SELECT slot_record FROM public.capacity_resource_slots`).WithArgs(b.IntegrationID, executorpower.Digest(b.Resource), executorPowerProfile, "ops", p.Environment, p.Domain, p.Dimension, b.Resource.InstanceID).WillReturnRows(sqlmock.NewRows([]string{"slot_record"}).AddRow(raw))
	r := executoractivity.ExactResource{AccountID: b.Resource.AccountID, Region: b.Resource.Region, InstanceID: b.Resource.InstanceID, OwnershipBindingID: adoption.ID}
	state := executoractivity.ExecutorActivityState{Revision: 3, UpdatedAt: now, Epoch: 2, Tasks: map[string]executoractivity.ExecutorTaskLease{"task": {Owner: "machine:task", Sequence: 1, ExpiresAt: now.Add(time.Minute)}}, BoundResource: &r, Power: &executoractivity.PowerCommand{ID: "command", Action: "start", Resource: r, IssuedAt: now}, PinnedPolicy: &executoractivity.ExecutorActivityPolicy{MaxObservationAge: 30 * time.Second}}
	raw, _ = json.Marshal(state)
	key, _ := json.Marshal([]string{"ops", p.Environment, p.Domain, p.Dimension})
	pin, _ := json.Marshal([]string{policy.ID.String(), policy.Checksum, s.WorkflowID.String()})
	m.ExpectQuery(`SELECT revision, state FROM public.capacity_executor_activity`).WithArgs(string(key), fmt.Sprintf("%x", sha256.Sum256(pin))).WillReturnRows(sqlmock.NewRows([]string{"revision", "state"}).AddRow(state.Revision, raw))
	m.ExpectQuery(`SELECT count\(\*\) FROM public.capacity_mutation_grants`).WithArgs(executorpower.Kind, "command", adoption.ID).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	m.ExpectExec(`INSERT INTO public.capacity_mutation_grants`).WithArgs(sqlmock.AnyArg(), "ops", p.Environment, p.Domain, p.Dimension, int64(3), b.IntegrationID, executorpower.Digest(b.Resource), executorPowerProfile, sqlmock.AnyArg(), now.Add(30*time.Second)).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	g, err := s.IssueExecutorPower(context.Background(), policy, "command")
	if err != nil || g.Action != "start" || g.AdoptionID != adoption.ID {
		t.Fatal(err, g)
	}
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestCapacityExecutorPowerVMDiscriminatorSeparation(t *testing.T) {
	for _, raw := range []string{`{"authority_kind":"ec2_power_v1"}`, `{"authority_kind":"ec2_operator_adoption_v1"}`, `{"Authority_Kind":"ec2_power_v1"}`} {
		var vm capacityMutationRecord
		var slot capacityResourceSlot
		if json.Unmarshal([]byte(raw), &vm) == nil || json.Unmarshal([]byte(raw), &slot) == nil {
			t.Fatal("foreign authority consumed by VM handler")
		}
	}
	var vm capacityMutationRecord
	if json.Unmarshal([]byte(`{"generation":1}`), &vm) != nil || vm.Generation != 1 {
		t.Fatal("legacy VM broken")
	}
	if _, err := decodePowerGrant([]byte(`{"grant":{"grant_id":"foreign"}}`)); err == nil {
		t.Fatal("VM record consumed by power handler")
	}
}

func powerCallbackFixture(t *testing.T) (model.Manifest, executorpower.Grant, time.Time) {
	policy, _, b, now := powerPolicy(t)
	scope := executorpower.Scope{Namespace: policy.Metadata.Namespace, Environment: "lab", Domain: "ai", Dimension: "executor", PolicyID: policy.ID.String(), PolicyChecksum: policy.Checksum, WorkflowID: uuid.NewString()}
	g := executorpower.Grant{Kind: executorpower.Kind, ID: uuid.NewString(), AdoptionID: uuid.NewString(), Action: "stop", CommandID: "original", Epoch: 2, State: "issued", IssuedAt: now, ExpiresAt: now.Add(30 * time.Second), Binding: b, Scope: scope}
	g.RequestSHA = executorpower.GrantSHA(g)
	return policy, g, now
}
func powerCallbackExpect(m sqlmock.Sqlmock, g executorpower.Grant, now time.Time) {
	raw, _ := json.Marshal(g)
	m.ExpectQuery(`SELECT state,grant_record FROM public.capacity_mutation_grants WHERE id=\$1$`).WithArgs(g.ID).WillReturnRows(sqlmock.NewRows([]string{"state", "grant_record"}).AddRow(g.State, raw))
	m.ExpectBegin()
	m.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs(sqlmock.AnyArg()).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("capacity-power-instance/" + g.Binding.Resource.InstanceID).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery(`SELECT state,grant_record FROM public.capacity_mutation_grants WHERE id=\$1 FOR UPDATE`).WithArgs(g.ID).WillReturnRows(sqlmock.NewRows([]string{"state", "grant_record"}).AddRow(g.State, raw))
	m.ExpectQuery(`SELECT clock_timestamp`).WillReturnRows(sqlmock.NewRows([]string{"now"}).AddRow(now))
}
func TestCapacityExecutorPowerRevokedRedeemPersistsNoSend(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		t.Run(fmt.Sprint(unknown), func(t *testing.T) {
			policy, g, now := powerCallbackFixture(t)
			db, m, _ := sqlmock.New()
			defer db.Close()
			powerCallbackExpect(m, g, now)
			m.ExpectQuery(`SELECT spec,checksum,active FROM public.manifests`).WithArgs(g.Scope.PolicyID).WillReturnRows(sqlmock.NewRows([]string{"spec", "checksum", "active"}).AddRow(policy.Spec, policy.Checksum, false))
			m.ExpectExec(`UPDATE public.capacity_mutation_grants SET state`).WithArgs(g.ID, "rejected", sqlmock.AnyArg(), executorpower.Kind).WillReturnResult(sqlmock.NewResult(0, 1))
			if unknown {
				m.ExpectCommit().WillReturnError(errors.New("commit unknown"))
			} else {
				m.ExpectCommit()
			}
			c := executorpower.Claim{GrantID: g.ID, Action: g.Action, CommandID: g.CommandID, RequestSHA: g.RequestSHA, AttemptID: uuid.NewString(), SettlementSHA: executorpower.Digest(strings.Repeat("t", 32))}
			r, err := (CapacityStore{DB: db, ExecutionEnabled: true, ExecutorPowerEnabled: true}).RedeemExecutorPower(context.Background(), g.Binding.AdapterPrincipal, g.Binding.IntegrationID, c)
			if unknown {
				if !errors.Is(err, executorpower.ErrUnknown) || r.Mode != "" {
					t.Fatal("ambiguous commit returned authority", err, r)
				}
			} else if err != nil || r.Mode != "read_only" {
				t.Fatal(err, r)
			}
			if err = m.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestCapacityExecutorPowerOriginalLateSettlementWithExecutionOff(t *testing.T) {
	_, g, now := powerCallbackFixture(t)
	token := strings.Repeat("s", 32)
	c := executorpower.Claim{GrantID: g.ID, Action: g.Action, CommandID: g.CommandID, RequestSHA: g.RequestSHA, AttemptID: uuid.NewString(), SettlementSHA: executorpower.Digest(token)}
	if _, err := executorpower.Redeem(&g, g.Binding.AdapterPrincipal, c, now, true, true); err != nil {
		t.Fatal(err)
	}
	db, m, _ := sqlmock.New()
	defer db.Close()
	powerCallbackExpect(m, g, now.Add(time.Second))
	m.ExpectExec(`UPDATE public.capacity_mutation_grants SET state`).WithArgs(g.ID, "settled", sqlmock.AnyArg(), executorpower.Kind).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectCommit()
	r := executorpower.Result{GrantID: g.ID, AttemptID: c.AttemptID, RequestSHA: g.RequestSHA, Outcome: "accepted", ServiceRequestID: "original-aws-service-request", OriginalJoined: true}
	if err := (CapacityStore{DB: db}).SettleExecutorPower(context.Background(), g.Binding.AdapterPrincipal, g.Binding.IntegrationID, g.Action, token, r); err != nil {
		t.Fatal(err)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestCapacityExecutorPowerForeignCallbackCannotAcquireTransaction(t *testing.T) {
	_, g, _ := powerCallbackFixture(t)
	db, m, _ := sqlmock.New()
	defer db.Close()
	raw, _ := json.Marshal(g)
	m.ExpectQuery(`SELECT state,grant_record`).WithArgs(g.ID).WillReturnRows(sqlmock.NewRows([]string{"state", "grant_record"}).AddRow(g.State, raw))
	if err := (CapacityStore{DB: db}).SettleExecutorPower(context.Background(), "wrong-principal", g.Binding.IntegrationID, g.Action, "never-read", executorpower.Result{GrantID: g.ID}); !errors.Is(err, executorpower.ErrDenied) {
		t.Fatal(err)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCapacityExecutorPowerPortRequiresExplicitDispatch(t *testing.T) {
	policy, _, b, _ := powerPolicy(t)
	id := uuid.NewString()
	r := executoractivity.ExactResource{AccountID: b.Resource.AccountID, Region: b.Resource.Region, InstanceID: b.Resource.InstanceID, OwnershipBindingID: id}
	port := ExecutorPowerPort{Policy: policy, AdoptionID: id, Store: CapacityStore{ExecutionEnabled: true, ExecutorPowerEnabled: true, ExecutorActivityPrincipal: "machine:controller"}}
	if err := port.Execute(context.Background(), executoractivity.PowerCommand{ID: "command", Action: "stop", Resource: r}); !errors.Is(err, executorpower.ErrDenied) {
		t.Fatal(err)
	}
	if _, err := port.Observe(context.Background(), r); !errors.Is(err, executorpower.ErrDenied) {
		t.Fatal(err)
	}
}

const powerCatalogJSON = `{"provider":"aws","capabilities":["execute"],"resource_types":[{"name":"ec2_instance","default_actions":["ensure_ec2_instance_running","ensure_ec2_instance_stopped"]}],"action_catalog":[{"name":"ensure_ec2_instance_running","resource_types":["ec2_instance"]},{"name":"ensure_ec2_instance_stopped","resource_types":["ec2_instance"]}]}`

func TestCapacityExecutorPowerRequiresDeclaredDistinctCatalog(t *testing.T) {
	if validatePowerCatalog([]byte(powerCatalogJSON)) != nil {
		t.Fatal("valid power catalog rejected")
	}
	for _, raw := range []string{`{}`, strings.ReplaceAll(powerCatalogJSON, "ensure_ec2_instance_stopped", "stop_ec2_instance"), strings.ReplaceAll(powerCatalogJSON, "ensure_ec2_instance_running", "ensure_ec2_instance"), strings.ReplaceAll(powerCatalogJSON, `"aws"`, `"other"`)} {
		if validatePowerCatalog([]byte(raw)) == nil {
			t.Fatal("legacy or foreign catalog admitted")
		}
	}
}

func TestCapacityExecutorPowerAdoptionHoldsUnresolvedVMOrigin(t *testing.T) {
	policy, p, b, now := powerPolicy(t)
	db, m, _ := sqlmock.New()
	defer db.Close()
	s := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorPowerEnabled: true, ExecutorPowerOperator: powerOperator, WorkflowID: uuid.New(), ExecutorPowerObserver: &powerObserverMock{o: executorpower.Observation{Resource: b.Resource, State: "stopped", ObservedAt: now}}}
	powerTxExpect(m, policy, p, s.WorkflowID, true, now)
	m.ExpectQuery(`SELECT count\(\*\) FROM public.capacity_resource_slots`).WithArgs(executorpower.Key(b.Resource), b.Resource.InstanceID).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(0))
	m.ExpectQuery(`SELECT count\(\*\) FROM public.capacity_mutation_grants WHERE NOT`).WithArgs(b.Resource.InstanceID).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	m.ExpectRollback()
	if a, err := s.AdoptExecutorPower(context.Background(), policy); !errors.Is(err, ErrCapacityConflict) || a.ID != "" {
		t.Fatal(err, a)
	}
	if err := m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestCapacityExecutorPowerLegacyDestroyCannotClaimAdoptedEC2(t *testing.T) {
	db, m, _ := sqlmock.New()
	defer db.Close()
	m.ExpectBegin()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	id := "i-0123456789abcdef0"
	m.ExpectExec(`SELECT pg_advisory_xact_lock`).WithArgs("capacity-power-instance/" + id).WillReturnResult(sqlmock.NewResult(0, 1))
	m.ExpectQuery(`SELECT count\(\*\) FROM public.capacity_resource_slots WHERE slot_record`).WithArgs(id).WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(1))
	m.ExpectRollback()
	if err = guardExecutorPowerAdoption(context.Background(), tx, id); !errors.Is(err, ErrCapacityConflict) {
		t.Fatal(err)
	}
	_ = tx.Rollback()
	if err = m.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
