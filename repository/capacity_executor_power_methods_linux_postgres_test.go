package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executoractivity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity/executorpower"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// A synthetic provider observer and persisted demand isolate the real SQL
// method protocol. This is not an AWS send or complete activity admission proof.
func TestExecutorPowerRealPostgresMethods(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getenv("EXECUTOR_POWER_LINUX_PG_TEST") != "isolated" {
		t.Skip("requires approved isolated Linux PostgreSQL")
	}
	dsn := os.Getenv("EXECUTOR_POWER_TEST_DB_URL")
	u, e := url.Parse(dsn)
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Hostname() != "127.0.0.1" || !regexp.MustCompile(`^/executor_lab_[a-z0-9_]{1,40}$`).MatchString(u.Path) || u.Query().Get("sslmode") != "disable" || u.Fragment != "" {
		t.Fatal("dedicated loopback executor_lab_* database required")
	}
	for k := range u.Query() {
		if k != "sslmode" {
			t.Fatal("database override refused")
		}
	}
	db, e := sql.Open("postgres", dsn)
	if e != nil {
		t.Fatal(e)
	}
	db.SetMaxOpenConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	policy, p, b, now := powerPolicy(t)
	ns := "power-method-" + uuid.NewString()
	policy.Metadata.Namespace = ns
	p.Workflow.Namespace = ns
	b.AdoptionWorkflow.Namespace = ns
	p.ExecutorPowerBinding = &b
	policy.Spec, _ = json.Marshal(p)
	controllerID, adoptionID := uuid.New(), uuid.New()
	t.Cleanup(func() {
		defer db.Close()
		for _, table := range []string{"capacity_mutation_grants", "capacity_resource_slots", "manifests"} {
			if _, err := db.Exec(`DELETE FROM public.`+table+` WHERE namespace=$1`, ns); err != nil {
				t.Error(err)
			}
		}
		key, _ := json.Marshal([]string{ns, p.Environment, p.Domain, p.Dimension})
		if _, err := db.Exec(`DELETE FROM public.capacity_executor_activity WHERE scope_key=$1`, string(key)); err != nil {
			t.Error(err)
		}
	})
	insert := func(id, kind, name, checksum string, spec any) {
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,checksum,spec) VALUES($1,'v1',$2,$3,$4,1,$5,$6::jsonb)`, id, kind, ns, name, checksum, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	insert(policy.ID.String(), "capacity_policy", policy.Metadata.Name, policy.Checksum, p)
	insert(controllerID.String(), "workflow", p.Workflow.Name, "controller-workflow", map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": ns, "name": "test-only"}}})
	insert(adoptionID.String(), "workflow", b.AdoptionWorkflow.Name, "operator-workflow", map[string]any{"authorization": map[string]any{"rbac": map[string]string{"namespace": ns, "name": "test-only"}}})
	var catalog any
	if json.Unmarshal([]byte(powerCatalogJSON), &catalog) != nil {
		t.Fatal("catalog")
	}
	insert(b.TypeID, "integration_type", "aws-power", b.TypeChecksum, catalog)
	insert(b.IntegrationID, "integration_instance", "aws-instance", b.IntegrationChecksum, map[string]any{"type_ref": model.ManifestSelector{ManifestID: b.TypeID}})
	observer := &powerObserverMock{o: executorpower.Observation{Resource: b.Resource, State: "stopped", ObservedAt: now}}
	store := CapacityStore{DB: db, ExecutionEnabled: true, ExecutorPowerEnabled: true, ExecutorPowerOperator: powerOperator, WorkflowID: adoptionID, ExecutorPowerObserver: observer}
	adoption, err := store.AdoptExecutorPower(ctx, policy)
	if err != nil {
		t.Fatal("actual SQL adopt", err)
	}
	if _, err = store.AdoptExecutorPower(ctx, policy); err == nil {
		t.Fatal("duplicate adoption admitted")
	}
	store.WorkflowID = controllerID
	store.ExecutorID = uuid.NewString()
	store.ExecutorActivityPrincipal = "machine:" + b.ControllerPrincipal
	resource := executoractivity.ExactResource{AccountID: b.Resource.AccountID, Region: b.Resource.Region, InstanceID: b.Resource.InstanceID, OwnershipBindingID: adoption.ID}
	command := uuid.NewString()
	state := executoractivity.ExecutorActivityState{Revision: 3, UpdatedAt: now, Epoch: 2, Tasks: map[string]executoractivity.ExecutorTaskLease{"synthetic-task": {Owner: "machine:test-task", Sequence: 1, ExpiresAt: now.Add(time.Minute)}}, BoundResource: &resource, Power: &executoractivity.PowerCommand{ID: command, Action: "start", Resource: resource, IssuedAt: now}, PinnedPolicy: &executoractivity.ExecutorActivityPolicy{MaxObservationAge: 30 * time.Second}}
	key, _ := json.Marshal([]string{ns, p.Environment, p.Domain, p.Dimension})
	pin, _ := json.Marshal([]string{policy.ID.String(), policy.Checksum, controllerID.String()})
	binding := fmt.Sprintf("%x", sha256.Sum256(pin))
	raw, _ := json.Marshal(state)
	if _, err = db.ExecContext(ctx, `INSERT INTO public.capacity_executor_activity(scope_key,binding_sha256,revision,state) VALUES($1,$2,3,$3::jsonb)`, string(key), binding, string(raw)); err != nil {
		t.Fatal(err)
	}
	grants := make(chan executorpower.Grant, 2)
	errors := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g, err := store.IssueExecutorPower(ctx, policy, command)
			if err != nil {
				errors <- err
			} else {
				grants <- g
			}
		}()
	}
	wg.Wait()
	close(grants)
	close(errors)
	if len(grants) != 1 || len(errors) != 1 {
		t.Fatalf("SQL issue winners=%d rejected=%d", len(grants), len(errors))
	}
	g := <-grants
	// A newly opened pool reconstructs custody before redemption.
	restarted, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	store.DB = restarted
	token := strings.Repeat("s", 32)
	claim := executorpower.Claim{GrantID: g.ID, Action: g.Action, CommandID: command, RequestSHA: g.RequestSHA, AttemptID: uuid.NewString(), SettlementSHA: executorpower.Digest(token)}
	reply, err := store.RedeemExecutorPower(ctx, b.AdapterPrincipal, b.IntegrationID, claim)
	if err != nil || reply.Mode != "execute_once" {
		t.Fatal("actual SQL redeem", reply, err)
	}
	duplicate, err := store.RedeemExecutorPower(ctx, b.AdapterPrincipal, b.IntegrationID, claim)
	if err != nil || duplicate.Mode != "read_only" {
		t.Fatal("duplicate send authority", duplicate, err)
	}
	// Execution off still accepts the original callback to close send uncertainty.
	store.ExecutionEnabled = false
	store.ExecutorPowerEnabled = false
	result := executorpower.Result{GrantID: g.ID, AttemptID: claim.AttemptID, RequestSHA: g.RequestSHA, Outcome: "accepted", ServiceRequestID: "synthetic-provider-request", OriginalJoined: true}
	if err = store.SettleExecutorPower(ctx, b.AdapterPrincipal, b.IntegrationID, g.Action, token, result); err != nil {
		t.Fatal("actual late SQL settle", err)
	}
	observer.o.State = "running"
	observer.o.ObservedAt = time.Now().UTC()
	if _, err = store.ConfirmExecutorPower(ctx, policy, g.ID); err == nil {
		t.Fatal("running without worker readiness admitted")
	}
	observer.o.WorkerReady = true
	observer.o.BootID = uuid.NewString()
	confirmed, err := store.ConfirmExecutorPower(ctx, policy, g.ID)
	if err != nil || confirmed.State != "confirmed" {
		t.Fatal("actual SQL confirm", confirmed, err)
	}
	var sqlState string
	var record []byte
	if err = restarted.QueryRowContext(ctx, `SELECT state,grant_record FROM public.capacity_mutation_grants WHERE id=$1`, g.ID).Scan(&sqlState, &record); err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePowerGrant(record)
	if err != nil || decoded.State != sqlState || sqlState != "confirmed" || decoded.ServiceRequestID != result.ServiceRequestID {
		t.Fatal("persistent original custody mismatch", err)
	}
}
