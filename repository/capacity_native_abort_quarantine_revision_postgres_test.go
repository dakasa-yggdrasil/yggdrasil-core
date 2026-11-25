package repository

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// CI-only PostgreSQL regressions use the real issued/redeemed recovery child,
// original expired deadline and immutable quarantine from the existing fixture.
// A current catalog revision is never substituted into that historical custody.
func abortQuarantineRevisionPolicy(t *testing.T, f abortQuarantinePGFixture) model.CapacityPolicySpec {
	t.Helper()
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(f.policy.Spec, &p); err != nil {
		t.Fatal("decode original policy", err)
	}
	return p
}

func abortQuarantineRevisionPublish(t *testing.T, f abortQuarantinePGFixture, ns, name string, p model.CapacityPolicySpec) model.Manifest {
	t.Helper()
	m := abortPGCreate(t, f.db, ns, "capacity_policy", name, p)
	if _, err := parseCapacityPolicy(m); err != nil {
		t.Fatal("revision fixture must be a valid capacity policy", err)
	}
	if ns != f.policy.Metadata.Namespace {
		// The shared fixture owns only its original namespace. Remove this
		// independent test catalog row before that fixture closes its connection.
		t.Cleanup(func() {
			if _, err := f.db.Exec(`DELETE FROM public.manifests WHERE id=$1`, m.ID); err != nil {
				t.Error("remove foreign test revision", err)
			}
		})
	}
	return m
}

func abortQuarantineRevisionSnapshot(t *testing.T, f abortQuarantinePGFixture) [][]byte {
	t.Helper()
	rows := abortQuarantinePGSnapshot(t, f)
	var raw []byte
	if err := f.db.QueryRow(`SELECT row_to_json(q) FROM public.capacity_native_abort_quarantines q WHERE command_id=$1`, f.child.CommandID).Scan(&raw); err != nil {
		t.Fatal("full original quarantine row", err)
	}
	return append(rows, raw)
}

func abortQuarantineRevisionUnchanged(t *testing.T, f abortQuarantinePGFixture, before [][]byte) {
	t.Helper()
	after := abortQuarantineRevisionSnapshot(t, f)
	if len(before) != len(after) {
		t.Fatal("original custody row count changed")
	}
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			// Never project private command, result, token or receipt bytes.
			t.Fatalf("original custody row %d changed", i)
		}
	}
}

func TestCapacityNativeAbortQuarantineCurrentRevisionPostgres(t *testing.T) {
	f := abortQuarantinePGSetup(t, nil)
	abortQuarantinePGClassify(t, f)
	before := abortQuarantineRevisionSnapshot(t, f)
	p := abortQuarantineRevisionPolicy(t, f)
	ns := f.policy.Metadata.Namespace

	// Publish actual new type/instance versions through the ordinary catalog
	// operation. Their UUIDs/checksums, like current HPA/Deployment UIDs and
	// immutable image, are current authority pins, not the old child's origin.
	typ := abortPGCreate(t, f.db, ns, "integration_type", "native-type", map[string]any{"provider": "kubernetes", "version": "revision-2"})
	instance := abortPGCreate(t, f.db, ns, "integration_instance", "native-instance", map[string]any{
		"type_ref": model.ManifestSelector{ManifestID: typ.ID.String()},
		"config":   map[string]any{"revision": "current"},
	})
	adapter := model.CapacityObservationAdapterBinding{IntegrationInstanceID: instance.ID.String(), InstanceChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), TypeChecksum: typ.Checksum}
	oldSnapshot := p.AssessmentBinding.Snapshot
	p.AssessmentBinding.Snapshot.Adapter = adapter
	for i := range p.AssessmentBinding.Signals {
		p.AssessmentBinding.Signals[i].Adapter = adapter
	}
	p.AssessmentBinding.Snapshot.HPAUID = uuid.NewString()
	p.AssessmentBinding.Snapshot.WorkloadUID = uuid.NewString()
	p.HPAExecutionBinding.ImageDigest = "sha256:" + strings.Repeat("c", 64)
	current := abortQuarantineRevisionPublish(t, f, ns, f.policy.Metadata.Name, p)
	if current.ID == f.policy.ID || current.Version != f.policy.Version+1 || current.Checksum == f.policy.Checksum ||
		typ.Version != 2 || instance.Version != 2 || oldSnapshot.Adapter == adapter ||
		oldSnapshot.HPAUID == p.AssessmentBinding.Snapshot.HPAUID ||
		oldSnapshot.WorkloadUID == p.AssessmentBinding.Snapshot.WorkloadUID {
		t.Fatal("current revision did not rotate the intended real catalog and physical pins")
	}
	origin, err := GetManifestByID(context.Background(), f.db, f.policy.ID)
	if err != nil || origin.Metadata.Active || origin.Checksum != f.policy.Checksum ||
		origin.Version != f.policy.Version || !bytes.Equal(origin.Spec, f.policy.Spec) {
		t.Fatal("normal publication did not retain the exact inactive original policy", err)
	}
	want := model.CapacityNativeUnsettledCounts{RawUnsettled: 1, Quarantined: 1}
	got, err := f.storeQ.NativeUnsettledCounts(context.Background(), current)
	if err != nil || got != want {
		t.Fatalf("compatible current revision lost historical quarantine: %+v %v", got, err)
	}
	if ok, err := f.storeQ.NativeAbortCommandQuarantined(context.Background(), current, f.child.CommandID); err != nil || !ok {
		t.Fatal("current revision did not validate the receipt against its inactive origin", err)
	}

	// This is only the repository's historical blocker classification. It grants
	// no new lease, registration, command, settlement or physical capacity.
	tx, err := f.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err = nativeActiveUnsettledTx(context.Background(), tx, current, p, uuid.NewString())
	tx.Rollback()
	if err != nil || got != want {
		t.Fatal("different UID could not retain the historical exclusion", err)
	}
	tx, err = f.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = nativeActiveUnsettledTx(context.Background(), tx, current, p, f.bindingQ.Native.PodUID)
	tx.Rollback()
	if !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("original quarantined UID used its own exclusion under the current revision", err)
	}
	tx, err = f.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = guardNativePreRegistrationAbortTx(context.Background(), tx, f.bindingQ.Native.PodUID)
	tx.Rollback()
	if !errors.Is(err, ErrCapacityConflict) {
		t.Fatal("catalog/physical rotation cleared the permanent original UID deny", err)
	}

	var uncertain, nullACKs, receipts int
	if err := f.db.QueryRow(`SELECT
		(SELECT count(*) FROM public.capacity_native_commands WHERE id=$1 AND state='uncertain'),
		(SELECT count(*) FROM public.capacity_native_release_results WHERE command_id=$1 AND adapter_ack_at IS NULL AND caller_ack_at IS NULL AND adapter_result IS NULL),
		(SELECT count(*) FROM public.capacity_native_abort_quarantines WHERE command_id=$1)`, f.child.CommandID).Scan(&uncertain, &nullACKs, &receipts); err != nil ||
		uncertain != 1 || nullACKs != 1 || receipts != 1 {
		t.Fatal("quarantine revision invented settlement or replaced the receipt", err)
	}
	abortQuarantineRevisionUnchanged(t, f, before)
}

func TestCapacityNativeAbortQuarantineRejectsLogicalRevisionPostgres(t *testing.T) {
	f := abortQuarantinePGSetup(t, nil)
	abortQuarantinePGClassify(t, f)
	before := abortQuarantineRevisionSnapshot(t, f)
	for _, tc := range []struct {
		name   string
		change func(*model.CapacityPolicySpec, *string, *string)
	}{
		{"policy_namespace", func(_ *model.CapacityPolicySpec, ns, _ *string) { *ns += "-foreign" }},
		{"policy_name", func(_ *model.CapacityPolicySpec, _, name *string) { *name += "-foreign" }},
		{"environment", func(p *model.CapacityPolicySpec, _, _ *string) { p.Environment = "other-environment" }},
		{"domain", func(p *model.CapacityPolicySpec, _, _ *string) { p.Domain = "other-domain" }},
		{"dimension", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.Dimension, p.AssessmentBinding, p.HPAExecutionBinding = "replicas", nil, nil
		}},
		{"owner", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.Owner = "other-owner"
			p.AssessmentBinding.Snapshot.Owner = p.Owner
		}},
		{"workload_namespace", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.AssessmentBinding.Snapshot.Namespace = "other-namespace"
		}},
		{"hpa_name", func(p *model.CapacityPolicySpec, _, _ *string) { p.AssessmentBinding.Snapshot.HPAName = "other-hpa" }},
		{"workload_name", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.AssessmentBinding.Snapshot.WorkloadName = "other-workload"
		}},
		{"profile", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.Profiles[0].Name = "other-profile"
			p.AssessmentBinding.Snapshot.Profile = p.Profiles[0].Name
		}},
		{"workflow_namespace", func(p *model.CapacityPolicySpec, _, _ *string) { p.Workflow.Namespace = "other-workflow-namespace" }},
		{"workflow_name", func(p *model.CapacityPolicySpec, _, _ *string) { p.Workflow.Name = "other-scale" }},
		{"native_mode", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.HPAExecutionBinding.Mode = capacity.HPAExecutionMode
		}},
		{"adapter_principal", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.HPAExecutionBinding.AdapterPrincipalID = "other-principal"
		}},
		{"termination_binding", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.HPAExecutionBinding.PodTerminationBinding = "other-binding"
		}},
		{"container", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.HPAExecutionBinding.ContainerName = "other-container"
		}},
		{"admission_workflow_namespace", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.HPAExecutionBinding.AdmissionWorkflow.Namespace = "other-admission-namespace"
		}},
		{"admission_workflow_name", func(p *model.CapacityPolicySpec, _, _ *string) {
			p.HPAExecutionBinding.AdmissionWorkflow.Name = "other-admission"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := abortQuarantineRevisionPolicy(t, f)
			ns, name := f.policy.Metadata.Namespace, f.policy.Metadata.Name
			tc.change(&p, &ns, &name)
			current := abortQuarantineRevisionPublish(t, f, ns, name, p)
			// A foreign empty scope may truthfully report counts=0. The security
			// boundary is refusing to borrow this exact historical command's q.
			if ok, err := f.storeQ.NativeAbortCommandQuarantined(context.Background(), current, f.child.CommandID); !errors.Is(err, ErrCapacityConflict) || ok {
				t.Fatal("incompatible valid policy borrowed the original quarantine", err)
			}
			abortQuarantineRevisionUnchanged(t, f, before)
		})
	}
}

func TestCapacityNativeAbortQuarantineRejectsLostOriginPostgres(t *testing.T) {
	for _, mode := range []string{"missing_origin", "changed_origin_checksum", "invalid_origin_spec", "changed_origin_workload_uid"} {
		t.Run(mode, func(t *testing.T) {
			f := abortQuarantinePGSetup(t, nil)
			abortQuarantinePGClassify(t, f)
			before := abortQuarantineRevisionSnapshot(t, f)
			p := abortQuarantineRevisionPolicy(t, f)
			p.HPAExecutionBinding.ImageDigest = "sha256:" + strings.Repeat("c", 64)
			current := abortQuarantineRevisionPublish(t, f, f.policy.Metadata.Namespace, f.policy.Metadata.Name, p)
			if ok, err := f.storeQ.NativeAbortCommandQuarantined(context.Background(), current, f.child.CommandID); err != nil || !ok {
				t.Fatal("compatible revision must validate before independent origin loss", err)
			}

			// Corrupt only the referenced original catalog row, as an independent
			// custody failure. No q, original command/identity or seed is rewritten;
			// no trigger is disabled, and current-policy validity is unaffected.
			var err error
			switch mode {
			case "missing_origin":
				_, err = f.db.Exec(`DELETE FROM public.manifests WHERE id=$1`, f.policy.ID)
			case "changed_origin_checksum":
				_, err = f.db.Exec(`UPDATE public.manifests SET checksum=$2 WHERE id=$1`, f.policy.ID, strings.Repeat("f", 64))
			case "invalid_origin_spec":
				_, err = f.db.Exec(`UPDATE public.manifests SET spec='{}'::jsonb WHERE id=$1`, f.policy.ID)
			case "changed_origin_workload_uid":
				origin := abortQuarantineRevisionPolicy(t, f)
				origin.AssessmentBinding.Snapshot.WorkloadUID = uuid.NewString()
				raw, marshalErr := json.Marshal(origin)
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				// Keep the old checksum unchanged: the full original validators
				// must still compare its body to the original child/proof.
				_, err = f.db.Exec(`UPDATE public.manifests SET spec=$2::jsonb WHERE id=$1`, f.policy.ID, raw)
			}
			if err != nil {
				t.Fatal("inject independent original-policy custody failure", err)
			}
			if ok, err := f.storeQ.NativeAbortCommandQuarantined(context.Background(), current, f.child.CommandID); !errors.Is(err, ErrCapacityConflict) || ok {
				t.Fatal("missing/tampered original policy silently replaced by current policy", err)
			}
			if _, err := f.storeQ.NativeUnsettledCounts(context.Background(), current); !errors.Is(err, ErrCapacityConflict) {
				t.Fatal("lost original policy silently removed a raw blocker", err)
			}
			abortQuarantineRevisionUnchanged(t, f, before)
		})
	}
}
