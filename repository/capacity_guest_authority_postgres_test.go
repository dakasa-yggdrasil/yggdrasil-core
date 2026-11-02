package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// This suite can only use the explicitly created disposable socket-only PG17
// on the Mac or the separately owned, networkless Source CI container.
// It does not infer authority from these synthetic SQL storage test operands.
func d12AuthorityLocalFixture(t *testing.T) (*sql.DB, model.Manifest) {
	t.Helper()
	dsn := os.Getenv("D12_LOCAL_PG17_DSN")
	if dsn == "" {
		dsn = os.Getenv("D12_SOURCE_CI_PG17_DSN")
		if dsn != "" {
			host := os.Getenv("PGHOST")
			prefix := filepath.Join(os.Getenv("RUNNER_TEMP"), "d12-installed-"+os.Getenv("GITHUB_RUN_ID")+"-"+os.Getenv("GITHUB_RUN_ATTEMPT")+"-")
			if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_TEMP") == "" || !filepath.IsAbs(host) || !strings.HasPrefix(host, prefix) || !strings.HasSuffix(host, "/socket") || dsn != "host="+host+" dbname=core_d12_test user=postgres sslmode=disable" {
				t.Fatal("only this CI job's owned socket fixture allowed")
			}
		} else {
			if os.Getenv("REQUIRE_D12_INSTALLED_SOURCE_POSTGRES") == "true" {
				t.Fatal("required isolated D12 PG17 fixture absent")
			}
			t.Skip("explicit disposable local or Source CI PG17 fixture required")
		}
	} else if !strings.Contains(dsn, "host=/private/tmp/codex-d12-pg17-") || !strings.Contains(dsn, "dbname=core_d12_test") {
		t.Fatal("only isolated D12 socket fixture allowed")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	var name, listen string
	var socket bool
	var version int
	err = db.QueryRow(`SELECT current_database(),inet_server_addr() IS NULL,current_setting('listen_addresses'),current_setting('server_version_num')::int`).Scan(&name, &socket, &listen, &version)
	_ = db.Close()
	if err != nil || name != "core_d12_test" || !socket || listen != "" || version/10000 != 17 {
		t.Fatal("wrong physical fixture")
	}
	t.Setenv("DB_URL", dsn)
	t.Setenv("REQUIRE_CAPACITY_POSTGRES", "true")
	db, policy, _ := capacityPostgresFixture(t)
	return db, policy
}

func TestD12AuthorityLedgerPostgresRequiresClosedIdentity(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	ctx := context.Background()
	t.Run("historical_compatibility_map", func(t *testing.T) { testGuestAuthorityHistoricalMapPostgres(t, db, policy) })
	t.Run("retirement_V2_drained_CAS", func(t *testing.T) { testGuestRetirementDrainedV2Postgres(t, db, policy) })
	for _, name := range []string{"exact", "empty", "missing_issuer", "missing_schema", "unknown_key", "null_issuer"} {
		t.Run(name, func(t *testing.T) {
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			id := uuid.NewString()
			actual := strings.Repeat("a", 40)
			authority := "48888f21acdddaf411094ec525004297c229863f"
			digest := strings.Repeat("b", 64)
			executor := uuid.NewString()
			record := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": "canary_challenge", "issue_id": id, "issuer_actual_source_commit": actual, "protocol_authority_source_commit": authority, "compatibility_map_sha256": digest, "profile": "notify-aws-elastic", "policy_id": policy.ID.String(), "workflow_id": policy.ID.String(), "executor_id": executor, "issued_wire_sha256": digest}
			switch name {
			case "empty":
				record = map[string]any{}
			case "missing_issuer":
				delete(record, "issuer_actual_source_commit")
			case "missing_schema":
				delete(record, "schema")
			case "unknown_key":
				record["healthy"] = true
			case "null_issuer":
				record["issuer_actual_source_commit"] = nil
			}
			raw, _ := json.Marshal(record)
			_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record)VALUES('canary_challenge',$1,$2,$3,$4,'notify-aws-elastic',$5,$5,$6,$4,$7,$8::jsonb)`, id, actual, authority, digest, policy.ID, executor, raw, string(raw))
			if name == "exact" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_guest_authority_issues SET issuer_actual_source_commit=$2 WHERE issue_id=$1`, id, strings.Repeat("c", 40)); err == nil {
					t.Fatal("immutable issuer rewritten")
				}
			} else {
				var pe *pq.Error
				if !errors.As(err, &pe) || string(pe.Code) != "23514" {
					t.Fatalf("malformed identity not refused by ledger CHECK: %T", err)
				}
			}
		})
	}
}

func testGuestAuthorityHistoricalMapPostgres(t *testing.T, db *sql.DB, fixture model.Manifest) {
	t.Helper()
	ctx := context.Background()
	for _, provider := range []string{"aws", "hetzner"} {
		for _, name := range []string{"exact_historical", "unknown_map", "changed_contract_same_profile_catalog", "wrong_policy", "wrong_workflow", "wrong_policy_checksum", "current_map_transaction_rollback", "actual_prior_D13_same_current_map"} {
			t.Run(provider+"/"+name, func(t *testing.T) {
				raw, err := os.ReadFile(filepath.Join("..", "internal", "capacity", "testdata", "original-notify-"+provider+"-production-contract.json"))
				if err != nil {
					t.Fatal(err)
				}
				var p model.CapacityPolicySpec
				if capacity.DecodeNativeCapacity(json.RawMessage(raw), &p) != nil {
					t.Fatal("original complete public contract fixture")
				}
				p.GuestRetirementBinding.CoreAuthoritySourceCommit = capacity.GuestD11ProtocolAuthority
				if name == "changed_contract_same_profile_catalog" {
					p.GuestRetirementBinding.IntentSigningKeyRef = "secret://source-test/successor-intent#value"
				}
				policyWire, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := db.BeginTx(ctx, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				policyID, id, actual, executor := uuid.NewString(), uuid.NewString(), strings.Repeat("a", 40), uuid.NewString()
				checksum := capacity.BusinessCreationSHA256(policyWire)
				_, err = tx.ExecContext(ctx, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,spec,checksum,active)VALUES($1,'v1','capacity_policy',$2,$3,1,$4::jsonb,$5,false)`, policyID, fixture.Metadata.Namespace, "historical-"+id, string(policyWire), checksum)
				if err != nil {
					t.Fatal(err)
				}
				compatibility := capacity.GuestD12ProtocolCompatibilityMapSHA256
				switch name {
				case "unknown_map":
					compatibility = strings.Repeat("f", 64)
				case "current_map_transaction_rollback", "actual_prior_D13_same_current_map":
					compatibility = capacity.GuestProtocolCompatibilityMapSHA256()
					if name == "actual_prior_D13_same_current_map" {
						actual = "3d570162ba51967ee791316c23c5b45419993f1b"
					}
				}
				wireSHA := strings.Repeat("b", 64)
				record := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": "retirement_intent", "issue_id": id, "issuer_actual_source_commit": actual, "protocol_authority_source_commit": capacity.GuestD11ProtocolAuthority, "compatibility_map_sha256": compatibility, "profile": p.GuestRetirementBinding.ProfileManifest.Profile, "policy_id": policyID, "workflow_id": fixture.ID.String(), "executor_id": executor, "issued_wire_sha256": wireSHA}
				recordWire, _ := json.Marshal(record)
				_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record)VALUES('retirement_intent',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb)`, id, actual, capacity.GuestD11ProtocolAuthority, compatibility, p.GuestRetirementBinding.ProfileManifest.Profile, policyID, fixture.ID, executor, wireSHA, recordWire, string(recordWire))
				if err != nil {
					t.Fatal(err)
				}
				pre := model.CapacityGuestOriginalProvisioningPreregistration{PolicyID: policyID, PolicyChecksum: checksum, WorkflowID: fixture.ID.String()}
				switch name {
				case "wrong_policy":
					pre.PolicyID = fixture.ID.String()
				case "wrong_workflow":
					pre.WorkflowID = policyID
				case "wrong_policy_checksum":
					pre.PolicyChecksum = strings.Repeat("c", 64)
				}
				err = verifyGuestAuthorityIssuerTx(ctx, tx, "retirement_intent", id, actual, *p.GuestRetirementBinding, pre)
				accepted := name == "exact_historical" || name == "current_map_transaction_rollback" || name == "actual_prior_D13_same_current_map"
				if (err == nil) != accepted {
					t.Fatalf("historical issuer/map scope accepted=%v, error=%v", accepted, err)
				}
				if err = tx.Rollback(); err != nil {
					t.Fatal(err)
				}
				var count int
				if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_guest_authority_issues WHERE issue_kind='retirement_intent' AND issue_id=$1`, id).Scan(&count); err != nil || count != 0 {
					t.Fatal("rolled-back source fixture left an issuer record")
				}
			})
		}
	}
}

func TestD12InstalledResumePostgresCASAndAtomicRollback(t *testing.T) {
	t.Run("scheduler_original_NULL_workflow_identity", testInstalledGuestDispatchWorkflowIdentityPostgres)
	db, policy := d12AuthorityLocalFixture(t)
	ctx := context.Background()
	p, _ := parseCapacityPolicy(policy)
	now := time.Now().UTC()
	old := model.CapacityIntent{Namespace: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Generation: 6, FencingToken: 11, Phase: "preparing", UpdatedAt: now}
	raw, _ := json.Marshal(old)
	_, err := db.ExecContext(ctx, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at)VALUES($1,$2,$3,$4,$5::jsonb,$6)`, old.Namespace, old.Environment, old.Domain, old.Dimension, raw, now)
	if err != nil {
		t.Fatal(err)
	}
	makeNext := func() model.CapacityIntent {
		next := old
		next.FencingToken = 12
		next.InstalledGuestReconcile = &model.CapacityInstalledGuestReconcile{Attempt: 1, OriginalFence: 11, PreviousFence: 11, NewFence: 12, OriginalRunID: uuid.NewString(), NewRunID: uuid.NewString()}
		return next
	}
	// Audit or any later issue error rolls the CAS AND event back together.
	tx, _ := db.BeginTx(ctx, nil)
	if err = persistInstalledGuestResumeTx(ctx, tx, policy, p, old, makeNext()); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback()
	var fence int
	if err = db.QueryRowContext(ctx, `SELECT (intent->>'fencing_token')::int FROM public.capacity_intents WHERE namespace=$1`, old.Namespace).Scan(&fence); err != nil || fence != 11 {
		t.Fatal("rolled-back issue left new authority")
	}
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, e := db.BeginTx(ctx, nil)
			if e != nil {
				results <- false
				return
			}
			defer tx.Rollback()
			e = persistInstalledGuestResumeTx(ctx, tx, policy, p, old, makeNext())
			if e == nil {
				e = tx.Commit()
			}
			results <- e == nil
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for won := range results {
		if won {
			wins++
		}
	}
	var events int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1 AND generation=6 AND fencing_token=12`, old.Namespace).Scan(&events)
	if wins != 1 || events != 1 {
		t.Fatal("concurrent original resume duplicated CAS/event", wins, events)
	}
}

func TestD12InstalledResumePostgresThreeFreshEpochsNeverReplaysFourth(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	ctx := context.Background()
	p, _ := parseCapacityPolicy(policy)
	now := time.Now().UTC()
	old := model.CapacityIntent{Namespace: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, PolicyID: policy.ID, PolicyChecksum: policy.Checksum, Generation: 6, FencingToken: 11, Phase: "preparing", UpdatedAt: now}
	raw, _ := json.Marshal(old)
	if _, err := db.ExecContext(ctx, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at)VALUES($1,$2,$3,$4,$5::jsonb,$6)`, old.Namespace, old.Environment, old.Domain, old.Dimension, raw, now); err != nil {
		t.Fatal(err)
	}
	originalRun := uuid.NewString()
	for attempt := 1; attempt <= 4; attempt++ {
		next := old
		next.FencingToken++
		next.Phase = "preparing"
		next.InstalledGuestReconcile = &model.CapacityInstalledGuestReconcile{Attempt: attempt, OriginalFence: 11, PreviousFence: old.FencingToken, NewFence: next.FencingToken, OriginalRunID: originalRun, NewRunID: uuid.NewString()}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		err = persistInstalledGuestResumeTx(ctx, tx, policy, p, old, next)
		if attempt <= 3 {
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			old = next
		} else {
			_ = tx.Rollback()
			if err == nil {
				t.Fatal("fourth readiness attempt admitted")
			}
		}
	}
	var count int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_intent_events WHERE namespace=$1`, old.Namespace).Scan(&count)
	if count != 3 || old.FencingToken != 14 {
		t.Fatal("fresh attempts repeated an epoch or changed generation", count, old.FencingToken)
	}
}

// Immutable installed markers remain independently rederivable even after the
// current intent has moved through another readiness attempt and promotion.
func TestD12AuthorityLedgerInstalledMarkerSurvivesIntentReplacement(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	p, _ := parseCapacityPolicy(policy)
	originalRun, run1, run2 := uuid.NewString(), uuid.NewString(), uuid.NewString()
	marker := model.CapacityInstalledGuestReconcile{Schema: "installed_original_guest_readiness_reconcile_v1", Attempt: 1, OriginalGeneration: 6, OriginalFence: 11, PreviousFence: 11, NewFence: 12, OriginalRunID: originalRun, NewRunID: run1, OriginalFailurePreserved: true}
	wire1, _ := json.Marshal(marker)
	insert := func(m model.CapacityInstalledGuestReconcile) {
		t.Helper()
		wire, _ := json.Marshal(m)
		actual, authority, digest := strings.Repeat("a", 40), capacity.GuestD11ProtocolAuthority, strings.Repeat("b", 64)
		executor := uuid.NewString()
		record := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": "installed_reconcile", "issue_id": m.NewRunID, "issuer_actual_source_commit": actual, "protocol_authority_source_commit": authority, "compatibility_map_sha256": digest, "profile": "notify-aws-elastic", "policy_id": policy.ID.String(), "workflow_id": policy.ID.String(), "executor_id": executor, "issued_wire_sha256": capacity.BusinessCreationSHA256(wire), "installed_reconcile_marker_base64": base64.StdEncoding.EncodeToString(wire)}
		raw, _ := json.Marshal(record)
		_, e := tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record)VALUES('installed_reconcile',$1,$2,$3,$4,'notify-aws-elastic',$5,$5,$6,$7,$8,$9::jsonb)`, m.NewRunID, actual, authority, digest, policy.ID, executor, capacity.BusinessCreationSHA256(wire), raw, string(raw))
		if e != nil {
			t.Fatal(e)
		}
	}
	insert(marker)
	intent := model.CapacityIntent{Namespace: policy.Metadata.Namespace, Environment: p.Environment, Domain: p.Domain, Dimension: p.Dimension, Generation: 6, FencingToken: 12, Phase: "preparing", InstalledGuestReconcile: &marker, UpdatedAt: time.Now().UTC()}
	raw, _ := json.Marshal(intent)
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_intents(namespace,environment,domain,dimension,intent,updated_at)VALUES($1,$2,$3,$4,$5::jsonb,clock_timestamp())`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, raw); err != nil {
		t.Fatal(err)
	}
	marker.Attempt, marker.PreviousFence, marker.NewFence, marker.NewRunID = 2, 12, 13, run2
	marker.PreviousResumeRunID = run1
	insert(marker)
	raw, _ = json.Marshal(marker)
	if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{installed_guest_reconcile}',$2::jsonb) WHERE namespace=$1`, policy.Metadata.Namespace, string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent-'installed_guest_reconcile','{phase}','"promoted"'::jsonb) WHERE namespace=$1`, policy.Metadata.Namespace); err != nil {
		t.Fatal(err)
	}
	var preserved []byte
	var digest string
	var hashValid bool
	err = tx.QueryRowContext(ctx, `SELECT decode(original_record->>'installed_reconcile_marker_base64','base64'),issued_wire_sha256,encode(sha256(decode(original_record->>'installed_reconcile_marker_base64','base64')),'hex')=issued_wire_sha256 FROM public.capacity_guest_authority_issues WHERE issue_kind='installed_reconcile' AND issue_id=$1`, run1).Scan(&preserved, &digest, &hashValid)
	if err != nil || !hashValid || !bytes.Equal(preserved, wire1) || capacity.BusinessCreationSHA256(preserved) != digest {
		t.Fatal("original marker lost or hash not rederivable", err)
	}
	if _, err = tx.ExecContext(ctx, `UPDATE public.capacity_guest_authority_issues SET original_record=original_record-'installed_reconcile_marker_base64' WHERE issue_id=$1`, run1); err == nil {
		t.Fatal("original marker mutable")
	}
}

func TestD12AuthorityLedgerInstalledMarkerClosedPayload(t *testing.T) {
	db, policy := d12AuthorityLocalFixture(t)
	for _, name := range []string{"valid", "missing", "null", "empty", "invalid_base64", "wrong_hash", "foreign_kind", "unknown_key"} {
		t.Run(name, func(t *testing.T) {
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			id, actual, authority, digest, executor := uuid.NewString(), strings.Repeat("a", 40), capacity.GuestD11ProtocolAuthority, strings.Repeat("b", 64), uuid.NewString()
			wire := []byte(`{"schema":"installed_original_guest_readiness_reconcile_v1","attempt":1}`)
			kind, wireSHA := "installed_reconcile", capacity.BusinessCreationSHA256(wire)
			if name == "foreign_kind" {
				kind = "canary_challenge"
			}
			record := map[string]any{"schema": "guest_authority_issue_v1", "issue_kind": kind, "issue_id": id, "issuer_actual_source_commit": actual, "protocol_authority_source_commit": authority, "compatibility_map_sha256": digest, "profile": "notify-aws-elastic", "policy_id": policy.ID.String(), "workflow_id": policy.ID.String(), "executor_id": executor, "issued_wire_sha256": wireSHA, "installed_reconcile_marker_base64": base64.StdEncoding.EncodeToString(wire)}
			switch name {
			case "missing":
				delete(record, "installed_reconcile_marker_base64")
			case "null":
				record["installed_reconcile_marker_base64"] = nil
			case "empty":
				record["installed_reconcile_marker_base64"] = ""
			case "invalid_base64":
				record["installed_reconcile_marker_base64"] = "***"
			case "wrong_hash":
				record["installed_reconcile_marker_base64"] = base64.StdEncoding.EncodeToString([]byte(`{}`))
			case "unknown_key":
				record["other_payload"] = "unadmitted"
			}
			raw, _ := json.Marshal(record)
			_, err = tx.Exec(`INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record)VALUES($1,$2,$3,$4,$5,'notify-aws-elastic',$6,$6,$7,$8,$9,$10::jsonb)`, kind, id, actual, authority, digest, policy.ID, executor, wireSHA, raw, string(raw))
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var pe *pq.Error
				if !errors.As(err, &pe) || (string(pe.Code) != "23514" && string(pe.Code) != "22023") {
					t.Fatalf("malformed marker admitted or wrong refusal: %T", err)
				}
			}
		})
	}
}
