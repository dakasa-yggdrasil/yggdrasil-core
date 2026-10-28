package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityfixturetest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type repositoryOriginalResult struct {
	Schema                       string `json:"schema"`
	CoreSource                   string `json:"core_source"`
	Provider                     string `json:"provider"`
	Slot                         int    `json:"slot"`
	Floor                        int    `json:"floor"`
	BaselineUnits                int    `json:"baseline_units"`
	RegisteredBaseline           int    `json:"registered_baseline"`
	IssuanceReturns              int    `json:"issuance_returns"`
	SerializedIssueMatches       bool   `json:"serialized_issue_matches"`
	ActiveGrantRows              int    `json:"active_grant_rows"`
	PreregistrationRows          int    `json:"preregistration_rows"`
	RedeemReturns                int    `json:"redeem_returns"`
	WriteOnce                    int    `json:"write_once"`
	ReadOnly                     int    `json:"read_only"`
	RepositoryLostReply          bool   `json:"repository_lost_reply"`
	SettlementScopePrivacyPassed bool   `json:"settlement_scope_privacy_passed"`
	RepositoryUnresolved         bool   `json:"repository_unresolved"`
	RepositoryNativeConfirmation bool   `json:"repository_native_confirmation"`
	ProviderSendAttempted        bool   `json:"provider_send_attempted"`
	NativeOrProductionQualified  bool   `json:"native_or_production_qualified"`
}

var repositoryOriginalOnce sync.Once
var repositoryOriginalReport repositoryOriginalResult
var repositoryOriginalErr error

// This calls a clean VCS-built executable on a separately owned PG17. It never
// promotes synthetic membership or receipts into production evidence. Each
// scenario is prepared separately within that DB, preserving independent cases.
func repositoryOriginalFixture(t *testing.T) repositoryOriginalResult {
	t.Helper()
	if os.Getenv("DB_URL") == "" && os.Getenv("REQUIRE_CAPACITY_POSTGRES") != "true" {
		t.Skip("PostgreSQL callback protocol runs in CI")
	}
	repositoryOriginalOnce.Do(func() { repositoryOriginalReport, repositoryOriginalErr = executeRepositoryOriginalFixture() })
	if repositoryOriginalErr != nil {
		t.Fatal(repositoryOriginalErr)
	}
	return repositoryOriginalReport
}

func executeRepositoryOriginalFixture() (result repositoryOriginalResult, err error) {
	pg, goBinary := os.Getenv("CAPACITY_TEST_PG_BIN"), os.Getenv("CAPACITY_TEST_GO")
	if !filepath.IsAbs(pg) || !filepath.IsAbs(goBinary) {
		return result, errors.New("PG17 and Go paths required for isolated repository qualification")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	rootBytes, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return result, errors.New("test source root unavailable")
	}
	root := strings.TrimSpace(string(rootBytes))
	if err = exec.CommandContext(ctx, "git", "-C", root, "diff", "--quiet", "HEAD", "--").Run(); err != nil {
		return result, errors.New("tracked test source differs from clean source")
	}
	headBytes, err := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil {
		return result, errors.New("test source revision unavailable")
	}
	head := strings.TrimSpace(string(headBytes))
	tmp, err := filepath.EvalSymlinks("/tmp")
	if err != nil {
		return result, err
	}
	if registry := os.Getenv("CAPACITY_TEST_OWNER_ROOT"); registry != "" {
		info, statErr := os.Lstat(registry)
		resolved, resolveErr := filepath.EvalSymlinks(registry)
		if statErr != nil || resolveErr != nil || resolved != registry || filepath.Dir(registry) != tmp || !strings.HasPrefix(filepath.Base(registry), "dk-reg-") || !info.IsDir() || info.Mode().Perm() != 0700 {
			return result, errors.New("private owner registry required")
		}
		tmp = registry
	}
	ownerDir, err := os.MkdirTemp(tmp, "dk-own-")
	if err != nil {
		return result, err
	}
	cleanup := true
	defer func() {
		if cleanup {
			if e := os.RemoveAll(ownerDir); e != nil {
				err = errors.Join(err, e)
			}
		}
	}()
	clone := filepath.Join(ownerDir, "source")
	if err = exec.CommandContext(ctx, "git", "clone", "--quiet", "--no-hardlinks", "--", root, clone).Run(); err != nil {
		return result, errors.New("clean qualification checkout unavailable")
	}
	cloned, err := exec.CommandContext(ctx, "git", "-C", clone, "rev-parse", "HEAD").Output()
	if err != nil || strings.TrimSpace(string(cloned)) != head {
		return result, errors.New("qualification checkout revision mismatch")
	}
	if os.Getenv("GOWORK") != "off" {
		return result, errors.New("GOWORK=off required for source comparison")
	}
	compare := exec.CommandContext(ctx, "python3", filepath.Join(clone, "scripts/ci/capacity_fixture_source_equivalence.py"), "--source", root, "--clone", clone, "--go", goBinary, "--package", "./repository")
	if err = compare.Run(); err != nil {
		return result, errors.New("repository compiler inputs differ from clean checkout")
	}
	command := exec.Command("python3", filepath.Join(clone, "scripts/ci/capacity_pg17_owned_fixture.py"), "--run-repository")
	command.Dir = clone
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH", "GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "CGO_ENABLED", "CC", "CXX", "SDKROOT"} {
		if value, ok := os.LookupEnv(key); ok {
			command.Env = append(command.Env, key+"="+value)
		}
	}
	command.Env = append(command.Env, "CAPACITY_TEST_PG_BIN="+pg, "CAPACITY_TEST_GO="+goBinary, "CAPACITY_TEST_PARENT_DIR="+ownerDir)
	if registry := os.Getenv("CAPACITY_TEST_OWNER_ROOT"); registry != "" {
		command.Env = append(command.Env, "CAPACITY_TEST_OWNER_ROOT="+registry)
	}
	stdout, confirmed, runErr := capacityfixturetest.Run(ctx, command, ownerDir, 45*time.Second)
	cleanup = confirmed
	if runErr != nil {
		return result, fmt.Errorf("repository owner failed (cleanup confirmed=%t; owner directory=%s): %w", confirmed, ownerDir, runErr)
	}
	if err = json.Unmarshal([]byte(stdout), &result); err != nil {
		return result, errors.New("repository qualification result invalid")
	}
	if result.Schema != "ci_original_grant_concurrency_result_v1" || result.CoreSource != head || result.Provider != "native-qemu" || result.Slot != 5 || result.Floor != 2 || result.BaselineUnits != 4 || result.RegisteredBaseline != 4 || result.ProviderSendAttempted || result.NativeOrProductionQualified {
		return result, errors.New("repository source or synthetic baseline differs")
	}
	return result, nil
}

// Exercise the generic event formatter and outbox on the existing CI DB,
// without inserting a synthetic grant or creating mutation authority. The
// entire event transaction is rolled back after checking idempotency.
func assertGenericCapacityMutationEvent(t *testing.T) {
	t.Helper()
	db, policy, _ := capacityPostgresFixture(t)
	ctx := context.Background()
	var spec model.CapacityPolicySpec
	if err := json.Unmarshal(policy.Spec, &spec); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	record := capacityMutationRecord{
		Grant:   model.CapacityMutationGrant{GrantID: uuid.NewString(), Capability: "ensure_server", IntegrationInstanceID: uuid.NewString(), ScopeChecksum: strings.Repeat("a", 64), ProfileName: "base", Slot: 5},
		Binding: model.CapacityMutationBinding{DestroyCapability: "destroy_server"}, WorkflowID: uuid.New(), EventProvider: "fixture", EventResource: "server",
	}
	proof := model.CapacityMutationProof{ResourceID: "fixture-event-resource", ResourceCreatedAt: time.Now().UTC().Format(time.RFC3339Nano), ReceiptRef: "fixture:event-only", ActionIDs: []string{"fixture-action"}}
	now := time.Now().UTC()
	for n := 0; n < 2; n++ {
		if err := emitCapacityMutationEvent(ctx, tx, policy.Metadata.Namespace, spec, record, proof, now); err != nil {
			t.Fatal("generic event emission failed", err)
		}
	}
	var typ, aggregate, resource, instance string
	if err := tx.QueryRowContext(ctx, `SELECT type,aggregate_type,payload->>'resource_id',payload->>'instance_id' FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+record.Grant.GrantID).Scan(&typ, &aggregate, &resource, &instance); err != nil || typ != "fixture.server.ensured" || aggregate != "fixture_server" || resource != proof.ResourceID || instance != record.Grant.IntegrationInstanceID {
		t.Fatal("generic event shape mismatch", typ, aggregate, resource, instance, err)
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+record.Grant.GrantID).Scan(&count); err != nil || count != 1 {
		t.Fatal("generic event replay duplicated", count, err)
	}
}

// A focused route for exercising the generic outbox branch on an owned DB.
func TestGenericCapacityMutationEventFixture(t *testing.T) {
	assertGenericCapacityMutationEvent(t)
}
