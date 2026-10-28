//go:build recoveryfixture && !nativequalification

package message

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

// Only test-tagged synthetic data and a fresh local PG16 database. No real
// native provider call or Guest qualification is asserted by this setup.
func nativeWorkflowFixtureDSN(t *testing.T, dsn string) string {
	t.Helper()
	if os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		return dsn
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("local fixture DSN required")
	}
	host, socket := u.Hostname(), u.Query().Get("host")
	if host != "localhost" && host != "127.0.0.1" && host != "::1" && !(host == "" && strings.HasPrefix(socket, "/")) {
		t.Fatal("remote PG refused")
	}
	admin, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal("fixture admin unavailable")
	}
	var addr string
	if err = admin.QueryRow(`SELECT COALESCE(inet_server_addr()::text,'unix')`).Scan(&addr); err != nil || !(addr == "unix" || strings.HasPrefix(addr, "127.") || addr == "::1") {
		t.Fatal("nonlocal PG refused")
	}
	name := "recovery_fixture_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec("CREATE DATABASE " + pq.QuoteIdentifier(name)); err != nil {
		t.Fatal("fixture database create failed")
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal("fixture database unavailable")
	}
	t.Cleanup(func() {
		_ = db.Close()
		if _, e := admin.Exec("DROP DATABASE " + pq.QuoteIdentifier(name) + " WITH (FORCE)"); e != nil {
			t.Error("fixture database cleanup failed")
		}
		_ = admin.Close()
	})
	var major int
	if err = db.QueryRow(`SELECT current_setting('server_version_num')::int / 10000`).Scan(&major); err != nil || major != 16 {
		t.Fatal("PG16 required")
	}
	if err = goose.SetDialect("postgres"); err != nil {
		t.Fatal("fixture migration dialect")
	}
	if err = goose.Up(db, "../../db/migrations"); err != nil {
		t.Fatal("fixture migrations failed")
	}
	return u.String()
}

func nativeWorkflowFixtureWorkflow(t *testing.T, wf model.WorkflowManifestSpec) model.WorkflowManifestSpec {
	t.Helper()
	if os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		return wf
	}
	_, b, _, _, _ := capacity.RecoveryFixtureInstalled(t)
	wf.Steps = append(wf.Steps, model.WorkflowStepSpec{ID: b.ProfileManifest.OriginalProvisioningStepID, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: capacity.ProvisionOriginalGuestOperation}, TimeoutSeconds: b.ProfileManifest.OriginalProvisioningBudgetSeconds})
	return wf
}

func nativeWorkflowFixturePolicy(t *testing.T, p model.CapacityPolicySpec, mutation model.CapacityMutationBinding, slots []model.CapacityMutationSlotBinding) (model.CapacityPolicySpec, model.CapacityMutationBinding) {
	t.Helper()
	if os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		return p, mutation
	}
	capacity.RecoveryFixtureApprovalScope(t)
	fixturePolicy, b, _, _, _ := capacity.RecoveryFixtureInstalled(t)
	mutation.OriginalProviderSourceCommit = fixturePolicy.MutationBindings[0].OriginalProviderSourceCommit
	p.MutationBindings = []model.CapacityMutationBinding{mutation}
	b.CoreAuthoritySourceCommit = capacity.CurrentGuestCoreSource()
	if b.CoreAuthoritySourceCommit == "" {
		t.Fatal("clean source identity required")
	}
	b.MutationBindingName = mutation.Name
	b.Members = append([]model.CapacityGuestRetirementMemberBinding(nil), b.Members[:len(slots)]...)
	b.ProfileManifest.Profile, b.ProfileManifest.MutationBinding = mutation.ProfileName, mutation.Name
	b.ProfileManifest.Writers[0].CgroupRelativePath = b.ProfileManifest.Writers[0].ID
	b.ProfileManifest.SlotBootstraps = nil
	if len(slots) == 0 || slots[0].DesiredSpec == nil {
		t.Fatal("approved slot required")
	}
	b.ProfileManifest.BootstrapSHA256 = slots[0].DesiredSpec.BootstrapSHA256
	for _, slot := range slots {
		if slot.DesiredSpec == nil || slot.DesiredSpec.BootstrapSHA256 != b.ProfileManifest.BootstrapSHA256 {
			t.Fatal("shared synthetic bootstrap must match every slot")
		}
	}
	b.ProfileManifestSHA256 = capacity.GuestRetirementSHA(b.ProfileManifest)
	p.GuestRetirementBinding = &b
	if err := capacity.ValidateGuestRetirementBinding(p, &b); err != nil {
		t.Fatal("synthetic binding refused", err)
	}
	if err := capacity.RegisterRecoveryFixtureApproval(p, b, "hetzner"); err != nil {
		t.Fatal("synthetic approval refused", err)
	}
	return p, mutation
}

func nativeWorkflowFixtureStore(t *testing.T, store repository.CapacityStore) repository.CapacityStore {
	t.Helper()
	if os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		return store
	}
	_, b, _, _, _ := capacity.RecoveryFixtureInstalled(t)
	step := model.WorkflowStepSpec{ID: b.ProfileManifest.OriginalProvisioningStepID, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: capacity.ProvisionOriginalGuestOperation}, TimeoutSeconds: b.ProfileManifest.OriginalProvisioningBudgetSeconds}
	return store.WithOriginalGuestProvisioning(step, capacity.CurrentGuestCoreSource(), capacity.BusinessCreationSHA256([]byte(uuid.NewString())))
}

func nativeWorkflowSyntheticGate(*testing.T) bool { return false }

// This is a declared response used only in the isolated test DB. It is not a
// provider call and must never be treated as production or native evidence.
func nativeWorkflowFixtureSettlement(t *testing.T, b model.CapacityMutationBinding, g model.CapacityMutationGrant, s model.CapacityMutationSettleRequest) model.CapacityMutationSettleRequest {
	t.Helper()
	if os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" || s.Outcome != "accepted" {
		return s
	}
	at := time.Now().UTC().Format(time.RFC3339Nano)
	if s.NextActionIDs == nil {
		s.NextActionIDs = []string{}
	}
	s.OriginalProviderCreateReturn = &model.CapacityOriginalProviderCreateReturn{Schema: "hetzner_original_create_return_v1", Provider: "hetzner", AdapterSourceCommit: b.OriginalProviderSourceCommit, GrantID: g.GrantID, AttemptID: s.AttemptID, RequestSHA256: g.RequestSHA256, ResourceID: s.ResourceID, ResourceCreatedAt: s.ResourceCreatedAt, ActionID: s.ActionID, NextActionIDs: append([]string{}, s.NextActionIDs...), CalledAt: at, ReturnedAt: at, ContextDeadline: g.ExpiresAt.UTC().Format(time.RFC3339Nano), ResponseStatus: 201, ResponseBodySHA256: capacity.BusinessCreationSHA256([]byte("synthetic provider response")), ResponseBytes: int64(len("synthetic provider response"))}
	s.ObservedAt = at
	return s
}

func nativeWorkflowFixtureContext(t *testing.T, parent context.Context) context.Context {
	t.Helper()
	if os.Getenv("CAPACITY_RECOVERY_FIXTURE_ONLY") != "true" {
		return parent
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}
