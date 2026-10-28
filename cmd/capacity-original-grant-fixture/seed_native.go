//go:build capacitytest && nativequalification

package main

// Synthetic source-only fixture: all provider identities, binaries, baselines,
// endpoints and credentials below are invented for a disposable database. No
// QEMU process or native Guest is run and no production profile is admitted.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func syntheticWorkflow(ns, stepID string) model.WorkflowManifestSpec {
	return model.WorkflowManifestSpec{
		Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: ns, Name: "synthetic-rbac"}},
		Steps:         []model.WorkflowStepSpec{{ID: stepID, Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: capacity.ProvisionOriginalGuestOperation}, TimeoutSeconds: 600, Retry: model.WorkflowRetrySpec{MaxAttempts: 1}}},
	}
}

func prepareSynthetic(ctx context.Context, db *sql.DB, source string) (request, error) {
	return prepareSyntheticWithBaseline(ctx, db, source, 1, 0, 2)
}

func prepareSyntheticWithBaseline(ctx context.Context, db *sql.DB, source string, floor, units, maxSlots int) (request, error) {
	var req request
	if source == "" || source != capacity.CurrentGuestCoreSource() {
		return req, errors.New("actual clean source required")
	}
	if floor < 1 || units < 0 || units >= maxSlots || floor > maxSlots || maxSlots > 20 {
		return req, errors.New("synthetic baseline outside bounded fixture scope")
	}
	ns := "ci-synthetic-" + uuid.NewString()[:8]
	makeManifest := func(kind, name string, spec any) (model.Manifest, error) {
		raw, e := json.Marshal(spec)
		if e != nil {
			return model.Manifest{}, e
		}
		doc := manifest.NormalizeDocument(model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: ns, Name: name}, Spec: raw})
		if e := manifest.ValidateDocument(doc); e != nil {
			return model.Manifest{}, fmt.Errorf("synthetic %s manifest validation: %w", kind, e)
		}
		checksum, e := manifest.Checksum(doc)
		if e != nil {
			return model.Manifest{}, e
		}
		return repository.CreateManifestVersion(ctx, db, doc, checksum)
	}
	provider := model.IntegrationTypeManifestSpec{Provider: "native-qemu", Domain: "infrastructure", Adapter: model.IntegrationAdapterSpec{Transport: "rabbitmq", Version: "1.0.0", TimeoutSeconds: 65, Queues: model.IntegrationAdapterQueue{Describe: "qualification.original.describe", Execute: "qualification.original.execute"}}, Capabilities: []string{"describe", "execute"}, CredentialSchema: model.IntegrationSchemaSpec{Mode: "none"}, InstanceSchema: model.IntegrationSchemaSpec{Mode: "none"}, ResourceTypes: []model.IntegrationResourceType{{Name: "server", CanonicalPrefix: "thirdparty.native-qemu.server", IdentityTemplate: "server.{id}", DefaultActions: []string{"ensure_server", "destroy_server"}}}, ActionCatalog: []model.IntegrationActionDefinition{{Name: "ensure_server", ResourceTypes: []string{"server"}, Idempotent: true}, {Name: "destroy_server", ResourceTypes: []string{"server"}, Idempotent: true}}, Discovery: model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"}, Normalization: model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.native-qemu.server"}, Execution: model.IntegrationExecutionSpec{SupportsDryRun: true, IdempotentActions: []string{"ensure_server", "destroy_server"}}}
	raw, e := json.Marshal(provider)
	if e != nil {
		return req, e
	}
	parsed, e := manifest.ParseIntegrationTypeSpec(raw)
	if e != nil {
		return req, e
	}
	if e = manifest.ValidateIntegrationTypeSpec(parsed); e != nil {
		return req, e
	}
	typ, e := makeManifest("integration_type", "synthetic-native", provider)
	if e != nil {
		return req, e
	}
	instance, e := makeManifest("integration_instance", "synthetic-native", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}})
	if e != nil {
		return req, e
	}
	digest := capacity.BusinessCreationSHA256([]byte("synthetic-no-binary-or-guest"))
	writer := model.CapacityGuestProtectedWriterDefinition{ID: capacity.GuestQualificationWriter, SourceCommit: source, BinarySHA256: digest, CgroupRelativePath: ".", CommandSHA256: capacity.GuestRetirementSHA(struct {
		Executable  string   `json:"executable"`
		Args        []string `json:"args"`
		SourceClass string   `json:"source_class"`
	}{"/usr/local/libexec/yggdrasil-guest-protected-runtime-owner", []string{"--qualification-original-writer"}, "native_qemu_qualification"}), HandleContractSHA256: capacity.GuestRetirementSHA(struct{ Writer, Workers, Connections, Withdraw string }{capacity.GuestQualificationWriter, "original-child-Wait+stderr-EOF-Close", "original-stdout-EOF-Close+stdin-Close", "same-original-child-operation-bound-ACK"})}
	profile := model.CapacityGuestProtectedProfileManifest{Schema: capacity.GuestProtectedProfileSchema, Profile: capacity.GuestQualificationProfile, CoverageClass: "native_qualification_subset", MutationBinding: "native-qemu", BootstrapOwnerSourceCommit: source, BootstrapOwnerBinarySHA256: digest, BootstrapReaderBinarySHA256: digest, BootstrapPayloadSHA256: digest, BootstrapSHA256: digest, OriginalProvisioningBudgetSeconds: 420, OriginalProvisioningStepID: "original-native-qemu-create", OwnerSourceCommit: source, OwnerBinarySHA256: digest, ProtectedCgroup: capacity.GuestProtectedCgroup, ActorSourceCommit: source, ActorBinarySHA256: digest, RuntimeClientCommandSHA256: digest, PoweroffCommandSHA256: digest, Writers: []model.CapacityGuestProtectedWriterDefinition{writer}}
	b := model.CapacityMutationBinding{Name: "native-qemu", IntegrationInstanceID: instance.ID.String(), IntegrationChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), IntegrationTypeChecksum: typ.Checksum, AdapterPrincipalID: "synthetic-adapter", ScopeChecksum: capacity.GuestRetirementSHA([]string{ns, source}), ProfileName: profile.Profile, EnsureCapability: "ensure_server", DestroyCapability: "destroy_server", ProtectedSlots: floor, MaxSlots: maxSlots}
	for slot := 1; slot <= maxSlots; slot++ {
		p := model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: b.EnsureCapability, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: digest, AdmissionChecksum: capacity.GuestRetirementSHA(profile), ProfileName: b.ProfileName, Slot: slot, NativeName: fmt.Sprintf("synthetic-slot-%d", slot), BootstrapSHA256: digest}
		sha := capacity.GuestRetirementSHA(map[string]any{"schema_version": p.SchemaVersion, "capability": p.Capability, "integration_instance_id": p.IntegrationInstanceID, "scope_checksum": p.ScopeChecksum, "profile_checksum": p.ProfileChecksum, "admission_checksum": p.AdmissionChecksum, "profile_name": p.ProfileName, "slot": p.Slot, "native_name": p.NativeName, "bootstrap_sha256": p.BootstrapSHA256})
		b.Slots = append(b.Slots, model.CapacityMutationSlotBinding{Slot: slot, DesiredSpecSHA256: sha, DesiredSpec: &p})
	}
	pub1, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return req, e
	}
	pub2, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return req, e
	}
	binding := model.CapacityGuestRetirementBinding{Mode: capacity.GuestRetirementSchema, MutationBindingName: b.Name, EvidenceClass: "native_qemu_qualification", ProvisionerSourceCommit: source, GuestSourceCommit: source, CoreAuthoritySourceCommit: source, ProvisionerPublicKey: base64.StdEncoding.EncodeToString(pub1), EnrollmentIssuerPublicKey: base64.StdEncoding.EncodeToString(pub2), EnrollmentSigningKeyRef: "secret://" + ns + "/synthetic-issuer#value", IntentSigningKeyRef: "secret://" + ns + "/synthetic-intent#value", ProfileManifest: profile, ProfileManifestSHA256: capacity.GuestRetirementSHA(profile), MaxEvidenceAgeSeconds: 30}
	for slot := 1; slot <= maxSlots; slot++ {
		name := fmt.Sprintf("synthetic-slot-%d", slot)
		binding.Members = append(binding.Members, model.CapacityGuestRetirementMemberBinding{Name: name, Slot: slot, Origin: fmt.Sprintf("https://127.0.0.1:%d", 19446+slot), ServerCARef: "secret://" + ns + "/ca#value", ClientCertificateRef: "secret://" + ns + "/cert#value", ClientKeyRef: "secret://" + ns + "/key#value", ActorClientPrincipal: name + "-actor", ProvisionerClientPrincipal: name + "-producer"})
	}
	rbac := map[string]any{"roles": []any{map[string]any{"name": "synthetic-caller", "rules": []any{map[string]any{"effect": "allow", "resources": []string{"workflow:" + ns + ":synthetic-native"}, "actions": []string{"run"}}}}}, "bindings": []any{map[string]any{"name": "synthetic-caller", "subjects": []any{map[string]string{"type": "service", "id": "synthetic-caller"}}, "roles": []string{"synthetic-caller"}}}}
	if _, e = makeManifest("rbac", "synthetic-rbac", rbac); e != nil {
		return req, e
	}
	wfSpec := syntheticWorkflow(ns, profile.OriginalProvisioningStepID)
	if e = manifest.ValidateWorkflowSpec(wfSpec); e != nil {
		return req, fmt.Errorf("synthetic workflow validation: %w", e)
	}
	wf, e := makeManifest("workflow", "synthetic-native", wfSpec)
	if e != nil {
		return req, e
	}
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "qualification", Domain: "infrastructure", Dimension: "native_echo", TargetIdentity: "synthetic:" + ns, Owner: "synthetic-native", Workflow: model.ManifestSelector{Namespace: ns, Name: wf.Metadata.Name}, Currency: "USD", Floor: floor, Ceiling: maxSlots, Step: 1, MaxEvidenceAgeSeconds: 30, MaxSampleGapSeconds: 5, MinSamples: 1, DownHoldSeconds: 1, LeaseSeconds: 300, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "qualification-demand", SourceIdentity: "source-controlled-native-fixture-demand", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, Profiles: []model.CapacityProfile{{Name: profile.Profile, Provider: "native-qemu", Region: "synthetic", MinUnits: floor, MaxUnits: maxSlots, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "synthetic-only:no-native-guest"}}, MutationBindings: []model.CapacityMutationBinding{b}, GuestRetirementBinding: &binding}
	if e = manifest.ValidateCapacityPolicySpec(p); e != nil {
		return req, fmt.Errorf("synthetic policy validation: %w", e)
	}
	if e = capacity.ValidateGuestRetirementBinding(p, &binding); e != nil {
		return req, fmt.Errorf("synthetic binding validation: %w", e)
	}
	if !capacity.GuestOriginalProfileEnabled(p, binding, "native-qemu") {
		return req, errors.New("synthetic profile registry refused")
	}
	policy, e := makeManifest("capacity_policy", "synthetic-native", p)
	if e != nil {
		return req, e
	}
	demand := .9
	a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: p.TargetIdentity, WorkloadUID: p.TargetIdentity, WorkloadResourceVersion: "synthetic-v1", ResourceVersion: "synthetic-v1", Owner: p.Owner, Profile: p.Profiles[0].Name, Units: units, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "qualification-demand", SourceIdentity: "source-controlled-native-fixture-demand", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &demand, RangeMin: &demand, RangeMax: &demand, SourceSampledAt: now, WindowStart: now, WindowEnd: now, Samples: 1, CoverageComplete: true, MaxGapSeconds: 0}}}
	executor := uuid.NewString()
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: executor}
	intent, e := store.Assess(ctx, policy, a)
	if e != nil {
		return req, fmt.Errorf("assess synthetic fixture: %w", e)
	}
	intent, e = store.Claim(ctx, policy, intent.Generation, a)
	if e != nil {
		return req, fmt.Errorf("claim synthetic fixture: %w", e)
	}
	for index := 0; index < units; index++ {
		approved := b.Slots[index]
		spec, err := json.Marshal(approved.DesiredSpec)
		if err != nil {
			return req, err
		}
		proof := model.CapacityMutationProof{BindingName: b.Name, Slot: approved.Slot, ResourceID: fmt.Sprintf("synthetic-baseline-%d", approved.Slot), ResourceCreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano), RequestSHA256: approved.DesiredSpecSHA256, ObservedAt: now, ReceiptRef: "synthetic:baseline-not-native", OwnerVerified: true, SpecVerified: true}
		if err = store.RecordMutationSlot(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: spec}, proof); err != nil {
			return req, fmt.Errorf("synthetic baseline registration: %w", err)
		}
	}
	return request{Schema: "ci_original_grant_concurrency_v1", PolicyID: policy.ID, WorkflowID: wf.ID, Generation: intent.Generation, Fence: intent.FencingToken, LeaseOwner: intent.LeaseOwner, ExecutorID: executor, BindingName: b.Name, Slot: units + 1, NonceSHA256: capacity.BusinessCreationSHA256([]byte(uuid.NewString()))}, nil
}

// seedAndRun uses only a source root and a disposable database chosen by the
// surrounding test owner. It deliberately refuses a dirty binary or checkout.
func seedAndRun() error {
	var input struct {
		SourceRoot string `json:"source_root"`
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil || len(raw) == 0 || len(raw) > 4096 {
		return errors.New("bounded source input required")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || !filepath.IsAbs(input.SourceRoot) {
		return errors.New("closed source input required")
	}
	database, err := checkDSN(os.Getenv("DB_URL"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	source, err := checkSource(ctx, input.SourceRoot)
	if err != nil {
		return err
	}
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		return errors.New("fixture database open failed")
	}
	defer db.Close()
	db.SetMaxOpenConns(contenders + 4)
	if err = checkOwnedPostgres(ctx, db, database, os.Getenv("CAPACITY_TEST_SOCKET_DIR")); err != nil {
		return err
	}
	request, err := prepareSynthetic(ctx, db, source)
	if err != nil {
		return err
	}
	request.SourceRoot = input.SourceRoot
	result, err := run(ctx, db, request, source)
	if err != nil {
		return err
	}
	if err = syntheticSettlementScope(ctx, db, source); err != nil {
		return fmt.Errorf("synthetic settlement scope: %w", err)
	}
	result.SettlementScopePrivacyPassed = true
	httpPassed, err := syntheticHTTPCallbacks(ctx, db, source)
	if err != nil {
		return fmt.Errorf("synthetic HTTP callbacks: %w", err)
	}
	result.SyntheticHTTPCallbacksPassed = httpPassed
	return json.NewEncoder(os.Stdout).Encode(result)
}
