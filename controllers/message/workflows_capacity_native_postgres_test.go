package message

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type capacityGuestProtocolPostgres struct {
	db            *sql.DB
	ctx           context.Context
	policy        model.Manifest
	wf            model.Manifest
	p             model.CapacityPolicySpec
	input         map[string]any
	guestReads    atomic.Int32
	describeReads atomic.Int32
	mode          atomic.Value
	tokenSecret   model.ManagedSecret
	sshSecret     model.ManagedSecret
	guestType     model.Manifest
	guestInstance model.Manifest
	lease         model.CapacityIntent
}

// Private CI rendezvous. It is never an API/capability input or production
// enrollment source. Its QEMU guest is native; provider/Node projections are
// explicitly protocol fixtures and physical certification stays false.
type capacityGuestFixtureIntegration struct {
	Type         model.ManifestReference `json:"type"`
	TypeSpec     json.RawMessage         `json:"type_spec"`
	Instance     model.ManifestReference `json:"instance"`
	InstanceSpec json.RawMessage         `json:"instance_spec"`
}
type capacityGuestFixtureCatalog struct {
	Schema            string          `json:"schema"`
	GuestSourceCommit string          `json:"guest_source_commit"`
	TypeSpec          json.RawMessage `json:"type_spec"`
}
type capacityGuestFixtureRuntime struct {
	Schema            string                          `json:"schema"`
	CoreSourceCommit  string                          `json:"core_source_commit"`
	GuestSourceCommit string                          `json:"guest_source_commit"`
	Integration       capacityGuestFixtureIntegration `json:"integration"`
	Binding           json.RawMessage                 `json:"binding"`
	UpstreamBaseURL   string                          `json:"upstream_base_url"`
	RPCBearer         string                          `json:"rpc_bearer"`
	SSHPrivateKey     string                          `json:"ssh_private_key"`
}
type capacityGuestFixtureBinding struct {
	Name                            string                         `json:"name"`
	AdapterInstanceID               string                         `json:"adapter_instance_id"`
	AdapterInstanceChecksum         string                         `json:"adapter_instance_checksum"`
	AdapterTypeID                   string                         `json:"adapter_type_id"`
	AdapterTypeChecksum             string                         `json:"adapter_type_checksum"`
	AdapterTypeNamespace            string                         `json:"adapter_type_namespace"`
	AdapterTypeName                 string                         `json:"adapter_type_name"`
	AdapterTypeVersion              int                            `json:"adapter_type_version"`
	AdapterTypeSpecSHA256           string                         `json:"adapter_type_spec_sha256"`
	AdapterInstanceNamespace        string                         `json:"adapter_instance_namespace"`
	AdapterInstanceName             string                         `json:"adapter_instance_name"`
	AdapterInstanceVersion          int                            `json:"adapter_instance_version"`
	AdapterInstanceSpecSHA256       string                         `json:"adapter_instance_spec_sha256"`
	Address                         string                         `json:"address"`
	Username                        string                         `json:"username"`
	HostPublicKey                   string                         `json:"host_public_key"`
	CredentialKey                   string                         `json:"credential_key"`
	CredentialPublicKeySHA256       string                         `json:"credential_public_key_sha256"`
	ForcedReaderCommandSHA256       string                         `json:"forced_reader_command_sha256"`
	Tuple                           model.CapacityGuestNativeTuple `json:"tuple"`
	BootID                          string                         `json:"boot_id"`
	UserDataSHA256                  string                         `json:"user_data_sha256"`
	PayloadSHA256                   string                         `json:"payload_sha256"`
	OwnerBinarySHA256               string                         `json:"owner_binary_sha256"`
	ReaderBinarySHA256              string                         `json:"reader_binary_sha256"`
	GuestSourceCommit               string                         `json:"guest_source_commit"`
	EnrollmentAuthorityPublicKey    string                         `json:"enrollment_authority_public_key"`
	EnrollmentAuthoritySourceCommit string                         `json:"enrollment_authority_source_commit"`
	Enrollment                      struct {
		Statement model.CapacityGuestEnrollmentStatement `json:"statement"`
		Signature string                                 `json:"signature"`
	} `json:"enrollment"`
}
type capacityGuestNativeFixture struct {
	ctx         context.Context
	prepareCtx  context.Context
	dir         string
	coreSource  string
	guestSource string
	catalog     capacityGuestFixtureCatalog
	runtime     capacityGuestFixtureRuntime
	binding     capacityGuestFixtureBinding
}

func capacityGuestFixtureSHA(raw []byte) string {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value any
	if d.Decode(&value) != nil || value == nil || d.Decode(new(any)) != io.EOF {
		return ""
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return capacity.BusinessCreationSHA256(canonical)
}

func capacityGuestFixtureDir(dir string) (*os.File, error) {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, errCapacityNativeObservation
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 || st.Mode()&os.ModeSymlink != 0 {
		return nil, errCapacityNativeObservation
	}
	native, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(native.Uid) != os.Geteuid() {
		return nil, errCapacityNativeObservation
	}
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errCapacityNativeObservation
	}
	return os.NewFile(uintptr(fd), "private-native-directory"), nil
}

func (n *capacityGuestNativeFixture) read(name string, out any) error {
	if nativeAdapterContext(n.ctx) != nil {
		return errCapacityNativeObservation
	}
	dir, err := capacityGuestFixtureDir(n.dir)
	if err != nil {
		return err
	}
	fd, openErr := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	dirErr := dir.Close()
	if openErr != nil {
		if errors.Is(openErr, syscall.ENOENT) && dirErr == nil {
			return os.ErrNotExist
		}
		return errCapacityNativeObservation
	}
	file := os.NewFile(uintptr(fd), "private-native-frame")
	st, statErr := file.Stat()
	valid := statErr == nil && st.Mode().IsRegular() && st.Mode().Perm() == 0600
	if valid {
		owner, ok := st.Sys().(*syscall.Stat_t)
		valid = ok && int(owner.Uid) == os.Geteuid()
	}
	var raw []byte
	var readErr error
	if valid {
		raw, readErr = io.ReadAll(io.LimitReader(file, capacity.GuestBootstrapLimit+1))
	}
	closeErr := file.Close()
	if !valid || dirErr != nil || readErr != nil || closeErr != nil || len(raw) > capacity.GuestBootstrapLimit || nativeAdapterContext(n.ctx) != nil {
		return errCapacityNativeObservation
	}
	if capacity.DecodeBusinessJSON(raw, out) != nil {
		return errCapacityNativeObservation
	}
	return nil
}

func (n *capacityGuestNativeFixture) await(name string, out any) error {
	for {
		err := n.read(name, out)
		if err == nil {
			return nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return errCapacityNativeObservation
		}
		select {
		case <-n.ctx.Done():
			return errCapacityNativeObservation
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func (n *capacityGuestNativeFixture) writePrepare(value any) (result error) {
	if nativeAdapterContext(n.ctx) != nil || nativeAdapterContext(n.prepareCtx) != nil {
		return errCapacityNativeObservation
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > capacity.GuestBootstrapLimit {
		return errCapacityNativeObservation
	}
	dir, err := capacityGuestFixtureDir(n.dir)
	if err != nil {
		return err
	}
	defer func() {
		if dir.Close() != nil {
			result = errCapacityNativeObservation
		}
	}()
	if _, e := os.Lstat(filepath.Join(n.dir, "prepare.json")); !errors.Is(e, os.ErrNotExist) {
		return errCapacityNativeObservation
	}
	fd, err := syscall.Openat(int(dir.Fd()), "prepare.json.new", syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return errCapacityNativeObservation
	}
	file := os.NewFile(uintptr(fd), "private-native-prepare")
	written, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if written != len(raw) || writeErr != nil || syncErr != nil || closeErr != nil || nativeAdapterContext(n.ctx) != nil || nativeAdapterContext(n.prepareCtx) != nil {
		return errCapacityNativeObservation
	}
	if err = syscall.Renameat(int(dir.Fd()), "prepare.json.new", int(dir.Fd()), "prepare.json"); err != nil {
		return errCapacityNativeObservation
	}
	if dir.Sync() != nil || nativeAdapterContext(n.ctx) != nil || nativeAdapterContext(n.prepareCtx) != nil {
		return errCapacityNativeObservation
	}
	return nil
}

func (n *capacityGuestNativeFixture) prepareAndAwait(t *testing.T, b model.CapacityMutationBinding, p model.CapacityPolicySpec, vm model.CapacityVMFleetInventoryMember, typ, instance model.Manifest, origin string) {
	t.Helper()
	tuple := model.CapacityGuestNativeTuple{Provider: p.Profiles[0].Provider, InstanceID: b.IntegrationInstanceID, InstanceChecksum: b.IntegrationChecksum, TypeID: b.IntegrationTypeID, TypeChecksum: b.IntegrationTypeChecksum, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: vm.DesiredSpec.ProfileChecksum, Profile: b.ProfileName, Slot: vm.Slot, ResourceID: vm.Server.ID, CreatedAt: vm.Server.CreatedAt}
	integration := capacityGuestFixtureIntegration{Type: manifestReferenceFromRecord(typ), TypeSpec: typ.Spec, Instance: manifestReferenceFromRecord(instance), InstanceSpec: instance.Spec}
	prepare := struct {
		Schema             string                          `json:"schema"`
		CoreSourceCommit   string                          `json:"core_source_commit"`
		GuestSourceCommit  string                          `json:"guest_source_commit"`
		Tuple              model.CapacityGuestNativeTuple  `json:"tuple"`
		Integration        capacityGuestFixtureIntegration `json:"integration"`
		TLSProxyOrigin     string                          `json:"tls_proxy_origin"`
		TypeChecksum       string                          `json:"type_checksum"`
		InstanceChecksum   string                          `json:"instance_checksum"`
		TypeSpecSHA256     string                          `json:"type_spec_sha256"`
		InstanceSpecSHA256 string                          `json:"instance_spec_sha256"`
	}{"native_guest_core_prepare_v1", n.coreSource, n.guestSource, tuple, integration, origin, typ.Checksum, instance.Checksum, capacityGuestFixtureSHA(typ.Spec), capacityGuestFixtureSHA(instance.Spec)}
	if n.writePrepare(prepare) != nil || n.await("runtime.json", &n.runtime) != nil {
		t.Fatal("original native Guest rendezvous unavailable")
	}
	actual, expected := capacityGuestFixtureSHA(mustGuestFixtureJSON(t, n.runtime.Integration)), capacityGuestFixtureSHA(mustGuestFixtureJSON(t, integration))
	if n.runtime.Schema != "native_guest_core_runtime_v1" || n.runtime.CoreSourceCommit != n.coreSource || n.runtime.GuestSourceCommit != n.guestSource || actual != expected || len(n.runtime.RPCBearer) < 32 || len(n.runtime.RPCBearer) > 4096 || strings.ContainsAny(n.runtime.RPCBearer, "\r\n") || n.runtime.SSHPrivateKey == "" || len(n.runtime.SSHPrivateKey) > 16384 || capacity.DecodeBusinessJSON(n.runtime.Binding, &n.binding) != nil {
		t.Fatal("original native Guest closed runtime refused")
	}
	u, err := url.Parse(n.runtime.UpstreamBaseURL)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		t.Fatal("original native Guest upstream refused")
	}
	g := n.binding
	if g.AdapterInstanceID != instance.ID.String() || g.AdapterInstanceChecksum != instance.Checksum || g.AdapterTypeID != typ.ID.String() || g.AdapterTypeChecksum != typ.Checksum || g.AdapterTypeNamespace != typ.Metadata.Namespace || g.AdapterTypeName != typ.Metadata.Name || g.AdapterTypeVersion != typ.Version || g.AdapterInstanceNamespace != instance.Metadata.Namespace || g.AdapterInstanceName != instance.Metadata.Name || g.AdapterInstanceVersion != instance.Version || g.AdapterTypeSpecSHA256 != prepare.TypeSpecSHA256 || g.AdapterInstanceSpecSHA256 != prepare.InstanceSpecSHA256 || g.Tuple != tuple || g.GuestSourceCommit != n.guestSource || g.Enrollment.Statement.Tuple != tuple || g.Enrollment.Statement.SourceClass != "native_qemu_qualification" || g.Enrollment.Statement.GuestSourceCommit != n.guestSource || g.CredentialKey != "ssh_private_key" || g.Enrollment.Statement.BindingName != g.Name || g.Enrollment.Statement.BootID != g.BootID || g.Enrollment.Statement.UserDataSHA256 != g.UserDataSHA256 || g.Enrollment.Statement.PayloadSHA256 != g.PayloadSHA256 || g.Enrollment.Statement.OwnerBinarySHA256 != g.OwnerBinarySHA256 || g.Enrollment.Statement.ReaderBinarySHA256 != g.ReaderBinarySHA256 || g.Enrollment.Statement.ProvisionerSourceCommit != g.EnrollmentAuthoritySourceCommit || g.CredentialPublicKeySHA256 != g.Enrollment.Statement.CredentialPublicKeySHA256 || g.ForcedReaderCommandSHA256 != g.Enrollment.Statement.ForcedReaderCommandSHA256 {
		t.Fatal("original native Guest enrollment/source tuple refused")
	}
}

func mustGuestFixtureJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("private native JSON unavailable")
	}
	return raw
}

func (n *capacityGuestNativeFixture) proxy(w http.ResponseWriter, r *http.Request, f *capacityGuestProtocolPostgres) {
	if n.runtime.UpstreamBaseURL == "" || (r.URL.Path != "/healthz" && r.URL.Path != "/rpc/describe" && r.URL.Path != "/rpc/execute") || r.Header.Get("Authorization") != "Bearer "+n.runtime.RPCBearer {
		w.WriteHeader(503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 65*time.Second)
	defer cancel()
	body, readErr := io.ReadAll(io.LimitReader(r.Body, capacity.GuestBootstrapLimit+1))
	closeErr := r.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > capacity.GuestBootstrapLimit || nativeAdapterContext(ctx) != nil {
		w.WriteHeader(502)
		return
	}
	upstream := strings.TrimRight(n.runtime.UpstreamBaseURL, "/") + r.URL.Path
	request, err := http.NewRequestWithContext(ctx, r.Method, upstream, bytes.NewReader(body))
	if err != nil {
		w.WriteHeader(502)
		return
	}
	request.GetBody = nil
	request.Header.Set("Authorization", "Bearer "+n.runtime.RPCBearer)
	request.Header.Set("Content-Type", "application/json")
	client := http.Client{Transport: http.DefaultTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return errCapacityNativeObservation }}
	reply, callErr := client.Do(request)
	var raw []byte
	var responseRead, responseClose error
	valid := reply != nil && reply.Body != nil && callErr == nil && reply.Request != nil && reply.Request.URL != nil && reply.Request.URL.String() == upstream && reply.Request.Method == r.Method
	if reply != nil && reply.Body != nil {
		if valid {
			raw, responseRead = io.ReadAll(io.LimitReader(reply.Body, capacity.GuestBootstrapLimit+1))
		}
		responseClose = reply.Body.Close()
	}
	if !valid || callErr != nil || responseRead != nil || responseClose != nil || len(raw) > capacity.GuestBootstrapLimit || nativeAdapterContext(ctx) != nil {
		w.WriteHeader(502)
		return
	}
	if r.URL.Path == "/rpc/execute" {
		f.guestReads.Add(1)
	}
	if r.URL.Path == "/rpc/describe" {
		f.describeReads.Add(1)
	}
	w.Header().Set("Content-Type", reply.Header.Get("Content-Type"))
	w.WriteHeader(reply.StatusCode)
	_, _ = w.Write(raw)
}

func TestCapacityVMGuestExistingCollectorPostgres(t *testing.T) {
	if os.Getenv("REQUIRE_CAPACITY_GUEST_NATIVE") != "true" {
		t.Skip("original private Guest/Core native gate is not this ordinary unit job")
	}
	if os.Getenv("REQUIRE_CAPACITY_POSTGRES") != "true" || os.Getenv("DB_URL") == "" {
		t.Fatal("original private Guest/Core native job required; no protocol fallback")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()
	prepareCtx, prepareCancel := context.WithTimeout(ctx, 300*time.Second)
	defer prepareCancel()
	native := &capacityGuestNativeFixture{ctx: ctx, dir: os.Getenv("CORE_NATIVE_GUEST_RENDEZVOUS_DIR"), coreSource: os.Getenv("CORE_NATIVE_GUEST_CORE_SOURCE_COMMIT"), guestSource: os.Getenv("CORE_NATIVE_GUEST_ADAPTER_SOURCE_COMMIT")}
	native.prepareCtx = prepareCtx
	catalogOwner := *native
	catalogOwner.ctx = prepareCtx
	if len(native.coreSource) != 40 || len(native.guestSource) != 40 || strings.Trim(native.coreSource+native.guestSource, "0123456789abcdef") != "" || catalogOwner.await("catalog.json", &native.catalog) != nil || native.catalog.Schema != "native_guest_catalog_v1" || native.catalog.GuestSourceCommit != native.guestSource {
		t.Fatal("original exact native source catalog required")
	}
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	t.Setenv("YGGDRASIL_CAPACITY_GUEST_BOOTSTRAP_ENABLED", "true")
	f := newCapacityGuestProtocolPostgres(t, "", native)
	t.Run("complete_selected_roster_and_missing_member_hold", func(t *testing.T) {
		before := f.ledger(t)
		got := f.run(f.ctx)
		if got.Status != "succeeded" || got.Metadata["original_guest_roster_observed"] != true || got.Metadata["physical_guest_certificate"] != false || got.Metadata["bootstrap_completed_known"] != false || got.Metadata["useful_capacity_known"] != false || f.guestReads.Load() != 1 || f.ledger(t) != before {
			t.Fatal("current Core did not join original native Guest scope")
		}
		// The protocol provider omits the originally registered member. The
		// independently retained registry must HOLD before another Guest read.
		f.mode.Store("empty_source")
		reads := f.guestReads.Load()
		held := f.run(f.ctx)
		if held.Status == "succeeded" || held.Metadata != nil || f.guestReads.Load() != reads || f.ledger(t) != before {
			t.Fatal("missing original selected member replayed or accepted")
		}
		f.mode.Store("")
	})
	t.Run("ordinary_unconfigured_collector_preserved", func(t *testing.T) {
		ordinary := f.p
		ordinary.GuestBootstrapBinding = nil
		raw := mustGuestFixtureJSON(t, ordinary)
		sum := fmt.Sprintf("%x", sha256.Sum256(raw))
		if _, err := f.db.ExecContext(f.ctx, `UPDATE public.manifests SET spec=$2::jsonb,checksum=$3 WHERE id=$1`, f.policy.ID, raw, sum); err != nil {
			t.Fatal("ordinary operator fixture unavailable")
		}
		before := f.ledger(t)
		reads := f.guestReads.Load()
		got := f.run(f.ctx)
		_, guestPresent := got.Metadata["original_guest_roster_observed"]
		if got.Status != "succeeded" || guestPresent || got.Metadata["bootstrap_completed_known"] != false || got.Metadata["useful_capacity_known"] != false || f.guestReads.Load() != reads || f.ledger(t) != before {
			t.Fatal("absent optional binding changed ordinary original collector")
		}
	})
}

// Actual PostgreSQL, resolver and protected collector; all represented VM,
// Node and Guest records in this corpus are expressly protocol fixtures.
func newCapacityGuestProtocolPostgres(t *testing.T, initialMode string, native *capacityGuestNativeFixture) *capacityGuestProtocolPostgres {
	t.Helper()
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		t.Fatal("original remote PostgreSQL gate required")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	f := &capacityGuestProtocolPostgres{db: db, ctx: newCapacityInvocationContext(t.Context())}
	if native != nil {
		f.ctx = newCapacityInvocationContext(native.prepareCtx)
	}
	f.mode.Store(initialMode)
	ns := "guest-source-" + uuid.NewString()
	t.Cleanup(func() {
		for _, table := range []string{"capacity_mutation_grants", "capacity_resource_slots", "capacity_intent_events", "capacity_intents", "managed_secrets", "manifests"} {
			query := `DELETE FROM public.` + table + ` WHERE namespace=$1`
			if _, e := db.ExecContext(context.Background(), query, ns); e != nil {
				t.Error(e)
			}
		}
		db.Close()
	})
	p, b, inv, nodes := capacityVMNodeProtocolFixture(t)
	p.Workflow.Namespace = ns
	if native != nil {
		p.Profiles[0].Provider = "qualification_qemu"
		inv.Members = inv.Members[:1]
		inv.MissingSlots = []int{2, 3, 4}
		nodes.Nodes = nodes.Nodes[:1]
		nodes.NativeNodeCount = 1
		inv.Members[0].Server.ID = uuid.NewString()
		inv.Members[0].Server.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		nodes.Nodes[0].ProviderID = p.VMNodeMembershipBinding.Target.ProviderIDPrefix + inv.Members[0].Server.ID
		nodes.Nodes[0].CreatedAt = time.Now().UTC()
		nodes.Nodes[0].ReadyChangedAt = nodes.Nodes[0].CreatedAt
	}
	typeSpec := func(provider, resource string, ops []string) model.IntegrationTypeManifestSpec {
		s := model.IntegrationTypeManifestSpec{Provider: provider, Domain: "infrastructure", Adapter: model.IntegrationAdapterSpec{Transport: "http_json", Version: "1.0.0", Endpoints: model.IntegrationAdapterRoute{Health: "/nativehealth", Describe: "/describe", Execute: "/execute"}, TimeoutSeconds: 65}, Capabilities: []string{"describe", "execute"}, CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{}}, InstanceSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{"base_url": {Type: "string"}}}, ResourceTypes: []model.IntegrationResourceType{{Name: resource, CanonicalPrefix: "thirdparty." + provider + "." + resource, IdentityTemplate: resource + ".{id}", DefaultActions: ops}}, Discovery: model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"}, Normalization: model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty." + provider + "." + resource}}
		for _, op := range ops {
			s.ActionCatalog = append(s.ActionCatalog, model.IntegrationActionDefinition{Name: op, ResourceTypes: []string{resource}, Idempotent: true})
		}
		return s
	}
	providerName := "native-provider"
	if native != nil {
		providerName = "qualification_qemu"
	}
	vmType := typeSpec(providerName, "server", []string{"ensure_server", "destroy_server", capacity.VMObserveInventory, capacity.VMObserveAction})
	nodeType := typeSpec("kubernetes", "object", []string{capacity.ObserveNodeMembership})
	guestType := typeSpec("guest-bootstrap", "guest_bootstrap", []string{capacity.ObserveGuestBootstrap})
	guestType.Adapter.Endpoints = model.IntegrationAdapterRoute{Describe: "/rpc/describe", Execute: "/rpc/execute"}
	guestType.CredentialSchema.Required = []string{"ssh_private_key"}
	guestType.CredentialSchema.Properties = map[string]model.IntegrationSchemaProperty{"ssh_private_key": {Type: "string", Secret: true, Sensitive: true}}
	if native != nil {
		if err = json.Unmarshal(native.catalog.TypeSpec, &guestType); err != nil || manifest.ValidateIntegrationTypeSpec(guestType) != nil {
			t.Fatal("original private Guest catalog refused")
		}
	}
	serve := func(ts model.IntegrationTypeManifestSpec, isNode bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && r.URL.Path == "/nativehealth" {
				w.WriteHeader(200)
				return
			}
			if r.Method == http.MethodPost && r.URL.Path == "/describe" {
				_ = json.NewEncoder(w).Encode(ts)
				return
			}
			var req model.AdapterExecuteIntegrationRequest
			if r.Method != http.MethodPost || r.URL.Path != "/execute" || json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Auth) != 0 || len(req.Metadata) != 0 {
				t.Error("protocol source received a write/auth")
				w.WriteHeader(400)
				return
			}
			now := time.Now().UTC()
			var value any
			if isNode {
				copy := nodes
				copy.Nodes = append([]model.CapacityNodeMembershipTuple(nil), nodes.Nodes...)
				copy.ObservationStartedAt, copy.ObservedAt = now.Add(-time.Millisecond), now
				for i := range copy.Nodes {
					copy.Nodes[i].LeaseRenewedAt = now
				}
				value = copy
			} else {
				copy := inv
				copy.Members = append([]model.CapacityVMFleetInventoryMember(nil), inv.Members...)
				copy.ObservationStartedAt, copy.ObservedAt = now.Add(-time.Millisecond).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)
				for i := range copy.Members {
					copy.Members[i].Server.ObservedAt = copy.ObservedAt
				}
				value = copy
			}
			if mode, _ := f.mode.Load().(string); mode == "empty_source" {
				if isNode {
					copy := value.(model.CapacityNodeMembershipResponse)
					copy.Nodes = nil
					copy.NativeNodeCount = 0
					value = copy
				} else {
					copy := value.(model.CapacityVMFleetInventory)
					copy.Members = nil
					copy.MissingSlots = []int{1, 2, 3, 4}
					value = copy
				}
			}
			if (isNode && req.Operation != capacity.ObserveNodeMembership) || (!isNode && req.Operation != capacity.VMObserveInventory) {
				t.Error("unexpected original protocol source operation")
				w.WriteHeader(400)
				return
			}
			_ = json.NewEncoder(w).Encode(model.AdapterExecuteIntegrationResponse{Operation: req.Operation, Capability: req.Capability, Status: "observed", Output: value})
		}))
	}
	vmServer, nodeServer := serve(vmType, false), serve(nodeType, true)
	t.Cleanup(vmServer.Close)
	t.Cleanup(nodeServer.Close)
	var results map[string]model.CapacityGuestBootstrapResult
	token, ssh := strings.Repeat("g", 32), "private-fixture-SSH-key"
	guestServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if native != nil {
			native.proxy(w, r, f)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+token || r.Header.Get("X-Capacity-Canary-Read-Key") != "" {
			t.Error("original private Guest header absent")
			w.WriteHeader(401)
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/healthz" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		if r.Method == http.MethodPost && r.URL.Path == "/rpc/describe" {
			f.describeReads.Add(1)
			_ = json.NewEncoder(w).Encode(guestType)
			return
		}
		var req struct {
			Operation   string            `json:"operation"`
			Capability  string            `json:"capability"`
			Input       map[string]any    `json:"input"`
			Auth        map[string]string `json:"auth"`
			Integration struct {
				Type         model.ManifestReference `json:"type"`
				TypeSpec     json.RawMessage         `json:"type_spec"`
				Instance     model.ManifestReference `json:"instance"`
				InstanceSpec json.RawMessage         `json:"instance_spec"`
			} `json:"integration"`
		}
		if r.Method != http.MethodPost || r.URL.Path != "/rpc/execute" || json.NewDecoder(r.Body).Decode(&req) != nil || req.Operation != capacity.ObserveGuestBootstrap || req.Capability != capacity.ObserveGuestBootstrap || len(req.Input) != 1 || len(req.Auth) != 1 || req.Auth["ssh_private_key"] != ssh || bytes.Contains(req.Integration.InstanceSpec, []byte(ssh)) || bytes.Contains(req.Integration.TypeSpec, []byte(token)) {
			t.Error("public spec and private Auth conflated")
			w.WriteHeader(400)
			return
		}
		f.guestReads.Add(1)
		name, _ := req.Input["binding_name"].(string)
		value, ok := results[name]
		if !ok {
			w.WriteHeader(409)
			return
		}
		mode, _ := f.mode.Load().(string)
		if mode == "missing_second" && value.Observation.Journal.Tuple.Slot == 2 {
			w.WriteHeader(409)
			return
		}
		if mode == "token_rotation" {
			if _, e := repository.RotateManagedSecret(f.ctx, db, model.RotateManagedSecretRequest{Namespace: ns, Name: "guest-read", Data: map[string]string{"value": token}}); e != nil {
				t.Error(e)
			}
		}
		if mode == "catalog_pause" {
			if _, e := db.ExecContext(f.ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, f.guestInstance.ID); e != nil {
				t.Error(e)
			}
		}
		value.Observation.ObservedAt = time.Now().UTC()
		raw, e := json.Marshal(map[string]any{"operation": capacity.ObserveGuestBootstrap, "capability": capacity.ObserveGuestBootstrap, "status": "observed", "output": value, "metadata": map[string]any{}})
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		if mode == "alias" {
			raw = []byte(strings.Replace(string(raw), `"original_context_failed":false`, `"original_context_failed":true,"Original_Context_Failed":false`, 1))
		}
		_, _ = w.Write(raw)
	}))
	t.Cleanup(guestServer.Close)
	// Only this remote test owns the TLS root for its real httptest endpoint.
	originalTransport := http.DefaultTransport
	http.DefaultTransport = guestServer.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	create := func(id uuid.UUID, kind, name string, spec any) model.Manifest {
		t.Helper()
		raw, e := json.Marshal(spec)
		if e != nil {
			t.Fatal(e)
		}
		sum := fmt.Sprintf("%x", sha256.Sum256(raw))
		if _, e = db.ExecContext(f.ctx, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,active,spec,checksum) VALUES($1,'yggdrasil.io/v1alpha1',$2,$3,$4,1,true,$5::jsonb,$6)`, id, kind, ns, name, raw, sum); e != nil {
			t.Fatal(e)
		}
		m, e := repository.GetManifestByID(f.ctx, db, id)
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	vmTy := create(uuid.MustParse(b.IntegrationTypeID), "integration_type", "provider-type", vmType)
	vm := create(uuid.MustParse(b.IntegrationInstanceID), "integration_instance", "provider", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: b.IntegrationTypeID}, Status: "active", Config: map[string]any{"base_url": vmServer.URL}})
	nodeTy := create(uuid.MustParse(p.VMNodeMembershipBinding.Adapter.IntegrationTypeID), "integration_type", "node-type", nodeType)
	node := create(uuid.MustParse(p.VMNodeMembershipBinding.Adapter.IntegrationInstanceID), "integration_instance", "nodes", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: nodeTy.ID.String()}, Status: "active", Config: map[string]any{"base_url": nodeServer.URL}})
	b.IntegrationChecksum, b.IntegrationTypeChecksum = vm.Checksum, vmTy.Checksum
	p.MutationBindings = []model.CapacityMutationBinding{b}
	p.VMNodeMembershipBinding.Adapter.InstanceChecksum, p.VMNodeMembershipBinding.Adapter.TypeChecksum = node.Checksum, nodeTy.Checksum
	var guestSpec any = guestType
	if native != nil {
		guestSpec = native.catalog.TypeSpec
	}
	guestTy := create(uuid.New(), "integration_type", "guest-type", guestSpec)
	guestInstance := create(uuid.New(), "integration_instance", "guest", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: guestTy.ID.String()}, Status: "active", CredentialsRef: "secret://" + ns + "/guest-ssh", Config: map[string]any{"base_url": guestServer.URL}})
	f.guestType, f.guestInstance = guestTy, guestInstance
	if native != nil {
		native.prepareAndAwait(t, b, p, inv.Members[0], guestTy, guestInstance, guestServer.URL)
		executor, _ := f.ctx.Value(capacityInvocationKey{}).(string)
		f.ctx = context.WithValue(native.ctx, capacityInvocationKey{}, executor)
		token, ssh = native.runtime.RPCBearer, native.runtime.SSHPrivateKey
		nodes.Nodes[0].BootID = native.binding.Enrollment.Statement.BootID
		for i := range b.Slots {
			b.Slots[i].DesiredSpec.BootstrapSHA256 = native.binding.UserDataSHA256
			raw := capacityVMNodeProtocolCanonicalSpec(t, b.Slots[i].DesiredSpec)
			b.Slots[i].DesiredSpecSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
		}
		p.MutationBindings = []model.CapacityMutationBinding{b}
		inv.Members[0].DesiredSpec = *b.Slots[0].DesiredSpec
		inv.Members[0].RequestSHA256 = b.Slots[0].DesiredSpecSHA256
	}
	var e error
	f.tokenSecret, e = repository.UpsertManagedSecret(f.ctx, db, model.UpsertManagedSecretRequest{Namespace: ns, Name: "guest-read", Status: "active", Data: map[string]string{"value": token}})
	if e != nil {
		t.Fatal(e)
	}
	f.sshSecret, e = repository.UpsertManagedSecret(f.ctx, db, model.UpsertManagedSecretRequest{Namespace: ns, Name: "guest-ssh", Status: "active", Data: map[string]string{"ssh_private_key": ssh}})
	if e != nil {
		t.Fatal(e)
	}
	g := &model.CapacityGuestBootstrapBinding{Mode: capacity.GuestBootstrapSchema, Adapter: model.CapacityObservationAdapterBinding{IntegrationInstanceID: guestInstance.ID.String(), InstanceChecksum: guestInstance.Checksum, IntegrationTypeID: guestTy.ID.String(), TypeChecksum: guestTy.Checksum}, BaseURL: guestServer.URL, ReadTokenRef: "secret://" + ns + "/guest-read#value", MaxEvidenceAgeSeconds: 30, EvidenceClass: "native_qemu_qualification"}
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	results = map[string]model.CapacityGuestBootstrapResult{}
	for i, vm := range inv.Members {
		if native != nil {
			continue
		}
		now := time.Now().UTC()
		source := strings.Repeat("a", 40)
		enrollment := model.CapacityGuestEnrollmentStatement{Schema: "original_guest_enrollment_v1", SourceClass: g.EvidenceClass, ProvisionerSourceCommit: source, OriginalNativeResultSHA256: strings.Repeat("a", 64), BindingName: fmt.Sprintf("guest-%d", vm.Slot), Tuple: model.CapacityGuestNativeTuple{Provider: "native-provider", InstanceID: b.IntegrationInstanceID, InstanceChecksum: b.IntegrationChecksum, TypeID: b.IntegrationTypeID, TypeChecksum: b.IntegrationTypeChecksum, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: vm.DesiredSpec.ProfileChecksum, Profile: b.ProfileName, Slot: vm.Slot, ResourceID: vm.Server.ID, CreatedAt: vm.Server.CreatedAt}, BootID: nodes.Nodes[i].BootID, HostKeySHA256: strings.Repeat("1", 64), CredentialPublicKeySHA256: strings.Repeat("2", 64), ForcedReaderCommandSHA256: strings.Repeat("3", 64), UserDataSHA256: vm.DesiredSpec.BootstrapSHA256, PayloadSHA256: strings.Repeat("4", 64), OwnerBinarySHA256: strings.Repeat("5", 64), ReaderBinarySHA256: strings.Repeat("6", 64), GuestSourceCommit: source, IssuedAt: now.Add(-time.Minute)}
		raw, _ := json.Marshal(enrollment)
		g.Members = append(g.Members, model.CapacityGuestMemberBinding{Name: enrollment.BindingName, EnrollmentIssuerKey: base64.StdEncoding.EncodeToString(pub), Enrollment: enrollment, EnrollmentSignature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))})
		started, waited, prepared := now.Add(-3*time.Second), now.Add(-2*time.Second), now.Add(-time.Second)
		zero := 0
		unit := model.CapacityGuestUnitObservation{InvocationID: strings.Repeat("b", 32), MainPID: 100, ExecMainPID: 100, StartMonotonic: 1000, ActiveState: "activating", SubState: "start", Result: "success"}
		journal := model.CapacityGuestJournal{Schema: capacity.GuestBootstrapSchema, AdmissionProtocol: "original_guest_bootstrap_prestarter_v1", InvocationNonce: uuid.NewString(), State: "returned", BootID: enrollment.BootID, Tuple: enrollment.Tuple, UserDataSHA256: enrollment.UserDataSHA256, PayloadSHA256: enrollment.PayloadSHA256, OwnerSourceCommit: source, OwnerBinarySHA256: enrollment.OwnerBinarySHA256, OwnerPID: 101, OwnerStartTicks: 100, ParentAncestry: []int{100, 1}, UnitAtAdmission: unit, PossibleStartAt: now.Add(-4 * time.Second), ChildPID: 102, ChildStartTicks: 200, StartedAt: &started, OriginalWaitReturnedAt: &waited, ExitCode: &zero, FinalRecordPreparedAt: &prepared}
		raw, _ = json.Marshal(journal)
		unit.MainPID, unit.ExecMainCode, unit.ExitMonotonic, unit.ActiveState, unit.SubState = 0, 1, 2000, "inactive", "dead"
		observation := model.CapacityGuestObservation{Schema: capacity.GuestBootstrapSchema, ReaderSourceCommit: source, ReaderBinarySHA256: enrollment.ReaderBinarySHA256, ReaderPID: 103, ReaderStartTicks: 300, BootID: enrollment.BootID, UserDataSHA256: enrollment.UserDataSHA256, Journal: journal, JournalSHA256: capacity.BusinessCreationSHA256(raw), Unit: unit, CloudInitStatus: "done", CloudInitFinalFinished: float64(now.Add(-time.Second).Unix()), ObservedAt: now}
		results[enrollment.BindingName] = model.CapacityGuestBootstrapResult{BindingName: enrollment.BindingName, EnrollmentSourceClass: g.EvidenceClass, Observation: observation, OriginalPayloadReturnObserved: true, BootstrapCompletedKnown: true}
	}
	p.GuestBootstrapBinding = g
	if native != nil {
		enrollment := native.binding.Enrollment
		g.Members = []model.CapacityGuestMemberBinding{{Name: native.binding.Name, EnrollmentIssuerKey: native.binding.EnrollmentAuthorityPublicKey, Enrollment: enrollment.Statement, EnrollmentSignature: enrollment.Signature}}
	}
	if initialMode == "missing_enrollment" {
		p.GuestBootstrapBinding.Members = p.GuestBootstrapBinding.Members[:1]
	}
	if initialMode == "enrolled_extra" {
		extra := g.Members[0]
		extra.Name = "guest-103"
		extra.Enrollment.BindingName = extra.Name
		extra.Enrollment.Tuple.Slot = 3
		extra.Enrollment.Tuple.ResourceID = "103"
		extra.Enrollment.BootID = uuid.NewString()
		raw, _ := json.Marshal(extra.Enrollment)
		extra.EnrollmentSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))
		g.Members = append(g.Members, extra)
	}
	f.wf = create(uuid.New(), "workflow", p.Workflow.Name, model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: ns, Name: "scope"}}, Steps: []model.WorkflowStepSpec{{ID: "join", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.observe_vm_node_membership"}}}})
	f.policy = create(uuid.New(), "capacity_policy", "workers", p)
	f.p = p
	f.input = map[string]any{"policy": map[string]any{"namespace": ns, "name": "workers"}, "binding_name": b.Name}
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: f.wf.ID}
	store.ExecutorID, _ = f.ctx.Value(capacityInvocationKey{}).(string)
	now := time.Now().UTC()
	load := .9
	assessment := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: "fleet", ResourceVersion: "1", WorkloadUID: "workers", WorkloadResourceVersion: "1", Owner: p.Owner, Profile: b.ProfileName, Units: len(inv.Members), ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "load", SourceIdentity: "prom/load", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &load, RangeMin: &load, RangeMax: &load, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	f.lease, e = store.Assess(f.ctx, f.policy, assessment)
	if e != nil {
		t.Fatal(e)
	}
	f.lease, e = store.Claim(f.ctx, f.policy, f.lease.Generation, assessment)
	if e != nil {
		t.Fatal(e)
	}
	proofs, e := capacity.VMInventoryProofs(p, b, inv, "", 0, time.Now().UTC(), "fixture:protocol-selected")
	if e != nil {
		t.Fatal(e)
	}
	for _, proof := range proofs {
		raw := capacityVMNodeProtocolCanonicalSpec(t, b.Slots[proof.Slot-1].DesiredSpec)
		if e = store.RecordMutationSlot(f.ctx, f.policy, f.lease.Generation, f.lease.FencingToken, f.lease.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw}, proof); e != nil {
			t.Fatal(e)
		}
	}
	return f
}

func (f *capacityGuestProtocolPostgres) run(ctx context.Context) model.WorkflowRunStepResult {
	return executeCapacityNativeWorkflowStep(ctx, nil, f.db, manifestReferenceFromRecord(f.wf), model.WorkflowRunStepResult{Operation: "capacity.observe_vm_node_membership"}, f.input)
}

func (f *capacityGuestProtocolPostgres) ledger(t *testing.T) string {
	t.Helper()
	var out strings.Builder
	for _, table := range []string{"capacity_intents", "capacity_resource_slots", "capacity_mutation_grants", "capacity_intent_events"} {
		var value string
		if err := f.db.QueryRowContext(f.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text)::text,'[]') FROM public.`+table+` AS x WHERE namespace=$1`, f.policy.Metadata.Namespace).Scan(&value); err != nil {
			t.Fatal(err)
		}
		out.WriteString(value)
	}
	return out.String()
}

func TestCapacityGuestCollectorProtocolPostgres(t *testing.T) {
	if os.Getenv("DB_URL") == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("remote PostgreSQL Guest consumer gate required")
		}
		t.Skip("remote PostgreSQL Guest consumer gate")
	}
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	t.Setenv("YGGDRASIL_CAPACITY_GUEST_BOOTSTRAP_ENABLED", "true")
	for _, mode := range []string{"full_selected_roster_scoped", "missing_second", "alias", "token_rotation", "catalog_pause", "process_off", "expired_lease", "foreign_executor", "preflight_catalog_before_secret", "denied_dispatch_fence", "fresh_describe_even_cached", "missing_enrollment", "enrolled_extra", "empty_source"} {
		t.Run(mode, func(t *testing.T) {
			f := newCapacityGuestProtocolPostgres(t, mode, nil)
			if mode == "process_off" {
				t.Setenv("YGGDRASIL_CAPACITY_GUEST_BOOTSTRAP_ENABLED", "false")
			}
			if mode == "expired_lease" {
				if _, err := f.db.ExecContext(f.ctx, `UPDATE public.capacity_intents SET intent=jsonb_set(intent,'{lease_expires_at}',to_jsonb(clock_timestamp()-INTERVAL '1 second')) WHERE namespace=$1`, f.policy.Metadata.Namespace); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "preflight_catalog_before_secret" {
				if _, err := f.db.ExecContext(f.ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, f.guestType.ID); err != nil {
					t.Fatal(err)
				}
			}
			before := f.ledger(t)
			ctx := f.ctx
			if mode == "foreign_executor" {
				ctx = newCapacityInvocationContext(t.Context())
			}
			if mode == "denied_dispatch_fence" {
				ctx = WithCapacityDispatchFence(ctx, func(context.Context) error { return guestNativePrivateCause("private-current-rbac-denied") })
			}
			if mode == "fresh_describe_even_cached" {
				first := f.run(ctx)
				if first.Status != "succeeded" {
					t.Fatal("initial native read failed", first.Error)
				}
				f.describeReads.Store(0)
				f.guestReads.Store(0)
			}
			got := f.run(ctx)
			positive := mode == "full_selected_roster_scoped" || mode == "fresh_describe_even_cached"
			if positive {
				if got.Status != "succeeded" || got.Metadata["original_guest_roster_observed"] != true || f.guestReads.Load() != 2 || got.Metadata["bootstrap_completed_known"] != false || got.Metadata["physical_guest_certificate"] != false || got.Metadata["useful_capacity_known"] != false || f.describeReads.Load() != 1 {
					t.Fatal("actual collector failed complete scoped roster", got.Error, f.guestReads.Load(), f.describeReads.Load())
				}
			} else if got.Status == "succeeded" || got.Metadata != nil {
				t.Fatal("unknown/partial/current authority accepted", mode, got.Status)
			}
			if before != f.ledger(t) {
				t.Fatal("original observer changed capacity ledger", mode)
			}
			if (mode == "process_off" || mode == "expired_lease" || mode == "foreign_executor" || mode == "preflight_catalog_before_secret" || mode == "denied_dispatch_fence") && f.guestReads.Load() != 0 {
				t.Fatal("refusal reached original Guest read", mode)
			}
			raw, _ := json.Marshal(got)
			if bytes.Contains(raw, []byte("private-fixture-SSH-key")) || bytes.Contains(raw, []byte(strings.Repeat("g", 32))) || bytes.Contains(raw, []byte("private-current-rbac-denied")) {
				t.Fatal("private Auth/cause leaked into result")
			}
		})
	}
}

func capacityNativeFixture(t *testing.T, input any) map[string]any {
	return capacitySourceFixture(t, "CAPACITY_NATIVE_FIXTURE_BINARY", "TestCapacityCoreNativeFixtureProducer", input)
}

func capacitySourceFixture(t *testing.T, binaryEnv, rootTest string, input any) map[string]any {
	t.Helper()
	binary := os.Getenv(binaryEnv)
	if binary == "" {
		t.Fatal("remote real-adapter fixture binary is required")
	}
	dir := t.TempDir()
	in, out := filepath.Join(dir, "input.json"), filepath.Join(dir, "output.json")
	raw, err := json.Marshal(input)
	if err != nil || os.WriteFile(in, raw, 0600) != nil {
		t.Fatal("fixture input could not be written", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^"+rootTest+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), "CAPACITY_NATIVE_INPUT_FILE="+in, "CAPACITY_NATIVE_OUTPUT_FILE="+out)
	if logs, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("reviewed native fixture producer failed: %v %s", err, logs)
	}
	raw, err = os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

// The native SDK is a separately compiled exact-source fixture, not a fake
// capability registry. The protected operation performs actual HTTP transport,
// Describe verification and durable PostgreSQL authority checks.
func TestCapacityMutationNativeWorkflowPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("capacity native PostgreSQL gate requires DB_URL")
		}
		t.Skip("remote PostgreSQL native bridge gate")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	ctx := newCapacityInvocationContext(context.Background())
	ns := "capacity-native-" + uuid.NewString()
	t.Cleanup(func() {
		for _, table := range []string{"event_log", "capacity_mutation_grants", "capacity_resource_slots", "capacity_intent_events", "capacity_intents", "manifests"} {
			query := `DELETE FROM public.` + table + ` WHERE namespace=$1`
			if table == "event_log" {
				query = `DELETE FROM public.event_log WHERE metadata->>'namespace'=$1`
			}
			if _, err := db.ExecContext(context.Background(), query, ns); err != nil {
				t.Error(err)
			}
		}
		db.Close()
	})
	iid, tid := uuid.New(), uuid.New()
	seed := capacityNativeFixture(t, map[string]any{"mode": "seed", "instance_id": iid.String(), "type_id": tid.String()})
	var typeSpec model.IntegrationTypeManifestSpec
	var describe model.AdapterDescribeResponse
	seedRaw, _ := json.Marshal(seed["describe"])
	if err := json.Unmarshal(seedRaw, &typeSpec); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(seedRaw, &describe); err != nil {
		t.Fatal(err)
	}
	// Only the IO route changes for the local CI fixture. Every action/resource,
	// schema and version is copied from the reviewed real Describe producer.
	typeSpec.Adapter.Transport = "http_json"
	typeSpec.Adapter.Queues = model.IntegrationAdapterQueue{}
	typeSpec.Adapter.Endpoints = model.IntegrationAdapterRoute{Describe: "/describe", Execute: "/execute"}
	// HTTP transport requires its fixed operator URL to be schema-declared.
	// This IO-only property does not alter any native action or fleet config.
	typeSpec.InstanceSchema.Properties["base_url"] = model.IntegrationSchemaProperty{Type: "string"}
	describe.Adapter, describe.InstanceSchema = typeSpec.Adapter, typeSpec.InstanceSchema
	if err = manifest.ValidateIntegrationTypeSpec(typeSpec); err != nil {
		t.Fatal("real Describe fixture must be registration-valid", err)
	}
	var members []map[string]any
	baselineCreated := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	for slot := 1; slot <= 2; slot++ {
		members = append(members, map[string]any{"slot": slot, "id": 100 + slot, "created_at": baselineCreated, "grant_id": uuid.NewString()})
	}
	mode := "inventory"
	var receipt model.CapacityMutationReceipt
	nativeCreated := ""
	rpcCalls, describeCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/describe" {
			describeCalls++
			json.NewEncoder(w).Encode(describe)
			return
		}
		if r.URL.Path != "/execute" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		rpcCalls++
		var request model.AdapterExecuteIntegrationRequest
		if json.NewDecoder(r.Body).Decode(&request) != nil || !strings.HasPrefix(request.Operation, "observe_") || request.Capability != request.Operation || len(request.Auth) != 0 || len(request.Metadata) != 0 {
			t.Error("protected observer widened its native request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		value := capacityNativeFixture(t, map[string]any{"mode": mode, "request": request, "receipt": receipt, "members": members, "native_created_at": nativeCreated})
		if value["error"] != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		json.NewEncoder(w).Encode(value)
	}))
	t.Cleanup(server.Close)
	create := func(id uuid.UUID, kind, name string, spec any) model.Manifest {
		t.Helper()
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		checksum := fmt.Sprintf("%x", sha256.Sum256(raw))
		// Explicit UUIDs let the separate native fixture bind the exact stored
		// manifest-version identity. No fake stable logical identity is added.
		if _, err = db.ExecContext(ctx, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,active,spec,checksum) VALUES($1,'yggdrasil.io/v1alpha1',$2,$3,$4,1,true,$5::jsonb,$6)`, id, kind, ns, name, raw, checksum); err != nil {
			t.Fatal(err)
		}
		m, err := repository.GetManifestByID(ctx, db, id)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	ty := create(tid, "integration_type", "native-vm-type", typeSpec)
	config := seed["config"].(map[string]any)
	config["base_url"] = server.URL
	instance := create(iid, "integration_instance", "native-vm", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: tid.String()}, Status: "active", Config: config, Credentials: seed["credentials"].(map[string]any)})
	wf := create(uuid.New(), "workflow", "native-scale", model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: ns, Name: "capacity-rbac"}}, Steps: []model.WorkflowStepSpec{{ID: "inventory", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.observe_vm_inventory"}}}})
	ref := manifestReferenceFromRecord(wf)
	var slots []model.CapacityMutationSlotBinding
	raw, _ := json.Marshal(seed["slots"])
	if err = json.Unmarshal(raw, &slots); err != nil || len(slots) != 4 {
		t.Fatal("native approved projections absent", err)
	}
	b := model.CapacityMutationBinding{Name: "native-vm", IntegrationInstanceID: iid.String(), IntegrationChecksum: instance.Checksum, IntegrationTypeID: tid.String(), IntegrationTypeChecksum: ty.Checksum, AdapterPrincipalID: "fleet-adapter", ScopeChecksum: slots[0].DesiredSpec.ScopeChecksum, ProfileName: "workers", EnsureCapability: "ensure_server", DestroyCapability: "destroy_server", ProtectedSlots: 1, MaxSlots: 4, Slots: slots}
	now := time.Now().UTC()
	p := model.CapacityPolicySpec{Environment: "production", Domain: "vm-workers", Dimension: "nodes", TargetIdentity: "fleet/native-vm", Owner: "capacity-native", Workflow: model.ManifestSelector{Namespace: ns, Name: wf.Metadata.Name}, Currency: "EUR", Floor: 1, Ceiling: 4, Step: 2, MaxEvidenceAgeSeconds: 60, MaxSampleGapSeconds: 30, MinSamples: 3, DownHoldSeconds: 60, LeaseSeconds: 120, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "load", SourceIdentity: "prom/queue", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, Profiles: []model.CapacityProfile{{Name: "workers", Provider: "hetzner", Region: "nbg1", MinUnits: 1, MaxUnits: 4, UnitMonthlyCostMinor: 100, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:capacity-qualification-is-separate"}}, MutationBindings: []model.CapacityMutationBinding{b}}
	policy := create(uuid.New(), "capacity_policy", "workers", p)
	executor, _ := ctx.Value(capacityInvocationKey{}).(string)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID, ExecutorID: executor}
	input := func() map[string]any {
		return map[string]any{"policy": map[string]any{"namespace": ns, "name": "workers"}, "binding_name": b.Name}
	}
	run := func(c context.Context, op string, value map[string]any) model.WorkflowRunStepResult {
		return executeCapacityNativeWorkflowStep(c, nil, db, ref, model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: op, Status: "failed"}, value)
	}
	count := func() int {
		var n int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1`, ns).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	t.Run("readonly_real_adapter_inventory_has_no_authority", func(t *testing.T) {
		t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "false")
		got := run(ctx, "capacity.observe_vm_inventory", input())
		if got.Status != "succeeded" || got.Metadata["native_members"] != float64(2) || got.Metadata["useful_capacity_known"] != false || got.Metadata["registered"] != float64(0) || count() != 0 {
			t.Fatalf("read-only source became authority: %+v", got)
		}
	})
	t.Run("caller_scope_proof_and_unprotected_workflow_are_refused", func(t *testing.T) {
		before := rpcCalls
		for _, field := range []string{"proof", "complete", "warm_ready", "integration", "capability", "owner", "url"} {
			value := input()
			value[field] = true
			if run(ctx, "capacity.observe_vm_inventory", value).Status == "succeeded" {
				t.Fatal("caller assertion accepted", field)
			}
		}
		wrong := ref
		wrong.ID = uuid.New()
		got := executeCapacityNativeWorkflowStep(ctx, nil, db, wrong, model.WorkflowRunStepResult{Kind: "yggdrasil", Operation: "capacity.observe_vm_inventory", Status: "failed"}, input())
		if got.Status == "succeeded" || rpcCalls != before {
			t.Fatal("wrong protected workflow reached adapter")
		}
	})
	t.Run("native_collision_refuses_entire_inventory", func(t *testing.T) {
		mode = "collision"
		defer func() { mode = "inventory" }()
		if run(ctx, "capacity.observe_vm_inventory", input()).Status == "succeeded" || count() != 0 {
			t.Fatal("native drift gained coverage")
		}
	})
	load := .9
	a := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: "fleet-uid", ResourceVersion: "1", WorkloadUID: "workers-uid", WorkloadResourceVersion: "1", Owner: p.Owner, Profile: b.ProfileName, Units: 2, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "load", SourceIdentity: "prom/queue", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &load, RangeMin: &load, RangeMax: &load, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	intent, err := store.Assess(ctx, policy, a)
	if err != nil {
		t.Fatal(err)
	}
	intent, err = store.Claim(ctx, policy, intent.Generation, a)
	if err != nil {
		t.Fatal(err)
	}
	leased := func() map[string]any {
		v := input()
		v["generation"], v["fencing_token"], v["lease_owner"] = intent.Generation, intent.FencingToken, intent.LeaseOwner
		return v
	}
	t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", "true")
	t.Run("complete_inventory_registers_through_existing_lease", func(t *testing.T) {
		got := run(ctx, "capacity.record_vm_inventory", leased())
		if got.Status != "succeeded" || got.Metadata["registered"] != float64(2) || count() != 2 {
			t.Fatalf("registration failed: %+v", got)
		}
		before := rpcCalls
		if run(newCapacityInvocationContext(context.Background()), "capacity.record_vm_inventory", leased()).Status == "succeeded" || rpcCalls != before {
			t.Fatal("another invocation borrowed native registration lease")
		}
	})
	issue := func(slot int) model.CapacityMutationGrant {
		raw, _ := json.Marshal(slots[slot-1].DesiredSpec)
		g, e := store.IssueMutation(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw})
		if e != nil {
			t.Fatal(e)
		}
		return g
	}
	settle := func(g model.CapacityMutationGrant, known bool) {
		nonce := strings.Repeat("a", 64)
		sum := sha256.Sum256([]byte(nonce))
		r := model.CapacityMutationRedeemRequest{GrantID: g.GrantID, AttemptID: uuid.NewString(), SettlementTokenSHA256: fmt.Sprintf("%x", sum), Capability: g.Capability, IntegrationInstanceID: g.IntegrationInstanceID, ScopeChecksum: g.ScopeChecksum, ProfileName: g.ProfileName, Slot: g.Slot, RequestSHA256: g.RequestSHA256}
		reply, e := store.RedeemMutation(ctx, b.AdapterPrincipalID, r)
		if e != nil || reply.Mode != "write_once" {
			t.Fatal("fixture redemption failed", e, reply)
		}
		nativeCreated = time.Now().UTC().Format(time.RFC3339Nano)
		s := model.CapacityMutationSettleRequest{GrantID: g.GrantID, AttemptID: r.AttemptID, RequestSHA256: g.RequestSHA256, Outcome: "uncertain", TransportCompleted: true, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		if known {
			s.Outcome = "accepted"
			s.ResourceID = "100"
			s.ResourceCreatedAt = nativeCreated
			s.ActionID = "500"
			s.AuxiliaryInventoryComplete = true
			s.AuxiliaryResources = []model.CapacityMutationAuxiliaryResource{{Kind: "primary_ip", ID: "101", RequiresAbsence: true}}
		}
		if _, e = store.SettleMutation(ctx, b.AdapterPrincipalID, nonce, s); e != nil {
			t.Fatal(e)
		}
		receipt, e = store.NativeMutationReceipt(ctx, policy, b, g.GrantID)
		if e != nil {
			t.Fatal(e)
		}
	}
	t.Run("native_reads_confirm_once_without_readiness_claim", func(t *testing.T) {
		g := issue(3)
		settle(g, true)
		mode = "confirm"
		v := leased()
		v["grant_id"] = g.GrantID
		got := run(ctx, "capacity.confirm_native_mutation", v)
		if got.Status != "succeeded" || count() != 3 || got.Metadata["useful_capacity_known"] != false {
			t.Fatalf("native confirmation failed: %+v", got)
		}
		receipt, err = store.NativeMutationReceipt(ctx, policy, b, g.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		if got = run(ctx, "capacity.confirm_native_mutation", v); got.Status != "succeeded" {
			t.Fatalf("readback replay failed: %+v", got)
		}
		var events int
		if err = db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE metadata->>'namespace'=$1`, ns).Scan(&events); err != nil || events != 1 {
			t.Fatal("native confirmation duplicated/missed canonical effect", events, err)
		}
		members = append(members, map[string]any{"slot": 3, "id": 100, "created_at": nativeCreated, "grant_id": g.GrantID})
	})
	t.Run("lost_failed_creation_is_explicit_unresolved_member", func(t *testing.T) {
		g := issue(4)
		settle(g, false)
		mode = "failed"
		v := input()
		v["parent_grant_id"], v["slot"] = g.GrantID, 4
		got := run(ctx, "capacity.observe_failed_vm_creation", v)
		if got.Status != "succeeded" {
			t.Fatalf("lost failed native readback failed: %+v", got)
		}
		raw, _ := json.Marshal(got.Metadata["mutation_proof"])
		var proof model.CapacityMutationProof
		json.Unmarshal(raw, &proof)
		if proof.ResourceID != "104" || proof.SpecVerified || !proof.CompensationIdentityVerified || !proof.ActionHistoryComplete || !proof.ActionsFailed || count() != 3 {
			t.Fatal("failed lifetime became physical/registered capacity", proof)
		}
		mode = "failed_inventory"
		got = run(ctx, "capacity.observe_vm_inventory", v)
		if got.Status != "succeeded" || got.Metadata["native_members"] != float64(4) || len(got.Metadata["mutation_proofs"].([]any)) != 3 || count() != 3 {
			t.Fatalf("unresolved member was dropped or counted as registered: %+v", got)
		}
		v = leased()
		v["parent_grant_id"], v["slot"] = g.GrantID, 4
		got = run(ctx, "capacity.record_vm_inventory", v)
		if got.Status != "succeeded" || got.Metadata["registered"] != float64(3) || count() != 3 {
			t.Fatalf("failed member altered serving ledger: %+v", got)
		}
		var state string
		if err = db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1`, g.GrantID).Scan(&state); err != nil || state != "settled" {
			t.Fatal("observer freed uncertain reserve", state, err)
		}
	})
	t.Run("paused_instance_and_old_type_refuse_current_reads", func(t *testing.T) {
		before := rpcCalls
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET active=false WHERE id=$1`, iid); err != nil {
			t.Fatal(err)
		}
		if run(ctx, "capacity.observe_vm_inventory", input()).Status == "succeeded" || rpcCalls != before {
			t.Fatal("paused exact instance reached native API")
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET active=true WHERE id=$1`, iid); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET checksum=$2 WHERE id=$1`, tid, strings.Repeat("0", 64)); err != nil {
			t.Fatal(err)
		}
		if run(ctx, "capacity.observe_vm_inventory", input()).Status == "succeeded" {
			t.Fatal("type revision drift accepted")
		}
	})
	t.Run("native_catalog_refuses_before_private_hydration", func(t *testing.T) {
		var bad model.IntegrationTypeManifestSpec
		raw, _ := json.Marshal(typeSpec)
		json.Unmarshal(raw, &bad)
		for i := range bad.ActionCatalog {
			if bad.ActionCatalog[i].Name == "observe_fleet_inventory" {
				bad.ActionCatalog[i].Category = "permission"
			}
		}
		typeRaw, _ := json.Marshal(bad)
		typeDigest := fmt.Sprintf("%x", sha256.Sum256(typeRaw))
		var spec model.IntegrationInstanceManifestSpec
		json.Unmarshal(instance.Spec, &spec)
		spec.CredentialsRef = "capacity-test://must-not-hydrate"
		instanceRaw, _ := json.Marshal(spec)
		instanceDigest := fmt.Sprintf("%x", sha256.Sum256(instanceRaw))
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET spec=$2::jsonb,checksum=$3 WHERE id=$1`, tid, typeRaw, typeDigest); err != nil {
			t.Fatal(err)
		}
		if _, err = db.ExecContext(ctx, `UPDATE public.manifests SET spec=$2::jsonb,checksum=$3,active=true WHERE id=$1`, iid, instanceRaw, instanceDigest); err != nil {
			t.Fatal(err)
		}
		var nativePolicy model.CapacityPolicySpec
		json.Unmarshal(policy.Spec, &nativePolicy)
		nativePolicy.MutationBindings[0].IntegrationChecksum = instanceDigest
		nativePolicy.MutationBindings[0].IntegrationTypeChecksum = typeDigest
		badPolicy := create(uuid.New(), "capacity_policy", "native-catalog-denied", nativePolicy)
		before, beforeDescribe := rpcCalls, describeCalls
		value := map[string]any{"policy": map[string]any{"namespace": ns, "name": badPolicy.Metadata.Name}, "binding_name": b.Name}
		if run(ctx, "capacity.observe_vm_inventory", value).Status == "succeeded" || rpcCalls != before || describeCalls != beforeDescribe {
			t.Fatal("native invalid capability reached private transport")
		}
	})
}

// The fixed typed slot DTO is encoded as a JSON object with sorted keys, as
// required by the production closed projection. Struct declaration order is
// not canonical request bytes and cannot authorize RecordMutationSlot.
func capacityVMNodeProtocolCanonicalSpec(t *testing.T, spec *model.CapacityMutationSpecV1) []byte {
	t.Helper()
	if spec == nil {
		t.Fatal("protocol fixture: typed slot spec absent")
	}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("protocol fixture: slot DTO encoding refused; cause_type=%T", err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("protocol fixture: slot object decoding refused; cause_type=%T", err)
	}
	canonical, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("protocol fixture: canonical slot encoding refused; cause_type=%T", err)
	}
	return canonical
}

// These Node/VM API identities are protocol fixtures. Only PostgreSQL and the
// Core HTTP dispatcher are actual native components in this source corpus.
func capacityVMNodeProtocolFixture(t *testing.T) (model.CapacityPolicySpec, model.CapacityMutationBinding, model.CapacityVMFleetInventory, model.CapacityNodeMembershipResponse) {
	t.Helper()
	now := time.Now().UTC()
	owner := "native-owner"
	b := model.CapacityMutationBinding{Name: "vm-nodes", IntegrationInstanceID: uuid.NewString(), IntegrationChecksum: strings.Repeat("a", 64), IntegrationTypeID: uuid.NewString(), IntegrationTypeChecksum: strings.Repeat("b", 64), AdapterPrincipalID: "fixture-adapter", ScopeChecksum: strings.Repeat("c", 64), ProfileName: "workers", EnsureCapability: "ensure_server", DestroyCapability: "destroy_server", ProtectedSlots: 1, MaxSlots: 4}
	p := model.CapacityPolicySpec{Environment: "production", Domain: "vm-node-source", Dimension: "nodes", TargetIdentity: "fleet/native", Owner: owner, Workflow: model.ManifestSelector{Namespace: "fixture", Name: "native-node-source"}, Currency: "EUR", Floor: 1, Ceiling: 4, Step: 1, MaxEvidenceAgeSeconds: 60, MinSamples: 3, MaxSampleGapSeconds: 30, DownHoldSeconds: 60, LeaseSeconds: 120, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "load", SourceIdentity: "prom/load", Unit: "ratio", UpAbove: .8, DownBelow: .3}}, Profiles: []model.CapacityProfile{{Name: "workers", Provider: "native-provider", Region: "fixed-region", MinUnits: 1, MaxUnits: 4, QuoteValidUntil: now.Add(time.Hour), ValidationValidUntil: now.Add(time.Hour), ValidationRef: "fixture:no-throughput-claim"}}}
	target := model.CapacityNodeMembershipTarget{BindingName: "workers", RealmUID: uuid.NewString(), Owner: owner, ProfileName: "workers", ProviderIDPrefix: "native://", MaxLeaseAgeSeconds: 60}
	label := func(s string) string {
		decoded, _ := hex.DecodeString(s)
		return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(decoded))
	}
	inv := model.CapacityVMFleetInventory{IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: strings.Repeat("d", 64), AdmissionChecksum: strings.Repeat("e", 64), ProfileName: b.ProfileName, ProtectedSlots: 1, MaxSlots: 4, Complete: true, ObservationStartedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ObservedAt: now.Format(time.RFC3339Nano), MissingSlots: []int{3, 4}}
	nodes := model.CapacityNodeMembershipResponse{Operation: capacity.ObserveNodeMembership, Status: "observed", BindingName: target.BindingName, RealmUID: target.RealmUID, Owner: owner, ProfileName: b.ProfileName, Complete: true, NativeNodeCount: 2, FirstListVersion: "11", LastListVersion: "12", FirstListSHA256: strings.Repeat("1", 64), LastListSHA256: strings.Repeat("2", 64), ObservationStartedAt: now.Add(-time.Second), ObservedAt: now, Metadata: map[string]any{"diagnostic_only": true}}
	for slot := 1; slot <= 4; slot++ {
		spec := &model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: b.EnsureCapability, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: inv.ProfileChecksum, AdmissionChecksum: inv.AdmissionChecksum, ProfileName: b.ProfileName, Slot: slot, NativeName: fmt.Sprintf("workers-%d", slot), BootstrapSHA256: strings.Repeat("f", 64)}
		raw := capacityVMNodeProtocolCanonicalSpec(t, spec)
		digest := fmt.Sprintf("%x", sha256.Sum256(raw))
		b.Slots = append(b.Slots, model.CapacityMutationSlotBinding{Slot: slot, DesiredSpecSHA256: digest, DesiredSpec: spec})
		target.Slots = append(target.Slots, model.CapacityNodeSlotBinding{Slot: slot, NodeName: fmt.Sprintf("node-%d", slot)})
		if slot > 2 {
			continue
		}
		server := model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: fmt.Sprint(100 + slot), CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano)}, Name: spec.NativeName, Status: "running", PhysicalSpecVerified: true, ObservedAt: inv.ObservedAt, Labels: map[string]string{"yggdrasil.io/owner": owner, "yggdrasil.io/scope": label(b.ScopeChecksum), "yggdrasil.io/spec": label(inv.ProfileChecksum), "yggdrasil.io/profile": b.ProfileName, "yggdrasil.io/slot": fmt.Sprint(slot)}}
		inv.Members = append(inv.Members, model.CapacityVMFleetInventoryMember{Slot: slot, Protected: slot == 1, DesiredSpec: *spec, RequestSHA256: digest, Server: server})
		nodes.Nodes = append(nodes.Nodes, model.CapacityNodeMembershipTuple{Slot: slot, Name: fmt.Sprintf("node-%d", slot), UID: uuid.NewString(), ResourceVersion: "12", CreatedAt: now.Add(-30 * time.Minute), ProviderID: target.ProviderIDPrefix + server.ID, BootID: uuid.NewString(), Ready: true, ReadyKnown: true, ReadyChangedAt: now.Add(-time.Minute), LeaseUID: uuid.NewString(), LeaseVersion: "13", LeaseHolder: fmt.Sprintf("node-%d", slot), LeaseDurationSeconds: 40, LeaseRenewedAt: now})
	}
	p.MutationBindings = []model.CapacityMutationBinding{b}
	p.VMNodeMembershipBinding = &model.CapacityVMNodeMembershipBinding{MutationBindingName: b.Name, Adapter: model.CapacityObservationAdapterBinding{IntegrationInstanceID: uuid.NewString(), InstanceChecksum: strings.Repeat("3", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("4", 64)}, Target: target}
	raw, _ := json.Marshal(target)
	nodes.BindingSHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	return p, b, inv, nodes
}

func TestCapacityVMNodeJoinRejectsForeignAndReadinessAuthority(t *testing.T) {
	p, _, inv, nodes := capacityVMNodeProtocolFixture(t)
	joins, err := capacity.JoinVMNodeMembership(p, inv, nodes, time.Now().UTC())
	if err != nil || len(joins) != 2 {
		t.Fatal("fixed primitive did not join", err)
	}
	for _, mode := range []string{"partial", "foreign_digest", "wrong_provider", "replacement_created", "missing_boot", "duplicate_uid", "stale_lease", "unknown_ready", "warm", "bootstrap", "atomic", "private_metadata", "unregistered_shape", "vm_off", "foreign_vm_owner", "missing_duration", "expired_duration", "overspan", "future_projection", "unordered_nodes"} {
		t.Run(mode, func(t *testing.T) {
			p, _, inv, nodes := capacityVMNodeProtocolFixture(t)
			switch mode {
			case "partial":
				nodes.Complete = false
			case "foreign_digest":
				nodes.BindingSHA256 = strings.Repeat("5", 64)
			case "wrong_provider":
				nodes.Nodes[0].ProviderID = "native://replacement"
			case "replacement_created":
				nodes.Nodes[0].CreatedAt = time.Now().Add(-2 * time.Hour)
			case "missing_boot":
				nodes.Nodes[0].BootID = ""
			case "duplicate_uid":
				nodes.Nodes[1].UID = nodes.Nodes[0].UID
			case "stale_lease":
				nodes.Nodes[0].LeaseRenewedAt = time.Now().Add(-2 * time.Minute)
			case "unknown_ready":
				nodes.Nodes[0].ReadyKnown = false
			case "warm":
				nodes.WarmResources = true
			case "bootstrap":
				nodes.BootstrapCompleted = true
			case "atomic":
				nodes.AtomicSnapshot = true
			case "private_metadata":
				nodes.Metadata["private-secret"] = "must-not-pass"
			case "unregistered_shape":
				nodes.Nodes = nodes.Nodes[:1]
			case "vm_off":
				inv.Members[0].Server.Status = "off"
			case "foreign_vm_owner":
				inv.Members[0].Server.Labels["yggdrasil.io/owner"] = "foreign"
			case "missing_duration":
				nodes.Nodes[0].LeaseDurationSeconds = 0
			case "expired_duration":
				nodes.Nodes[0].LeaseDurationSeconds = 1
				nodes.Nodes[0].LeaseRenewedAt = time.Now().Add(-2 * time.Second)
			case "overspan":
				nodes.ObservationStartedAt = time.Now().Add(-61 * time.Second)
			case "future_projection":
				nodes.ObservedAt = time.Now().Add(time.Second)
			case "unordered_nodes":
				nodes.Nodes[0], nodes.Nodes[1] = nodes.Nodes[1], nodes.Nodes[0]
			}
			if _, e := capacity.JoinVMNodeMembership(p, inv, nodes, time.Now().UTC()); e == nil {
				t.Fatal("unsafe native join admitted", mode)
			}
		})
	}
	nodes.Nodes[0].Ready = false
	if _, err = capacity.JoinVMNodeMembership(p, inv, nodes, time.Now().UTC()); err != nil {
		t.Fatal("known unhealthy point was mistaken for malformed evidence", err)
	}
}

func TestCapacityMutationVMNodeProtectedDispatcherPostgres(t *testing.T) {
	dsn := os.Getenv("DB_URL")
	if dsn == "" {
		if os.Getenv("REQUIRE_CAPACITY_POSTGRES") == "true" {
			t.Fatal("remote PostgreSQL gate required")
		}
		t.Skip("remote PostgreSQL protocol gate")
	}
	db, e := sql.Open("postgres", dsn)
	if e != nil {
		t.Fatal(e)
	}
	ctx := newCapacityInvocationContext(context.Background())
	ns := "node-membership-" + uuid.NewString()
	t.Cleanup(func() {
		for _, table := range []string{"capacity_mutation_grants", "capacity_resource_slots", "capacity_intent_events", "capacity_intents", "manifests"} {
			if _, e := db.ExecContext(context.Background(), `DELETE FROM public.`+table+` WHERE namespace=$1`, ns); e != nil {
				t.Error(e)
			}
		}
		db.Close()
	})
	p, b, inv, nodes := capacityVMNodeProtocolFixture(t)
	p.Workflow.Namespace = ns
	typeSpec := func(provider, resource string, ops []string) model.IntegrationTypeManifestSpec {
		ts := model.IntegrationTypeManifestSpec{Provider: provider, Domain: "infrastructure", Adapter: model.IntegrationAdapterSpec{Transport: "http_json", Version: "1.0.0", Endpoints: model.IntegrationAdapterRoute{Health: "/nativehealth", Describe: "/describe", Execute: "/execute"}, TimeoutSeconds: 65}, Capabilities: []string{"describe", "execute"}, CredentialSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{}}, InstanceSchema: model.IntegrationSchemaSpec{Mode: "inline", Properties: map[string]model.IntegrationSchemaProperty{"base_url": {Type: "string"}}}, ResourceTypes: []model.IntegrationResourceType{{Name: resource, CanonicalPrefix: "thirdparty." + provider + "." + resource, IdentityTemplate: resource + ".{id}", DefaultActions: ops}}}
		for _, op := range ops {
			ts.ActionCatalog = append(ts.ActionCatalog, model.IntegrationActionDefinition{Name: op, ResourceTypes: []string{resource}, Idempotent: true})
		}
		ts.Discovery = model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"}
		ts.Normalization = model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty." + provider + "." + resource}
		if e := manifest.ValidateIntegrationTypeSpec(ts); e != nil {
			t.Fatal("closed fixture catalog invalid", e)
		}
		return ts
	}
	vmType := typeSpec("native-provider", "server", []string{"ensure_server", "destroy_server", capacity.VMObserveInventory, capacity.VMObserveAction})
	nodeType := typeSpec("kubernetes", "object", []string{capacity.ObserveNodeMembership})
	var mu sync.Mutex
	healthReads, describeReads, reads, writes := 0, 0, 0, 0
	changed := false
	var lateOwner *capacityVMNodeAbsoluteContext
	serve := func(ts model.IntegrationTypeManifestSpec, isNode bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			if r.Method == http.MethodGet && r.URL.Path == "/nativehealth" {
				healthReads++
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == http.MethodPost && r.URL.Path == "/describe" {
				describeReads++
				raw, _ := json.Marshal(ts)
				var desc model.AdapterDescribeResponse
				_ = json.Unmarshal(raw, &desc)
				_ = json.NewEncoder(w).Encode(desc)
				return
			}
			if r.URL.Path != "/execute" {
				writes++
				w.WriteHeader(404)
				return
			}
			var req model.AdapterExecuteIntegrationRequest
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil || !strings.HasPrefix(req.Operation, "observe_") || req.Capability != req.Operation || len(req.Auth) != 0 || len(req.Metadata) != 0 {
				writes++
				w.WriteHeader(400)
				return
			}
			reads++
			now := time.Now().UTC()
			vmCopy := inv
			vmCopy.Members = append([]model.CapacityVMFleetInventoryMember(nil), inv.Members...)
			vmCopy.ObservationStartedAt, vmCopy.ObservedAt = now.Add(-time.Millisecond).Format(time.RFC3339Nano), now.Format(time.RFC3339Nano)
			for i := range vmCopy.Members {
				vmCopy.Members[i].Server.ObservedAt = vmCopy.ObservedAt
			}
			var value any = vmCopy
			if isNode {
				copy := nodes
				copy.Nodes = append([]model.CapacityNodeMembershipTuple(nil), nodes.Nodes...)
				copy.ObservationStartedAt, copy.ObservedAt = now.Add(-time.Millisecond), now
				for i := range copy.Nodes {
					copy.Nodes[i].LeaseRenewedAt = now
				}
				if changed {
					copy.Nodes[0].BootID = uuid.NewString()
				}
				value = copy
				if lateOwner != nil {
					lateOwner.expire()
				}
			}
			_ = json.NewEncoder(w).Encode(model.AdapterExecuteIntegrationResponse{Operation: req.Operation, Capability: req.Operation, Status: "observed", Output: value})
		}))
	}
	vmServer, nodeServer := serve(vmType, false), serve(nodeType, true)
	t.Cleanup(vmServer.Close)
	t.Cleanup(nodeServer.Close)
	create := func(id uuid.UUID, kind, name string, spec any) model.Manifest {
		t.Helper()
		raw, e := json.Marshal(spec)
		if e != nil {
			t.Fatal(e)
		}
		sum := fmt.Sprintf("%x", sha256.Sum256(raw))
		if _, e = db.ExecContext(ctx, `INSERT INTO public.manifests(id,api_version,kind,namespace,name,version,active,spec,checksum) VALUES($1,'yggdrasil.io/v1alpha1',$2,$3,$4,1,true,$5::jsonb,$6)`, id, kind, ns, name, raw, sum); e != nil {
			t.Fatal(e)
		}
		m, e := repository.GetManifestByID(ctx, db, id)
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	vmTy := create(uuid.MustParse(b.IntegrationTypeID), "integration_type", "vm-type", vmType)
	vmInstance := create(uuid.MustParse(b.IntegrationInstanceID), "integration_instance", "vm", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: b.IntegrationTypeID}, Status: "active", Config: map[string]any{"base_url": vmServer.URL}})
	nodeTy := create(uuid.MustParse(p.VMNodeMembershipBinding.Adapter.IntegrationTypeID), "integration_type", "node-type", nodeType)
	nodeInstance := create(uuid.MustParse(p.VMNodeMembershipBinding.Adapter.IntegrationInstanceID), "integration_instance", "nodes", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: nodeTy.ID.String()}, Status: "active", Config: map[string]any{"base_url": nodeServer.URL}})
	b.IntegrationChecksum, b.IntegrationTypeChecksum = vmInstance.Checksum, vmTy.Checksum
	p.MutationBindings = []model.CapacityMutationBinding{b}
	p.VMNodeMembershipBinding.Adapter.InstanceChecksum, p.VMNodeMembershipBinding.Adapter.TypeChecksum = nodeInstance.Checksum, nodeTy.Checksum
	wf := create(uuid.New(), "workflow", p.Workflow.Name, model.WorkflowManifestSpec{Trigger: model.WorkflowTriggerSpec{Mode: "manual"}, Authorization: &model.WorkflowAuthorizationSpec{RBAC: model.ManifestSelector{Namespace: ns, Name: "scope"}}, Steps: []model.WorkflowStepSpec{{ID: "join", Use: model.WorkflowStepUseSpec{Kind: "yggdrasil", Operation: "capacity.observe_vm_node_membership"}}}})
	policy := create(uuid.New(), "capacity_policy", "workers", p)
	ref := manifestReferenceFromRecord(wf)
	store := repository.CapacityStore{DB: db, ExecutionEnabled: true, WorkflowID: wf.ID}
	store.ExecutorID, _ = ctx.Value(capacityInvocationKey{}).(string)
	now := time.Now().UTC()
	load := .9
	assessment := model.CapacityAssessment{Snapshot: model.CapacitySnapshot{TargetIdentity: p.TargetIdentity, ResourceUID: "fleet", ResourceVersion: "1", WorkloadUID: "workers", WorkloadResourceVersion: "1", Owner: p.Owner, Profile: b.ProfileName, Units: 2, ObservedAt: now}, Evidence: []model.CapacityEvidence{{Name: "load", SourceIdentity: "prom/load", Unit: "ratio", RequireData: true, Matched: true, DataState: "present", Value: &load, RangeMin: &load, RangeMax: &load, SourceSampledAt: now, WindowStart: now.Add(-time.Minute), WindowEnd: now, Samples: 10, CoverageComplete: true, MaxGapSeconds: 15}}}
	intent, e := store.Assess(ctx, policy, assessment)
	if e != nil {
		t.Fatal(e)
	}
	intent, e = store.Claim(ctx, policy, intent.Generation, assessment)
	if e != nil {
		t.Fatal(e)
	}
	proofs, e := capacity.VMInventoryProofs(p, b, inv, "", 0, time.Now().UTC(), "fixture:registered-native-tuples")
	if e != nil {
		t.Fatal(e)
	}
	for _, proof := range proofs {
		raw := capacityVMNodeProtocolCanonicalSpec(t, b.Slots[proof.Slot-1].DesiredSpec)
		if e = store.RecordMutationSlot(ctx, policy, intent.Generation, intent.FencingToken, intent.LeaseOwner, model.CapacityMutationIssue{BindingName: b.Name, DesiredSpec: raw}, proof); e != nil {
			t.Fatal(e)
		}
	}
	input := func() map[string]any {
		return map[string]any{"policy": map[string]any{"namespace": ns, "name": "workers"}, "binding_name": b.Name}
	}
	run := func(c context.Context, v map[string]any) model.WorkflowRunStepResult {
		return executeCapacityNativeWorkflowStep(c, nil, db, ref, model.WorkflowRunStepResult{Operation: "capacity.observe_vm_node_membership"}, v)
	}
	got := run(ctx, input())
	if got.Status != "succeeded" || got.Metadata["native_join_observed"] != true || got.Metadata["warm_resources_known"] != false || got.Metadata["useful_capacity_known"] != false || got.Metadata["provider_mutation_quiescence_known"] != false {
		mu.Lock()
		h, d, r, w := healthReads, describeReads, reads, writes
		mu.Unlock()
		t.Fatalf("protected point was not observed or became authority: status=%s; health=%d describe=%d reads=%d forbidden=%d", got.Status, h, d, r, w)
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return reads }
	privateCount := func() int { mu.Lock(); defer mu.Unlock(); return healthReads + describeReads + reads }
	var grants int
	if e = db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_mutation_grants WHERE namespace=$1`, ns).Scan(&grants); e != nil || grants != 0 {
		t.Fatal("observer issued a provider grant", e)
	}
	before := count()
	privateBefore := privateCount()
	for _, field := range []string{"healthy", "selector", "url", "proof", "capability", "generation"} {
		v := input()
		v[field] = true
		if run(ctx, v).Status == "succeeded" {
			t.Fatal("caller authority admitted", field)
		}
	}
	if run(context.Background(), input()).Status == "succeeded" || count() != before || privateCount() != privateBefore {
		t.Fatal("actorless/refused input performed native reads")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if run(canceled, input()).Status == "succeeded" || count() != before || privateCount() != privateBefore {
		t.Fatal("expired invocation read or accepted a point")
	}
	rawPolicy, _ := json.Marshal(p)
	p.VMNodeMembershipBinding.Adapter.TypeChecksum = strings.Repeat("6", 64)
	badRaw, _ := json.Marshal(p)
	if _, e = db.ExecContext(ctx, `UPDATE public.manifests SET spec=$2::jsonb,checksum=$3 WHERE id=$1`, policy.ID, badRaw, fmt.Sprintf("%x", sha256.Sum256(badRaw))); e != nil {
		t.Fatal(e)
	}
	if run(ctx, input()).Status == "succeeded" || count() != before || privateCount() != privateBefore {
		t.Fatal("bad native catalog reached a private adapter")
	}
	if _, e = db.ExecContext(ctx, `UPDATE public.manifests SET spec=$2::jsonb,checksum=$3 WHERE id=$1`, policy.ID, rawPolicy, policy.Checksum); e != nil {
		t.Fatal(e)
	}

	t.Run("registered_tombstone_refuses_before_node_source", func(t *testing.T) {
		var original []byte
		if e = db.QueryRowContext(ctx, `SELECT slot_record FROM public.capacity_resource_slots WHERE namespace=$1 AND slot=1`, ns).Scan(&original); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if _, e := db.ExecContext(ctx, `UPDATE public.capacity_resource_slots SET slot_record=$2::jsonb WHERE namespace=$1 AND slot=1`, ns, original); e != nil {
				t.Error(e)
			}
		})
		if _, e = db.ExecContext(ctx, `UPDATE public.capacity_resource_slots SET slot_record=jsonb_set(slot_record,'{tombstone}','true'::jsonb) WHERE namespace=$1 AND slot=1`, ns); e != nil {
			t.Fatal(e)
		}
		before := count()
		if run(ctx, input()).Status == "succeeded" || count() != before+1 {
			t.Fatal("tombstone revived or reached native Node observer")
		}
	})
	t.Run("original_sdk_return_after_parent_absolute_deadline", func(t *testing.T) {
		absolute := &capacityVMNodeAbsoluteContext{Context: ctx, deadline: time.Now().Add(time.Minute)}
		mu.Lock()
		lateOwner = absolute
		mu.Unlock()
		t.Cleanup(func() { mu.Lock(); lateOwner = nil; mu.Unlock() })
		before := count()
		got := run(absolute, input())
		if got.Status == "succeeded" || got.Metadata != nil || absolute.Err() != nil || count() != before+2 {
			t.Fatal("late original SDK point accepted or issued another read")
		}
	})
	mu.Lock()
	changed = true
	mu.Unlock()
	if run(ctx, input()).Status == "succeeded" {
		t.Fatal("changed original Node lifetime admitted")
	}
	for _, phase := range []string{"prepared", "canary", "drained", "promoted"} {
		v := map[string]any{"policy": input()["policy"], "generation": intent.Generation, "fencing_token": intent.FencingToken, "lease_owner": intent.LeaseOwner, "phase": phase, "proof": map[string]any{"healthy": true, "inflight": 0}}
		blocked := executeCapacityWorkflowStep(ctx, db, ref, model.WorkflowRunStepResult{Operation: "capacity.advance"}, v)
		if blocked.Status == "succeeded" || !strings.Contains(blocked.Error, "native VM/Node linkage is not readiness") {
			t.Fatal("native linkage refusal did not reach the opt-in phase boundary", phase)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if writes != 0 {
		t.Fatal("read-only membership performed a provider mutation")
	}
}

// Original-context deadline seam only; no fake source identities or SDK calls.
type capacityVMNodeAbsoluteContext struct {
	context.Context
	mu       sync.Mutex
	deadline time.Time
}

func (c *capacityVMNodeAbsoluteContext) Deadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline, true
}
func (c *capacityVMNodeAbsoluteContext) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadline = time.Now().Add(-time.Second)
}
