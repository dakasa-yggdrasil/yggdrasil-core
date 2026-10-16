//go:build linux && nativequalification

// This independently built clean Core command owns the real ephemeral PG/API
// caller. It cannot run outside the mandatory owning GitHub native workflow.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	message "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

type fixture struct {
	publicReturns     []originalPublicReturn
	db                *sql.DB
	request           q.SourceRequest
	private           string
	profile           model.CapacityGuestProtectedProfileManifest
	binding           model.CapacityGuestRetirementBinding
	policy            model.Manifest
	workflow          model.Manifest
	realm             *q.Realm
	corePublic        ed25519.PublicKey
	corePrivate       ed25519.PrivateKey
	issuerPublic      ed25519.PublicKey
	issuerPrivate     ed25519.PrivateKey
	producerPublic    ed25519.PublicKey
	producerPrivate   ed25519.PrivateKey
	ca                *x509.Certificate
	caPrivate         ed25519.PrivateKey
	caPEM             []byte
	coreCertificate   []byte
	coreKey           []byte
	callerCertificate []byte
	callerKey         []byte
	workflowToken     string
	mutationToken     string
	guestPrincipals   []map[string]any
	namespace         string
	completed         q.SourceCaseStage
}

func main() {
	if run() != nil {
		fmt.Fprintln(os.Stderr, "original native Core caller unavailable; HOLD")
		os.Exit(1)
	}
}
func run() (runErr error) {
	enabled := flag.Bool("original-native-qemu-fixture", false, "owning native qualification only")
	requestPath := flag.String("request", "", "original immutable private source request")
	private := flag.String("private-dir", "", "original private directory outside source checkouts")
	flag.Parse()
	if !*enabled || flag.NArg() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("REQUIRE_GUEST_PROVISIONING_NATIVE") != "true" || !filepath.IsAbs(*private) || *requestPath != filepath.Join(*private, "original-source-request.json") {
		return q.ErrOriginalUnknown
	}
	parent, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	read, cancelRead := context.WithTimeout(parent, 5*time.Second)
	var request q.SourceRequest
	_, err := q.ReadPrivate(read, *requestPath, &request)
	cancelRead()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(parent, request.OriginalContextDeadline)
	defer cancel()
	var f *fixture
	// This defer is registered BEFORE DB/broker/API owners. It runs after their
	// actual Close/Serve returns and never emits completion when any join fails.
	defer func() {
		if runErr == nil && f != nil && f.completed.NativeCorpusReceiptSHA256 != "" {
			_, runErr = q.Publish(ctx, filepath.Join(f.private, f.completed.Stage), f.completed)
		}
	}()
	if capacity.CurrentGuestCoreSource() == "" || verifyCleanSources(ctx, request) != nil {
		return q.ErrOriginalUnknown
	}
	if err = verifyOriginalPreparation(ctx, *private, request); err != nil {
		return err
	}
	var profile model.CapacityGuestProtectedProfileManifest
	if _, err = q.ReadPrivate(ctx, filepath.Join(*private, "approved-profile.json"), &profile); err != nil {
		return err
	}
	if err = verifyActualGuestBinaries(ctx, *private, profile); err != nil {
		return err
	}
	// Both endpoints must be owning CI loopback services. This command never
	// connects to a production database, remote broker or physical provider.
	dsn, err := url.Parse(os.Getenv("DB_URL"))
	if err != nil || dsn.Scheme != "postgres" || (dsn.Hostname() != "127.0.0.1" && dsn.Hostname() != "localhost") || dsn.Port() != "5432" || dsn.Path != "/yggdrasil_native_guest" || dsn.Query().Get("sslmode") != "disable" || os.Getenv("BROKER_URL") != "amqp://native:native-ci-only@127.0.0.1:5672/" {
		return q.ErrOriginalUnknown
	}
	db, err := sql.Open("postgres", dsn.String())
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, db.Close()) }()
	db.SetMaxOpenConns(24)
	if err = db.PingContext(ctx); err != nil {
		return err
	}
	if err = goose.SetDialect("postgres"); err != nil {
		return err
	}
	if err = goose.UpContext(ctx, db, filepath.Join(os.Getenv("CORE_NATIVE_SOURCE_ROOT"), "db", "migrations")); err != nil {
		return err
	}
	broker, err := amqp.DialConfig(os.Getenv("BROKER_URL"), amqp.Config{Dial: amqp.DefaultDial(5 * time.Second)})
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, broker.Close()) }()
	f = &fixture{db: db, request: request, private: *private, profile: profile, namespace: "original-qemu-" + uuid.NewString()[:8]}
	if err = f.prepareSource(ctx); err != nil {
		return err
	}
	if err = message.InstallOriginalGuestNativeFixture(f.realm); err != nil {
		return err
	}
	defer f.realm.Close()
	defer func() { runErr = errors.Join(runErr, f.realm.CloseOriginalPins()) }()
	workflowOwners, err := httpapi.NewNativeOriginalWorkflowOwners(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if runErr != nil {
			cancel()
		}
		// A cleanup timeout is not an original return. Keep the DB/broker and
		// native pins owned until every SAME workflow actually finishes.
		runErr = errors.Join(runErr, workflowOwners.Join(context.WithoutCancel(ctx)))
	}()
	handler, err := httpapi.New("original-native-guest-fixture", db, broker, zap.NewNop(), httpapi.WithNativeOriginalWorkflowOwners(workflowOwners))
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(f.caPEM) {
		return q.ErrOriginalUnknown
	}
	pair, err := tls.X509KeyPair(f.coreCertificate, f.coreKey)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", request.Listen)
	if err != nil {
		return err
	}
	handlerOwners, err := httpapi.NewNativeOriginalWorkflowOwners(ctx)
	if err != nil {
		return errors.Join(err, listener.Close())
	}
	server := &http.Server{Handler: originalNativeHTTPHandler(handler, handlerOwners), BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}}
	returned := make(chan error, 1)
	go func() { returned <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	defer func() {
		if runErr != nil {
			cancel()
		}
		shutdown, cancelShutdown := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		shutdownErr := server.Shutdown(shutdown)
		cancelShutdown()
		if shutdownErr != nil {
			cancel()
			runErr = errors.Join(runErr, shutdownErr, server.Close())
		}
		if serveErr := <-returned; !errors.Is(serveErr, http.ErrServerClosed) {
			runErr = errors.Join(runErr, serveErr)
		}
		// Serve returns when its listener closes; a handler can still own an
		// original DB/HTTP call. Its lifetime is joined separately, including
		// after Shutdown refuses and Close cancels the same connection.
		runErr = errors.Join(runErr, handlerOwners.Join(context.WithoutCancel(ctx)))
	}()
	for slot := 1; slot <= 2; slot++ {
		stage := q.Stage{Schema: q.FixtureSchema, Stage: "source-config-ready.json", Slot: slot, CoreActualSourceCommit: capacity.CurrentGuestCoreSource(), SourceCommit: request.SourceCommit, OriginalDeadline: request.OriginalContextDeadline, RecordedAt: time.Now().UTC(), OriginalRecordSHA256: capacity.GuestRetirementSHA(f.binding)}
		if _, err = q.Publish(ctx, filepath.Join(q.SlotDirectory(*private, slot), stage.Stage), stage); err != nil {
			return err
		}
	}
	return f.runOriginalPublicCaller(ctx)
}

func originalNativeHTTPHandler(handler http.Handler, owners *httpapi.NativeOriginalWorkflowOwners) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, finish, err := owners.Begin()
		if err != nil {
			http.Error(w, "original native HTTP owner closed", http.StatusServiceUnavailable)
			return
		}
		defer finish()
		handler.ServeHTTP(w, r)
	})
}

func verifyCleanSources(ctx context.Context, request q.SourceRequest) error {
	for _, source := range []struct{ Root, Commit string }{{os.Getenv("GUEST_NATIVE_SOURCE_ROOT"), request.SourceCommit}, {os.Getenv("CORE_NATIVE_SOURCE_ROOT"), capacity.CurrentGuestCoreSource()}} {
		if !filepath.IsAbs(source.Root) {
			return q.ErrOriginalUnknown
		}
		head, err := exec.CommandContext(ctx, "git", "-C", source.Root, "rev-parse", "HEAD").Output()
		if err != nil || strings.TrimSpace(string(head)) != source.Commit {
			return q.ErrOriginalUnknown
		}
		dirty, err := exec.CommandContext(ctx, "git", "-C", source.Root, "status", "--porcelain", "--untracked-files=normal").Output()
		if err != nil || len(dirty) != 0 {
			return q.ErrOriginalUnknown
		}
	}
	sha, err := q.FileSHA(ctx, filepath.Join(os.Getenv("GUEST_NATIVE_SOURCE_ROOT"), ".github", "fixtures", "native-provisioning", "run.py"), 1<<20)
	if err != nil || sha != request.CreatorSourceSHA256 {
		return q.ErrOriginalUnknown
	}
	return nil
}
func verifyActualGuestBinaries(ctx context.Context, private string, p model.CapacityGuestProtectedProfileManifest) error {
	for _, source := range []struct{ Name, SHA string }{{"runtime-owner", p.OwnerBinarySHA256}, {"retirement-actor", p.ActorBinarySHA256}, {"retirement-client", p.RuntimeClientCommandSHA256}, {"bootstrap", p.BootstrapOwnerBinarySHA256}, {"payload", p.BootstrapPayloadSHA256}} {
		sha, err := q.FileSHA(ctx, filepath.Join(private, "compiled-source", source.Name), 128<<20)
		if err != nil || sha != source.SHA {
			return q.ErrOriginalUnknown
		}
	}
	if p.BootstrapReaderBinarySHA256 != p.OwnerBinarySHA256 {
		return q.ErrOriginalUnknown
	}
	return nil
}
func randomToken() (string, error) {
	var raw [32]byte
	_, err := rand.Read(raw[:])
	return hex.EncodeToString(raw[:]), err
}
func jsonBytes(value any) []byte {
	raw, err := json.Marshal(value)
	if err != nil {
		panic("source fixture JSON construction refused")
	}
	return raw
}

func (f *fixture) makeCertificates(ctx context.Context) error {
	var err error
	f.corePublic, f.corePrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f.issuerPublic, f.issuerPrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f.producerPublic, f.producerPrivate, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f.caPrivate = private
	now := time.Now().UTC()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "original-native-guest-private-ca"}, NotBefore: now.Add(-time.Minute), NotAfter: f.request.OriginalContextDeadline.Add(2 * time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return err
	}
	f.ca, err = x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	f.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.coreCertificate, f.coreKey, err = f.issueCertificate("original-core-private-gateway", true)
	if err != nil {
		return err
	}
	f.callerCertificate, f.callerKey, err = f.issueCertificate("original-core-private-caller", false)
	if err != nil {
		return err
	}
	for path, raw := range map[string][]byte{"core-ca.crt": f.caPEM, "core-server.crt": f.coreCertificate, "core-server.key": f.coreKey, "guest-core-client.crt": f.callerCertificate, "guest-core-client.key": f.callerKey} {
		if _, err = q.PublishBytes(ctx, filepath.Join(f.private, path), raw); err != nil {
			return err
		}
	}
	return nil
}
func (f *fixture) issueCertificate(name string, server bool) ([]byte, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, nil, err
	}
	t := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().UTC().Add(-time.Minute), NotAfter: f.request.OriginalContextDeadline.Add(2 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if server {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		t.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("10.0.2.2")}
	}
	der, err := x509.CreateCertificate(rand.Reader, t, f.ca, public, f.caPrivate)
	if err != nil {
		return nil, nil, err
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), nil
}
func (f *fixture) secret(ctx context.Context, name string, raw []byte) (string, error) {
	_, err := repository.UpsertManagedSecret(ctx, f.db, model.UpsertManagedSecretRequest{Namespace: f.namespace, Name: name, Status: "active", Data: map[string]string{"value": string(raw)}, ExpiresAt: &f.request.OriginalContextDeadline})
	return "secret://" + f.namespace + "/" + name + "#value", err
}
func (f *fixture) createManifest(ctx context.Context, kind, name string, spec any) (model.Manifest, error) {
	raw := jsonBytes(spec)
	return repository.CreateManifestVersion(ctx, f.db, model.ManifestDocument{APIVersion: "v1", Kind: kind, Metadata: model.ManifestMetadataInput{Namespace: f.namespace, Name: name}, Spec: raw}, capacity.BusinessCreationSHA256(raw))
}

func (f *fixture) prepareSource(ctx context.Context) error {
	if err := f.makeCertificates(ctx); err != nil {
		return err
	}
	var err error
	f.workflowToken, err = randomToken()
	if err != nil {
		return err
	}
	f.mutationToken, err = randomToken()
	if err != nil {
		return err
	}
	intentRef, err := f.secret(ctx, "original-intent-signing", []byte(base64.StdEncoding.EncodeToString(f.corePrivate)))
	if err != nil {
		return err
	}
	issuerRef, err := f.secret(ctx, "original-enrollment-signing", []byte(base64.StdEncoding.EncodeToString(f.issuerPrivate)))
	if err != nil {
		return err
	}
	provider := model.IntegrationTypeManifestSpec{Provider: "native-qemu", Domain: "infrastructure", Adapter: model.IntegrationAdapterSpec{Transport: "rabbitmq", Version: "1.0.0", TimeoutSeconds: 65, Queues: model.IntegrationAdapterQueue{Describe: "qualification.original.describe", Execute: "qualification.original.execute"}}, Capabilities: []string{"describe", "execute"}, CredentialSchema: model.IntegrationSchemaSpec{Mode: "none"}, InstanceSchema: model.IntegrationSchemaSpec{Mode: "none"}, ResourceTypes: []model.IntegrationResourceType{{Name: "server", CanonicalPrefix: "thirdparty.native-qemu.server", IdentityTemplate: "server.{id}", DefaultActions: []string{"ensure_server", "destroy_server"}}}, ActionCatalog: []model.IntegrationActionDefinition{{Name: "ensure_server", ResourceTypes: []string{"server"}, Idempotent: true}, {Name: "destroy_server", ResourceTypes: []string{"server"}, Idempotent: true}}, Discovery: model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"}, Normalization: model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.native-qemu.server"}, Execution: model.IntegrationExecutionSpec{SupportsDryRun: true, IdempotentActions: []string{"ensure_server", "destroy_server"}}}
	typ, err := f.createManifest(ctx, "integration_type", "original-native-qemu", provider)
	if err != nil {
		return err
	}
	instance, err := f.createManifest(ctx, "integration_instance", "original-native-qemu", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}})
	if err != nil {
		return err
	}
	b := model.CapacityMutationBinding{Name: "native-qemu", IntegrationInstanceID: instance.ID.String(), IntegrationChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), IntegrationTypeChecksum: typ.Checksum, AdapterPrincipalID: "original-native-qemu-adapter", ScopeChecksum: capacity.GuestRetirementSHA([]string{f.namespace, f.request.SourceCommit, capacity.CurrentGuestCoreSource()}), ProfileName: f.profile.Profile, EnsureCapability: "ensure_server", DestroyCapability: "destroy_server", ProtectedSlots: 1, MaxSlots: 2}
	for slot := 1; slot <= 2; slot++ {
		projection := model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: b.EnsureCapability, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: capacity.GuestRetirementSHA([]string{"native-original-qemu-fixed-1536-2-kvm", f.profile.OwnerSourceCommit}), AdmissionChecksum: capacity.GuestRetirementSHA(f.profile), ProfileName: b.ProfileName, Slot: slot, NativeName: "original-native-qemu-slot-" + fmt.Sprint(slot), BootstrapSHA256: f.profile.BootstrapSHA256}
		b.Slots = append(b.Slots, model.CapacityMutationSlotBinding{Slot: slot, DesiredSpecSHA256: capacity.GuestRetirementSHA(projection), DesiredSpec: &projection})
	}
	f.binding = model.CapacityGuestRetirementBinding{Mode: capacity.GuestRetirementSchema, MutationBindingName: b.Name, EvidenceClass: "native_qemu_qualification", ProvisionerSourceCommit: f.request.SourceCommit, GuestSourceCommit: f.request.SourceCommit, CoreAuthoritySourceCommit: capacity.CurrentGuestCoreSource(), ProvisionerPublicKey: base64.StdEncoding.EncodeToString(f.producerPublic), EnrollmentIssuerPublicKey: base64.StdEncoding.EncodeToString(f.issuerPublic), EnrollmentSigningKeyRef: issuerRef, IntentSigningKeyRef: intentRef, ProfileManifest: f.profile, ProfileManifestSHA256: capacity.GuestRetirementSHA(f.profile), MaxEvidenceAgeSeconds: 30}
	for _, slot := range f.request.Slots {
		member, err := f.prepareMember(ctx, slot)
		if err != nil {
			return err
		}
		f.binding.Members = append(f.binding.Members, member)
	}
	rbac, err := f.createManifest(ctx, "rbac", "original-native-qemu", map[string]any{"roles": []any{map[string]any{"name": "original-qemu-caller", "rules": []any{map[string]any{"effect": "allow", "resources": []string{"workflow:" + f.namespace + ":original-native-qemu"}, "actions": []string{"run"}}}}}, "bindings": []any{map[string]any{"name": "original-caller", "subjects": []any{map[string]string{"type": "service", "id": "original-native-qemu-workflow-caller"}}, "roles": []string{"original-qemu-caller"}}}})
	if err != nil {
		return err
	}
	wfSpec := f.workflowSpec(rbac)
	f.workflow, err = f.createManifest(ctx, "workflow", "original-native-qemu", wfSpec)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	policy := model.CapacityPolicySpec{Environment: "qualification", Domain: "infrastructure", Dimension: "native_echo", TargetIdentity: "original-native-qemu:" + f.namespace, Owner: "original-native-qemu", Workflow: model.ManifestSelector{Namespace: f.namespace, Name: f.workflow.Metadata.Name}, Currency: "USD", Floor: 1, Ceiling: 2, Step: 1, MaxEvidenceAgeSeconds: 30, MaxSampleGapSeconds: 5, MinSamples: 1, UpHoldSeconds: 0, DownHoldSeconds: 1, CooldownSeconds: 0, LeaseSeconds: 300, ExecutionEnabled: true, Signals: []model.CapacitySignalRule{{Name: "qualification-demand", SourceIdentity: "source-controlled-native-fixture-demand", Unit: "ratio", UpAbove: 0.8, DownBelow: 0.3}}, Profiles: []model.CapacityProfile{{Name: f.profile.Profile, Provider: "native-qemu", Region: "owning-ci-qemu", MinUnits: 1, MaxUnits: 2, UnitMonthlyCostMinor: 0, QuoteValidUntil: f.request.OriginalContextDeadline, ValidationValidUntil: f.request.OriginalContextDeadline, ValidationRef: "native-qualification-source-only:" + f.request.SourceCommit, ReadinessSeconds: 0}}, MutationBindings: []model.CapacityMutationBinding{b}, GuestRetirementBinding: &f.binding}
	if !capacity.GuestOriginalProfileEnabled(policy, f.binding, "native-qemu") {
		return q.ErrOriginalUnknown
	}
	f.policy, err = f.createManifest(ctx, "capacity_policy", "original-native-qemu", policy)
	if err != nil {
		return err
	}
	principal := func(id, token string) map[string]any {
		return map[string]any{"principal_id": id, "status": "active", "expires_at": f.request.OriginalContextDeadline, "rotation_id": uuid.NewString(), "rotated_at": now, "token_sha256": capacity.BusinessCreationSHA256([]byte(token))}
	}
	work := principal("original-native-qemu-workflow-caller", f.workflowToken)
	work["allowed_workflows"] = []any{map[string]string{"namespace": f.namespace, "name": f.workflow.Metadata.Name}}
	mutation := principal(b.AdapterPrincipalID, f.mutationToken)
	mutation["integration_instance_id"] = b.IntegrationInstanceID
	mutation["capabilities"] = []string{b.EnsureCapability, b.DestroyCapability}
	for name, value := range map[string]string{"YGGDRASIL_ENV": "test", "YGGDRASIL_CAPACITY_EXECUTION_ENABLED": "true", "YGGDRASIL_WORKFLOW_MACHINE_PRINCIPALS_JSON": string(jsonBytes([]any{work})), "YGGDRASIL_CAPACITY_MUTATION_PRINCIPALS_JSON": string(jsonBytes([]any{mutation})), "YGGDRASIL_CAPACITY_GUEST_PRINCIPALS_JSON": string(jsonBytes(f.guestPrincipals))} {
		if err = os.Setenv(name, value); err != nil {
			return err
		}
	}
	f.realm, err = q.NewRealm(f.private, f.request, f.profile, f.mutationToken, f.caPEM, f.callerCertificate, f.callerKey)
	if err != nil {
		return err
	}
	_, err = q.Publish(ctx, filepath.Join(f.private, "binding.json"), f.binding)
	return err
}
