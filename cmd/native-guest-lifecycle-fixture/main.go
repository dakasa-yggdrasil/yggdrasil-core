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
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityqualification"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

type fixture struct {
	publicReturns              []originalPublicReturn
	db                         *sql.DB
	request                    q.SourceRequest
	private                    string
	profile                    model.CapacityGuestProtectedProfileManifest
	binding                    model.CapacityGuestRetirementBinding
	policy                     model.Manifest
	workflow                   model.Manifest
	realm                      *q.Realm
	corePublic                 ed25519.PublicKey
	corePrivate                ed25519.PrivateKey
	issuerPublic               ed25519.PublicKey
	issuerPrivate              ed25519.PrivateKey
	producerPublic             ed25519.PublicKey
	producerPrivate            ed25519.PrivateKey
	ca                         *x509.Certificate
	caPrivate                  ed25519.PrivateKey
	caPEM                      []byte
	coreCertificate            []byte
	coreKey                    []byte
	callerCertificate          []byte
	callerKey                  []byte
	workflowToken              string
	mutationToken              string
	guestPrincipals            []map[string]any
	namespace                  string
	completedSourceFloor       map[string]any
	completedHistoricalConfirm map[string]any
	completedTerminal          map[string]any
	completedLivePartial       map[string]any
	completed                  q.SourceCaseStage
	completedSourceContract    q.SourceFenceCompletion
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
		if runErr == nil && f != nil && f.completedSourceFloor != nil {
			_, runErr = q.Publish(ctx, filepath.Join(f.private, "original-failed-floor-completed.json"), f.completedSourceFloor)
		}
		if runErr == nil && f != nil && f.completedHistoricalConfirm != nil {
			_, runErr = q.Publish(ctx, filepath.Join(f.private, "original-historical-confirm-completed.json"), f.completedHistoricalConfirm)
		}
		if runErr == nil && f != nil && f.completedTerminal != nil {
			_, runErr = q.Publish(ctx, filepath.Join(f.private, "original-terminal-contract-completed.json"), f.completedTerminal)
		}
		if runErr == nil && f != nil && f.completedLivePartial != nil {
			_, runErr = q.Publish(ctx, filepath.Join(f.private, "original-live-partial-completed.json"), f.completedLivePartial)
		}
		if runErr == nil && f != nil && f.completedSourceContract.ContractSHA256 != "" {
			_, runErr = q.Publish(ctx, filepath.Join(f.private, "original-source-contract-completed.json"), f.completedSourceContract)
		}
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
	if request.NativeCase == "positive_original_lifecycle" {
		readBroker, dialErr := capacityqualification.DialDedicated(ctx, os.Getenv("BROKER_URL"))
		if dialErr != nil {
			return dialErr
		}
		closePG17Read, pg17Err := readBroker.StartWith(ctx, 5*time.Second, func() (func() error, error) {
			return message.StartPG17OriginalReadConsumer(ctx, broker, readBroker.Connection, repository.CapacityStore{DB: db, WorkflowID: f.workflow.ID}, f.policy, f.realm)
		})
		if pg17Err != nil {
			return errors.Join(pg17Err, readBroker.CloseWith(ctx, 5*time.Second, closePG17Read))
		}
		defer func() { runErr = errors.Join(runErr, readBroker.CloseWith(ctx, 5*time.Second, closePG17Read)) }()
	}
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
	pg17Handler := http.Handler(handler)
	if request.NativeCase == "positive_original_lifecycle" {
		pg17Callbacks, pg17Err := httpapi.NewNativeOriginalWorkflowOwners(ctx)
		if pg17Err != nil {
			return pg17Err
		}
		if pg17Err = f.realm.InstallPG17CallbackOwner(pg17Callbacks); pg17Err != nil {
			return pg17Err
		}
		defer func() { runErr = errors.Join(runErr, pg17Callbacks.Join(context.WithoutCancel(ctx))) }()
		pg17Handler = pg17PausedCallbackHTTPHandler(pg17Handler, pg17Callbacks, f.realm, f.policy)
	}
	server := &http.Server{Handler: originalNativeHTTPHandler(pg17Handler, handlerOwners), BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}}
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
	if q.SourceRecoveryCase(request.NativeCase) {
		return f.runOriginalRecoveryContractCaller(ctx)
	}
	if q.SourceContractCase(request.NativeCase) {
		return f.runOriginalSourceFenceCaller(ctx)
	}
	if q.SourceFailedFloorCase(f.request.NativeCase) {
		return f.runOriginalFailedFloorCaller(ctx)
	}
	if q.SourceHistoricalConfirmCase(f.request.NativeCase) {
		return f.runOriginalHistoricalConfirmCaller(ctx)
	}
	if q.SourceTerminalCase(f.request.NativeCase) {
		return f.runOriginalTerminalCaller(ctx)
	}
	if q.SourceLivePartialCase(f.request.NativeCase) {
		return f.runOriginalLivePartialCaller(ctx)
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
	if f.request.NativeCase == "positive_original_lifecycle" {
		for _, operation := range []string{capacity.VMObserveServer, capacity.VMObserveAction} {
			provider.ActionCatalog = append(provider.ActionCatalog, model.IntegrationActionDefinition{Name: operation, Category: "capability", ResourceTypes: []string{"server"}, Idempotent: true})
			provider.ResourceTypes[0].DefaultActions = append(provider.ResourceTypes[0].DefaultActions, operation)
		}
	}
	typ, err := f.createManifest(ctx, "integration_type", "original-native-qemu", provider)
	if err != nil {
		return err
	}
	instance, err := f.createManifest(ctx, "integration_instance", "original-native-qemu", model.IntegrationInstanceManifestSpec{TypeRef: model.ManifestSelector{ManifestID: typ.ID.String()}})
	if err != nil {
		return err
	}
	b := model.CapacityMutationBinding{Name: "native-qemu", IntegrationInstanceID: instance.ID.String(), IntegrationChecksum: instance.Checksum, IntegrationTypeID: typ.ID.String(), IntegrationTypeChecksum: typ.Checksum, AdapterPrincipalID: "original-native-qemu-adapter", ScopeChecksum: capacity.GuestRetirementSHA([]string{f.namespace, f.request.SourceCommit, capacity.CurrentGuestCoreSource()}), ProfileName: f.profile.Profile, EnsureCapability: "ensure_server", DestroyCapability: "destroy_server", ProtectedSlots: 1, MaxSlots: 2}
	if q.SourceProtectedCompensationCase(f.request.NativeCase) {
		b.ProtectedSlots = 2
	}
	if q.SourceFailedFloorCase(f.request.NativeCase) || q.PostlossSourceCase(f.request.NativeCase) {
		b.CompensationEnabled = true
	}
	approvedSlots := 2
	if q.SourceLivePartialCase(f.request.NativeCase) {
		approvedSlots, b.MaxSlots = 3, 3
	}
	for slot := 1; slot <= approvedSlots; slot++ {
		projection := model.CapacityMutationSpecV1{SchemaVersion: "capacity_vm_slot_v1", Capability: b.EnsureCapability, IntegrationInstanceID: b.IntegrationInstanceID, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: capacity.GuestRetirementSHA([]string{"native-original-qemu-fixed-1536-2-kvm", f.profile.OwnerSourceCommit}), AdmissionChecksum: capacity.GuestRetirementSHA(f.profile), ProfileName: b.ProfileName, Slot: slot, NativeName: "original-native-qemu-slot-" + fmt.Sprint(slot), BootstrapSHA256: f.profile.BootstrapSHA256}
		projectionSHA := capacity.GuestRetirementSHA(map[string]any{
			"schema_version":          projection.SchemaVersion,
			"capability":              projection.Capability,
			"integration_instance_id": projection.IntegrationInstanceID,
			"scope_checksum":          projection.ScopeChecksum,
			"profile_checksum":        projection.ProfileChecksum,
			"admission_checksum":      projection.AdmissionChecksum,
			"profile_name":            projection.ProfileName,
			"slot":                    projection.Slot,
			"native_name":             projection.NativeName,
			"bootstrap_sha256":        projection.BootstrapSHA256,
		})
		b.Slots = append(b.Slots, model.CapacityMutationSlotBinding{Slot: slot, DesiredSpecSHA256: projectionSHA, DesiredSpec: &projection})
	}
	f.binding = model.CapacityGuestRetirementBinding{Mode: capacity.GuestRetirementSchema, MutationBindingName: b.Name, EvidenceClass: "native_qemu_qualification", ProvisionerSourceCommit: f.request.SourceCommit, GuestSourceCommit: f.request.SourceCommit, CoreAuthoritySourceCommit: capacity.CurrentGuestCoreSource(), ProvisionerPublicKey: base64.StdEncoding.EncodeToString(f.producerPublic), EnrollmentIssuerPublicKey: base64.StdEncoding.EncodeToString(f.issuerPublic), EnrollmentSigningKeyRef: issuerRef, IntentSigningKeyRef: intentRef, ProfileManifest: f.profile, ProfileManifestSHA256: capacity.GuestRetirementSHA(f.profile), MaxEvidenceAgeSeconds: 30}
	for _, slot := range f.request.Slots {
		member, err := f.prepareMember(ctx, slot)
		if err != nil {
			return err
		}
		f.binding.Members = append(f.binding.Members, member)
	}
	// Slot3 is an approved prospective permission only. It has independent
	// source config and credentials, but is absent from the physical request;
	// the fixed native realm still refuses every Prepare/Create above slot2.
	if q.SourceLivePartialCase(f.request.NativeCase) {
		prospective, prepareErr := f.prepareMember(ctx, q.SlotRequest{Slot: 3, ActorOrigin: "https://127.0.0.1:21447"})
		if prepareErr != nil {
			return prepareErr
		}
		f.binding.Members = append(f.binding.Members, prospective)
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
	if q.SourceLivePartialCase(f.request.NativeCase) {
		policy.Ceiling, policy.Step, policy.Profiles[0].MaxUnits = 3, 2, 3
	}
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

// This separate closed caller never enters the native original corpus reader.
// It executes the actual authenticated workflow and rereads the same durable
// grant/administrative result; its result has Source authority only.
func (f *fixture) runOriginalSourceFenceCaller(ctx context.Context) (runErr error) {
	defer f.retainSourceCallerFailure(ctx, &runErr)
	if !q.SourceContractCase(f.request.NativeCase) || len(f.realm.OwnedSlots()) != 0 {
		return q.ErrOriginalUnknown
	}
	var p model.CapacityPolicySpec
	if json.Unmarshal(f.policy.Spec, &p) != nil {
		return q.ErrOriginalUnknown
	}
	run, returns, err := f.originalWorkflow(ctx, "source_contract", 1, q.QualificationAssessment(p, 0, 0.9, time.Now().UTC()), "")
	if err != nil || run.Status != "succeeded" || run.Result == nil || len(run.Result.Steps) != 3 {
		return q.ErrOriginalUnknown
	}
	var contract q.SourceFenceContract
	contractWire, err := q.ReadPrivate(ctx, filepath.Join(f.private, "source-fence-contract.json"), &contract)
	if err != nil || contract.Schema != "core_original_source_fence_contract_v1" || contract.Scope != "SOURCE_CONTRACT_ONLY_NO_NATIVE_AUTHORITY" || contract.Case != f.request.NativeCase || contract.CoreSource != capacity.CurrentGuestCoreSource() || contract.GuestSource != f.request.SourceCommit || contract.PolicyID != f.policy.ID.String() || contract.WorkflowID != f.workflow.ID.String() || contract.Namespace != f.namespace || contract.Slot != 1 || contract.NativeQualified || !contract.CheckedAt.Before(contract.OriginalDeadline) {
		return q.ErrOriginalUnknown
	}
	if _, err = uuid.Parse(contract.GrantID); err != nil {
		return q.ErrOriginalUnknown
	}
	matched := 0
	for _, step := range run.Result.Steps {
		if step.Status != "succeeded" || step.Error != "" {
			return q.ErrOriginalUnknown
		}
		if step.Operation == capacity.ProvisionOriginalGuestOperation {
			wire, err := json.Marshal(step.Metadata)
			var actual q.SourceFenceContract
			if err != nil || json.Unmarshal(wire, &actual) != nil || capacity.GuestRetirementSHA(actual) != capacity.GuestRetirementSHA(contract) {
				return q.ErrOriginalUnknown
			}
			matched++
		}
	}
	if matched != 1 {
		return q.ErrOriginalUnknown
	}
	var grantWire []byte
	if err = f.db.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, contract.GrantID, f.namespace).Scan(&grantWire); err != nil || capacity.BusinessCreationSHA256(grantWire) != contract.GrantAfterSHA256 {
		return q.ErrOriginalUnknown
	}
	if contract.Case == "source_contract_executor_fence" {
		store := repository.CapacityStore{DB: f.db}
		current, err := store.Observe(ctx, f.policy)
		if err != nil || current.FencingToken != contract.FenceBefore+1 || current.FencingToken != contract.FenceAfter || !current.RecoveryOnly || current.Decision.ExecutionPermitted || !contract.ExecutorChanged || !contract.LeaseOwnerChanged || !contract.OldIssueRefused || !contract.OriginalGrantExpired || contract.HTTP.Status != 200 || contract.HTTP.Mode != "read_only" || contract.RepositoryRedeemResult != "read_only_after_real_expiry" || contract.GrantTransition != "issued_to_expired_only" {
			return q.ErrOriginalUnknown
		}
	} else {
		id, err := uuid.Parse(contract.RevokedID)
		if err != nil {
			return q.ErrOriginalUnknown
		}
		revoked, err := repository.GetManifestByID(ctx, f.db, id)
		if err != nil || revoked.Metadata.Active || revoked.Kind != contract.RevokedKind || revoked.Metadata.Namespace != f.namespace || contract.RevocationRows != 1 || contract.RevokedActiveAfter || contract.GrantBeforeSHA256 != contract.GrantAfterSHA256 || contract.RepositoryRedeemResult != "revoked_scope_refused" || contract.GrantTransition != "byte_exact_unchanged" {
			return q.ErrOriginalUnknown
		}
	}
	{
		pg17FenceRead, cancelPG17FenceRead := context.WithDeadline(ctx, contract.OriginalDeadline)
		defer cancelPG17FenceRead()
		pg17Fence, pg17FenceErr := message.AssertPG17SourceFence(pg17FenceRead, repository.CapacityStore{DB: f.db, WorkflowID: f.workflow.ID}, f.policy, contract)
		if pg17FenceErr != nil {
			return pg17FenceErr
		}
		if pg17FenceErr = message.PG17RetainAssertions(pg17FenceRead, f.realm, f.policy, f.workflow.ID.String(), 0, "source-fence", []message.PG17AssertionResult{pg17Fence}); pg17FenceErr != nil {
			return pg17FenceErr
		}
	}
	returnsWire, err := q.Publish(ctx, filepath.Join(f.private, "source-contract-public-returns.json"), returns)
	if err != nil {
		return err
	}
	completion := q.SourceFenceCompletion{Schema: q.FixtureSchema, Stage: "original-source-contract-completed.json", Scope: "SOURCE_CONTRACT_ONLY_NO_NATIVE_AUTHORITY", Case: contract.Case, CoreSource: contract.CoreSource, GuestSource: contract.GuestSource, WorkflowRunID: run.ID.String(), ContractSHA256: capacity.BusinessCreationSHA256(contractWire), PublicReturnsSHA256: capacity.BusinessCreationSHA256(returnsWire), NativeQualified: false}
	if _, err = q.Publish(ctx, filepath.Join(f.private, "source-contract-caller-readback.json"), completion); err != nil {
		return err
	}
	// The existing run() completion defer publishes this same DTO only AFTER
	// the original handlers/workflows/server/broker/DB owners have returned.
	f.completedSourceContract = completion
	return nil
}

func (f *fixture) runOriginalRecoveryContractCaller(ctx context.Context) (runErr error) {
	defer f.retainSourceCallerFailure(ctx, &runErr)
	stage := "entry"
	defer func() { f.retainRecoveryGuardFailure(ctx, runErr, stage) }()
	if !q.SourceRecoveryCase(f.request.NativeCase) || len(f.realm.OwnedSlots()) != 0 {
		return q.ErrOriginalUnknown
	}
	stage = "policy_decode"
	var p model.CapacityPolicySpec
	if json.Unmarshal(f.policy.Spec, &p) != nil {
		return q.ErrOriginalUnknown
	}
	stage = "workflow"
	run, returns, err := f.originalWorkflow(ctx, "source_contract", 1, q.QualificationAssessment(p, 0, 0.9, time.Now().UTC()), "")
	if err != nil || run.Status != "succeeded" || run.Result == nil || len(run.Result.Steps) != 3 {
		return q.ErrOriginalUnknown
	}
	stage = "contract_read_and_identity"
	var contract q.SourceRecoveryContract
	wire, err := q.ReadPrivate(ctx, filepath.Join(f.private, "source-recovery-contract.json"), &contract)
	if err != nil || contract.Schema != "core_original_source_recovery_contract_v1" || contract.Scope != "SOURCE_CONTRACT_ONLY_NO_NATIVE_AUTHORITY" || contract.Case != f.request.NativeCase || contract.CoreSource != capacity.CurrentGuestCoreSource() || contract.GuestSource != f.request.SourceCommit || contract.Namespace != f.namespace || contract.PolicyID != f.policy.ID.String() || contract.WorkflowID != f.workflow.ID.String() || contract.Slot != 1 || contract.NativeQualified || !contract.CheckedAt.Before(contract.OriginalDeadline) || contract.OriginalDeadline.After(f.request.OriginalContextDeadline) || contract.DBExpiryObservedAt.Before(contract.GrantExpiresAt) {
		return q.ErrOriginalUnknown
	}
	stage = "workflow_step_binding"
	matched := 0
	for _, step := range run.Result.Steps {
		if step.Status != "succeeded" || step.Error != "" {
			return q.ErrOriginalUnknown
		}
		if step.Operation == capacity.ProvisionOriginalGuestOperation {
			raw, err := json.Marshal(step.Metadata)
			var typed q.SourceRecoveryContract
			if err != nil || json.Unmarshal(raw, &typed) != nil || capacity.GuestRetirementSHA(typed) != capacity.GuestRetirementSHA(contract) {
				return q.ErrOriginalUnknown
			}
			matched++
		}
	}
	stage = "phase_binding"
	if matched != 1 || contract.PhaseAfter != contract.PhaseBefore || contract.PhaseAfter != "preparing" || contract.ReconcileAccepted {
		return q.ErrOriginalUnknown
	}
	stage = "original_provisioning"
	store := repository.CapacityStore{DB: f.db}
	pre, err := store.ReadSourceRecoveryHistoricalPreregistration(ctx, f.policy, f.workflow.ID, contract.GrantID, contract.PreregistrationID, contract.Slot, contract.Generation, contract.FenceBefore)
	if err != nil || pre.PreregistrationID != contract.PreregistrationID || pre.Generation != contract.Generation || pre.Fence != contract.FenceBefore {
		return q.ErrOriginalUnknown
	}
	stage = "intent_read_and_binding"
	var rawIntent, rawGrant []byte
	if err = f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, f.namespace, p.Environment, p.Domain, p.Dimension).Scan(&rawIntent); err != nil {
		return err
	}
	var intent model.CapacityIntent
	if json.Unmarshal(rawIntent, &intent) != nil || intent.PolicyID != f.policy.ID || intent.PolicyChecksum != f.policy.Checksum || intent.FencingToken != contract.FenceAfter || intent.Phase != contract.PhaseAfter {
		return q.ErrOriginalUnknown
	}
	stage = "grant_record_hash"
	if err = f.db.QueryRowContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, contract.GrantID, f.namespace).Scan(&rawGrant); err != nil || capacity.BusinessCreationSHA256(rawGrant) != contract.GrantAfterSHA256 {
		return q.ErrOriginalUnknown
	}
	stage = "grant_state"
	var state string
	if err = f.db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, contract.GrantID, f.namespace).Scan(&state); err != nil || state != contract.StateAfter {
		return q.ErrOriginalUnknown
	}
	stage = "policy_binding"
	actualPolicy, err := repository.GetManifestByID(ctx, f.db, f.policy.ID)
	if err != nil || actualPolicy.ID != f.policy.ID || actualPolicy.Kind != "capacity_policy" || actualPolicy.Checksum != f.policy.Checksum || actualPolicy.Metadata.Namespace != f.namespace || actualPolicy.Metadata.Active != contract.PolicyActiveAfter {
		return q.ErrOriginalUnknown
	}
	stage = "case_invariants"
	if contract.Case == "source_contract_unredeemed_expiry_recovery" {
		if !contract.PolicyPauseApplied || contract.PolicyPauseRows != 1 || contract.PolicyActiveAfter || contract.PauseMode != "persisted_policy_manifest_inactive_and_recovery_store_execution_disabled" {
			return q.ErrOriginalUnknown
		}
		if !contract.RecoveryAttempted || !contract.RecoveryOnly || !contract.ExecutorChanged || !contract.LeaseOwnerChanged || contract.FenceAfter != contract.FenceBefore+1 || !intent.RecoveryOnly || intent.Decision.ExecutionPermitted || intent.LeaseOwner == pre.LeaseOwner || intent.LeaseExecutorID == pre.ExecutorID || contract.DBExpiryObservedAt.Before(contract.LeaseExpiresAt) || contract.StateAfter != "expired" || contract.ReplayMode != "read_only" || !contract.ReconcileAttempted || contract.ReconcileErrorClass != "missing_genuine_recovery_proof" || contract.ProofBoundary != "ABORT_NOT_ADMITTED_MISSING_GENUINE_HEALTH_AND_NO_MUTATION_PROOF" {
			return q.ErrOriginalUnknown
		}
	} else {
		if contract.PolicyPauseApplied || contract.PolicyPauseRows != 0 || !contract.PolicyActiveAfter || contract.PauseMode != "none" {
			return q.ErrOriginalUnknown
		}
		if contract.RecoveryAttempted || contract.RecoveryOnly || contract.ExecutorChanged || contract.LeaseOwnerChanged || contract.ReconcileAttempted || contract.FenceAfter != contract.FenceBefore || intent.RecoveryOnly || intent.LeaseOwner != pre.LeaseOwner || intent.LeaseExecutorID != pre.ExecutorID || contract.StateAfter != "redeemed" || contract.FirstMode != "write_once" || contract.ReplayMode != "read_only" || !contract.IssueReturnedOriginal || contract.GrantBeforeSHA256 != contract.GrantAfterSHA256 || contract.ProofBoundary != "TERMINAL_UNRESOLVED_GUARD_NOT_EXERCISED_MISSING_GENUINE_PROTECTED_TRANSITION_PROOF" {
			return q.ErrOriginalUnknown
		}
	}
	stage = "publish_returns"
	returnsWire, err := q.Publish(ctx, filepath.Join(f.private, "source-recovery-public-returns.json"), returns)
	if err != nil {
		return err
	}
	stage = "publish_completion_readback"
	completion := q.SourceFenceCompletion{Schema: q.FixtureSchema, Stage: "original-source-contract-completed.json", Scope: "SOURCE_CONTRACT_ONLY_NO_NATIVE_AUTHORITY", Case: contract.Case, CoreSource: contract.CoreSource, GuestSource: contract.GuestSource, WorkflowRunID: run.ID.String(), ContractSHA256: capacity.BusinessCreationSHA256(wire), PublicReturnsSHA256: capacity.BusinessCreationSHA256(returnsWire), NativeQualified: false}
	if _, err = q.Publish(ctx, filepath.Join(f.private, "source-recovery-caller-readback.json"), completion); err != nil {
		return err
	}
	f.completedSourceContract = completion
	return nil
}

func (f *fixture) runOriginalLivePartialCaller(ctx context.Context) (runErr error) {
	defer f.retainSourceCallerFailure(ctx, &runErr)
	var p model.CapacityPolicySpec
	if json.Unmarshal(f.policy.Spec, &p) != nil || len(f.realm.OwnedSlots()) != 0 {
		return q.ErrOriginalUnknown
	}
	if err := f.initializeOriginalRecoverySourceTables(ctx); err != nil {
		return err
	}
	baseline, _, err := f.originalWorkflow(ctx, "baseline", 1, q.QualificationAssessment(p, 0, 0.9, time.Now().UTC()), "")
	if err != nil || baseline.Status != "succeeded" {
		return q.ErrOriginalUnknown
	}
	at, err := f.actualLastUsefulProbeTime(ctx, 1)
	if err != nil {
		return err
	}
	run, _, err := f.originalWorkflow(ctx, "live_partial", 2, q.QualificationAssessment(p, 1, 0.9, at), "")
	if err != nil || run.Status != "succeeded" || run.Result == nil {
		return q.ErrOriginalUnknown
	}
	var retained q.SourceLivePartialContract
	wire, err := q.ReadPrivate(ctx, filepath.Join(f.private, "source-live-partial-contract.json"), &retained)
	if err != nil || retained.Schema != "core_original_live_partial_recovery_v1" || retained.Case != f.request.NativeCase || retained.NativeQualified || retained.PolicyID != f.policy.ID.String() || retained.WorkflowID != f.workflow.ID.String() || retained.CoreSource != capacity.CurrentGuestCoreSource() || retained.GuestSource != f.request.SourceCommit || retained.Scope != "SOURCE_NATIVE_NEW_MEMBER_PARTIAL_ONLY" || retained.BaselineUnits != 1 || retained.TargetUnits != 3 || retained.PartialUnits != 2 || retained.OutstandingMutations != 0 || retained.Slot2Grants != 1 || retained.MemberRows != 2 || !retained.PendingPromotionRefused || retained.PendingCreateCalled || retained.NextGeneration <= retained.PriorGeneration || !retained.CheckedAt.Before(retained.OriginalDeadline) {
		return q.ErrOriginalUnknown
	}
	matched := 0
	for _, step := range run.Result.Steps {
		if step.Operation == capacity.ProvisionOriginalGuestOperation && step.Status == "succeeded" {
			encoded, err := json.Marshal(step.Metadata)
			var actual q.SourceLivePartialContract
			if err != nil || json.Unmarshal(encoded, &actual) != nil || capacity.GuestRetirementSHA(actual) != capacity.GuestRetirementSHA(retained) {
				return q.ErrOriginalUnknown
			}
			matched++
		}
	}
	if matched != 1 {
		return q.ErrOriginalUnknown
	}
	var intentRaw []byte
	var actualIntent model.CapacityIntent
	if err = f.db.QueryRowContext(ctx, `SELECT intent FROM public.capacity_intents WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4`, f.namespace, p.Environment, p.Domain, p.Dimension).Scan(&intentRaw); err != nil {
		return err
	}
	if json.Unmarshal(intentRaw, &actualIntent) != nil || capacity.GuestRetirementSHA(actualIntent) != retained.NextIntentSHA256 || actualIntent.Generation != retained.NextGeneration || actualIntent.RecoveryOnly {
		return q.ErrOriginalUnknown
	}
	f.completedLivePartial = map[string]any{"schema": q.FixtureSchema, "stage": "original-live-partial-completed.json", "case": f.request.NativeCase, "contract_sha256": capacity.BusinessCreationSHA256(wire), "scope": "SOURCE_NATIVE_NEW_MEMBER_PARTIAL_ONLY", "native_qualified": false, "core_source": capacity.CurrentGuestCoreSource(), "guest_source": f.request.SourceCommit}
	return nil
}

func (f *fixture) runOriginalHistoricalConfirmCaller(ctx context.Context) (runErr error) {
	defer f.retainSourceCallerFailure(ctx, &runErr)
	var p model.CapacityPolicySpec
	if json.Unmarshal(f.policy.Spec, &p) != nil || len(f.realm.OwnedSlots()) != 0 {
		return q.ErrOriginalUnknown
	}
	run, _, err := f.originalWorkflow(ctx, "historical_confirm", 1, q.QualificationAssessment(p, 0, 0.9, time.Now().UTC()), "")
	if err != nil || run.Status != "succeeded" || run.Result == nil {
		return q.ErrOriginalUnknown
	}
	var retained q.SourceHistoricalConfirmContract
	wire, err := q.ReadPrivate(ctx, filepath.Join(f.private, "source-historical-confirm-contract.json"), &retained)
	if err != nil || retained.Schema != "core_original_source_historical_confirm_v1" || retained.Scope != "SOURCE_HISTORICAL_CONFIRMED_AFTER_REAL_PAUSE_ONLY" || retained.Case != f.request.NativeCase || retained.CoreSource != capacity.CurrentGuestCoreSource() || retained.GuestSource != f.request.SourceCommit || retained.PolicyID != f.policy.ID.String() || retained.NativeQualified || retained.PauseRows != 1 || retained.PolicyActiveAfter || retained.RecoveryExecutionEnabled || retained.CanonicalEvents != 1 || !retained.OldObservationRefused || retained.StateAfter != "confirmed" || !retained.CheckedAt.Before(retained.OriginalDeadline) {
		return q.ErrOriginalUnknown
	}
	matched := 0
	for _, step := range run.Result.Steps {
		if step.Operation == capacity.ProvisionOriginalGuestOperation && step.Status == "succeeded" {
			encoded, err := json.Marshal(step.Metadata)
			var result q.SourceHistoricalConfirmContract
			if err != nil || json.Unmarshal(encoded, &result) != nil || capacity.GuestRetirementSHA(result) != capacity.GuestRetirementSHA(retained) {
				return q.ErrOriginalUnknown
			}
			matched++
		}
	}
	if matched != 1 {
		return q.ErrOriginalUnknown
	}
	actual, err := repository.GetManifestByID(ctx, f.db, f.policy.ID)
	if err != nil || actual.ID != f.policy.ID || actual.Checksum != f.policy.Checksum || actual.Metadata.Active {
		return q.ErrOriginalUnknown
	}
	var events int
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.event_log WHERE idempotency_key=$1`, "capacity-mutation/"+retained.GrantID).Scan(&events); err != nil || events != 1 {
		return q.ErrOriginalUnknown
	}
	f.completedHistoricalConfirm = map[string]any{"schema": q.FixtureSchema, "stage": "original-historical-confirm-completed.json", "case": f.request.NativeCase, "contract_sha256": capacity.BusinessCreationSHA256(wire), "scope": retained.Scope, "native_qualified": false, "core_source": retained.CoreSource, "guest_source": retained.GuestSource}
	return nil
}

func (f *fixture) initializeOriginalRecoverySourceTables(ctx context.Context) error {
	// Fixture-owned Source-only schema; production migration00064 and its
	// closed usage/stage enums remain unchanged.
	if _, err := f.db.ExecContext(ctx, `CREATE TABLE public.capacity_guest_qualification_recovery_source_challenges (
 challenge_id UUID PRIMARY KEY, preregistration_id UUID NOT NULL REFERENCES public.capacity_vm_provisioning_preregistrations(id), challenge_sha256 TEXT NOT NULL UNIQUE CHECK(challenge_sha256 ~ '^[0-9a-f]{64}$'),
 original_wire BYTEA NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 16384), original_record JSONB NOT NULL CHECK(jsonb_typeof(original_record)='object'), original_deadline TIMESTAMPTZ NOT NULL, recorded_at TIMESTAMPTZ NOT NULL,
 usage_class TEXT NOT NULL CHECK(usage_class='capacity_recovery'))`); err != nil {
		return err
	}
	if _, err := f.db.ExecContext(ctx, `CREATE TABLE public.capacity_guest_qualification_recovery_source_returns (
 id UUID PRIMARY KEY, preregistration_id UUID NOT NULL REFERENCES public.capacity_vm_provisioning_preregistrations(id), native_stage TEXT NOT NULL CHECK(native_stage='recovery_serving_probe'),
 return_sha256 TEXT NOT NULL CHECK(return_sha256 ~ '^[0-9a-f]{64}$'), original_wire BYTEA NOT NULL CHECK(octet_length(original_wire) BETWEEN 1 AND 1048576), original_record JSONB NOT NULL CHECK(jsonb_typeof(original_record)='object'), recorded_at TIMESTAMPTZ NOT NULL, UNIQUE(preregistration_id,native_stage,return_sha256))`); err != nil {
		return err
	}
	if _, err := f.db.ExecContext(ctx, `CREATE TRIGGER capacity_recovery_source_challenges_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_qualification_recovery_source_challenges FOR EACH ROW EXECUTE FUNCTION public.capacity_vm_original_retirement_immutable()`); err != nil {
		return err
	}
	if _, err := f.db.ExecContext(ctx, `CREATE TRIGGER capacity_recovery_source_returns_immutable BEFORE UPDATE OR DELETE ON public.capacity_guest_qualification_recovery_source_returns FOR EACH ROW EXECUTE FUNCTION public.capacity_vm_original_retirement_immutable()`); err != nil {
		return err
	}
	return nil
}

func (f *fixture) runOriginalTerminalCaller(ctx context.Context) (runErr error) {
	defer f.retainSourceCallerFailure(ctx, &runErr)
	var p model.CapacityPolicySpec
	if json.Unmarshal(f.policy.Spec, &p) != nil || len(f.realm.OwnedSlots()) != 0 {
		return q.ErrOriginalUnknown
	}
	if err := f.initializeOriginalRecoverySourceTables(ctx); err != nil {
		return err
	}
	baseline, _, err := f.originalWorkflow(ctx, "baseline", 1, q.QualificationAssessment(p, 0, 0.9, time.Now().UTC()), "")
	if err != nil || baseline.Status != "succeeded" {
		return q.ErrOriginalUnknown
	}
	at, err := f.actualLastUsefulProbeTime(ctx, 1)
	if err != nil {
		return err
	}
	run, _, err := f.originalWorkflow(ctx, "terminal_contract", 2, q.QualificationAssessment(p, 1, 0.9, at), "")
	if err != nil || run.Status != "succeeded" || run.Result == nil {
		return q.ErrOriginalUnknown
	}
	var c q.SourceTerminalContract
	wire, err := q.ReadPrivate(ctx, filepath.Join(f.private, "source-terminal-contract.json"), &c)
	if err != nil || c.Schema != "core_original_source_terminal_contract_v1" || c.Scope != "SOURCE_TERMINAL_CONTRACT_ONLY_NO_NATIVE_CREDIT" || c.Case != f.request.NativeCase || c.CoreSource != capacity.CurrentGuestCoreSource() || c.GuestSource != f.request.SourceCommit || c.PolicyID != f.policy.ID.String() || c.NativeQualified || !c.CheckedAt.Before(c.OriginalDeadline) {
		return q.ErrOriginalUnknown
	}
	matched := 0
	for _, step := range run.Result.Steps {
		if step.Operation == capacity.ProvisionOriginalGuestOperation && step.Status == "succeeded" {
			encoded, err := json.Marshal(step.Metadata)
			var actual q.SourceTerminalContract
			if err != nil || capacity.DecodeGuestLifecycle(encoded, &actual) != nil || capacity.GuestRetirementSHA(actual) != capacity.GuestRetirementSHA(c) {
				return q.ErrOriginalUnknown
			}
			matched++
		}
	}
	if matched != 1 {
		return q.ErrOriginalUnknown
	}
	var state string
	var members int
	if err = f.db.QueryRowContext(ctx, `SELECT state FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, c.GrantID, f.namespace).Scan(&state); err != nil || state != c.GrantState {
		return q.ErrOriginalUnknown
	}
	if err = f.db.QueryRowContext(ctx, `SELECT count(*) FROM public.capacity_resource_slots WHERE namespace=$1 AND resource_id<>''`, f.namespace).Scan(&members); err != nil || members != 1 || len(f.realm.OwnedSlots()) != 1 {
		return q.ErrOriginalUnknown
	}
	if c.Case == "source_live_unredeemed_abort" {
		if state != "expired" || c.Terminal != "aborted" || c.TerminalRefused {
			return q.ErrOriginalUnknown
		}
	} else {
		if state != "redeemed" || c.Terminal != "reconciled_partial" || !c.TerminalRefused || !capacity.ValidDigest(c.ReplaySHA256) {
			return q.ErrOriginalUnknown
		}
	}
	if c.CallbackRepresentation != "TYPED_RESERIALIZATION_NOT_RAW_HTTP" {
		return q.ErrOriginalUnknown
	}
	if c.Case == "source_live_unresolved_terminal" {
		var first, replay model.CapacityMutationRedeemResponse
		firstWire, err := q.ReadPrivate(ctx, filepath.Join(f.private, "source-terminal-first-typed-return.json"), &first)
		if err != nil || capacity.BusinessCreationSHA256(firstWire) != c.FirstSHA256 {
			return q.ErrOriginalUnknown
		}
		replayWire, err := q.ReadPrivate(ctx, filepath.Join(f.private, "source-terminal-replay-typed-return.json"), &replay)
		if err != nil || capacity.BusinessCreationSHA256(replayWire) != c.ReplaySHA256 {
			return q.ErrOriginalUnknown
		}
		if first.Mode != "write_once" || replay.Mode != "read_only" || first.GrantID != c.GrantID || replay.GrantID != c.GrantID || first.AttemptID != c.CallbackAttemptID || replay.AttemptID != c.CallbackAttemptID || first.RequestSHA256 != c.CallbackRequestSHA256 || replay.RequestSHA256 != c.CallbackRequestSHA256 || first.ExpiresAt == "" || first.ExpiresAt != replay.ExpiresAt || first.CompensationOf != "" || replay.CompensationOf != "" {
			return q.ErrOriginalUnknown
		}
		if _, err = uuid.Parse(c.CallbackAttemptID); err != nil || !capacity.ValidDigest(c.CallbackRequestSHA256) {
			return q.ErrOriginalUnknown
		}
		var attempt, requestSHA string
		if err = f.db.QueryRowContext(ctx, `SELECT grant_record->>'attempt_id',grant_record->'grant'->>'request_sha256' FROM public.capacity_mutation_grants WHERE id=$1 AND namespace=$2`, c.GrantID, f.namespace).Scan(&attempt, &requestSHA); err != nil || attempt != c.CallbackAttemptID || requestSHA != c.CallbackRequestSHA256 {
			return q.ErrOriginalUnknown
		}
		var refusal q.SourceTerminalRefusal
		refusalWire, err := q.ReadPrivate(ctx, filepath.Join(f.private, "source-terminal-refusal-return.json"), &refusal)
		if err != nil || capacity.BusinessCreationSHA256(refusalWire) != c.RefusalSHA256 {
			return q.ErrOriginalUnknown
		}
		expected := repository.ErrCapacityConflict.Error() + ": unresolved provider mutation authority"
		if refusal.Schema != "core_original_terminal_refusal_return_v1" || refusal.Representation != "ACTUAL_ERROR_CLASS_COUNT_HASH_NO_RAW_MESSAGE" || refusal.ErrorClass != "repository.ErrCapacityConflict" || refusal.Predicate != "unresolved_provider_mutation_authority" || refusal.ReturnCount != 1 || refusal.ErrorBytes != len(expected) || refusal.ErrorSHA256 != capacity.BusinessCreationSHA256([]byte(expected)) {
			return q.ErrOriginalUnknown
		}
	} else if c.FirstSHA256 != "" || c.RefusalSHA256 != "" || c.CallbackAttemptID != "" || c.CallbackRequestSHA256 != "" {
		return q.ErrOriginalUnknown
	}
	if _, err = q.Publish(ctx, filepath.Join(f.private, "source-terminal-public-returns.json"), f.publicReturns); err != nil {
		return err
	}
	if c.Case == "source_live_unredeemed_abort" {
		paused, err := repository.GetManifestByID(ctx, f.db, f.policy.ID)
		if err != nil || paused.Metadata.Active || paused.Checksum != f.policy.Checksum {
			return q.ErrOriginalUnknown
		}
	}
	f.completedTerminal = map[string]any{"schema": q.FixtureSchema, "stage": "original-terminal-contract-completed.json", "case": c.Case, "scope": c.Scope, "native_qualified": false, "core_source": c.CoreSource, "guest_source": c.GuestSource, "contract_sha256": capacity.BusinessCreationSHA256(wire)}
	return nil
}
