//go:build linux && nativequalification

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityhostfactory"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	err := run(ctx, os.Args[1:])
	cancel()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "host original factory fixture HOLD:", capacityhostfactory.RefusalCode(err))
		os.Exit(78)
	}
}

// This binary is Core/exterior/issuer. httpapi.New serves in THIS process;
// registrar is its only independent control-only child, not a fourth API.
func run(parent context.Context, args []string) (runErr error) {
	if len(args) == 1 && args[0] == "--original-host-factory-registrar" {
		return capacityhostfactory.RunOriginalRegistrar(parent)
	}
	flags := flag.NewFlagSet("native-host-factory-fixture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	private := flags.String("private-dir", "", "Source-owned prepared directory")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !filepath.IsAbs(*private) || filepath.Clean(*private) != *private || os.Getenv("GITHUB_ACTIONS") != "true" {
		return errors.New("host original factory fixture unavailable")
	}
	// NewRealm owns the first and sole UTC/monotonic origin. The compiled
	// Source catalog remains EMPTY, so this returns before DB/API/Start today.
	realm, err := capacityhostfactory.NewOriginalFactoryRealm(parent, *private)
	if err != nil {
		return err
	}
	ctx, err := realm.Context(parent)
	if err != nil {
		return errors.Join(err, realm.CloseAndJoin(parent))
	}
	owners, err := newOriginalFixtureOwners(parent, ctx, realm)
	if err != nil {
		cleanup, cancelCleanup := context.WithDeadline(context.WithoutCancel(parent), originalBound(ctx, parent))
		defer cancelCleanup()
		return errors.Join(err, realm.CloseAndJoin(cleanup))
	}
	defer func() {
		defer owners.cancelCleanup()
		// Only this lexical finalization call exists. Every actual concrete
		// Main resource owner must have returned first, with DB LAST.
		cleanupErr := owners.cleanupOriginalResources()
		runErr = errors.Join(runErr, cleanupErr)
		runErr = errors.Join(runErr, owners.finishOriginalCompletion(*private, cleanupErr))
	}()
	var db *sql.DB
	var broker *amqp.Connection
	var server *http.Server
	// Source-specific owning CI must create/migrate the genuine private DB.
	// This program never seeds healthy phases, counts or a native EMPTY.
	db, err = owners.openOriginalDatabase()
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(24)
	if err = owners.pingOriginalDatabase(ctx); err != nil {
		return err
	}
	broker, err = owners.connectOriginalBroker(ctx)
	if err != nil {
		return err
	}
	if err = message.InstallOriginalHostFactoryQualification(realm); err != nil {
		return err
	}
	owners.workflows, err = httpapi.NewNativeOriginalWorkflowOwners(ctx)
	if err != nil {
		return err
	}
	handler, err := httpapi.New("original-host-factory-fixture", db, broker, zap.NewNop(), httpapi.WithNativeOriginalWorkflowOwners(owners.workflows))
	if err != nil {
		return err
	}
	ca, err := owners.originalPrivateFile(ctx, *private, "core-ca.crt", false)
	if err != nil {
		return err
	}
	certificate, err := owners.originalPrivateFile(ctx, *private, "core-server.crt", false)
	if err != nil {
		return err
	}
	key, err := owners.originalPrivateFile(ctx, *private, "core-server.key", true)
	if err != nil {
		return err
	}
	defer clear(key)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("host original TLS unavailable")
	}
	pair, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return err
	}
	listener, err := owners.openOriginalAPIListener()
	if err != nil {
		return err
	}
	owners.handlers, err = httpapi.NewNativeOriginalWorkflowOwners(ctx)
	if err != nil {
		return errors.Join(err, listener.Close())
	}
	guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, finish, e := owners.handlers.Begin()
		if e != nil {
			http.Error(w, "original owner unavailable", 503)
			return
		}
		defer finish()
		handler.ServeHTTP(w, r)
	})
	server = &http.Server{Handler: guarded, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}}
	owners.server = server
	owners.serveOriginalAPI(tls.NewListener(listener, server.TLSConfig))
	// The genuine protected public workflow/corpus supplier is a separate
	// owning prerequisite. No passed DTO/counter/phase can substitute it.
	return owners.runOriginalProtectedCaller(ctx, db, *private)
}

func (owners *originalFixtureOwners) runOriginalProtectedCaller(ctx context.Context, db *sql.DB, directory string) (runErr error) {
	realm := owners.realm
	call := owners.beginMainReturn("public_caller_return", "main_caller", owners.context.OriginalDeadline)
	defer func() { owners.finishMainReturn(call, runErr, "not_applicable") }()
	if err := realm.VerifyLive(ctx); err != nil {
		return err
	}
	approval, err := realm.Approval(ctx)
	if err != nil {
		return err
	}
	assessment, err := realm.InitialAssessment(ctx)
	if err != nil {
		return err
	}
	// Operator-owned policy/workflow definitions must already exist in the
	// SAME genuine private PG. No native baseline/lease/healthy phase is seeded.
	var policyNS, policyName, workflowNS, workflowName string
	if err = db.QueryRowContext(ctx, `SELECT namespace,name FROM public.manifests WHERE id=$1 AND kind='capacity_policy' AND active`, approval.AllowedPolicyID).Scan(&policyNS, &policyName); err != nil {
		return err
	}
	if err = db.QueryRowContext(ctx, `SELECT namespace,name FROM public.manifests WHERE id=$1 AND kind='workflow' AND active`, approval.AllowedWorkflowID).Scan(&workflowNS, &workflowName); err != nil {
		return err
	}
	if policyNS != approval.AllowedNamespace || workflowNS != approval.AllowedNamespace {
		return errors.New("host original public scope unavailable")
	}
	ca, err := owners.originalPrivateFile(ctx, directory, "core-ca.crt", false)
	if err != nil {
		return err
	}
	cert, err := owners.originalPrivateFile(ctx, directory, "workflow-client.crt", false)
	if err != nil {
		return err
	}
	key, err := owners.originalPrivateFile(ctx, directory, "workflow-client.key", true)
	if err != nil {
		return err
	}
	defer clear(key)
	token, err := owners.originalPrivateFile(ctx, directory, "workflow.token", true)
	if err != nil {
		return err
	}
	defer clear(token)
	if len(token) < 32 || len(token) > 4096 || strings.TrimSpace(string(token)) != string(token) {
		return errors.New("host original public credential unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return errors.New("host original public TLS unavailable")
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{pair}}}
	owners.transport = transport
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	request := model.RunWorkflowRequest{Workflow: model.ManifestSelector{Namespace: workflowNS, Name: workflowName}, Inputs: map[string]any{"policy": model.ManifestSelector{Namespace: policyNS, Name: policyName}, "assessment": assessment}}
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	callHTTP := func(method, path string, body []byte) ([]byte, int, error) {
		return owners.callOriginalPublicWorkflow(ctx, client, method, path, string(token), body)
	}
	// FIRST and SOLE POST. Loss/refusal can only remain uncertain; there is no
	// redispatch/retry/replay or another Claim/context in this caller.
	raw, status, err := callHTTP(http.MethodPost, "/api/v1/workflow-runs", body)
	if err != nil || status != http.StatusAccepted {
		return errors.New("host original public caller HOLD")
	}
	issued, e := decodeOriginalAcceptedPOST(raw, status, request.Workflow)
	if e != nil {
		return e
	}
	owners.publicRunID, owners.publicRunStatus = issued.RunID, issued.Status
	owners.classifyAcceptedOriginalPOST(raw)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return errors.New("host original public caller HOLD")
		case <-ticker.C:
		}
		raw, status, err = callHTTP(http.MethodGet, "/api/v1/workflow-runs/"+issued.RunID, nil)
		if err != nil || status != http.StatusOK {
			return errors.New("host original public caller HOLD")
		}
		var record model.WorkflowRunRecord
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if originalJSONShape(raw) != nil || decoder.Decode(&record) != nil || decoder.Decode(new(any)) != io.EOF || record.ID.String() != issued.RunID {
			return errors.New("host original public caller HOLD")
		}
		owners.publicRunStatus = record.Status
		switch record.Status {
		case "pending", "running":
			continue
		case "failed", "succeeded":
			// A real failed public run can carry sealed A disposition; the live
			// SQL/Realm verifier separately checks branch and all original rows.
			return owners.verifyOriginalPrecloseCorpus(ctx)
		default:
			return errors.New("host original public caller HOLD")
		}
	}
}

// These are private Main-owned NONAUTHORITY return projections. SourceAudit
// records retain concrete subcalls; enclosing methods are a distinct family.
type originalSubjectIdentity struct {
	SubjectKind     string  `json:"subject_kind"`
	RequestIdentity *string `json:"request_identity"`
	PublicRunID     *string `json:"public_run_id"`
	Method          *string `json:"method"`
	PathFamily      *string `json:"path_family"`
}
type originalAuditProjection struct {
	Family                 string                             `json:"family"`
	SubjectIdentity        originalSubjectIdentity            `json:"subject_identity"`
	Fact                   model.HostFactorySourceAuditReturn `json:"fact"`
	OriginalCloseReference *string                            `json:"original_close_reference"`
}
type originalMainReturn struct {
	Family                    string                  `json:"family"`
	Schema                    string                  `json:"schema"`
	Operation                 string                  `json:"operation"`
	OriginalOwnerID           string                  `json:"original_owner_id"`
	SubjectIdentity           originalSubjectIdentity `json:"subject_identity"`
	OriginalHandleID          string                  `json:"original_handle_id"`
	OriginalCallID            *string                 `json:"original_call_id"`
	OriginalState             string                  `json:"original_state"`
	OriginalCalledAt          *time.Time              `json:"original_called_at"`
	OriginalReturnedAt        *time.Time              `json:"original_returned_at"`
	OriginalOperationDeadline time.Time               `json:"original_operation_deadline"`
	OriginalErrorPresent      *bool                   `json:"original_error_present"`
	OriginalReturnClass       *string                 `json:"original_return_class"`
	ActualOwnerJoinState      string                  `json:"actual_owner_join_state"`
	SourceAuditCallReferences []string                `json:"source_audit_call_references"`
}
type originalContextBounds struct {
	OriginalStartedAt       time.Time `json:"original_started_at"`
	OriginalDeadline        time.Time `json:"original_deadline"`
	OriginalCleanupDeadline time.Time `json:"original_cleanup_deadline"`
}
type originalPublicCallerIdentity struct {
	RequestID       *string `json:"request_id"`
	PublicRunID     string  `json:"public_run_id"`
	PublicRunStatus string  `json:"public_run_status"`
}
type originalSourceIdentity struct {
	ScopeRootID              string `json:"scope_root_id"`
	NativeFactoryRootID      string `json:"native_factory_root_id"`
	FactoryAttemptID         string `json:"factory_attempt_id"`
	CreatorOwnerID           string `json:"creator_owner_id"`
	EntryClass               string `json:"entry_class"`
	StableTargetSHA256       string `json:"stable_target_sha256"`
	SourceApprovalBodySHA256 string `json:"source_approval_body_sha256"`
	ApprovedPeerSourceCode   string `json:"approved_peer_source_code"`
	ActualBuildSourceCommit  string `json:"actual_build_source_commit"`
}
type originalHTTPReply struct {
	requestID   string
	method      string
	status      int
	raw         []byte // untouched private cap+1 original buffer; never emitted
	readIndices []int
	pieces      [][]byte // original subreturn buffers, not a sanitized projection
	closeID     *string
	actualEOF   bool
	cause       error
}
type originalFixtureOwners struct {
	mu                                                   sync.Mutex
	realm                                                *capacityhostfactory.OriginalFactoryRealm
	ownerID                                              string
	factoryAttemptID, creatorOwnerID                     string
	context                                              originalContextBounds
	cleanup                                              context.Context
	cancelCleanup                                        context.CancelFunc
	approval                                             model.HostFactorySourceApproval
	root                                                 model.HostFactoryRootPreparation
	db                                                   *sql.DB
	broker                                               *amqp.Connection
	listener                                             net.Listener
	server                                               *http.Server
	handlers, workflows                                  *httpapi.NativeOriginalWorkflowOwners
	transport                                            *http.Transport
	serveDone                                            chan struct{}
	serveCause                                           error
	audits                                               []originalAuditProjection
	methods                                              []*originalMainReturn
	ordered                                              []any
	ordinals                                             map[string]uint64
	mainPrivateSourceHandles                             []string
	mainPrivateSourceFrozen                              bool
	replies                                              []*originalHTTPReply
	preclose                                             []byte
	realmSourceAuditRaw                                  []byte
	precloseCause                                        error
	publicRunID, publicRunStatus                         string
	lastCallerRequest                                    *string
	dbHandle, brokerHandle, listenerHandle, serverHandle string
	handlerHandle, workflowHandle                        string
	brokerCloseReturn, dbCloseReturn                     chan error
}

func originalHash(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }
func originalPointer[T any](v T) *T  { return &v }
func originalBound(ctx, parent context.Context) time.Time {
	deadline, ok := ctx.Deadline()
	if !ok {
		return time.Time{}
	}
	bound := deadline.Add(150 * time.Second)
	if d, ok := parent.Deadline(); ok && d.Before(bound) {
		bound = d
	}
	return bound
}
func newOriginalFixtureOwners(parent, ctx context.Context, realm *capacityhostfactory.OriginalFactoryRealm) (*originalFixtureOwners, error) {
	stages, e := realm.OriginalRootStages(ctx)
	if e != nil {
		return nil, e
	}
	var rootEnvelope, basalEnvelope model.HostFactoryRootSignedEnvelope
	if capacity.DecodeHostFactory(stages["root-preparation"], &rootEnvelope) != nil || capacity.DecodeHostFactory(stages["basal-owner-core"], &basalEnvelope) != nil {
		return nil, errors.New("original Main source unavailable")
	}
	rootRaw, e := base64.StdEncoding.Strict().DecodeString(rootEnvelope.BodyBase64)
	if e != nil {
		return nil, e
	}
	basalRaw, e := base64.StdEncoding.Strict().DecodeString(basalEnvelope.BodyBase64)
	if e != nil {
		return nil, e
	}
	var root model.HostFactoryRootPreparation
	var basal model.HostFactoryBasalOwnerObservation
	if capacity.DecodeHostFactory(rootRaw, &root) != nil || capacity.DecodeHostFactory(basalRaw, &basal) != nil || realm.VerifyOriginalStage(ctx, "root-preparation", stages["root-preparation"]) != nil || realm.VerifyOriginalStage(ctx, "basal-owner-core", stages["basal-owner-core"]) != nil {
		return nil, errors.New("original Main source unavailable")
	}
	approval, e := realm.Approval(ctx)
	if e != nil {
		return nil, e
	}
	bound := originalBound(ctx, parent)
	ceiling := root.OriginalContextStartedAt.Add(13 * time.Minute)
	if bound.After(ceiling) {
		bound = ceiling
	}
	if bound.IsZero() || !bound.After(root.OriginalContextStartedAt) || root.FactoryRootID != basal.FactoryRootID {
		return nil, errors.New("original cleanup unavailable")
	}
	attempt, creator, _, e := realm.OriginalRootIdentity(ctx)
	if e != nil {
		return nil, e
	}
	cleanup, cancel := context.WithDeadline(context.WithoutCancel(parent), bound)
	return &originalFixtureOwners{realm: realm, ownerID: basal.OriginalOwnerID, factoryAttemptID: attempt, creatorOwnerID: creator, context: originalContextBounds{root.OriginalContextStartedAt, root.OriginalContextDeadline, bound}, cleanup: cleanup, cancelCleanup: cancel, approval: approval, root: root, ordinals: map[string]uint64{}}, nil
}

// Called before each concrete I/O. All actual owner call identities are fixed
// here; no public AddFact/time/error/body setter is exposed.
func (o *originalFixtureOwners) beginAudit(operation, handle string, subject originalSubjectIdentity, deadline time.Time) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ordinals[handle]++
	id := handle + ":" + fmt.Sprint(o.ordinals[handle])
	at := time.Now().UTC()
	fact := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: o.root.FactoryRootID, OriginalAuditHandleID: handle, OriginalCallID: &id, Operation: operation, OriginalState: "called_pending", OriginalCalledAt: &at, OriginalOperationDeadline: deadline, OriginalHashState: "unknown_original_bytes"}
	o.audits = append(o.audits, originalAuditProjection{Family: "source_audit", SubjectIdentity: subject, Fact: fact})
	index := len(o.audits) - 1
	o.ordered = append(o.ordered, index)
	return index
}
func (o *originalFixtureOwners) finishAudit(index int, cause error, status *int) {
	at := time.Now().UTC()
	o.mu.Lock()
	defer o.mu.Unlock()
	f := &o.audits[index].Fact
	f.OriginalState, f.OriginalReturnedAt, f.OriginalErrorPresent = "returned", &at, originalPointer(cause != nil)
	f.OriginalHashState, f.OriginalStatusCode = "not_byte_operation", status
}
func (o *originalFixtureOwners) beginMainReturn(operation, subject string, deadline time.Time) *originalMainReturn {
	handle := uuid.NewString()
	id := handle + ":1"
	at := time.Now().UTC()
	r := &originalMainReturn{Family: "main_owner_return", Schema: "source_owned_host_factory_main_owner_return_v1", Operation: operation, OriginalOwnerID: o.ownerID, SubjectIdentity: originalSubjectIdentity{SubjectKind: operation}, OriginalHandleID: handle, OriginalCallID: &id, OriginalState: "called_pending", OriginalCalledAt: &at, OriginalOperationDeadline: deadline, ActualOwnerJoinState: "pending", SourceAuditCallReferences: []string{}}
	o.mu.Lock()
	o.methods = append(o.methods, r)
	o.ordered = append(o.ordered, r)
	o.mu.Unlock()
	_ = subject // private actual concrete method label, never a Host role
	return r
}
func (o *originalFixtureOwners) finishMainReturn(r *originalMainReturn, cause error, join string) {
	at := time.Now().UTC()
	class := "nil_error"
	if cause != nil {
		class = "opaque_error"
		if errors.Is(cause, context.DeadlineExceeded) {
			class = "original_deadline"
		} else if errors.Is(cause, context.Canceled) {
			class = "context_cancelled"
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	r.OriginalState, r.OriginalReturnedAt, r.OriginalErrorPresent, r.OriginalReturnClass = "returned", &at, originalPointer(cause != nil), &class
	r.ActualOwnerJoinState = join
}
func (o *originalFixtureOwners) openOriginalDatabase() (*sql.DB, error) {
	h := uuid.NewString()
	o.dbHandle = h
	i := o.beginAudit("db_open", h, originalSubjectIdentity{SubjectKind: "main_db"}, o.context.OriginalDeadline)
	db, e := sql.Open("postgres", "postgres://postgres:postgres@127.0.0.1:5432/yggdrasil_native_host?sslmode=disable")
	o.db = db
	o.finishAudit(i, e, nil)
	return db, e
}
func (o *originalFixtureOwners) pingOriginalDatabase(ctx context.Context) error {
	i := o.beginAudit("db_ping", o.dbHandle, originalSubjectIdentity{SubjectKind: "main_db"}, o.context.OriginalDeadline)
	e := o.db.PingContext(ctx)
	o.finishAudit(i, e, nil)
	return e
}
func (o *originalFixtureOwners) connectOriginalBroker(ctx context.Context) (*amqp.Connection, error) {
	o.brokerHandle = uuid.NewString()
	i := o.beginAudit("broker_connect", o.brokerHandle, originalSubjectIdentity{SubjectKind: "main_broker"}, o.context.OriginalDeadline)
	c, e := amqp.DialConfig("amqp://guest:guest@127.0.0.1:5672/", amqp.Config{Dial: func(network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
	}})
	o.broker = c
	o.finishAudit(i, e, nil)
	return c, e
}
func (o *originalFixtureOwners) openOriginalAPIListener() (net.Listener, error) {
	o.listenerHandle = uuid.NewString()
	i := o.beginAudit("api_listener_open", o.listenerHandle, originalSubjectIdentity{SubjectKind: "main_api"}, o.context.OriginalDeadline)
	l, e := net.Listen("tcp", "127.0.0.1:19449")
	o.finishAudit(i, e, nil)
	if e != nil {
		return nil, e
	}
	owned := &originalAPIListener{Listener: l, owners: o, handle: o.listenerHandle}
	o.listener = owned
	return owned, nil
}

type originalAPIListener struct {
	net.Listener
	owners     *originalFixtureOwners
	handle     string
	closeOnce  sync.Once
	closeCause error
}

func (l *originalAPIListener) Close() error {
	l.closeOnce.Do(func() {
		i := l.owners.beginAudit("api_listener_close", l.handle, originalSubjectIdentity{SubjectKind: "main_api"}, l.owners.context.OriginalCleanupDeadline)
		l.closeCause = l.Listener.Close()
		l.owners.finishAudit(i, l.closeCause, nil)
	})
	return l.closeCause
}
func (o *originalFixtureOwners) serveOriginalAPI(listener net.Listener) {
	o.serverHandle = uuid.NewString()
	i := o.beginAudit("api_original_serve", o.serverHandle, originalSubjectIdentity{SubjectKind: "main_api"}, o.context.OriginalCleanupDeadline)
	o.serveDone = make(chan struct{})
	go func() { e := o.server.Serve(listener); o.finishAudit(i, e, nil); o.serveCause = e; close(o.serveDone) }()
}
func (o *originalFixtureOwners) callOriginalPublicWorkflow(ctx context.Context, client *http.Client, method, path, bearer string, body []byte) ([]byte, int, error) {
	o.mu.Lock()
	full := len(o.audits)+len(o.methods) >= 65536
	o.mu.Unlock()
	if full {
		return nil, 0, errors.New("original return inventory cap refused")
	}
	requestID := uuid.NewString()
	handle := uuid.NewString()
	family := "same_original_workflow_run"
	var runID *string
	if method == http.MethodPost {
		family = "workflow_run_collection"
	} else if o.publicRunID != "" {
		runID = originalPointer(o.publicRunID)
	}
	subject := originalSubjectIdentity{"public_workflow_http", &requestID, runID, &method, &family}
	reply := &originalHTTPReply{requestID: requestID, method: method}
	o.replies = append(o.replies, reply)

	req, e := http.NewRequestWithContext(ctx, method, "https://127.0.0.1:19449"+path, bytes.NewReader(body))
	if e != nil {
		return nil, 0, e
	}
	req.GetBody = nil
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	i := o.beginAudit("public_workflow_http_do", handle, subject, o.context.OriginalDeadline)
	response, doErr := client.Do(req)
	var status *int
	if response != nil {
		status = &response.StatusCode
		reply.status = response.StatusCode
		if method == http.MethodPost {
			if value := response.Header.Get("X-Request-ID"); value != "" {
				if id, e := uuid.Parse(value); e == nil && id != uuid.Nil && id.String() == value {
					o.lastCallerRequest = &value
				}
			}
		}
	}
	o.finishAudit(i, doErr, status)
	if response == nil || response.Body == nil {
		reply.cause = errors.Join(doErr, errors.New("original body unavailable"))
		return nil, reply.status, reply.cause
	}
	// This aggregate is the actual io.ReadAll GoReturn. Its nested original
	// Body.Read calls retain their own counts/errors (including io.EOF), with
	// scope NULL. A cap never manufactures EOF or a complete body.
	aggregate := o.beginAudit("public_workflow_body_read", handle, subject, o.context.OriginalDeadline)
	reader := &originalHTTPTrackingReader{ctx: ctx, owners: o, source: response.Body, reply: reply, handle: handle, subject: subject, status: status}
	raw, readErr := io.ReadAll(reader)
	returnedAt := time.Now().UTC()
	reply.actualEOF = reader.actualEOF
	o.mu.Lock()
	fact := &o.audits[aggregate].Fact
	fact.OriginalState, fact.OriginalReturnedAt, fact.OriginalErrorPresent = "returned", &returnedAt, originalPointer(readErr != nil)
	fact.OriginalStatusCode, fact.OriginalCount, fact.OriginalEOF = status, originalPointer(int64(len(raw))), originalPointer(reader.actualEOF)
	fact.OriginalHashState = "private_withheld"
	scope := "incomplete_original_body_read"
	if readErr == nil && reader.actualEOF && len(raw) <= 65536 {
		scope = "complete_original_body_read"
	}
	fact.OriginalReadScope = &scope
	prefix := int64(len(raw))
	if prefix > 65536 {
		prefix = 65536
	}
	fact.RetainedPrefixBytes = &prefix
	// Classification later, only of the whole validated FIRST POST, may
	// reveal this OWN aggregate SHA. GET/raw refused bodies remain private.
	reply.readIndices = append(reply.readIndices, aggregate)
	reply.pieces = append(reply.pieces, bytes.Clone(raw))
	o.mu.Unlock()
	i = o.beginAudit("public_workflow_body_close", handle, subject, o.context.OriginalDeadline)
	closeErr := response.Body.Close()
	o.finishAudit(i, closeErr, status)
	o.mu.Lock()
	reply.closeID = o.audits[i].Fact.OriginalCallID
	for _, readIndex := range reply.readIndices {
		o.audits[readIndex].OriginalCloseReference = reply.closeID
	}
	o.mu.Unlock()
	reply.raw = bytes.Clone(raw)
	reply.cause = errors.Join(doErr, readErr, closeErr, ctx.Err())
	if !reply.actualEOF {
		reply.cause = errors.Join(reply.cause, errors.New("original full EOF unavailable"))
	}
	return bytes.Clone(raw), reply.status, reply.cause
}

type originalHTTPTrackingReader struct {
	ctx       context.Context
	owners    *originalFixtureOwners
	source    io.Reader
	reply     *originalHTTPReply
	handle    string
	subject   originalSubjectIdentity
	status    *int
	count     int
	actualEOF bool
}

func (r *originalHTTPTrackingReader) Read(buffer []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, r.ctx.Err()
	}
	remaining := 65537 - r.count
	if remaining <= 0 {
		return 0, errors.New("original public body exceeds source cap")
	}
	if len(buffer) > remaining {
		buffer = buffer[:remaining]
	}
	index := r.owners.beginAudit("public_workflow_body_read", r.handle, r.subject, r.owners.context.OriginalDeadline)
	n, cause := r.source.Read(buffer)
	returnedAt := time.Now().UTC()
	r.owners.mu.Lock()
	fact := &r.owners.audits[index].Fact
	fact.OriginalState, fact.OriginalReturnedAt, fact.OriginalErrorPresent = "returned", &returnedAt, originalPointer(cause != nil)
	fact.OriginalStatusCode, fact.OriginalEOF = r.status, originalPointer(cause == io.EOF)
	if n < 0 || n > len(buffer) {
		fact.OriginalHashState = "unknown_original_bytes"
		r.owners.mu.Unlock()
		return 0, errors.Join(cause, errors.New("original read count refused"))
	}
	fact.OriginalCount, fact.OriginalHashState = originalPointer(int64(n)), "private_withheld"
	piece := bytes.Clone(buffer[:n])
	r.reply.readIndices = append(r.reply.readIndices, index)
	r.reply.pieces = append(r.reply.pieces, piece)
	r.owners.mu.Unlock()
	r.count += n
	r.actualEOF = cause == io.EOF
	if r.count > 65536 {
		return n, errors.Join(cause, errors.New("original public body exceeds source cap"))
	}
	if cause == nil && n == 0 {
		return 0, io.ErrNoProgress
	}
	return n, cause
}
func (o *originalFixtureOwners) classifyAcceptedOriginalPOST(raw []byte) {
	// Only the already-whole-validated FIRST original POST may become public.
	if len(o.replies) == 0 {
		return
	}
	reply := o.replies[0]
	if reply.method != http.MethodPost || reply.status != 202 || reply.cause != nil || !reply.actualEOF || !bytes.Equal(reply.raw, raw) {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for j, index := range reply.readIndices {
		f := &o.audits[index].Fact
		f.OriginalHashState = "actual_public_bytes"
		f.OriginalSHA256 = originalPointer(originalHash(reply.pieces[j]))
		if f.RetainedPrefixBytes != nil {
			n := *f.RetainedPrefixBytes
			f.RetainedPrefixSHA256 = originalPointer(originalHash(reply.pieces[j][:int(n)]))
		}
	}
}
func (o *originalFixtureOwners) verifyOriginalPrecloseCorpus(ctx context.Context) error {
	call := o.beginMainReturn("preclose_verifier_return", "main_preclose", o.context.OriginalDeadline)
	raw, e := (repository.CapacityStore{DB: o.db}).VerifyOriginalHostLiveReadonlyCorpus(ctx, o.realm, o.publicRunID)
	o.preclose, o.precloseCause = bytes.Clone(raw), e
	if len(raw) == 0 || len(raw) > 32*1024*1024 {
		e = errors.Join(e, errors.New("original preclose snapshot unavailable"))
	}
	o.finishMainReturn(call, e, "not_applicable")
	return e
}

// Sole Main finalizer. A refusal from the actual external Persist-return
// capture is a cleanup error and stops ALL finalization/getter/publication.
func (o *originalFixtureOwners) finishOriginalCompletion(directory string, cleanupErr error) error {
	if cleanupErr != nil {
		return cleanupErr
	}
	if len(o.preclose) == 0 {
		return nil
	}
	if err := o.realm.FinalizeOriginalRootCompletion(o.cleanup); err != nil {
		return err
	}
	bundle, err := o.realm.OriginalFinalCorpus(o.cleanup)
	if err != nil {
		return err
	}
	return o.publishOriginalFinalWrapper(directory, bundle)
}

func (o *originalFixtureOwners) cleanupOriginalResources() (runErr error) {
	call := o.beginMainReturn("main_cleanup_return", "main_cleanup", o.context.OriginalCleanupDeadline)
	defer func() {
		state := "joined_actual"
		if runErr != nil {
			state = "pending"
		}
		o.finishMainReturn(call, runErr, state)
	}()
	runErr = o.copyOriginalMainPrivateSourceAuditReferences(call)
	if o.server != nil {
		shutdown, cancel := context.WithTimeout(o.cleanup, 5*time.Second)
		shutdownDeadline, _ := shutdown.Deadline() // SAME actual owning context, before Shutdown
		i := o.beginAudit("api_original_shutdown", o.serverHandle, originalSubjectIdentity{SubjectKind: "main_api"}, shutdownDeadline)
		e := o.server.Shutdown(shutdown)
		cancel()
		o.finishAudit(i, e, nil)
		if e != nil {
			i = o.beginAudit("api_original_close", o.serverHandle, originalSubjectIdentity{SubjectKind: "main_api"}, o.context.OriginalCleanupDeadline)
			actualErr := o.server.Close()
			o.finishAudit(i, actualErr, nil)
			runErr = errors.Join(runErr, e, actualErr)
		}
		select {
		case <-o.serveDone:
			if !errors.Is(o.serveCause, http.ErrServerClosed) {
				runErr = errors.Join(runErr, o.serveCause)
			}
		case <-o.cleanup.Done():
			runErr = errors.Join(runErr, o.cleanup.Err())
		}
	}
	if o.listener != nil {
		runErr = errors.Join(runErr, o.listener.Close())
	}
	for _, owner := range []struct {
		value           *httpapi.NativeOriginalWorkflowOwners
		operation, kind string
	}{{o.handlers, "api_handler_owner_join", "main_handlers"}, {o.workflows, "workflow_owner_join", "main_workflows"}} {
		if owner.value == nil {
			continue
		}
		i := o.beginAudit(owner.operation, uuid.NewString(), originalSubjectIdentity{SubjectKind: owner.kind}, o.context.OriginalCleanupDeadline)
		e := owner.value.Join(o.cleanup)
		o.finishAudit(i, e, nil)
		runErr = errors.Join(runErr, e)

	}
	if o.realm != nil {
		r := o.beginMainReturn("realm_close_join", "main_realm", o.context.OriginalCleanupDeadline)
		e := o.realm.CloseAndJoin(o.cleanup)
		state := "joined_actual"
		if e != nil {
			state = "pending"
		}
		o.finishMainReturn(r, e, state)
		runErr = errors.Join(runErr, e)
		refs, refsErr := o.realm.OriginalPolicyAuditCallReferences(o.cleanup)
		if refsErr == nil {
			r.SourceAuditCallReferences = append([]string(nil), refs...)
		}
		runErr = errors.Join(runErr, refsErr)
		// This cache-only handoff returns the original Source producer's
		// projection bytes. It does not create a Main method/native return or
		// derive a replacement Close relation.
		runErr = errors.Join(runErr, o.copyOriginalRealmSourceAudits())

	}
	if o.db != nil {
		i := o.beginAudit("db_original_query", o.dbHandle, originalSubjectIdentity{SubjectKind: "main_db"}, o.context.OriginalCleanupDeadline)
		closingCalledAt := time.Now().UTC()
		e := (repository.CapacityStore{DB: o.db}).PersistOriginalHostClosingIO(o.cleanup, o.realm)
		closingReturnedAt := time.Now().UTC() // actual sole Persist owning GoReturn
		o.finishAudit(i, e, nil)              // retain the actual Persist error independently
		captureErr := (repository.CapacityStore{DB: o.db}).CaptureOriginalHostClosingReturn(o.cleanup, o.realm, closingCalledAt, closingReturnedAt, e)
		runErr = errors.Join(runErr, e, captureErr)
	}
	if o.transport != nil {
		r := o.beginMainReturn("transport_close_idle", "main_transport", o.context.OriginalCleanupDeadline)
		o.transport.CloseIdleConnections()
		o.finishMainReturn(r, nil, "not_applicable")
	}
	if o.broker != nil {
		i := o.beginAudit("broker_close", o.brokerHandle, originalSubjectIdentity{SubjectKind: "main_broker"}, o.context.OriginalCleanupDeadline)
		returned := make(chan error, 1)
		go func() { e := o.broker.Close(); o.finishAudit(i, e, nil); returned <- e }()
		o.brokerCloseReturn = returned
		select {
		case e := <-returned:
			runErr = errors.Join(runErr, e)
		case <-o.cleanup.Done():
			runErr = errors.Join(runErr, o.cleanup.Err())
		}
	}
	if o.db != nil {
		i := o.beginAudit("db_close", o.dbHandle, originalSubjectIdentity{SubjectKind: "main_db"}, o.context.OriginalCleanupDeadline)
		returned := make(chan error, 1)
		go func() { e := o.db.Close(); o.finishAudit(i, e, nil); returned <- e }()
		o.dbCloseReturn = returned
		select {
		case e := <-returned:
			runErr = errors.Join(runErr, e)
		case <-o.cleanup.Done():
			runErr = errors.Join(runErr, o.cleanup.Err())
		}
	}
	return errors.Join(runErr, o.cleanup.Err())
}
func (o *originalFixtureOwners) copyOriginalRealmSourceAudits() error {
	raw, cause := o.realm.OriginalSourceAudits(o.cleanup)
	o.realmSourceAuditRaw = bytes.Clone(raw) // Exact private projection custody.
	if cause != nil || originalJSONShapeBounded(raw, 1024*1024) != nil {
		return errors.Join(cause, errors.New("original Realm audit incomplete"))
	}
	var rows []json.RawMessage
	if json.Unmarshal(raw, &rows) != nil || len(rows) == 0 || len(rows) > 4096 {
		return errors.New("original Realm audit cap refused")
	}
	seen := map[string]bool{}
	o.mu.Lock()
	for _, prior := range o.audits {
		if prior.Fact.OriginalCallID != nil {
			seen[*prior.Fact.OriginalCallID] = true
		}
	}
	o.mu.Unlock()
	var copied []originalAuditProjection
	for _, row := range rows {
		var fields map[string]json.RawMessage
		if json.Unmarshal(row, &fields) != nil || len(fields) != 4 || fields["family"] == nil || fields["subject_identity"] == nil || fields["fact"] == nil || fields["original_close_reference"] == nil {
			return errors.New("original Realm audit shape refused")
		}
		var family string
		var subject originalSubjectIdentity
		var subjectFields map[string]json.RawMessage
		var fact model.HostFactorySourceAuditReturn
		var closeReference *string
		if json.Unmarshal(fields["family"], &family) != nil || family != "source_audit" || json.Unmarshal(fields["subject_identity"], &subjectFields) != nil || len(subjectFields) != 5 || json.Unmarshal(fields["subject_identity"], &subject) != nil || subject.SubjectKind != "source_file" || subject.RequestIdentity != nil || subject.PublicRunID != nil || subject.Method != nil || subject.PathFamily != nil || capacity.DecodeHostFactory(fields["fact"], &fact) != nil || json.Unmarshal(fields["original_close_reference"], &closeReference) != nil {
			return errors.New("original Realm audit shape refused")
		}
		for _, key := range []string{"subject_kind", "request_identity", "public_run_id", "method", "path_family"} {
			if subjectFields[key] == nil {
				return errors.New("original Realm audit shape refused")
			}
		}
		if fact.FactoryRootID != o.root.FactoryRootID || fact.OriginalCallID == nil || seen[*fact.OriginalCallID] || closeReference != nil && !strings.HasPrefix(*closeReference, fact.OriginalAuditHandleID+":") {
			return errors.New("original Realm audit identity refused")
		}
		seen[*fact.OriginalCallID] = true
		copied = append(copied, originalAuditProjection{Family: family, SubjectIdentity: subject, Fact: fact, OriginalCloseReference: closeReference})
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.audits)+len(copied)+len(o.methods) > 65536 {
		return errors.New("original return inventory cap refused")
	}
	for _, fact := range copied {
		o.audits = append(o.audits, fact)
		o.ordered = append(o.ordered, len(o.audits)-1)
	}
	return nil
}

func (o *originalFixtureOwners) publishOriginalFinalWrapper(directory string, bundle []byte) error {
	// The live SQL snapshot is an independently returned private Source
	// projection. Only its closed safe identity header is copied here.
	var header struct {
		StableTargetSHA256 string `json:"stable_target_sha256"`
	}
	if len(o.preclose) == 0 || json.Unmarshal(o.preclose, &header) != nil || !capacity.ValidDigest(header.StableTargetSHA256) {
		return errors.New("original corpus unavailable")
	}
	attempt, owner := o.factoryAttemptID, o.creatorOwnerID
	approvalRaw, e := capacity.CanonicalHostFactory(o.approval)
	if e != nil {
		return e
	}
	identity := originalSourceIdentity{o.approval.ScopeRootID, o.root.FactoryRootID, attempt, owner, o.root.FactoryEntryClass, header.StableTargetSHA256, originalHash(approvalRaw), o.approval.ApprovedPeerSourceCODE, o.approval.ActualBuildSourceCommit}
	o.mu.Lock()
	var returns []any
	for _, entry := range o.ordered {
		if index, ok := entry.(int); ok {
			fact := o.audits[index]
			if capacity.ValidateHostFactory(fact.Fact) != nil {
				o.mu.Unlock()
				return errors.New("original audit incomplete")
			}
			returns = append(returns, fact)
		} else {
			r := entry.(*originalMainReturn)
			if r.OriginalState != "returned" || r.OriginalErrorPresent == nil || *r.OriginalErrorPresent || r.ActualOwnerJoinState == "pending" || !originalMainReturnRecordBounded(r) {
				o.mu.Unlock()
				return errors.New("original owner incomplete")
			}
			returns = append(returns, r)
		}
	}
	o.mu.Unlock()
	// Source-copied policy audit facts preserve their own acquisition order
	// and immutable CallIDs. The combined stream is ordered by the already
	// captured original call times; no new observation time is produced.
	sort.SliceStable(returns, func(i, j int) bool {
		called := func(value any) *time.Time {
			if fact, ok := value.(originalAuditProjection); ok {
				return fact.Fact.OriginalCalledAt
			}
			return value.(*originalMainReturn).OriginalCalledAt
		}
		a, b := called(returns[i]), called(returns[j])
		return a != nil && b != nil && a.Before(*b)
	})
	wrapper := struct {
		Schema                      string                       `json:"schema"`
		EvidenceClass               string                       `json:"evidence_class"`
		SourceIdentity              originalSourceIdentity       `json:"source_identity"`
		OriginalContext             originalContextBounds        `json:"original_context"`
		PublicCallerIdentity        originalPublicCallerIdentity `json:"public_caller_identity"`
		PrecloseSQLSnapshotBase64   string                       `json:"preclose_sql_snapshot_base64"`
		PrecloseSQLSnapshotSHA256   string                       `json:"preclose_sql_snapshot_sha256"`
		RealmCompletionBundleBase64 string                       `json:"realm_completion_bundle_base64"`
		RealmCompletionBundleSHA256 string                       `json:"realm_completion_bundle_sha256"`
		MainOwnerReturns            []any                        `json:"main_owner_returns"`
		PublicationReturnReference  *string                      `json:"publication_return_reference"`
	}{"source_owned_host_factory_final_corpus_v1", "source_owned_historical_returns_no_native_permission_or_old45_closure", identity, o.context, originalPublicCallerIdentity{o.lastCallerRequest, o.publicRunID, o.publicRunStatus}, base64.StdEncoding.EncodeToString(o.preclose), originalHash(o.preclose), base64.StdEncoding.EncodeToString(bundle), originalHash(bundle), returns, nil}
	raw, e := json.Marshal(wrapper)
	if e != nil || len(raw) > 64*1024*1024 {
		return errors.New("original corpus cap refused")
	}
	return publishOriginalWrapper(directory, raw)
}

type originalAcceptedPOST struct {
	RunID  string
	Status string
}

func originalJSONShape(raw []byte) error {
	return originalJSONShapeBounded(raw, 65536)
}
func originalJSONShapeBounded(raw []byte, limit int) error {
	if len(raw) == 0 || len(raw) > limit || !utf8.Valid(raw) {
		return errors.New("original response cap refused")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 32 {
			return errors.New("original response depth refused")
		}
		token, e := decoder.Token()
		if e != nil {
			return e
		}
		if d, ok := token.(json.Delim); ok {
			switch d {
			case '{':
				keys := map[string]bool{}
				for decoder.More() {
					key, e := decoder.Token()
					name, ok := key.(string)
					if e != nil || !ok || keys[name] {
						return errors.New("original response shape refused")
					}
					keys[name] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			case '[':
				for decoder.More() {
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			default:
				return errors.New("original response shape refused")
			}
			_, e = decoder.Token()
			return e
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := decoder.Token(); e != io.EOF {
		return errors.New("original response trailing refused")
	}
	return nil
}
func decodeOriginalAcceptedPOST(raw []byte, status int, expected model.ManifestSelector) (originalAcceptedPOST, error) {
	var zero originalAcceptedPOST
	if status != 202 || originalJSONShape(raw) != nil {
		return zero, errors.New("original public caller HOLD")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 4 {
		return zero, errors.New("original public caller HOLD")
	}
	for _, name := range []string{"run_id", "status", "workflow", "deduped"} {
		if b, ok := fields[name]; !ok || bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
			return zero, errors.New("original public caller HOLD")
		}
	}
	var response struct {
		RunID    string                 `json:"run_id"`
		Status   string                 `json:"status"`
		Workflow model.ManifestSelector `json:"workflow"`
		Deduped  *bool                  `json:"deduped"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&response) != nil || d.Decode(new(any)) != io.EOF || response.Deduped == nil || *response.Deduped || response.Status != "pending" {
		return zero, errors.New("original public caller HOLD")
	}
	id, e := uuid.Parse(response.RunID)
	if e != nil || id == uuid.Nil || id.String() != response.RunID {
		return zero, errors.New("original public caller HOLD")
	}
	selectorRaw, e := json.Marshal(expected)
	if e != nil {
		return zero, e
	}
	var actual, approved map[string]json.RawMessage
	if json.Unmarshal(fields["workflow"], &actual) != nil || json.Unmarshal(selectorRaw, &approved) != nil || len(actual) != len(approved) {
		return zero, errors.New("original public caller HOLD")
	}
	for key, b := range actual {
		wanted, ok := approved[key]
		if !ok || !bytes.Equal(bytes.TrimSpace(b), bytes.TrimSpace(wanted)) {
			return zero, errors.New("original public caller HOLD")
		}
	}
	return originalAcceptedPOST{response.RunID, response.Status}, nil
}

// Publication is its own original owner. Its returns cannot appear inside the
// immutable wrapper which it writes, avoiding self-reference/future receipt.
func publishOriginalWrapper(directory string, raw []byte) (runErr error) {
	if len(raw) == 0 || len(raw) > 64*1024*1024 || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return errors.New("original corpus unavailable")
	}
	dfd, e := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return e
	}
	dir := os.NewFile(uintptr(dfd), "original-corpus-publication-directory")
	defer func() { runErr = errors.Join(runErr, dir.Close()) }()
	var st unix.Stat_t
	if unix.Fstat(dfd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0777 != 0700 {
		return errors.New("original publication unavailable")
	}
	fd, e := unix.Openat(dfd, ".original-host-final-corpus.tmp", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), "original-corpus-publication")
	n, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if n != len(raw) || writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.Join(writeErr, syncErr, closeErr, io.ErrShortWrite)
	}
	if e = unix.Renameat2(dfd, ".original-host-final-corpus.tmp", dfd, "original-host-final-corpus.json", unix.RENAME_NOREPLACE); e != nil {
		return e
	}
	return dir.Sync()
}

// The consumer already requires each Main owner record to fit 65536 bytes.
// A long actual short-read history stays unavailable; no reference is clipped.
func originalMainReturnRecordBounded(call *originalMainReturn) bool {
	raw, err := json.Marshal(call)
	return err == nil && len(raw) <= 65536
}

// The Main-private census is acquired before its first concrete Open. Realm
// audit copies never enter this registry and cannot select Main-owned streams.
func (o *originalFixtureOwners) registerOriginalMainPrivateSourceHandle(handle string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.mainPrivateSourceFrozen || len(o.mainPrivateSourceHandles) >= 7 {
		return errors.New("original Main private census refused")
	}
	for _, prior := range o.mainPrivateSourceHandles {
		if prior == handle {
			return errors.New("original Main private census refused")
		}
	}
	o.mainPrivateSourceHandles = append(o.mainPrivateSourceHandles, handle)
	return nil
}

// Copy only actual CallIDs of the independently registered Main handles. This
// selection is frozen before cleanup and retains each actual EOF/error/Close.
func (o *originalFixtureOwners) copyOriginalMainPrivateSourceAuditReferences(call *originalMainReturn) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.mainPrivateSourceFrozen || call == nil || call.Operation != "main_cleanup_return" {
		return errors.New("original Main private census refused")
	}
	o.mainPrivateSourceFrozen = true
	if len(o.mainPrivateSourceHandles) != 7 {
		return errors.New("original Main private census refused")
	}
	handles := map[string]bool{}
	for _, handle := range o.mainPrivateSourceHandles {
		handles[handle] = true
	}
	refs := []string{}
	seen := map[string]bool{}
	for _, row := range o.audits {
		if !handles[row.Fact.OriginalAuditHandleID] {
			continue
		}
		if row.SubjectIdentity.SubjectKind != "source_file" || row.Fact.OriginalCallID == nil || seen[*row.Fact.OriginalCallID] {
			return errors.New("original Main private census refused")
		}
		seen[*row.Fact.OriginalCallID] = true
		refs = append(refs, *row.Fact.OriginalCallID)
	}
	call.SourceAuditCallReferences = refs
	return nil
}

// These concrete Main readers own actual SourceAudit Open/Fstat/each Read/EOF
// and independent Close. All original TLS/token input buffers and hashes stay
// private; actual byte counts/errors/EOF/times are safe projections only.
func (owners *originalFixtureOwners) originalPrivateFile(ctx context.Context, directory, name string, private bool) (_ []byte, runErr error) {
	if name != "core-ca.crt" && name != "core-server.crt" && name != "core-server.key" && name != "workflow-client.crt" && name != "workflow-client.key" && name != "workflow.token" {
		return nil, errors.New("original source unavailable")
	}
	handle := uuid.NewString()
	if e := owners.registerOriginalMainPrivateSourceHandle(handle); e != nil {
		return nil, e
	}
	subject := originalSubjectIdentity{SubjectKind: "source_file"}
	i := owners.beginAudit("source_file_open", handle, subject, owners.context.OriginalDeadline)
	indices := []int{i}
	fd, e := unix.Open(filepath.Join(directory, name), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	owners.finishAudit(i, e, nil)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "original-Main-private-source")
	defer func() {
		i := owners.beginAudit("source_file_close", handle, subject, owners.context.OriginalDeadline)
		e := f.Close()
		owners.finishAudit(i, e, nil)
		owners.mu.Lock()
		closeID := owners.audits[i].Fact.OriginalCallID
		owners.audits[i].OriginalCloseReference = closeID
		for _, index := range indices {
			owners.audits[index].OriginalCloseReference = closeID
		}
		owners.mu.Unlock()
		runErr = errors.Join(runErr, e)
	}()
	i = owners.beginAudit("source_file_fstat", handle, subject, owners.context.OriginalDeadline)
	indices = append(indices, i)
	var st unix.Stat_t
	e = unix.Fstat(fd, &st)
	owners.finishAudit(i, e, nil)
	if e != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || (private && st.Mode&0777 != 0600) {
		return nil, errors.New("original source unavailable")
	}
	var raw []byte
	for len(raw) <= 65536 {
		if ctx.Err() != nil {
			return raw, ctx.Err()
		}
		i = owners.beginAudit("source_file_read", handle, subject, owners.context.OriginalDeadline)
		indices = append(indices, i)
		buf := make([]byte, 65537-len(raw))
		n, e := f.Read(buf)
		at := time.Now().UTC()
		if n < 0 || n > len(buf) {
			owners.finishAudit(i, errors.New("original count refused"), nil)
			return raw, errors.New("original count refused")
		}
		owners.mu.Lock()
		fact := &owners.audits[i].Fact
		fact.OriginalState = "returned"
		fact.OriginalReturnedAt = &at
		fact.OriginalErrorPresent = originalPointer(e != nil)
		fact.OriginalCount = originalPointer(int64(n))
		fact.OriginalEOF = originalPointer(e == io.EOF)
		fact.OriginalHashState = "private_withheld"
		owners.mu.Unlock()
		raw = append(raw, buf[:n]...)
		if len(raw) > 65536 {
			return raw, errors.New("original private source cap refused")
		}
		if e == io.EOF {
			if len(raw) == 0 {
				return raw, errors.New("original source empty")
			}
			return raw, nil
		}
		if e != nil {
			return raw, e
		}
		if n == 0 {
			return raw, io.ErrNoProgress
		}
	}
	return raw, errors.New("original source cap refused")
}
