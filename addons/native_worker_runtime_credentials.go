package addons

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

// No ambient AWS chain and no cached temporary keys. Each signing operation
// resolves the same protected managed-secret identity and checks its rotation,
// expiry and artifact scope. Metadata is a binding check, not proof of IAM.
type nativeWorkerArtifactProvider struct {
	*nativeWorkerArtifactProviderState
}
type nativeWorkerArtifactProviderState struct {
	mu     sync.RWMutex
	closed bool
	ctx    context.Context
	cancel context.CancelFunc
	db     *sql.DB
	ref    nativeWorkerArtifactSecret
	scope  nativeWorkerArtifactScope
}

type nativeWorkerArtifactScope struct {
	Schema           string    `json:"schema"`
	CoreSourceCommit string    `json:"core_source_commit"`
	PolicyID         uuid.UUID `json:"policy_id"`
	Profile          string    `json:"profile"`
	Bucket           string    `json:"bucket"`
	Key              string    `json:"key"`
	VersionID        string    `json:"version_id"`
	BucketOwner      string    `json:"bucket_owner"`
	Region           string    `json:"region"`
	Action           string    `json:"action"`
}

func (nativeWorkerArtifactProvider) String() string     { return "[private rotating artifact credentials]" }
func (p nativeWorkerArtifactProvider) GoString() string { return p.String() }
func (nativeWorkerArtifactProvider) MarshalJSON() ([]byte, error) {
	return []byte(`{"private_artifact_credentials":"redacted"}`), nil
}

func nativeArtifactScope(c nativeWorkerRuntimeConfig, profile nativeWorkerProfileFiles) nativeWorkerArtifactScope {
	return nativeWorkerArtifactScope{Schema: "native_worker_artifact_reader_v1", CoreSourceCommit: c.CoreSourceCommit, PolicyID: c.Policy.ID,
		Profile: profile.Profile, Bucket: profile.ArtifactBucket, Key: profile.ArtifactKey, VersionID: profile.ArtifactVersionID,
		BucketOwner: "153828470928", Region: "us-east-1", Action: "s3:GetObjectVersion"}
}

func nativeArtifactScopeSHA(scope nativeWorkerArtifactScope) string {
	raw, _ := json.Marshal(scope)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func newNativeWorkerArtifactProvider(db *sql.DB, ref nativeWorkerArtifactSecret, scope nativeWorkerArtifactScope) (*nativeWorkerArtifactProvider, error) {
	if db == nil || ref.ID == uuid.Nil || !nativeRuntimeName.MatchString(ref.Namespace) || !nativeRuntimeName.MatchString(ref.Name) ||
		!nativeRuntimeSHA.MatchString(ref.ScopeSHA256) || ref.ScopeSHA256 != nativeArtifactScopeSHA(scope) || !nativeRuntimeSource.MatchString(scope.CoreSourceCommit) ||
		scope.PolicyID == uuid.Nil || !nativeRuntimeName.MatchString(scope.Profile) || scope.Bucket == "" || scope.Key == "" || scope.VersionID == "" ||
		scope.Schema != "native_worker_artifact_reader_v1" || scope.BucketOwner != "153828470928" || scope.Region != "us-east-1" || scope.Action != "s3:GetObjectVersion" {
		return nil, errNativeWorkerInstallation
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &nativeWorkerArtifactProvider{&nativeWorkerArtifactProviderState{ctx: ctx, cancel: cancel, db: db, ref: ref, scope: scope}}, nil
}

func (p *nativeWorkerArtifactProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	if p == nil || p.nativeWorkerArtifactProviderState == nil || ctx == nil || ctx.Err() != nil {
		return aws.Credentials{}, errNativeWorkerInstallation
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return aws.Credentials{}, errNativeWorkerInstallation
	}
	call, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.ctx, cancel)
	defer func() { stop(); cancel() }()
	s, err := repository.GetManagedSecret(call, p.db, model.GetManagedSecretRequest{Namespace: p.ref.Namespace, Name: p.ref.Name})
	now := time.Now().UTC()
	if err != nil || call.Err() != nil || s.ID != p.ref.ID || s.Namespace != p.ref.Namespace || s.Name != p.ref.Name || s.Status != "active" || s.Version < 1 ||
		s.ExpiresAt == nil || !s.ExpiresAt.After(now) || len(s.Data) != 3 || len(s.Metadata) != 2 ||
		!nativeArtifactCredentialText(s.Data["access_key_id"], 256) || !nativeArtifactCredentialText(s.Data["secret_access_key"], 4096) || !nativeArtifactCredentialText(s.Data["session_token"], 65536) {
		return aws.Credentials{}, errNativeWorkerInstallation
	}
	raw, err := json.Marshal(s.Metadata)
	var metadata struct {
		Scope       nativeWorkerArtifactScope `json:"artifact_reader"`
		ScopeSHA256 string                    `json:"scope_sha256"`
	}
	// Exact closed metadata avoids adopting a generic provider writer secret.
	if err != nil || capacity.DecodeNativeCapacity(json.RawMessage(raw), &metadata) != nil || metadata.Scope != p.scope || metadata.ScopeSHA256 != p.ref.ScopeSHA256 {
		return aws.Credentials{}, errNativeWorkerInstallation
	}
	return aws.Credentials{AccessKeyID: s.Data["access_key_id"], SecretAccessKey: s.Data["secret_access_key"], SessionToken: s.Data["session_token"],
		CanExpire: true, Expires: s.ExpiresAt.UTC(), Source: "native-worker-managed-artifact-reader"}, nil
}

func nativeArtifactCredentialText(value string, limit int) bool {
	return len(value) > 0 && len(value) <= limit && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func (p *nativeWorkerArtifactProvider) Close() error {
	if p == nil || p.nativeWorkerArtifactProviderState == nil {
		return nil
	}
	// Cancel in-flight private DB resolution before waiting for its read lock.
	p.cancel()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.db = nil
	return nil
}
