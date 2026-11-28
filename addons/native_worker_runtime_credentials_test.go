package addons

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

func TestNativeRuntimeArtifactCredentialsRotateAndNeverOwnDatabase(t *testing.T) {
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := nativeWorkerArtifactScope{Schema: "native_worker_artifact_reader_v1", CoreSourceCommit: strings.Repeat("a", 40), PolicyID: uuid.New(), Profile: "aws", Bucket: "ci-artifact", Key: "operator", VersionID: "fixed", BucketOwner: "153828470928", Region: "us-east-1", Action: "s3:GetObjectVersion"}
	ref := nativeWorkerArtifactSecret{ID: uuid.New(), Namespace: "infra", Name: "artifact-reader", ScopeSHA256: nativeArtifactScopeSHA(scope)}
	p, err := newNativeWorkerArtifactProvider(db, ref, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	meta := map[string]any{"artifact_reader": scope, "scope_sha256": ref.ScopeSHA256}
	expires := time.Now().UTC().Add(time.Minute)
	for _, version := range []int{1, 2} {
		key := fmt.Sprintf("CI_ROTATED_%d", version)
		mock.ExpectQuery(`FROM public.managed_secrets`).WithArgs(ref.Namespace, ref.Name).WillReturnRows(nativeArtifactSecretRows(t, ref.ID, ref.Namespace, ref.Name, "active", version, key, meta, &expires))
		creds, err := p.Retrieve(context.Background())
		if err != nil || creds.AccessKeyID != key || creds.SessionToken != "CI_SESSION" || !creds.CanExpire || !creds.Expires.Equal(expires) {
			t.Fatalf("fresh rotation not used: %v", err)
		}
	}
	// Close is shared across value copies; it refuses even with cached keys in
	// a preceding caller, and does not close the process's borrowed DB.
	copy := *p
	if err := copy.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Retrieve(context.Background()); err == nil {
		t.Fatal("closed provider returned prior credentials")
	}
	mock.ExpectPing()
	if err := db.Ping(); err != nil {
		t.Fatal("provider closed borrowed DB")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRuntimeArtifactCredentialsRefuseDriftExpiryAndMissingToken(t *testing.T) {
	type change struct {
		id                      uuid.UUID
		namespace, name, status string
		version                 int
		metadata                map[string]any
		expiry                  *time.Time
		data                    map[string]string
	}
	scope := nativeWorkerArtifactScope{Schema: "native_worker_artifact_reader_v1", CoreSourceCommit: strings.Repeat("a", 40), PolicyID: uuid.New(), Profile: "aws", Bucket: "ci-artifact", Key: "operator", VersionID: "fixed", BucketOwner: "153828470928", Region: "us-east-1", Action: "s3:GetObjectVersion"}
	ref := nativeWorkerArtifactSecret{ID: uuid.New(), Namespace: "infra", Name: "artifact-reader", ScopeSHA256: nativeArtifactScopeSHA(scope)}
	future, past := time.Now().UTC().Add(time.Minute), time.Now().UTC().Add(-time.Second)
	changes := map[string]func(*change){
		"wrong ID": func(c *change) { c.id = uuid.New() }, "namespace": func(c *change) { c.namespace = "other" }, "name": func(c *change) { c.name = "other" },
		"disabled": func(c *change) { c.status = "disabled" }, "revoked": func(c *change) { c.status = "revoked" }, "version": func(c *change) { c.version = 0 },
		"expired": func(c *change) { c.expiry = &past }, "no expiry": func(c *change) { c.expiry = nil },
		"source": func(c *change) {
			s := scope
			s.CoreSourceCommit = strings.Repeat("b", 40)
			c.metadata["artifact_reader"] = s
		},
		"scope":            func(c *change) { c.metadata["scope_sha256"] = strings.Repeat("b", 64) },
		"writer action":    func(c *change) { s := scope; s.Action = "ec2:RunInstances"; c.metadata["artifact_reader"] = s },
		"other artifact":   func(c *change) { s := scope; s.VersionID = "other"; c.metadata["artifact_reader"] = s },
		"unknown metadata": func(c *change) { c.metadata["other"] = true },
		"no token":         func(c *change) { delete(c.data, "session_token") }, "empty token": func(c *change) { c.data["session_token"] = "" },
		"extra key": func(c *change) { c.data["provider_write_key"] = "CI_MUST_REFUSE" },
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			p, err := newNativeWorkerArtifactProvider(db, ref, scope)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			c := change{id: ref.ID, namespace: ref.Namespace, name: ref.Name, status: "active", version: 1, metadata: map[string]any{"artifact_reader": scope, "scope_sha256": ref.ScopeSHA256}, expiry: &future, data: map[string]string{"access_key_id": "CI_ACCESS", "secret_access_key": "CI_SECRET", "session_token": "CI_SESSION"}}
			mutate(&c)
			data, _ := json.Marshal(c.data)
			// Each failure is a real GetManagedSecret query/scan, with no fallback.
			rows := sqlmock.NewRows([]string{"id", "namespace", "name", "status", "version", "data", "metadata", "rotation", "last_rotated_at", "expires_at", "created_at", "updated_at"}).AddRow(c.id, c.namespace, c.name, c.status, c.version, data, mustNativeJSON(t, c.metadata), []byte(`{}`), future, c.expiry, future, future)
			mock.ExpectQuery(`FROM public.managed_secrets`).WithArgs(ref.Namespace, ref.Name).WillReturnRows(rows)
			if creds, err := p.Retrieve(context.Background()); err == nil || creds.AccessKeyID != "" {
				t.Fatal("invalid secret became credentials")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A caller cannot relabel arbitrary scope as this artifact's read authority.
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	bad := ref
	bad.ScopeSHA256 = strings.Repeat("c", 64)
	if _, err := newNativeWorkerArtifactProvider(db, bad, scope); err == nil {
		t.Fatal("unrelated private scope accepted")
	}
}

func nativeArtifactSecretRows(t *testing.T, id uuid.UUID, namespace, name, status string, version int, key string, metadata map[string]any, expiry *time.Time) *sqlmock.Rows {
	t.Helper()
	now := time.Now().UTC()
	return sqlmock.NewRows([]string{"id", "namespace", "name", "status", "version", "data", "metadata", "rotation", "last_rotated_at", "expires_at", "created_at", "updated_at"}).AddRow(id, namespace, name, status, version, mustNativeJSON(t, map[string]string{"access_key_id": key, "secret_access_key": "CI_SECRET", "session_token": "CI_SESSION"}), mustNativeJSON(t, metadata), []byte(`{}`), now, expiry, now, now)
}

func TestNativeRuntimeArtifactCloseCancelsPrivateResolution(t *testing.T) {
	started := make(chan struct{})
	db, mock, err := sqlmock.New(sqlmock.MonitorPingsOption(true), sqlmock.QueryMatcherOption(sqlmock.QueryMatcherFunc(func(expected, actual string) error {
		if err := sqlmock.QueryMatcherRegexp.Match(expected, actual); err != nil {
			return err
		}
		close(started)
		return nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	scope := nativeWorkerArtifactScope{Schema: "native_worker_artifact_reader_v1", CoreSourceCommit: strings.Repeat("a", 40), PolicyID: uuid.New(), Profile: "aws", Bucket: "ci-artifact", Key: "operator", VersionID: "fixed", BucketOwner: "153828470928", Region: "us-east-1", Action: "s3:GetObjectVersion"}
	ref := nativeWorkerArtifactSecret{ID: uuid.New(), Namespace: "infra", Name: "artifact-reader", ScopeSHA256: nativeArtifactScopeSHA(scope)}
	p, err := newNativeWorkerArtifactProvider(db, ref, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	expires := time.Now().UTC().Add(time.Minute)
	mock.ExpectQuery(`FROM public.managed_secrets`).WithArgs(ref.Namespace, ref.Name).WillDelayFor(10 * time.Second).WillReturnRows(nativeArtifactSecretRows(t, ref.ID, ref.Namespace, ref.Name, "active", 1, "CI_ACCESS", map[string]any{"artifact_reader": scope, "scope_sha256": ref.ScopeSHA256}, &expires))
	returned := make(chan error, 1)
	go func() { _, err := p.Retrieve(context.Background()); returned <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("private read did not start")
	}
	closed := make(chan error, 1)
	go func() { closed <- p.Close() }()
	select {
	case err := <-returned:
		if err == nil {
			t.Fatal("closed owner accepted private resolution")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel private DB read")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join private DB read")
	}
	mock.ExpectPing()
	if err := db.Ping(); err != nil {
		t.Fatal("borrowed DB closed")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func mustNativeJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
