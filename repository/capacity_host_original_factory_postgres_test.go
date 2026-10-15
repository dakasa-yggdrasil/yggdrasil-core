package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityhostfactory"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type hostFactoryBuildStream struct {
	ReadCalledAt, ReadReturnedAt, CloseReturnedAt time.Time
	Bytes                                         int64
	EOF                                           bool
	ReadFailed, CloseFailed                       bool
}

// This owner is invoked only by the owning remote Source job. It builds code
// and reads Go build metadata; it never executes a compiled fixture/test CLI.
func TestHostOriginalFactoryRemoteSourceBuildOwner(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	if os.Getenv("REQUIRE_CAPACITY_HOST_ORIGINAL_SOURCE_BUILDS") != "true" {
		t.Skip("remote owning Source build gate not requested")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("Source build owner requires the owning GitHub Actions job")
	}
	root := os.Getenv("RUNNER_TEMP")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("original RUNNER_TEMP required")
	}
	directory, err := os.MkdirTemp(root, "host-factory-source-build-")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	// The same original bounded context owns every child; no timeout renewal.
	type build struct {
		name string
		args []string
	}
	builds := []build{{"ordinary-worker", []string{"build", "-mod=readonly", "-buildvcs=true", "-tags", "nativequalification", "-o", filepath.Join(directory, "ordinary-worker"), "./cmd/original-host-factory-worker"}}, {"host-fixture", []string{"build", "-mod=readonly", "-buildvcs=true", "-tags", "nativequalification", "-o", filepath.Join(directory, "host-fixture"), "./cmd/native-host-factory-fixture"}}, {"native-reader-tests", []string{"test", "-c", "-mod=readonly", "-buildvcs=true", "-tags", "nativequalification", "-o", filepath.Join(directory, "native-reader-tests"), "./repository"}}}
	if !hostFactoryBuildCommand(t, ctx, directory, "clean-before", "git", []string{"status", "--porcelain", "--untracked-files=normal"}, true) {
		t.Fatal("owning source checkout is not clean")
	}
	if !hostFactoryBuildCommand(t, ctx, directory, "checkout-head", "git", []string{"rev-parse", "HEAD"}, false) {
		t.Fatal("actual checkout head unavailable")
	}
	for _, b := range builds {
		if !hostFactoryBuildCommand(t, ctx, directory, b.name, "go", b.args, false) {
			continue
		}
		binary := filepath.Join(directory, b.name)
		if !hostFactoryBuildCommand(t, ctx, directory, b.name+"-metadata", "go", []string{"version", "-m", binary}, false) {
			continue
		}
		f, err := os.Open(binary)
		if err != nil {
			t.Error("actual build artifact missing", err)
			continue
		}
		hash := sha256.New()
		_, readErr := io.Copy(hash, io.LimitReader(f, 512<<20))
		closeErr := f.Close()
		info, statErr := os.Stat(binary)
		if readErr != nil || closeErr != nil || statErr != nil || info.Size() <= 0 || info.Size() >= 512<<20 {
			t.Error("actual build artifact identity incomplete")
			continue
		}
		if err = os.WriteFile(binary+".sha256", []byte(fmt.Sprintf("%x\n", hash.Sum(nil))), 0600); err != nil {
			t.Error("actual artifact hash retention failed", err)
		}
	}
	if !hostFactoryBuildCommand(t, ctx, directory, "clean-after", "git", []string{"status", "--porcelain", "--untracked-files=normal"}, true) {
		t.Error("Source build changed the original checkout")
	}
}

func hostFactoryBuildCommand(t *testing.T, ctx context.Context, directory, name, program string, args []string, requireEmpty bool) bool {
	t.Helper()
	stdoutFile, err := os.OpenFile(filepath.Join(directory, name+".stdout.raw"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Error(err)
		return false
	}
	stderrFile, err := os.OpenFile(filepath.Join(directory, name+".stderr.raw"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = stdoutFile.Close()
		t.Error(err)
		return false
	}
	command := exec.CommandContext(ctx, program, args...)
	// Tests start in repository/. Keep every compiler output outside checkout.
	command.Dir = ".."
	command.Env = append(os.Environ(), "GOWORK=off")
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
		t.Error(err)
		return false
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		_ = stdout.Close()
		_ = stdoutFile.Close()
		_ = stderrFile.Close()
		t.Error(err)
		return false
	}
	calledAt := time.Now().UTC()
	startErr := command.Start()
	startedAt := time.Now().UTC()
	var out, diagnostic hostFactoryBuildStream
	var waitCalledAt, waitReturnedAt time.Time
	var waitErr error
	if startErr == nil {
		done := make(chan struct{})
		watchJoined := make(chan struct{})
		var joins sync.WaitGroup
		joins.Add(2)
		read := func(source io.ReadCloser, dest *os.File, result *hostFactoryBuildStream) {
			defer joins.Done()
			result.ReadCalledAt = time.Now().UTC()
			var buffer [32768]byte
			for {
				n, readErr := source.Read(buffer[:])
				if n > 0 {
					result.Bytes += int64(n)
					if result.Bytes > 64<<20 {
						result.ReadFailed = true
						break
					}
					if written, e := dest.Write(buffer[:n]); e != nil || written != n {
						result.ReadFailed = true
						break
					}
				}
				if readErr != nil {
					result.EOF = errors.Is(readErr, io.EOF)
					result.ReadFailed = !result.EOF
					break
				}
			}
			result.ReadReturnedAt = time.Now().UTC()
			result.CloseFailed = source.Close() != nil
			result.CloseReturnedAt = time.Now().UTC()
		}
		go read(stdout, stdoutFile, &out)
		go read(stderr, stderrFile, &diagnostic)
		go func() {
			defer close(watchJoined)
			select {
			case <-ctx.Done():
				_ = stdout.Close()
				_ = stderr.Close()
			case <-done:
			}
		}()
		// Drain real EOF before Wait, which otherwise closes StdoutPipe early.
		joins.Wait()
		close(done)
		<-watchJoined
		waitCalledAt = time.Now().UTC()
		waitErr = command.Wait()
		waitReturnedAt = time.Now().UTC()
	} else {
		_ = stdout.Close()
		_ = stderr.Close()
	}
	outClose := stdoutFile.Close()
	stderrClose := stderrFile.Close()
	returnedAt := time.Now().UTC()
	deadline, _ := ctx.Deadline()
	record := struct {
		Program                                                                               string
		Args                                                                                  []string
		OriginalDeadline, CalledAt, StartReturnedAt, WaitCalledAt, WaitReturnedAt, ReturnedAt time.Time
		Stdout, Stderr                                                                        hostFactoryBuildStream
		StartFailed, WaitFailed, OutputCloseFailed, ContextFailed                             bool
		Qualification                                                                         string
	}{program, args, deadline, calledAt, startedAt, waitCalledAt, waitReturnedAt, returnedAt, out, diagnostic, startErr != nil, waitErr != nil, outClose != nil || stderrClose != nil, ctx.Err() != nil, "SOURCE_BUILD_ONLY_FULL_CORE_NATIVE_PENDING"}
	raw, encodeErr := json.Marshal(record)
	retainErr := encodeErr
	if encodeErr == nil {
		retainErr = os.WriteFile(filepath.Join(directory, name+".return.json"), append(raw, '\n'), 0600)
	}
	ok := startErr == nil && waitErr == nil && outClose == nil && stderrClose == nil && ctx.Err() == nil && !deadline.IsZero() && returnedAt.Before(deadline) && out.EOF && diagnostic.EOF && !out.ReadFailed && !diagnostic.ReadFailed && !out.CloseFailed && !diagnostic.CloseFailed && retainErr == nil && (!requireEmpty || out.Bytes == 0)
	if !ok {
		t.Error("original remote Source command incomplete:", name)
	}
	return ok
}

// These cases exercise real PostgreSQL constraints and source algorithms with
// explicit protocol vectors. They never install a source approval, acquire a
// native handle, execute a process, or qualify an original native supplier.
func hostFactoryPostgres(t *testing.T) *sql.DB {
	t.Helper()
	hostFactorySourceCaseStatus(t)
	if os.Getenv("DB_URL") == "" {
		if os.Getenv("REQUIRE_CAPACITY_HOST_ORIGINAL_POSTGRES") == "true" {
			t.Fatal("DB_URL required by Host source PostgreSQL gate")
		}
		t.Skip("Host source PostgreSQL corpus runs in CI")
	}
	return guestOriginalPostgres(t)
}

func hostFactorySourceCaseStatus(t *testing.T) {
	t.Helper()
	root := os.Getenv("RUNNER_TEMP")
	if root == "" {
		return
	}
	name := strings.ReplaceAll(t.Name(), "/", "-")
	t.Cleanup(func() {
		status := "observed_not_failed_at_cleanup_partial"
		if t.Failed() {
			status = "observed_failed_at_cleanup_partial"
		}
		if t.Skipped() {
			status = "observed_skipped_at_cleanup_incomplete"
		}
		body, err := json.Marshal(struct {
			Case, Status, Qualification, Native string
			Old45Closed                         int
		}{name, status, "SOURCE_PG_ONLY", "FULL_CORE_NATIVE_PENDING", 0})
		if err != nil {
			t.Error("Source census encode failed")
			return
		}
		if err = os.WriteFile(filepath.Join(root, "host-factory-source-case-"+name+".json"), append(body, '\n'), 0600); err != nil {
			t.Error("Source census retention failed")
		}
	})
}

type hostFactoryStorageVector struct {
	root, owner, handle, binding, primitive string
	start                                   time.Time
}

func hostFactoryStorageRoot(t *testing.T, tx *sql.Tx) hostFactoryStorageVector {
	t.Helper()
	f := hostFactoryStorageVector{root: uuid.NewString(), owner: uuid.NewString(), handle: uuid.NewString(), binding: strings.Repeat("a", 64), primitive: strings.Repeat("b", 64), start: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	// Deliberately invalid native bodies: direct schema fixture insertion
	// proves storage constraints only. Public admission rejects these bytes.
	raw := []byte(`{"storage_vector_only":true}`)
	_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_roots(scope_root_id,factory_realm_id,factory_attempt_id,creator_owner_id,factory_registry_class,root_key_sha256,source_approval_sha256,source_approval_wire,root_preparation_sha256,root_preparation_wire,original_started_at,original_deadline,root_device,root_inode,source_closure_sha256) VALUES($1,$2,$3,$4,'original_source_owned_factory',$5,$6,$7,$8,$7,$9,$10,1,$11,$12)`, f.root, uuid.NewString(), uuid.NewString(), f.owner, capacity.HostFactoryRawSHA256([]byte(f.root)), f.binding, raw, capacity.HostFactoryRawSHA256([]byte("prep/"+f.root)), f.start, f.start.Add(600*time.Second), time.Now().UnixNano(), f.primitive)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func hostFactoryStorageTx(t *testing.T) (*sql.Tx, hostFactoryStorageVector) {
	t.Helper()
	tx, err := hostFactoryPostgres(t).BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx, hostFactoryStorageRoot(t, tx)
}

func hostFactoryStoragePtr[T any](v T) *T { return &v }

// Unsigned SQL/FIRST vectors use legacy SourceApproval only; this is not
// native/source admission. Exact Source Scope refusals remain separately owned.
func (f hostFactoryStorageVector) chunk(first, last uint64, pending bool) model.HostFactoryCallVectorChunk {
	c := model.HostFactoryCallVectorChunk{Schema: "original_host_factory_call_vector_chunk_v2", Purpose: "original_host_factory_call_vector_chunk_v2", BindingSchema: "original_host_factory_source_approval_v4", BindingSHA256: f.binding, OwnerRole: "host_exterior", OriginalOwnerID: f.owner, OwnerPrimitiveRawSHA256: f.primitive, Operation: "stdout_read", OriginalHandleID: f.handle, FirstOrdinal: first, LastOrdinal: last, RecordedAt: f.start.Add(time.Second)}
	for ordinal := first; ordinal <= last; ordinal++ {
		called := f.start.Add(time.Duration(ordinal*2) * time.Microsecond)
		r := model.HostFactoryPrimitiveIOReturn{Operation: c.Operation, OriginalHandleID: f.handle, SubjectOwnerID: f.owner, OwnerPrimitiveRawSHA256: &f.primitive, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: hostFactoryStoragePtr(called.Add(time.Microsecond)), OriginalCount: hostFactoryStoragePtr(int64(0)), OriginalSHA256: hostFactoryStoragePtr(capacity.HostFactoryRawSHA256(nil)), OriginalReturnClass: "success", OriginalOperationDeadline: f.start.Add(60 * time.Second), OriginalHashState: "actual_public_bytes", OriginalEOF: hostFactoryStoragePtr(false), OriginalCallOrdinal: hostFactoryStoragePtr(ordinal), OriginalCallID: hostFactoryStoragePtr(fmt.Sprintf("%s:%d", f.handle, ordinal))}
		if pending {
			r.OriginalState = "called_pending"
			r.OriginalReturnedAt = nil
			r.OriginalCount = nil
			r.OriginalSHA256 = nil
			r.OriginalReturnClass = "unavailable"
			r.OriginalHashState = "unknown_original_bytes"
			r.OriginalEOF = nil
			c.RecordedAt = called
		}
		c.OriginalCalls = append(c.OriginalCalls, r)
	}
	return c
}

func hostFactoryStorageAppend(t *testing.T, tx *sql.Tx, f hostFactoryStorageVector, c model.HostFactoryCallVectorChunk) (hostFactoryIOIdentity, []byte) {
	t.Helper()
	raw, err := capacity.CanonicalHostFactory(c)
	if err != nil {
		t.Fatal(err)
	}
	x, err := originalHostIOIdentity(hostOriginalConstraintCodec(), f.root, &c, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = appendOriginalHostChunkTx(context.Background(), tx, x, c, raw, []byte(`{"storage_envelope_only":true}`)); err != nil {
		t.Fatal(err)
	}
	return x, raw
}

func hostFactoryStorageManifest(t *testing.T, tx *sql.Tx, f hostFactoryStorageVector, last uint64, children ...string) {
	t.Helper()
	m := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: "original_host_factory_source_approval_v4", BindingSHA256: f.binding, OwnerRole: "host_exterior", OriginalOwnerID: f.owner, OwnerPrimitiveRawSHA256: f.primitive, Operation: "stdout_read", OriginalHandleID: f.handle, Level: 0, FirstOrdinal: 1, LastOrdinal: last, OriginalCallCount: last, ChildBodySHAs: children, CollectionState: "complete_original_calls"}
	raw, err := capacity.CanonicalHostFactory(m)
	if err != nil {
		t.Fatal(err)
	}
	x, err := originalHostIOIdentity(hostOriginalConstraintCodec(), f.root, &m, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = appendOriginalHostIOBodyTx(context.Background(), tx, x, raw, []byte(`{"storage_envelope_only":true}`)); err != nil {
		t.Fatal(err)
	}
	if err = validateOriginalHostManifestTx(context.Background(), tx, x, m); err != nil {
		t.Fatal(err)
	}
}

func TestHostOriginalFactoryPostgresSchemaAndImmutability(t *testing.T) {
	tx, f := hostFactoryStorageTx(t)
	var tables int
	if err := tx.QueryRow(`SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('capacity_host_factory_roots','capacity_host_factory_stable_targets','capacity_host_factory_owners','capacity_host_factory_scopes','capacity_host_factory_leases','capacity_host_factory_stage_returns','capacity_host_factory_registrations','capacity_factory_original_grant_bindings','capacity_host_factory_issued_attachments','capacity_host_factory_sealed_reservations','capacity_host_factory_dispositions','capacity_host_factory_io_returns','capacity_host_factory_call_snapshot_links')`).Scan(&tables); err != nil || tables != 13 {
		t.Fatal("exact SQL13 tables absent", err)
	}
	for _, stmt := range []string{`UPDATE public.capacity_host_factory_roots SET original_deadline=original_deadline+interval '1 second' WHERE scope_root_id=$1`, `DELETE FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`} {
		if _, err := tx.Exec(`SAVEPOINT refused`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(stmt, f.root); err == nil {
			t.Fatal("immutable original root changed")
		}
		if _, err := tx.Exec(`ROLLBACK TO SAVEPOINT refused`); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHostOriginalFactoryPostgresAwaitingOwnerOnceFill(t *testing.T) {
	tx, f := hostFactoryStorageTx(t)
	var attempt string
	if err := tx.QueryRow(`SELECT factory_attempt_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, f.root).Scan(&attempt); err != nil {
		t.Fatal(err)
	}
	targetRaw := []byte(`{"storage_target_only":"` + f.root + `"}`)
	targetSHA := capacity.HostFactoryRawSHA256(targetRaw)
	awaitingRaw := []byte(`{"storage_awaiting_only":"` + f.root + `"}`)
	// Storage vectors deliberately carry no native supplier facts or authority.
	_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_stable_targets(stable_target_sha256,target_wire,root_id,namespace,environment,domain,dimension,target_identity,mutation_binding_name,slot,factory_class,integration_instance_id,integration_type_id,integration_checksum,integration_type_checksum,scope_checksum,profile_name,factory_attempt_id,original_owner_id,entry_class) VALUES($1,$2,$3,$3::text,'storage','storage','storage',$3::text,'storage',1,'original_source_owned_factory',$4,$5,$6,$6,$6,'storage',$7,$8,'sealed_a0')`, targetSHA, targetRaw, f.root, uuid.NewString(), uuid.NewString(), f.binding, attempt, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO public.capacity_host_factory_owners(owner_id,root_id,attempt_id,stable_target_sha256,state,awaiting_sha256,awaiting_wire) VALUES($1,$2,$3,$4,'awaiting_native_preparation',$5,$6)`, f.owner, f.root, attempt, targetSHA, capacity.HostFactoryRawSHA256(awaitingRaw), awaitingRaw)
	if err != nil {
		t.Fatal(err)
	}
	var noFutureFacts bool
	if err = tx.QueryRow(`SELECT prepared_handle_id IS NULL AND worker_primitive_sha256 IS NULL AND prepared_plan_sha256 IS NULL AND prepared_plan_wire IS NULL AND native_registration_wire IS NULL FROM public.capacity_host_factory_owners WHERE owner_id=$1`, f.owner).Scan(&noFutureFacts); err != nil || !noFutureFacts {
		t.Fatal("awaiting owner acquired future preparation facts", err)
	}
	refuse := func(stmt string, args ...any) {
		t.Helper()
		if _, err := tx.Exec(`SAVEPOINT owner_refusal`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(stmt, args...); err == nil {
			t.Fatal("immutable awaiting/prepared owner mutation accepted")
		}
		if _, err := tx.Exec(`ROLLBACK TO SAVEPOINT owner_refusal`); err != nil {
			t.Fatal(err)
		}
	}
	refuse(`UPDATE public.capacity_host_factory_owners SET awaiting_wire=$2 WHERE owner_id=$1`, f.owner, []byte(`{"replacement":true}`))
	refuse(`UPDATE public.capacity_host_factory_owners SET prepared_handle_id=$2 WHERE owner_id=$1`, f.owner, f.handle)
	refuse(`UPDATE public.capacity_host_factory_owners SET state='registered' WHERE owner_id=$1`, f.owner)
	refuse(`UPDATE public.capacity_host_factory_owners SET root_id=$2 WHERE owner_id=$1`, f.owner, uuid.NewString())
	refuse(`DELETE FROM public.capacity_host_factory_owners WHERE owner_id=$1`, f.owner)
	plan := []byte(`{"storage_prepared_only":true}`)
	registration := []byte(`{"storage_registration_only":true}`)
	filled, err := tx.Exec(`UPDATE public.capacity_host_factory_owners SET state='registered',prepared_handle_id=$2,worker_primitive_sha256=$3,prepared_plan_sha256=$4,prepared_plan_wire=$5,native_registration_wire=$6 WHERE owner_id=$1`, f.owner, f.handle, capacity.HostFactoryRawSHA256([]byte(f.owner)), capacity.HostFactoryRawSHA256(plan), plan, registration)
	if err != nil {
		t.Fatal(err)
	}
	count, err := filled.RowsAffected()
	if err != nil || count != 1 {
		t.Fatal("original once-fill did not change exactly one owner", err)
	}
	var retained []byte
	if err = tx.QueryRow(`SELECT awaiting_wire FROM public.capacity_host_factory_owners WHERE owner_id=$1`, f.owner).Scan(&retained); err != nil || !bytes.Equal(retained, awaitingRaw) {
		t.Fatal("original awaiting buffer changed at preparation return", err)
	}
	refuse(`UPDATE public.capacity_host_factory_owners SET prepared_handle_id=$2 WHERE owner_id=$1`, f.owner, uuid.NewString())
	refuse(`UPDATE public.capacity_host_factory_owners SET state='awaiting_native_preparation',prepared_handle_id=NULL,worker_primitive_sha256=NULL,prepared_plan_sha256=NULL,prepared_plan_wire=NULL,native_registration_wire=NULL WHERE owner_id=$1`, f.owner)
	refuse(`DELETE FROM public.capacity_host_factory_owners WHERE owner_id=$1`, f.owner)
}

func TestHostOriginalFactoryPostgresOrdinaryCallbackOmittedRealmHolds(t *testing.T) {
	tx, f := hostFactoryStorageTx(t)
	var attempt string
	if err := tx.QueryRow(`SELECT factory_attempt_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, f.root).Scan(&attempt); err != nil {
		t.Fatal(err)
	}
	p := model.CapacityPolicySpec{Environment: "storage", Domain: "storage", Dimension: "storage", TargetIdentity: f.root}
	b := model.CapacityMutationBinding{Name: "storage", IntegrationInstanceID: uuid.NewString(), IntegrationTypeID: uuid.NewString(), IntegrationChecksum: f.binding, IntegrationTypeChecksum: f.binding, ScopeChecksum: f.binding, ProfileName: "storage"}
	targetRaw, target, err := originalHostStableTarget(f.root, p, b.Name, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO public.capacity_host_factory_stable_targets(stable_target_sha256,target_wire,root_id,namespace,environment,domain,dimension,target_identity,mutation_binding_name,slot,factory_class,integration_instance_id,integration_type_id,integration_checksum,integration_type_checksum,scope_checksum,profile_name,factory_attempt_id,original_owner_id,entry_class) VALUES($1,$2,$3,$3::text,'storage','storage','storage',$3::text,'storage',1,'original_source_owned_factory',$4,$5,$6,$6,$6,'storage',$7,$8,'ordinary_original_create')`, target, targetRaw, f.root, b.IntegrationInstanceID, b.IntegrationTypeID, f.binding, attempt, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	if realm, _, installed := OriginalHostFactoryRealm(); installed || realm != nil {
		t.Fatal("storage corpus unexpectedly has actual native supplier")
	}
	store := CapacityStore{}
	record := capacityMutationRecord{Binding: b, Grant: model.CapacityMutationGrant{GrantID: uuid.NewString(), Slot: 1}}
	request := model.CapacityMutationRedeemRequest{GrantID: record.Grant.GrantID, AttemptID: uuid.NewString()}
	for _, requests := range [][]hostOriginalCallbackRequest{nil, {{principal: "storage", redeem: &request}}} {
		handled, err := store.guardOriginalOrdinaryCallbackTx(context.Background(), tx, record, f.root, p, requests)
		if !handled || !errors.Is(err, ErrHostFactoryHold) {
			t.Fatal("durable ordinary target escaped without genuine installed Source", err)
		}
	}
}

func TestHostOriginalFactoryPostgresFifteenPendingSuccessor(t *testing.T) {
	tx, f := hostFactoryStorageTx(t)
	prefix, _ := hostFactoryStorageAppend(t, tx, f, f.chunk(1, 15, false))
	pending, pendingRaw := hostFactoryStorageAppend(t, tx, f, f.chunk(16, 16, true))
	successor, _ := hostFactoryStorageAppend(t, tx, f, f.chunk(16, 16, false))
	raw, index, err := originalHostPredecessorTx(context.Background(), tx, successor, successor.bodySHA, 0)
	if err != nil || index != 0 || !bytes.Equal(raw, pendingRaw) {
		t.Fatal("exact singleton pending predecessor absent", err)
	}
	hostFactoryStorageManifest(t, tx, f, 16, prefix.bodySHA, successor.bodySHA)
	var retained []byte
	if err = tx.QueryRow(`SELECT raw_body_wire FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND record_kind='chunk' AND raw_body_sha256=$2`, f.root, pending.bodySHA).Scan(&retained); err != nil || !bytes.Equal(retained, pendingRaw) {
		t.Fatal("historical pending bytes changed", err)
	}
	var logical, versions int
	if err = tx.QueryRow(`SELECT count(DISTINCT original_call_id),count(*) FROM public.capacity_host_factory_call_snapshot_links WHERE root_id=$1`, f.root).Scan(&logical, &versions); err != nil || logical != 16 || versions != 17 {
		t.Fatal("historical versions counted as new calls", err)
	}
}

func TestHostOriginalFactoryPostgresTwoSequentialPendingSuccessors(t *testing.T) {
	tx, f := hostFactoryStorageTx(t)
	var children []string
	for ordinal := uint64(1); ordinal <= 2; ordinal++ {
		_, pending := hostFactoryStorageAppend(t, tx, f, f.chunk(ordinal, ordinal, true))
		x, _ := hostFactoryStorageAppend(t, tx, f, f.chunk(ordinal, ordinal, false))
		raw, index, err := originalHostPredecessorTx(context.Background(), tx, x, x.bodySHA, 0)
		if err != nil || index != 0 || !bytes.Equal(raw, pending) {
			t.Fatal("sequential original predecessor diverged", err)
		}
		children = append(children, x.bodySHA)
	}
	hostFactoryStorageManifest(t, tx, f, 2, children...)
}

func TestHostOriginalFactoryPostgresPublicationRefusals(t *testing.T) {
	for _, name := range []string{"mixed_prefix_pending", "gap_before_pending", "later_call_while_pending", "terminal_republication", "second_pending", "second_successor", "unknown_FIRST"} {
		t.Run(name, func(t *testing.T) {
			tx, f := hostFactoryStorageTx(t)
			ctx := context.Background()
			var bad model.HostFactoryCallVectorChunk
			switch name {
			case "mixed_prefix_pending":
				bad = f.chunk(1, 2, false)
				bad.OriginalCalls[1] = f.chunk(2, 2, true).OriginalCalls[0]
			case "gap_before_pending":
				bad = f.chunk(2, 2, true)
			case "later_call_while_pending":
				hostFactoryStorageAppend(t, tx, f, f.chunk(1, 1, true))
				bad = f.chunk(2, 2, true)
			case "terminal_republication":
				hostFactoryStorageAppend(t, tx, f, f.chunk(1, 1, false))
				bad = f.chunk(1, 1, false)
				bad.RecordedAt = bad.RecordedAt.Add(time.Second)
			case "second_pending":
				hostFactoryStorageAppend(t, tx, f, f.chunk(1, 1, true))
				bad = f.chunk(1, 1, true)
			case "second_successor":
				hostFactoryStorageAppend(t, tx, f, f.chunk(1, 1, true))
				hostFactoryStorageAppend(t, tx, f, f.chunk(1, 1, false))
				bad = f.chunk(1, 1, false)
			case "unknown_FIRST":
				bad = f.chunk(1, 1, false)
				raw, _ := capacity.CanonicalHostFactory(bad)
				x, _ := originalHostIOIdentity(hostOriginalConstraintCodec(), f.root, &bad, raw)
				if _, _, err := originalHostPredecessorTx(ctx, tx, x, x.bodySHA, 0); !errors.Is(err, ErrHostFactoryHold) {
					t.Fatal("missing FIRST became permission", err)
				}
				return
			}
			raw, _ := capacity.CanonicalHostFactory(bad)
			x, _ := originalHostIOIdentity(hostOriginalConstraintCodec(), f.root, &bad, raw)
			if err := appendOriginalHostChunkTx(ctx, tx, x, bad, raw, []byte(`{"storage_envelope_only":true}`)); err == nil {
				t.Fatal("invalid publication accepted")
			}
		})
	}
}

func TestHostOriginalFactoryPostgresFailurePartKeys(t *testing.T) {
	tx, f := hostFactoryStorageTx(t)
	ctx := context.Background()
	collection := uuid.NewString()
	part := model.HostFactoryFailureDiagnostic{Schema: "original_host_factory_failure_diagnostic_v4", Purpose: "original_host_factory_failure_diagnostic_v4", BindingSchema: "original_host_factory_source_approval_v4", BindingSHA256: f.binding, OriginalStage: "storage_unknown", OriginalContextStartedAt: f.start, OriginalContextDeadline: f.start.Add(600 * time.Second), OriginalOperationDeadline: f.start.Add(60 * time.Second), FailureCode: "storage_unknown", OriginalRecordState: "not_acquired", Operations: []model.HostFactoryCallVectorReference{}, RecordedAt: f.start.Add(time.Second), FailureCollectionID: collection, PartOrdinal: 1, FinalPart: false, RetentionState: "incomplete_retention"}
	// OriginalStage must be an operation stage, independent of FailureCode.
	part.OriginalStage = "choice_write"
	for ordinal := uint32(1); ordinal <= 2; ordinal++ {
		part.PartOrdinal = ordinal
		raw, err := capacity.CanonicalHostFactory(part)
		if err != nil {
			t.Fatal(err)
		}
		x, err := originalHostIOIdentity(hostOriginalConstraintCodec(), f.root, &part, raw)
		if err != nil {
			t.Fatal(err)
		}
		x.owner, x.role = f.owner, "host_worker"
		if x.handle != nil || x.operation != nil || x.first != nil || x.last != nil {
			t.Fatal("failure part fabricated a handle/range")
		}
		if err = appendOriginalHostFailureTx(ctx, tx, x, part, raw, []byte(`{"storage_envelope_only":true}`)); err != nil {
			t.Fatal(err)
		}
		part.PreviousPartRawSHA256 = hostFactoryStoragePtr(x.bodySHA)
	}
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM public.capacity_host_factory_io_returns WHERE root_id=$1 AND failure_collection_id=$2 AND original_handle_id IS NULL`, f.root, collection).Scan(&count); err != nil || count != 2 {
		t.Fatal("failure parts not independently retained", err)
	}
}

func TestHostOriginalFactoryPostgresDurableClaimBlocksOmittedContext(t *testing.T) {
	tx, f := hostFactoryStorageTx(t)
	_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_leases(root_id,original_invocation_id,namespace,environment,domain,dimension,generation,fence,original_intent_sha256,original_intent_wire,original_assessment_sha256,original_assessment_wire,initial_empty_sha256,initial_empty_wire) VALUES($1,$2,'source-vector','test','domain','dimension',1,1,$3,$4,$5,$4,$6,$4)`, f.root, uuid.NewString(), capacity.HostFactoryRawSHA256([]byte(f.handle)), []byte(`{"storage_vector_only":true}`), f.binding, f.primitive)
	if err != nil {
		t.Fatal(err)
	}
	if err = guardOriginalHostCapacityTx(context.Background(), tx, "source-vector", model.CapacityPolicySpec{Environment: "test", Domain: "domain", Dimension: "dimension"}); !errors.Is(err, ErrHostFactoryHold) {
		t.Fatal("durable original claim allowed omitted context", err)
	}
}

func TestHostOriginalFactoryActualRegistryAndZeroRealmRefuse(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	if _, err := capacity.ApprovedHostFactorySource(); !errors.Is(err, capacity.ErrHostFactorySourceUnavailable) {
		t.Fatal("actual compiled catalog was populated", err)
	}
	if err := InstallOriginalHostFactoryRealm(context.Background(), &capacityhostfactory.OriginalFactoryRealm{}); !errors.Is(err, ErrHostFactoryHold) {
		t.Fatal("zero/caller realm installed authority", err)
	}
}

func TestHostOriginalFactorySourcePrimeOriginalReturnFence(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// Private return-state vectors exercise the replay/Claim fence only. The
	// zero Realm and unopened DB identities supply no Source or native authority.
	realm, db := &capacityhostfactory.OriginalFactoryRealm{}, &sql.DB{}
	called := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	original := hostOriginalPrimeReturn{realm: realm, db: db, root: "source-vector-root", nativeRoot: uuid.NewString(), attempt: uuid.NewString(), owner: uuid.NewString(), calledAt: called, returnedAt: called.Add(time.Second), deadline: called.Add(2 * time.Second), committed: true}
	if !original.completedFor(realm, db, original.root) {
		t.Fatal("complete private return-state vector refused")
	}
	cases := []struct {
		name   string
		mutate func(*hostOriginalPrimeReturn)
	}{
		{"pending_before_sql", func(r *hostOriginalPrimeReturn) { r.returnedAt = time.Time{}; r.committed = false }},
		{"commit_without_go_return", func(r *hostOriginalPrimeReturn) { r.returnedAt = time.Time{} }},
		{"returned_without_commit", func(r *hostOriginalPrimeReturn) { r.committed = false }},
		{"unknown_commit", func(r *hostOriginalPrimeReturn) { r.originalErr = errors.New("original commit uncertainty") }},
		{"post_return_admission_failed", func(r *hostOriginalPrimeReturn) { r.admissionErr = ErrHostFactoryHold }},
		{"panic_keeps_pending", func(r *hostOriginalPrimeReturn) { r.originalErr = ErrHostFactoryHold; r.returnedAt = time.Time{} }},
		{"returned_at_bound", func(r *hostOriginalPrimeReturn) { r.returnedAt = r.deadline }},
		{"late_return_timer_lag", func(r *hostOriginalPrimeReturn) { r.returnedAt = r.deadline.Add(time.Nanosecond) }},
		{"return_before_call", func(r *hostOriginalPrimeReturn) { r.returnedAt = r.calledAt.Add(-time.Nanosecond) }},
		{"missing_original_bound", func(r *hostOriginalPrimeReturn) { r.deadline = time.Time{} }},
		{"missing_original_realm", func(r *hostOriginalPrimeReturn) { r.realm = nil }},
		{"foreign_database", func(r *hostOriginalPrimeReturn) { r.db = &sql.DB{} }},
		{"foreign_root", func(r *hostOriginalPrimeReturn) { r.root = "another-root" }},
		{"missing_native_root", func(r *hostOriginalPrimeReturn) { r.nativeRoot = "" }},
		{"missing_reserved_attempt", func(r *hostOriginalPrimeReturn) { r.attempt = "" }},
		{"missing_reserved_owner", func(r *hostOriginalPrimeReturn) { r.owner = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := original
			tc.mutate(&r)
			if r.completedFor(realm, db, original.root) {
				t.Fatal("incomplete/foreign original owning return opened the effect fence")
			}
		})
	}
}

func TestHostOriginalFactorySourcePrimeEmptySourceCannotInitialize(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// The compiled registry remains EMPTY. Caller-created Realm/DB objects and
	// context bounds cannot reach any initializer SQL or establish FIRST.
	bounded, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	defer cancel()
	canceled, cancelNow := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	cancelNow()
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{{"nil_context", nil}, {"unbounded", context.Background()}, {"bounded_caller_context", bounded}, {"canceled", canceled}} {
		t.Run(tc.name, func(t *testing.T) {
			store := CapacityStore{DB: &sql.DB{}}
			if err := store.PrimeOriginalHostRoot(tc.ctx, &capacityhostfactory.OriginalFactoryRealm{}, model.Manifest{}, model.Manifest{}, model.WorkflowStepSpec{}, model.WorkflowStepSpec{}, model.WorkflowStepSpec{}); !errors.Is(err, ErrHostFactoryHold) {
				t.Fatal("caller inputs installed an early Root/FIRST initializer", err)
			}
			if err := store.GuardOriginalHostPrimedRoot(tc.ctx, &capacityhostfactory.OriginalFactoryRealm{}, model.Manifest{}, model.Manifest{}, model.WorkflowStepSpec{}, model.WorkflowStepSpec{}, model.WorkflowStepSpec{}); !errors.Is(err, ErrHostFactoryHold) {
				t.Fatal("caller inputs installed post-return native/source admission", err)
			}
		})
	}
}

func TestHostOriginalFactorySourcePrimePostReturnBoundCannotRenew(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	realm, db := &capacityhostfactory.OriginalFactoryRealm{}, &sql.DB{}
	called := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	original := hostOriginalPrimeReturn{realm: realm, db: db, root: "source-vector-root", nativeRoot: uuid.NewString(), attempt: uuid.NewString(), owner: uuid.NewString(), calledAt: called, returnedAt: called.Add(time.Second), deadline: called.Add(2 * time.Second), committed: true}
	for _, tc := range []struct {
		name     string
		bound    time.Time
		accepted bool
	}{
		{"same_original_bound", original.deadline, true},
		{"narrower_source_derived_bound", original.deadline.Add(-time.Nanosecond), true},
		{"one_nanosecond_extension", original.deadline.Add(time.Nanosecond), false},
		{"replacement_epoch", original.deadline.Add(30 * time.Minute), false},
		{"unbounded_replacement", time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if original.completedWithin(realm, db, original.root, tc.bound) != tc.accepted {
				t.Fatal("post-return read widened the original primer bound")
			}
		})
	}
}

func TestHostOriginalFactorySourcePreparationAttemptOnce(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, entry := range []string{"sealed_a0", "sealed_a1", "ordinary_original_create"} {
		t.Run(entry, func(t *testing.T) {
			// Private algorithm identities only; no installed Source/native realm,
			// authenticated stage, SQL execution or genuine Commit is supplied.
			realm := &capacityhostfactory.OriginalFactoryRealm{}
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
			defer cancel()
			deadline, _ := ctx.Deadline()
			h := &hostOriginalClaim{realm: realm, invocation: uuid.NewString(), rootID: uuid.NewString(), attemptID: uuid.NewString(), creatorOwnerID: uuid.NewString(), committed: true, claimReturnedAt: time.Now().UTC()}
			awaiting := hostOriginalAwaitingRecord{RootID: h.rootID, FactoryAttemptID: h.attemptID, CreatorOwnerID: h.creatorOwnerID, OriginalInvocationID: h.invocation, EntryClass: entry, OriginalContextDeadline: deadline.UTC()}
			raw, err := json.Marshal(awaiting)
			if err != nil {
				t.Fatal(err)
			}
			h.awaiting = &hostOriginalAwaitingReturn{raw: raw, committed: true, returnedAt: time.Now().UTC()}
			store := CapacityStore{DB: &sql.DB{}, ExecutorID: h.invocation, hostOriginalClaim: h}
			binding := []byte(`{"source_vector_only":true}`)
			stages := map[string][]byte{"source_vector": []byte(`{"source_vector_only":true}`)}
			original, err := store.beginOriginalHostPreparation(ctx, realm, entry, binding, stages)
			if err != nil || original == nil || h.preparationReturn != original {
				t.Fatal("first private reservation refused", err)
			}
			binding[0] = ' '
			stages["source_vector"][0] = ' '
			if original.bindingRaw[0] != '{' || original.stages["source_vector"][0] != '{' {
				t.Fatal("retained originals borrowed mutable caller buffers")
			}
			if _, err = store.beginOriginalHostPreparation(ctx, realm, entry, []byte(`{}`), map[string][]byte{"x": []byte(`{}`)}); !errors.Is(err, ErrHostFactoryHold) {
				t.Fatal("pending registration allowed second attempt", err)
			}
			unknown := errors.New("original driver commit uncertainty")
			store.captureOriginalHostPreparationCommit(original)(original.calledAt, time.Now().UTC(), unknown)
			original.transactionReturnedAt = time.Now().UTC()
			if err = store.finishOriginalHostPreparation(original, unknown); !errors.Is(err, unknown) || !errors.Is(err, ErrHostFactoryHold) || original.committed {
				t.Fatal("unknown commit lost original HOLD cause", err)
			}
			if _, err = store.beginOriginalHostPreparation(ctx, realm, entry, []byte(`{}`), map[string][]byte{"x": []byte(`{}`)}); !errors.Is(err, ErrHostFactoryHold) {
				t.Fatal("failed registration reopened already-started supplier", err)
			}
		})
	}
}

func TestHostOriginalFactorySourcePreparationReturnFence(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, name := range []string{"commit_without_go_return", "late_go_return", "canceled_owner", "unknown_commit", "panic_pending", "foreign_binding", "foreign_handle", "foreign_database", "foreign_realm", "foreign_entry", "commit_before_owner", "helper_before_commit_return", "outer_before_helper"} {
		t.Run(name, func(t *testing.T) {
			realm := &capacityhostfactory.OriginalFactoryRealm{}
			h := &hostOriginalClaim{realm: realm}
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
			defer cancel()
			deadline, _ := ctx.Deadline()
			now := time.Now().UTC()
			binding := []byte(`{"source_vector_only":true}`)
			r := &hostOriginalPreparationReturn{claim: h, realm: realm, db: &sql.DB{}, ctx: ctx, entry: "ordinary_original_create", handle: uuid.NewString(), bindingRaw: bytes.Clone(binding), preparedRaw: []byte(`{}`), registrationRaw: []byte(`{}`), calledAt: now, commitCalledAt: now, commitReturnedAt: now, transactionReturnedAt: now, methodFinishedAt: now, externalCalledAt: now, returnedAt: now, deadline: deadline, committed: true, externalReturnReserved: true}
			h.preparationReturn = r
			if !originalHostPreparationCompleted(h, realm, r.db, r.entry, binding, r.handle) {
				t.Fatal("private returned-state vector refused")
			}
			queryBinding, queryHandle := binding, r.handle
			queryDB, queryRealm, queryEntry := r.db, realm, r.entry
			switch name {
			case "commit_without_go_return":
				r.returnedAt = time.Time{}
			case "late_go_return":
				r.returnedAt = deadline
			case "canceled_owner":
				cancel()
				r.returnedAt = time.Time{}
				if err := (CapacityStore{DB: r.db, hostOriginalClaim: h}).finishOriginalHostPreparation(r, nil); !errors.Is(err, ErrHostFactoryHold) {
					t.Fatal("canceled actual owner returned eligibility", err)
				}
			case "unknown_commit":
				r.originalErr = errors.New("driver uncertainty")
				r.committed = false
			case "panic_pending":
				r.originalErr = ErrHostFactoryHold
				r.returnedAt = time.Time{}
			case "foreign_binding":
				queryBinding = []byte(`{"foreign":true}`)
			case "foreign_handle":
				queryHandle = uuid.NewString()
			case "foreign_database":
				queryDB = &sql.DB{}
			case "foreign_realm":
				queryRealm = &capacityhostfactory.OriginalFactoryRealm{}
			case "foreign_entry":
				queryEntry = "sealed_a1"
			case "commit_before_owner":
				r.commitCalledAt = r.calledAt.Add(-time.Nanosecond)
			case "helper_before_commit_return":
				r.transactionReturnedAt = r.commitReturnedAt.Add(-time.Nanosecond)
			case "outer_before_helper":
				r.returnedAt = r.transactionReturnedAt.Add(-time.Nanosecond)
			}
			if originalHostPreparationCompleted(h, queryRealm, queryDB, queryEntry, queryBinding, queryHandle) {
				t.Fatal("incomplete/foreign registration opened Issue admission")
			}
		})
	}
}

func TestHostOriginalFactorySourceMainOwnerCausality(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// Unapproved Source-only chronology vectors. These are not actual owner
	// returns, signed native facts, SQL execution or a fixture qualification.
	for _, name := range []string{"broker_before_serve_join", "broker_before_shutdown_return", "broker_before_handler_join", "broker_before_workflow_join", "broker_before_realm_join", "broker_before_transport_return", "db_before_broker_return", "shutdown_before_caller_return", "closing_sql_before_realm_join", "broker_before_closing_sql_return", "main_cleanup_before_db_return", "late_operation_return", "foreign_subject", "missing_closing_sql", "realm_before_serve_join", "realm_before_shutdown_return", "realm_before_handler_join", "realm_before_workflow_join"} {
		t.Run(name, func(t *testing.T) {
			origin := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
			at := func(n int) *time.Time { v := origin.Add(time.Duration(n) * time.Second); return &v }
			deadline := origin.Add(time.Minute)
			audits := map[string]hostOriginalSourceAuditProjection{}
			for _, row := range []struct {
				op, subject      string
				called, returned int
			}{{"api_original_serve", "main_api", 1, 9}, {"api_original_shutdown", "main_api", 7, 8}, {"api_handler_owner_join", "main_handlers", 10, 11}, {"workflow_owner_join", "main_workflows", 12, 13}, {"db_original_query", "main_db", 16, 17}, {"broker_close", "main_broker", 20, 21}, {"db_close", "main_db", 22, 23}} {
				failed := row.op == "api_original_serve" // actual ErrServerClosed remains nonnil
				audits[row.op] = hostOriginalSourceAuditProjection{SubjectIdentity: hostOriginalSubjectIdentity{SubjectKind: row.subject}, Fact: model.HostFactorySourceAuditReturn{Operation: row.op, OriginalCalledAt: at(row.called), OriginalReturnedAt: at(row.returned), OriginalOperationDeadline: deadline, OriginalErrorPresent: &failed}}
			}
			main := map[string]hostOriginalMainReturn{}
			for _, row := range []struct {
				op               string
				called, returned int
			}{{"preclose_verifier_return", 2, 4}, {"public_caller_return", 1, 5}, {"realm_close_join", 14, 15}, {"transport_close_idle", 18, 19}, {"main_cleanup_return", 6, 24}} {
				main[row.op] = hostOriginalMainReturn{OriginalCalledAt: at(row.called), OriginalReturnedAt: at(row.returned), OriginalOperationDeadline: deadline}
			}
			if err := verifyOriginalHostHistoricalOwnerOrder(audits, main, *at(3)); err != nil {
				t.Fatal("private completed-order vector refused", err)
			}
			mutateAudit := func(op string, called, returned *time.Time) {
				r := audits[op]
				if called != nil {
					r.Fact.OriginalCalledAt = called
				}
				if returned != nil {
					r.Fact.OriginalReturnedAt = returned
				}
				audits[op] = r
			}
			switch name {
			case "realm_before_serve_join":
				mutateAudit("api_original_serve", nil, at(15))
			case "realm_before_shutdown_return":
				mutateAudit("api_original_shutdown", nil, at(15))
			case "realm_before_handler_join":
				mutateAudit("api_handler_owner_join", nil, at(15))
			case "realm_before_workflow_join":
				mutateAudit("workflow_owner_join", nil, at(15))
			case "broker_before_serve_join":
				mutateAudit("api_original_serve", nil, at(21))
			case "broker_before_shutdown_return":
				mutateAudit("api_original_shutdown", nil, at(21))
			case "broker_before_handler_join":
				mutateAudit("api_handler_owner_join", nil, at(21))
			case "broker_before_workflow_join":
				mutateAudit("workflow_owner_join", nil, at(21))
			case "broker_before_realm_join":
				r := main["realm_close_join"]
				r.OriginalReturnedAt = at(21)
				main["realm_close_join"] = r
			case "broker_before_transport_return":
				r := main["transport_close_idle"]
				r.OriginalReturnedAt = at(21)
				main["transport_close_idle"] = r
			case "db_before_broker_return":
				mutateAudit("broker_close", nil, at(23))
			case "shutdown_before_caller_return":
				mutateAudit("api_original_shutdown", at(4), nil)
			case "closing_sql_before_realm_join":
				mutateAudit("db_original_query", at(14), nil)
			case "broker_before_closing_sql_return":
				mutateAudit("db_original_query", nil, at(21))
			case "main_cleanup_before_db_return":
				r := main["main_cleanup_return"]
				r.OriginalReturnedAt = at(22)
				main["main_cleanup_return"] = r
			case "late_operation_return":
				r := audits["broker_close"]
				r.Fact.OriginalOperationDeadline = *r.Fact.OriginalReturnedAt
				audits["broker_close"] = r
			case "foreign_subject":
				r := audits["broker_close"]
				r.SubjectIdentity.SubjectKind = "source_file"
				audits["broker_close"] = r
			case "missing_closing_sql":
				delete(audits, "db_original_query")
			}
			if err := verifyOriginalHostHistoricalOwnerOrder(audits, main, *at(3)); !errors.Is(err, ErrHostFactoryHold) {
				t.Fatal("foreign/inverted owning return admitted", err)
			}
		})
	}
}

func TestHostOriginalFactoryPostgresPrimedOriginalComparisonIsReadonly(t *testing.T) {
	tx, vector := hostFactoryStorageTx(t)
	body := vector.chunk(1, 1, false)
	identity, bodyRaw := hostFactoryStorageAppend(t, tx, vector, body)
	// This is a storage/FIRST algorithm vector, deliberately no authentic
	// Source envelope. It cannot exercise public/native admission.
	original := hostOriginalRetainedRecord{selector: HostFactoryRecordSelector{RootID: vector.root, BindingSchema: body.BindingSchema, BindingSHA256: body.BindingSHA256, OwnerID: vector.owner, Role: body.OwnerRole, Kind: "chunk", HandleID: vector.handle}, body: &body, bodyRaw: bodyRaw, envelopeRaw: []byte(`{"storage_envelope_only":true}`)}
	store := CapacityStore{}
	ctx := context.Background()
	if err := store.compareOriginalHostRecordStorageTx(ctx, tx, hostOriginalConstraintCodec(), original); err != nil {
		t.Fatal("exact immutable storage/FIRST comparison refused", err)
	}
	t.Run("owning-source-admission-refuses-storage-fixture", func(t *testing.T) {
		if store.compareOriginalHostRecordsTx(ctx, tx, []hostOriginalRetainedRecord{original}) == nil {
			t.Fatal("unsigned storage fixture installed original Source admission")
		}
	})
	var before int
	if err := tx.QueryRow(`SELECT count(*) FROM public.capacity_host_factory_io_returns WHERE root_id=$1`, vector.root).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*hostOriginalRetainedRecord)
	}{
		{"missing_root", func(r *hostOriginalRetainedRecord) { r.selector.RootID = uuid.NewString() }},
		{"foreign_binding", func(r *hostOriginalRetainedRecord) { r.selector.BindingSHA256 = strings.Repeat("c", 64) }},
		{"foreign_owner", func(r *hostOriginalRetainedRecord) { r.selector.OwnerID = uuid.NewString() }},
		{"foreign_handle", func(r *hostOriginalRetainedRecord) { r.selector.HandleID = uuid.NewString() }},
		{"foreign_signer_role", func(r *hostOriginalRetainedRecord) { r.selector.Role = "host_registrar" }},
		{"changed_original_body", func(r *hostOriginalRetainedRecord) { r.bodyRaw = append(bytes.Clone(r.bodyRaw), ' ') }},
		{"changed_original_envelope", func(r *hostOriginalRetainedRecord) { r.envelopeRaw = append(bytes.Clone(r.envelopeRaw), ' ') }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := original
			tc.mutate(&r)
			if err := store.compareOriginalHostRecordStorageTx(ctx, tx, hostOriginalConstraintCodec(), r); !errors.Is(err, ErrHostFactoryHold) {
				t.Fatal("original mismatch triggered replay repair/admission", err)
			}
		})
	}
	var after int
	if err := tx.QueryRow(`SELECT count(*) FROM public.capacity_host_factory_io_returns WHERE root_id=$1`, vector.root).Scan(&after); err != nil || after != before {
		t.Fatal("comparison reinserted or rewrote original IO", err)
	}
	if _, _, err := originalHostPredecessorTx(ctx, tx, identity, identity.bodySHA, 0); err != nil {
		t.Fatal("comparison damaged original known FIRST", err)
	}
}

func TestHostOriginalFactoryPostgresPrimedBodyWithoutSQLFirstHolds(t *testing.T) {
	tx, vector := hostFactoryStorageTx(t)
	body := vector.chunk(1, 1, false)
	bodyRaw, err := capacity.CanonicalHostFactory(body)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := originalHostIOIdentity(hostOriginalConstraintCodec(), vector.root, &body, bodyRaw)
	if err != nil {
		t.Fatal(err)
	}
	envelope := []byte(`{"storage_envelope_only":true}`)
	// Bypass the owning chunk appender intentionally: the immutable BODY row
	// alone is not a verified SQL13 FIRST relation and cannot authorize nil0nil.
	if err = appendOriginalHostIOBodyTx(context.Background(), tx, identity, bodyRaw, envelope); err != nil {
		t.Fatal(err)
	}
	original := hostOriginalRetainedRecord{selector: HostFactoryRecordSelector{RootID: vector.root, BindingSchema: body.BindingSchema, BindingSHA256: body.BindingSHA256, OwnerID: vector.owner, Role: body.OwnerRole, Kind: "chunk", HandleID: vector.handle}, body: &body, bodyRaw: bodyRaw, envelopeRaw: envelope}
	if err = (CapacityStore{}).compareOriginalHostRecordStorageTx(context.Background(), tx, hostOriginalConstraintCodec(), original); !errors.Is(err, ErrHostFactoryHold) {
		t.Fatal("BODY-only row became known FIRST/admission", err)
	}
}

func TestHostOriginalFactoryActualRegistryFailedGoReturnsStayHeld(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// These private algorithm vectors have no Realm, approval, SQL commit or
	// native supplier. A failed first return must never call one or allow retry.
	called := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	returned := called.Add(time.Second)
	originalErr := errors.New("source vector unknown commit")
	t.Run("claim", func(t *testing.T) {
		h := &hostOriginalClaim{}
		s := CapacityStore{hostOriginalClaim: h}
		intent := model.CapacityIntent{LeaseOwner: "private-source-vector"}
		if err := s.CaptureOriginalHostClaimReturn(context.Background(), intent, called, returned, originalErr); !errors.Is(err, originalErr) || !errors.Is(err, ErrHostFactoryHold) {
			t.Fatal("failed Claim return did not retain original HOLD cause", err)
		}
		originalProjection := bytes.Clone(h.claimReturnedProjection)
		if h.committed || !h.claimCalledAt.Equal(called) || !h.claimReturnedAt.Equal(returned) || !errors.Is(h.claimReturnErr, originalErr) || len(originalProjection) == 0 {
			t.Fatal("failed Claim became committed or lost its actual return")
		}
		if err := s.CaptureOriginalHostClaimReturn(context.Background(), model.CapacityIntent{}, called, returned.Add(time.Second), nil); !errors.Is(err, ErrHostFactoryHold) || !bytes.Equal(h.claimReturnedProjection, originalProjection) || !h.claimReturnedAt.Equal(returned) {
			t.Fatal("later Claim return replaced failed original", err)
		}
	})
	t.Run("sealed_issue", func(t *testing.T) {
		h := &hostOriginalFactoryScope{issueReserved: true}
		s := CapacityStore{hostOriginalFactory: h}
		if err := s.CaptureOriginalHostIssueReturn(model.CapacityMutationGrant{}, called, returned, originalErr); !errors.Is(err, originalErr) || !errors.Is(err, ErrHostFactoryHold) {
			t.Fatal("failed sealed Issue lost original HOLD cause", err)
		}
		if h.issueCommitted || h.issueCaptured || !h.issueReturnedAt.Equal(returned) || !errors.Is(h.issueReturnErr, originalErr) {
			t.Fatal("failed sealed Issue became captured/committed")
		}
		if err := s.CaptureOriginalHostIssueReturn(model.CapacityMutationGrant{}, called, returned.Add(time.Second), nil); !errors.Is(err, ErrHostFactoryHold) || !h.issueReturnedAt.Equal(returned) {
			t.Fatal("sealed Issue retried after original uncertainty", err)
		}
	})
	t.Run("ordinary_issue", func(t *testing.T) {
		h := &hostOriginalOrdinaryFactory{issueReserved: true}
		s := CapacityStore{hostOriginalOrdinary: h}
		if err := s.CaptureOriginalOrdinaryIssueReturn(context.Background(), model.CapacityMutationGrant{}, called, returned, originalErr); !errors.Is(err, originalErr) || !errors.Is(err, ErrHostFactoryHold) {
			t.Fatal("failed ordinary Issue lost original HOLD cause", err)
		}
		if h.issueCommitted || h.issueCaptured || !h.issueReturnedAt.Equal(returned) || !errors.Is(h.issueReturnErr, originalErr) {
			t.Fatal("failed ordinary Issue became captured/committed")
		}
		if err := s.CaptureOriginalOrdinaryIssueReturn(context.Background(), model.CapacityMutationGrant{}, called, returned.Add(time.Second), nil); !errors.Is(err, ErrHostFactoryHold) || !h.issueReturnedAt.Equal(returned) {
			t.Fatal("ordinary Issue retried after original uncertainty", err)
		}
		if _, err := s.ContinueOriginalOrdinaryCreate(context.Background()); !errors.Is(err, ErrHostFactoryHold) {
			t.Fatal("failed ordinary Issue entered original create", err)
		}
	})
	for _, kind := range []string{"claim", "sealed_issue", "ordinary_issue"} {
		t.Run(kind+"_unknown_zero_return_sticky", func(t *testing.T) {
			claim, sealed, ordinary := &hostOriginalClaim{}, &hostOriginalFactoryScope{issueReserved: true}, &hostOriginalOrdinaryFactory{issueReserved: true}
			store := CapacityStore{hostOriginalClaim: claim, hostOriginalFactory: sealed, hostOriginalOrdinary: ordinary}
			capture := func(at time.Time, callErr error) error {
				switch kind {
				case "claim":
					return store.CaptureOriginalHostClaimReturn(context.Background(), model.CapacityIntent{}, called, at, callErr)
				case "sealed_issue":
					return store.CaptureOriginalHostIssueReturn(model.CapacityMutationGrant{}, called, at, callErr)
				default:
					return store.CaptureOriginalOrdinaryIssueReturn(context.Background(), model.CapacityMutationGrant{}, called, at, callErr)
				}
			}
			if err := capture(time.Time{}, originalErr); !errors.Is(err, originalErr) || !errors.Is(err, ErrHostFactoryHold) {
				t.Fatal("unknown first return lost HOLD", err)
			}
			if err := capture(returned, nil); !errors.Is(err, ErrHostFactoryHold) {
				t.Fatal("unknown ZERO return regained capture permission", err)
			}
			switch kind {
			case "claim":
				if !claim.claimReturnReserved || !claim.claimReturnedAt.IsZero() || !errors.Is(claim.claimReturnErr, originalErr) {
					t.Fatal("unknown Claim replaced original")
				}
			case "sealed_issue":
				if !sealed.issueReturnReserved || !sealed.issueReturnedAt.IsZero() || sealed.issueCaptured || !errors.Is(sealed.issueReturnErr, originalErr) {
					t.Fatal("unknown sealed Issue replaced original")
				}
			default:
				if !ordinary.issueReturnReserved || !ordinary.issueReturnedAt.IsZero() || ordinary.issueCaptured || !errors.Is(ordinary.issueReturnErr, originalErr) {
					t.Fatal("unknown ordinary Issue replaced original")
				}
			}
		})
	}
}

func TestHostOriginalFactoryPostgresHandleInventoryInterleaving(t *testing.T) {
	tx, f := hostFactoryStorageTx(t)
	ctx := context.Background()
	// Declared protocol/SQL graph only: invalid root/signature vectors above
	// remain refused by real public Source admission; no native supplier exists.
	first := f.chunk(1, 1, false)
	middle := f.chunk(2, 2, false)
	middle.Operation = "stderr_read"
	middle.OriginalCalls[0].Operation = "stderr_read"
	last := f.chunk(3, 3, false)
	a, _ := hostFactoryStorageAppend(t, tx, f, first)
	b, _ := hostFactoryStorageAppend(t, tx, f, middle)
	c, _ := hostFactoryStorageAppend(t, tx, f, last)
	appendManifest := func(operation string, first, last, count uint64, children []string) model.HostFactoryCallVectorReference {
		m := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: "original_host_factory_source_approval_v4", BindingSHA256: f.binding, OwnerRole: "host_exterior", OriginalOwnerID: f.owner, OwnerPrimitiveRawSHA256: f.primitive, Operation: operation, OriginalHandleID: f.handle, Level: 0, FirstOrdinal: first, LastOrdinal: last, OriginalCallCount: count, ChildBodySHAs: children, CollectionState: "complete_original_calls"}
		raw, err := capacity.CanonicalHostFactory(m)
		if err != nil {
			t.Fatal(err)
		}
		x, err := originalHostIOIdentity(hostOriginalConstraintCodec(), f.root, &m, raw)
		if err != nil {
			t.Fatal(err)
		}
		if err = appendOriginalHostIOBodyTx(ctx, tx, x, raw, []byte(`{"storage_envelope_only":true}`)); err != nil {
			t.Fatal(err)
		}
		if err = validateOriginalHostManifestTx(ctx, tx, x, m); err != nil {
			t.Fatal(err)
		}
		sha := capacity.HostFactoryRawSHA256(raw)
		return model.HostFactoryCallVectorReference{Operation: operation, OriginalHandleID: f.handle, OriginalOwnerID: f.owner, OwnerPrimitiveRawSHA256: &f.primitive, SubjectOwnerID: f.owner, FirstOrdinal: first, LastOrdinal: last, OriginalCallCount: count, ManifestRootSHA256: &sha, CollectionState: "complete_original_calls"}
	}
	stdout := appendManifest("stdout_read", 1, 3, 2, []string{a.bodySHA, c.bodySHA})
	stderr := appendManifest("stderr_read", 2, 2, 1, []string{b.bodySHA})
	inventory := model.HostFactoryHandleCallInventory{Schema: "original_host_factory_handle_call_inventory_v1", Purpose: "original_host_factory_handle_call_inventory_v1", BindingSchema: "original_host_factory_source_approval_v4", BindingSHA256: f.binding, OwnerRole: "host_exterior", OriginalOwnerID: f.owner, OwnerPrimitiveRawSHA256: &f.primitive, OriginalHandleID: f.handle, OriginalAcquisitionState: "acquired_held", FirstOrdinal: 1, LastOrdinal: 3, OriginalCallCount: 3, OperationVectors: []model.HostFactoryCallVectorReference{stdout, stderr}, CollectionState: "complete_original_calls", OriginalOperationDeadline: f.start.Add(60 * time.Second), RecordedAt: f.start.Add(time.Second)}
	raw, err := capacity.CanonicalHostFactory(inventory)
	if err != nil {
		t.Fatal(err)
	}
	x, err := originalHostIOIdentity(hostOriginalConstraintCodec(), f.root, &inventory, raw)
	if err != nil {
		t.Fatal(err)
	}
	if x.operation != nil || x.kind != "handle-inventory" {
		t.Fatal("inventory aliased operation/failure purpose")
	}
	if err = appendOriginalHostIOBodyTx(ctx, tx, x, raw, []byte(`{"storage_envelope_only":true}`)); err != nil {
		t.Fatal(err)
	}
	if err = validateOriginalHostInventoryTx(ctx, tx, x, inventory); err != nil {
		t.Fatal("complete declared union refused", err)
	}
	v := x
	v.operation = &stdout.Operation
	v.primitive = f.primitive
	resolve := func(sha string) ([]byte, error) { return resolveOriginalHostBodyTx(ctx, tx, v, sha) }
	prior := func(sha string, index uint32) ([]byte, uint32, error) {
		return originalHostPredecessorTx(ctx, tx, v, sha, index)
	}
	if capacity.ValidateHostFactoryCallVector(stdout, resolve, prior) == nil {
		t.Fatal("standalone sparse operation became whole no-gap inventory")
	}
	t.Run("sparse_diagnostic_reader_requires_actual_basal", func(t *testing.T) {
		failure := model.HostFactoryFailureDiagnostic{Schema: "original_host_factory_failure_diagnostic_v4", Purpose: "original_host_factory_failure_diagnostic_v4", BindingSchema: "original_host_factory_source_approval_v4", BindingSHA256: f.binding, OriginalStage: "stdout_read", OriginalContextStartedAt: f.start, OriginalContextDeadline: f.start.Add(600 * time.Second), OriginalOperationDeadline: f.start.Add(60 * time.Second), FailureCode: "storage_unknown", OriginalRecordState: "not_acquired", Operations: []model.HostFactoryCallVectorReference{stdout}, OriginalVectorReferenceCount: 1, RecordedAt: f.start.Add(time.Second), FailureCollectionID: uuid.NewString(), PartOrdinal: 1, FinalPart: false, RetentionState: "incomplete_retention"}
		raw, err := capacity.CanonicalHostFactory(failure)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := originalHostIOIdentity(hostOriginalConstraintCodec(), f.root, &failure, raw)
		if err != nil {
			t.Fatal(err)
		}
		identity.owner, identity.role = f.owner, "host_exterior"
		if err = appendOriginalHostFailureTx(ctx, tx, identity, failure, raw, []byte(`{"storage_envelope_only":true}`)); !errors.Is(err, ErrHostFactoryHold) {
			t.Fatal("missing actual basal/source custody became diagnostic admission", err)
		}
		manifestRaw, err := resolve(*stdout.ManifestRootSHA256)
		var sparse model.HostFactoryCallVectorManifest
		if err != nil || capacity.DecodeHostFactory(manifestRaw, &sparse) != nil {
			t.Fatal("original sparse manifest missing", err)
		}
		facts, err := originalHostManifestFactsTx(ctx, tx, v, sparse)
		if err != nil || len(facts) != 2 {
			t.Fatal("diagnostic sparse immutable/FIRST reader refused exact interleaving", err)
		}
	})
	inventory.OperationVectors = inventory.OperationVectors[:1]
	if validateOriginalHostInventoryTx(ctx, tx, x, inventory) == nil {
		t.Fatal("missing interleaved operation erased original handle call")
	}
}

func TestHostOriginalFactoryPostgresInventoryNullShape(t *testing.T) {
	for _, name := range []string{"inventory_one_null_range", "inventory_operation_alias", "chunk_null_range"} {
		t.Run(name, func(t *testing.T) {
			tx, f := hostFactoryStorageTx(t)
			kind := "handle-inventory"
			var operation any
			var first, last any = int64(1), int64(1)
			switch name {
			case "inventory_one_null_range":
				last = nil
			case "inventory_operation_alias":
				operation = "stdout_read"
			case "chunk_null_range":
				kind = "chunk"
				operation = "stdout_read"
				first = nil
			}
			raw := []byte(`{"storage_vector_only":true}`)
			_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,record_identity_sha256,original_handle_id,operation,first_ordinal,last_ordinal,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire) VALUES($1,'original_host_factory_pre_authority_scope_v4',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$10,$11)`, f.root, f.binding, f.owner, kind, capacity.HostFactoryRawSHA256([]byte(name)), f.handle, operation, first, last, capacity.HostFactoryRawSHA256(raw), raw)
			if err == nil {
				t.Fatal("NULL CHECK or operation alias accepted invalid SQL inventory shape")
			}
		})
	}
}

func TestHostOriginalFactorySourceReadScopePrivacyAndClosedDecoder(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	started := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	returned := started.Add(time.Second)
	factory, handle := uuid.NewString(), uuid.NewString()
	count, prefix := int64(17), int64(17)
	failed, eof := false, true
	scope := "complete_original_body_read"
	call := handle + ":1"
	base := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: factory, OriginalAuditHandleID: handle, OriginalCallID: &call, Operation: "public_workflow_body_read", OriginalState: "returned", OriginalCalledAt: &started, OriginalReturnedAt: &returned, OriginalOperationDeadline: started.Add(600 * time.Second), OriginalErrorPresent: &failed, OriginalCount: &count, OriginalHashState: "private_withheld", OriginalEOF: &eof, OriginalReadScope: &scope, RetainedPrefixBytes: &prefix}
	for _, name := range []string{"GET_complete_NULL_hashes", "GET_partial_NULL_hashes", "GET_prefix_digest_refused", "GET_aggregate_digest_refused", "GET_scope_retained", "duplicate_key_refused", "missing_nullable_key_refused"} {
		t.Run(name, func(t *testing.T) {
			value := base
			want := true
			switch name {
			case "GET_partial_NULL_hashes":
				partial := "incomplete_original_body_read"
				yes, no := true, false
				value.OriginalReadScope = &partial
				value.OriginalErrorPresent = &yes
				value.OriginalEOF = &no
			case "GET_prefix_digest_refused":
				sha := capacity.HostFactoryRawSHA256([]byte("private"))
				value.RetainedPrefixSHA256 = &sha
				want = false
			case "GET_aggregate_digest_refused":
				sha := capacity.HostFactoryRawSHA256([]byte("private"))
				value.OriginalSHA256 = &sha
				want = false
			case "GET_scope_retained":
				if value.OriginalReadScope == nil || *value.OriginalReadScope != "complete_original_body_read" {
					t.Fatal("actual scope omitted for privacy")
				}
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if name == "duplicate_key_refused" {
				raw = bytes.Replace(raw, []byte(`"original_hash_state":"private_withheld"`), []byte(`"original_hash_state":"private_withheld","original_hash_state":"private_withheld"`), 1)
				want = false
			}
			if name == "missing_nullable_key_refused" {
				raw = bytes.Replace(raw, []byte(`"original_sha256":null,`), nil, 1)
				want = false
			}
			var decoded model.HostFactorySourceAuditReturn
			err = hostOriginalStrictJSON(raw, &decoded, 65536)
			if err == nil {
				err = capacity.ValidateHostFactory(decoded)
			}
			if (err == nil) != want {
				t.Fatal("source-only privacy/closed decode differs", name, err)
			}
		})
	}
}

func TestHostOriginalFactorySourceHTTPReadAllCausality(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// Declared Source-only return vectors exercise the historical reader. They
	// are not native suppliers or evidence that HTTP methods actually ran.
	for _, name := range []string{"nested_original_EOF", "aggregate_double_count_refused", "normalized_subread_EOF_refused", "synthetic_EOF_refused", "foreign_close_refused", "subread_scope_refused", "late_subread_refused", "private_GET_digest_refused", "missing_aggregate_refused"} {
		t.Run(name, func(t *testing.T) {
			rows := map[string]hostOriginalSourceAuditProjection{}
			started := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
			factory := uuid.NewString()
			var getAggregate, getEOF, postAggregate, postEOF, postFirst string
			for _, method := range []string{"POST", "GET"} {
				handle, request := uuid.NewString(), uuid.NewString()
				status, path := 202, "workflow_run_collection"
				if method == "GET" {
					status, path = 200, "same_original_workflow_run"
				}
				subject := hostOriginalSubjectIdentity{SubjectKind: "public_workflow_http", RequestIdentity: &request, Method: &method, PathFamily: &path}
				closeID := handle + ":5"
				for n, operation := range []string{"public_workflow_http_do", "public_workflow_body_read", "public_workflow_body_read", "public_workflow_body_read", "public_workflow_body_close"} {
					id := handle + ":" + strconv.Itoa(n+1)
					called, returned := started.Add(time.Duration(n*2)*time.Second), started.Add(time.Duration(n*2+1)*time.Second)
					failed := n == 3
					fact := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: factory, OriginalAuditHandleID: handle, OriginalCallID: &id, Operation: operation, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: started.Add(600 * time.Second), OriginalErrorPresent: &failed, OriginalStatusCode: &status, OriginalHashState: "not_byte_operation"}
					row := hostOriginalSourceAuditProjection{Family: "source_audit", SubjectIdentity: subject, Fact: fact}
					if n >= 1 && n <= 3 {
						count, eof := int64(17), n == 1 || n == 3
						if n == 2 {
							count = 10
						} else if n == 3 {
							count = 7
						}
						row.Fact.OriginalCount, row.Fact.OriginalEOF = &count, &eof
						row.Fact.OriginalHashState = "private_withheld"
						row.OriginalCloseReference = &closeID
						if method == "POST" {
							sha := capacity.HostFactoryRawSHA256([]byte(strings.Repeat("x", int(count))))
							row.Fact.OriginalHashState, row.Fact.OriginalSHA256 = "actual_public_bytes", &sha
						}
						if n == 1 {
							scope, prefix := "complete_original_body_read", count
							row.Fact.OriginalReadScope, row.Fact.RetainedPrefixBytes = &scope, &prefix
							row.Fact.RetainedPrefixSHA256 = row.Fact.OriginalSHA256
							at := started.Add(8 * time.Second)
							row.Fact.OriginalReturnedAt = &at
						}
					}
					rows[id] = row
				}
				if method == "POST" {
					postAggregate, postFirst, postEOF = handle+":2", handle+":3", handle+":4"
				} else {
					getAggregate, getEOF = handle+":2", handle+":4"
				}
			}
			change := func(id string, mutate func(*hostOriginalSourceAuditProjection)) {
				row := rows[id]
				mutate(&row)
				rows[id] = row
			}
			want := name == "nested_original_EOF"
			switch name {
			case "aggregate_double_count_refused":
				change(postAggregate, func(row *hostOriginalSourceAuditProjection) {
					count := int64(34)
					row.Fact.OriginalCount, row.Fact.RetainedPrefixBytes = &count, &count
				})
			case "normalized_subread_EOF_refused":
				change(postEOF, func(row *hostOriginalSourceAuditProjection) { failed := false; row.Fact.OriginalErrorPresent = &failed })
			case "synthetic_EOF_refused":
				change(getEOF, func(row *hostOriginalSourceAuditProjection) { eof := false; row.Fact.OriginalEOF = &eof })
			case "foreign_close_refused":
				change(postFirst, func(row *hostOriginalSourceAuditProjection) {
					id := uuid.NewString() + ":5"
					row.OriginalCloseReference = &id
				})
			case "subread_scope_refused":
				change(postFirst, func(row *hostOriginalSourceAuditProjection) {
					scope, eof := "complete_original_body_read", true
					row.Fact.OriginalReadScope, row.Fact.OriginalEOF = &scope, &eof
					row.Fact.RetainedPrefixBytes, row.Fact.RetainedPrefixSHA256 = row.Fact.OriginalCount, row.Fact.OriginalSHA256
				})
			case "late_subread_refused":
				change(postEOF, func(row *hostOriginalSourceAuditProjection) {
					at := started.Add(9 * time.Second)
					row.Fact.OriginalReturnedAt = &at
				})
			case "private_GET_digest_refused":
				change(getAggregate, func(row *hostOriginalSourceAuditProjection) {
					sha := capacity.HostFactoryRawSHA256([]byte("private"))
					row.Fact.OriginalSHA256 = &sha
				})
			case "missing_aggregate_refused":
				delete(rows, postAggregate)
			}
			if err := verifyOriginalHostHistoricalHTTPAudits(rows); (err == nil) != want {
				t.Fatal("Source-only original ReadAll grouping differs", name, err)
			}
		})
	}
}

func TestHostOriginalFactorySourcePolicyFileCustody(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// Declared unsigned Source vectors do not stand in for real policy file
	// reads, compiled approval or a native observation.
	for _, name := range []string{"three_original_input_lifetimes", "distinct_failed_Open_diagnostic", "duplicate_policy_reference_refused", "omitted_policy_call_refused", "missing_input_refused", "normalized_file_EOF_refused", "foreign_Close_refused", "missing_post_Fstat_refused", "read_after_EOF_refused"} {
		t.Run(name, func(t *testing.T) {
			rows := map[string]hostOriginalSourceAuditProjection{}
			started := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
			factory := uuid.NewString()
			var handles []string
			var policyReferences []string
			for input := 0; input < 3; input++ {
				handle := uuid.NewString()
				handles = append(handles, handle)
				closeID := handle + ":6"
				for n, operation := range []string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_read", "source_file_fstat", "source_file_close"} {
					id := handle + ":" + strconv.Itoa(n+1)
					called := started.Add(time.Duration(input*20+n*2) * time.Second)
					returned, failed := called.Add(time.Second), n == 3
					fact := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: factory, OriginalAuditHandleID: handle, OriginalCallID: &id, Operation: operation, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: started.Add(600 * time.Second), OriginalErrorPresent: &failed, OriginalHashState: "not_byte_operation"}
					if operation == "source_file_read" {
						count, eof := int64(17), n == 3
						if eof {
							count = 0
						}
						fact.OriginalCount, fact.OriginalEOF, fact.OriginalHashState = &count, &eof, "private_withheld"
					}
					rows[id] = hostOriginalSourceAuditProjection{Family: "source_audit", SubjectIdentity: hostOriginalSubjectIdentity{SubjectKind: "source_file"}, Fact: fact, OriginalCloseReference: &closeID}
					policyReferences = append(policyReferences, id)
				}
			}
			want := name == "three_original_input_lifetimes" || name == "distinct_failed_Open_diagnostic"
			switch name {
			case "distinct_failed_Open_diagnostic":
				handle := uuid.NewString()
				id, called, returned, failed := handle+":1", started.Add(70*time.Second), started.Add(71*time.Second), true
				rows[id] = hostOriginalSourceAuditProjection{Family: "source_audit", SubjectIdentity: hostOriginalSubjectIdentity{SubjectKind: "source_file"}, Fact: model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: factory, OriginalAuditHandleID: handle, OriginalCallID: &id, Operation: "source_file_open", OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: started.Add(600 * time.Second), OriginalErrorPresent: &failed, OriginalHashState: "not_byte_operation"}}
			case "duplicate_policy_reference_refused":
				policyReferences = append(policyReferences, policyReferences[0])
			case "omitted_policy_call_refused":
				policyReferences = policyReferences[1:]
			case "missing_input_refused":
				for id, row := range rows {
					if row.Fact.OriginalAuditHandleID == handles[0] {
						delete(rows, id)
					}
				}
			case "normalized_file_EOF_refused":
				id := handles[0] + ":4"
				row, failed := rows[id], false
				row.Fact.OriginalErrorPresent = &failed
				rows[id] = row
			case "foreign_Close_refused":
				id := handles[0] + ":2"
				row, closeID := rows[id], handles[1]+":6"
				row.OriginalCloseReference = &closeID
				rows[id] = row
			case "missing_post_Fstat_refused":
				delete(rows, handles[0]+":5")
			case "read_after_EOF_refused":
				id := handles[0] + ":5"
				row, count, eof := rows[id], int64(1), false
				row.Fact.Operation, row.Fact.OriginalHashState = "source_file_read", "private_withheld"
				row.Fact.OriginalCount, row.Fact.OriginalEOF = &count, &eof
				rows[id] = row
			}
			if err := verifyOriginalHostHistoricalSourceFileAudits(rows, policyReferences); (err == nil) != want {
				t.Fatal("Source-only policy file custody differs", name, err)
			}
		})
	}
}

func TestHostOriginalFactorySourceDirectoryCustody(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// Unsigned Source algorithm vectors, without an acquired directory, mode
	// observation, native FD/absence proof, SQL or an approved Realm.
	for _, name := range []string{"original_directory_methods", "failed_Open_diagnostic", "missing_Close", "foreign_Close", "byte_read_alias", "native_close_alias", "late_Fstat", "duplicate_ordinal"} {
		t.Run(name, func(t *testing.T) {
			rows := map[string]hostOriginalSourceAuditProjection{}
			handle, root := uuid.NewString(), uuid.NewString()
			origin := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
			closeID := handle + ":3"
			for n, operation := range []string{"source_directory_open", "source_directory_fstat", "source_directory_close"} {
				id := handle + ":" + strconv.Itoa(n+1)
				called := origin.Add(time.Duration(n*2) * time.Second)
				returned := called.Add(time.Second)
				failed := false
				rows[id] = hostOriginalSourceAuditProjection{Family: "source_audit", SubjectIdentity: hostOriginalSubjectIdentity{SubjectKind: "source_file"}, Fact: model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: root, OriginalAuditHandleID: handle, OriginalCallID: &id, Operation: operation, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: origin.Add(time.Minute), OriginalErrorPresent: &failed, OriginalHashState: "not_byte_operation"}, OriginalCloseReference: &closeID}
			}
			want := name == "original_directory_methods" || name == "failed_Open_diagnostic"
			switch name {
			case "failed_Open_diagnostic":
				r := rows[handle+":1"]
				yes := true
				r.Fact.OriginalErrorPresent = &yes
				r.OriginalCloseReference = nil
				rows = map[string]hostOriginalSourceAuditProjection{handle + ":1": r}
			case "missing_Close":
				delete(rows, closeID)
			case "foreign_Close":
				r := rows[handle+":2"]
				id := uuid.NewString() + ":3"
				r.OriginalCloseReference = &id
				rows[handle+":2"] = r
			case "byte_read_alias":
				r := rows[handle+":2"]
				r.Fact.Operation = "source_file_read"
				rows[handle+":2"] = r
			case "native_close_alias":
				r := rows[closeID]
				r.Fact.Operation = "root_directory_close"
				rows[closeID] = r
			case "late_Fstat":
				r := rows[handle+":2"]
				at := r.Fact.OriginalOperationDeadline
				r.Fact.OriginalReturnedAt = &at
				rows[handle+":2"] = r
			case "duplicate_ordinal":
				r := rows[handle+":2"]
				id := handle + ":1"
				r.Fact.OriginalCallID = &id
				rows[handle+":2"] = r
			}
			if err := verifyOriginalHostHistoricalSourceDirectories(rows); (err == nil) != want {
				t.Fatal("Source-only directory custody differs", name, err)
			}
		})
	}
}

func TestHostOriginalFactorySourceIssueOriginalContextFence(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// Context and clock algorithm only: no SQL Commit, grant, Source realm or
	// native supplier. A derived/new epoch never becomes an original Issue.
	for _, name := range []string{"same_original_bound", "late_return_at_bound", "unknown_return", "inverted_return", "foreign_context", "changed_recorded_bound", "unbounded_context", "canceled_original", "scope_bound_extension"} {
		t.Run(name, func(t *testing.T) {
			called := time.Now().UTC()
			deadline := called.Add(time.Minute)
			original, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			ctx := context.Context(original)
			returned, storedDeadline := called.Add(time.Second), deadline
			switch name {
			case "late_return_at_bound":
				returned = deadline
			case "unknown_return":
				returned = time.Time{}
			case "inverted_return":
				returned = called.Add(-time.Second)
			case "foreign_context":
				var cancelForeign context.CancelFunc
				ctx, cancelForeign = context.WithDeadline(context.Background(), deadline)
				defer cancelForeign()
			case "changed_recorded_bound":
				storedDeadline = deadline.Add(time.Second)
			case "unbounded_context":
				ctx, original = context.Background(), context.Background()
			case "canceled_original":
				cancel()
			}
			if name == "scope_bound_extension" {
				if _, accepted := originalHostIssueContextBound(original, deadline.Add(-time.Second)); accepted {
					t.Fatal("caller Issue bound extended original scope/ordinary binding")
				}
				return
			}
			if accepted := originalHostIssueReturnedWithin(ctx, original, storedDeadline, called, returned); accepted != (name == "same_original_bound") {
				t.Fatal("Source-only original Issue fence differs", name)
			}
		})
	}
	// The existing default mutation path gains no Source context requirement.
	if err := (CapacityStore{}).reserveOriginalFactoryIssue(nil); err != nil {
		t.Fatal("nil Source frame changed default mutation reservation", err)
	}
}

// Isolated unexecuted Source/PG proposal: native_source_cases_test.go
func TestHostOriginalFactorySourceCustodyByteTransport(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, test := range []struct {
		name                 string
		raw                  []byte
		rawMessage, accepted bool
	}{
		{"canonical_base64", []byte(`"AP8="`), false, true},
		{"numeric_byte_array", []byte(`[0,255]`), false, false},
		{"NULL_slice", []byte(`null`), false, false},
		{"literal_UTF8", []byte(`"{}"`), false, false},
		{"base64_newline", []byte(`"AP\n8="`), false, false},
		{"base64_unpadded", []byte(`"AP8"`), false, false},
		{"base64_noncanonical_padding_bits", []byte(`"AP9="`), false, false},
		{"base64_escaped_character", []byte(`"\u0041P8="`), false, false},
		{"base64_outer_whitespace", []byte(` "AP8=" `), false, false},
		{"RawMessage_original_array", []byte(`[0,255]`), true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Exact typed transport only; no writer/native/Source capability.
			var target any
			kind := reflect.TypeOf([]byte(nil))
			if test.rawMessage {
				target = new(json.RawMessage)
				kind = reflect.TypeOf(json.RawMessage(nil))
			} else {
				target = new([]byte)
			}
			err := hostOriginalStrictJSON(test.raw, target, 65536)
			if err == nil {
				err = originalHostSourceCustodyRequiredFields(test.raw, kind, 0)
			}
			if (err == nil) != test.accepted {
				t.Fatal("closed original byte transport", test.name, err)
			}
		})
	}
}

// These are unsigned, unacquired method vectors. They discriminate the
// private custody parser, not native observations, SQL FIRST or Source trust.
func hostOriginalSourceGetdentsFileVector(root string, writer bool, count int) hostOriginalGetdentsSourceFileSelection {
	handle := uuid.NewString()
	ops := []string{"source_file_open", "source_file_fstat"}
	if writer {
		if count > 0 {
			ops = append(ops, "source_file_write")
		}
		ops = append(ops, "source_file_sync")
	} else {
		if count > 0 {
			ops = append(ops, "source_file_read")
		}
		ops = append(ops, "source_file_read", "source_file_fstat")
	}
	ops = append(ops, "source_file_close")
	selection := hostOriginalGetdentsSourceFileSelection{OriginalHandleID: handle, OriginalCloseCallID: handle + ":" + strconv.Itoa(len(ops))}
	start := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	readBytesReturned := false
	for n, op := range ops {
		id, called := handle+":"+strconv.Itoa(n+1), start.Add(time.Duration(n*2)*time.Second)
		returned, failed := called.Add(time.Second), false
		fact := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: root, OriginalAuditHandleID: handle, OriginalCallID: &id, Operation: op, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: start.Add(time.Minute), OriginalErrorPresent: &failed, OriginalHashState: "not_byte_operation"}
		if op == "source_file_write" {
			fact.OriginalCount, fact.OriginalHashState = hostFactoryStoragePtr(int64(count)), "private_withheld"
		} else if op == "source_file_read" {
			fact.OriginalHashState = "private_withheld"
			if count > 0 && !readBytesReturned {
				fact.OriginalCount, fact.OriginalEOF = hostFactoryStoragePtr(int64(count)), hostFactoryStoragePtr(false)
				readBytesReturned = true
			} else {
				fact.OriginalCount, fact.OriginalEOF, fact.OriginalErrorPresent = hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(true), hostFactoryStoragePtr(true)
			}
		}
		selection.OriginalCallReferences = append(selection.OriginalCallReferences, id)
		selection.OriginalSourceAuditProjections = append(selection.OriginalSourceAuditProjections, hostOriginalSourceAuditProjection{Family: "source_audit", SubjectIdentity: hostOriginalSubjectIdentity{SubjectKind: "source_file"}, Fact: fact, OriginalCloseReference: &selection.OriginalCloseCallID})
	}
	return selection
}

func TestHostOriginalFactorySourceGetdentsFileCustodySelection(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, name := range []string{"known_empty_reader", "known_empty_writer_no_write", "nonempty_reader", "nonempty_writer", "normalized_EOF_error", "synthetic_Write_zero", "unknown_Close", "byte_SHA_leak", "missing_second_Fstat", "foreign_root", "late_Close", "duplicated_CallID", "count_mismatch", "request_identity_alias"} {
		t.Run(name, func(t *testing.T) {
			root := uuid.NewString()
			writer := name == "known_empty_writer_no_write" || name == "nonempty_writer" || name == "synthetic_Write_zero"
			count := 0
			if name == "nonempty_reader" || name == "nonempty_writer" {
				count = 8
			}
			selection := hostOriginalSourceGetdentsFileVector(root, writer, count)
			rows := selection.OriginalSourceAuditProjections
			want := name == "known_empty_reader" || name == "known_empty_writer_no_write" || name == "nonempty_reader" || name == "nonempty_writer"
			switch name {
			case "normalized_EOF_error":
				rows[2].Fact.OriginalErrorPresent = hostFactoryStoragePtr(false)
			case "synthetic_Write_zero":
				rows[2].Fact.Operation = "source_file_write"
				rows[2].Fact.OriginalCount = hostFactoryStoragePtr(int64(0))
				rows[2].Fact.OriginalHashState = "private_withheld"
			case "unknown_Close":
				rows[2].OriginalCloseReference = nil
			case "byte_SHA_leak":
				rows[2].Fact.OriginalSHA256 = hostFactoryStoragePtr(capacity.HostFactoryRawSHA256(nil))
			case "missing_second_Fstat":
				rows[3].Fact.Operation = "source_file_sync"
			case "foreign_root":
				rows[2].Fact.FactoryRootID = uuid.NewString()
			case "late_Close":
				rows[len(rows)-1].Fact.OriginalReturnedAt = &rows[len(rows)-1].Fact.OriginalOperationDeadline
			case "duplicated_CallID":
				rows[2].Fact.OriginalCallID = rows[1].Fact.OriginalCallID
			case "count_mismatch":
				count = 1
			case "request_identity_alias":
				rows[2].SubjectIdentity.RequestIdentity = hostFactoryStoragePtr(uuid.NewString())
			}
			if err := originalHostGetdentsSourceSelection(selection, root, writer, count); (err == nil) != want {
				t.Fatal("Source-only owned custody shape", name, err)
			}
		})
	}
}

func TestHostOriginalFactorySourceGetdentsCustodyNativeIdentity(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, name := range []string{"known_empty_local_kernel", "unknown_NULL_raw", "file_EOF_native_alias", "native_errno", "native_scalar_mismatch", "foreign_native_owner", "foreign_chunk_BODY", "foreign_chunk_envelope", "foreign_fact_index", "missing_RequestUUID", "local_with_reader", "unknown_custody_class", "duplicate_JSON_key", "unknown_JSON_key", "omitted_NULL_reader", "omitted_zero_count", "trailing_JSON", "oversize_whole"} {
		t.Run(name, func(t *testing.T) {
			handle, owner, root := uuid.NewString(), uuid.NewString(), uuid.NewString()
			call, digest := handle+":1", strings.Repeat("a", 64)
			zero, no := int64(0), false
			raw := make([]byte, 0)
			emptySHA := capacity.HostFactoryRawSHA256(raw)
			fact := model.HostFactoryPrimitiveIOReturn{OriginalHandleID: handle, OriginalCallID: &call, OriginalState: "returned", OriginalCount: &zero, OriginalSHA256: &emptySHA, OriginalEOF: &no, OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "unix_getdents64", OriginalScalar: &zero, OriginalErrorPresent: &no, OriginalErrno: hostFactoryStoragePtr(uint32(0))}}
			identity := hostOriginalGetdentsCustodyIdentity{root, owner, "original_host_factory_root_preparation_v4", digest, digest, digest, 0, fact}
			custody := hostOriginalGetdentsSourceAuditCustody{Schema: "source_private_original_getdents_source_audit_custody_v1", CustodyClass: "local_kernel", FactoryRootID: root, RequestID: uuid.NewString(), Phase: "initial", OriginalCallID: call, OriginalChunkBodySHA256: digest, OriginalChunkEnvelopeSHA256: digest, OriginalOwnerID: owner, BindingSchema: identity.schema, BindingSHA256: digest, OriginalRawSHA256: emptySHA}
			switch name {
			case "unknown_NULL_raw":
				raw = nil
			case "file_EOF_native_alias":
				identity.fact.OriginalEOF = hostFactoryStoragePtr(true)
			case "native_errno":
				identity.fact.OriginalNativeReturn.OriginalErrno = hostFactoryStoragePtr(uint32(2))
			case "native_scalar_mismatch":
				identity.fact.OriginalNativeReturn.OriginalScalar = hostFactoryStoragePtr(int64(1))
			case "foreign_native_owner":
				custody.OriginalOwnerID = uuid.NewString()
			case "foreign_chunk_BODY":
				custody.OriginalChunkBodySHA256 = strings.Repeat("b", 64)
			case "foreign_chunk_envelope":
				custody.OriginalChunkEnvelopeSHA256 = strings.Repeat("b", 64)
			case "foreign_fact_index":
				custody.OriginalFactIndex = 1
			case "missing_RequestUUID":
				custody.RequestID = ""
			case "local_with_reader":
				custody.OriginalReaderAudit = &hostOriginalGetdentsSourceFileSelection{}
			case "unknown_custody_class":
				custody.CustodyClass = "file_eof"
			}
			wire, err := json.Marshal(custody)
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "duplicate_JSON_key":
				wire = bytes.Replace(wire, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1)
			case "unknown_JSON_key":
				wire = bytes.Replace(wire, []byte(`"schema":`), []byte(`"unknown":null,"schema":`), 1)
			case "omitted_NULL_reader":
				wire = bytes.Replace(wire, []byte(`"original_reader_audit":null,`), nil, 1)
			case "omitted_zero_count":
				wire = bytes.Replace(wire, []byte(`"original_raw_bytes":0,`), nil, 1)
			case "trailing_JSON":
				wire = append(wire, []byte(`{}`)...)
			case "oversize_whole":
				wire = bytes.Repeat([]byte(" "), 65537)
			}
			if _, err := originalHostGetdentsSourceCustody(wire, identity, raw); (err == nil) != (name == "known_empty_local_kernel") {
				t.Fatal("Source-only custody identity", name, err)
			}
		})
	}
	if _, _, installed := OriginalHostFactoryRealm(); installed {
		t.Fatal("private parser vectors installed Source trust")
	}
}

func hostOriginalSourceTransferredGetdentsVector(t *testing.T) (hostOriginalGetdentsSourceAuditCustody, hostOriginalGetdentsCustodyIdentity, []byte) {
	t.Helper()
	root, owner, nativeHandle, request, digest := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), strings.Repeat("a", 64)
	call, empty := nativeHandle+":1", make([]byte, 0)
	emptySHA, zero, no := capacity.HostFactoryRawSHA256(empty), int64(0), false
	origin := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	nativeReturned := origin.Add(-time.Second)
	fact := model.HostFactoryPrimitiveIOReturn{OriginalHandleID: nativeHandle, OriginalCallID: &call, OriginalState: "returned", OriginalReturnedAt: &nativeReturned, OriginalCount: &zero, OriginalSHA256: &emptySHA, OriginalEOF: &no, OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "unix_getdents64", OriginalScalar: &zero, OriginalErrno: hostFactoryStoragePtr(uint32(0)), OriginalErrorPresent: &no}}
	identity := hostOriginalGetdentsCustodyIdentity{root, owner, "original_host_factory_root_preparation_v4", digest, digest, digest, 0, fact}
	writerSelection := hostOriginalSourceGetdentsFileVector(root, true, 0)
	method := uuid.NewString()
	projections, methodRefs := append([]hostOriginalSourceAuditProjection{}, writerSelection.OriginalSourceAuditProjections...), []string{}
	for n, operation := range []string{"source_file_rename_noreplace", "source_directory_sync"} {
		id, called := method+":"+strconv.Itoa(n+1), origin.Add(time.Duration(8+n*2)*time.Second)
		returned := called.Add(time.Second)
		projections = append(projections, hostOriginalSourceAuditProjection{Family: "source_audit", SubjectIdentity: hostOriginalSubjectIdentity{SubjectKind: "source_file"}, Fact: model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: root, OriginalAuditHandleID: method, OriginalCallID: &id, Operation: operation, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: origin.Add(time.Minute), OriginalErrorPresent: &no, OriginalHashState: "not_byte_operation"}})
		methodRefs = append(methodRefs, id)
	}
	artifact := hostOriginalGetdentsWriterAuditArtifact{Schema: "source_private_original_getdents_writer_audit_v1", FactoryRootID: root, RequestID: request, Phase: "initial", OriginalCallID: call, OriginalChunkBodySHA256: digest, OriginalChunkEnvelopeSHA256: digest, OriginalOwnerID: owner, BindingSchema: identity.schema, BindingSHA256: digest, OriginalRawSHA256: emptySHA, SourceAuditOwnerID: uuid.NewString(), SourceAuditOwnerRole: "host_exterior", SourceAuditBindingSchema: identity.schema, SourceAuditBindingSHA256: digest, OriginalWriterHandleID: writerSelection.OriginalHandleID, OriginalWriterCloseCallID: writerSelection.OriginalCloseCallID, OriginalPublicationMethodHandleID: method, OriginalWriterCallReferences: writerSelection.OriginalCallReferences, OriginalPublicationCallReferences: methodRefs, OriginalSourceAuditProjections: projections}
	artifactRaw, err := json.Marshal(artifact)
	if err != nil {
		t.Fatal(err)
	}
	ref := hostOriginalGetdentsWriterAuditReference{Basename: request + "-" + capacity.HostFactoryRawSHA256([]byte(call)) + ".writer-audit", OriginalBytes: len(artifactRaw), OriginalSHA256: capacity.HostFactoryRawSHA256(artifactRaw), RequestID: request, OriginalCallID: call, OriginalChunkBodySHA256: digest, OriginalChunkEnvelopeSHA256: digest, OriginalOwnerID: owner, BindingSchema: identity.schema, BindingSHA256: digest, OriginalWriterHandleID: artifact.OriginalWriterHandleID, OriginalWriterCloseCallID: artifact.OriginalWriterCloseCallID, OriginalPublicationMethodHandleID: method, OriginalWriterCallReferences: artifact.OriginalWriterCallReferences, OriginalPublicationCallReferences: methodRefs}
	reader, artifactReader := hostOriginalSourceGetdentsFileVector(root, false, 0), hostOriginalSourceGetdentsFileVector(root, false, len(artifactRaw))
	for n, selection := range []*hostOriginalGetdentsSourceFileSelection{&reader, &artifactReader} {
		for index := range selection.OriginalSourceAuditProjections {
			fact := &selection.OriginalSourceAuditProjections[index].Fact
			called, returned := fact.OriginalCalledAt.Add(time.Duration(20+n*20)*time.Second), fact.OriginalReturnedAt.Add(time.Duration(20+n*20)*time.Second)
			fact.OriginalCalledAt, fact.OriginalReturnedAt = &called, &returned
		}
	}
	return hostOriginalGetdentsSourceAuditCustody{Schema: "source_private_original_getdents_source_audit_custody_v1", CustodyClass: "transferred_file", FactoryRootID: root, RequestID: request, Phase: "initial", OriginalCallID: call, OriginalChunkBodySHA256: digest, OriginalChunkEnvelopeSHA256: digest, OriginalOwnerID: owner, BindingSchema: identity.schema, BindingSHA256: digest, OriginalRawSHA256: emptySHA, OriginalReaderAudit: &reader, OriginalWriterAudit: &ref, OriginalWriterAuditRaw: &artifactRaw, OriginalWriterAuditArtifactReader: &artifactReader}, identity, empty
}

func TestHostOriginalFactorySourceTransferredGetdentsCustody(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, name := range []string{"known_empty_transferred_shape", "reader_unknown", "writer_unknown", "artifact_raw_unknown", "artifact_reader_unknown", "foreign_writer_RAW_SHA", "foreign_writer_native_owner", "reader_writer_alias", "artifact_reader_alias", "publication_method_alias", "native_after_writer", "reader_before_rename", "artifact_reader_before_sync", "private_hash_leak", "writer_ref_CallID_mismatch", "omitted_nested_NULL", "numeric_byte_array_alias", "base64_newline_alias"} {
		t.Run(name, func(t *testing.T) {
			custody, identity, raw := hostOriginalSourceTransferredGetdentsVector(t)
			switch name {
			case "reader_unknown":
				custody.OriginalReaderAudit = nil
			case "writer_unknown":
				custody.OriginalWriterAudit = nil
			case "artifact_raw_unknown":
				custody.OriginalWriterAuditRaw = nil
			case "artifact_reader_unknown":
				custody.OriginalWriterAuditArtifactReader = nil
			case "foreign_writer_RAW_SHA":
				custody.OriginalWriterAudit.OriginalSHA256 = strings.Repeat("b", 64)
			case "foreign_writer_native_owner":
				custody.OriginalWriterAudit.OriginalOwnerID = uuid.NewString()
			case "reader_writer_alias":
				custody.OriginalReaderAudit.OriginalHandleID = custody.OriginalWriterAudit.OriginalWriterHandleID
			case "artifact_reader_alias":
				custody.OriginalWriterAuditArtifactReader.OriginalHandleID = custody.OriginalReaderAudit.OriginalHandleID
			case "publication_method_alias":
				custody.OriginalWriterAudit.OriginalPublicationMethodHandleID = custody.OriginalReaderAudit.OriginalHandleID
			case "native_after_writer":
				at := time.Date(2026, 10, 13, 12, 0, 1, 0, time.UTC)
				identity.fact.OriginalReturnedAt = &at
			case "reader_before_rename":
				at := time.Date(2026, 10, 13, 12, 0, 8, 0, time.UTC)
				custody.OriginalReaderAudit.OriginalSourceAuditProjections[0].Fact.OriginalCalledAt = &at
			case "artifact_reader_before_sync":
				at := time.Date(2026, 10, 13, 12, 0, 10, 0, time.UTC)
				custody.OriginalWriterAuditArtifactReader.OriginalSourceAuditProjections[0].Fact.OriginalCalledAt = &at
			case "private_hash_leak":
				custody.OriginalReaderAudit.OriginalSourceAuditProjections[2].Fact.OriginalSHA256 = hostFactoryStoragePtr(capacity.HostFactoryRawSHA256(raw))
			case "writer_ref_CallID_mismatch":
				custody.OriginalWriterAudit.OriginalWriterCallReferences = append([]string{}, custody.OriginalWriterAudit.OriginalWriterCallReferences...)
				custody.OriginalWriterAudit.OriginalWriterCallReferences[0] = uuid.NewString() + ":1"
			}
			wire, err := json.Marshal(custody)
			if err != nil {
				t.Fatal(err)
			}
			if name == "omitted_nested_NULL" {
				wire = bytes.Replace(wire, []byte(`"request_identity":null,`), nil, 1)
			}
			if name == "numeric_byte_array_alias" || name == "base64_newline_alias" {
				original, err := json.Marshal(*custody.OriginalWriterAuditRaw)
				if err != nil {
					t.Fatal(err)
				}
				var replacement []byte
				if name == "numeric_byte_array_alias" {
					values := make([]int, len(*custody.OriginalWriterAuditRaw))
					for n, value := range *custody.OriginalWriterAuditRaw {
						values[n] = int(value)
					}
					replacement, err = json.Marshal(values)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					replacement = append([]byte{}, original[:3]...)
					replacement = append(replacement, []byte(`\n`)...)
					replacement = append(replacement, original[3:]...)
				}
				wire = bytes.Replace(wire, append([]byte(`"original_writer_audit_raw":`), original...), append([]byte(`"original_writer_audit_raw":`), replacement...), 1)
			}
			if _, err = originalHostGetdentsSourceCustody(wire, identity, raw); (err == nil) != (name == "known_empty_transferred_shape") {
				t.Fatal("Source-only transferred parser shape", name, err)
			}
		})
	}
}

func TestHostOriginalFactorySourceNativeSelectors(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	digest := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, selector string
		accepted       bool
	}{
		{"record_pair", "native-observations/record/" + digest + "/" + digest, true},
		{"manifest_pair", "native-observations/manifest/" + digest + "/" + digest, true},
		{"io_namespace_alias", "io-calls/record/" + digest + "/" + digest, false},
		{"unknown_kind", "native-observations/chunk/" + digest + "/" + digest, false},
		{"missing_envelope", "native-observations/record/" + digest, false},
		{"extra_component", "native-observations/record/" + digest + "/" + digest + "/x", false},
		{"query_suffix", "native-observations/record/" + digest + "/" + digest + "?sha256=" + digest, false},
		{"uppercase_body", "native-observations/record/" + strings.ToUpper(digest) + "/" + digest, false},
		{"empty_body", "native-observations/record//" + digest, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := originalHostNativeSelector(test.selector)
			if (err == nil) != test.accepted {
				t.Fatal("exact native readonly selector", err)
			}
		})
	}
}

func TestHostOriginalFactorySourceNativePrivateInventoryRelations(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	owner, handle := uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("a", 64)
	ref := model.HostFactoryCallVectorReference{Operation: "stdout_read", OriginalHandleID: handle, OriginalOwnerID: owner, OwnerPrimitiveRawSHA256: &digest, SubjectOwnerID: owner, FirstOrdinal: 1, LastOrdinal: 1, OriginalCallCount: 1, ManifestRootSHA256: &digest, CollectionState: "complete_original_calls"}
	// Deliberately incomplete native payload. Only the closed private vector
	// selection decoder is exercised; whole native validation must refuse it.
	ioProjection := model.HostFactoryOriginalIOFact{OriginalCallVector: ref, OriginalCloseCallVector: ref}
	record := model.HostFactoryNativeObservationRecord{TaskDirectory: &model.HostFactoryTaskDirectoryRead{OriginalSubjectStatBeforeRead: ioProjection, OriginalSubjectStatAfterRead: ioProjection, OriginalOpenCallVector: ref, OriginalFstatCallVector: ref, OriginalGetdentsCallVector: ref, OriginalCloseCallVector: ref}}
	relation := hostOriginalNativeInventoryRelation{OriginalCallVector: ref, OriginalInventoryBodySHA256: digest, OriginalInventoryEnvelopeSHA256: digest}
	valid, _ := json.Marshal([]hostOriginalNativeInventoryRelation{relation})
	duplicate, _ := json.Marshal([]hostOriginalNativeInventoryRelation{relation, relation})
	foreign := relation
	foreign.OriginalCallVector.OriginalHandleID = uuid.NewString()
	foreignRaw, _ := json.Marshal([]hostOriginalNativeInventoryRelation{foreign})
	missingDigest := relation
	missingDigest.OriginalInventoryEnvelopeSHA256 = ""
	missingRaw, _ := json.Marshal([]hostOriginalNativeInventoryRelation{missingDigest})
	unknown := bytes.Replace(valid, []byte(`"original_inventory_body_sha256":`), []byte(`"unknown":null,"original_inventory_body_sha256":`), 1)
	duplicateKey := bytes.Replace(valid, []byte(`"original_inventory_body_sha256":`), []byte(`"original_inventory_body_sha256":"`+digest+`","original_inventory_body_sha256":`), 1)
	for _, test := range []struct {
		name     string
		raw      []byte
		accepted bool
	}{
		{"exact_dedup_selection", valid, true}, {"duplicate_vector", duplicate, false}, {"foreign_vector", foreignRaw, false}, {"missing_digest", missingRaw, false}, {"unknown_key", unknown, false}, {"duplicate_key", duplicateKey, false}, {"empty_array", []byte(`[]`), false}, {"trailing_json", append(bytes.Clone(valid), []byte(`{}`)...), false}, {"oversize_whole_relation", bytes.Repeat([]byte(" "), 65537), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeOriginalHostNativeInventoryRelations(test.raw, record)
			if (err == nil) != test.accepted {
				t.Fatal("closed original private relation", err)
			}
		})
	}
	if capacity.ValidateHostFactory(record) == nil {
		t.Fatal("incomplete parser vector falsely native-admitted")
	}
}

func TestHostOriginalFactorySourceNativeGetdentsCustody(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	call := uuid.NewString() + ":1"
	zero := int64(0)
	no := false
	emptySHA := capacity.HostFactoryRawSHA256(nil)
	fact := model.HostFactoryPrimitiveIOReturn{OriginalState: "returned", OriginalCallID: &call, OriginalCount: &zero, OriginalSHA256: &emptySHA, OriginalEOF: &no, OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "unix_getdents64", OriginalScalar: &zero, OriginalErrorPresent: &no}}
	for _, test := range []struct {
		name     string
		raw      []byte
		mutate   func(*model.HostFactoryPrimitiveIOReturn)
		accepted bool
	}{
		{"known_terminal_empty", make([]byte, 0), nil, true},
		{"unknown_null", nil, nil, false},
		{"count_mismatch", []byte{1}, nil, false},
		{"oversize_raw", make([]byte, 65537), nil, false},
		{"native_zero_is_not_eof", make([]byte, 0), func(x *model.HostFactoryPrimitiveIOReturn) { x.OriginalEOF = hostFactoryStoragePtr(true) }, false},
		{"wrong_raw_digest", make([]byte, 0), func(x *model.HostFactoryPrimitiveIOReturn) {
			x.OriginalSHA256 = hostFactoryStoragePtr(strings.Repeat("a", 64))
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			x := fact
			if test.mutate != nil {
				test.mutate(&x)
			}
			raw, err := originalHostGetdentsBeforeLink(x, func(id string) ([]byte, error) {
				if id != call {
					t.Fatal("different original call")
				}
				return test.raw, nil
			})
			if (err == nil) != test.accepted || test.accepted && raw == nil {
				t.Fatal("actual known custody distinction", err)
			}
		})
	}
	pending := fact
	pending.OriginalState = "called_pending"
	if raw, err := originalHostGetdentsBeforeLink(pending, func(string) ([]byte, error) { t.Fatal("pending must not request bytes"); return nil, nil }); err != nil || raw != nil {
		t.Fatal("pending stayed unknown", err)
	}
	// None of the helper's structural buffer checks creates an actual realm.
	if _, _, ok := OriginalHostFactoryRealm(); ok {
		t.Fatal("test process installed a native capability")
	}
	if _, _, _, err := originalHostNativeSelector("native-observations/record/" + emptySHA + "/" + emptySHA); err != nil {
		t.Fatal(err)
	}
}

func TestHostOriginalFactorySourceNativeSevenFixedPhaseAnchors(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	selected := model.HostFactoryNativeObservationReference{ObservationID: uuid.NewString()}
	foreign := model.HostFactoryNativeObservationReference{ObservationID: uuid.NewString()}
	for _, test := range []struct {
		name string
		body any
	}{
		{"original_start_exterior", &model.HostFactoryOriginalStartReturn{Exterior: selected}},
		{"alive_worker", &model.HostFactoryAliveNativeRead{Worker: selected, Exterior: foreign, Registrar: foreign}},
		{"exterior_join_exterior", &model.HostFactoryExteriorJoin{Exterior: selected}},
		{"terminal_reader_before", &model.HostFactoryTerminalRead{ReaderBefore: selected, ReaderAfter: foreign, ExteriorBefore: foreign, ExteriorAfter: foreign}},
		{"native_leaf_process", &model.HostFactoryNativeLeaf{Process: selected, OriginalTaskInventoryRead: foreign}},
		{"initial_empty_control_before", &model.HostFactoryInitialEmptyRealmRead{ControlBefore: selected, ControlAfter: foreign, RegistrarBefore: foreign, RegistrarAfter: foreign}},
		{"original_empty_control_before", &model.HostFactoryOriginalEmptyRealmRead{ControlProcessBefore: selected, ControlProcessAfter: foreign, WorkerBefore: foreign, WorkerAfter: foreign}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Selection identity only: intentionally incomplete unsigned aggregates
			// cannot supply native proof/current EMPTY/full roster/lease authority.
			ref, err := originalHostNativePhaseOwner(test.body)
			if err != nil || ref.ObservationID != selected.ObservationID {
				t.Fatal("fixed signed anchor selection differs", err)
			}
			if _, err = originalHostNativePhaseDeadlineTx(context.Background(), nil, uuid.NewString(), test.body); err == nil {
				t.Fatal("missing original phase/source/SQL custody accepted")
			}
			if _, err = resolveOriginalHostHistoricalNativeAggregateTx(nil, nil, uuid.NewString(), "original_host_factory_root_preparation_v4", strings.Repeat("a", 64), time.Now().UTC(), test.body, ""); err == nil {
				t.Fatal("missing original source/context/native graph accepted")
			}
		})
	}
	t.Run("unknown_aggregate", func(t *testing.T) {
		if _, err := originalHostNativePhaseOwner(&model.HostFactoryRootCompletion{}); err == nil {
			t.Fatal("unknown phase type accepted")
		}
	})
}

func TestHostOriginalFactorySourceNativePrivatePhaseWire(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	digest := strings.Repeat("a", 64)
	start := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	owner := uuid.NewString()
	anchor := model.HostFactoryNativeObservationReference{ObservationID: uuid.NewString(), ObservationKind: "process", OriginalBodySHA256: digest, OriginalEnvelopeSHA256: digest, ObserverOwnerID: owner, ObserverPrimitiveRawSHA256: digest, SubjectOwnerID: uuid.NewString(), SubjectPrimitiveRawSHA256: digest}
	original := hostOriginalNativePhase{Schema: "source_private_original_native_phase_context_v1", FactoryRootID: uuid.NewString(), SourceApprovalBodySHA256: digest, OriginalPhaseID: uuid.NewString(), StageSelector: "initial-empty-realm-read", AggregateSchema: "original_host_factory_initial_empty_realm_read_v5", AggregateBodySHA256: digest, AggregateEnvelopeSHA256: digest, PhaseAnchor: anchor, ObserverOwnerID: owner, ObserverPrimitiveRawSHA256: digest, BindingSchema: "original_host_factory_root_preparation_v4", BindingSHA256: digest, OriginalContextStartedAt: start, OriginalRootContextDeadline: start.Add(300 * time.Second), OriginalEffectiveDeadline: start.Add(60 * time.Second), OriginalCalledAt: start.Add(time.Second), OriginalReturnedAt: start.Add(2 * time.Second)}
	valid, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeOriginalHostNativePhaseWire(valid); err != nil {
		t.Fatal("closed private shape with genuine-type reference refused", err)
	}
	// This structural decoder has no Source capability, SQL-FIRST, signed
	// aggregate or native proof. The complete semantic consumer still refuses.
	if _, err = decodeOriginalHostNativePhase(hostOriginalConstraintCodec(), valid, &model.HostFactoryInitialEmptyRealmRead{ControlBefore: anchor}, digest, digest, original.BindingSchema, digest); err == nil {
		t.Fatal("unsigned structural phase supplied native authority")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*hostOriginalNativePhase)
	}{
		{"missing_original_schema", func(x *hostOriginalNativePhase) { x.Schema = "" }},
		{"missing_root", func(x *hostOriginalNativePhase) { x.FactoryRootID = "" }},
		{"noncanonical_root_uuid", func(x *hostOriginalNativePhase) { x.FactoryRootID = strings.ReplaceAll(x.FactoryRootID, "-", "") }},
		{"missing_approval", func(x *hostOriginalNativePhase) { x.SourceApprovalBodySHA256 = "" }},
		{"request_identity_is_observation", func(x *hostOriginalNativePhase) { x.OriginalPhaseID = x.PhaseAnchor.ObservationID }},
		{"unknown_stage", func(x *hostOriginalNativePhase) { x.StageSelector = "ordinary-source-binding" }},
		{"wrong_aggregate_version", func(x *hostOriginalNativePhase) {
			x.AggregateSchema = "original_host_factory_initial_empty_realm_read_v4"
		}},
		{"missing_body_identity", func(x *hostOriginalNativePhase) { x.AggregateBodySHA256 = "" }},
		{"missing_envelope_identity", func(x *hostOriginalNativePhase) { x.AggregateEnvelopeSHA256 = "" }},
		{"foreign_observer", func(x *hostOriginalNativePhase) { x.ObserverOwnerID = uuid.NewString() }},
		{"foreign_basal", func(x *hostOriginalNativePhase) { x.ObserverPrimitiveRawSHA256 = strings.Repeat("b", 64) }},
		{"unsupported_basal_binding", func(x *hostOriginalNativePhase) { x.BindingSchema = "original_host_factory_basal_owner_observation_v3" }},
		{"missing_binding_identity", func(x *hostOriginalNativePhase) { x.BindingSHA256 = "" }},
		{"unknown_original_start", func(x *hostOriginalNativePhase) { x.OriginalContextStartedAt = time.Time{} }},
		{"nonUTC_original_start", func(x *hostOriginalNativePhase) {
			x.OriginalContextStartedAt = x.OriginalContextStartedAt.In(time.FixedZone("caller", 3600))
		}},
		{"call_before_source_context", func(x *hostOriginalNativePhase) { x.OriginalCalledAt = start.Add(-time.Nanosecond) }},
		{"return_before_original_call", func(x *hostOriginalNativePhase) { x.OriginalReturnedAt = x.OriginalCalledAt.Add(-time.Nanosecond) }},
		{"late_original_return", func(x *hostOriginalNativePhase) {
			x.OriginalReturnedAt = x.OriginalEffectiveDeadline.Add(time.Nanosecond)
		}},
		{"effective_not_after_call", func(x *hostOriginalNativePhase) { x.OriginalEffectiveDeadline = x.OriginalCalledAt }},
		{"effective_widens_actual_parent", func(x *hostOriginalNativePhase) { x.OriginalEffectiveDeadline = start.Add(600 * time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			phase := original
			tc.mutate(&phase)
			raw, err := json.Marshal(phase)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decodeOriginalHostNativePhaseWire(raw); err == nil {
				t.Fatal("private phase shape widened or fabricated original custody")
			}
		})
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"unknown_key", bytes.Replace(valid, []byte(`"schema":`), []byte(`"unknown":null,"schema":`), 1)},
		{"duplicate_key", bytes.Replace(valid, []byte(`"schema":`), []byte(`"schema":"x","schema":`), 1)},
		{"trailing_json", append(bytes.Clone(valid), []byte(`{}`)...)},
		{"whole_cap_no_trimming", bytes.Repeat([]byte(" "), 65537)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeOriginalHostNativePhaseWire(tc.raw); err == nil {
				t.Fatal("open/oversize phase wire accepted")
			}
		})
	}
}

func TestHostOriginalFactorySourcePrivateEmptyPublicationCustody(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	start := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"empty_zero_write_chain", "empty_without_original_custody", "nonempty_actual_write_chain", "fake_Write_zero_refused", "missing_Sync_refused", "foreign_Close_refused", "method_Rename_after_Close_separate"} {
		t.Run(name, func(t *testing.T) {
			handle := uuid.NewString()
			factory := uuid.NewString()
			ops := []string{"source_file_open", "source_file_fstat", "source_file_sync", "source_file_close"}
			if name == "nonempty_actual_write_chain" || name == "fake_Write_zero_refused" {
				ops = []string{"source_file_open", "source_file_fstat", "source_file_write", "source_file_sync", "source_file_close"}
			}
			closeID := handle + ":" + strconv.Itoa(len(ops))
			var rows []hostOriginalSourceAuditProjection
			for n, op := range ops {
				id := handle + ":" + strconv.Itoa(n+1)
				called := start.Add(time.Duration(n*2) * time.Second)
				returned := called.Add(time.Second)
				failed := false
				fact := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: factory, OriginalAuditHandleID: handle, OriginalCallID: &id, Operation: op, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: start.Add(600 * time.Second), OriginalErrorPresent: &failed, OriginalHashState: "not_byte_operation"}
				if op == "source_file_write" {
					count := int64(1)
					if name == "fake_Write_zero_refused" {
						count = 0
					}
					fact.OriginalCount = &count
					fact.OriginalHashState = "private_withheld"
				}
				rows = append(rows, hostOriginalSourceAuditProjection{Family: "source_audit", SubjectIdentity: hostOriginalSubjectIdentity{SubjectKind: "source_file"}, Fact: fact, OriginalCloseReference: &closeID})
			}
			if name == "missing_Sync_refused" {
				rows[2].Fact.Operation = "source_file_fstat"
			}
			if name == "foreign_Close_refused" {
				foreign := uuid.NewString() + ":4"
				rows[1].OriginalCloseReference = &foreign
			}
			if name == "method_Rename_after_Close_separate" {
				rows[2].Fact.Operation = "source_file_rename_noreplace"
			}
			// This discriminates the internal selected-parser branch. The live
			// caller never takes a supplied bool: only authenticated immutable
			// native/SQL/private custody selects the exact zero-file handle.
			selected := name == "empty_zero_write_chain"
			err := verifyOriginalHostSourcePublicationWriteSelected(rows, handle, selected)
			accepted := name == "empty_zero_write_chain" || name == "nonempty_actual_write_chain"
			if (err == nil) != accepted {
				t.Fatal("closed actual Source custody shape only", err)
			}
		})
	}
}

func TestHostOriginalFactorySourcePrivateEmptyReadCustody(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, name := range []string{"known_empty_private_read", "empty_without_original_custody", "selected_policy_empty_refused", "missing_empty_post_Fstat", "normalized_empty_EOF_refused"} {
		t.Run(name, func(t *testing.T) {
			rows := map[string]hostOriginalSourceAuditProjection{}
			var policy []string
			start := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
			factory := uuid.NewString()
			var emptyHandle string
			for input := 0; input < 4; input++ {
				handle := uuid.NewString()
				if input == 3 {
					emptyHandle = handle
				}
				closeID := handle + ":5"
				for n, op := range []string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_fstat", "source_file_close"} {
					id := handle + ":" + strconv.Itoa(n+1)
					called := start.Add(time.Duration(input*20+n*2) * time.Second)
					returned := called.Add(time.Second)
					failed := op == "source_file_read"
					fact := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: factory, OriginalAuditHandleID: handle, OriginalCallID: &id, Operation: op, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: start.Add(600 * time.Second), OriginalErrorPresent: &failed, OriginalHashState: "not_byte_operation"}
					if op == "source_file_read" {
						count, eof := int64(17), true
						if input == 3 || name == "selected_policy_empty_refused" && input == 0 {
							count = 0
						}
						fact.OriginalCount = &count
						fact.OriginalEOF = &eof
						fact.OriginalHashState = "private_withheld"
					}
					rows[id] = hostOriginalSourceAuditProjection{Family: "source_audit", SubjectIdentity: hostOriginalSubjectIdentity{SubjectKind: "source_file"}, Fact: fact, OriginalCloseReference: &closeID}
					if input < 3 {
						policy = append(policy, id)
					}
				}
			}
			switch name {
			case "missing_empty_post_Fstat":
				delete(rows, emptyHandle+":4")
			case "normalized_empty_EOF_refused":
				id := emptyHandle + ":3"
				row := rows[id]
				row.Fact.OriginalErrorPresent = hostFactoryStoragePtr(false)
				rows[id] = row
			}
			if err := verifyOriginalHostHistoricalSourceFileAudits(rows, policy); err == nil {
				t.Fatal("generic file EOF/count0 supplied original getdents custody")
			}
			selected := map[string]bool{}
			if name != "empty_without_original_custody" {
				// Only this unexported parser algorithm is supplied a vector
				// selection. Production obtains it from the strict SAME SQL
				// FIRST/native signed chunk/private audit custody joins.
				selected[emptyHandle] = true
			}
			err := verifyOriginalHostHistoricalSourceFileAuditsSelected(rows, policy, selected)
			if (err == nil) != (name == "known_empty_private_read") {
				t.Fatal("original empty Source custody differs", err)
			}
			// File EOF/count0 is an unsigned nonauthority custody return. It does
			// not construct an original native getdents result or approved realm.
		})
	}
}

// Isolated unexecuted Source/PG proposal: native_postgres_cases_test.go
type hostFactoryNativeStorageRow struct {
	tag, identity, observation, kind, subject, primitive, subjectPrimitive, collection string
	nativeRoot, owner, binding                                                         string
	handle, operation                                                                  *string
	firstIO, lastIO                                                                    *int
	ordinal, level, first, last, count                                                 *int
	relations, body, envelope                                                          []byte
}

func hostFactoryNativeStorage(t *testing.T, tx *sql.Tx, f hostFactoryStorageVector, tag string) hostFactoryNativeStorageRow {
	t.Helper()
	x := hostFactoryNativeStorageRow{tag: tag, owner: f.owner, binding: f.binding, kind: "process", observation: uuid.NewString(), subject: uuid.NewString(), primitive: f.primitive, subjectPrimitive: strings.Repeat("c", 64), relations: []byte(`[{"storage_relation_only":true}]`), envelope: []byte(`{"storage_envelope_only":true}`)}
	if tx.QueryRow(`SELECT factory_realm_id::text FROM public.capacity_host_factory_roots WHERE scope_root_id=$1`, f.root).Scan(&x.nativeRoot) != nil {
		t.Fatal("storage native root missing")
	}
	if tag == "native-manifest" {
		x.observation = ""
		x.kind = "thread_children"
		x.subject = ""
		x.subjectPrimitive = ""
		x.collection = uuid.NewString()
		x.level = hostFactoryStoragePtr(0)
		x.first = hostFactoryStoragePtr(1)
		x.last = hostFactoryStoragePtr(16)
		x.count = hostFactoryStoragePtr(16)
		x.relations = nil
	}
	x.body, _ = json.Marshal(map[string]any{"storage_native_only": true, "observation": x.observation, "collection": x.collection})
	x.identity = capacity.HostFactoryRawSHA256(x.body)
	return x
}

func hostFactoryNativeStorageInsert(tx *sql.Tx, f hostFactoryStorageVector, x hostFactoryNativeStorageRow) error {
	nullable := func(v string) any {
		if v == "" {
			return nil
		}
		return v
	}
	_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,record_identity_sha256,native_factory_root_id,native_observation_id,native_observation_kind,native_subject_owner_id,native_observer_primitive_sha256,native_subject_primitive_sha256,native_collection_id,native_census_ordinal,native_manifest_level,native_first_ordinal,native_last_ordinal,native_observation_count,native_inventory_relations_wire,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire,original_handle_id,operation,first_ordinal,last_ordinal) VALUES($1,'original_host_factory_root_preparation_v4',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`, f.root, x.binding, x.owner, x.tag, x.identity, x.nativeRoot, nullable(x.observation), x.kind, nullable(x.subject), x.primitive, nullable(x.subjectPrimitive), nullable(x.collection), x.ordinal, x.level, x.first, x.last, x.count, x.relations, capacity.HostFactoryRawSHA256(x.body), x.body, capacity.HostFactoryRawSHA256(x.envelope), x.envelope, x.handle, x.operation, x.firstIO, x.lastIO)
	return err
}

func hostFactoryNativePhaseStorageInsert(tx *sql.Tx, f hostFactoryStorageVector, stage string, phase []byte) error {
	// These invalid Source bodies exercise only bytea/null/tag constraints.
	body := []byte(`{"storage_phase_only":true}`)
	envelope := []byte(`{"storage_phase_envelope_only":true}`)
	var privatePostStart []byte
	if stage == "poststart-empty-realm-read" {
		// Invalid Source storage fixture only: preserve original phase presence.
		privatePostStart = []byte(`{"storage_poststart_custody_only":true}`)
	}
	_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_stage_returns(root_id,subject_owner_id,stage,binding_schema,binding_sha256,signer_role,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire,native_phase_wire,original_poststart_ledger_wire) VALUES($1,$2,$3,'original_host_factory_root_preparation_v4',$4,'host_registrar',$5,$6,$7,$8,$9,$10)`, f.root, f.owner, stage, f.binding, capacity.HostFactoryRawSHA256(body), body, capacity.HostFactoryRawSHA256(envelope), envelope, phase, privatePostStart)
	return err
}

func TestHostOriginalFactoryPostgresNativeTenPhasePresence(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, stage := range []string{"original-start-return", "alive-native-read", "exterior-join", "terminal-read", "native-leaf-core-by-registrar", "native-leaf-registrar-by-core", "native-leaf-worker", "ordinary-native-leaf-worker", "initial-empty-realm-read", "poststart-empty-realm-read"} {
		for _, present := range []bool{false, true} {
			name := stage + "/missing"
			if present {
				name = stage + "/present_storage_only"
			}
			t.Run(name, func(t *testing.T) {
				tx, f := hostFactoryStorageTx(t)
				var raw []byte
				if present {
					raw = []byte(`{"storage_original_phase_only":true}`)
				}
				if err := hostFactoryNativePhaseStorageInsert(tx, f, stage, raw); (err == nil) != present {
					t.Fatal("aggregate exact phase NULL/BYTEA guard differs", err)
				}
			})
		}
	}
}

func TestHostOriginalFactoryPostgresNativePhaseCapAndImmutability(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, tc := range []struct {
		name, stage string
		raw         []byte
		accepted    bool
	}{
		{"nonaggregate_null", "root-preparation", nil, true},
		{"nonaggregate_phase_refused", "root-preparation", []byte(`{}`), false},
		{"aggregate_empty_not_null", "initial-empty-realm-read", make([]byte, 0), false},
		{"aggregate_array_refused", "initial-empty-realm-read", []byte(`[]`), false},
		{"aggregate_json_null_refused", "initial-empty-realm-read", []byte(`null`), false},
		{"aggregate_whole_overcap", "initial-empty-realm-read", []byte("{\"x\":\"" + strings.Repeat("x", 65537) + "\"}"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, f := hostFactoryStorageTx(t)
			if err := hostFactoryNativePhaseStorageInsert(tx, f, tc.stage, tc.raw); (err == nil) != tc.accepted {
				t.Fatal("phase cap/null storage guard differs", err)
			}
		})
	}
	t.Run("original_phase_cannot_be_replaced", func(t *testing.T) {
		tx, f := hostFactoryStorageTx(t)
		if err := hostFactoryNativePhaseStorageInsert(tx, f, "initial-empty-realm-read", []byte(`{"storage_original_phase_only":true}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(`UPDATE public.capacity_host_factory_stage_returns SET native_phase_wire=$2 WHERE root_id=$1 AND stage='initial-empty-realm-read'`, f.root, []byte(`{"replacement_epoch":true}`)); err == nil {
			t.Fatal("original phase BYTEA was mutable")
		}
	})
}

func TestHostOriginalFactoryPostgresNativePublicationTags(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, test := range []struct {
		name, tag string
		mutate    func(*hostFactoryNativeStorageRow)
		accepted  bool
	}{
		{"record_storage_shape_only", "native-record", nil, true},
		{"manifest_storage_shape_only", "native-manifest", nil, true},
		{"native_io_handle_alias", "native-record", func(x *hostFactoryNativeStorageRow) { x.handle = hostFactoryStoragePtr(uuid.NewString()) }, false},
		{"native_io_operation_alias", "native-record", func(x *hostFactoryNativeStorageRow) { x.operation = hostFactoryStoragePtr("stdout_read") }, false},
		{"record_unknown_relation", "native-record", func(x *hostFactoryNativeStorageRow) { x.relations = nil }, false},
		{"record_relation_object", "native-record", func(x *hostFactoryNativeStorageRow) { x.relations = []byte(`{}`) }, false},
		{"record_relation_empty", "native-record", func(x *hostFactoryNativeStorageRow) { x.relations = []byte(`[]`) }, false},
		{"record_relation_over20", "native-record", func(x *hostFactoryNativeStorageRow) { x.relations = []byte("[" + strings.Repeat("{},", 20) + "{}]") }, false},
		{"record_relation_over64k", "native-record", func(x *hostFactoryNativeStorageRow) {
			x.relations = append(x.relations, []byte(strings.Repeat(" ", 65537-len(x.relations)))...)
		}, false},
		{"manifest_relation_alias", "native-manifest", func(x *hostFactoryNativeStorageRow) { x.relations = []byte(`[{}]`) }, false},
		{"manifest_unknown_kind", "native-manifest", func(x *hostFactoryNativeStorageRow) { x.kind = "" }, false},
		{"manifest_missing_range", "native-manifest", func(x *hostFactoryNativeStorageRow) { x.first = nil }, false},
		{"manifest_count_mismatch", "native-manifest", func(x *hostFactoryNativeStorageRow) { x.count = hostFactoryStoragePtr(15) }, false},
		{"cross_root_native_uuid", "native-record", func(x *hostFactoryNativeStorageRow) { x.nativeRoot = uuid.NewString() }, false},
		{"whole_body_oversize", "native-record", func(x *hostFactoryNativeStorageRow) { x.body = []byte(strings.Repeat("x", 65537)) }, false},
		{"whole_envelope_oversize", "native-record", func(x *hostFactoryNativeStorageRow) { x.envelope = []byte(strings.Repeat("x", 65537)) }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, f := hostFactoryStorageTx(t)
			x := hostFactoryNativeStorage(t, tx, f, test.tag)
			if test.mutate != nil {
				test.mutate(&x)
			}
			err := hostFactoryNativeStorageInsert(tx, f, x)
			if (err == nil) != test.accepted {
				t.Fatal("native tag SQL shape only", err)
			}
		})
	}
}

func TestHostOriginalFactoryPostgresNativeOriginalIdentityAndRange(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, name := range []string{"same_observation_changed_body", "same_observation_changed_owner_binding", "same_collection_start_changed_range", "same_collection_level_overlapping_range", "same_collection_level_adjacent_range"} {
		t.Run(name, func(t *testing.T) {
			tx, f := hostFactoryStorageTx(t)
			tag := "native-record"
			if strings.HasPrefix(name, "same_collection") {
				tag = "native-manifest"
			}
			x := hostFactoryNativeStorage(t, tx, f, tag)
			if err := hostFactoryNativeStorageInsert(tx, f, x); err != nil {
				t.Fatal(err)
			}
			next := x
			next.identity = capacity.HostFactoryRawSHA256([]byte(name))
			next.body = []byte(`{"storage_changed_only":true}`)
			switch name {
			case "same_observation_changed_owner_binding":
				next.owner = uuid.NewString()
				next.binding = strings.Repeat("d", 64)
			case "same_collection_start_changed_range":
				next.last = hostFactoryStoragePtr(8)
				next.count = hostFactoryStoragePtr(8)
			case "same_collection_level_overlapping_range":
				next.first = hostFactoryStoragePtr(8)
				next.last = hostFactoryStoragePtr(24)
				next.count = hostFactoryStoragePtr(17)
			case "same_collection_level_adjacent_range":
				next.first = hostFactoryStoragePtr(17)
				next.last = hostFactoryStoragePtr(32)
			}
			err := hostFactoryNativeStorageInsert(tx, f, next)
			if (err == nil) != (name == "same_collection_level_adjacent_range") {
				t.Fatal("original publication identity/range", err)
			}
		})
	}
}

func TestHostOriginalFactoryPostgresNativeGetdentsExactNulls(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, test := range []struct {
		name, state, kind string
		scalar, count     *int64
		failed            *bool
		eof               *bool
		raw               []byte
		accepted          bool
	}{
		{"known_empty_return_storage_only", "returned", "unix_getdents64", hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(false), hostFactoryStoragePtr(false), make([]byte, 0), true},
		{"successful_return_unknown_null", "returned", "unix_getdents64", hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(false), hostFactoryStoragePtr(false), nil, false},
		{"positive_count_shape_only", "returned", "unix_getdents64", hostFactoryStoragePtr(int64(1)), hostFactoryStoragePtr(int64(1)), hostFactoryStoragePtr(false), hostFactoryStoragePtr(false), []byte{0}, true},
		{"count_mismatch", "returned", "unix_getdents64", hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(int64(1)), hostFactoryStoragePtr(false), hostFactoryStoragePtr(false), make([]byte, 0), false},
		{"scalar_missing", "returned", "unix_getdents64", nil, hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(false), hostFactoryStoragePtr(false), make([]byte, 0), false},
		{"eof_missing", "returned", "unix_getdents64", hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(false), nil, make([]byte, 0), false},
		{"kernel_zero_fake_eof", "returned", "unix_getdents64", hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(false), hostFactoryStoragePtr(true), make([]byte, 0), false},
		{"pending_unknown_null", "called_pending", "unix_getdents64", nil, nil, nil, nil, nil, true},
		{"pending_raw_alias", "called_pending", "unix_getdents64", nil, nil, nil, nil, make([]byte, 0), false},
		{"failed_unknown_null", "returned", "unix_getdents64", hostFactoryStoragePtr(int64(-1)), nil, hostFactoryStoragePtr(true), nil, nil, true},
		{"failed_empty_is_not_success", "returned", "unix_getdents64", hostFactoryStoragePtr(int64(-1)), nil, hostFactoryStoragePtr(true), nil, make([]byte, 0), false},
		{"other_syscall_alias", "returned", "unix_fstat", hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(false), hostFactoryStoragePtr(false), make([]byte, 0), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			tx, f := hostFactoryStorageTx(t)
			fact := map[string]any{"original_state": test.state, "original_count": test.count, "original_eof": test.eof, "original_native_return": map[string]any{"kind": test.kind, "original_scalar": test.scalar, "original_error_present": test.failed}}
			// Deliberately not a complete signed native chunk. This isolates the
			// BYTEA/returned-index SQL constraint, never a native proof supplier.
			body, _ := json.Marshal(map[string]any{"storage_only": true, "original_calls": []any{fact}})
			sha := capacity.HostFactoryRawSHA256(body)
			if _, err := tx.Exec(`INSERT INTO public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,record_identity_sha256,original_handle_id,operation,first_ordinal,last_ordinal,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire) VALUES($1,'original_host_factory_root_preparation_v4',$2,$3,'chunk',$4,$5,'task_inventory_read',1,1,$4,$6,$4,$6)`, f.root, f.binding, f.owner, sha, f.handle, body); err != nil {
				t.Fatal(err)
			}
			_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_call_snapshot_links(root_id,binding_schema,binding_sha256,original_owner_id,original_handle_id,original_call_id,version_kind,current_chunk_raw_body_sha256,current_fact_index,original_called_at,original_operation_deadline,original_getdents_wire) VALUES($1,'original_host_factory_root_preparation_v4',$2,$3,$4,$5,'first',$6,0,$7,$8,$9)`, f.root, f.binding, f.owner, f.handle, f.handle+":1", sha, f.start, f.start.Add(60*time.Second), test.raw)
			if (err == nil) != test.accepted {
				t.Fatal("SQL exact known/NULL custody", err)
			}
			if err == nil {
				var unknown bool
				var count *int64
				if tx.QueryRow(`SELECT original_getdents_wire IS NULL,octet_length(original_getdents_wire) FROM public.capacity_host_factory_call_snapshot_links WHERE root_id=$1`, f.root).Scan(&unknown, &count) != nil || unknown != (test.raw == nil) || (!unknown && (count == nil || *count != int64(len(test.raw)))) {
					t.Fatal("BYTEA NULL/known empty lost")
				}
			}
		})
	}
}

func TestHostOriginalFactoryPostgresGetdentsSourceAuditBytea(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, name := range []string{"known_empty_storage_only", "pending_NULL_diagnostic", "custody_without_kernel_raw", "custody_empty", "custody_overcap", "pending_custody_alias", "nongetdents_custody_alias", "immutable_custody"} {
		t.Run(name, func(t *testing.T) {
			tx, f := hostFactoryStorageTx(t)
			state, kind, raw, custody := "returned", "unix_getdents64", make([]byte, 0), []byte(`{"storage_audit_only":true}`)
			var count, scalar *int64 = hostFactoryStoragePtr(int64(0)), hostFactoryStoragePtr(int64(0))
			var eof, failed *bool = hostFactoryStoragePtr(false), hostFactoryStoragePtr(false)
			want := name == "known_empty_storage_only" || name == "pending_NULL_diagnostic" || name == "immutable_custody"
			switch name {
			case "pending_NULL_diagnostic":
				state, raw, custody, count, scalar, eof, failed = "called_pending", nil, nil, nil, nil, nil, nil
			case "custody_without_kernel_raw":
				raw = nil
			case "custody_empty":
				custody = make([]byte, 0)
			case "custody_overcap":
				custody = []byte(strings.Repeat("x", 65537))
			case "pending_custody_alias":
				state, raw, count, scalar, eof, failed = "called_pending", nil, nil, nil, nil, nil
			case "nongetdents_custody_alias":
				kind = "unix_fstat"
			}
			fact := map[string]any{"original_state": state, "original_count": count, "original_eof": eof, "original_native_return": map[string]any{"kind": kind, "original_scalar": scalar, "original_error_present": failed}}
			body, _ := json.Marshal(map[string]any{"storage_only": true, "original_calls": []any{fact}})
			sha := capacity.HostFactoryRawSHA256(body)
			if _, err := tx.Exec(`INSERT INTO public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,record_identity_sha256,original_handle_id,operation,first_ordinal,last_ordinal,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire) VALUES($1,'original_host_factory_root_preparation_v4',$2,$3,'chunk',$4,$5,'task_inventory_read',1,1,$4,$6,$4,$6)`, f.root, f.binding, f.owner, sha, f.handle, body); err != nil {
				t.Fatal(err)
			}
			_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_call_snapshot_links(root_id,binding_schema,binding_sha256,original_owner_id,original_handle_id,original_call_id,version_kind,current_chunk_raw_body_sha256,current_fact_index,original_called_at,original_operation_deadline,original_getdents_wire,original_getdents_source_audit_wire) VALUES($1,'original_host_factory_root_preparation_v4',$2,$3,$4,$5,'first',$6,0,$7,$8,$9,$10)`, f.root, f.binding, f.owner, f.handle, f.handle+":1", sha, f.start, f.start.Add(time.Minute), raw, custody)
			if (err == nil) != want {
				t.Fatal("private custody BYTEA shape only", name, err)
			}
			if name == "immutable_custody" {
				if _, err = tx.Exec(`UPDATE public.capacity_host_factory_call_snapshot_links SET original_getdents_source_audit_wire=$2 WHERE root_id=$1`, f.root, []byte(`{"replacement_audit":true}`)); err == nil {
					t.Fatal("original private audit custody became mutable")
				}
			}
			// Invalid storage-only bodies/headers cannot be native suppliers.
			if name == "known_empty_storage_only" {
				if _, err = originalHostGetdentsSourceCustody(custody, hostOriginalGetdentsCustodyIdentity{}, raw); err == nil {
					t.Fatal("storage header alone installed custody/native permission")
				}
			}
		})
	}
}

func hostOriginalConstraintCodec() hostOriginalSourceCodec {
	return hostOriginalSourceCodec{profile: capacity.ProposedHostFactorySourceProfileV1()}
}

// Unexecuted Source-only explicit-profile transport discriminants.
func TestHostOriginalFactorySourceProfileTransportDiscriminants(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	codec := hostOriginalConstraintCodec()
	body := []byte(`{}`)
	bodySHA := capacity.HostFactoryRawSHA256(body)
	set := capacity.HostFactorySourcePurposeSet{
		Schema:               "source_host_factory_original_call_purposes_v1",
		OriginalBodySHA256:   bodySHA,
		OriginalCallPurposes: []capacity.HostFactorySourceCallPurpose{},
	}
	purposeRaw, err := codec.Canonical(set)
	if err != nil {
		t.Fatal(err)
	}
	envelope := capacity.HostFactorySourceSignedEnvelope{
		Schema:  "source_host_factory_signed_envelope_v1",
		Purpose: "original_host_factory_call_vector_chunk_v4",
		Role:    "host_exterior", KeyID: "123e4567-e89b-42d3-a456-426614174000",
		PreAuthorityScopeSHA256: strings.Repeat("a", 64), SourceProfileSHA256: hostOriginalSourceProfileSHA,
		OriginalPurposeBase64: base64.StdEncoding.EncodeToString(purposeRaw),
		BodyBase64:            base64.StdEncoding.EncodeToString(body),
		SignatureBase64:       base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}
	raw, err := codec.Canonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("explicit-source-transport-is-inert-exact-body", func(t *testing.T) {
		actual, role, schema, sha, e := codec.Envelope(raw)
		if e != nil || !bytes.Equal(actual, body) || role != envelope.Role || schema != "original_host_factory_pre_authority_scope_v4" || sha != envelope.PreAuthorityScopeSHA256 {
			t.Fatalf("transport mismatch: %v", e)
		}
		var target capacity.HostFactorySourceSignedEnvelope
		if capacity.DecodeHostFactory(raw, &target) == nil {
			t.Fatal("default decoder accepted new Source envelope")
		}
	})
	t.Run("nil-expected-profile-refused", func(t *testing.T) {
		if _, _, _, _, e := (hostOriginalSourceCodec{}).Envelope(raw); e == nil {
			t.Fatal("no expected Source profile accepted")
		}
	})
	t.Run("zero-profile-refused", func(t *testing.T) {
		zero := hostOriginalSourceCodec{profile: &capacity.HostFactorySourceProfile{}}
		if _, _, _, _, e := zero.Envelope(raw); e == nil {
			t.Fatal("zero profile accepted")
		}
	})
	t.Run("caller-profile-label-refused", func(t *testing.T) {
		bad := envelope
		bad.SourceProfileSHA256 = strings.Repeat("b", 64)
		wire, _ := json.Marshal(bad)
		if _, _, _, _, e := codec.Envelope(wire); e == nil {
			t.Fatal("caller profile SHA selected grammar")
		}
	})
	t.Run("prior-41-profile-identity-refused", func(t *testing.T) {
		bad := envelope
		bad.SourceProfileSHA256 = "107d1a2cf25fee4d966fa1886dbf5f94c19c866c2eb4cda28405d27c70923ebd"
		wire, _ := json.Marshal(bad)
		if _, _, _, _, e := codec.Envelope(wire); e == nil {
			t.Fatal("prior profile identity relabeled into current Source expectation")
		}
	})
	for _, prior := range []struct{ name, identity string }{
		{"prior-44-profile-identity-refused", "b9d558f44df5b7a9a2555b7b0434e9ddcaf727adbfb6d309d63b02e89672b0c8"},
		{"prior-50-profile-identity-refused", "da18f6b330b6fd0a11e52689350871f98124fd614bc8da7917c01a5ddf84e5de"},
	} {
		t.Run(prior.name, func(t *testing.T) {
			bad := envelope
			bad.SourceProfileSHA256 = prior.identity
			wire, _ := json.Marshal(bad)
			if _, _, _, _, e := codec.Envelope(wire); e == nil {
				t.Fatal("prior profile relabeled into Source51 expectation")
			}
		})
	}
	t.Run("legacy-scope-no-fallback", func(t *testing.T) {
		old := model.HostFactorySignedEnvelope{Schema: "original_host_factory_signed_envelope_v4", Purpose: envelope.Purpose, Role: envelope.Role, KeyID: envelope.KeyID, PreAuthorityScopeSHA256: envelope.PreAuthorityScopeSHA256, BodyBase64: envelope.BodyBase64, SignatureBase64: envelope.SignatureBase64}
		wire, _ := json.Marshal(old)
		if _, _, _, _, e := codec.Envelope(wire); e == nil {
			t.Fatal("legacy Scope transport admitted through new profile")
		}
	})
	t.Run("purpose-body-hash-mismatch", func(t *testing.T) {
		bad := set
		bad.OriginalBodySHA256 = strings.Repeat("b", 64)
		wire, _ := codec.Canonical(bad)
		changed := envelope
		changed.OriginalPurposeBase64 = base64.StdEncoding.EncodeToString(wire)
		outer, _ := json.Marshal(changed)
		if _, _, _, _, e := codec.Envelope(outer); e == nil {
			t.Fatal("purpose detached from actual BODY")
		}
	})
	t.Run("null-purpose-list-refused", func(t *testing.T) {
		bad := set
		bad.OriginalCallPurposes = nil
		wire, _ := json.Marshal(bad)
		changed := envelope
		changed.OriginalPurposeBase64 = base64.StdEncoding.EncodeToString(wire)
		outer, _ := json.Marshal(changed)
		if _, _, _, _, e := codec.Envelope(outer); e == nil {
			t.Fatal("unknown NULL purpose list accepted")
		}
	})
	t.Run("noncanonical-purpose-byte-string", func(t *testing.T) {
		changed := envelope
		changed.OriginalPurposeBase64 = changed.OriginalPurposeBase64[:4] + "\n" + changed.OriginalPurposeBase64[4:]
		outer, _ := json.Marshal(changed)
		if _, _, _, _, e := codec.Envelope(outer); e == nil {
			t.Fatal("base64 newline alias accepted")
		}
	})
	t.Run("oversized-enclosing-envelope", func(t *testing.T) {
		if _, _, _, _, e := codec.Envelope(bytes.Repeat([]byte(" "), 65537)); e == nil {
			t.Fatal("envelope cap raised")
		}
	})
	t.Run("unknown-envelope-schema", func(t *testing.T) {
		changed := envelope
		changed.Schema = "caller_selected_profile_v1"
		outer, _ := json.Marshal(changed)
		if _, _, _, _, e := codec.Envelope(outer); e == nil {
			t.Fatal("unknown transport repaired")
		}
	})
	t.Run("Root-ancestor-wire-preserved", func(t *testing.T) {
		root := model.HostFactoryRootSignedEnvelope{Schema: "original_host_factory_root_signed_envelope_v4", Purpose: envelope.Purpose, Role: "host_exterior", KeyID: envelope.KeyID, BindingSchema: "original_host_factory_root_preparation_v4", BindingSHA256: envelope.PreAuthorityScopeSHA256, BodyBase64: envelope.BodyBase64, SignatureBase64: envelope.SignatureBase64}
		wire, e := capacity.CanonicalHostFactory(root)
		if e != nil {
			t.Fatal(e)
		}
		actual, _, schema, _, e := codec.Envelope(wire)
		if e != nil || !bytes.Equal(actual, body) || schema != root.BindingSchema {
			t.Fatalf("legacy Root mutation/refusal: %v", e)
		}
		again, e := codec.Canonical(root)
		if e != nil || !bytes.Equal(wire, again) {
			t.Fatal("original Root bytes changed")
		}
	})
	t.Run("ordinary-ancestor-wire-preserved", func(t *testing.T) {
		ordinary := model.HostFactoryRootSignedEnvelope{Schema: "original_host_factory_root_signed_envelope_v4", Purpose: envelope.Purpose, Role: "factory_ordinary_worker", KeyID: envelope.KeyID, BindingSchema: "factory_ordinary_source_binding_v4", BindingSHA256: envelope.PreAuthorityScopeSHA256, BodyBase64: envelope.BodyBase64, SignatureBase64: envelope.SignatureBase64}
		wire, e := capacity.CanonicalHostFactory(ordinary)
		if e != nil {
			t.Fatal(e)
		}
		actual, _, schema, _, e := codec.Envelope(wire)
		if e != nil || !bytes.Equal(actual, body) || schema != ordinary.BindingSchema {
			t.Fatalf("ordinary original transport refused: %v", e)
		}
		again, e := codec.Canonical(ordinary)
		if e != nil || !bytes.Equal(wire, again) {
			t.Fatal("ordinary original bytes changed")
		}
	})
}

func TestHostOriginalFactorySourceProfileSQLFirstUnavailableDiscriminants(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	codec := originalHostSourceCodecTx(context.Background(), nil, "123e4567-e89b-42d3-a456-426614174000")
	if codec.err == nil || codec.profile != nil {
		t.Fatal("missing SQL owner became profile/FIRST")
	}
	t.Run("public-label-cannot-install-live-owner", func(t *testing.T) {
		codec := originalHostSourceCodecRealm(context.Background(), nil)
		if codec.err == nil || codec.profile != nil {
			t.Fatal("missing actual Realm became Source owner")
		}
	})
	t.Run("Scope-pending-missing-owner-remains-HOLD", func(t *testing.T) {
		x := hostFactoryIOIdentity{bindingSchema: "original_host_factory_pre_authority_scope_v4", codec: hostOriginalConstraintCodec()}
		if originalHostSourcePendingTx(context.Background(), nil, x, model.HostFactoryCallVectorChunk{}, model.HostFactoryCallVectorChunk{}, nil) == nil {
			t.Fatal("absent SQL relation became FIRST")
		}
	})
}

func TestHostOriginalFactorySourceProfileMixedStageTransport(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// Fixed logical stage-family relationships only. None of these strings
	// authenticates an original envelope or installs Source/native authority.
	for _, tc := range []struct {
		name, stage, role, binding string
		accept                     bool
	}{
		{"scope-body-issued-by-original-root", "preauthority-scope", "host_core_issuer", "original_host_factory_root_preparation_v4", true},
		{"root-preparation-retains-original-domain", "root-preparation", "host_exterior", "original_host_factory_source_approval_v4", true},
		{"prepared-plan-uses-new-scoped-transport", "prepared-create-plan", "host_worker", "original_host_factory_pre_authority_scope_v4", true},
		{"Alive-registration-uses-scoped-issuer", "alive-registration", "host_core_issuer", "original_host_factory_pre_authority_scope_v4", true},
		{"scope-body-cannot-sign-itself-under-scope", "preauthority-scope", "host_core_issuer", "original_host_factory_pre_authority_scope_v4", false},
		{"prepared-plan-cannot-use-parent-root-domain", "prepared-create-plan", "host_worker", "original_host_factory_root_preparation_v4", false},
		{"caller-role-cannot-select-family", "preauthority-scope", "host_worker", "original_host_factory_root_preparation_v4", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if (originalHostSourceStageTransport(tc.stage, tc.role, tc.binding) == nil) != tc.accept {
				t.Fatal("fixed stage transport disposition")
			}
		})
	}
}

func TestHostOriginalFactorySourceProfilePostgresUnsignedScopeRefusals(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// The two owning SQL algorithms below may retain storage-only originals.
	// A Scope successor/inventory additionally requires authentic Source pairs.
	// No test token, dummy envelope or FIRST row installs that Source capability.
	t.Run("Scope-pending-successor-requires-original-purpose-pair", func(t *testing.T) {
		tx, fixture := hostFactoryStorageTx(t)
		pending := fixture.chunk(1, 1, true)
		pending.BindingSchema = "original_host_factory_pre_authority_scope_v4"
		hostFactoryStorageAppend(t, tx, fixture, pending)
		next := fixture.chunk(1, 1, false)
		next.BindingSchema = pending.BindingSchema
		raw, err := capacity.CanonicalHostFactory(next)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := originalHostIOIdentity(hostOriginalConstraintCodec(), fixture.root, &next, raw)
		if err != nil {
			t.Fatal(err)
		}
		if appendOriginalHostChunkTx(context.Background(), tx, identity, next, raw, []byte(`{"storage_envelope_only":true}`)) == nil {
			t.Fatal("unsigned Scope successor became authenticated original purpose custody")
		}
		var versions int
		if err = tx.QueryRow(`SELECT count(*) FROM public.capacity_host_factory_call_snapshot_links WHERE root_id=$1`, fixture.root).Scan(&versions); err != nil || versions != 1 {
			t.Fatal("refused Scope successor altered original FIRST rows", err)
		}
	})
	t.Run("Scope-inventory-requires-actual-Source-owner", func(t *testing.T) {
		tx, fixture := hostFactoryStorageTx(t)
		chunk := fixture.chunk(1, 1, false)
		chunk.BindingSchema = "original_host_factory_pre_authority_scope_v4"
		identity, _ := hostFactoryStorageAppend(t, tx, fixture, chunk)
		manifest := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: chunk.BindingSchema, BindingSHA256: fixture.binding, OwnerRole: chunk.OwnerRole, OriginalOwnerID: fixture.owner, OwnerPrimitiveRawSHA256: fixture.primitive, Operation: chunk.Operation, OriginalHandleID: fixture.handle, FirstOrdinal: 1, LastOrdinal: 1, OriginalCallCount: 1, ChildBodySHAs: []string{identity.bodySHA}, CollectionState: "complete_original_calls"}
		manifestRaw, err := capacity.CanonicalHostFactory(manifest)
		if err != nil {
			t.Fatal(err)
		}
		manifestIdentity, err := originalHostIOIdentity(hostOriginalConstraintCodec(), fixture.root, &manifest, manifestRaw)
		if err != nil {
			t.Fatal(err)
		}
		if err = appendOriginalHostIOBodyTx(context.Background(), tx, manifestIdentity, manifestRaw, []byte(`{"storage_envelope_only":true}`)); err != nil {
			t.Fatal(err)
		}
		inventory := model.HostFactoryHandleCallInventory{Schema: "original_host_factory_handle_call_inventory_v1", Purpose: "original_host_factory_handle_call_inventory_v1", BindingSchema: chunk.BindingSchema, BindingSHA256: fixture.binding, OwnerRole: chunk.OwnerRole, OriginalOwnerID: fixture.owner, OwnerPrimitiveRawSHA256: &fixture.primitive, OriginalHandleID: fixture.handle, OriginalAcquisitionState: "acquired_held", FirstOrdinal: 1, LastOrdinal: 1, OriginalCallCount: 1, OperationVectors: []model.HostFactoryCallVectorReference{{Operation: chunk.Operation, OriginalHandleID: fixture.handle, OriginalOwnerID: fixture.owner, OwnerPrimitiveRawSHA256: &fixture.primitive, SubjectOwnerID: fixture.owner, FirstOrdinal: 1, LastOrdinal: 1, OriginalCallCount: 1, ManifestRootSHA256: &manifestIdentity.bodySHA, CollectionState: "complete_original_calls"}}, CollectionState: "complete_original_calls", OriginalOperationDeadline: chunk.OriginalCalls[0].OriginalOperationDeadline, RecordedAt: chunk.RecordedAt}
		raw, err := capacity.CanonicalHostFactory(inventory)
		if err != nil {
			t.Fatal(err)
		}
		identity, err = originalHostIOIdentity(hostOriginalConstraintCodec(), fixture.root, &inventory, raw)
		if err != nil {
			t.Fatal(err)
		}
		if validateOriginalHostInventoryTx(context.Background(), tx, identity, inventory) == nil {
			t.Fatal("grammar token and FIRST row supplied an authentic Source owner")
		}
	})
}

// Bounded private custody R5 Source/PG cases, unexecuted.
func postStartSourceFixtureID(n int) string     { return fmt.Sprintf("10000000-0000-4000-8000-%012d", n) }
func postStartSourceFixturePtr[T any](v T) *T   { return &v }
func postStartSourceFixtureSHA(s string) string { return capacity.HostFactoryRawSHA256([]byte(s)) }
func postStartSourceFixtureTime(seconds float64) time.Time {
	return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC).Add(time.Duration(seconds * float64(time.Second)))
}
func postStartSourceFixtureReturn(op string, called, returned float64) hostOriginalPostStartSourceReturn {
	return hostOriginalPostStartSourceReturn{Operation: op, OriginalOwnerID: postStartSourceFixtureID(6), OriginalOwnerRole: "host_exterior", OriginalCalledAt: postStartSourceFixtureTime(called), OriginalReturnedAt: postStartSourceFixtureTime(returned), OriginalContextDeadline: postStartSourceFixtureTime(100), OriginalState: "returned"}
}
func postStartSourceFixtureStream(c hostOriginalPostStartLedgerCustody, id, owner int, role, state string, anchor *string, operations []string, called float64, contentBytes uint32) (hostOriginalPostStartSourceSelection, []hostOriginalSourceAuditProjection) {
	handle := postStartSourceFixtureID(id)
	selection := hostOriginalPostStartSourceSelection{OriginalSourceOwnerID: postStartSourceFixtureID(owner), OriginalSourceOwnerRole: role, OriginalSourceBindingSchema: c.BindingSchema, OriginalSourceBindingSHA256: c.ScopeBodySHA256, OriginalHandleID: handle, OriginalAnchorHandleID: anchor, OriginalCallReferences: []string{}, OriginalStreamState: state}
	if state == "closed_file" {
		selection.OriginalCloseCallID = postStartSourceFixturePtr(handle + ":" + fmt.Sprint(len(operations)))
	}
	rows := []hostOriginalSourceAuditProjection{}
	for n, op := range operations {
		call := handle + ":" + fmt.Sprint(n+1)
		at := postStartSourceFixtureTime(called + float64(n)/10)
		fact := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: c.FactoryRootID, OriginalAuditHandleID: handle, OriginalCallID: &call, Operation: op, OriginalState: "returned", OriginalCalledAt: &at, OriginalReturnedAt: postStartSourceFixturePtr(at.Add(time.Nanosecond)), OriginalOperationDeadline: postStartSourceFixtureTime(100), OriginalErrorPresent: postStartSourceFixturePtr(false), OriginalHashState: "not_byte_operation"}
		if op == "source_file_write" {
			fact.OriginalCount = postStartSourceFixturePtr(int64(contentBytes))
			fact.OriginalHashState = "private_withheld"
		}
		if op == "source_file_read" {
			terminal := n > 2
			fact.OriginalCount = postStartSourceFixturePtr(int64(contentBytes))
			fact.OriginalHashState = "private_withheld"
			fact.OriginalEOF = postStartSourceFixturePtr(terminal)
			fact.OriginalErrorPresent = postStartSourceFixturePtr(terminal)
			if terminal {
				fact.OriginalCount = postStartSourceFixturePtr(int64(0))
			}
		}
		rows = append(rows, hostOriginalSourceAuditProjection{Family: "source_audit", SubjectIdentity: hostOriginalSubjectIdentity{SubjectKind: "source_file"}, Fact: fact, OriginalCloseReference: selection.OriginalCloseCallID})
		selection.OriginalCallReferences = append(selection.OriginalCallReferences, call)
	}
	return selection, rows
}
func postStartSourceFixture(t *testing.T) hostOriginalPostStartLedgerCustody {
	t.Helper()
	scopeRaw := []byte(`{}`)
	envelope := []byte(`{}`)
	payload, err := json.Marshal(struct {
		Schema      string `json:"schema"`
		Selector    string `json:"selector"`
		EnvelopeRaw []byte `json:"envelope_raw"`
	}{"source_private_original_worker_signed_frame_v1", "prepared-create-plan", envelope})
	if err != nil {
		t.Fatal(err)
	}
	wire := make([]byte, 4, len(payload)+4)
	binary.BigEndian.PutUint32(wire, uint32(len(payload)))
	wire = append(wire, payload...)
	stdout := postStartSourceFixtureID(9)
	segments := []hostOriginalPostStartReadSegment{{stdout + ":8", postStartSourceFixtureSHA("read-prefix-body"), postStartSourceFixtureSHA("read-prefix-env"), 0, 0, 4}, {stdout + ":9", postStartSourceFixtureSHA("read-payload-body"), postStartSourceFixtureSHA("read-payload-env"), 0, 4, uint32(len(payload))}}
	start := hostOriginalPostStartNativeReference{postStartSourceFixtureID(10) + ":1", postStartSourceFixtureSHA("start-body"), postStartSourceFixtureSHA("start-env"), 0}
	c := hostOriginalPostStartLedgerCustody{Schema: "source_private_original_poststart_ledger_custody_v3", OriginalParentHeldRootAnchor: hostOriginalPostStartNativeAnchor{postStartSourceFixtureID(10), postStartSourceFixtureSHA("heldBODY"), postStartSourceFixtureSHA("heldENV"), postStartSourceFixtureID(10) + ":1", postStartSourceFixtureID(10) + ":2"}, LogicalScopeRootID: postStartSourceFixtureID(2), FactoryRootID: postStartSourceFixtureID(1), SourceApprovalBodySHA256: postStartSourceFixtureSHA("approval"), RootPreparationBodySHA256: postStartSourceFixtureSHA("root"), InitialEmptyBodySHA256: postStartSourceFixtureSHA("initial"), InitialControlLedgerSHA256: postStartSourceFixtureSHA("initial-control"), InitialProtectedAdmissionSHA256: postStartSourceFixtureSHA("initial-admission"), OriginalLeaseProvenanceBodySHA256: postStartSourceFixtureSHA("lease"), BindingSchema: "original_host_factory_pre_authority_scope_v4", ScopeBodySHA256: capacity.HostFactoryRawSHA256(scopeRaw), ScopeEnvelopeSHA256: postStartSourceFixtureSHA("scope-envelope"), ScopeWire: scopeRaw, RequestID: postStartSourceFixtureID(3), OriginalPhaseID: postStartSourceFixtureID(4), OriginalEffectivePhaseDeadline: postStartSourceFixtureTime(100), AggregateBodySHA256: postStartSourceFixtureSHA("post-body"), AggregateEnvelopeSHA256: postStartSourceFixtureSHA("post-env"), PreparedBodySHA256: postStartSourceFixtureSHA("prepared-body"), PreparedEnvelopeSHA256: capacity.HostFactoryRawSHA256(envelope), OriginalStartReference: start, OriginalPreparedFrame: hostOriginalPostStartPreparedFrame{FramingSchema: "source_private_original_worker_signed_frame_length_prefix_v1", OriginalStreamHandleID: stdout, OriginalReadWire: wire, OriginalFrameOffset: 4, OriginalFrameBytes: uint32(len(payload)), OriginalReadSegments: segments, OriginalReceiverReturn: postStartSourceFixtureReturn("read_original_parent_worker_frame", 5, 7), OriginalAuthenticationReturn: postStartSourceFixtureReturn("control_retain_original_factory_prepared", 8, 9)}, OriginalPublicationReturn: postStartSourceFixtureReturn("control_publish_original_current_ledgers", 10, 14), OriginalDirectoryCustody: []hostOriginalPostStartDirectoryCustody{}, OriginalSourceAuditProjections: []hostOriginalSourceAuditProjection{}}
	journal := hostOriginalCurrentFactoryOwnerJournal{Schema: "source_private_original_current_factory_owner_journal_v1", FactoryRootID: c.FactoryRootID, RootPreparationSHA256: c.RootPreparationBodySHA256, SourceApprovalSHA256: c.SourceApprovalBodySHA256, CoreBasalOwnerRawSHA256: postStartSourceFixtureSHA("core-basal"), FactoryRegistrySHA256: postStartSourceFixtureSHA("registry"), FactorySourceClosureSHA256: postStartSourceFixtureSHA("closure"), InitialControlLedgerSHA256: c.InitialControlLedgerSHA256, InitialProtectedAdmissionSHA256: c.InitialProtectedAdmissionSHA256, PreAuthorityScopeSHA256: c.ScopeBodySHA256, Phase: "worker", RequestID: c.RequestID, FactoryAttemptID: postStartSourceFixtureID(20), CreatorOwnerID: postStartSourceFixtureID(5), OriginalRootContextStartedAt: postStartSourceFixtureTime(0), OriginalRootContextDeadline: postStartSourceFixtureTime(600), OriginalEffectivePhaseDeadline: c.OriginalEffectivePhaseDeadline, OriginalPhaseCalledAt: postStartSourceFixtureTime(0.5), FactoryOwnerEvents: []hostOriginalCurrentFactoryOwnerEvent{}}
	for n, transition := range []string{"scope_associated", "worker_start", "worker_prepared_plan"} {
		e := hostOriginalCurrentFactoryOwnerEvent{Ordinal: uint32(n + 1), EventID: postStartSourceFixtureID(30 + n), Transition: transition, OriginalOwnerID: c.OriginalPublicationReturn.OriginalOwnerID, OriginalFrameCallIDs: []string{}, OriginalContextDeadline: c.OriginalEffectivePhaseDeadline, OriginalState: "returned", OriginalErrorPresent: postStartSourceFixturePtr(false)}
		switch n {
		case 0:
			e.SourceOwnerKind = "owning_source_go_return"
			e.OriginalBodySHA256 = &c.ScopeBodySHA256
			e.OriginalEnvelopeSHA256 = &c.ScopeEnvelopeSHA256
			e.OriginalCalledAt = postStartSourceFixtureTime(1)
			e.OriginalReturnedAt = postStartSourceFixturePtr(postStartSourceFixtureTime(2))
		case 1:
			e.SourceOwnerKind = "original_native_call"
			e.OriginalCallID = &start.OriginalCallID
			e.OriginalChunkBodySHA256 = &start.OriginalChunkBodySHA256
			e.OriginalChunkEnvelopeSHA256 = &start.OriginalChunkEnvelopeSHA256
			e.OriginalFactIndex = &start.OriginalFactIndex
			e.OriginalCalledAt = postStartSourceFixtureTime(3)
			e.OriginalReturnedAt = postStartSourceFixturePtr(postStartSourceFixtureTime(4))
		case 2:
			e.SourceOwnerKind = "original_worker_frame"
			e.OriginalBodySHA256 = &c.PreparedBodySHA256
			e.OriginalEnvelopeSHA256 = &c.PreparedEnvelopeSHA256
			e.OriginalFrameCallIDs = []string{segments[0].OriginalCallID, segments[1].OriginalCallID}
			e.OriginalCalledAt = c.OriginalPreparedFrame.OriginalAuthenticationReturn.OriginalCalledAt
			e.OriginalReturnedAt = &c.OriginalPreparedFrame.OriginalAuthenticationReturn.OriginalReturnedAt
		}
		journal.FactoryOwnerEvents = append(journal.FactoryOwnerEvents, e)
	}
	c.CurrentJournalWire, err = json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	c.CurrentJournalSHA256 = capacity.HostFactoryRawSHA256(c.CurrentJournalWire)
	nativeAnchor := postStartSourceFixtureID(8)
	directory := postStartSourceFixtureID(19)
	prefix, rows := postStartSourceFixtureStream(c, 19, 7, "host_registrar", "open_directory_prefix", nil, []string{"source_directory_open", "source_directory_fstat"}, 0.1, 0)
	prefix.OriginalSourceBindingSchema, prefix.OriginalSourceBindingSHA256 = "original_host_factory_source_approval_v4", c.SourceApprovalBodySHA256
	for n := range rows {
		rows[n].Fact.OriginalOperationDeadline = postStartSourceFixtureTime(600)
	}
	c.OriginalDirectoryCustody = append(c.OriginalDirectoryCustody, hostOriginalPostStartDirectoryCustody{directory, hostOriginalPostStartNativeAnchor{postStartSourceFixtureID(22), postStartSourceFixtureSHA("actor-native-inventory-body"), postStartSourceFixtureSHA("actor-native-inventory-env"), postStartSourceFixtureID(22) + ":1", postStartSourceFixtureID(22) + ":2"}, prefix})
	c.OriginalSourceAuditProjections = append(c.OriginalSourceAuditProjections, rows...)
	writerOps := []string{"source_file_open", "source_file_fstat", "source_file_write", "source_file_sync", "source_file_close"}
	readerOps := []string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_read", "source_file_fstat", "source_file_close"}
	methods := []string{"source_file_rename_noreplace", "source_directory_sync"}
	var writerRows, methodRows, expectedRows, finalRows [2][]hostOriginalSourceAuditProjection
	for n := 0; n < 2; n++ {
		raw, name, kind, sha := c.ScopeWire, "current-scope-ledger.json", "scope", c.ScopeBodySHA256
		if n == 1 {
			raw, name, kind, sha = c.CurrentJournalWire, "current-control-operation-ledger.json", "current_control_journal", c.CurrentJournalSHA256
		}
		file := hostOriginalPostStartFileCustody{Basename: name, ContentKind: kind, OriginalBytes: uint32(len(raw)), OriginalWholeSHA256: sha, OriginalNativeRootAnchorHandleID: nativeAnchor}
		file.OriginalWriter, writerRows[n] = postStartSourceFixtureStream(c, 11+n*4, 6, "host_exterior", "closed_file", &nativeAnchor, writerOps, 10+float64(n)*2, file.OriginalBytes)
		file.OriginalPublicationMethod, methodRows[n] = postStartSourceFixtureStream(c, 12+n*4, 6, "host_exterior", "closed_publication_method", nil, methods, 11+float64(n)*2, 0)
		file.OriginalExpectedReader, expectedRows[n] = postStartSourceFixtureStream(c, 13+n*4, 7, "host_registrar", "closed_file", &directory, readerOps, 20+float64(n), file.OriginalBytes)
		file.OriginalFinalReader, finalRows[n] = postStartSourceFixtureStream(c, 14+n*4, 7, "host_registrar", "closed_file", &directory, readerOps, 30+float64(n), file.OriginalBytes)
		c.OriginalFileCustody[n] = file
	}
	for n := 0; n < 2; n++ {
		c.OriginalSourceAuditProjections = append(c.OriginalSourceAuditProjections, writerRows[n]...)
		c.OriginalSourceAuditProjections = append(c.OriginalSourceAuditProjections, methodRows[n]...)
	}
	for n := 0; n < 2; n++ {
		c.OriginalSourceAuditProjections = append(c.OriginalSourceAuditProjections, expectedRows[n]...)
	}
	for n := 0; n < 2; n++ {
		c.OriginalSourceAuditProjections = append(c.OriginalSourceAuditProjections, finalRows[n]...)
	}
	return c
}
func postStartSourceFixtureWire(t *testing.T, c hostOriginalPostStartLedgerCustody) []byte {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func postStartSourceFixtureJournal(t *testing.T, c *hostOriginalPostStartLedgerCustody, change func(*hostOriginalCurrentFactoryOwnerJournal)) {
	t.Helper()
	var j hostOriginalCurrentFactoryOwnerJournal
	if json.Unmarshal(c.CurrentJournalWire, &j) != nil {
		t.Fatal("fixture journal")
	}
	change(&j)
	raw, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	c.CurrentJournalWire, c.CurrentJournalSHA256 = raw, capacity.HostFactoryRawSHA256(raw)
	f := &c.OriginalFileCustody[1]
	f.OriginalBytes, f.OriginalWholeSHA256 = uint32(len(raw)), c.CurrentJournalSHA256
	for n := range c.OriginalSourceAuditProjections {
		row := &c.OriginalSourceAuditProjections[n]
		for _, selected := range []hostOriginalPostStartSourceSelection{f.OriginalWriter, f.OriginalExpectedReader, f.OriginalFinalReader} {
			if row.Fact.OriginalAuditHandleID == selected.OriginalHandleID && row.Fact.OriginalCount != nil && *row.Fact.OriginalCount > 0 {
				row.Fact.OriginalCount = postStartSourceFixturePtr(int64(len(raw)))
			}
		}
	}
}
func postStartSourceFixtureFinal(t *testing.T, c hostOriginalPostStartLedgerCustody) map[string]hostOriginalSourceAuditProjection {
	t.Helper()
	m := map[string]hostOriginalSourceAuditProjection{}
	for _, row := range c.OriginalSourceAuditProjections {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		var clone hostOriginalSourceAuditProjection
		if json.Unmarshal(raw, &clone) != nil {
			t.Fatal("fixture clone")
		}
		m[*clone.Fact.OriginalCallID] = clone
	}
	handle := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID
	closeID := handle + ":3"
	for n := 1; n <= 2; n++ {
		id := handle + ":" + fmt.Sprint(n)
		row := m[id]
		row.OriginalCloseReference = &closeID
		m[id] = row
	}
	row := m[handle+":1"]
	row.Fact.Operation = "source_directory_close"
	row.Fact.OriginalCallID = &closeID
	row.Fact.OriginalCalledAt = postStartSourceFixturePtr(postStartSourceFixtureTime(50))
	row.Fact.OriginalReturnedAt = postStartSourceFixturePtr(postStartSourceFixtureTime(50).Add(time.Nanosecond))
	m[closeID] = row
	return m
}

func TestHostFactoryPostStartCustodyStructuralRefusals(t *testing.T) {
	t.Run("bounded_structural_fixture_only", func(t *testing.T) {
		c := postStartSourceFixture(t)
		raw := postStartSourceFixtureWire(t, c)
		if len(raw) > 65536 {
			t.Fatalf("structural fixture exceeds immutable cap: %d", len(raw))
		}
		if _, err := decodeOriginalHostPostStartLedgerCustody(raw); err != nil {
			t.Fatal(err)
		}
	})
	cases := []struct {
		name   string
		mutate func(*hostOriginalPostStartLedgerCustody)
	}{
		{"logical_native_root_collision", func(c *hostOriginalPostStartLedgerCustody) { c.LogicalScopeRootID = c.FactoryRootID }},
		{"noncanonical_uuid", func(c *hostOriginalPostStartLedgerCustody) { c.RequestID = strings.ToUpper(c.RequestID) + "x" }},
		{"scope_wire_null", func(c *hostOriginalPostStartLedgerCustody) { c.ScopeWire = nil }},
		{"current_journal_null", func(c *hostOriginalPostStartLedgerCustody) { c.CurrentJournalWire = nil }},
		{"foreign_scope_raw", func(c *hostOriginalPostStartLedgerCustody) { c.ScopeWire = []byte(`{"foreign":true}`) }},
		{"old_initial_digest_as_current", func(c *hostOriginalPostStartLedgerCustody) { c.CurrentJournalSHA256 = c.InitialControlLedgerSHA256 }},
		{"directory_unknown_null", func(c *hostOriginalPostStartLedgerCustody) { c.OriginalDirectoryCustody = nil }},
		{"directory_missing_empty", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalDirectoryCustody = []hostOriginalPostStartDirectoryCustody{}
		}},
		{"directory_extra_acquisition", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalDirectoryCustody = append(c.OriginalDirectoryCustody, c.OriginalDirectoryCustody[0])
		}},
		{"source_audits_unknown", func(c *hostOriginalPostStartLedgerCustody) { c.OriginalSourceAuditProjections = nil }},
		{"source_audits_orphan", func(c *hostOriginalPostStartLedgerCustody) {
			row := c.OriginalSourceAuditProjections[0]
			row.Fact.OriginalAuditHandleID = postStartSourceFixtureID(90)
			row.Fact.OriginalCallID = postStartSourceFixturePtr(postStartSourceFixtureID(90) + ":1")
			c.OriginalSourceAuditProjections = append(c.OriginalSourceAuditProjections, row)
		}},
		{"source_acquisition_reordered", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalSourceAuditProjections[0], c.OriginalSourceAuditProjections[2] = c.OriginalSourceAuditProjections[2], c.OriginalSourceAuditProjections[0]
		}},
		{"source_counter_gap", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalSourceAuditProjections[1].Fact.OriginalCallID = postStartSourceFixturePtr(c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":3")
		}},
		{"source_stream_deadline_rebound", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalSourceAuditProjections[1].Fact.OriginalOperationDeadline = postStartSourceFixtureTime(101)
		}},
		{"source_private_hash_leak", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalSourceAuditProjections[4].Fact.OriginalSHA256 = postStartSourceFixturePtr(postStartSourceFixtureSHA("secret"))
		}},
		{"source_return_at_bound", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalSourceAuditProjections[1].Fact.OriginalReturnedAt = postStartSourceFixturePtr(c.OriginalEffectivePhaseDeadline)
		}},
		{"directory_future_close_in_prefix", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalDirectoryCustody[0].OriginalPrefix.OriginalCloseCallID = postStartSourceFixturePtr(c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":3")
		}},
		{"directory_prefix_future_close_ref", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalSourceAuditProjections[0].OriginalCloseReference = postStartSourceFixturePtr(c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":3")
		}},
		{"directory_native_anchor_alias", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalDirectoryCustody[0].OriginalNativeRootAnchor.OriginalHandleID = c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID
		}},

		{"actor_native_anchor_parent_id_alias", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalDirectoryCustody[0].OriginalNativeRootAnchor.OriginalHandleID = c.OriginalFileCustody[0].OriginalNativeRootAnchorHandleID
		}},
		{"actor_native_anchor_inventory_body_missing", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalDirectoryCustody[0].OriginalNativeRootAnchor.OriginalInventoryBodySHA256 = ""
		}},
		{"actor_native_anchor_inventory_envelope_missing", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalDirectoryCustody[0].OriginalNativeRootAnchor.OriginalInventoryEnvelopeSHA256 = ""
		}},
		{"actor_native_anchor_foreign_acquisition", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalDirectoryCustody[0].OriginalNativeRootAnchor.OriginalAcquisitionCallID = postStartSourceFixtureID(88) + ":1"
		}},
		{"actor_native_anchor_fstat_future_snapshot", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalDirectoryCustody[0].OriginalNativeRootAnchor.OriginalFstatCallID = c.OriginalDirectoryCustody[0].OriginalNativeRootAnchor.OriginalHandleID + ":3"
		}},
		{"r4_private_schema_no_positive_fallback", func(c *hostOriginalPostStartLedgerCustody) {
			c.Schema = "source_private_original_poststart_ledger_custody_v1"
		}},
		{"reader_alias_writer", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalFileCustody[0].OriginalExpectedReader = c.OriginalFileCustody[0].OriginalWriter
		}},
		{"final_reader_alias_expected", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalFileCustody[0].OriginalFinalReader = c.OriginalFileCustody[0].OriginalExpectedReader
		}},
		{"reader_unknown_source_namespace", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalFileCustody[0].OriginalExpectedReader.OriginalSourceBindingSchema = "factory_ordinary_source_binding_v4"
		}},
		{"reader_foreign_binding", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalFileCustody[0].OriginalExpectedReader.OriginalSourceBindingSHA256 = postStartSourceFixtureSHA("foreign")
		}},
		{"writer_wrong_source_owner", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalFileCustody[0].OriginalWriter.OriginalSourceOwnerID = postStartSourceFixtureID(7)
		}},
		{"scope_control_order_swapped", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalFileCustody[0], c.OriginalFileCustody[1] = c.OriginalFileCustody[1], c.OriginalFileCustody[0]
		}},
		{"publication_owning_return_late", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPublicationReturn.OriginalReturnedAt = c.OriginalEffectivePhaseDeadline
		}},
		{"expected_read_before_publication_goreturn", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPublicationReturn.OriginalReturnedAt = postStartSourceFixtureTime(25)
		}},
		{"receiver_owning_return_late", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalReceiverReturn.OriginalReturnedAt = c.OriginalEffectivePhaseDeadline
		}},
		{"receiver_helper_error", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalReceiverReturn.OriginalErrorPresent = true
		}},
		{"receiver_pending_no_goreturn", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalReceiverReturn.OriginalState = "called_pending"
			c.OriginalPreparedFrame.OriginalReceiverReturn.OriginalReturnedAt = time.Time{}
		}},
		{"receiver_aliased_authentication", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalAuthenticationReturn = c.OriginalPreparedFrame.OriginalReceiverReturn
		}},
		{"receiver_before_actual_start_return", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalReceiverReturn.OriginalCalledAt = postStartSourceFixtureTime(3)
		}},
		{"lf_framing_refused", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.FramingSchema = "source_private_original_worker_signed_frame_lf_v1"
		}},
		{"frame_offset_not_four", func(c *hostOriginalPostStartLedgerCustody) { c.OriginalPreparedFrame.OriginalFrameOffset = 0 }},
		{"frame_length_prefix_disagreement", func(c *hostOriginalPostStartLedgerCustody) { c.OriginalPreparedFrame.OriginalReadWire[3]++ }},
		{"frame_adjacent_trailing_bytes", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalReadWire = append(c.OriginalPreparedFrame.OriginalReadWire, '\n')
		}},
		{"frame_missing_segments", func(c *hostOriginalPostStartLedgerCustody) { c.OriginalPreparedFrame.OriginalReadSegments = nil }},
		{"frame_segment_gap", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalReadSegments[1].OriginalRawOffset++
		}},
		{"frame_segment_straddles_prefix", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalReadSegments[0].OriginalRawBytes = 5
			c.OriginalPreparedFrame.OriginalReadSegments[1].OriginalRawOffset = 5
			c.OriginalPreparedFrame.OriginalReadSegments[1].OriginalRawBytes--
		}},
		{"frame_counter_gap", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalReadSegments[1].OriginalCallID = c.OriginalPreparedFrame.OriginalStreamHandleID + ":10"
		}},
		{"frame_foreign_handle", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalReadSegments[1].OriginalCallID = postStartSourceFixtureID(80) + ":9"
		}},
		{"frame_fact_index_exceeds_cap", func(c *hostOriginalPostStartLedgerCustody) {
			c.OriginalPreparedFrame.OriginalReadSegments[1].OriginalFactIndex = 4096
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := postStartSourceFixture(t)
			tc.mutate(&c)
			if _, err := decodeOriginalHostPostStartLedgerCustody(postStartSourceFixtureWire(t, c)); err == nil {
				t.Fatal("invalid structural custody admitted")
			}
		})
	}
	t.Run("literal_source_eof_error_preserved", func(t *testing.T) {
		c := postStartSourceFixture(t)
		id := c.OriginalFileCustody[0].OriginalExpectedReader.OriginalCallReferences[3]
		for n := range c.OriginalSourceAuditProjections {
			row := &c.OriginalSourceAuditProjections[n]
			if *row.Fact.OriginalCallID == id {
				row.Fact.OriginalErrorPresent = postStartSourceFixturePtr(false)
			}
		}
		if _, err := decodeOriginalHostPostStartLedgerCustody(postStartSourceFixtureWire(t, c)); err == nil {
			t.Fatal("actual EOF error normalized")
		}
	})
	t.Run("missing_selected_postfstat", func(t *testing.T) {
		c := postStartSourceFixture(t)
		id := c.OriginalFileCustody[0].OriginalExpectedReader.OriginalCallReferences[4]
		for n := range c.OriginalSourceAuditProjections {
			row := &c.OriginalSourceAuditProjections[n]
			if *row.Fact.OriginalCallID == id {
				row.Fact.Operation = "source_file_sync"
			}
		}
		if _, err := decodeOriginalHostPostStartLedgerCustody(postStartSourceFixtureWire(t, c)); err == nil {
			t.Fatal("single Fstat accepted for selected current file")
		}
	})
}

func TestHostFactoryPostStartCustodyCanonicalBytes(t *testing.T) {
	canonical := postStartSourceFixtureWire(t, postStartSourceFixture(t))
	cases := []struct {
		name string
		raw  []byte
	}{
		{"missing_required_key", bytes.Replace(canonical, []byte(`"schema":"source_private_original_poststart_ledger_custody_v2",`), nil, 1)},
		{"unknown_key", append(append([]byte(`{"unknown":null,`), canonical[1:]...), []byte{}...)},
		{"duplicate_key", append([]byte(`{"schema":"source_private_original_poststart_ledger_custody_v2",`), canonical[1:]...)},
		{"trailing_value", append(bytes.Clone(canonical), []byte(`{}`)...)},
		{"whitespace_alias", append([]byte(" "), canonical...)},
		{"scope_byte_array_alias", bytes.Replace(canonical, []byte(`"scope_wire":"e30="`), []byte(`"scope_wire":[123,125]`), 1)},
		{"scope_escaped_base64_alias", bytes.Replace(canonical, []byte(`"scope_wire":"e30="`), []byte(`"scope_wire":"\u006530="`), 1)},
		{"scope_base64_newline_alias", bytes.Replace(canonical, []byte(`"scope_wire":"e30="`), []byte(`"scope_wire":"e30=\n"`), 1)},
		{"whole_limit_refuses_before_decode", bytes.Repeat([]byte(" "), 65537)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if bytes.Equal(tc.raw, canonical) {
				t.Fatal("fixture discriminant did not mutate original")
			}
			if _, err := decodeOriginalHostPostStartLedgerCustody(tc.raw); err == nil {
				t.Fatal("noncanonical private bytes admitted")
			}
		})
	}
}

func TestHostFactoryPostStartJournalOriginalChronology(t *testing.T) {
	cases := []struct {
		name   string
		change func(*hostOriginalCurrentFactoryOwnerJournal)
	}{
		{"foreign_original_request", func(j *hostOriginalCurrentFactoryOwnerJournal) { j.RequestID = postStartSourceFixtureID(77) }},
		{"future_rpc_event_forbidden", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			e := j.FactoryOwnerEvents[2]
			e.Ordinal = 4
			e.EventID = postStartSourceFixtureID(77)
			e.Transition = "worker_rpc_return"
			j.FactoryOwnerEvents = append(j.FactoryOwnerEvents, e)
		}},
		{"event_without_actual_goreturn", func(j *hostOriginalCurrentFactoryOwnerJournal) { j.FactoryOwnerEvents[0].OriginalReturnedAt = nil }},
		{"pending_start_not_positive", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[1].OriginalState = "called_pending"
			j.FactoryOwnerEvents[1].OriginalErrorPresent = nil
			j.FactoryOwnerEvents[1].OriginalReturnedAt = nil
		}},
		{"failed_start_retained_hold", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[1].OriginalErrorPresent = postStartSourceFixturePtr(true)
		}},
		{"start_before_scope_association_return", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[1].OriginalCalledAt = postStartSourceFixtureTime(1.5)
		}},
		{"auth_event_aliased_receiver_return", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[2].OriginalCalledAt = postStartSourceFixtureTime(5)
			j.FactoryOwnerEvents[2].OriginalReturnedAt = postStartSourceFixturePtr(postStartSourceFixtureTime(7))
		}},
		{"event_source_owner_replaced", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[1].OriginalOwnerID = postStartSourceFixtureID(77)
		}},
		{"duplicate_event_identity", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[1].EventID = j.FactoryOwnerEvents[0].EventID
		}},
		{"event_deadline_renewed_past_first_root", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[0].OriginalContextDeadline = postStartSourceFixtureTime(601)
		}},
		{"event_actual_return_at_effective_bound", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[2].OriginalReturnedAt = postStartSourceFixturePtr(j.OriginalEffectivePhaseDeadline)
		}},
		{"event_before_original_context_origin", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[0].OriginalCalledAt = postStartSourceFixtureTime(-1)
		}},
		{"original_start_envelope_changed", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[1].OriginalChunkEnvelopeSHA256 = postStartSourceFixturePtr(postStartSourceFixtureSHA("foreign"))
		}},
		{"frame_call_census_missing", func(j *hostOriginalCurrentFactoryOwnerJournal) {
			j.FactoryOwnerEvents[2].OriginalFrameCallIDs = j.FactoryOwnerEvents[2].OriginalFrameCallIDs[:1]
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := postStartSourceFixture(t)
			postStartSourceFixtureJournal(t, &c, tc.change)
			if _, err := decodeOriginalHostPostStartLedgerCustody(postStartSourceFixtureWire(t, c)); err == nil {
				t.Fatal("original journal chronology admitted false completion")
			}
		})
	}
}

func TestHostFactoryPostStartDirectoryReadonlyPrefix(t *testing.T) {
	t.Run("actual_later_close_extension_only", func(t *testing.T) {
		c := postStartSourceFixture(t)
		raw := postStartSourceFixtureWire(t, c)
		final := postStartSourceFixtureFinal(t, c)
		if compareOriginalHostPostStartDirectoryPrefix(c, final) != nil {
			t.Fatal("valid structural prefix relation refused")
		}
		if !bytes.Equal(raw, postStartSourceFixtureWire(t, c)) {
			t.Fatal("immutable prefix rewritten")
		}
		id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":1"
		if c.OriginalSourceAuditProjections[0].OriginalCloseReference != nil || final[id].OriginalCloseReference == nil {
			t.Fatal("fixture failed explicit NULL-to-actualclose relation")
		}
	})
	cases := []struct {
		name   string
		mutate func(hostOriginalPostStartLedgerCustody, map[string]hostOriginalSourceAuditProjection)
	}{
		{"missing_actual_close", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			delete(m, c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID+":3")
		}},
		{"close_before_reader_returns", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":3"
			r := m[id]
			r.Fact.OriginalCalledAt = postStartSourceFixturePtr(postStartSourceFixtureTime(21))
			r.Fact.OriginalReturnedAt = postStartSourceFixturePtr(postStartSourceFixtureTime(21).Add(time.Nanosecond))
			m[id] = r
		}},
		{"close_foreign_factory_root", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":3"
			r := m[id]
			r.Fact.FactoryRootID = postStartSourceFixtureID(77)
			m[id] = r
		}},
		{"close_family_alias", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":3"
			r := m[id]
			r.Family = "main_owner_return"
			m[id] = r
		}},
		{"close_subject_alias", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":3"
			r := m[id]
			r.SubjectIdentity.SubjectKind = "source_directory"
			m[id] = r
		}},
		{"close_bound_renewed", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":3"
			r := m[id]
			r.Fact.OriginalOperationDeadline = postStartSourceFixtureTime(101)
			m[id] = r
		}},
		{"close_at_original_deadline", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":3"
			r := m[id]
			r.Fact.OriginalReturnedAt = postStartSourceFixturePtr(r.Fact.OriginalOperationDeadline)
			m[id] = r
		}},
		{"close_error_not_success", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":3"
			r := m[id]
			r.Fact.OriginalErrorPresent = postStartSourceFixturePtr(true)
			m[id] = r
		}},
		{"prefix_original_fact_replaced", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":1"
			r := m[id]
			r.Fact.OriginalCalledAt = postStartSourceFixturePtr(postStartSourceFixtureTime(0.2))
			m[id] = r
		}},
		{"prefix_no_actual_close_ref", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":1"
			r := m[id]
			r.OriginalCloseReference = nil
			m[id] = r
		}},
		{"directory_counter_extension_four", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID + ":4"
			r := m[c.OriginalDirectoryCustody[0].OriginalSourceDirectoryHandleID+":3"]
			r.Fact.OriginalCallID = &id
			m[id] = r
		}},
		{"closed_writer_fact_replaced", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalFileCustody[0].OriginalWriter.OriginalCallReferences[0]
			r := m[id]
			r.Fact.OriginalOperationDeadline = postStartSourceFixtureTime(101)
			m[id] = r
		}},
		{"closed_writer_close_ref_replaced", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalFileCustody[0].OriginalWriter.OriginalCallReferences[0]
			r := m[id]
			r.OriginalCloseReference = nil
			m[id] = r
		}},
		{"closed_reader_new_extension", func(c hostOriginalPostStartLedgerCustody, m map[string]hostOriginalSourceAuditProjection) {
			id := c.OriginalFileCustody[0].OriginalFinalReader.OriginalHandleID + ":7"
			r := m[c.OriginalFileCustody[0].OriginalFinalReader.OriginalCallReferences[5]]
			r.Fact.OriginalCallID = &id
			m[id] = r
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := postStartSourceFixture(t)
			final := postStartSourceFixtureFinal(t, c)
			tc.mutate(c, final)
			if compareOriginalHostPostStartDirectoryPrefix(c, final) == nil {
				t.Fatal("invalid readonly directory/closed-stream relation admitted")
			}
		})
	}
}

// Owning remote PostgreSQL ONLY. Direct legacy RootPreparation insertion here
// exercises conditional storage, never Source Scope auth or native positivity.
func TestHostOriginalFactoryPostgresPostStartCustodyPresence(t *testing.T) {
	cases := []struct {
		name, stage    string
		phase, private []byte
		wantError      bool
	}{
		{"poststage_private_object_storage_only", "poststart-empty-realm-read", []byte(`{"storage_phase_only":true}`), []byte(`{"storage_custody_only":true}`), false},
		{"poststage_unknown_sql_null", "poststart-empty-realm-read", []byte(`{"storage_phase_only":true}`), nil, true},
		{"poststage_empty_bytea_not_unknown", "poststart-empty-realm-read", []byte(`{"storage_phase_only":true}`), []byte{}, true},
		{"poststage_json_null_not_object", "poststart-empty-realm-read", []byte(`{"storage_phase_only":true}`), []byte(`null`), true},
		{"poststage_json_array_not_object", "poststart-empty-realm-read", []byte(`{"storage_phase_only":true}`), []byte(`[]`), true},
		{"poststage_whole_over_cap", "poststart-empty-realm-read", []byte(`{"storage_phase_only":true}`), bytes.Repeat([]byte(" "), 65537), true},
		{"initial_unchanged_sql_null", "initial-empty-realm-read", []byte(`{"storage_phase_only":true}`), nil, false},
		{"initial_current_custody_alias_refused", "initial-empty-realm-read", []byte(`{"storage_phase_only":true}`), []byte(`{"storage_custody_only":true}`), true},
		{"nonaggregate_sql_null", "root-preparation", nil, nil, false},
		{"nonaggregate_private_custody_forbidden", "root-preparation", nil, []byte(`{"storage_custody_only":true}`), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tx, f := hostFactoryStorageTx(t)
			body := []byte(`{"storage_post_custody_test_only":true}`)
			env := []byte(`{"storage_post_custody_envelope_only":true}`)
			_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_stage_returns(root_id,subject_owner_id,stage,binding_schema,binding_sha256,signer_role,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire,native_phase_wire,original_poststart_ledger_wire) VALUES($1,$2,$3,'original_host_factory_root_preparation_v4',$4,'host_registrar',$5,$6,$7,$8,$9,$10)`, f.root, f.owner, tc.stage, f.binding, capacity.HostFactoryRawSHA256(body), body, capacity.HostFactoryRawSHA256(env), env, tc.phase, tc.private)
			if (err != nil) != tc.wantError {
				t.Fatalf("conditional private storage error=%v, wantError=%v", err, tc.wantError)
			}
		})
	}
	t.Run("private_original_bytea_no_timestamp_rewrite", func(t *testing.T) {
		tx, f := hostFactoryStorageTx(t)
		raw := []byte(`{"source_storage_only":true,"original_returned_at":"2026-10-13T00:00:00.123456789Z"}`)
		body := []byte(`{"storage_custody_roundtrip_only":true}`)
		env := []byte(`{"storage_custody_roundtrip_envelope_only":true}`)
		_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_stage_returns(root_id,subject_owner_id,stage,binding_schema,binding_sha256,signer_role,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire,native_phase_wire,original_poststart_ledger_wire) VALUES($1,$2,'poststart-empty-realm-read','original_host_factory_root_preparation_v4',$3,'host_registrar',$4,$5,$6,$7,$8,$9)`, f.root, f.owner, f.binding, capacity.HostFactoryRawSHA256(body), body, capacity.HostFactoryRawSHA256(env), env, []byte(`{"storage_phase_only":true}`), raw)
		if err != nil {
			t.Fatal(err)
		}
		var returned []byte
		if tx.QueryRow(`SELECT original_poststart_ledger_wire FROM public.capacity_host_factory_stage_returns WHERE root_id=$1 AND subject_owner_id=$2 AND stage='poststart-empty-realm-read'`, f.root, f.owner).Scan(&returned) != nil || !bytes.Equal(returned, raw) {
			t.Fatal("private original BYTEA changed")
		}
		// Storage roundtrip is expressly not exact28 decoding/authentication.
		if _, err := decodeOriginalHostPostStartLedgerCustody(returned); err == nil {
			t.Fatal("invalid storage-only body became admitted custody")
		}
	})
}

func TestHostFactoryPostStartNativeAnchorStructuralFacts(t *testing.T) {
	fixture := func(t *testing.T) (hostOriginalPostStartLedgerCustody, model.HostFactoryBootstrapDescriptorSource, []model.HostFactoryPrimitiveIOReturn) {
		c := postStartSourceFixture(t)
		ref := c.OriginalDirectoryCustody[0].OriginalNativeRootAnchor
		parent := model.HostFactoryBootstrapDescriptorSource{OriginalHandleID: c.OriginalFileCustody[0].OriginalNativeRootAnchorHandleID, Device: 9, Inode: 10, Mode: 0040700, LinkCount: 2, UID: 1000, GID: 1000}
		actual := model.HostFactoryNativeStatReturn{Device: parent.Device, Inode: parent.Inode, Mode: parent.Mode, LinkCount: parent.LinkCount, UID: parent.UID, GID: parent.GID}
		facts := []model.HostFactoryPrimitiveIOReturn{}
		for n, op := range []string{"native_reader_open", "native_reader_fstat"} {
			called := postStartSourceFixtureTime(0.3 + float64(n)*0.05)
			id := ref.OriginalAcquisitionCallID
			if n == 1 {
				id = ref.OriginalFstatCallID
			}
			native := &model.HostFactoryNativeCallReturn{Kind: "unix_open", OriginalScalar: postStartSourceFixturePtr(int64(8)), OriginalErrno: postStartSourceFixturePtr(uint32(0)), OriginalErrorPresent: postStartSourceFixturePtr(false), ReturnedDescriptors: []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: ref.OriginalHandleID, OriginalDescriptorNumber: 8}}}
			if n == 1 {
				native = &model.HostFactoryNativeCallReturn{Kind: "unix_fstat", InputDescriptorNumber: postStartSourceFixturePtr(8), OriginalStat: &actual, OriginalErrno: postStartSourceFixturePtr(uint32(0)), OriginalErrorPresent: postStartSourceFixturePtr(false)}
			}
			facts = append(facts, model.HostFactoryPrimitiveIOReturn{Operation: op, OriginalHandleID: ref.OriginalHandleID, SubjectOwnerID: c.OriginalPublicationReturn.OriginalOwnerID, OriginalCallID: &id, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: postStartSourceFixturePtr(called.Add(time.Nanosecond)), OriginalOperationDeadline: postStartSourceFixtureTime(600), OriginalReturnClass: "success", OriginalHashState: "not_byte_operation", OriginalNativeReturn: native})
		}
		return c, parent, facts
	}
	t.Run("two_original_different_handles_structural_only", func(t *testing.T) {
		c, parent, facts := fixture(t)
		if validateOriginalHostPostStartNativeAnchorFacts(c, parent, facts) != nil {
			t.Fatal("valid structural original descriptor/stat join refused")
		}
	})
	cases := []struct {
		name   string
		mutate func(*hostOriginalPostStartLedgerCustody, *model.HostFactoryBootstrapDescriptorSource, []model.HostFactoryPrimitiveIOReturn)
	}{
		{"source_audit_fstat_not_native", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[1].Operation = "source_directory_fstat"
		}},
		{"unknown_native_stat", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[1].OriginalNativeReturn.OriginalStat = nil
		}},
		{"native_root_inode_foreign", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[1].OriginalNativeReturn.OriginalStat.Inode++
		}},
		{"native_root_link_count_foreign", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[1].OriginalNativeReturn.OriginalStat.LinkCount++
		}},
		{"native_root_uid_foreign", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[1].OriginalNativeReturn.OriginalStat.UID++
		}},
		{"different_acquired_descriptor", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[1].OriginalNativeReturn.InputDescriptorNumber = postStartSourceFixturePtr(9)
		}},
		{"foreign_original_fstat_call", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[1].OriginalCallID = postStartSourceFixturePtr(c.OriginalDirectoryCustody[0].OriginalNativeRootAnchor.OriginalHandleID + ":3")
		}},
		{"native_pending_no_return", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[0].OriginalReturnedAt = nil
			f[0].OriginalState = "called_pending"
		}},
		{"actual_fstat_error", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[1].OriginalNativeReturn.OriginalErrorPresent = postStartSourceFixturePtr(true)
		}},
		{"native_fstat_before_acquisition_return", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[1].OriginalCalledAt = postStartSourceFixturePtr(postStartSourceFixtureTime(0.2))
		}},
		{"native_actual_return_at_effective_bound", func(c *hostOriginalPostStartLedgerCustody, p *model.HostFactoryBootstrapDescriptorSource, f []model.HostFactoryPrimitiveIOReturn) {
			f[1].OriginalReturnedAt = postStartSourceFixturePtr(c.OriginalEffectivePhaseDeadline)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, parent, facts := fixture(t)
			tc.mutate(&c, &parent, facts)
			if validateOriginalHostPostStartNativeAnchorFacts(c, parent, facts) == nil {
				t.Fatal("invalid structural native descriptor/stat relation admitted")
			}
		})
	}
}

// Private chronology vectors only, written for remote Source CI. No SQL
// query, native supplier, compiled approval, key or Source capability is faked.
func TestHostOriginalFactoryRegistrationExternalGoReturn(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	cases := []string{"internal_marker_is_not_external_return", "external_called_after_method_began", "external_return_before_internal_marker", "late_external_return", "foreign_context", "foreign_database", "foreign_executor", "unknown_commit", "panic_without_method_return", "duplicate_capture_is_not_replay", "helper_before_commit", "sealed_missing_original_getter", "sealed_getter_late", "sealed_commit_before_getter_return"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
			defer cancel()
			deadline, _ := ctx.Deadline()
			now := time.Now().UTC()
			realm := &capacityhostfactory.OriginalFactoryRealm{}
			h := &hostOriginalClaim{realm: realm, invocation: uuid.NewString()}
			r := &hostOriginalPreparationReturn{claim: h, realm: realm, db: &sql.DB{}, ctx: ctx, entry: "ordinary_original_create", handle: uuid.NewString(), bindingRaw: []byte(`{"private_boundary_vector_only":true}`), preparedRaw: []byte(`{}`), registrationRaw: []byte(`{}`), calledAt: now, commitCalledAt: now, commitReturnedAt: now, transactionReturnedAt: now, methodFinishedAt: now, deadline: deadline, committed: true}
			h.preparationReturn = r
			store := CapacityStore{DB: r.db, ExecutorID: h.invocation, hostOriginalClaim: h}
			if originalHostPreparationCompleted(h, realm, r.db, r.entry, r.bindingRaw, r.handle) {
				t.Fatal("internal marker substituted for actual external GoReturn")
			}
			if name == "internal_marker_is_not_external_return" {
				return
			}
			called, returned := now.Add(-time.Nanosecond), now
			captureCtx := ctx
			switch name {
			case "external_called_after_method_began":
				called = now.Add(time.Nanosecond)
			case "external_return_before_internal_marker":
				returned = now.Add(-time.Nanosecond)
			case "late_external_return":
				returned = deadline
			case "foreign_context":
				captureCtx = context.WithValue(ctx, struct{}{}, "foreign")
			case "foreign_database":
				store.DB = &sql.DB{}
			case "foreign_executor":
				store.ExecutorID = uuid.NewString()
			case "unknown_commit":
				r.committed = false
				r.originalErr = errors.New("original driver uncertainty")
			case "panic_without_method_return":
				r.methodFinishedAt = time.Time{}
				r.originalErr = ErrHostFactoryHold
			case "helper_before_commit":
				r.transactionReturnedAt = now.Add(-time.Nanosecond)
			case "sealed_missing_original_getter":
				r.entry = "sealed_a0"
			case "sealed_getter_late", "sealed_commit_before_getter_return":
				r.entry = "sealed_a0"
				r.postStart = &hostOriginalPostStartCaptureReturn{ctx: ctx, bodySHA: strings.Repeat("a", 64), envelopeSHA: strings.Repeat("b", 64), raw: []byte(`{"opaque_private_boundary_only":true}`), calledAt: now, returnedAt: now}
				if name == "sealed_getter_late" {
					r.postStart.returnedAt = deadline
				} else {
					r.commitCalledAt = now.Add(-time.Nanosecond)
				}
			}
			if name == "duplicate_capture_is_not_replay" {
				if err := store.CaptureOriginalHostPreparationReturn(ctx, called, returned, nil); err != nil || !originalHostPreparationCompleted(h, realm, r.db, r.entry, r.bindingRaw, r.handle) {
					t.Fatal("valid private boundary vector refused", err)
				}
				if err := store.CaptureOriginalHostPreparationReturn(ctx, called, returned, nil); !errors.Is(err, ErrHostFactoryHold) {
					t.Fatal("duplicate replaced original returned attempt", err)
				}
			} else {
				_ = store.CaptureOriginalHostPreparationReturn(captureCtx, called, returned, nil)
			}
			if originalHostPreparationCompleted(h, realm, r.db, r.entry, r.bindingRaw, r.handle) {
				t.Fatal("invalid/unknown registration permitted Issue or choice")
			}
			if r.returnedAt.IsZero() && name != "panic_without_method_return" {
				t.Fatal("actual failed callback return was discarded")
			}
		})
	}
}

func TestHostFactoryPostStartFinalDirectoryWaitRelation(t *testing.T) {
	// Wait may already be blocked when the actor closes its directory. Only
	// the actual Wait RETURN is an upper join; it is not an actor GoReturn.
	cases := []string{"wait_called_before_close_is_lawful", "wait_returns_during_realm_join_is_lawful", "wait_return_before_directory_close", "realm_join_before_wait_return", "foreign_registrar_subject", "missing_original_native_reference", "duplicate_wait_return", "native_wait_error", "missing_closed_writer_fact"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			c := postStartSourceFixture(t)
			audits := postStartSourceFixtureFinal(t, c)
			owner := c.OriginalDirectoryCustody[0].OriginalPrefix.OriginalSourceOwnerID
			waitCalled, waitReturned := postStartSourceFixtureTime(1), postStartSourceFixtureTime(90)
			falseError := false
			fact := &model.HostFactoryPrimitiveIOReturn{SubjectOwnerID: owner, Operation: "registrar_wait", OriginalState: "returned", OriginalReturnClass: "success", OriginalCalledAt: &waitCalled, OriginalReturnedAt: &waitReturned, OriginalNativeReturn: &model.HostFactoryNativeCallReturn{OriginalErrorPresent: &falseError}}
			returns := []hostOriginalRealmOwnerReturn{{Operation: "registrar_wait", SubjectOwnerID: owner, SubjectRole: "host_registrar", OwnerRole: "host_exterior", OriginalOwnerID: c.OriginalPublicationReturn.OriginalOwnerID, OriginalFact: fact, OriginalFactReference: &hostOriginalRealmFactReference{}}}
			joinCalled, joinReturned := postStartSourceFixtureTime(70), postStartSourceFixtureTime(92)
			join := hostOriginalMainReturn{Operation: "realm_close_join", OriginalOwnerID: c.OriginalPublicationReturn.OriginalOwnerID, OriginalCalledAt: &joinCalled, OriginalReturnedAt: &joinReturned}
			if err := validateOriginalHostPostStartFinalLifetime(c, audits, returns, join); err != nil {
				t.Fatal("blocked Wait structural relation refused", err)
			}
			if name == "wait_called_before_close_is_lawful" || name == "wait_returns_during_realm_join_is_lawful" {
				return
			}
			switch name {
			case "wait_return_before_directory_close":
				waitReturned = postStartSourceFixtureTime(2)
			case "realm_join_before_wait_return":
				joinReturned = postStartSourceFixtureTime(89)
			case "foreign_registrar_subject":
				returns[0].SubjectOwnerID = postStartSourceFixtureID(99)
			case "missing_original_native_reference":
				returns[0].OriginalFactReference = nil
			case "duplicate_wait_return":
				returns = append(returns, returns[0])
			case "native_wait_error":
				falseError = true
			case "missing_closed_writer_fact":
				delete(audits, c.OriginalFileCustody[0].OriginalWriter.OriginalCallReferences[0])
			}
			if validateOriginalHostPostStartFinalLifetime(c, audits, returns, join) == nil {
				t.Fatal("invalid final Source/native Wait relation admitted")
			}
		})
	}
}

func TestHostOriginalFactoryHelperReturnMutexContention(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	// Actual memory ownership/locking only; no SQL/native/Realm approval.
	h := &hostOriginalClaim{}
	r := &hostOriginalPreparationReturn{claim: h, db: &sql.DB{}}
	h.preparationReturn = r
	store := CapacityStore{DB: r.db, hostOriginalClaim: h}
	sampled := time.Now().UTC() // actual caller sample, before mutex contention
	errOriginal := errors.New("original helper cause retained")
	prepared, registration := []byte(`{"private_prepared_vector":true}`), []byte(`{"private_registration_vector":true}`)
	h.mu.Lock()
	started, done := make(chan struct{}), make(chan struct{})
	go func() {
		close(started)
		store.retainOriginalHostPreparationHelperReturn(r, sampled, errOriginal, "original-private-handle", prepared, registration)
		close(done)
	}()
	<-started
	// The retention cannot complete while another actual owner holds mu.
	select {
	case <-done:
		h.mu.Unlock()
		t.Fatal("retention bypassed actual owning mutex")
	default:
	}
	h.mu.Unlock()
	<-done
	if !r.transactionReturnedAt.Equal(sampled) || !errors.Is(r.originalErr, errOriginal) || r.handle != "original-private-handle" || !bytes.Equal(r.preparedRaw, prepared) || !bytes.Equal(r.registrationRaw, registration) {
		t.Fatal("mutex wait resampled/dropped original helper return or buffers")
	}
	prepared[0] = 'x'
	registration[0] = 'x'
	if r.preparedRaw[0] == 'x' || r.registrationRaw[0] == 'x' {
		t.Fatal("original returned buffer was adopted by pointer")
	}
	store.retainOriginalHostPreparationHelperReturn(r, sampled.Add(time.Second), nil, "replacement", nil, nil)
	if !r.transactionReturnedAt.Equal(sampled) || !errors.Is(r.originalErr, ErrHostFactoryHold) {
		t.Fatal("duplicate overwrote original contended return")
	}
}

// Isolated final Source audit consumer discriminants.
// Source structural/memory discriminants only. All constructed headers,
// signatures and native references below lack Source/native authority.
// Written for owning CI; NEVER executed on this machine.
func finalAuditSourceFixture(t *testing.T) hostOriginalFinalSourceAuditCustody {
	t.Helper()
	c := hostOriginalFinalSourceAuditCustody{Schema: "source_private_original_final_source_audit_custody_v2", FactoryRootID: postStartSourceFixtureID(501), LogicalScopeRootID: postStartSourceFixtureID(502), SourceApprovalBodySHA256: postStartSourceFixtureSHA("approval"), RootPreparationBodySHA256: postStartSourceFixtureSHA("prep"), OriginalParentHeldRootAnchor: hostOriginalPostStartNativeAnchor{postStartSourceFixtureID(601), postStartSourceFixtureSHA("heldBODY"), postStartSourceFixtureSHA("heldENV"), postStartSourceFixtureID(601) + ":1", postStartSourceFixtureID(601) + ":2"}, OriginalActors: []hostOriginalFinalSourceAuditActor{}, OriginalParentSourceStreams: []hostOriginalFinalSourceAuditStream{}}
	for n, role := range []string{"host_worker", "host_registrar"} {
		owner := postStartSourceFixtureID(510 + n)
		bindingSchema, bindingSHA := "original_host_factory_pre_authority_scope_v4", postStartSourceFixtureSHA("scope")
		if n == 1 {
			bindingSchema, bindingSHA = "original_host_factory_root_preparation_v4", c.RootPreparationBodySHA256
		}
		header := hostOriginalPostStartLedgerCustody{FactoryRootID: c.FactoryRootID, BindingSchema: bindingSchema, ScopeBodySHA256: bindingSHA}
		_, rows := postStartSourceFixtureStream(header, 520+n, 510+n, role, "closed_file", postStartSourceFixturePtr(postStartSourceFixtureID(599)), []string{"source_directory_open", "source_directory_fstat", "source_directory_close"}, 70, 0)
		stream := hostOriginalFinalSourceAuditStream{1, owner, role, bindingSchema, bindingSHA, postStartSourceFixtureID(520 + n), rows}
		helper := postStartSourceFixtureReturn([]string{"receive_original_sealed_worker", "serve_original_registrar"}[n], 1, 81)
		helper.OriginalOwnerID, helper.OriginalOwnerRole = owner, role
		carrier := hostOriginalFinalSourceAuditCarrier{Schema: "source_private_original_final_source_audit_carrier_v1", FactoryRootID: c.FactoryRootID, SourceApprovalSHA256: c.SourceApprovalBodySHA256, RootPreparationSHA256: c.RootPreparationBodySHA256, OriginalOwnerID: owner, OriginalOwnerRole: role, OriginalBasalSHA256: postStartSourceFixtureSHA(role), BindingSchema: bindingSchema, BindingSHA256: bindingSHA, SnapshotID: postStartSourceFixtureID(530 + n), OriginalStreamCount: 1, OriginalArtifactReferences: []hostOriginalFinalSourceAuditArtifactReference{}, OriginalRemainingStreams: []hostOriginalFinalSourceAuditStream{stream}, OriginalHelperReturn: helper}
		body, _ := json.Marshal(carrier)
		envelope := hostOriginalFinalSourceAuditEnvelope{"source_private_original_final_source_audit_envelope_v1", "SOURCE_FIXTURE_NOT_APPROVED", role, "source_private_original_final_source_audit_carrier_domain_v1", base64.StdEncoding.EncodeToString(body), base64.StdEncoding.EncodeToString(make([]byte, 64))}
		env, _ := json.Marshal(envelope)
		frame, _ := json.Marshal(struct {
			Schema      string `json:"schema"`
			Selector    string `json:"selector"`
			EnvelopeRaw []byte `json:"envelope_raw"`
		}{"source_private_original_final_source_audit_signed_frame_v1", []string{"final-source-audit-worker", "final-source-audit-registrar"}[n], env})
		wire := append([]byte{0, 0, 0, 0}, frame...)
		binary.BigEndian.PutUint32(wire, uint32(len(frame)))
		if n == 1 {
			wire = append(append([]byte{}, frame...), byte('\n'))
		}
		handle := postStartSourceFixtureID(540 + n)
		offset := uint32(4)
		if n == 1 {
			offset = 0
		}
		segment := hostOriginalPostStartReadSegment{handle + ":1", postStartSourceFixtureSHA("stdoutBODY" + role), postStartSourceFixtureSHA("stdoutENV" + role), 0, 0, uint32(len(wire))}
		transport := hostOriginalFinalSourceAuditTransport{"source_private_original_final_source_audit_transport_custody_v1", handle, wire, offset, uint32(len(frame)), []hostOriginalPostStartReadSegment{segment}, hostOriginalPostStartNativeReference{handle + ":2", postStartSourceFixtureSHA("eofBODY" + role), postStartSourceFixtureSHA("eofENV" + role), 0}, hostOriginalPostStartNativeReference{handle + ":3", postStartSourceFixtureSHA("closeBODY" + role), postStartSourceFixtureSHA("closeENV" + role), 0}}
		receiver := postStartSourceFixtureReturn([]string{"read_original_parent_worker_frame", "collect_original_parent_registrar_source_audit_frame"}[n], 85, 86)
		c.OriginalActors = append(c.OriginalActors, hostOriginalFinalSourceAuditActor{"source_private_original_final_source_audit_actor_custody_v1", role, owner, carrier.OriginalBasalSHA256, body, env, transport, receiver, []hostOriginalFinalSourceAuditArtifactRead{}})
	}
	c.OriginalAllSourceFacts = 6
	return c
}

func finalAuditSourceWire(t *testing.T, c hostOriginalFinalSourceAuditCustody) []byte {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func finalAuditSourceCarrier(t *testing.T, c *hostOriginalFinalSourceAuditCustody, n int, mutate func(*hostOriginalFinalSourceAuditCarrier)) {
	t.Helper()
	var carrier hostOriginalFinalSourceAuditCarrier
	if json.Unmarshal(c.OriginalActors[n].OriginalCarrierBodyWire, &carrier) != nil {
		t.Fatal("fixture carrier")
	}
	mutate(&carrier)
	body, _ := json.Marshal(carrier)
	var envelope hostOriginalFinalSourceAuditEnvelope
	if json.Unmarshal(c.OriginalActors[n].OriginalCarrierEnvelopeWire, &envelope) != nil {
		t.Fatal("fixture envelope")
	}
	envelope.BodyBase64 = base64.StdEncoding.EncodeToString(body)
	env, _ := json.Marshal(envelope)
	actor := &c.OriginalActors[n]
	actor.OriginalCarrierBodyWire, actor.OriginalCarrierEnvelopeWire = body, env
	frame, _ := json.Marshal(struct {
		Schema      string `json:"schema"`
		Selector    string `json:"selector"`
		EnvelopeRaw []byte `json:"envelope_raw"`
	}{"source_private_original_final_source_audit_signed_frame_v1", []string{"final-source-audit-worker", "final-source-audit-registrar"}[n], env})
	wire := make([]byte, 4)
	binary.BigEndian.PutUint32(wire, uint32(len(frame)))
	wire = append(wire, frame...)
	if n == 1 {
		wire = append(append([]byte{}, frame...), byte('\n'))
	}
	actor.OriginalTransport.OriginalStdoutWire = wire
	actor.OriginalTransport.OriginalFrameBytes = uint32(len(frame))
	actor.OriginalTransport.OriginalReadSegments[0].OriginalRawBytes = uint32(len(wire))
}

func TestHostOriginalFinalSourceAuditStructuralCustody(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	t.Run("complete_structural_only_no_approved_supplier", func(t *testing.T) {
		c := finalAuditSourceFixture(t)
		_, m, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, c))
		if err != nil || len(m) != 6 {
			t.Fatal("structural original census refused", err)
		}
		if _, err = capacity.ApprovedHostFactorySource(); err == nil {
			t.Fatal("fixture must not install approval")
		}
	})
	tests := []struct {
		name   string
		mutate func(*hostOriginalFinalSourceAuditCustody)
	}{
		{"unknown_parent_streams_null", func(c *hostOriginalFinalSourceAuditCustody) { c.OriginalParentSourceStreams = nil }},
		{"missing_registrar_actor", func(c *hostOriginalFinalSourceAuditCustody) { c.OriginalActors = c.OriginalActors[:1] }},
		{"ordinary_role_alias", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalOwnerRole = "factory_ordinary_worker"
		}},
		{"actor_order_swapped", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0], c.OriginalActors[1] = c.OriginalActors[1], c.OriginalActors[0]
		}},
		{"receiver_internal_marker_operation_alias", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalReceiverReturn.Operation = "kernel_defer"
		}},
		{"registrar_receiver_actor_alias", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[1].OriginalReceiverReturn.Operation = "serve_original_registrar"
		}},
		{"receiver_return_at_own_bound", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[1].OriginalReceiverReturn.OriginalReturnedAt = c.OriginalActors[1].OriginalReceiverReturn.OriginalContextDeadline
		}},
		{"whole_stdout_cap", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalTransport.OriginalStdoutWire = make([]byte, 65537)
		}},
		{"segment_missing_original_bytes", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalTransport.OriginalReadSegments[0].OriginalRawBytes--
		}},
		{"segment_positive_zero", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalTransport.OriginalReadSegments[0].OriginalRawBytes = 0
		}},
		{"segment_foreign_handle", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalTransport.OriginalReadSegments[0].OriginalCallID = postStartSourceFixtureID(999) + ":1"
		}},
		{"segment_offset_gap", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalTransport.OriginalReadSegments[0].OriginalRawOffset = 1
		}},
		{"segment_fact_index_over_cap", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalTransport.OriginalReadSegments[0].OriginalFactIndex = 16
		}},
		{"missing_eof_pair", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalTransport.OriginalEOFReference.OriginalChunkEnvelopeSHA256 = ""
		}},
		{"eof_is_read_alias", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalTransport.OriginalEOFReference.OriginalCallID = c.OriginalActors[0].OriginalTransport.OriginalReadSegments[0].OriginalCallID
		}},
		{"close_is_eof_alias", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalTransport.OriginalCloseReference = c.OriginalActors[0].OriginalTransport.OriginalEOFReference
		}},
		{"frame_offset_clipped", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[0].OriginalTransport.OriginalFrameOffset = 0
		}},
		{"frame_payload_extended_to_framing", func(c *hostOriginalFinalSourceAuditCustody) {
			c.OriginalActors[1].OriginalTransport.OriginalFrameBytes++
		}},
		{"wrong_source_census", func(c *hostOriginalFinalSourceAuditCustody) { c.OriginalAllSourceFacts++ }},
		{"source_census_over4096", func(c *hostOriginalFinalSourceAuditCustody) { c.OriginalAllSourceFacts = 4097 }},
		{"unknown_artifact_list", func(c *hostOriginalFinalSourceAuditCustody) { c.OriginalActors[0].OriginalArtifacts = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := finalAuditSourceFixture(t)
			test.mutate(&c)
			if _, _, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, c)); err == nil {
				t.Fatal("invalid original custody accepted")
			}
		})
	}
	carrierTests := []struct {
		name   string
		mutate func(*hostOriginalFinalSourceAuditCarrier)
	}{
		{"helper_snapshot_return_alias", func(c *hostOriginalFinalSourceAuditCarrier) {
			c.OriginalHelperReturn.Operation = "publish_original_final_source_audit_snapshot"
		}},
		{"helper_unknown_state", func(c *hostOriginalFinalSourceAuditCarrier) { c.OriginalHelperReturn.OriginalState = "called_pending" }},
		{"helper_return_at_bound", func(c *hostOriginalFinalSourceAuditCarrier) {
			c.OriginalHelperReturn.OriginalReturnedAt = c.OriginalHelperReturn.OriginalContextDeadline
		}},
		{"helper_before_actual_directory_close", func(c *hostOriginalFinalSourceAuditCarrier) {
			c.OriginalHelperReturn.OriginalReturnedAt = postStartSourceFixtureTime(70)
		}},
		{"acquisition_counter_gap", func(c *hostOriginalFinalSourceAuditCarrier) {
			c.OriginalRemainingStreams[0].OriginalAcquisitionOrdinal = 2
		}},
		{"source_handle_fact_extension_gap", func(c *hostOriginalFinalSourceAuditCarrier) {
			c.OriginalRemainingStreams[0].OriginalSourceAuditProjections[1].Fact.OriginalCallID = postStartSourceFixturePtr(c.OriginalRemainingStreams[0].OriginalHandleID + ":3")
		}},
		{"private_source_byte_hash_leak", func(c *hostOriginalFinalSourceAuditCarrier) {
			c.OriginalRemainingStreams[0].OriginalSourceAuditProjections[0].Fact.OriginalSHA256 = postStartSourceFixturePtr(postStartSourceFixtureSHA("PRIVATE"))
		}},
		{"future_directory_close_reference", func(c *hostOriginalFinalSourceAuditCarrier) {
			c.OriginalRemainingStreams[0].OriginalSourceAuditProjections[0].OriginalCloseReference = postStartSourceFixturePtr(c.OriginalRemainingStreams[0].OriginalHandleID + ":4")
		}},
	}
	for _, test := range carrierTests {
		t.Run(test.name, func(t *testing.T) {
			c := finalAuditSourceFixture(t)
			finalAuditSourceCarrier(t, &c, 0, test.mutate)
			if _, _, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, c)); err == nil {
				t.Fatal("invalid carrier original accepted")
			}
		})
	}
	t.Run("helper_real_error_is_source_diagnostic_only", func(t *testing.T) {
		c := finalAuditSourceFixture(t)
		finalAuditSourceCarrier(t, &c, 0, func(c *hostOriginalFinalSourceAuditCarrier) { c.OriginalHelperReturn.OriginalErrorPresent = true })
		if _, _, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, c)); err != nil {
			t.Fatal("complete structural Source diagnostic refused", err)
		}
		if validateOriginalHostFinalSourceActorLifetime(c, nil, nil, hostOriginalMainReturn{Operation: "realm_close_join", OriginalCalledAt: postStartSourceFixturePtr(postStartSourceFixtureTime(70)), OriginalReturnedAt: postStartSourceFixturePtr(postStartSourceFixtureTime(92))}) == nil {
			t.Fatal("error metadata became positive Main/native closure")
		}
	})
}

func TestHostOriginalFinalSourceAuditCanonicalPrivateBytes(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"omitted_field", func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"original_all_source_facts":6`), []byte(`"omitted":6`), 1)
		}},
		{"extra_key", func(raw []byte) []byte { return append([]byte(`{"extra":1,`), raw[1:]...) }},
		{"duplicate_key", func(raw []byte) []byte { return append([]byte(`{"schema":"duplicate",`), raw[1:]...) }},
		{"trailing_json", func(raw []byte) []byte { return append(raw, []byte(`{}`)...) }},
		{"whitespace_alias", func(raw []byte) []byte { return append([]byte(" "), raw...) }},
		{"numeric_byte_array_alias", func(raw []byte) []byte {
			key := []byte(`"original_stdout_wire":"`)
			start := bytes.Index(raw, key) + len(key)
			end := start + bytes.IndexByte(raw[start:], '"')
			return append(append(append([]byte{}, raw[:start-1]...), []byte(`[1,2]`)...), raw[end+1:]...)
		}},
		{"escaped_base64_json_alias", func(raw []byte) []byte {
			key := []byte(`"original_stdout_wire":"`)
			start := bytes.Index(raw, key) + len(key)
			return append(append(append([]byte{}, raw[:start]...), []byte(fmt.Sprintf(`\u%04x`, raw[start]))...), raw[start+1:]...)
		}},
		{"whole_bundle_over_cap", func(raw []byte) []byte { return bytes.Repeat([]byte(" "), 1048577) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := test.mutate(finalAuditSourceWire(t, finalAuditSourceFixture(t)))
			if _, _, err := parseOriginalHostFinalSourceAuditCustody(raw); err == nil {
				t.Fatal("noncanonical private byte wire accepted")
			}
		})
	}
}

func TestHostOriginalFinalSourceAuditMapAndActorReturns(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	makeRelations := func(t *testing.T) (hostOriginalFinalSourceAuditCustody, map[string]hostOriginalSourceAuditProjection, []hostOriginalRealmOwnerReturn, hostOriginalMainReturn) {
		c := finalAuditSourceFixture(t)
		_, audits, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, c))
		if err != nil {
			t.Fatal(err)
		}
		returns := []hostOriginalRealmOwnerReturn{}
		core := postStartSourceFixtureID(6)
		for n, actor := range c.OriginalActors {
			operation := []string{"worker_wait", "registrar_wait"}[n]
			f := model.HostFactoryPrimitiveIOReturn{Operation: operation, SubjectOwnerID: actor.OriginalOwnerID, OriginalState: "returned", OriginalReturnedAt: postStartSourceFixturePtr(postStartSourceFixtureTime(90)), OriginalCallID: postStartSourceFixturePtr(postStartSourceFixtureID(600+n) + ":1"), OriginalOperationDeadline: postStartSourceFixtureTime(100), OriginalReturnClass: "success", OriginalNativeReturn: &model.HostFactoryNativeCallReturn{OriginalErrorPresent: postStartSourceFixturePtr(false)}}
			returns = append(returns, hostOriginalRealmOwnerReturn{Operation: operation, OwnerRole: "host_exterior", SubjectRole: actor.OriginalOwnerRole, OriginalOwnerID: core, SubjectOwnerID: actor.OriginalOwnerID, OriginalFactReference: &hostOriginalRealmFactReference{}, OriginalFact: &f})
		}
		main := hostOriginalMainReturn{Operation: "realm_close_join", OriginalOwnerID: core, OriginalCalledAt: postStartSourceFixturePtr(postStartSourceFixtureTime(70)), OriginalReturnedAt: postStartSourceFixturePtr(postStartSourceFixtureTime(92))}
		return c, audits, returns, main
	}
	t.Run("wait_returns_during_realm_join_is_lawful", func(t *testing.T) {
		c, a, r, m := makeRelations(t)
		if validateOriginalHostFinalSourceActorLifetime(c, a, r, m) != nil {
			t.Fatal("genuine allowed overlap refused")
		}
	})
	t.Run("main_missing_source_fact", func(t *testing.T) {
		_, a, _, _ := makeRelations(t)
		b := map[string]hostOriginalSourceAuditProjection{}
		for k, v := range a {
			b[k] = v
		}
		for k := range b {
			delete(b, k)
			break
		}
		if compareOriginalHostFinalAuditMap(a, b) == nil {
			t.Fatal("omission accepted")
		}
	})
	t.Run("main_original_fact_replaced", func(t *testing.T) {
		_, a, _, _ := makeRelations(t)
		b := map[string]hostOriginalSourceAuditProjection{}
		for k, v := range a {
			b[k] = v
		}
		for k, v := range b {
			v.Fact.OriginalReturnedAt = postStartSourceFixturePtr(postStartSourceFixtureTime(72))
			b[k] = v
			break
		}
		if compareOriginalHostFinalAuditMap(a, b) == nil {
			t.Fatal("replacement accepted")
		}
	})
	t.Run("helper_return_not_inferred_from_wait", func(t *testing.T) {
		c, a, r, m := makeRelations(t)
		finalAuditSourceCarrier(t, &c, 0, func(c *hostOriginalFinalSourceAuditCarrier) {
			c.OriginalHelperReturn.OriginalReturnedAt = postStartSourceFixtureTime(91)
		})
		if validateOriginalHostFinalSourceActorLifetime(c, a, r, m) == nil {
			t.Fatal("wait before actual helper return accepted")
		}
	})
	t.Run("wait_after_realm_return", func(t *testing.T) {
		c, a, r, m := makeRelations(t)
		m.OriginalReturnedAt = postStartSourceFixturePtr(postStartSourceFixtureTime(89))
		if validateOriginalHostFinalSourceActorLifetime(c, a, r, m) == nil {
			t.Fatal("late Wait accepted")
		}
	})
	t.Run("actor_error_source_metadata_refuses_positive", func(t *testing.T) {
		c, a, r, m := makeRelations(t)
		finalAuditSourceCarrier(t, &c, 1, func(c *hostOriginalFinalSourceAuditCarrier) { c.OriginalHelperReturn.OriginalErrorPresent = true })
		if validateOriginalHostFinalSourceActorLifetime(c, a, r, m) == nil {
			t.Fatal("error authority accepted")
		}
	})
	t.Run("collector_error_source_metadata_refuses_positive", func(t *testing.T) {
		c, a, r, m := makeRelations(t)
		c.OriginalActors[1].OriginalReceiverReturn.OriginalErrorPresent = true
		if validateOriginalHostFinalSourceActorLifetime(c, a, r, m) == nil {
			t.Fatal("collector error authority accepted")
		}
	})
	t.Run("receiver_after_realm_return", func(t *testing.T) {
		c, a, r, m := makeRelations(t)
		c.OriginalActors[1].OriginalReceiverReturn.OriginalReturnedAt = postStartSourceFixtureTime(93)
		if validateOriginalHostFinalSourceActorLifetime(c, a, r, m) == nil {
			t.Fatal("late actual collector return accepted")
		}
	})
	t.Run("duplicate_original_wait", func(t *testing.T) {
		c, a, r, m := makeRelations(t)
		r = append(r, r[0])
		if validateOriginalHostFinalSourceActorLifetime(c, a, r, m) == nil {
			t.Fatal("duplicate wait accepted")
		}
	})
	t.Run("missing_actor_original_reference", func(t *testing.T) {
		c, a, r, m := makeRelations(t)
		r[0].OriginalFactReference = nil
		if validateOriginalHostFinalSourceActorLifetime(c, a, r, m) == nil {
			t.Fatal("unreferenced Wait accepted")
		}
	})
}

func TestHostOriginalClosingExternalGoReturnFence(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	makeState := func(t *testing.T) (CapacityStore, *capacityhostfactory.OriginalFactoryRealm, context.Context, *hostOriginalClosingSQLReturn) {
		t.Helper()
		now := time.Now().UTC()
		ctx, cancel := context.WithDeadline(context.Background(), now.Add(time.Minute))
		t.Cleanup(cancel)
		realm := &capacityhostfactory.OriginalFactoryRealm{} // MEMORY ONLY: no constructor or Source approval
		db := &sql.DB{}                                      // pointer identity ONLY, never SQL/connection access
		store := CapacityStore{DB: db}
		state := &hostOriginalClosingSQLReturn{ctx: ctx, realm: realm, db: db, root: postStartSourceFixtureID(502), calledAt: now, deadline: now.Add(time.Minute), commitCalledAt: now.Add(time.Millisecond), commitReturnedAt: now.Add(2 * time.Millisecond), helperReturnedAt: now.Add(3 * time.Millisecond), methodFinishedAt: now.Add(4 * time.Millisecond), committed: true}
		installedHostFactory.Lock()
		oldRealm, oldState := installedHostFactory.realm, installedHostFactory.closingSQL
		installedHostFactory.realm, installedHostFactory.closingSQL = realm, state
		installedHostFactory.Unlock()
		t.Cleanup(func() {
			installedHostFactory.Lock()
			installedHostFactory.realm, installedHostFactory.closingSQL = oldRealm, oldState
			installedHostFactory.Unlock()
		})
		return store, realm, ctx, state
	}
	t.Run("internal_defer_marker_does_not_capture_outer_return", func(t *testing.T) {
		_, _, _, state := makeState(t)
		if state.externalReturnReserved || !state.returnedAt.IsZero() {
			t.Fatal("internal marker relabeled")
		}
	})
	t.Run("separate_three_return_boundaries_memory_only", func(t *testing.T) {
		s, r, ctx, state := makeState(t)
		at := state.calledAt.Add(5 * time.Millisecond)
		if s.CaptureOriginalHostClosingReturn(ctx, r, state.calledAt, at, nil) != nil || !state.returnedAt.Equal(at) || !state.helperReturnedAt.Equal(state.calledAt.Add(3*time.Millisecond)) || !state.commitReturnedAt.Equal(state.calledAt.Add(2*time.Millisecond)) {
			t.Fatal("actual caller sample not preserved")
		}
	})
	tests := []struct {
		name   string
		mutate func(*hostOriginalClosingSQLReturn)
	}{
		{"unknown_commit", func(s *hostOriginalClosingSQLReturn) { s.committed = false }},
		{"commit_return_unknown", func(s *hostOriginalClosingSQLReturn) { s.commitReturnedAt = time.Time{} }},
		{"helper_return_before_commit", func(s *hostOriginalClosingSQLReturn) { s.helperReturnedAt = s.commitReturnedAt.Add(-time.Nanosecond) }},
		{"method_finished_before_helper", func(s *hostOriginalClosingSQLReturn) { s.methodFinishedAt = s.helperReturnedAt.Add(-time.Nanosecond) }},
		{"panic_no_method_goreturn", func(s *hostOriginalClosingSQLReturn) {
			s.methodFinishedAt = time.Time{}
			s.originalErr = ErrHostFactoryHold
		}},
		{"original_error_sticky", func(s *hostOriginalClosingSQLReturn) { s.originalErr = errors.New("opaque source cause") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, r, ctx, state := makeState(t)
			test.mutate(state)
			if s.CaptureOriginalHostClosingReturn(ctx, r, state.calledAt, state.calledAt.Add(5*time.Millisecond), nil) == nil || !state.externalReturnReserved || state.originalErr == nil {
				t.Fatal("unknown boundary accepted or retryable")
			}
		})
	}
	t.Run("late_external_return", func(t *testing.T) {
		s, r, ctx, state := makeState(t)
		if s.CaptureOriginalHostClosingReturn(ctx, r, state.calledAt, state.deadline, nil) == nil {
			t.Fatal("late return accepted")
		}
	})
	t.Run("foreign_current_context", func(t *testing.T) {
		s, r, _, state := makeState(t)
		ctx, cancel := context.WithDeadline(context.Background(), state.deadline)
		defer cancel()
		if s.CaptureOriginalHostClosingReturn(ctx, r, state.calledAt, state.calledAt.Add(5*time.Millisecond), nil) == nil {
			t.Fatal("context substituted")
		}
	})
	t.Run("external_return_before_internal_marker", func(t *testing.T) {
		s, r, ctx, state := makeState(t)
		if s.CaptureOriginalHostClosingReturn(ctx, r, state.calledAt, state.methodFinishedAt.Add(-time.Nanosecond), nil) == nil {
			t.Fatal("marker masqueraded as later return")
		}
	})
	t.Run("external_called_after_method_started", func(t *testing.T) {
		s, r, ctx, state := makeState(t)
		if s.CaptureOriginalHostClosingReturn(ctx, r, state.calledAt.Add(time.Nanosecond), state.calledAt.Add(5*time.Millisecond), nil) == nil {
			t.Fatal("new epoch accepted")
		}
	})
	t.Run("duplicate_capture_sticky_hold", func(t *testing.T) {
		s, r, ctx, state := makeState(t)
		at := state.calledAt.Add(5 * time.Millisecond)
		if s.CaptureOriginalHostClosingReturn(ctx, r, state.calledAt, at, nil) != nil {
			t.Fatal("first memory capture")
		}
		if s.CaptureOriginalHostClosingReturn(ctx, r, state.calledAt, at, nil) == nil || state.originalErr == nil {
			t.Fatal("duplicate became replay/repair")
		}
	})
	t.Run("caller_error_cannot_be_overwritten", func(t *testing.T) {
		s, r, ctx, state := makeState(t)
		cause := errors.New("opaque original cause")
		if err := s.CaptureOriginalHostClosingReturn(ctx, r, state.calledAt, state.calledAt.Add(5*time.Millisecond), cause); !errors.Is(err, cause) || !errors.Is(state.originalErr, cause) {
			t.Fatal("actual cause lost")
		}
	})
	t.Run("helper_sample_not_resampled_by_retainer", func(t *testing.T) {
		_, _, _, state := makeState(t)
		state.helperReturnedAt = time.Time{}
		sample := state.calledAt.Add(3 * time.Millisecond)
		cause := errors.New("opaque helper cause")
		retainOriginalHostClosingHelperReturn(state, sample, cause)
		if !state.helperReturnedAt.Equal(sample) || !errors.Is(state.originalErr, cause) {
			t.Fatal("captured timestamp/cause replaced")
		}
	})
}

func TestHostOriginalFinalAuditSelectedCloseStructuralIdentity(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	makeFacts := func() (model.HostFactoryRootPreparation, hostOriginalPostStartNativeAnchor, model.HostFactoryBasalOwnerObservation, model.HostFactoryCallVectorChunk) {
		ref := hostOriginalPostStartNativeAnchor{postStartSourceFixtureID(601), postStartSourceFixtureSHA("heldBODY"), postStartSourceFixtureSHA("heldENV"), postStartSourceFixtureID(601) + ":1", postStartSourceFixtureID(601) + ":2"}
		primitive := postStartSourceFixtureSHA("CoreBasal")
		owner, handle := postStartSourceFixtureID(6), postStartSourceFixtureID(601)
		prep := model.HostFactoryRootPreparation{FactoryRootID: postStartSourceFixtureID(501), SourceApprovalSHA256: postStartSourceFixtureSHA("approval"), CoreBasalOwnerRawSHA256: primitive, RootDirectorySource: model.HostFactoryBootstrapDescriptorSource{OriginalHandleID: postStartSourceFixtureID(602)}, OriginalHandleInventorySHAs: []string{ref.OriginalInventoryBodySHA256}}
		core := model.HostFactoryBasalOwnerObservation{FactoryRootID: prep.FactoryRootID, OriginalOwnerID: owner, Role: "host_exterior"}
		f := model.HostFactoryPrimitiveIOReturn{Operation: "root_directory_close", OriginalHandleID: handle, SubjectOwnerID: owner, OwnerPrimitiveRawSHA256: &primitive, OriginalState: "returned", OriginalCalledAt: postStartSourceFixturePtr(postStartSourceFixtureTime(80)), OriginalReturnedAt: postStartSourceFixturePtr(postStartSourceFixtureTime(81)), OriginalOperationDeadline: postStartSourceFixtureTime(100), OriginalCallID: postStartSourceFixturePtr(handle + ":5"), OriginalReturnClass: "success", OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "original_file_close", OriginalErrorPresent: postStartSourceFixturePtr(false), OriginalErrno: postStartSourceFixturePtr(uint32(0))}}
		c := model.HostFactoryCallVectorChunk{OriginalOwnerID: owner, OwnerRole: "host_exterior", OwnerPrimitiveRawSHA256: primitive, OriginalHandleID: handle, BindingSchema: "original_host_factory_source_approval_v4", BindingSHA256: prep.SourceApprovalSHA256, OriginalCalls: []model.HostFactoryPrimitiveIOReturn{f}}
		return prep, ref, core, c
	}
	t.Run("actual_held_sourceapproval_close_structural_only", func(t *testing.T) {
		p, r, b, c := makeFacts()
		if !originalHostFinalRootCloseIdentity(p, r, b, c, 0) {
			t.Fatal("exact structural held Close refused")
		}
	})
	// Structural original-reference relation ONLY. The separate Source-owned
	// getter/compiledkey/native graph/SQL FIRST authenticators remain required;
	// RootDirectorySource is deliberately a different earlier-closed handle.
	tests := []struct {
		name   string
		mutate func(*model.HostFactoryRootPreparation, *model.HostFactoryBasalOwnerObservation, *model.HostFactoryCallVectorChunk)
	}{
		{"foreign_original_handle", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, c *model.HostFactoryCallVectorChunk) {
			c.OriginalHandleID = postStartSourceFixtureID(602)
		}},
		{"foreign_original_owner", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, c *model.HostFactoryCallVectorChunk) {
			c.OriginalOwnerID = postStartSourceFixtureID(602)
		}},
		{"scope_namespace_is_not_root_close", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, c *model.HostFactoryCallVectorChunk) {
			c.BindingSchema = "original_host_factory_pre_authority_scope_v4"
			c.BindingSHA256 = postStartSourceFixtureSHA("scope")
		}},
		{"rewritten_root_binding", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, c *model.HostFactoryCallVectorChunk) {
			c.BindingSHA256 = postStartSourceFixtureSHA("foreign")
		}},
		{"called_pending_is_not_returned", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, c *model.HostFactoryCallVectorChunk) {
			c.OriginalCalls[0].OriginalState = "called_pending"
			c.OriginalCalls[0].OriginalReturnedAt = nil
		}},
		{"stdout_close_operation_alias", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, c *model.HostFactoryCallVectorChunk) {
			c.OriginalCalls[0].Operation = "stdout_close"
		}},
		{"different_original_primitive", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, c *model.HostFactoryCallVectorChunk) {
			c.OriginalCalls[0].OwnerPrimitiveRawSHA256 = postStartSourceFixturePtr(postStartSourceFixtureSHA("foreign"))
		}},
		{"close_before_original_four_acquisitions", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, c *model.HostFactoryCallVectorChunk) {
			c.OriginalCalls[0].OriginalCallID = postStartSourceFixturePtr(c.OriginalHandleID + ":4")
		}},
		{"close_actual_native_error", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, c *model.HostFactoryCallVectorChunk) {
			c.OriginalCalls[0].OriginalNativeReturn.OriginalErrorPresent = postStartSourceFixturePtr(true)
		}},
		{"close_return_at_operation_bound", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, c *model.HostFactoryCallVectorChunk) {
			c.OriginalCalls[0].OriginalReturnedAt = postStartSourceFixturePtr(c.OriginalCalls[0].OriginalOperationDeadline)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, sha, b, c := makeFacts()
			test.mutate(&p, &b, &c)
			if originalHostFinalRootCloseIdentity(p, sha, b, c, 0) {
				t.Fatal("foreign selected original accepted")
			}
		})
	}
	t.Run("out_of_range_fact_index", func(t *testing.T) {
		p, sha, b, c := makeFacts()
		if originalHostFinalRootCloseIdentity(p, sha, b, c, 1) {
			t.Fatal("missing fact index accepted")
		}
	})
}

// Constructed native tuples are structural discriminants, never suppliers.
// No process/syscall/key/Source capability is created by this fixture.
func parentHeldSourceFixture() (model.HostFactoryRootPreparation, model.HostFactoryBasalOwnerObservation, hostOriginalPostStartNativeAnchor, []model.HostFactoryPrimitiveIOReturn) {
	ref := hostOriginalPostStartNativeAnchor{postStartSourceFixtureID(701), postStartSourceFixtureSHA("heldRootBODY"), postStartSourceFixtureSHA("heldRootENV"), postStartSourceFixtureID(701) + ":1", postStartSourceFixtureID(701) + ":2"}
	primitive := postStartSourceFixtureSHA("coreRootBasal")
	owner := postStartSourceFixtureID(6)
	prep := model.HostFactoryRootPreparation{FactoryRootID: postStartSourceFixtureID(1), SourceApprovalSHA256: postStartSourceFixtureSHA("approval"), CoreBasalOwnerRawSHA256: primitive, OriginalHandleInventorySHAs: []string{ref.OriginalInventoryBodySHA256}, OriginalContextStartedAt: postStartSourceFixtureTime(0), OriginalContextDeadline: postStartSourceFixtureTime(600), RootDirectorySource: model.HostFactoryBootstrapDescriptorSource{OriginalHandleID: postStartSourceFixtureID(702), Device: 11, Inode: 12, Mode: 0040700, LinkCount: 2, UID: 1000, GID: 1000}}
	core := model.HostFactoryBasalOwnerObservation{FactoryRootID: prep.FactoryRootID, OriginalOwnerID: owner, SourceApprovalSHA256: prep.SourceApprovalSHA256, Role: "host_exterior"}
	facts := []model.HostFactoryPrimitiveIOReturn{}
	for n, operation := range []string{"root_directory_open", "descriptor_fstat", "fcntl_getfl", "fcntl_getfd"} {
		called := postStartSourceFixtureTime(1 + float64(n))
		native := &model.HostFactoryNativeCallReturn{OriginalErrorPresent: postStartSourceFixturePtr(false), OriginalErrno: postStartSourceFixturePtr(uint32(0))}
		switch n {
		case 0:
			native.Kind = "unix_openat"
			native.RequestedFlags = postStartSourceFixturePtr(uint32(0x290000))
			native.OriginalScalar = postStartSourceFixturePtr(int64(19))
			native.ReturnedDescriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: ref.OriginalHandleID, OriginalDescriptorNumber: 19}}
		case 1:
			native.Kind = "unix_fstat"
			native.InputDescriptorNumber = postStartSourceFixturePtr(19)
			native.OriginalStat = &model.HostFactoryNativeStatReturn{Device: 11, Inode: 12, Mode: 0040700, LinkCount: 2, UID: 1000, GID: 1000}
		case 2, 3:
			native.Kind = operation
			native.InputDescriptorNumber = postStartSourceFixturePtr(19)
			native.RequestedFcntlCommand = postStartSourceFixturePtr([]int{3, 1}[n-2])
			native.RequestedArgument = postStartSourceFixturePtr(int64(0))
			native.OriginalScalar = postStartSourceFixturePtr([]int64{0x210000, 1}[n-2])
		}
		facts = append(facts, model.HostFactoryPrimitiveIOReturn{Operation: operation, OriginalHandleID: ref.OriginalHandleID, SubjectOwnerID: owner, OwnerPrimitiveRawSHA256: &primitive, OriginalCallID: postStartSourceFixturePtr(ref.OriginalHandleID + ":" + strconv.Itoa(n+1)), OriginalCalledAt: &called, OriginalReturnedAt: postStartSourceFixturePtr(called.Add(time.Microsecond)), OriginalOperationDeadline: prep.OriginalContextDeadline, OriginalState: "returned", OriginalReturnClass: "success", OriginalNativeReturn: native})
	}
	return prep, core, ref, facts
}

func TestHostOriginalParentHeldAnchorStructuralIdentity(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	t.Run("two_distinct_original_directory_handles_same_stat", func(t *testing.T) {
		p, b, r, f := parentHeldSourceFixture()
		if r.OriginalHandleID == p.RootDirectorySource.OriginalHandleID || validateOriginalHostParentHeldAnchorFacts(p, b, r, f) != nil {
			t.Fatal("structural exact held reference refused")
		}
	})
	tests := []struct {
		name   string
		mutate func(*model.HostFactoryRootPreparation, *model.HostFactoryBasalOwnerObservation, *hostOriginalPostStartNativeAnchor, *[]model.HostFactoryPrimitiveIOReturn)
	}{
		{"earlier_closed_rootdirectorysource_alias", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			r.OriginalHandleID = p.RootDirectorySource.OriginalHandleID
		}},
		{"missing_saved_inventory_membership", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			p.OriginalHandleInventorySHAs = []string{}
		}},
		{"duplicate_saved_inventory_membership", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			p.OriginalHandleInventorySHAs = append(p.OriginalHandleInventorySHAs, r.OriginalInventoryBodySHA256)
		}},
		{"later_inventory_snapshot_body_not_saved", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			r.OriginalInventoryBodySHA256 = postStartSourceFixtureSHA("later")
		}},
		{"missing_original_envelope_hash", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			r.OriginalInventoryEnvelopeSHA256 = ""
		}},
		{"acquisition_callid_not_original_one", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			r.OriginalAcquisitionCallID = r.OriginalHandleID + ":5"
		}},
		{"fstat_callid_not_original_two", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			r.OriginalFstatCallID = r.OriginalHandleID + ":6"
		}},
		{"actor_native_reader_open_not_parent_root_open", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[0].Operation = "native_reader_open"
		}},
		{"wrong_syscall_kind", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[0].OriginalNativeReturn.Kind = "unix_open"
		}},
		{"different_original_descriptor_number", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[1].OriginalNativeReturn.InputDescriptorNumber = postStartSourceFixturePtr(20)
		}},
		{"same_fd_but_different_acquired_handle", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[0].OriginalNativeReturn.ReturnedDescriptors[0].OriginalHandleID = p.RootDirectorySource.OriginalHandleID
		}},
		{"fstat_dev_inode_mismatch", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[1].OriginalNativeReturn.OriginalStat.Inode++
		}},
		{"generic_unix_fcntl_kind_is_not_original_getfl", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[2].OriginalNativeReturn.Kind = "unix_fcntl"
		}},
		{"getfd_return_kind_cannot_alias_getfl", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[3].OriginalNativeReturn.Kind = "fcntl_getfl"
		}},
		{"getfl_observation_unknown", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[2].OriginalNativeReturn.OriginalScalar = nil
		}},
		{"getfd_not_getfl_command_alias", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[3].OriginalNativeReturn.RequestedFcntlCommand = postStartSourceFixturePtr(3)
		}},
		{"fcntl_setfl_not_readonly_argzero", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[2].OriginalNativeReturn.RequestedArgument = postStartSourceFixturePtr(int64(1))
		}},
		{"foreign_core_owner", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			b.OriginalOwnerID = postStartSourceFixtureID(703)
		}},
		{"native_error_not_normalized_to_success", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[2].OriginalNativeReturn.OriginalErrorPresent = postStartSourceFixturePtr(true)
		}},
		{"native_called_pending_not_returned", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[0].OriginalState = "called_pending"
			(*f)[0].OriginalReturnedAt = nil
		}},
		{"actual_return_at_original_root_bound", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			(*f)[3].OriginalReturnedAt = &p.OriginalContextDeadline
		}},
		{"missing_original_getfd_fact", func(p *model.HostFactoryRootPreparation, b *model.HostFactoryBasalOwnerObservation, r *hostOriginalPostStartNativeAnchor, f *[]model.HostFactoryPrimitiveIOReturn) {
			*f = (*f)[:3]
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, b, r, f := parentHeldSourceFixture()
			test.mutate(&p, &b, &r, &f)
			if validateOriginalHostParentHeldAnchorFacts(p, b, r, f) == nil {
				t.Fatal("foreign/unknown original accepted")
			}
		})
	}
}

func TestHostOriginalHeldAnchorRequiredPrivateVersions(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	t.Run("current_v2_no_new_required_anchor_fallback", func(t *testing.T) {
		c := postStartSourceFixture(t)
		c.Schema = "source_private_original_poststart_ledger_custody_v2"
		if _, err := decodeOriginalHostPostStartLedgerCustody(postStartSourceFixtureWire(t, c)); err == nil {
			t.Fatal("old private schema adopted")
		}
	})
	t.Run("current_required_anchor_missing", func(t *testing.T) {
		c := postStartSourceFixture(t)
		c.OriginalParentHeldRootAnchor = hostOriginalPostStartNativeAnchor{}
		if _, err := decodeOriginalHostPostStartLedgerCustody(postStartSourceFixtureWire(t, c)); err == nil {
			t.Fatal("unknown parent anchor accepted")
		}
	})
	t.Run("final_v1_no_new_required_anchor_fallback", func(t *testing.T) {
		c := finalAuditSourceFixture(t)
		c.Schema = "source_private_original_final_source_audit_custody_v1"
		if _, _, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, c)); err == nil {
			t.Fatal("old final schema adopted")
		}
	})
	t.Run("final_required_anchor_missing", func(t *testing.T) {
		c := finalAuditSourceFixture(t)
		c.OriginalParentHeldRootAnchor = hostOriginalPostStartNativeAnchor{}
		if _, _, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, c)); err == nil {
			t.Fatal("unknown final anchor accepted")
		}
	})
}

// Direct SQL vectors exercise storage shape only. Their placeholder envelopes,
// incomplete private bodies and declared native tuples never pass Source or
// native authentication. Every owning remote case rolls its transaction back.
type finalAuditStorageFixture struct {
	root, owner, handle, earlyHandle, binding, primitive, preparation string
	inventoryBody, inventoryEnvelope                                  string
	rootBody                                                          map[string]any
	fact                                                              map[string]any
	bundle                                                            map[string]any
	schema, kind, callID                                              string
	index                                                             int
	wire                                                              []byte
	omitFirst                                                         bool
}

func finalAuditStorageVector() finalAuditStorageFixture {
	f := finalAuditStorageFixture{root: uuid.NewString(), owner: uuid.NewString(), handle: uuid.NewString(), earlyHandle: uuid.NewString(), binding: strings.Repeat("a", 64), primitive: strings.Repeat("b", 64), schema: "original_host_factory_source_approval_v4", kind: "first"}
	f.inventoryBody = capacity.HostFactoryRawSHA256([]byte("storage-inventory/" + f.root))
	f.inventoryEnvelope = capacity.HostFactoryRawSHA256([]byte("storage-envelope/" + f.root))
	f.rootBody = map[string]any{"root_directory_source": map[string]any{"original_handle_id": f.earlyHandle}, "core_basal_owner_raw_sha256": f.primitive, "original_handle_inventory_sh_as": []string{f.inventoryBody}}
	f.fact = map[string]any{"original_state": "returned", "operation": "root_directory_close", "original_call_id": f.handle + ":5", "original_handle_id": f.handle, "subject_owner_id": f.owner, "owner_primitive_raw_sha256": f.primitive, "original_native_return": map[string]any{"kind": "original_file_close", "original_error_present": false}}
	f.callID = f.handle + ":5"
	f.bundle = map[string]any{"schema": "source_private_original_final_source_audit_custody_v2", "logical_scope_root_id": f.root, "source_approval_body_sha256": f.binding, "original_parent_held_root_anchor": map[string]any{"original_handle_id": f.handle, "original_inventory_body_sha256": f.inventoryBody, "original_inventory_envelope_sha256": f.inventoryEnvelope, "original_acquisition_call_id": f.handle + ":1", "original_fstat_call_id": f.handle + ":2"}}
	return f
}

func finalAuditStorageSetup(t *testing.T, tx *sql.Tx, f *finalAuditStorageFixture) (string, []byte) {
	t.Helper()
	encode := func(v any) []byte {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	rootRaw := encode(f.rootBody)
	f.preparation = capacity.HostFactoryRawSHA256(rootRaw)
	f.bundle["root_preparation_body_sha256"] = f.preparation
	start := postStartSourceFixtureTime(0)
	_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_roots(scope_root_id,factory_realm_id,factory_attempt_id,creator_owner_id,factory_registry_class,root_key_sha256,source_approval_sha256,source_approval_wire,root_preparation_sha256,root_preparation_wire,original_started_at,original_deadline,root_device,root_inode,source_closure_sha256) VALUES($1,$2,$3,$4,'original_source_owned_factory',$5,$6,$7,$8,$9,$10,$11,1,$12,$13)`, f.root, uuid.NewString(), uuid.NewString(), f.owner, capacity.HostFactoryRawSHA256([]byte(f.root)), f.binding, []byte(`{"storage_only":true}`), f.preparation, rootRaw, start, start.Add(600*time.Second), time.Now().UnixNano(), f.primitive)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO public.capacity_host_factory_stage_returns(root_id,subject_owner_id,stage,binding_schema,binding_sha256,signer_role,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire) VALUES($1,$2,'basal-owner-core','original_host_factory_source_approval_v4',$3,'host_exterior',$4,$5,$6,$5)`, f.root, f.owner, f.binding, f.primitive, []byte(`{"storage_only":true}`), capacity.HostFactoryRawSHA256([]byte("basal-envelope/"+f.root)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(`INSERT INTO public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,record_identity_sha256,original_handle_id,first_ordinal,last_ordinal,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire) VALUES($1,'original_host_factory_source_approval_v4',$2,$3,'handle-inventory',$4,$5,1,4,$4,$6,$7,$6)`, f.root, f.binding, f.owner, f.inventoryBody, f.handle, []byte(`{"storage_only":true}`), f.inventoryEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	body := encode(map[string]any{"original_calls": []any{f.fact}})
	sha := capacity.HostFactoryRawSHA256(body)
	_, err = tx.Exec(`INSERT INTO public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,record_identity_sha256,original_handle_id,operation,first_ordinal,last_ordinal,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire) VALUES($1,$2,$3,$4,'chunk',$5,$6,'root_directory_close',5,5,$5,$7,$8,$7)`, f.root, f.schema, f.binding, f.owner, sha, f.handle, body, capacity.HostFactoryRawSHA256(append([]byte("chunk/"), body...)))
	if err != nil {
		t.Fatal(err)
	}
	if f.wire == nil {
		f.wire = encode(f.bundle)
	}
	return sha, body
}

func finalAuditStorageLink(tx *sql.Tx, f finalAuditStorageFixture, sha string) error {
	var prior any
	var priorIndex, priorKind any
	if f.kind == "pending_to_returned" {
		// An actual stored FIRST relation is required even for a storage vector.
		pending := []byte(`{"original_calls":[{"original_state":"called_pending"}]}`)
		prior = capacity.HostFactoryRawSHA256(pending)
		priorIndex, priorKind = 0, "first"
		if !f.omitFirst {
			_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_io_returns(root_id,binding_schema,binding_sha256,original_owner_id,record_kind,record_identity_sha256,original_handle_id,operation,first_ordinal,last_ordinal,raw_body_sha256,raw_body_wire,raw_envelope_sha256,raw_envelope_wire) VALUES($1,$2,$3,$4,'chunk',$5,$6,'root_directory_close',5,5,$5,$7,$5,$7)`, f.root, f.schema, f.binding, f.owner, prior, f.handle, pending)
			if err != nil {
				return err
			}
			_, err = tx.Exec(`INSERT INTO public.capacity_host_factory_call_snapshot_links(root_id,binding_schema,binding_sha256,original_owner_id,original_handle_id,original_call_id,version_kind,current_chunk_raw_body_sha256,current_fact_index,original_called_at,original_operation_deadline) VALUES($1,$2,$3,$4,$5,$6,'first',$7,0,$8,$9)`, f.root, f.schema, f.binding, f.owner, f.handle, f.callID, prior, postStartSourceFixtureTime(80), postStartSourceFixtureTime(150))
			if err != nil {
				return err
			}
		}
	}
	_, err := tx.Exec(`INSERT INTO public.capacity_host_factory_call_snapshot_links(root_id,binding_schema,binding_sha256,original_owner_id,original_handle_id,original_call_id,version_kind,current_chunk_raw_body_sha256,current_fact_index,predecessor_chunk_raw_body_sha256,predecessor_fact_index,predecessor_version_kind,original_called_at,original_operation_deadline,original_final_source_audit_wire) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, f.root, f.schema, f.binding, f.owner, f.handle, f.callID, f.kind, sha, f.index, prior, priorIndex, priorKind, postStartSourceFixtureTime(80), postStartSourceFixtureTime(150), f.wire)
	return err
}

func TestHostOriginalFactoryPostgresFinalAuditSameInsertStorage(t *testing.T) {
	for _, kind := range []string{"first", "pending_to_returned"} {
		t.Run(kind, func(t *testing.T) {
			tx, err := hostFactoryPostgres(t).BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			f := finalAuditStorageVector()
			f.kind = kind
			sha, _ := finalAuditStorageSetup(t, tx, &f)
			if err = finalAuditStorageLink(tx, f, sha); err != nil {
				t.Fatal("storage shape refused", err)
			}
			var stored []byte
			if err = tx.QueryRow(`SELECT original_final_source_audit_wire FROM public.capacity_host_factory_call_snapshot_links WHERE root_id=$1 AND version_kind=$2`, f.root, kind).Scan(&stored); err != nil || !bytes.Equal(stored, f.wire) {
				t.Fatal("private original not retained", err)
			}
			snapshot := hostOriginalSQLSnapshot{Records: []hostOriginalSQLRecord{}}
			total := 0
			for _, table := range originalHostSQLTables {
				if table.table == "public.capacity_host_factory_call_snapshot_links" {
					if err = originalHostSQLReadTable(context.Background(), tx, table, []any{f.root}, &snapshot, &total); err != nil {
						t.Fatal(err)
					}
				}
			}
			selected := 0
			for _, row := range snapshot.Records {
				if bytes.Equal(row.original["original_final_source_audit_wire"], f.wire) {
					selected++
				}
				for _, field := range row.RawFields {
					if field.Column == "original_final_source_audit_wire" {
						t.Fatal("private count/hash exported")
					}
				}
			}
			public, encodeErr := json.Marshal(snapshot)
			if encodeErr != nil || selected != 1 || bytes.Contains(public, []byte("original_final_source_audit_wire")) || bytes.Contains(public, []byte(base64.StdEncoding.EncodeToString(f.wire))) {
				t.Fatal("private final bundle leaked or not retained")
			}
			// SQL acceptance of these deliberately invalid Source bytes is not an
			// approval: the canonical full custody parser must still reject them.
			if _, _, err = parseOriginalHostFinalSourceAuditCustody(stored); err == nil {
				t.Fatal("storage vector became Source authority")
			}
		})
	}
}

func TestHostOriginalFactoryPostgresFinalAuditSelectorRefusals(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*finalAuditStorageFixture)
	}{
		{"earlier_rootdirectorysource_alias", func(f *finalAuditStorageFixture) {
			f.rootBody["root_directory_source"] = map[string]any{"original_handle_id": f.handle}
		}},
		{"missing_saved_inventory", func(f *finalAuditStorageFixture) { f.rootBody["original_handle_inventory_sh_as"] = []string{} }},
		{"duplicate_saved_inventory", func(f *finalAuditStorageFixture) {
			f.rootBody["original_handle_inventory_sh_as"] = []string{f.inventoryBody, f.inventoryBody}
		}},
		{"different_saved_envelope", func(f *finalAuditStorageFixture) {
			f.bundle["original_parent_held_root_anchor"].(map[string]any)["original_inventory_envelope_sha256"] = strings.Repeat("c", 64)
		}},
		{"different_saved_body", func(f *finalAuditStorageFixture) {
			f.bundle["original_parent_held_root_anchor"].(map[string]any)["original_inventory_body_sha256"] = strings.Repeat("c", 64)
		}},
		{"wrong_original_acquisition", func(f *finalAuditStorageFixture) {
			f.bundle["original_parent_held_root_anchor"].(map[string]any)["original_acquisition_call_id"] = f.handle + ":3"
		}},
		{"wrong_original_fstat", func(f *finalAuditStorageFixture) {
			f.bundle["original_parent_held_root_anchor"].(map[string]any)["original_fstat_call_id"] = f.handle + ":4"
		}},
		{"scope_binding_cannot_replace_sourceapproval", func(f *finalAuditStorageFixture) { f.schema = "original_host_factory_pre_authority_scope_v4" }},
		{"original_state_pending", func(f *finalAuditStorageFixture) { f.fact["original_state"] = "called_pending" }},
		{"stdout_close_operation_alias", func(f *finalAuditStorageFixture) { f.fact["operation"] = "stdout_close" }},
		{"foreign_subject_owner", func(f *finalAuditStorageFixture) { f.fact["subject_owner_id"] = uuid.NewString() }},
		{"foreign_owner_basal", func(f *finalAuditStorageFixture) { f.fact["owner_primitive_raw_sha256"] = strings.Repeat("c", 64) }},
		{"native_close_error", func(f *finalAuditStorageFixture) {
			f.fact["original_native_return"].(map[string]any)["original_error_present"] = true
		}},
		{"original_call_id_mismatch", func(f *finalAuditStorageFixture) { f.callID = f.handle + ":6" }},
		{"missing_original_fact_index", func(f *finalAuditStorageFixture) { f.index = 1 }},
		{"orphan_pending_to_returned_no_original_first", func(f *finalAuditStorageFixture) { f.kind = "pending_to_returned"; f.omitFirst = true }},
		{"returned_is_not_relation_kind", func(f *finalAuditStorageFixture) { f.kind = "returned" }},
		{"old_final_schema_no_fallback", func(f *finalAuditStorageFixture) {
			f.bundle["schema"] = "source_private_original_final_source_audit_custody_v1"
		}},
		{"private_whole_wire_oversize", func(f *finalAuditStorageFixture) { f.wire = bytes.Repeat([]byte(" "), 1048577) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx, err := hostFactoryPostgres(t).BeginTx(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			f := finalAuditStorageVector()
			test.mutate(&f)
			sha, _ := finalAuditStorageSetup(t, tx, &f)
			if finalAuditStorageLink(tx, f, sha) == nil {
				t.Fatal("foreign/unknown storage relation accepted")
			}
		})
	}
}

func TestHostOriginalFactoryPostgresFinalAuditNoBackfill(t *testing.T) {
	tx, err := hostFactoryPostgres(t).BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	f := finalAuditStorageVector()
	sha, _ := finalAuditStorageSetup(t, tx, &f)
	original := bytes.Clone(f.wire)
	f.wire = nil
	if err = finalAuditStorageLink(tx, f, sha); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`UPDATE public.capacity_host_factory_call_snapshot_links SET original_final_source_audit_wire=$2 WHERE root_id=$1`, f.root, original); err == nil {
		t.Fatal("immutable historical link backfilled")
	}
}

// The bounded Source File.Read may return 65537 after a preFstat race. Its
// complete diagnostic projections retain that count, without exporting the
// original private bytes or authorizing a native/current successful result.
func finalAuditCountSourceFixture(t *testing.T, count uint32) hostOriginalFinalSourceAuditCustody {
	t.Helper()
	c := finalAuditSourceFixture(t)
	finalAuditSourceCarrier(t, &c, 0, func(carrier *hostOriginalFinalSourceAuditCarrier) {
		header := hostOriginalPostStartLedgerCustody{FactoryRootID: c.FactoryRootID, BindingSchema: carrier.BindingSchema, ScopeBodySHA256: carrier.BindingSHA256}
		_, rows := postStartSourceFixtureStream(header, 915, 510, "host_worker", "closed_file", postStartSourceFixturePtr(carrier.OriginalRemainingStreams[0].OriginalHandleID), []string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_close"}, 70, count)
		// The held directory is acquired first and closes after this actual
		// private file chain, before the whole actor helper's original return.
		directory := &carrier.OriginalRemainingStreams[0]
		for n := range directory.OriginalSourceAuditProjections {
			at := postStartSourceFixtureTime(50 + float64(n)/10)
			if n == len(directory.OriginalSourceAuditProjections)-1 {
				at = postStartSourceFixtureTime(80)
			}
			directory.OriginalSourceAuditProjections[n].Fact.OriginalCalledAt = &at
			directory.OriginalSourceAuditProjections[n].Fact.OriginalReturnedAt = postStartSourceFixturePtr(at.Add(time.Nanosecond))
		}
		carrier.OriginalRemainingStreams = append(carrier.OriginalRemainingStreams, hostOriginalFinalSourceAuditStream{2, carrier.OriginalOwnerID, carrier.OriginalOwnerRole, carrier.BindingSchema, carrier.BindingSHA256, postStartSourceFixtureID(915), rows})
		carrier.OriginalStreamCount = 2
		carrier.OriginalHelperReturn.OriginalErrorPresent = true
	})
	c.OriginalAllSourceFacts += 4
	return c
}

func TestHostOriginalFinalSourceAuditDiagnosticReadCount(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	t.Run("count65537_complete_private_diagnostic_retained", func(t *testing.T) {
		c := finalAuditCountSourceFixture(t, 65537)
		_, facts, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, c))
		read, ok := facts[postStartSourceFixtureID(915)+":3"]
		if err != nil || !ok || read.Fact.OriginalCount == nil || *read.Fact.OriginalCount != 65537 || read.Fact.OriginalSHA256 != nil || read.Fact.RetainedPrefixSHA256 != nil || read.Fact.RetainedPrefixBytes != nil || read.Fact.OriginalReadScope != nil || read.Fact.OriginalEOF == nil || *read.Fact.OriginalEOF || read.Fact.OriginalErrorPresent == nil || *read.Fact.OriginalErrorPresent {
			t.Fatal("actual diagnostic count/error/NULL privacy rewritten", err)
		}
		if _, err = capacity.ApprovedHostFactorySource(); err == nil {
			t.Fatal("structural diagnostic installed a Source supplier")
		}
	})
	t.Run("count65538_refused_by_SourceAudit20", func(t *testing.T) {
		if _, _, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, finalAuditCountSourceFixture(t, 65538))); err == nil {
			t.Fatal("count contract widened")
		}
	})
	for _, which := range []string{"whole_private_sha", "retained_prefix_sha"} {
		t.Run("count65537_"+which+"_refused", func(t *testing.T) {
			c := finalAuditCountSourceFixture(t, 65537)
			finalAuditSourceCarrier(t, &c, 0, func(carrier *hostOriginalFinalSourceAuditCarrier) {
				fact := &carrier.OriginalRemainingStreams[1].OriginalSourceAuditProjections[2].Fact
				if which == "whole_private_sha" {
					fact.OriginalSHA256 = postStartSourceFixturePtr(postStartSourceFixtureSHA("private-not-exported"))
				} else {
					fact.RetainedPrefixSHA256 = postStartSourceFixturePtr(postStartSourceFixtureSHA("private-prefix-not-exported"))
				}
			})
			if _, _, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, c)); err == nil {
				t.Fatal("diagnostic metadata exposed private byte hash")
			}
		})
	}
	t.Run("count65537_helper_error_never_positive_Main_native", func(t *testing.T) {
		makeReturns := func(c hostOriginalFinalSourceAuditCustody) ([]hostOriginalRealmOwnerReturn, hostOriginalMainReturn) {
			returns := []hostOriginalRealmOwnerReturn{}
			for n, actor := range c.OriginalActors {
				operation := []string{"worker_wait", "registrar_wait"}[n]
				fact := model.HostFactoryPrimitiveIOReturn{Operation: operation, SubjectOwnerID: actor.OriginalOwnerID, OriginalState: "returned", OriginalReturnedAt: postStartSourceFixturePtr(postStartSourceFixtureTime(90)), OriginalCallID: postStartSourceFixturePtr(postStartSourceFixtureID(930+n) + ":1"), OriginalOperationDeadline: postStartSourceFixtureTime(100), OriginalReturnClass: "success", OriginalNativeReturn: &model.HostFactoryNativeCallReturn{OriginalErrorPresent: postStartSourceFixturePtr(false)}}
				returns = append(returns, hostOriginalRealmOwnerReturn{Operation: operation, OwnerRole: "host_exterior", SubjectRole: actor.OriginalOwnerRole, OriginalOwnerID: postStartSourceFixtureID(6), SubjectOwnerID: actor.OriginalOwnerID, OriginalFactReference: &hostOriginalRealmFactReference{}, OriginalFact: &fact})
			}
			return returns, hostOriginalMainReturn{Operation: "realm_close_join", OriginalOwnerID: postStartSourceFixtureID(6), OriginalCalledAt: postStartSourceFixturePtr(postStartSourceFixtureTime(70)), OriginalReturnedAt: postStartSourceFixturePtr(postStartSourceFixtureTime(92))}
		}
		// First establish that this structural owning-return relation is valid;
		// a missing Wait or malformed Main must not make the error test vacuous.
		base := finalAuditSourceFixture(t)
		_, audits, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, base))
		returns, main := makeReturns(base)
		if err != nil || validateOriginalHostFinalSourceActorLifetime(base, audits, returns, main) != nil {
			t.Fatal("structural lifetime control refused", err)
		}
		diagnostic := finalAuditCountSourceFixture(t, 65537)
		_, audits, err = parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, diagnostic))
		returns, main = makeReturns(diagnostic)
		if err != nil || validateOriginalHostFinalSourceActorLifetime(diagnostic, audits, returns, main) == nil {
			t.Fatal("safe error diagnostic became positive native/Main closure", err)
		}
	})
}

// A Source-only transaction-entry sentinel, not a successful SQL/Native supplier.
// Begin always fails before a transaction/query/write can exist. These tests
// run only in remoteCI; they never install an approved Source or mock Wait.
var originalSettleWaitSourceBeginRefused = errors.New("source-only transaction entry sentinel; no SQL transaction")
var originalSettleWaitSourceDriverNames struct {
	sync.Mutex
	n uint64
}

type originalSettleWaitSourceBoundary struct {
	mu     sync.Mutex
	begins int
	ctx    context.Context
}
type originalSettleWaitSourceDriver struct {
	boundary *originalSettleWaitSourceBoundary
}
type originalSettleWaitSourceConn struct {
	boundary *originalSettleWaitSourceBoundary
}

func (d originalSettleWaitSourceDriver) Open(string) (driver.Conn, error) {
	return &originalSettleWaitSourceConn{d.boundary}, nil
}
func (*originalSettleWaitSourceConn) Prepare(string) (driver.Stmt, error) {
	return nil, originalSettleWaitSourceBeginRefused
}
func (*originalSettleWaitSourceConn) Close() error { return nil }
func (c *originalSettleWaitSourceConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *originalSettleWaitSourceConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	c.boundary.mu.Lock()
	c.boundary.begins++
	c.boundary.ctx = ctx
	c.boundary.mu.Unlock()
	return nil, originalSettleWaitSourceBeginRefused
}
func originalSettleWaitSourceDB(t *testing.T) (*sql.DB, *originalSettleWaitSourceBoundary) {
	t.Helper()
	originalSettleWaitSourceDriverNames.Lock()
	originalSettleWaitSourceDriverNames.n++
	name := fmt.Sprintf("source13-ordinary-settle-wait-boundary-%d", originalSettleWaitSourceDriverNames.n)
	originalSettleWaitSourceDriverNames.Unlock()
	boundary := &originalSettleWaitSourceBoundary{}
	sql.Register(name, originalSettleWaitSourceDriver{boundary})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, boundary
}

func originalSettleWaitSourceCache(t *testing.T, realm *capacityhostfactory.OriginalFactoryRealm, approval model.HostFactorySourceApproval, factories map[string]*hostOriginalOrdinaryFactory) {
	t.Helper()
	installedHostFactory.Lock()
	oldRealm, oldApproval, oldFactories := installedHostFactory.realm, installedHostFactory.approval, installedHostFactory.ordinaryFactories
	installedHostFactory.realm, installedHostFactory.approval, installedHostFactory.ordinaryFactories = realm, approval, factories
	installedHostFactory.Unlock()
	t.Cleanup(func() {
		installedHostFactory.Lock()
		installedHostFactory.realm, installedHostFactory.approval, installedHostFactory.ordinaryFactories = oldRealm, oldApproval, oldFactories
		installedHostFactory.Unlock()
	})
}
func originalSettleWaitSourceRequest() model.CapacityMutationSettleRequest {
	return model.CapacityMutationSettleRequest{GrantID: "11111111-1111-4111-8111-111111111111", AttemptID: "22222222-2222-4222-8222-222222222222", RequestSHA256: strings.Repeat("a", 64), Outcome: "accepted", TransportCompleted: true}
}

func TestHostOriginalFactoryOrdinarySettleWaitBeforeTransactionSource(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, name := range []string{"nonoriginal_no_cache_keeps_normal_Begin", "different_grant_keeps_normal_Begin", "matching_grant_no_installed_realm_HOLD", "matching_foreign_realm_HOLD", "matching_missing_claim_HOLD", "matching_foreign_original_root_HOLD", "matching_issue_uncommitted_HOLD", "matching_issue_uncaptured_HOLD", "matching_issue_return_unknown_HOLD", "matching_issue_return_error_HOLD", "duplicate_original_grant_HOLD", "cache_flags_cannot_bypass_actual_EMPTY_Source_method", "nil_cache_entry_keeps_normal_Begin", "unissued_empty_grant_is_not_match"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			db, boundary := originalSettleWaitSourceDB(t)
			request := originalSettleWaitSourceRequest()
			// Zero Realm is intentionally NOT a genuine Source capability.
			// Synthetic private cache flags may reach only its real refusing
			// method. They cannot create a successful native/source path.
			realm := &capacityhostfactory.OriginalFactoryRealm{}
			approval := model.HostFactorySourceApproval{ScopeRootID: "33333333-3333-4333-8333-333333333333"}
			h := &hostOriginalOrdinaryFactory{realm: realm, claim: &hostOriginalClaim{realm: realm, rootID: approval.ScopeRootID}, grant: model.CapacityMutationGrant{GrantID: request.GrantID}, issueCommitted: true, issueCaptured: true, issueReturnedAt: time.Now().UTC()}
			factories := map[string]*hostOriginalOrdinaryFactory{"actual-private-target-fixture": h}
			wantBegin := false
			actualSourceRefusal := false
			wantAuthorization := false
			switch name {
			case "nonoriginal_no_cache_keeps_normal_Begin":
				realm = nil
				factories = nil
				wantBegin = true
			case "different_grant_keeps_normal_Begin":
				h.grant.GrantID = "44444444-4444-4444-8444-444444444444"
				wantBegin = true
			case "matching_grant_no_installed_realm_HOLD":
				realm = nil
			case "matching_foreign_realm_HOLD":
				h.realm = &capacityhostfactory.OriginalFactoryRealm{}
			case "matching_missing_claim_HOLD":
				h.claim = nil
			case "matching_foreign_original_root_HOLD":
				h.claim.rootID = "44444444-4444-4444-8444-444444444444"
			case "matching_issue_uncommitted_HOLD":
				h.issueCommitted = false
			case "matching_issue_uncaptured_HOLD":
				h.issueCaptured = false
			case "matching_issue_return_unknown_HOLD":
				h.issueReturnedAt = time.Time{}
			case "matching_issue_return_error_HOLD":
				h.issueReturnErr = errors.New("original helper error retained")
			case "duplicate_original_grant_HOLD":
				second := &hostOriginalOrdinaryFactory{realm: h.realm, claim: h.claim, grant: h.grant, issueCommitted: h.issueCommitted, issueCaptured: h.issueCaptured, issueReturnedAt: h.issueReturnedAt}
				factories["second-private-target-fixture"] = second
			case "cache_flags_cannot_bypass_actual_EMPTY_Source_method":
				actualSourceRefusal = true
			case "nil_cache_entry_keeps_normal_Begin":
				factories = map[string]*hostOriginalOrdinaryFactory{"unknown": nil}
				wantBegin = true
			case "unissued_empty_grant_is_not_match":
				h.grant.GrantID = ""
				request.GrantID = ""
				wantAuthorization = true
			}
			originalSettleWaitSourceCache(t, realm, approval, factories)
			result, err := (CapacityStore{DB: db}).SettleMutation(ctx, "source-only-principal", strings.Repeat("b", 64), request)
			boundary.mu.Lock()
			begins, actualCtx := boundary.begins, boundary.ctx
			boundary.mu.Unlock()
			if result.GrantID != "" {
				t.Fatal("sentinel fixture returned settlement permission")
			}
			if wantBegin {
				if !errors.Is(err, originalSettleWaitSourceBeginRefused) || begins != 1 || actualCtx != ctx {
					t.Fatal("normal settlement entry/context changed", err, begins)
				}
			} else if wantAuthorization {
				if err != ErrCapacityMutationAuthorization || begins != 0 {
					t.Fatal("empty unissued grant changed callback validation", err, begins)
				}
			} else {
				if !errors.Is(err, ErrHostFactoryHold) || begins != 0 {
					t.Fatal("original refusal happened after transaction entry", err, begins)
				}
				if actualSourceRefusal == (err == ErrHostFactoryHold) {
					t.Fatal("actual Source refusal and private selection refusal were confused")
				}
			}
		})
	}
}

func TestHostOriginalFactoryOrdinarySettleInitialValidationSource(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	for _, name := range []string{"nonce_short", "transport_incomplete", "invalid_attempt", "invalid_request_digest", "invalid_error_code", "unknown_outcome"} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			db, boundary := originalSettleWaitSourceDB(t)
			request := originalSettleWaitSourceRequest()
			nonce := strings.Repeat("b", 64)
			realm := &capacityhostfactory.OriginalFactoryRealm{}
			approval := model.HostFactorySourceApproval{ScopeRootID: "33333333-3333-4333-8333-333333333333"}
			h := &hostOriginalOrdinaryFactory{realm: realm, claim: &hostOriginalClaim{realm: realm, rootID: approval.ScopeRootID}, grant: model.CapacityMutationGrant{GrantID: request.GrantID}, issueCommitted: true, issueCaptured: true, issueReturnedAt: time.Now().UTC()}
			originalSettleWaitSourceCache(t, realm, approval, map[string]*hostOriginalOrdinaryFactory{"private-target": h})
			switch name {
			case "nonce_short":
				nonce = "short"
			case "transport_incomplete":
				request.TransportCompleted = false
			case "invalid_attempt":
				request.AttemptID = "caller-label"
			case "invalid_request_digest":
				request.RequestSHA256 = "caller-label"
			case "invalid_error_code":
				request.ProviderErrorCode = "unsafe error text"
			case "unknown_outcome":
				request.Outcome = "caller-success"
			}
			_, err := (CapacityStore{DB: db}).SettleMutation(ctx, "source-only-principal", nonce, request)
			boundary.mu.Lock()
			begins := boundary.begins
			boundary.mu.Unlock()
			if err != ErrCapacityMutationAuthorization || begins != 0 {
				t.Fatal("initial validation was moved after wait/transaction", err, begins)
			}
		})
	}
}

// Source-only partition regression. The Realm parser provides a structurally
// complete expected census here; these synthetic signatures have NO authority.
// The production caller obtains that map only from authenticated SQL custody.
// Written for owning remote CI, never executed on the owner's machine.
func finalMainRealmAuditPartitionSourceFixture(t *testing.T) (map[string]hostOriginalSourceAuditProjection, map[string]hostOriginalSourceAuditProjection, map[string]hostOriginalMainReturn) {
	t.Helper()
	custody := finalAuditSourceFixture(t)
	_, expected, err := parseOriginalHostFinalSourceAuditCustody(finalAuditSourceWire(t, custody))
	if err != nil {
		t.Fatal(err)
	}
	actual := map[string]hostOriginalSourceAuditProjection{}
	for id, row := range expected {
		actual[id] = row
	}
	main := map[string]hostOriginalMainReturn{
		"public_caller_return": {Operation: "public_caller_return", OriginalCalledAt: postStartSourceFixturePtr(postStartSourceFixtureTime(30)), OriginalReturnedAt: postStartSourceFixturePtr(postStartSourceFixtureTime(60)), OriginalOperationDeadline: postStartSourceFixtureTime(100)},
		"main_cleanup_return":  {Operation: "main_cleanup_return", OriginalCalledAt: postStartSourceFixturePtr(postStartSourceFixtureTime(65)), OriginalReturnedAt: postStartSourceFixturePtr(postStartSourceFixtureTime(95)), OriginalOperationDeadline: postStartSourceFixtureTime(100), SourceAuditCallReferences: []string{}},
	}
	cleanup := main["main_cleanup_return"]
	for n := 0; n < 7; n++ {
		called := float64(10 + n)
		if n >= 3 {
			called = float64(40 + n)
		}
		selection, rows := postStartSourceFixtureStream(hostOriginalPostStartLedgerCustody{FactoryRootID: custody.FactoryRootID}, 1000+n, 6, "host_exterior", "closed_file", nil, []string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_read", "source_file_close"}, called, 32)
		cleanup.SourceAuditCallReferences = append(cleanup.SourceAuditCallReferences, selection.OriginalCallReferences...)
		for _, row := range rows {
			actual[*row.Fact.OriginalCallID] = row
		}
	}
	main["main_cleanup_return"] = cleanup
	return expected, actual, main
}

func TestHostOriginalFinalMainAndRealmSourceAuditPartition(t *testing.T) {
	hostFactorySourceCaseStatus(t)
	t.Run("lawful_complete_disjoint_union", func(t *testing.T) {
		hostFactorySourceCaseStatus(t)
		expected, actual, main := finalMainRealmAuditPartitionSourceFixture(t)
		if compareOriginalHostFinalAuditMap(expected, actual) == nil {
			t.Fatal("fixture no longer exercises the original seven-stream mismatch")
		}
		if compareOriginalHostFinalSourceAuditPartition(expected, actual, main) != nil {
			t.Fatal("complete independent Main7 plus Realm census refused")
		}
		if len(expected) != 6 || len(actual) != 41 || len(main["main_cleanup_return"].SourceAuditCallReferences) != 35 {
			t.Fatal("combined stream census drift")
		}
	})
	firstMain := postStartSourceFixtureID(1000)
	firstRealm := postStartSourceFixtureID(520)
	changeMain := func(actual map[string]hostOriginalSourceAuditProjection, ordinal int, change func(*hostOriginalSourceAuditProjection)) {
		id := firstMain + ":" + strconv.Itoa(ordinal)
		row := actual[id]
		change(&row)
		actual[id] = row
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]hostOriginalSourceAuditProjection, map[string]hostOriginalSourceAuditProjection, map[string]hostOriginalMainReturn)
	}{
		{"missing_main_reference", func(_, a map[string]hostOriginalSourceAuditProjection, m map[string]hostOriginalMainReturn) {
			r := m["main_cleanup_return"]
			r.SourceAuditCallReferences = r.SourceAuditCallReferences[1:]
			m["main_cleanup_return"] = r
		}},
		{"missing_entire_main_stream", func(_, a map[string]hostOriginalSourceAuditProjection, m map[string]hostOriginalMainReturn) {
			r := m["main_cleanup_return"]
			r.SourceAuditCallReferences = r.SourceAuditCallReferences[5:]
			m["main_cleanup_return"] = r
			for n := 1; n <= 5; n++ {
				delete(a, firstMain+":"+strconv.Itoa(n))
			}
		}},
		{"unreferenced_main_fact", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			row := a[firstMain+":5"]
			row.Fact.OriginalCallID = postStartSourceFixturePtr(firstMain + ":6")
			a[firstMain+":6"] = row
		}},
		{"unregistered_extra_stream", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			_, rows := postStartSourceFixtureStream(hostOriginalPostStartLedgerCustody{FactoryRootID: a[firstMain+":1"].Fact.FactoryRootID}, 1010, 6, "host_exterior", "closed_file", nil, []string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_read", "source_file_close"}, 20, 32)
			for _, row := range rows {
				a[*row.Fact.OriginalCallID] = row
			}
		}},
		{"realm_fact_selected_as_main", func(_, _ map[string]hostOriginalSourceAuditProjection, m map[string]hostOriginalMainReturn) {
			r := m["main_cleanup_return"]
			r.SourceAuditCallReferences = append(r.SourceAuditCallReferences, firstRealm+":1")
			m["main_cleanup_return"] = r
		}},
		{"main_handle_reuses_realm_handle", func(e, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			e[firstMain+":1"] = a[firstMain+":1"]
		}},
		{"missing_realm_fact", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			delete(a, firstRealm+":1")
		}},
		{"replaced_realm_fact", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			row := a[firstRealm+":1"]
			row.Fact.OriginalReturnedAt = postStartSourceFixturePtr(postStartSourceFixtureTime(72))
			a[firstRealm+":1"] = row
		}},
		{"duplicate_main_reference", func(_, _ map[string]hostOriginalSourceAuditProjection, m map[string]hostOriginalMainReturn) {
			r := m["main_cleanup_return"]
			r.SourceAuditCallReferences = append(r.SourceAuditCallReferences, firstMain+":1")
			m["main_cleanup_return"] = r
		}},
		{"wrong_main_subject", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 1, func(r *hostOriginalSourceAuditProjection) { r.SubjectIdentity.SubjectKind = "main_db" })
		}},
		{"main_missing_eof", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 4, func(r *hostOriginalSourceAuditProjection) {
				r.Fact.OriginalEOF = postStartSourceFixturePtr(false)
				r.Fact.OriginalErrorPresent = postStartSourceFixturePtr(false)
				r.Fact.OriginalCount = postStartSourceFixturePtr(int64(1))
			})
		}},
		{"main_error_after_positive_read", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 3, func(r *hostOriginalSourceAuditProjection) {
				r.Fact.OriginalErrorPresent = postStartSourceFixturePtr(true)
			})
		}},
		{"main_close_error", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 5, func(r *hostOriginalSourceAuditProjection) {
				r.Fact.OriginalErrorPresent = postStartSourceFixturePtr(true)
			})
		}},
		{"private_hash_leak", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 3, func(r *hostOriginalSourceAuditProjection) {
				r.Fact.OriginalSHA256 = postStartSourceFixturePtr(postStartSourceFixtureSHA("PRIVATE-MAIN-INPUT"))
			})
		}},
		{"second_main_fstat", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 4, func(r *hostOriginalSourceAuditProjection) {
				r.Fact.Operation = "source_file_fstat"
				r.Fact.OriginalCount = nil
				r.Fact.OriginalEOF = nil
				r.Fact.OriginalErrorPresent = postStartSourceFixturePtr(false)
				r.Fact.OriginalHashState = "not_byte_operation"
			})
		}},
		{"main_read_after_eof", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 3, func(r *hostOriginalSourceAuditProjection) {
				r.Fact.OriginalEOF = postStartSourceFixturePtr(true)
				r.Fact.OriginalErrorPresent = postStartSourceFixturePtr(true)
			})
		}},
		{"forged_main_close_reference", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 3, func(r *hostOriginalSourceAuditProjection) {
				r.OriginalCloseReference = postStartSourceFixturePtr(firstRealm + ":3")
			})
		}},
		{"main_stream_crosses_caller_start", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 5, func(r *hostOriginalSourceAuditProjection) {
				r.Fact.OriginalCalledAt = postStartSourceFixturePtr(postStartSourceFixtureTime(31))
				r.Fact.OriginalReturnedAt = postStartSourceFixturePtr(postStartSourceFixtureTime(31.1))
			})
		}},
		{"main_stream_after_caller_return", func(_, a map[string]hostOriginalSourceAuditProjection, m map[string]hostOriginalMainReturn) {
			r := m["public_caller_return"]
			r.OriginalReturnedAt = postStartSourceFixturePtr(postStartSourceFixtureTime(42))
			m["public_caller_return"] = r
		}},
		{"wrong_main_three_plus_four_census", func(_, a map[string]hostOriginalSourceAuditProjection, m map[string]hostOriginalMainReturn) {
			r := m["public_caller_return"]
			r.OriginalCalledAt = postStartSourceFixturePtr(postStartSourceFixtureTime(11))
			m["public_caller_return"] = r
		}},
		{"main_return_at_own_deadline", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 5, func(r *hostOriginalSourceAuditProjection) {
				r.Fact.OriginalReturnedAt = postStartSourceFixturePtr(r.Fact.OriginalOperationDeadline)
			})
		}},
		{"main_deadline_renewed", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 3, func(r *hostOriginalSourceAuditProjection) {
				r.Fact.OriginalOperationDeadline = postStartSourceFixtureTime(101)
			})
		}},
		{"zero_main_input", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 3, func(r *hostOriginalSourceAuditProjection) { r.Fact.OriginalCount = postStartSourceFixturePtr(int64(0)) })
		}},
		{"noncanonical_main_ordinal", func(_, a map[string]hostOriginalSourceAuditProjection, _ map[string]hostOriginalMainReturn) {
			changeMain(a, 3, func(r *hostOriginalSourceAuditProjection) {
				r.Fact.OriginalCallID = postStartSourceFixturePtr(firstMain + ":03")
			})
		}},
		{"no_main_selection", func(_, _ map[string]hostOriginalSourceAuditProjection, m map[string]hostOriginalMainReturn) {
			r := m["main_cleanup_return"]
			r.SourceAuditCallReferences = nil
			m["main_cleanup_return"] = r
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			hostFactorySourceCaseStatus(t)
			expected, actual, main := finalMainRealmAuditPartitionSourceFixture(t)
			test.mutate(expected, actual, main)
			if compareOriginalHostFinalSourceAuditPartition(expected, actual, main) == nil {
				t.Fatal("incomplete, overlapping or altered Main/Realm partition accepted")
			}
		})
	}
}
