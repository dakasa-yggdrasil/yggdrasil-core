//go:build linux && nativequalification

package repository_test

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// This is a readonly admission boundary, not an original native producer.
// Source approval is presently EMPTY. Enabling a required corpus never
// converts row counts, test flags or raw hashes into supplier qualification.
func TestHostOriginalFactoryNativeCorpusEmptySourceHold(t *testing.T) {
	if _, err := capacity.ApprovedHostFactorySource(); !errors.Is(err, capacity.ErrHostFactorySourceUnavailable) {
		t.Fatal("actual Source catalog changed; whole native supplier review required", err)
	}
	if os.Getenv("REQUIRE_CAPACITY_HOST_ORIGINAL_NATIVE_CORPUS") == "true" {
		t.Fatal("FULL_CORE_NATIVE_PENDING: actual approved Source tuple and original native corpus supplier unavailable")
	}
}

func TestHostOriginalFactoryNativeCorpusReadonlyAdmission(t *testing.T) {
	if os.Getenv("REQUIRE_CAPACITY_HOST_ORIGINAL_NATIVE_CORPUS") != "true" {
		t.Skip("new Host native corpus remains outside authorized source/PG execution")
	}
	if _, err := capacity.ApprovedHostFactorySource(); err != nil {
		t.Fatal("actual compiled original Source approval unavailable", err)
	}
	deadline, bounded := t.Deadline()
	if !bounded {
		t.Fatal("one bounded historical reader owner required")
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	path := os.Getenv("CAPACITY_HOST_ORIGINAL_FINAL_CORPUS")
	if path == "" || os.Getenv("DB_URL") == "" {
		t.Fatal("genuine final wrapper and SAME original owning PG required")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, 64*1024*1024+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(raw) > 64*1024*1024 {
		t.Fatal("complete bounded original corpus Read/Close required", errors.Join(readErr, closeErr))
	}
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// This process NEVER constructs or installs a Realm. Authenticator is
	// compiled Source/key inventory only, followed by full SQL/graph/owner joins.
	if err = (repository.CapacityStore{DB: db}).VerifyOriginalHostHistoricalCorpus(ctx, raw); err != nil {
		t.Fatal("historical original corpus refused", err)
	}
	wrapper, err := repository.DecodeOriginalHostFinalCorpusForNativeTest(raw)
	if err != nil {
		t.Fatal("closed original wrapper required")
	}
	if wrapper.SourceIdentity.EntryClass != "ordinary_original_create" {
		return
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true, Isolation: sql.LevelRepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT n.original_wire,n.return_sha256,n.original_record=convert_from(n.original_wire,'UTF8')::jsonb FROM public.capacity_guest_qualification_native_source_returns n JOIN public.capacity_factory_original_grant_bindings g ON g.preregistration_id=n.preregistration_id WHERE g.root_id=$1 AND n.native_stage='native_read' LIMIT 2`, wrapper.SourceIdentity.ScopeRootID)
	if err != nil {
		t.Fatal(err)
	}
	var nativeRaw []byte
	var sha string
	var consistent bool
	count := 0
	for rows.Next() {
		count++
		if err = rows.Scan(&nativeRaw, &sha, &consistent); err != nil {
			rows.Close()
			t.Fatal(err)
		}
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil || count != 1 || !consistent || len(nativeRaw) > 65536 || capacity.HostFactoryRawSHA256(nativeRaw) != sha {
		t.Fatal("exact ONE immutable original native_read required", err)
	}
	var read q.IndependentReturn
	if capacity.DecodeGuestLifecycle(nativeRaw, &read) != nil || read.Schema != "core_independent_original_qemu_read_v1" || read.Original.OriginalSourceCommit != wrapper.SourceIdentity.ActualBuildSourceCommit || read.Original.Provider != "native-qemu" || read.Original.OriginalCreateReturnedAt.Before(read.Original.OriginalCreateStartedAt) || read.Original.OriginalReadStartedAt.Before(read.Original.OriginalCreateReturnedAt) || read.Before.PID < 2 || read.Before.PID != read.Original.QEMU.PID || read.Before.PPID != read.Original.QEMU.PPID || read.Before.StartTicks != read.Original.QEMU.StartTicks || read.After.PID != read.Before.PID || read.After.PPID != read.Before.PPID || read.After.StartTicks != read.Before.StartTicks || read.QMPPeerPID != int32(read.Before.PID) || read.StartedAt.Before(read.Original.OriginalReadReturnedAt) || read.ReadReturnedAt.Before(read.StartedAt) || read.CloseReturnedAt.Before(read.ReadReturnedAt) || strings.ToLower(read.UUID.UUID) != read.Original.ResourceID || !read.Status.Running || read.Status.SingleStep || read.Status.Status != "running" || read.OriginalDisk.Device == 0 || read.OriginalDisk.Inode == 0 || read.OriginalDiskFD < 0 || read.OriginalDiskReadReturnedAt.Before(read.StartedAt) || read.OriginalDiskDirectoryCloseReturnedAt.Before(read.OriginalDiskReadReturnedAt) || read.OriginalDiskDirectoryCloseReturnedAt.After(read.ReadReturnedAt) || !capacity.ValidDigest(read.ExecutableSHA256) || !capacity.ValidDigest(read.CommandLineSHA256) || !capacity.ValidDigest(read.Before.StatSHA256) || !capacity.ValidDigest(read.After.StatSHA256) || len(read.IO) < 7 || len(read.IO) > 64 {
		t.Fatal("full actual Core creator/independent native original ABI does not join")
	}
	prior := read.StartedAt
	for _, ioReturn := range read.IO {
		if ioReturn.Bytes < 1 || ioReturn.Bytes > 65536 || !capacity.ValidDigest(ioReturn.SHA256) || ioReturn.Direction != "read" && ioReturn.Direction != "write" || ioReturn.ReturnedAt.Before(prior) || ioReturn.ReturnedAt.After(read.ReadReturnedAt) {
			t.Fatal("actual original QMP IO return missing")
		}
		prior = ioReturn.ReturnedAt
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		t.Fatal("same historical owner deadline exceeded")
	}
	// Readonly historical source acceptance does not close inherited old45,
	// accepted geometry, Native qualification or a production approval tuple.
}
