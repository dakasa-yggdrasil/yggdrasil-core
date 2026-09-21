package metrics

import "testing"

// ADR-0019: the directory audit failure family must be present with a
// bounded label set, every bump must land in exactly one bucket, and
// unknown reasons must be no-ops.

func TestIncDirectoryAuditFailure_CountsByReason(t *testing.T) {
	ResetForTest()
	IncDirectoryAuditFailure(DirectoryAuditFailureInsertFailed)
	IncDirectoryAuditFailure(DirectoryAuditFailureInsertFailed)
	IncDirectoryAuditFailure(DirectoryAuditFailureInsertTimeout)

	snap := DirectoryAuditFailuresSnapshot()
	if snap[DirectoryAuditFailureInsertFailed] != 2 {
		t.Errorf("insert_failed expected 2, got %d", snap[DirectoryAuditFailureInsertFailed])
	}
	if snap[DirectoryAuditFailureInsertTimeout] != 1 {
		t.Errorf("insert_timeout expected 1, got %d", snap[DirectoryAuditFailureInsertTimeout])
	}
	if snap[DirectoryAuditFailureStoreUnconfigured] != 0 {
		t.Errorf("store_unconfigured expected 0 (never bumped), got %d", snap[DirectoryAuditFailureStoreUnconfigured])
	}
}

func TestIncDirectoryAuditFailure_UnknownReasonDropped(t *testing.T) {
	ResetForTest()
	IncDirectoryAuditFailure("nonexistent_reason")
	IncDirectoryAuditFailure("")

	total := uint64(0)
	for _, v := range DirectoryAuditFailuresSnapshot() {
		total += v
	}
	if total != 0 {
		t.Fatalf("unknown reasons must be dropped; got total=%d", total)
	}
}

func TestDirectoryAuditFailuresSnapshot_AllReasonsPresent(t *testing.T) {
	ResetForTest()
	snap := DirectoryAuditFailuresSnapshot()
	for _, reason := range []string{
		DirectoryAuditFailureStoreUnconfigured,
		DirectoryAuditFailureInsertTimeout,
		DirectoryAuditFailureInsertFailed,
	} {
		if _, ok := snap[reason]; !ok {
			t.Errorf("snapshot missing closed-set reason %q (must be zero-padded)", reason)
		}
	}
	if len(snap) != 3 {
		t.Fatalf("snapshot has %d reasons, want exactly 3", len(snap))
	}
}

func TestResetForTest_ClearsDirectoryAuditFailures(t *testing.T) {
	IncDirectoryAuditFailure(DirectoryAuditFailureStoreUnconfigured)
	IncDirectoryAuditFailure(DirectoryAuditFailureInsertTimeout)
	IncDirectoryAuditFailure(DirectoryAuditFailureInsertFailed)

	ResetForTest()
	for reason, v := range DirectoryAuditFailuresSnapshot() {
		if v != 0 {
			t.Errorf("ResetForTest must zero all counters; %s=%d", reason, v)
		}
	}
}
