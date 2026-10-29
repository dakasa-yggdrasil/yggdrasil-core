//go:build linux && nativequalification

package repository

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Unit data only: not a signed original, physical read or qualification. The
// runtime reader also verifies the ed25519 signature, row locks and the DB.
func canonicalStoredReadFixture(t *testing.T) (CanonicalSourceAbsenceRead, []byte, string, capacityMutationRecord, CanonicalSourceEligibility, string, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	childID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	parentID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	attempt := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	actionID := "canonical-original-cleanup:" + childID + ":" + attempt
	child := capacityMutationRecord{Grant: model.CapacityMutationGrant{GrantID: childID, CompensationOf: parentID, Slot: 2, State: "redeemed", RequestSHA256: strings.Repeat("e", 64), ExpectedResourceID: parentID, ExpectedResourceCreatedAt: now.Add(-time.Minute).Format(time.RFC3339Nano)}, Binding: model.CapacityMutationBinding{Name: "guest"}, AttemptID: attempt}
	e := CanonicalSourceEligibility{EligibilityWireSHA256: strings.Repeat("f", 64), ParentGrantID: parentID}
	returned := now.Add(-3 * time.Second)
	proof := model.CapacityMutationProof{GrantID: childID, BindingName: "guest", Slot: 2, ResourceID: parentID, ResourceCreatedAt: child.Grant.ExpectedResourceCreatedAt, RequestSHA256: child.Grant.RequestSHA256, ObservedAt: returned, ReceiptRef: "canonical-child-owned-cleanup:" + actionID, OwnerVerified: true, SpecVerified: true, ResourceAbsent: true, ActionIDs: []string{actionID}, ActionsTerminal: true, ActionsSuccessful: true, CompensationIdentityVerified: true, ObservedCreationGrantID: parentID}
	observed := CanonicalSourceAbsenceRead{Schema: "canonical_source_compensation_absence_v2", Scope: "ORIGINAL_CHILD_OWNED_KILL_UNLINK_AND_FRESH_ABSENCE", ChildGrantID: childID, ParentGrantID: parentID, RequestSHA256: child.Grant.RequestSHA256, EligibilitySHA256: e.EligibilityWireSHA256, ActionID: actionID, Read: SourceFailureCleanupCurrentRead{PIDFDOpenError: "ESRCH", DiskAbsence: "ENOENT", ReturnedAt: returned}, Proof: proof}
	wire := []byte(`{"body":"unit-only","signature":"unit-only"}`)
	return observed, wire, capacity.BusinessCreationSHA256(wire), child, e, actionID, now
}

func TestCanonicalSourceStoredReadValidAcceptsTheObservedRead(t *testing.T) {
	observed, wire, sha, child, e, actionID, now := canonicalStoredReadFixture(t)
	if !canonicalSourceStoredReadValid(observed, wire, sha, child, e, actionID, 30, now) {
		t.Fatal("the stored absence read built by Observe was refused")
	}
	if !canonicalSourceStoredProofBound(observed, child, e, actionID) {
		t.Fatal("the stored proof built by Observe was refused")
	}
	// The stored proof survives its JSON round trip exactly, which is what
	// Settle now returns and Confirm compares with reflect.DeepEqual.
	raw, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CanonicalSourceAbsenceRead
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if !canonicalSourceStoredReadValid(decoded, wire, sha, child, e, actionID, 30, now) || !canonicalSourceStoredProofBound(decoded, child, e, actionID) {
		t.Fatal("decoded stored read was refused")
	}
}

func TestCanonicalSourceStoredReadValidRefusesForeignOrStaleRead(t *testing.T) {
	for _, name := range []string{"digest", "schema", "scope", "eligibility", "request", "child", "parent", "action", "production", "pidfd_alive", "disk_present", "stale", "future", "zero_time"} {
		observed, wire, sha, child, e, actionID, now := canonicalStoredReadFixture(t)
		maxAge := 30
		switch name {
		case "digest":
			sha = strings.Repeat("0", 64)
		case "schema":
			observed.Schema = "canonical_source_compensation_absence_v1"
		case "scope":
			observed.Scope = "SOURCE_ONLY_CHILD_OWNED_ORIGINAL_KILL_UNLINK_NOT_POSITIVE_QUIESCENCE"
		case "eligibility":
			observed.EligibilitySHA256 = strings.Repeat("1", 64)
		case "request":
			observed.RequestSHA256 = strings.Repeat("2", 64)
		case "child":
			observed.ChildGrantID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		case "parent":
			observed.ParentGrantID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		case "action":
			observed.ActionID = "canonical-original-cleanup:foreign"
		case "production":
			observed.ProductionQualified = true
		case "pidfd_alive":
			observed.Read.PIDFDOpenError = ""
		case "disk_present":
			observed.Read.DiskAbsence = ""
		case "stale":
			observed.Read.ReturnedAt = now.Add(-31 * time.Second)
		case "future":
			observed.Read.ReturnedAt = now.Add(6 * time.Second)
		case "zero_time":
			observed.Read.ReturnedAt = time.Time{}
		}
		if canonicalSourceStoredReadValid(observed, wire, sha, child, e, actionID, maxAge, now) {
			t.Fatalf("stored absence read accepted with %s", name)
		}
	}
}

func TestCanonicalSourceStoredProofBoundRefusesForeignProof(t *testing.T) {
	for _, name := range []string{"grant", "binding", "slot", "resource", "created", "request", "observed_at", "receipt", "owner", "spec", "present", "no_action", "extra_action", "foreign_action", "not_terminal", "not_successful", "identity", "creation_grant", "aws_retirement", "provider_identity", "aws_instance", "history_complete", "actions_failed", "auxiliary"} {
		observed, _, _, child, e, actionID, _ := canonicalStoredReadFixture(t)
		p := &observed.Proof
		switch name {
		case "grant":
			p.GrantID = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
		case "binding":
			p.BindingName = "foreign"
		case "slot":
			p.Slot = 1
		case "resource":
			p.ResourceID = "foreign"
		case "created":
			p.ResourceCreatedAt = ""
		case "request":
			p.RequestSHA256 = strings.Repeat("3", 64)
		case "observed_at":
			p.ObservedAt = p.ObservedAt.Add(time.Nanosecond)
		case "receipt":
			p.ReceiptRef = "foreign"
		case "owner":
			p.OwnerVerified = false
		case "spec":
			p.SpecVerified = false
		case "present":
			p.ResourceAbsent = false
		case "no_action":
			p.ActionIDs = nil
		case "extra_action":
			p.ActionIDs = append(p.ActionIDs, "extra")
		case "foreign_action":
			p.ActionIDs = []string{"canonical-original-cleanup:foreign"}
		case "not_terminal":
			p.ActionsTerminal = false
		case "not_successful":
			p.ActionsSuccessful = false
		case "identity":
			p.CompensationIdentityVerified = false
		case "creation_grant":
			p.ObservedCreationGrantID = ""
		case "aws_retirement":
			p.AWSRetirementLifecycle = &model.CapacityAWSRetirementLifecycle{}
		case "provider_identity":
			p.ProviderNativeIdentity = &model.CapacityGuestProviderNativeIdentity{}
		case "aws_instance":
			p.AWSInstanceLifecycle = &model.CapacityAWSInstanceLifecycle{}
		case "history_complete":
			p.ActionHistoryComplete = true
		case "actions_failed":
			p.ActionsFailed = true
		case "auxiliary":
			p.AuxiliaryAbsent = []model.CapacityMutationAuxiliaryResource{{}}
		}
		if canonicalSourceStoredProofBound(observed, child, e, actionID) {
			t.Fatalf("stored proof accepted with %s", name)
		}
	}
}

// Unit data only: the original cleanup body shape that Observe's static gate in
// sourceFailureCleanupCurrentRead accepts before it takes its native read.
func canonicalStoredReadBodyFixture(t *testing.T) (SourceFailureCleanupBody, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	nativeCase := "compensation_unprotected_failed_create"
	slot := canonicalSourceExpectedSlot(nativeCase)
	if slot == 0 {
		slot = 2
	}
	b := SourceFailureCleanupBody{NativeCase: nativeCase, Slot: slot, CoreSource: capacity.CurrentGuestCoreSource(), SourceDirectoryDevice: 64769, SourceDirectoryInode: 4242, SourceSlotDirectory: "/var/lib/yggdrasil/guest-provisioning-native-unit/slot-" + strconv.Itoa(slot), OriginalContextDeadline: now.Add(3 * time.Minute)}
	if !sourceCleanupSlotDirectoryMatches(b) {
		t.Fatal("unit body fixture does not match the expected slot directory")
	}
	return b, now
}

func TestCanonicalSourceStoredReadBodyCurrentMatchesObserveGate(t *testing.T) {
	b, now := canonicalStoredReadBodyFixture(t)
	if !canonicalSourceStoredReadBodyCurrent(b, now) {
		t.Fatal("the original cleanup body Observe accepts was refused")
	}
	for _, name := range []string{"core_source", "device", "inode", "slot", "slot_directory", "unclean", "relative", "foreign_parent", "deadline_reached", "deadline_passed", "zero_deadline"} {
		b, now := canonicalStoredReadBodyFixture(t)
		switch name {
		case "core_source":
			b.CoreSource = strings.Repeat("0", 40)
		case "device":
			b.SourceDirectoryDevice = 0
		case "inode":
			b.SourceDirectoryInode = 0
		case "slot":
			b.Slot = 3 - b.Slot
		case "slot_directory":
			b.SourceSlotDirectory = filepath.Join(filepath.Dir(b.SourceSlotDirectory), "slot-9")
		case "unclean":
			b.SourceSlotDirectory = filepath.Dir(b.SourceSlotDirectory) + "/./" + filepath.Base(b.SourceSlotDirectory)
		case "relative":
			b.SourceSlotDirectory = strings.TrimPrefix(b.SourceSlotDirectory, "/")
		case "foreign_parent":
			b.SourceSlotDirectory = filepath.Join("/var/lib/yggdrasil/foreign", filepath.Base(b.SourceSlotDirectory))
		case "deadline_reached":
			now = b.OriginalContextDeadline
		case "deadline_passed":
			now = b.OriginalContextDeadline.Add(time.Nanosecond)
		case "zero_deadline":
			b.OriginalContextDeadline = time.Time{}
		}
		if canonicalSourceStoredReadBodyCurrent(b, now) {
			t.Fatalf("stored-read reader accepted the original cleanup body with %s", name)
		}
	}
}

// The pre-settlement reader must never write: the read row is write-once and
// keyed by child_grant_id, so any second INSERT for the child is a PK failure.
// Confirm must keep using the same stored-read validator.
func TestCanonicalSourceCompensationObservedIsReadOnly(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "capacity_canonical_source_compensation_qualification.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var reader, confirm *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil {
			switch fn.Name.Name {
			case "CanonicalSourceCompensationObserved":
				reader = fn
			case "canonicalSourceConfirmedCleanupTx":
				confirm = fn
			}
		}
	}
	if reader == nil || confirm == nil {
		t.Fatal("stored-read reader or confirm path not found")
	}
	calls := func(fn *ast.FuncDecl) map[string]int {
		out := map[string]int{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				switch f := call.Fun.(type) {
				case *ast.Ident:
					out[f.Name]++
				case *ast.SelectorExpr:
					out[f.Sel.Name]++
				}
			}
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				upper := strings.ToUpper(lit.Value)
				for _, verb := range []string{"INSERT", "UPDATE ", "DELETE", "UPSERT"} {
					if strings.Contains(upper, verb) {
						out["sql:"+verb]++
					}
				}
			}
			return true
		})
		return out
	}
	r := calls(reader)
	for _, forbidden := range []string{"ExecContext", "Exec", "canonicalSign", "sourceFailureCleanupCurrentRead", "ObserveCanonicalSourceCompensation", "sql:INSERT", "sql:UPDATE ", "sql:DELETE", "sql:UPSERT"} {
		if r[forbidden] != 0 {
			t.Fatalf("read-only stored reader uses %s", forbidden)
		}
	}
	for _, required := range []string{"compensationTransaction", "lockNativeMutationSlot", "loadCompensationRecord", "canonicalEligibilityTx", "canonicalOwnedPhysicalTx", "canonicalSourceStoredReadBodyCurrent", "canonicalSignedBody", "canonicalSourceStoredReadValid", "canonicalSourceStoredProofBound"} {
		if r[required] != 1 {
			t.Fatalf("read-only stored reader must call %s exactly once, got %d", required, r[required])
		}
	}
	if calls(confirm)["canonicalSourceStoredReadValid"] != 1 {
		t.Fatal("confirm path no longer shares the stored-read validator")
	}
}
