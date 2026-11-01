package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestRollbackRepresentativeAWSPolicy(t *testing.T) {
	raw, err := os.ReadFile("testdata/rollback/aws_policy_public.json")
	if err != nil {
		t.Fatal(err)
	}
	var p model.CapacityPolicySpec
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if err := capacity.ValidatePolicy(p); err != nil {
		t.Fatal(err)
	}
}

// Two actual source revisions share only this isolated full-schema database.
// It does not prove a production rollout, network drain, or provider effects.
func TestFailedOriginalAWSLegacyRollbackCompatibility(t *testing.T) {
	probe := os.Getenv("LEGACY_CORE_ROLLBACK_PROBE")
	if probe == "" {
		if os.Getenv("REQUIRE_LEGACY_CORE_ROLLBACK_PROBE") == "true" {
			t.Fatal("legacy executable required")
		}
		t.Skip("explicit two-source isolated rollback fixture only")
	}
	db := originalDispositionPG(t)
	f := enrolledFailedAWSOriginalPGFixturePrepared(t, db, "", "", func(f *dispositionPGFixture) {
		raw, err := os.ReadFile("testdata/rollback/aws_policy_public.json")
		if err != nil {
			t.Fatal(err)
		}
		var p model.CapacityPolicySpec
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		if err := capacity.ValidatePolicy(p); err != nil {
			t.Fatalf("representative policy: %v", err)
		}
		if len(p.MutationBindings) != 1 || p.GuestRetirementBinding == nil || len(p.GuestRetirementBinding.Members) != 8 || len(p.MutationBindings[0].Slots) != 8 {
			t.Fatal("representative AWS roster changed")
		}
		b := p.MutationBindings[0]
		if b.OriginalProviderSourceCommit != enrolledFailedAWSCreator {
			t.Fatal("creator pin differs")
		}
		slot := b.Slots[0]
		if slot.Slot != 1 || slot.DesiredSpec == nil {
			t.Fatal("slot 1 absent")
		}
		f.record.Binding = b
		f.record.Grant.BindingName, f.record.Grant.IntegrationInstanceID = b.Name, b.IntegrationInstanceID
		f.record.Grant.ScopeChecksum, f.record.Grant.ProfileName = b.ScopeChecksum, b.ProfileName
		f.record.Grant.Capability, f.record.Grant.RequestSHA256 = b.EnsureCapability, slot.DesiredSpecSHA256
		f.pre.BindingName = p.GuestRetirementBinding.Members[0].Name
		f.pre.OriginalCreateRequestSHA256 = slot.DesiredSpecSHA256
		f.pre.ProfileManifestSHA256 = p.GuestRetirementBinding.ProfileManifestSHA256
		f.pre.CoreSourceCommit = p.GuestRetirementBinding.CoreAuthoritySourceCommit
		f.pre.OriginalWorkflowStepID = p.GuestRetirementBinding.ProfileManifest.OriginalProvisioningStepID
		f.pre.OriginalWorkflowStepTimeoutSeconds = p.GuestRetirementBinding.ProfileManifest.OriginalProvisioningBudgetSeconds
		f.binding = *p.GuestRetirementBinding
		if !capacity.GuestOriginalProvisioningDeadlineMatches(f.pre, f.binding.ProfileManifest) {
			t.Fatal("representative preregistration deadline mismatch")
		}
		f.record.Settlement.RequestSHA256 = slot.DesiredSpecSHA256
		f.record.Settlement.OriginalProviderCreateReturn.RequestSHA256 = slot.DesiredSpecSHA256
		f.policy.Spec, err = json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		f.intent.Environment, f.intent.Domain, f.intent.Dimension = p.Environment, p.Domain, p.Dimension
		f.intent.BaselineSnapshot.Profile = b.ProfileName
		f.intent.Assessment.Snapshot.Profile = b.ProfileName
		f.intent.Decision.Profile, f.intent.Decision.Floor, f.intent.Decision.Units = b.ProfileName, p.Floor, p.Floor
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	owner, err := f.store.BeginFailedOriginalDisposition(ctx, f.pre.OriginalCreateGrantID, f.jobID.String(), "collaborator:"+uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.store.CompleteFailedOriginalDisposition(ctx, owner, witnessedUnenrolledAWSObservation(t, owner.Candidate()))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := json.Marshal(f.policy)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, probe, result.GrantID, f.jobID.String())
	cmd.Stdin = bytes.NewReader(policy)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("legacy binary failed: %v: %s", err, out)
	}
	if !bytes.Contains(out, []byte("LEGACY_READ_AND_REOPEN_REFUSAL_PASS")) {
		t.Fatalf("missing legacy evidence: %s", out)
	}
	var state string
	var ack sql.NullTime
	if err = db.QueryRowContext(ctx, `SELECT state,finalization_ack_at FROM capacity_dispatch_jobs WHERE id=$1`, f.jobID).Scan(&state, &ack); err != nil || state != "failed_disposed" || ack.Valid {
		t.Fatal("legacy changed dispatch", state, ack, err)
	}
}
