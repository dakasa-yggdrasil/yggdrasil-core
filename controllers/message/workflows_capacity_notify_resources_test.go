package message

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// These are closed protocol/refusal fixtures, never native pool qualification.
func originalNotifyPoolProtocolFixture() (model.CapacityPolicySpec, OriginalNotifyWindowScope, originalNotifyPoolPrerequisite) {
	now := time.Now().UTC()
	identity := OriginalNotifyNativeIdentity{PodName: "notify-a", PodUID: "00000000-0000-4000-8000-000000000001", ProcessNonce: "00000000-0000-4000-8000-000000000002"}
	resource := model.CapacityNativeNotifyResource{PodName: identity.PodName, Kind: originalNotifyPoolKind, ResourceName: "notify_primary_pg_session", BindingSHA256: strings.Repeat("a", 64), Database: "notify", DatabaseOID: "42", SystemIdentifier: "77", Role: "notify"}
	p := model.CapacityPolicySpec{MaxEvidenceAgeSeconds: 60, NativeNotifyWindowBinding: &model.CapacityNativeNotifyWindowBinding{RequiredResources: []model.CapacityNativeNotifyResource{resource}}}
	scope := OriginalNotifyWindowScope{Deadline: now.Add(time.Minute)}
	roster, _ := json.Marshal([]string{resource.ResourceName})
	value := true
	read := originalNotifyPoolObservation{SchemaVersion: 1, Kind: originalNotifyPoolKind, ResourceName: resource.ResourceName, SelectedRoster: []string{resource.ResourceName}, SelectedCount: 1, RosterSHA256: capacity.BusinessCreationSHA256(roster), BindingSHA256: resource.BindingSHA256, InstanceNonce: strings.Repeat("1", 32), Process: originalNotifyPoolProcess{BootID: "00000000-0000-4000-8000-000000000003", PID: 1, StartTicks: 100, ExecutableSHA256: strings.Repeat("b", 64), ExecutableBytes: 4096}, Session: originalNotifyPoolSession{Database: resource.Database, DatabaseOID: resource.DatabaseOID, SystemIdentifier: resource.SystemIdentifier, Role: resource.Role, BackendPID: 123, BackendStart: now.Add(-3 * time.Second)}, InitializedAt: now.Add(-2 * time.Second), ObservedAt: now.Add(-time.Second), OriginalAcquisitionCalls: 1, OriginalAcquisitionReturned: &value, OriginalPingReturned: &value, IdentityRowsClosed: &value, OriginalIdentityReplySHA256: strings.Repeat("c", 64), CurrentIdentityReplySHA256: strings.Repeat("c", 64), DeclarationStatus: "declared_unverified"}
	// Static values intentionally are not the scope's dynamic lease/actor.
	read.Declarations.CoreLease = "static-unverified-binding"
	read.Declarations.PodUID = "unverified-static-pod"
	read.Declarations.SourceCommit = "unverified-static-source"
	after := read
	record := originalNotifyPoolPrerequisite{Schema: "notify_native_pool_prerequisite_v1", Kind: originalNotifyPoolKind, ResourceName: resource.ResourceName, WindowSHA: strings.Repeat("d", 64), MessageSHA: strings.Repeat("e", 64), Actor: identity, Before: &read, After: &after}
	record.After.ObservedAt = now.Add(-500 * time.Millisecond)
	return p, scope, record
}

func TestOriginalNotifyRetainedPoolProtocol(t *testing.T) {
	t.Run("same_retained_session_static_declarations_are_not_authority", func(t *testing.T) {
		p, scope, record := originalNotifyPoolProtocolFixture()
		if originalNotifyPoolRoster(p, scope, record.WindowSHA, record.MessageSHA, record.Actor, []originalNotifyPoolPrerequisite{record}) != nil {
			t.Fatal("same closed retained session refused")
		}
	})
	for _, missing := range []string{"before", "after", "both"} {
		t.Run("pending_null_"+missing+"_decodes_but_never_proves_completion", func(t *testing.T) {
			p, scope, record := originalNotifyPoolProtocolFixture()
			if missing != "after" {
				record.Before = nil
			}
			if missing != "before" {
				record.After = nil
			}
			raw, err := json.Marshal(record)
			var decoded originalNotifyPoolPrerequisite
			if err != nil || capacity.DecodeBusinessJSON(raw, &decoded) != nil {
				t.Fatal("original producer's pending null resource body cannot reach polling")
			}
			if originalNotifyPoolRoster(p, scope, record.WindowSHA, record.MessageSHA, record.Actor, []originalNotifyPoolPrerequisite{decoded}) == nil {
				t.Fatal("pending null resource body proved completion")
			}
		})
	}
	for _, kind := range []string{"missing", "duplicate", "foreign_actor", "foreign_window", "foreign_message", "replacement_session", "replacement_process", "replacement_keeper", "changed_binding", "changed_declaration", "missing_close_return", "false_ping", "reacquisition", "stale", "reversed_reads", "late", "false_verified_declaration", "extra_selected_resource", "changed_reply", "empty_instance", "invalid_process", "wrong_database"} {
		t.Run(kind, func(t *testing.T) {
			p, scope, record := originalNotifyPoolProtocolFixture()
			records := []originalNotifyPoolPrerequisite{record}
			value := false
			switch kind {
			case "missing":
				records = nil
			case "duplicate":
				records = append(records, record)
			case "foreign_actor":
				records[0].Actor.ProcessNonce = "00000000-0000-4000-8000-000000000004"
			case "foreign_window":
				records[0].WindowSHA = strings.Repeat("f", 64)
			case "foreign_message":
				records[0].MessageSHA = strings.Repeat("f", 64)
			case "replacement_session":
				records[0].After.Session.BackendPID++
			case "replacement_process":
				records[0].After.Process.StartTicks++
			case "replacement_keeper":
				records[0].After.InstanceNonce = strings.Repeat("2", 32)
			case "changed_binding":
				records[0].After.BindingSHA256 = strings.Repeat("f", 64)
			case "changed_declaration":
				records[0].After.Declarations.CoreLease = "changed-static-binding"
			case "missing_close_return":
				records[0].After.IdentityRowsClosed = nil
			case "false_ping":
				records[0].Before.OriginalPingReturned = &value
			case "reacquisition":
				records[0].After.OriginalAcquisitionCalls = 2
			case "stale":
				records[0].Before.ObservedAt = time.Now().Add(-2 * time.Minute)
			case "reversed_reads":
				records[0].After.ObservedAt = records[0].Before.ObservedAt.Add(-time.Second)
			case "late":
				scope.Deadline = time.Now().Add(-time.Second)
			case "false_verified_declaration":
				records[0].After.DeclarationStatus = "verified"
			case "extra_selected_resource":
				records[0].After.SelectedRoster = append(records[0].After.SelectedRoster, "push")
			case "changed_reply":
				records[0].After.CurrentIdentityReplySHA256 = strings.Repeat("f", 64)
			case "empty_instance":
				records[0].After.InstanceNonce = ""
			case "invalid_process":
				records[0].After.Process.StartTicks = 0
			case "wrong_database":
				records[0].After.Session.DatabaseOID = "43"
			}
			if originalNotifyPoolRoster(p, scope, record.WindowSHA, record.MessageSHA, record.Actor, records) == nil {
				t.Fatal("incomplete or foreign resource prerequisite accepted")
			}
		})
	}
	t.Run("unsupported_full_roster_does_not_shrink_to_main_pool", func(t *testing.T) {
		p, scope, record := originalNotifyPoolProtocolFixture()
		p.NativeNotifyWindowBinding.RequiredResources = append(p.NativeNotifyWindowBinding.RequiredResources, model.CapacityNativeNotifyResource{PodName: record.Actor.PodName, Kind: "redis_retained_connection_v1", ResourceName: "redis"})
		if originalNotifyResourcesSupported(p) || originalNotifyPoolRoster(p, scope, record.WindowSHA, record.MessageSHA, record.Actor, []originalNotifyPoolPrerequisite{record}) == nil {
			t.Fatal("one available session replaced an unsupported required resource")
		}
	})
	t.Run("unsupported_pg_resource_refuses_before_possible_start", func(t *testing.T) {
		p, _, _ := originalNotifyPoolProtocolFixture()
		p.NativeNotifyWindowBinding.RequiredResources[0].ResourceName = "another_pg_session"
		if originalNotifyResourcesSupported(p) {
			t.Fatal("resource with no original producer accepted before possible-start")
		}
	})
	t.Run("absent_optional_roster_preserves_legacy", func(t *testing.T) {
		p, scope, record := originalNotifyPoolProtocolFixture()
		p.NativeNotifyWindowBinding.RequiredResources = nil
		if originalNotifyPoolRoster(p, scope, record.WindowSHA, record.MessageSHA, record.Actor, nil) != nil {
			t.Fatal("absent resource prerequisite changed legacy completion")
		}
	})
}
