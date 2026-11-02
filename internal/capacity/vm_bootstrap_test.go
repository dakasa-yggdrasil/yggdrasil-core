package capacity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Protocol fixtures only: signed fixture issuer and represented native facts
// exercise joins, never certify a provider, live guest or physical capacity.
func guestBootstrapProtocolFixture(t *testing.T) (model.CapacityPolicySpec, []model.CapacityVMNodeJoin, []model.CapacityGuestBootstrapResult, time.Time) {
	t.Helper()
	p, b, inv, now := vmObservationFixture()
	b.IntegrationInstanceID, b.IntegrationTypeID = uuid.NewString(), uuid.NewString()
	b.IntegrationChecksum, b.IntegrationTypeChecksum = strings.Repeat("a", 64), strings.Repeat("b", 64)
	p.Owner = "native-owner"
	p.Profiles = []model.CapacityProfile{{Name: b.ProfileName, Provider: "native-fixture"}}
	p.MutationBindings = []model.CapacityMutationBinding{b}
	p.VMNodeMembershipBinding = &model.CapacityVMNodeMembershipBinding{MutationBindingName: b.Name, Adapter: model.CapacityObservationAdapterBinding{IntegrationInstanceID: uuid.NewString(), InstanceChecksum: strings.Repeat("c", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("d", 64)}, Target: model.CapacityNodeMembershipTarget{BindingName: "workers", RealmUID: uuid.NewString(), Owner: p.Owner, ProfileName: b.ProfileName, ProviderIDPrefix: "native://", MaxLeaseAgeSeconds: 30}}
	for i := range b.Slots {
		p.VMNodeMembershipBinding.Target.Slots = append(p.VMNodeMembershipBinding.Target.Slots, model.CapacityNodeSlotBinding{Slot: i + 1, NodeName: "node-" + string(rune('1'+i))})
	}
	g := &model.CapacityGuestBootstrapBinding{Mode: GuestBootstrapSchema, Adapter: model.CapacityObservationAdapterBinding{IntegrationInstanceID: uuid.NewString(), InstanceChecksum: strings.Repeat("e", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("f", 64)}, BaseURL: "https://fixed-native-fixture.example", ReadTokenRef: "secret://fixture/read#value", MaxEvidenceAgeSeconds: 30, EvidenceClass: "native_qemu_qualification"}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var nodes []model.CapacityVMNodeJoin
	var results []model.CapacityGuestBootstrapResult
	for i, slot := range b.Slots {
		if i >= len(inv.Members) {
			continue
		}
		created, resource := inv.Members[i].Server.CreatedAt, inv.Members[i].Server.ID
		e := model.CapacityGuestEnrollmentStatement{Schema: "original_guest_enrollment_v1", SourceClass: g.EvidenceClass, ProvisionerSourceCommit: strings.Repeat("a", 40), OriginalNativeResultSHA256: strings.Repeat("a", 64), BindingName: "guest-" + resource, Tuple: model.CapacityGuestNativeTuple{Provider: "native-fixture", InstanceID: b.IntegrationInstanceID, InstanceChecksum: b.IntegrationChecksum, TypeID: b.IntegrationTypeID, TypeChecksum: b.IntegrationTypeChecksum, ScopeChecksum: b.ScopeChecksum, ProfileChecksum: slot.DesiredSpec.ProfileChecksum, Profile: b.ProfileName, Slot: slot.Slot, ResourceID: resource, CreatedAt: created}, BootID: uuid.NewString(), HostKeySHA256: strings.Repeat("1", 64), CredentialPublicKeySHA256: strings.Repeat("2", 64), ForcedReaderCommandSHA256: strings.Repeat("3", 64), UserDataSHA256: slot.DesiredSpec.BootstrapSHA256, PayloadSHA256: strings.Repeat("4", 64), OwnerBinarySHA256: strings.Repeat("5", 64), ReaderBinarySHA256: strings.Repeat("6", 64), GuestSourceCommit: strings.Repeat("b", 40), IssuedAt: now.Add(-time.Minute)}
		raw, _ := json.Marshal(e)
		g.Members = append(g.Members, model.CapacityGuestMemberBinding{Name: e.BindingName, EnrollmentIssuerKey: base64.StdEncoding.EncodeToString(pub), Enrollment: e, EnrollmentSignature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, raw))})
		nodes = append(nodes, model.CapacityVMNodeJoin{Slot: slot.Slot, ResourceID: resource, ResourceCreatedAt: created, Node: model.CapacityNodeMembershipTuple{BootID: e.BootID}})
		started, waited, prepared := now.Add(-3*time.Second), now.Add(-2*time.Second), now.Add(-time.Second)
		zero := 0
		unit := model.CapacityGuestUnitObservation{InvocationID: strings.Repeat("a", 32), MainPID: 100, ExecMainPID: 100, StartMonotonic: 1000, ActiveState: "activating", SubState: "start", Result: "success"}
		j := model.CapacityGuestJournal{Schema: GuestBootstrapSchema, AdmissionProtocol: "original_guest_bootstrap_prestarter_v1", InvocationNonce: uuid.NewString(), State: "returned", BootID: e.BootID, Tuple: e.Tuple, UserDataSHA256: e.UserDataSHA256, PayloadSHA256: e.PayloadSHA256, OwnerSourceCommit: e.GuestSourceCommit, OwnerBinarySHA256: e.OwnerBinarySHA256, OwnerPID: 101, OwnerStartTicks: 100, ParentAncestry: []int{100, 1}, UnitAtAdmission: unit, PossibleStartAt: now.Add(-4 * time.Second), ChildPID: 102, ChildStartTicks: 200, StartedAt: &started, OriginalWaitReturnedAt: &waited, ExitCode: &zero, FinalRecordPreparedAt: &prepared}
		raw, _ = json.Marshal(j)
		unit.MainPID, unit.ExecMainCode, unit.ExecMainStatus, unit.ExitMonotonic, unit.ActiveState, unit.SubState = 0, 1, 0, 2000, "inactive", "dead"
		o := model.CapacityGuestObservation{Schema: GuestBootstrapSchema, ReaderSourceCommit: e.GuestSourceCommit, ReaderBinarySHA256: e.ReaderBinarySHA256, ReaderPID: 103, ReaderStartTicks: 300, BootID: e.BootID, UserDataSHA256: e.UserDataSHA256, Journal: j, JournalSHA256: BusinessCreationSHA256(raw), Unit: unit, CloudInitStatus: "done", CloudInitFinalFinished: float64(now.Add(-time.Second).Unix()), ObservedAt: now}
		results = append(results, model.CapacityGuestBootstrapResult{BindingName: e.BindingName, EnrollmentSourceClass: e.SourceClass, Observation: o, OriginalPayloadReturnObserved: true, BootstrapCompletedKnown: true})
	}
	p.GuestBootstrapBinding = g
	if err := ValidateGuestBootstrapBinding(p); err != nil {
		t.Fatal("fixed fixture binding invalid", err)
	}
	return p, nodes, results, now
}

func guestProtocolReply(t *testing.T, r model.CapacityGuestBootstrapResult) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"operation": ObserveGuestBootstrap, "capability": ObserveGuestBootstrap, "status": "observed", "output": r, "metadata": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCapacityGuestOriginalClosedWire(t *testing.T) {
	_, _, results, _ := guestBootstrapProtocolFixture(t)
	raw := guestProtocolReply(t, results[0])
	var response model.AdapterExecuteIntegrationResponse
	if DecodeGuestBootstrapReply(raw, &response) != nil {
		t.Fatal("closed original reply refused")
	}
	for _, mode := range []string{"alias", "duplicate", "alias_overwrite", "missing_false", "null_false", "missing_wait", "null_wait", "trailing", "extra", "metadata_null", "metadata_authority", "cap"} {
		t.Run(mode, func(t *testing.T) {
			bad := string(raw)
			switch mode {
			case "alias":
				bad = strings.Replace(bad, `"original_context_failed"`, `"Original_Context_Failed"`, 1)
			case "duplicate":
				bad = strings.Replace(bad, `"original_context_failed":false`, `"original_context_failed":true,"original_context_failed":false`, 1)
			case "alias_overwrite":
				bad = strings.Replace(bad, `"original_context_failed":false`, `"original_context_failed":true,"Original_Context_Failed":false`, 1)
			case "missing_false":
				bad = strings.Replace(bad, `"original_context_failed":false,`, "", 1)
			case "null_false":
				bad = strings.Replace(bad, `"original_context_failed":false`, `"original_context_failed":null`, 1)
			case "missing_wait":
				bad = strings.Replace(bad, `"original_wait_returned_at"`, `"unapproved_wait"`, 1)
			case "null_wait":
				bad = strings.Replace(bad, `"exit_code":0`, `"exit_code":null`, 1)
			case "trailing":
				bad += `{}`
			case "extra":
				bad = strings.Replace(bad, `"output":`, `"healthy":true,"output":`, 1)
			case "metadata_null":
				bad = strings.Replace(bad, `"metadata":{}`, `"metadata":null`, 1)
			case "metadata_authority":
				bad = strings.Replace(bad, `"metadata":{}`, `"metadata":{"healthy":true}`, 1)
			case "cap":
				bad += strings.Repeat(" ", GuestBootstrapLimit)
			}
			if DecodeGuestBootstrapReply([]byte(bad), &response) == nil {
				t.Fatal("unknown native wire accepted", mode)
			}
		})
	}
}

func TestCapacityGuestOriginalRosterJoinsWithoutAuthority(t *testing.T) {
	p, nodes, results, now := guestBootstrapProtocolFixture(t)
	joined, err := JoinGuestBootstrapRoster(p, nodes, results, now)
	if err != nil || len(joined) != 2 || !joined[0].EnclosingBootstrapRead || joined[0].PhysicalCertificate || joined[0].OriginalCallerReturnKnown {
		t.Fatal("scoped join unavailable or authority fabricated", err)
	}
	for _, mode := range []string{"missing", "extra", "duplicate", "empty", "boot", "tuple", "context", "source", "stale", "journal_hash", "unfinished", "enclosing_projection", "warm", "useful", "route", "drain", "quiescence", "release"} {
		t.Run(mode, func(t *testing.T) {
			p, nodes, results, now := guestBootstrapProtocolFixture(t)
			switch mode {
			case "missing":
				results = results[:1]
			case "extra":
				results = append(results, results[0])
			case "duplicate":
				results[1] = results[0]
			case "empty":
				nodes, results = nil, nil
			case "boot":
				nodes[0].Node.BootID = uuid.NewString()
			case "tuple":
				results[0].Observation.Journal.Tuple.ResourceID = "replacement"
			case "context":
				results[0].Observation.Journal.OriginalContextFailed = true
			case "source":
				results[0].Observation.ReaderSourceCommit = strings.Repeat("c", 40)
			case "stale":
				results[0].Observation.ObservedAt = now.Add(-time.Minute)
			case "journal_hash":
				results[0].Observation.JournalSHA256 = strings.Repeat("0", 64)
			case "unfinished":
				results[0].Observation.Journal.OriginalWaitReturnedAt = nil
			case "enclosing_projection":
				results[0].Observation.Unit.MainPID = 100
			case "warm":
				results[0].WarmResourcesKnown = true
			case "useful":
				results[0].UsefulCapacityKnown = true
			case "route":
				results[0].RoutingWithdrawnKnown = true
			case "drain":
				results[0].BusinessDrainKnown = true
			case "quiescence":
				results[0].ProviderMutationQuiescenceKnown = true
			case "release":
				results[0].PhysicalCapacityReleased = true
			}
			if _, err := JoinGuestBootstrapRoster(p, nodes, results, now); err == nil {
				t.Fatal("unknown/partial/authority projection admitted", mode)
			}
		})
	}
	t.Run("pending_enclosing_unit_is_scoped_only", func(t *testing.T) {
		results[0].Observation.Unit.MainPID = 100
		results[0].BootstrapCompletedKnown = false
		joined, err := JoinGuestBootstrapRoster(p, nodes, results, now)
		if err != nil || joined[0].EnclosingBootstrapRead || joined[0].PhysicalCertificate {
			t.Fatal("payload Wait substituted for enclosing completion", err)
		}
	})
}

func TestCapacityGuestOptionalBindingPreserved(t *testing.T) {
	if ValidateGuestBootstrapBinding(model.CapacityPolicySpec{}) != nil || ValidateGuestBootstrapPolicyJSON([]byte(`{"dimension":"ordinary"}`)) != nil {
		t.Fatal("absent Guest changed ordinary validation")
	}
	for _, raw := range []string{`{"Guest_Bootstrap_Binding":null}`, `{"guest_bootstrap_binding":null}`, `{"guest_bootstrap_binding":{}}`, `{"guest_bootstrap_binding":{},"guest_bootstrap_binding":{}}`} {
		if ValidateGuestBootstrapPolicyJSON([]byte(raw)) == nil {
			t.Fatal("malformed optional binding collapsed to absent")
		}
	}
}
