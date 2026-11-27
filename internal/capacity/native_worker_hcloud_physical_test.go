package capacity

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeHCloudACKBindsRealActionIndependentReadAndCanonicalSystem(t *testing.T) {
	p, a, launch, original, read, out, now := nativeHCloudFixtureACK(t)
	if out.State != "acknowledged" || out.OriginalAcceptance != out.IndependentCurrent || out.IndependentCurrent.AccountID != "" ||
		out.OriginalRequestID != "" || out.IndependentRequestID != "" || out.HCloudWitness == nil || out.HCloudWitness.Acceptance.ActionID != "987654" ||
		!NativeWorkerHCloudWitnessValid(a, out.IndependentCurrent, out.HCloudWitness) || !NativeWorkerHCloudWitnessBindingValid(p, a, out.HCloudWitness) ||
		NativeWorkerObservationValid(a, out, now, 30) != nil {
		t.Fatal("complete provider-specific witness or actual optional IDs were lost")
	}
	var l nativePrivateLaunch
	if json.Unmarshal(launch, &l) != nil {
		t.Fatal("invalid canonical launch fixture")
	}
	f := read.HCloud.Physical
	expected := nativePhysicalBinding{l.Schema, l.Mode, l.SourceCommit, l.PoolID, l.PoolUID, l.Registry, l.PolicyID, l.PolicySHA256, l.ExpectedPoolEpoch,
		l.IntentGeneration, l.FencingToken, l.ReservationID, l.IntentSHA256, a.LaunchSHA256,
		nativePhysicalProvider{"hetzner", f.ResourceID, f.ProviderID, "", "eu-central", "hel1", f.ImageID, f.NativeIPv4, f.NativeNetworkCIDR},
		l.Floor, l.Network, l.Operator, l.Reserve}
	raw, _ := json.Marshal(expected)
	if out.IndependentCurrent.PhysicalBindingSHA256 != nativePrivateSHA(raw) || out.IndependentCurrent.Region != "hel1" ||
		out.IndependentCurrent.PhysicalBindingSHA256 == read.HCloud.EvidenceSHA256 {
		t.Fatal("market location replaced System network_zone or a claimed digest was used")
	}
	expected.Provider.Region = "hel1"
	wrong, _ := json.Marshal(expected)
	if nativePrivateSHA(wrong) == out.IndependentCurrent.PhysicalBindingSHA256 {
		t.Fatal("distinct provider region conventions were collapsed")
	}
	// Observation is an internal Go custody callback, not a public wire DTO.
	// The public birth embeds only this typed safe witness and physical facts.
	public, err := json.Marshal(out.HCloudWitness)
	if err != nil || bytes.Contains(public, []byte("CI-only-private-original-password")) || bytes.Contains(public, []byte(nativePrivateSHA(original.Wire))) ||
		bytes.Contains(public, []byte(nativeHCloudOriginalSchema)) || bytes.Contains(public, []byte("root_password")) {
		t.Fatal("private original bytes, digest or secret escaped into a public witness")
	}
	// These are actual mock response headers, not action-ID substitutions.
	var envelope nativeHCloudOriginal
	if json.Unmarshal(original.Wire, &envelope) != nil {
		t.Fatal("bad original fixture")
	}
	envelope.RequestID, envelope.RequestIDObserved = "original.actual:header", true
	original.Wire, _ = json.Marshal(envelope)
	last := len(read.HCloud.Reads) - 1
	read.HCloud.Reads[last].RequestID, read.HCloud.Reads[last].RequestIDObserved = "independent.actual:header", true
	sealNativeHCloudFixture(read.HCloud)
	withIDs, err := PureNativePhysicalQualify(a, launch, original, read, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now)
	if err != nil || withIDs.OriginalRequestID != envelope.RequestID || withIDs.IndependentRequestID != "independent.actual:header" {
		t.Fatal("genuine optional request-header facts were replaced", err)
	}
}

func TestNativeHCloudCurrentReadRefusesSubstitutionAndInventedProof(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*model.CapacityNativeWorkerHCloudPhysicalObservation)
	}{
		{"project", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.ProjectScope.DeclaredProjectID = "foreign"
		}},
		{"proofKind", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.ProjectScope.ProofKind = "sts" }},
		{"anchor", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.ProjectScope.AnchorID = "999" }},
		{"anchorOwner", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.ProjectScope.AnchorOwnerLabelValue = "foreign"
		}},
		{"Source", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.SourceCommit = strings.Repeat("f", 40) }},
		{"scope", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.BindingScopeSHA256 = strings.Repeat("f", 64)
		}},
		{"tuple", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.Adapter.Version++ }},
		{"selector", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.Requested.AttemptID = o.Physical.ResourceID
		}},
		{"partial", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.Complete = false }},
		{"account", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.Physical.AccountID = "invented-project-account"
		}},
		{"providerID", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.Physical.ProviderID = "hetzner://" + o.Physical.ResourceID
		}},
		{"retained", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.Physical.ResourceID = "174243510"
			o.Physical.ProviderID = "hcloud://174243510"
		}},
		{"nativeBroadNetwork", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.Physical.NativeNetworkCIDR = "10.90.0.0/16"
		}},
		{"nativeMAC", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.Physical.MACAddress = "02:00:00:00:00:09"
		}},
		{"networkZone", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.Physical.NetworkZone = "hel1" }},
		{"location", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.Physical.Region = "eu-central" }},
		{"labelUpper", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.ActualLabels.LaunchSHA256Base32 = strings.ToUpper(o.ActualLabels.LaunchSHA256Base32)
		}},
		{"labelPadding", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.ActualLabels.LaunchSHA256Base32 += "=" }},
		{"labelHex", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.ActualLabels.LaunchSHA256Base32 = o.ActualLaunchSHA256
		}},
		{"pool", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.ActualLabels.PoolUID = o.ActualLabels.AttemptID
		}},
		{"fakeHeader", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.Reads[0].RequestID = "action:987654" }},
		{"missingHeader", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.Reads[0].RequestIDObserved = true }},
		{"incompleteBracket", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.Reads = o.Reads[:len(o.Reads)-1] }},
		{"inventedProjectGET", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.Reads[0].Operation = "GET /projects/{id}"
		}},
		{"read403", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.Reads[0].HTTPStatus = 403 }},
		{"staleRead", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.Reads[0].ObservedAt = o.StartedAt.Add(-1)
		}},
		{"reorderedBracket", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.Reads[0], o.Reads[1] = o.Reads[1], o.Reads[0]
		}},
		{"foreignIP", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.PrimaryIPs[0].AssigneeID = "999" }},
		{"duplicateIP", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.PrimaryIPs = append(o.PrimaryIPs, o.PrimaryIPs[0])
		}},
		{"privateTransport", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.TransportEndpointIPv4 = o.Physical.NativeIPv4
		}},
		{"missingIPJoin", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.PrimaryIPs[0].IP = "203.0.113.9" }},
		{"firewall", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.FirewallIDs = append(o.FirewallIDs, o.FirewallIDs[0])
		}},
		{"encryptionClaim", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) {
			o.RootStorage.ProviderEncryptionProven = true
		}},
		{"mutation", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.MutationAuthorized = true }},
		{"NodeReady", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.NodeReadyQualified = true }},
		{"useful", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.UsefulCapacityQualified = true }},
		{"absence", func(o *model.CapacityNativeWorkerHCloudPhysicalObservation) { o.AbsenceProven = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, a, launch, original, read, now := nativeHCloudPhysicalFixture(t)
			tc.change(read.HCloud)
			sealNativeHCloudFixture(read.HCloud)
			if _, err := PureNativePhysicalQualify(a, launch, original, read, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now); err == nil {
				t.Fatal("substituted or fabricated HCloud proof accepted")
			}
		})
	}
}

func TestNativeHCloudQualifiesOnlyAfterOriginalCustodyAndCanonicalLaunch(t *testing.T) {
	for _, fault := range []string{"partial", "captureError", "HTTP202", "badAction", "wrongResource", "duplicate", "alias", "unicodeServerAlias", "unicodeStatusAlias", "trailing", "requestNotObserved", "badLaunch", "wrongProvider"} {
		t.Run(fault, func(t *testing.T) {
			p, a, launch, original, read, _ := nativeHCloudPhysicalFixture(t)
			var wire nativeHCloudOriginal
			if json.Unmarshal(original.Wire, &wire) != nil {
				t.Fatal("bad fixture")
			}
			switch fault {
			case "partial":
				original.CaptureComplete = false
			case "captureError":
				original.ErrorClass = "ORIGINAL_TRANSPORT_UNCERTAIN"
			case "HTTP202":
				wire.HTTPStatus = 202
			case "badAction":
				wire.Body = bytes.Replace(wire.Body, []byte("create_server"), []byte("delete_server"), 1)
			case "wrongResource":
				wire.Body = bytes.Replace(wire.Body, []byte(`"id":43210`), []byte(`"id":43211`), 1)
			case "duplicate":
				wire.Body = bytes.Replace(wire.Body, []byte(`"server":`), []byte(`"server":{},"server":`), 1)
			case "alias":
				wire.Body = bytes.Replace(wire.Body, []byte(`"server":`), []byte(`"Server":`), 1)
			case "unicodeServerAlias":
				wire.Body = bytes.Replace(wire.Body, []byte(`"server":`), []byte(`"ſerver":{},"server":`), 1)
			case "unicodeStatusAlias":
				wire.Body = bytes.Replace(wire.Body, []byte(`"status":"running"`), []byte(`"status":"running","ſtatus":"success"`), 1)
			case "trailing":
				wire.Body = append(wire.Body, []byte(" {}")...)
			case "requestNotObserved":
				wire.RequestID = "made-up:header"
			case "badLaunch":
				launch = append(append([]byte{}, launch...), '\n')
			case "wrongProvider":
				a.Provider = "hcloud"
			}
			original.Wire, _ = json.Marshal(wire)
			calls := 0
			q, err := NewNativeWorkerACKQualifier(p, func(context.Context, model.CapacityNativeWorkerPhysicalReadBinding, model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
				calls++
				return read, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err = q.QualifyACK(t.Context(), a, launch, original); err == nil || calls != 0 {
				t.Fatal("unqualified original/launch reached a read or became an ACK", fault, err, calls)
			}
		})
	}
}

func TestNativeHCloudReobservePreservesEverySealedStateAndOriginalWitness(t *testing.T) {
	for _, state := range []string{"acknowledged", "registered", "admitted", "draining", "aborting"} {
		t.Run(state, func(t *testing.T) {
			p, a, launch, original, read, ack, _ := nativeHCloudFixtureACK(t)
			a.State, a.Physical, a.BirthSHA256 = state, &ack.IndependentCurrent, strings.Repeat("e", 64)
			a.HCloudWitness = CloneNativeWorkerHCloudWitness(ack.HCloudWitness)
			before, _ := json.Marshal(a)
			calls := 0
			q, err := NewNativeWorkerACKQualifier(p, func(context.Context, model.CapacityNativeWorkerPhysicalReadBinding, model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
				calls++
				return read, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			current, err := q.ReobserveACK(t.Context(), a, launch, original)
			after, _ := json.Marshal(a)
			if err != nil || calls != 1 || current != *a.Physical || !bytes.Equal(before, after) {
				t.Fatal("fresh read changed state/birth, invented original IDs or lost physical identity", err)
			}
			if _, err = q.QualifyACK(t.Context(), a, launch, original); err == nil || calls != 1 {
				t.Fatal("a sealed birth accepted another original qualification")
			}
		})
	}
}

func TestNativeHCloudReaderPinsAreCopiedAndAWSCarrierCannotShadow(t *testing.T) {
	p, a, launch, original, read, now := nativeHCloudPhysicalFixture(t)
	q, err := NewNativeWorkerACKQualifier(p, func(_ context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, _ model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		if b.HCloudScope.DeclaredProjectID != "ci-reviewed-project" {
			t.Fatal("constructor retained caller-owned scope pointer")
		}
		b.HCloudScope.DeclaredProjectID = "local-callback-change"
		return read, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	p.NativeWorkerLifecycleBinding.PhysicalObservers[0].HCloudScope.DeclaredProjectID = "external-policy-change"
	if _, err = q.QualifyACK(t.Context(), a, launch, original); err != nil {
		t.Fatal("callback changed the qualifier's private pin", err)
	}
	p, a, launch, original, read, now = nativeHCloudPhysicalFixture(t)
	read.Schema = "aws_native_worker_physical_observation_v1"
	if _, err = PureNativePhysicalQualify(a, launch, original, read, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now); err == nil {
		t.Fatal("mixed provider carrier accepted")
	}
	p, _, _, _, read, _ = nativeHCloudPhysicalFixture(t)
	p.NativeWorkerLifecycleBinding.PhysicalObservers[0].HCloudScope = nil
	if _, err = NewNativeWorkerACKQualifier(p, func(context.Context, model.CapacityNativeWorkerPhysicalReadBinding, model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		t.Fatal("missing scope read")
		return read, nil
	}); err == nil {
		t.Fatal("HCloud scope pin was optional")
	}
	_, aws, awsLaunch, awsOriginal, awsRead, awsNow := nativePhysicalFixture(t)
	b := model.CapacityNativeWorkerPhysicalReadBinding{Profile: aws.Profile, Provider: "aws", Region: aws.Region, Adapter: awsRead.Adapter, BindingName: awsRead.BindingName, SourceCommit: awsRead.SourceCommit, ScopeSHA256: awsRead.BindingScopeSHA256, Capability: ObserveNativeWorkerPhysical, HCloudScope: &model.CapacityNativeWorkerHCloudProjectScope{}}
	if _, err = PureNativePhysicalQualify(aws, awsLaunch, awsOriginal, awsRead, b, 30, awsNow); err == nil {
		t.Fatal("HCloud scope leaked into AWS qualification")
	}
}

func TestNativeHCloudAsyncAcceptanceKeepsUnobservedNICAndExactLargeActionID(t *testing.T) {
	p, a, launch, original, read, now := nativeHCloudPhysicalFixture(t)
	var envelope nativeHCloudOriginal
	if json.Unmarshal(original.Wire, &envelope) != nil {
		t.Fatal("bad envelope")
	}
	var body map[string]json.RawMessage
	var server map[string]json.RawMessage
	var action map[string]json.RawMessage
	if json.Unmarshal(envelope.Body, &body) != nil || json.Unmarshal(body["server"], &server) != nil || json.Unmarshal(body["action"], &action) != nil {
		t.Fatal("bad provider fixture")
	}
	delete(server, "private_net")
	action["id"] = json.RawMessage("9007199254740993")
	body["server"], _ = json.Marshal(server)
	body["action"], _ = json.Marshal(action)
	envelope.Body, _ = json.Marshal(body)
	original.Wire, _ = json.Marshal(envelope)
	out, err := PureNativePhysicalQualify(a, launch, original, read, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now)
	if err != nil || out.HCloudWitness.Acceptance.ActionID != "9007199254740993" || out.HCloudWitness.Acceptance.NetworkID != "" ||
		out.HCloudWitness.Acceptance.NativeIPv4 != "" || out.HCloudWitness.Acceptance.MACAddress != "" || out.IndependentCurrent.NativeIPv4 != read.HCloud.Physical.NativeIPv4 {
		t.Fatal("asynchronous original facts were fabricated or exact action ID was rounded", err)
	}
}

func TestNativeHCloudCannotMaterializeProtectedOrOversizedServerIdentity(t *testing.T) {
	for _, id := range []string{"174243510", "1234567890123"} {
		t.Run(id, func(t *testing.T) {
			p, a, launch, original, read, now := nativeHCloudPhysicalFixture(t)
			var envelope nativeHCloudOriginal
			if json.Unmarshal(original.Wire, &envelope) != nil {
				t.Fatal("bad fixture")
			}
			envelope.Body = bytes.ReplaceAll(envelope.Body, []byte("43210"), []byte(id))
			original.Wire, _ = json.Marshal(envelope)
			read.HCloud.Physical.ResourceID = id
			read.HCloud.Physical.ProviderID = "hcloud://" + id
			read.HCloud.Requested.ResourceID = id
			read.HCloud.PrimaryIPs[0].AssigneeID = id
			sealNativeHCloudFixture(read.HCloud)
			if _, err := PureNativePhysicalQualify(a, launch, original, read, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now); err == nil {
				t.Fatal("coherent original/current facts crossed the existing System protected-ID boundary")
			}
		})
	}
	p, a, launch, original, read, now := nativeHCloudPhysicalFixture(t)
	var l nativePrivateLaunch
	if json.Unmarshal(launch, &l) != nil {
		t.Fatal("bad launch")
	}
	oldLabel := nativeHCloudLaunchLabel(a.LaunchSHA256)
	l.Floor.ProviderID = read.HCloud.Physical.ProviderID
	launch, _ = json.Marshal(l)
	a.LaunchSHA256 = nativePrivateSHA(launch)
	read.HCloud.ActualLabels.LaunchSHA256Base32 = nativeHCloudLaunchLabel(a.LaunchSHA256)
	read.HCloud.ActualLaunchSHA256, read.HCloud.Requested.LaunchSHA256 = a.LaunchSHA256, a.LaunchSHA256
	read.HCloud.Physical.LaunchSHA256 = a.LaunchSHA256
	var envelope nativeHCloudOriginal
	if json.Unmarshal(original.Wire, &envelope) != nil {
		t.Fatal("bad original")
	}
	envelope.Body = bytes.ReplaceAll(envelope.Body, []byte(oldLabel), []byte(read.HCloud.ActualLabels.LaunchSHA256Base32))
	original.Wire, _ = json.Marshal(envelope)
	sealNativeHCloudFixture(read.HCloud)
	if _, err := PureNativePhysicalQualify(a, launch, original, read, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now); err == nil {
		t.Fatal("coherent worker identity reused the immutable floor provider ID")
	}
}
