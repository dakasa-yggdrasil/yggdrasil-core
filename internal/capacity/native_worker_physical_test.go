package capacity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func nativePhysicalFixture(t *testing.T) (model.CapacityPolicySpec, model.CapacityNativeWorkerAttempt, []byte, model.CapacityNativeWorkerOriginalReturn, model.CapacityNativeWorkerPhysicalObservation, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	f, a := nativePrivateFactoryFixture(t, strings.Repeat("a", 40))
	defer f.Close()
	launch, e := f.Prepare(a)
	if e != nil {
		t.Fatal(e)
	}
	a.LaunchSHA256 = nativePrivateSHA(launch.PublicJSON)
	a.SourceCommit = strings.Repeat("c", 40)
	a.State = "send_started"
	a.ProviderIDPrefix = "aws:///"
	a.PhysicalSpecSHA256 = strings.Repeat("d", 64)
	a.CreatedAt = now.Add(-5 * time.Second)
	b := model.CapacityNativeWorkerPhysicalReadBinding{Profile: a.Profile, Provider: "aws", Region: a.Region, Adapter: model.CapacityMarketAdapterBinding{ManifestID: uuid.NewString(), Version: 7, Checksum: strings.Repeat("5", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("6", 64)}, BindingName: "ci-independent-read", SourceCommit: strings.Repeat("7", 40), ScopeSHA256: strings.Repeat("8", 64), Capability: ObserveNativeWorkerPhysical}
	p := model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: a.Profile, Provider: a.Provider, Region: a.Region}}, NativeWorkerLifecycleBinding: &model.CapacityNativeWorkerLifecycleBinding{SourceCommit: a.SourceCommit, MaxReadAgeSeconds: 30, Profiles: []model.CapacityNativeWorkerExecutionProfile{a.Execution}, PhysicalObservers: []model.CapacityNativeWorkerPhysicalReadBinding{b}}, MarketBinding: &model.CapacityMarketBinding{Profiles: []model.CapacityMarketProfileBinding{{Profile: a.Profile, Adapter: model.CapacityMarketAdapterBinding{ManifestID: uuid.NewString(), Version: 7, Checksum: strings.Repeat("5", 64), IntegrationTypeID: uuid.NewString(), TypeChecksum: strings.Repeat("6", 64)}}}}}
	created := now.Add(-time.Second)
	facts := model.CapacityNativeWorkerPhysicalFacts{ResourceID: "i-0123456789abcdef0", ProviderID: "aws:///us-east-1a/i-0123456789abcdef0", AccountID: "153828470928", InstanceType: "m7a.large", NetworkID: "vpc-0123456789abcdef0", NativeNetworkCIDR: "10.90.0.0/24", CreatedAt: created, ImageID: "ami-11111111111111111", Region: "us-east-1", Zone: "us-east-1a", NativeIPv4: "10.90.0.8", MACAddress: "02:00:00:00:00:08", PhysicalSpecSHA256: a.PhysicalSpecSHA256, LaunchSHA256: a.LaunchSHA256}
	o := model.CapacityNativeWorkerPhysicalObservation{Schema: "aws_native_worker_physical_observation_v1", SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.BindingName, BindingScopeSHA256: b.ScopeSHA256, Requested: model.CapacityNativeWorkerObservationRequest{BindingName: b.BindingName, AttemptID: a.ID.String(), ResourceID: facts.ResourceID, LaunchSHA256: a.LaunchSHA256}, StartedAt: now.Add(-500 * time.Millisecond), ObservedAt: now.Add(-time.Millisecond), Complete: true, ActualTags: model.CapacityNativeWorkerObservedTags{AttemptID: a.ID.String(), PoolUID: a.PoolUID, LaunchSHA256: a.LaunchSHA256}, ActualClientToken: a.ID.String(), InstanceState: "running", Physical: facts, RootVolume: model.CapacityNativeWorkerObservedVolume{ResourceID: "vol-0123456789abcdef0", DeviceName: "/dev/sda1", AttachedInstanceID: facts.ResourceID, Encrypted: true, KMSKeyARN: "arn:aws:kms:us-east-1:153828470928:key/11111111-1111-4111-8111-111111111111", VolumeType: "gp3", VolumeGiB: 20, IOPS: 3000, Throughput: 125, DeleteOnTermination: true}, PrimaryInterface: model.CapacityNativeWorkerObservedInterface{ResourceID: "eni-0123456789abcdef0", NetworkID: facts.NetworkID, SubnetID: "subnet-0123456789abcdef0", NativeIPv4: facts.NativeIPv4, MACAddress: facts.MACAddress, AttachedInstanceID: facts.ResourceID, AttachmentID: "eni-attach-0123456789abcdef0", DeleteOnTermination: true}}
	for i, op := range []string{"GetCallerIdentity", "DescribeInstances", "DescribeSubnets", "DescribeSecurityGroups", "DescribeVolumes", "DescribeNetworkInterfaces", "DescribeInstances"} {
		o.Reads = append(o.Reads, model.CapacityNativeWorkerObservedRPC{Operation: op, Role: []string{"caller", "before", "network", "security", "root_volume", "primary_interface", "after"}[i], RequestID: fmt.Sprintf("actual-request-%d", i), ObservedAt: now.Add(-100 * time.Millisecond)})
	}
	sealNativePhysicalFixture(&o)
	xml := fmt.Sprintf(`<RunInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>original-request</requestId><reservationId>r-0123456789abcdef0</reservationId><ownerId>%s</ownerId><instancesSet><item><instanceId>%s</instanceId><imageId>%s</imageId><instanceType>%s</instanceType><instanceState><code>0</code><name>pending</name></instanceState><launchTime>%s</launchTime><placement><availabilityZone>%s</availabilityZone></placement><architecture>x86_64</architecture><vpcId>%s</vpcId><subnetId>%s</subnetId><privateIpAddress>%s</privateIpAddress><clientToken>%s</clientToken><rootDeviceType>ebs</rootDeviceType><rootDeviceName>/dev/sda1</rootDeviceName><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>%s</volumeId><deleteOnTermination>true</deleteOnTermination></ebs></item></blockDeviceMapping><networkInterfaceSet><item><networkInterfaceId>%s</networkInterfaceId><vpcId>%s</vpcId><subnetId>%s</subnetId><privateIpAddress>%s</privateIpAddress><macAddress>%s</macAddress><attachment><deviceIndex>0</deviceIndex><deleteOnTermination>true</deleteOnTermination></attachment></item></networkInterfaceSet><tagSet><item><key>yggdrasil.io/native-worker-attempt</key><value>%s</value></item><item><key>dakasa.io/native-worker-pool</key><value>%s</value></item><item><key>yggdrasil.io/native-worker-launch-sha256</key><value>%s</value></item></tagSet></item></instancesSet></RunInstancesResponse>`, facts.AccountID, facts.ResourceID, facts.ImageID, facts.InstanceType, created.Format(time.RFC3339Nano), facts.Zone, facts.NetworkID, o.PrimaryInterface.SubnetID, facts.NativeIPv4, a.ID, o.RootVolume.ResourceID, o.PrimaryInterface.ResourceID, facts.NetworkID, o.PrimaryInterface.SubnetID, facts.NativeIPv4, facts.MACAddress, a.ID, a.PoolUID, a.LaunchSHA256)
	wire, _ := json.Marshal(nativeAWSOriginal{Schema: "aws_native_worker_original_return_v1", AttemptID: a.ID.String(), HTTPStatus: 200, TransportCompleted: true, Body: []byte(xml)})
	return p, a, launch.PublicJSON, model.CapacityNativeWorkerOriginalReturn{Wire: wire, CaptureComplete: true}, o, now
}
func sealNativePhysicalFixture(o *model.CapacityNativeWorkerPhysicalObservation) {
	o.EvidenceSHA256 = ""
	b, _ := json.Marshal(o)
	o.EvidenceSHA256 = nativePrivateSHA(b)
}

func TestNativePhysicalACKJoinsPrivateOriginalActualReadAndCanonicalLaunch(t *testing.T) {
	p, a, launch, original, o, now := nativePhysicalFixture(t)
	b := p.NativeWorkerLifecycleBinding.PhysicalObservers[0]
	out, e := PureNativePhysicalQualify(a, launch, original, o, b, 30, now)
	if e != nil || out.State != "acknowledged" || out.OriginalAcceptance != out.IndependentCurrent || !ValidDigest(out.IndependentCurrent.PhysicalBindingSHA256) || out.OriginalRequestID != "original-request" || out.IndependentRequestID != "actual-request-6" {
		t.Fatal("real complete ACK/read identity was refused", e)
	}
	public, e := json.Marshal(out)
	if e != nil || strings.Contains(string(public), out.OriginalReturnSHA256) || strings.Contains(string(public), "RunInstancesResponse") || strings.Contains(string(public), "aws_native_worker_original_return_v1") {
		t.Fatal("raw original or private raw digest entered public observation")
	}
	// Binding hashing must use the System declaration order, not a generic
	// alphabetically sorted map, nor the producer's safe evidence digest.
	var unordered map[string]any
	var l nativePrivateLaunch
	if json.Unmarshal(launch, &l) != nil {
		t.Fatal("bad stored fixture")
	}
	physical := nativePhysicalBinding{l.Schema, l.Mode, l.SourceCommit, l.PoolID, l.PoolUID, l.Registry, l.PolicyID, l.PolicySHA256, l.ExpectedPoolEpoch, l.IntentGeneration, l.FencingToken, l.ReservationID, l.IntentSHA256, a.LaunchSHA256, nativePhysicalProvider{"aws", o.Physical.ResourceID, o.Physical.ProviderID, o.Physical.AccountID, o.Physical.Region, o.Physical.Zone, o.Physical.ImageID, o.Physical.NativeIPv4, o.Physical.NativeNetworkCIDR}, l.Floor, l.Network, l.Operator, l.Reserve}
	raw, _ := json.Marshal(physical)
	if json.Unmarshal(raw, &unordered) != nil {
		t.Fatal("bad binding fixture")
	}
	sorted, _ := json.Marshal(unordered)
	if out.IndependentCurrent.PhysicalBindingSHA256 != nativePrivateSHA(raw) || nativePrivateSHA(sorted) == nativePrivateSHA(raw) || out.IndependentCurrent.PhysicalBindingSHA256 == o.EvidenceSHA256 {
		t.Fatal("physical digest lost the canonical System ABI")
	}
}

func TestNativePhysicalACKRefusesIndependentSubstitutionAndFalseQualifications(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*model.CapacityNativeWorkerPhysicalObservation)
	}{
		{"nativeIPAsTransport", func(o *model.CapacityNativeWorkerPhysicalObservation) {
			o.TransportEndpointIPv4 = o.Physical.NativeIPv4
		}},
		{"loopbackTransport", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.TransportEndpointIPv4 = "127.0.0.1" }},
		{"IPv6Transport", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.TransportEndpointIPv4 = "2001:db8::1" }},
		{"noncanonicalTransport", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.TransportEndpointIPv4 = "203.0.113.009" }},
		{"actorIdentity", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.Adapter.ManifestID = "wrong" }},
		{"compiledSource", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.SourceCommit = strings.Repeat("f", 40) }},
		{"rawFileScope", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.BindingScopeSHA256 = strings.Repeat("f", 64) }},
		{"wrongRequest", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.Requested.AttemptID = uuid.NewString() }},
		{"future", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.ObservedAt = time.Now().Add(time.Second) }},
		{"stale", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.ObservedAt = time.Now().Add(-time.Hour) }},
		{"partialRead", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.Reads = o.Reads[:6] }},
		{"duplicateRead", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.Reads[6] = o.Reads[1] }},
		{"emptyRequestID", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.Reads[1].RequestID = "" }},
		{"wrongAZsameSuffix", func(o *model.CapacityNativeWorkerPhysicalObservation) {
			o.Physical.ProviderID = "aws:///us-east-1b/" + o.Physical.ResourceID
		}},
		{"wrongAccount", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.Physical.AccountID = "000000000000" }},
		{"wrongCreation", func(o *model.CapacityNativeWorkerPhysicalObservation) {
			o.Physical.CreatedAt = o.Physical.CreatedAt.Add(time.Second)
		}},
		{"wrongNativeCIDR", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.Physical.NativeNetworkCIDR = "10.91.0.0/24" }},
		{"wrongMAC", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.Physical.MACAddress = "02:00:00:00:00:09" }},
		{"foreignVolume", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.RootVolume.AttachedInstanceID = "i-foreign" }},
		{"retainedRoot", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.RootVolume.DeleteOnTermination = false }},
		{"foreignENI", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.PrimaryInterface.SubnetID = "subnet-foreign" }},
		{"wrongTag", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.ActualTags.PoolUID = uuid.NewString() }},
		{"labelAsClientToken", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.ActualClientToken = o.Physical.LaunchSHA256 }},
		{"mutationClaim", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.MutationAuthorized = true }},
		{"usefulClaim", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.UsefulCapacityQualified = true }},
		{"absenceClaim", func(o *model.CapacityNativeWorkerPhysicalObservation) { o.AbsenceProven = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, a, l, r, o, now := nativePhysicalFixture(t)
			tc.change(&o)
			sealNativePhysicalFixture(&o)
			if _, e := PureNativePhysicalQualify(a, l, r, o, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now); e == nil {
				t.Fatal("substituted or invented physical proof was accepted")
			}
		})
	}
}

func TestNativePhysicalQualifierSelectsOnlyProtectedReaderAndNeverCallsOnBadCustody(t *testing.T) {
	p, a, l, r, o, _ := nativePhysicalFixture(t)
	calls := 0
	q, e := NewNativeWorkerACKQualifier(p, func(_ context.Context, b model.CapacityNativeWorkerPhysicalReadBinding, req model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		calls++
		if b != p.NativeWorkerLifecycleBinding.PhysicalObservers[0] || req != o.Requested {
			t.Fatal("caller-chosen observer or selector")
		}
		return o, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	for _, fault := range []string{"partial", "failed", "trailing", "launch", "source"} {
		bad := r
		bad.Wire = append([]byte{}, r.Wire...)
		child := a
		launch := l
		switch fault {
		case "partial":
			bad.CaptureComplete = false
		case "failed":
			bad.ErrorClass = "ORIGINAL_TRANSPORT_UNCERTAIN"
		case "trailing":
			bad.Wire = append(bad.Wire, []byte(` {}`)...)
		case "launch":
			launch = append(append([]byte{}, l...), '\n')
		case "source":
			child.SourceCommit = strings.Repeat("0", 40)
		}
		if _, e = q.QualifyACK(t.Context(), child, launch, bad); e == nil || calls != 0 {
			t.Fatal("unqualified custody reached a provider GET", fault)
		}
	}
	if _, e = q.QualifyACK(t.Context(), a, l, r); e != nil || calls != 1 {
		t.Fatal("one Source-qualified independent GET failed", e)
	}
	for _, role := range []string{"execution", "market"} {
		bad := p
		life := *p.NativeWorkerLifecycleBinding
		life.PhysicalObservers = append([]model.CapacityNativeWorkerPhysicalReadBinding{}, life.PhysicalObservers...)
		bad.NativeWorkerLifecycleBinding = &life
		if role == "execution" {
			life.PhysicalObservers[0].Adapter = a.Execution.Adapter
		} else {
			life.PhysicalObservers[0].Adapter = p.MarketBinding.Profiles[0].Adapter
		}
		if ValidateNativeWorkerPhysicalObservers(bad) == nil {
			t.Fatal("writer/pricing instance acquired physical reader authority", role)
		}
	}
}

func TestNativePhysicalBindingIsOptionalButCannotWidenReadAuthority(t *testing.T) {
	p, _, _, _, _, _ := nativePhysicalFixture(t)
	absent := *p.NativeWorkerLifecycleBinding
	absent.PhysicalObservers = nil
	wire, e := json.Marshal(absent)
	if e != nil || strings.Contains(string(wire), "physical_observers") {
		t.Fatal("absent optional mode changed legacy wire")
	}
	if e = ValidateNativeWorkerPhysicalObservers(model.CapacityPolicySpec{NativeWorkerLifecycleBinding: &absent}); e != nil {
		t.Fatal("legacy absent binding was changed", e)
	}
	for _, fault := range []string{"missingProfile", "duplicateProfile", "unknownProfile", "differentRegion", "wrongCapability", "missingTypePin", "missingScope", "missingSource"} {
		bad := p
		life := *p.NativeWorkerLifecycleBinding
		life.PhysicalObservers = append([]model.CapacityNativeWorkerPhysicalReadBinding{}, life.PhysicalObservers...)
		bad.NativeWorkerLifecycleBinding = &life
		switch fault {
		case "missingProfile":
			life.PhysicalObservers[0].Profile = ""
		case "duplicateProfile":
			life.PhysicalObservers = append(life.PhysicalObservers, life.PhysicalObservers[0])
		case "unknownProfile":
			life.PhysicalObservers[0].Profile = "unbound"
		case "differentRegion":
			life.PhysicalObservers[0].Region = "us-west-2"
		case "wrongCapability":
			life.PhysicalObservers[0].Capability = "ensure_native_worker"
		case "missingTypePin":
			life.PhysicalObservers[0].Adapter.TypeChecksum = ""
		case "missingScope":
			life.PhysicalObservers[0].ScopeSHA256 = ""
		case "missingSource":
			life.PhysicalObservers[0].SourceCommit = ""
		}
		if ValidateNativeWorkerPhysicalObservers(bad) == nil {
			t.Fatal("unbound read authority accepted", fault)
		}
	}
}

func TestNativePhysicalSystemRetainedHostFenceSurvivesCoherentForgedBirth(t *testing.T) {
	for _, id := range []string{"i-0eb40396f80878812", "i-0f051cfd6d8da97e9", "i-070b5767a35c7f0d5"} {
		p, a, l, original, o, now := nativePhysicalFixture(t)
		var wire nativeAWSOriginal
		if json.Unmarshal(original.Wire, &wire) != nil {
			t.Fatal("bad original fixture")
		}
		wire.Body = []byte(strings.ReplaceAll(string(wire.Body), o.Physical.ResourceID, id))
		original.Wire, _ = json.Marshal(wire)
		o.Physical.ResourceID = id
		o.Physical.ProviderID = "aws:///us-east-1a/" + id
		o.Requested.ResourceID = id
		o.RootVolume.AttachedInstanceID = id
		o.PrimaryInterface.AttachedInstanceID = id
		sealNativePhysicalFixture(&o)
		// All fresh times, the original acceptance, client token, tags, current
		// SDK and launch remain mutually coherent. This refusal must come from
		// the same retained-ID fence as System, not an incidental mismatch.
		if _, e := decodeNativeAWSAcceptance(a, original); e != nil {
			t.Fatal("retained ID fixture failed before the physical fence", e)
		}
		if _, e := PureNativePhysicalQualify(a, l, original, o, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now); e == nil {
			t.Fatal("preserved System host identity became a new Native birth", id)
		}
	}
}

func TestNativePhysicalReobserveRetainsSealedStateWithoutLifecycleAuthority(t *testing.T) {
	p, a, l, original, o, now := nativePhysicalFixture(t)
	first, e := PureNativePhysicalQualify(a, l, original, o, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now)
	if e != nil {
		t.Fatal(e)
	}
	physical := first.IndependentCurrent
	a.Physical = &physical
	a.BirthSHA256 = strings.Repeat("9", 64)
	calls := 0
	q, e := NewNativeWorkerACKQualifier(p, func(_ context.Context, _ model.CapacityNativeWorkerPhysicalReadBinding, _ model.CapacityNativeWorkerObservationRequest) (model.CapacityNativeWorkerPhysicalObservation, error) {
		calls++
		return o, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	for _, state := range []string{"acknowledged", "registered", "admitted", "draining"} {
		a.State = state
		got, e := q.ReobserveACK(t.Context(), a, l, original)
		if e != nil || got != *a.Physical || a.State != state {
			t.Fatal("sealed read required a fake state or changed physical birth", state, e)
		}
		// The normal first-ACK entrypoint still cannot mint an acknowledgement
		// for a later lifecycle state, even with otherwise correct evidence.
		before := calls
		if _, e = q.QualifyACK(t.Context(), a, l, original); e == nil || calls != before {
			t.Fatal("sealed state reopened first-ACK qualification")
		}
	}
	for _, fault := range []string{"noPhysical", "noBirth", "unknownState", "reservedState", "absentState"} {
		bad := a
		bad.State = "acknowledged"
		switch fault {
		case "noPhysical":
			bad.Physical = nil
		case "noBirth":
			bad.BirthSHA256 = ""
		case "unknownState":
			bad.State = "unknown"
		case "reservedState":
			bad.State = "reserved"
		case "absentState":
			bad.State = "absent"
		}
		before := calls
		if _, e = q.ReobserveACK(t.Context(), bad, l, original); e == nil || calls != before {
			t.Fatal("unsealed or terminal state reached provider read", fault)
		}
	}
	a.State = "acknowledged"
	changed := *a.Physical
	changed.MACAddress = "02:00:00:00:00:09"
	a.Physical = &changed
	if _, e = q.ReobserveACK(t.Context(), a, l, original); e == nil {
		t.Fatal("stored sealed birth was substituted")
	}
	a.Physical = &physical
	o.PrimaryInterface.AttachedInstanceID = "i-foreign"
	sealNativePhysicalFixture(&o)
	if _, e = q.ReobserveACK(t.Context(), a, l, original); e == nil {
		t.Fatal("current SDK drift masqueraded as the sealed birth")
	}
}

func TestNativePhysicalPairedPublicEndpointRemainsOnlyAnObservedFact(t *testing.T) {
	p, a, l, r, o, now := nativePhysicalFixture(t)
	o.TransportEndpointIPv4 = "203.0.113.9"
	sealNativePhysicalFixture(&o)
	out, e := PureNativePhysicalQualify(a, l, r, o, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now)
	if e != nil || out.State != "acknowledged" || out.NodeUID != "" || out.NetworkEvidenceSHA256 != "" || out.AdmissionReceiptSHA256 != "" {
		t.Fatal("paired public endpoint became scheduling/network authority or was refused", e)
	}
}
