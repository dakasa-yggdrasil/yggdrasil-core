package capacity

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeAWSOriginalDecoderRejectsAmbiguousXMLBeforeAnyProviderSelector(t *testing.T) {
	_, a, _, original, _, _ := nativePhysicalFixture(t)
	var envelope nativeAWSOriginal
	if json.Unmarshal(original.Wire, &envelope) != nil {
		t.Fatal("bad original fixture")
	}
	xml := string(envelope.Body)
	for _, tc := range []struct {
		name   string
		change func(string) string
	}{
		{"duplicateRequest", func(s string) string {
			return strings.Replace(s, "<requestId>", "<requestId>forged</requestId><requestId>", 1)
		}},
		{"duplicateInstance", func(s string) string {
			return strings.Replace(s, "<instanceId>", "<instanceId>i-forged</instanceId><instanceId>", 1)
		}},
		{"duplicateNestedMAC", func(s string) string {
			return strings.Replace(s, "<macAddress>", "<macAddress>02:00:00:00:00:09</macAddress><macAddress>", 1)
		}},
		{"caseAlias", func(s string) string {
			return strings.Replace(s, "<instanceId>", "<InstanceId>i-forged</InstanceId><instanceId>", 1)
		}},
		{"nestedCaseAlias", func(s string) string {
			return strings.Replace(s, "<deviceIndex>", "<DeviceIndex>1</DeviceIndex><deviceIndex>", 1)
		}},
		{"foreignNamespace", func(s string) string {
			return strings.ReplaceAll(s, "http://ec2.amazonaws.com/doc/2016-11-15/", "http://untrusted.invalid/")
		}},
		{"namespaceAlias", func(s string) string {
			return strings.Replace(s, `xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"`, `xmlns="http://ec2.amazonaws.com/doc/2016-11-15/" xmlns:alias="http://ec2.amazonaws.com/doc/2016-11-15/"`, 1)
		}},
		{"DTD", func(s string) string { return `<!DOCTYPE RunInstancesResponse [<!ENTITY forge "value">]>` + s }},
		{"instruction", func(s string) string { return `<?accept trust?>` + s }},
		{"secondRoot", func(s string) string { return s + s }},
		{"truncated", func(s string) string { return s[:len(s)-1] }},
		{"unknownRootMember", func(s string) string {
			return strings.Replace(s, "<requestId>", "<trusted>true</trusted><requestId>", 1)
		}},
		{"wrongRoot", func(s string) string {
			return strings.ReplaceAll(s, "RunInstancesResponse", "DescribeInstancesResponse")
		}},
		{"secondInstance", func(s string) string {
			return strings.Replace(s, "</instancesSet>", "<item><instanceId>i-foreign</instanceId></item></instancesSet>", 1)
		}},
		{"secondNIC", func(s string) string {
			return strings.Replace(s, "</networkInterfaceSet>", "<item><networkInterfaceId>eni-foreign</networkInterfaceId></item></networkInterfaceSet>", 1)
		}},
		{"foreignClientToken", func(s string) string {
			return strings.Replace(s, "<clientToken>"+a.ID.String(), "<clientToken>different", 1)
		}},
		{"wrongLaunchTag", func(s string) string {
			return strings.Replace(s, "<value>"+a.LaunchSHA256, "<value>"+strings.Repeat("f", 64), 1)
		}},
		{"sameTagRepeated", func(s string) string {
			return strings.Replace(s, "</tagSet>", "<item><key>dakasa.io/native-worker-pool</key><value>different</value></item></tagSet>", 1)
		}},
		{"detachedRoot", func(s string) string {
			return strings.Replace(s, "<deleteOnTermination>true</deleteOnTermination>", "<deleteOnTermination>false</deleteOnTermination>", 1)
		}},
		{"wrongStateCode", func(s string) string { return strings.Replace(s, "<code>0</code>", "<code>16</code>", 1) }},
		{"wrongArchitecture", func(s string) string { return strings.Replace(s, "x86_64", "arm64", 1) }},
		{"missingCreationTime", func(s string) string { return strings.Replace(s, "<launchTime>", "<unknownTime>", 1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := envelope
			wire.Body = []byte(tc.change(xml))
			raw, _ := json.Marshal(wire)
			if _, e := decodeNativeAWSAcceptance(a, model.CapacityNativeWorkerOriginalReturn{Wire: raw, CaptureComplete: true}); e == nil {
				t.Fatal("ambiguous private XML became a creation selector")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		change func(*nativeAWSOriginal)
	}{
		{"errorHTTP", func(v *nativeAWSOriginal) { v.HTTPStatus = 403 }},
		{"incompleteTransport", func(v *nativeAWSOriginal) { v.TransportCompleted = false }},
		{"wrongAttempt", func(v *nativeAWSOriginal) { v.AttemptID = "other" }},
		{"wrongSchema", func(v *nativeAWSOriginal) { v.Schema = "other" }},
		{"conflictingHeaderRequestID", func(v *nativeAWSOriginal) { v.RequestID = "different-header" }},
		{"bodyOverflow", func(v *nativeAWSOriginal) { v.Body = make([]byte, 736<<10+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := envelope
			tc.change(&wire)
			raw, _ := json.Marshal(wire)
			if _, e := decodeNativeAWSAcceptance(a, model.CapacityNativeWorkerOriginalReturn{Wire: raw, CaptureComplete: true}); e == nil {
				t.Fatal("unqualified original envelope accepted")
			}
		})
	}
	// A real EC2 request ID can be XML-only. A missing HTTP header is never
	// filled with a synthetic identifier; the actual XML request ID is retained.
	if got, e := decodeNativeAWSAcceptance(a, original); e != nil || got.requestID != "original-request" {
		t.Fatal("actual XML-only EC2 request ID was lost", e)
	}
}

func TestNativeAWSPendingACKDoesNotFabricateAncillaryIDs(t *testing.T) {
	p, a, launch, original, o, now := nativePhysicalFixture(t)
	var envelope nativeAWSOriginal
	if json.Unmarshal(original.Wire, &envelope) != nil {
		t.Fatal("bad original fixture")
	}
	xml := string(envelope.Body)
	start, end := strings.Index(xml, "<blockDeviceMapping>"), strings.Index(xml, "</blockDeviceMapping>")
	if start < 0 || end < 0 {
		t.Fatal("no original root mapping fixture")
	}
	end += len("</blockDeviceMapping>")
	for _, replacement := range []string{"", "<blockDeviceMapping/>"} {
		pending := xml[:start] + replacement + xml[end:]
		pending = strings.Replace(pending, "<networkInterfaceId>"+o.PrimaryInterface.ResourceID+"</networkInterfaceId>", "", 1)
		wire := envelope
		wire.Body = []byte(pending)
		raw, _ := json.Marshal(wire)
		custody := model.CapacityNativeWorkerOriginalReturn{Wire: raw, CaptureComplete: true}
		ack, e := decodeNativeAWSAcceptance(a, custody)
		if e != nil || ack.rootVolumePresent || ack.interfaceIDPresent || ack.rootVolumeID != "" || ack.interfaceID != "" {
			t.Fatal("missing original ancillary IDs were invented or refused", e)
		}
		if _, e = PureNativePhysicalQualify(a, launch, custody, o, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now); e != nil {
			t.Fatal("full independent root/interface facts could not qualify a pending original", e)
		}
		missing := o
		missing.RootVolume.ResourceID = ""
		sealNativePhysicalFixture(&missing)
		if _, e = PureNativePhysicalQualify(a, launch, custody, missing, p.NativeWorkerLifecycleBinding.PhysicalObservers[0], 30, now); e == nil {
			t.Fatal("missing original ancillary IDs allowed missing actual SDK identity")
		}
	}
	for _, tag := range []string{"volumeId", "networkInterfaceId"} {
		bad := xml
		start, end := strings.Index(bad, "<"+tag+">"), strings.Index(bad, "</"+tag+">")
		if start < 0 || end < 0 {
			t.Fatal("missing complete fixture ID", tag)
		}
		bad = bad[:start] + "<" + tag + "/>" + bad[end+len("</"+tag+">"):]
		wire := envelope
		wire.Body = []byte(bad)
		raw, _ := json.Marshal(wire)
		if _, e := decodeNativeAWSAcceptance(a, model.CapacityNativeWorkerOriginalReturn{Wire: raw, CaptureComplete: true}); e == nil {
			t.Fatal("present-empty original ID accepted", tag)
		}
	}
}
