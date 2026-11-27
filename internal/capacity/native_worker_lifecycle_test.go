package capacity

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeLifecycleNeverReusesReadonlyOrLegacyAuthority(t *testing.T) {
	now := time.Now().UTC()
	p, _, _ := plannerMarketFixture(now, 0)
	exec := p.MarketBinding.Profiles[0].Adapter
	exec.ManifestID = marketTestUUID(900)
	p.NativeWorkerLifecycleBinding = &model.CapacityNativeWorkerLifecycleBinding{Mode: NativeWorkerLifecycleMode, SourceCommit: strings.Repeat("a", 40), MaxReadAgeSeconds: 60}
	for _, profile := range p.MarketBinding.Profiles {
		p.NativeWorkerLifecycleBinding.Profiles = append(p.NativeWorkerLifecycleBinding.Profiles, model.CapacityNativeWorkerExecutionProfile{Profile: profile.Profile, Adapter: exec, BindingName: "owned/" + profile.Profile, SDKSourceCommit: strings.Repeat("e", 40), ScopeSHA256: strings.Repeat("f", 64), EnsureCapability: "ensure_worker", ObserveCapability: "observe_worker", DestroyCapability: "destroy_worker", LaunchTemplateSHA256: strings.Repeat("b", 64), BootstrapSourceCommit: strings.Repeat("c", 40), IPAMScope: "native/overlay", OverlayCIDR: "10.81.0.0/24", ExcludedIPv4: []string{"10.81.0.2"}})
	}
	if ValidateNativeWorkerLifecycleBinding(p) != nil {
		t.Fatal("closed Source refused")
	}
	original, _ := json.Marshal(p)
	for _, fault := range []string{"readonly-instance", "missing-epoch-source", "missing-sdk-source", "public-IPAM", "duplicate-exclusion", "legacy-slot", "registry-pricing-instance"} {
		var bad model.CapacityPolicySpec
		json.Unmarshal(original, &bad)
		switch fault {
		case "readonly-instance":
			bad.NativeWorkerLifecycleBinding.Profiles[0].Adapter = bad.MarketBinding.Profiles[0].Adapter
		case "missing-epoch-source":
			bad.NativeWorkerLifecycleBinding.SourceCommit = ""
		case "missing-sdk-source":
			bad.NativeWorkerLifecycleBinding.Profiles[0].SDKSourceCommit = ""
		case "public-IPAM":
			bad.NativeWorkerLifecycleBinding.Profiles[0].OverlayCIDR = "0.0.0.0/0"
		case "duplicate-exclusion":
			bad.NativeWorkerLifecycleBinding.Profiles[0].ExcludedIPv4 = []string{"10.81.0.2", "10.81.0.2"}
		case "legacy-slot":
			bad.MutationBindings = []model.CapacityMutationBinding{{}}
		case "registry-pricing-instance":
			bad.NativeWorkerLifecycleBinding.RegistryWriter = &model.CapacityNativeWorkerRegistryWriterBinding{Adapter: bad.MarketBinding.Profiles[0].Adapter, BindingName: "writer/pool", PrincipalID: "principal/fixed", SourceCommit: strings.Repeat("d", 40), ScopeSHA256: strings.Repeat("e", 64), Capability: "ensure_native_worker_pool", MaxPermitSeconds: 15}
		}
		if ValidateNativeWorkerLifecycleBinding(bad) == nil {
			t.Fatal("authority or IPAM escape", fault)
		}
	}
}

func TestNativeAttemptStateMachineCannotResendOrFreeUnknown(t *testing.T) {
	for _, from := range []string{"send_started", "unknown", "acknowledged", "registered", "admitted", "draining", "absent"} {
		if NativeWorkerTransitionAllowed(from, "reserved") || NativeWorkerTransitionAllowed(from, "send_started") {
			t.Fatal("phase replay minted a send", from)
		}
		if from != "draining" && NativeWorkerTransitionAllowed(from, "absent") {
			t.Fatal("uncertain child silently released", from)
		}
	}
	if !NativeWorkerTransitionAllowed("unknown", "acknowledged") || !NativeWorkerTransitionAllowed("draining", "absent") {
		t.Fatal("genuine read-only receiving blocked")
	}
}

func TestNativeAttemptPrivateOriginalCannotSerializeIntoPublicJSON(t *testing.T) {
	raw, _ := json.Marshal(model.CapacityNativeWorkerOriginalReturn{Wire: []byte("private-password"), ErrorClass: "private-error", CaptureComplete: true})
	if string(raw) != "{}" {
		t.Fatal("original private response entered public DTO")
	}
	raw, _ = json.Marshal(model.CapacityNativeWorkerObservation{OriginalReturnSHA256: strings.Repeat("a", 64)})
	if strings.Contains(string(raw), strings.Repeat("a", 64)) {
		t.Fatal("raw private blob hash entered public projection")
	}
}
