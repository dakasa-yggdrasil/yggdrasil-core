package repository

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func TestNativeWorkerConcreteRuntimeProviderAndStoredProfileAreExact(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		if !nativeConcreteRuntimeProvider(provider) {
			t.Fatal("paired provider refused", provider)
		}
	}
	for _, provider := range []string{"", "AWS", "Hetzner", "HETZNER", "hcloud", "hcloud://", "ec2", "amazon", "gcp", "fixture", "aws ", " hetzner", "\taws", "aws\n", "aws\x00"} {
		if nativeConcreteRuntimeProvider(provider) {
			t.Fatal("provider alias/case/control value selected a real path", provider)
		}
	}
	profiles := []model.CapacityProfile{{Name: "worker-aws", Provider: "aws", Region: "us-east-1"}, {Name: "worker-hetzner", Provider: "hetzner", Region: "hel1"}}
	// Only the frozen policy table is needed for this pure guard. This object
	// is NOT a constructed runtime/factory, physical proof, Ready or Witness.
	r := &NativeWorkerConcreteRuntime{nativeWorkerConcreteRuntimeState: &nativeWorkerConcreteRuntimeState{spec: model.CapacityPolicySpec{Profiles: profiles}}}
	for _, tc := range []struct {
		name, profile, provider, region string
		want                            bool
	}{
		{"aws", "worker-aws", "aws", "us-east-1", true},
		{"hetzner", "worker-hetzner", "hetzner", "hel1", true},
		{"unknownProfile", "missing", "aws", "us-east-1", false},
		{"profileCase", "Worker-aws", "aws", "us-east-1", false},
		{"profileSpace", "worker-aws ", "aws", "us-east-1", false},
		{"providerSwap", "worker-aws", "hetzner", "us-east-1", false},
		{"reverseProviderSwap", "worker-hetzner", "aws", "hel1", false},
		{"knownRegionSwap", "worker-aws", "aws", "eu-central-1", false},
		{"zoneIsNotRegion", "worker-aws", "aws", "us-east-1a", false},
		{"marketRegionIsNotNetworkZone", "worker-hetzner", "hetzner", "eu-central", false},
		{"legacyProviderAlias", "worker-hetzner", "hcloud", "hel1", false},
		{"providerCase", "worker-aws", "AWS", "us-east-1", false},
		{"regionCase", "worker-hetzner", "hetzner", "HEL1", false},
		{"regionSpace", "worker-aws", "aws", "us-east-1 ", false},
		{"missingRegion", "worker-aws", "aws", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := model.CapacityNativeWorkerAttempt{Profile: tc.profile, Provider: tc.provider, Region: tc.region}
			if got := r.attemptProfileBound(a); got != tc.want {
				t.Fatalf("stored profile binding=%t want=%t", got, tc.want)
			}
		})
	}
	for _, table := range [][]model.CapacityProfile{nil, {{Name: "worker-hetzner", Provider: "hcloud", Region: "hel1"}}} {
		other := &NativeWorkerConcreteRuntime{nativeWorkerConcreteRuntimeState: &nativeWorkerConcreteRuntimeState{spec: model.CapacityPolicySpec{Profiles: table}}}
		if other.attemptProfileBound(model.CapacityNativeWorkerAttempt{Profile: "worker-hetzner", Provider: "hcloud", Region: "hel1"}) {
			t.Fatal("empty or unpaired frozen policy table authorized an attempt")
		}
	}
}
