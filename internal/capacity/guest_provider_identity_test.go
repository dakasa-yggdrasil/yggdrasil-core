package capacity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"os"
	"strings"
	"testing"
	"time"
)

// These are pure source-projection operands, never SQL or provider authority.
func TestOriginalGuestProviderNativeIdentity(t *testing.T) {
	for _, provider := range []string{"aws", "hetzner"} {
		for _, kind := range []string{"original", "missing", "source", "resource", "lifetime", "account", "region", "zone", "hostname", "stale", "future", "physical_missing"} {
			t.Run(provider+"/"+kind, func(t *testing.T) {
				now := time.Now().UTC()
				source := strings.Repeat("a", 40)
				id := "i-1234567890abcdef0"
				typ := "t3.small"
				image := "ami-1234567890abcdef0"
				region := "us-east-1"
				zone := "us-east-1a"
				account := "123456789012"
				if provider == "hetzner" {
					id = "123456"
					typ = "77"
					image = "123"
					region = "ash"
					zone = "us-east"
					account = ""
				}
				created := now.Add(-time.Second).Format(time.RFC3339Nano)
				p := model.CapacityPolicySpec{Profiles: []model.CapacityProfile{{Name: "workers", Provider: provider}}}
				b := model.CapacityMutationBinding{ProfileName: "workers", OriginalProviderSourceCommit: source}
				proof := model.CapacityMutationProof{ResourceID: id, ResourceCreatedAt: created, OwnerVerified: true, SpecVerified: true, ObservedAt: now}
				plan := model.CapacityVMFleetPlan{Server: &model.CapacityVMServerObservation{CapacityVMNativeTuple: model.CapacityVMNativeTuple{ID: id, CreatedAt: created}, Name: "native-server", ProviderHostname: "native-server", ProviderAccountID: account, Location: region, NetworkZone: zone, TypeID: typ, ImageID: image}}
				identity, err := OriginalGuestProviderIdentity(p, b, plan, proof, now)
				if err != nil {
					t.Fatal(err)
				}
				tuple := model.CapacityGuestNativeTuple{Provider: provider, ResourceID: id, CreatedAt: created}
				switch kind {
				case "missing":
					identity = nil
				case "source":
					identity.AdapterSourceCommit = strings.Repeat("b", 40)
				case "resource":
					identity.ResourceID = "foreign"
				case "lifetime":
					identity.ResourceCreatedAt = now.Add(-2 * time.Second).Format(time.RFC3339Nano)
				case "account":
					identity.AccountID = "wrong"
				case "region":
					identity.Region = ""
				case "zone":
					if provider == "aws" {
						identity.Zone = ""
					} else {
						identity.Zone = "ash-dc1"
					}
				case "hostname":
					identity.Hostname = ""
				case "stale":
					identity.ObservedAt = now.Add(-31 * time.Second)
				case "future":
					identity.ObservedAt = now.Add(time.Second)
				case "physical_missing":
					proof.SpecVerified = false
					_, err = OriginalGuestProviderIdentity(p, b, plan, proof, now)
				}
				if kind != "physical_missing" {
					err = ValidateGuestProviderNativeIdentity(identity, tuple, source, now)
				}
				if (err == nil) != (kind == "original") {
					t.Fatalf("identity %s accepted=%v err=%v", kind, err == nil, err)
				}
			})
		}
	}
}

func TestProviderNativeIdentitySignedClosedWitness(t *testing.T) {
	now := time.Now().UTC()
	source := strings.Repeat("a", 40)
	identity := &model.CapacityGuestProviderNativeIdentity{Schema: GuestProviderNativeIdentitySchema, Provider: "hetzner", ResourceID: "123", ResourceCreatedAt: now.Add(-time.Second).Format(time.RFC3339Nano), Region: "us-east", Location: "ash", Zone: "", TypeID: "77", ImageID: "1234", AccountID: "", Hostname: "native-server", ObservedAt: now, AdapterSourceCommit: source}
	w := model.CapacityGuestOriginalCreateWitness{Schema: GuestCreateWitnessSchema, ProviderNativeIdentity: identity, Tuple: model.CapacityGuestNativeTuple{Provider: identity.Provider, ResourceID: identity.ResourceID, CreatedAt: identity.ResourceCreatedAt}, OriginalCreateReturnedAt: now.Add(-time.Second), ObservedAt: now}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	public := base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	signature, err := GuestLifecycleSignature(key, w)
	if err != nil {
		t.Fatal(err)
	}
	w.Signature = signature
	wire, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.CapacityGuestOriginalCreateWitness
	if DecodeGuestLifecycle(wire, &decoded) != nil {
		t.Fatal("closed witness decode failed")
	}
	decoded.Signature = ""
	if !guestRetirementVerify(public, signature, decoded) {
		t.Fatal("native identity signature did not survive JSON")
	}
	decoded.ProviderNativeIdentity.Location = "fsn1"
	if guestRetirementVerify(public, signature, decoded) {
		t.Fatal("native identity was outside original signature")
	}
	for _, bad := range []string{strings.Replace(string(wire), `"region":"us-east"`, `"region":"us-east","Region":"us-east"`, 1), strings.Replace(string(wire), `"region":"us-east"`, `"region":"us-east","authority":true`, 1)} {
		if DecodeGuestLifecycle([]byte(bad), &decoded) == nil {
			t.Fatal("unknown/casefold nested identity accepted")
		}
	}
	legacy, _ := json.Marshal(model.CapacityGuestOriginalCreateWitness{})
	if bytes.Contains(legacy, []byte("provider_native_identity")) {
		t.Fatal("optional native identity changed legacy signed bytes")
	}
	if path := os.Getenv("PROVIDER_NATIVE_IDENTITY_CROSS_EXPORT"); path != "" {
		out, _ := json.Marshal(struct {
			Scope     string                                   `json:"scope"`
			PublicKey string                                   `json:"public_key"`
			Witness   model.CapacityGuestOriginalCreateWitness `json:"witness"`
		}{"unit source signed wire only; no SQL authority", public, w})
		if err = os.WriteFile(path, out, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
