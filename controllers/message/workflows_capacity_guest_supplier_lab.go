//go:build labqualification && !nativequalification

package message

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"

	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// This approval is confined to the two immutable LAB catalog/instance pairs;
// production retains the independently reviewed supplier registry.
func labOriginalGuestSupplierApproved(provider, source string, instance, typ model.Manifest, ts model.IntegrationTypeManifestSpec) bool {
	type approval struct{ source, instanceID, instanceChecksum, typeID, typeChecksum, version, queue, instanceSpecSHA, typeSpecSHA string }
	var a approval
	switch provider {
	case "aws":
		a = approval{"57fcec882c31ad958d92556de9e9789fc95b8970", "bf14f99f-5de3-4314-a462-db85fa973f3c", "32638e487fd58c64aff23d20990e8e2f243762c60b2d918d1f19d344df723beb", "c7547c2f-1fb5-424b-bb7b-03d99f98328c", "75344b44769a8a9089da8fc13d2217ce6c58fa0234cd8fa77af514d379d855ce", "1.65.5", "yggdrasil.adapter.aws", "30d99e36e0d8153e941057f408636db59e491384faa478dc7d2310f235e9e86b", "e4caa7a4e2f52ab1bed4de030be6ea579e2c50521d3cb7b690b1965a9d5f794d"}
	case "hetzner":
		a = approval{"bcd65615c8704e0fd1f5d60875f80180b35f9599", "73bbf97c-e6c5-44ff-aaf3-0cb868ae764a", "5893366ae4d8791eb41402c1dbb7050dffe5717f6763aa091c688cecfa635b50", "8b3ccd73-a5d8-4544-ae8f-f2d9ee356df1", "fbaa33a618963333f68b8991a7548a6550f713c3543f112cd7e4f33275304dc7", "0.3.5", "yggdrasil.adapter.hetzner", "e0e3d84cd468eefa8622f25b1ad24138881e4da8320ff348bc74161066272d82", "c6bdc1d1f973bc1d1e0723c426e7bc76b2e4dccb52e33feb713ad54b768b9175"}
	default:
		return false
	}
	if labCanonicalSpecSHA(instance.Spec) != a.instanceSpecSHA || labCanonicalSpecSHA(typ.Spec) != a.typeSpecSHA || source != a.source || instance.ID.String() != a.instanceID || instance.Checksum != a.instanceChecksum || typ.ID.String() != a.typeID || typ.Checksum != a.typeChecksum || ts.Provider != provider || ts.Adapter.Version != a.version || ts.Adapter.Transport != "rabbitmq" || ts.Adapter.Queues.Describe != a.queue+".describe" || ts.Adapter.Queues.Execute != a.queue+".execute" || manifest.ValidateIntegrationTypeSpec(ts) != nil {
		return false
	}
	actual, err := manifest.ParseIntegrationTypeSpec(typ.Spec)
	return err == nil && reflect.DeepEqual(actual, ts)
}

// Hash all fields of the persisted raw specs, including fields not represented
// by the typed view. No hydrated credentials enter this calculation.
func labCanonicalSpecSHA(raw json.RawMessage) string {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
