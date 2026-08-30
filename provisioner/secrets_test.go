package provisioner

import "testing"

func TestTartaroRTAReceivesSharedHMACSecret(t *testing.T) {
	for _, service := range allServices() {
		if service.name != "tartaro-rta" {
			continue
		}
		if !service.needsHMAC {
			t.Fatal("tartaro-rta must receive DAKASA_HMAC_SECRET for its private revocation endpoint")
		}
		return
	}
	t.Fatal("tartaro-rta service spec not found")
}
