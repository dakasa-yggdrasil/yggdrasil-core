package executorpower

import (
	"strings"
	"testing"
)

func TestSettlementTokenDigestPreservesWire(t *testing.T) {
	for _, token := range []string{"", strings.Repeat("a", 32), strings.Repeat("z", 256), "quoted \"token\"", "token-ç-東京", "line\nbreak"} {
		if got, want := settlementTokenDigest(token), Digest(token); got != want {
			t.Errorf("settlement token digest differs from original JSON-string protocol")
		}
	}
}
