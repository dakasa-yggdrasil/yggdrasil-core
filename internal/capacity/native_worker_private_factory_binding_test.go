package capacity

import (
	"strings"
	"testing"
)

func TestNativePrivateFactoryExecutionMatchSharesExactPrepareAndCloseFence(t *testing.T) {
	factory, attempt := nativePrivateFactoryFixture(t, strings.Repeat("a", 40))
	defer factory.Close()
	if !factory.MatchesExecution(attempt.Execution) {
		t.Fatal("the existing constructed factory did not match its real execution")
	}
	for _, field := range []string{"profile", "scope", "source", "adapter", "excluded"} {
		changed := attempt.Execution
		switch field {
		case "profile":
			changed.Profile += "other"
		case "scope":
			changed.ScopeSHA256 = strings.Repeat("0", 64)
		case "source":
			changed.SDKSourceCommit = strings.Repeat("0", 40)
		case "adapter":
			changed.Adapter.Checksum = strings.Repeat("0", 64)
		case "excluded":
			changed.ExcludedIPv4 = append(append([]string(nil), changed.ExcludedIPv4...), "10.81.0.8")
		}
		if factory.MatchesExecution(changed) {
			t.Fatal("different execution selected an existing private factory", field)
		}
	}
	copy := *factory
	if err := copy.Close(); err != nil || factory.MatchesExecution(attempt.Execution) {
		t.Fatal("copy did not share the existing factory Close fence", err)
	}
	if new(NativeWorkerPrivateFactory).MatchesExecution(attempt.Execution) {
		t.Fatal("an unconstructed private factory matched execution")
	}
}
