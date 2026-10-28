//go:build !recoveryfixture || nativequalification

package message

import (
	"strings"
	"testing"
	"time"
)

func TestNativeFixtureCensusAndOutput(t *testing.T) {
	names := []string{"TestCapacityMutationNativeWorkflowPostgres", "TestCapacityMutationNativeWorkflowPostgres/complete_inventory_registers_through_existing_lease", "TestCapacityMutationNativeWorkflowPostgres/native_reads_confirm_once_without_readiness_claim", "TestCapacityMutationNativeWorkflowPostgres/lost_failed_creation_is_explicit_unresolved_member"}
	var events string
	for _, name := range names {
		events += `{"Action":"run","Test":"` + name + `"}` + "\n" + `{"Action":"pass","Test":"` + name + `"}` + "\n"
	}
	events += `{"Action":"pass"}` + "\n"
	var out, stderr nativeFixtureCapture
	_, _ = out.Write([]byte(events))
	if !nativeFixtureCensus(&out) {
		t.Fatal("complete child census refused")
	}
	for _, value := range []string{strings.Replace(events, `"Action":"run"`, `"Action":"skip"`, 1), strings.Replace(events, `"Action":"pass"`, `"Action":"fail"`, 1), strings.Replace(events, names[3], "unknown", 1), events + events, "not-json\n"} {
		capture := nativeFixtureCapture{}
		_, _ = capture.Write([]byte(value))
		if nativeFixtureCensus(&capture) {
			t.Fatal("incomplete child census accepted")
		}
	}
	_, _ = stderr.Write([]byte("secret-token workflows_capacity_native_postgres_test.go:123\n"))
	summary := nativeFixtureSummary(&out, &stderr, 1)
	if strings.Contains(summary, "secret-token") || !strings.Contains(summary, "workflows_capacity_native_postgres_test.go:123") || !strings.Contains(summary, "exit=1") {
		t.Fatal("unsafe or incomplete summary")
	}
	huge := nativeFixtureCapture{}
	_, _ = huge.Write([]byte(strings.Repeat("x", nativeFixtureOutputLimit+1)))
	if nativeFixtureCensus(&huge) || !strings.Contains(nativeFixtureSummary(&huge, &stderr, 1), "stdout_truncated=true") {
		t.Fatal("truncated child accepted")
	}
}

func TestNativeFixtureNeedsCleanupTime(t *testing.T) {
	if nativeFixtureEnoughTime(164*time.Second) || !nativeFixtureEnoughTime(165*time.Second) {
		t.Fatal("insufficient owner cleanup interval")
	}
}
