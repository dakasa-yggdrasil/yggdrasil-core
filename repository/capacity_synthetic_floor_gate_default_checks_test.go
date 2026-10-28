//go:build !recoveryfixture || nativequalification

package repository

import (
	"strings"
	"testing"
	"time"
)

func TestSyntheticFloorChildCensusAndOutput(t *testing.T) {
	events := `{"Action":"run","Test":"TestSyntheticFloorDrainBudgetPostgres"}
{"Action":"pass","Test":"TestSyntheticFloorDrainBudgetPostgres"}
{"Action":"pass"}` + "\n"
	var out, stderr floorFixtureCapture
	_, _ = out.Write([]byte(events))
	if !floorFixtureCensus(&out) {
		t.Fatal("complete child census refused")
	}
	bad := []string{strings.Replace(events, `"Action":"run"`, `"Action":"skip"`, 1), strings.Replace(events, `"Action":"pass"`, `"Action":"fail"`, 1), strings.Replace(events, `{"Action":"pass"}`, `{"Action":"output"}`, 1), "not-json\n"}
	for _, value := range bad {
		capture := floorFixtureCapture{}
		_, _ = capture.Write([]byte(value))
		if floorFixtureCensus(&capture) {
			t.Fatal("incomplete child census accepted")
		}
	}
	_, _ = stderr.Write([]byte("secret-token capacity_synthetic_floor_gate_postgres_test.go:123\n"))
	text := floorFixtureSummary(&out, &stderr, 1)
	if strings.Contains(text, "secret-token") || !strings.Contains(text, "capacity_synthetic_floor_gate_postgres_test.go:123") || !strings.Contains(text, "exit=1") {
		t.Fatal("child summary leaked data or lost location/exit")
	}
	huge := floorFixtureCapture{}
	_, _ = huge.Write([]byte(strings.Repeat("x", floorFixtureOutputLimit+1)))
	if len(huge.buf) != floorFixtureOutputLimit || floorFixtureCensus(&huge) || !strings.Contains(floorFixtureSummary(&huge, &stderr, 1), "stdout_truncated=true") {
		t.Fatal("bounded output or truncation guard failed")
	}
}

func TestFloorFixtureNeedsCleanupTime(t *testing.T) {
	if floorFixtureEnoughTime(164*time.Second) || !floorFixtureEnoughTime(165*time.Second) {
		t.Fatal("owner began without its full cleanup interval")
	}
}

func TestSyntheticCompensationChildCensus(t *testing.T) {
	root := "TestCapacityMutationCompensationPostgres"
	child := root + "/unprotected_failed_create"
	events := `{"Action":"run","Test":"` + root + `"}` + "\n" +
		`{"Action":"run","Test":"` + child + `"}` + "\n" +
		`{"Action":"pass","Test":"` + child + `"}` + "\n" +
		`{"Action":"pass","Test":"` + root + `"}` + "\n" + `{"Action":"pass"}` + "\n"
	capture := func(s string) floorFixtureCapture {
		var out floorFixtureCapture
		_, _ = out.Write([]byte(s))
		return out
	}
	out := capture(events)
	if !syntheticRepositoryCensus(&out, root, child) {
		t.Fatal("complete compensation census refused")
	}
	for _, bad := range []string{
		strings.Replace(events, `{"Action":"run","Test":"`+child+`"}`+"\n", "", 1),
		events + `{"Action":"pass","Test":"` + child + `"}` + "\n",
		strings.Replace(events, `{"Action":"pass","Test":"`+root+`"}`, `{"Action":"skip","Test":"`+root+`"}`, 1),
		events + `{"Action":"pass"}` + "\n",
	} {
		out = capture(bad)
		if syntheticRepositoryCensus(&out, root, child) {
			t.Fatal("incomplete or duplicated census accepted")
		}
	}
}
