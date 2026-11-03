//go:build linux && nativequalification

package capacitynativeqemu

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

func TestPG17OriginalReadStoreUsesActualExecutionState(t *testing.T) {
	workflowID := uuid.New()
	executor := uuid.NewString()
	original := repository.CapacityStore{WorkflowID: workflowID, ExecutorID: "unrelated", ExecutionEnabled: true}
	for _, tc := range []struct {
		name, value string
		want        bool
	}{{"empty", "", false}, {"disabled", "false", false}, {"noncanonical", "TRUE", false}, {"enabled", "true", true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("YGGDRASIL_CAPACITY_EXECUTION_ENABLED", tc.value)
			got := pg17OriginalReadStore(original, executor)
			if got.WorkflowID != workflowID || got.ExecutorID != executor || got.ExecutionEnabled != tc.want {
				t.Fatal("original executor or process execution state was not preserved")
			}
			if original.ExecutorID != "unrelated" || !original.ExecutionEnabled {
				t.Fatal("read copy changed the caller's store")
			}
		})
	}
}
