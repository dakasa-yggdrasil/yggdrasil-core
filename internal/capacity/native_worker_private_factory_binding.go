package capacity

import (
	"reflect"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// MatchesExecution reads only the already constructed handle. It neither
// opens files nor resolves credentials, and shares Prepare/Close's exact fence.
func (f *NativeWorkerPrivateFactory) MatchesExecution(execution model.CapacityNativeWorkerExecutionProfile) bool {
	if f == nil || f.nativeWorkerPrivateFactoryState == nil {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return !f.closed && reflect.DeepEqual(f.config.Execution, execution)
}
