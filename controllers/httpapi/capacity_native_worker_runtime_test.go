package httpapi

import (
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

func TestConcreteNativeRuntimeOptionKeepsUnconstructedAndNilHandlesDisabled(t *testing.T) {
	server := &Server{}
	var _ repository.NativeWorkerPhaseRuntime = (*repository.NativeWorkerConcreteRuntime)(nil)
	for _, runtime := range []*repository.NativeWorkerConcreteRuntime{nil, new(repository.NativeWorkerConcreteRuntime)} {
		// A previous independently installed reader must not survive a failed
		// replacement and become paired with another worker/bootstrap handle.
		server.nativeWorkerPhaseRuntime = &serverNativeWorkerPhaseReader{server: server}
		WithConcreteNativeWorkerRuntime(runtime)(server)
		if server.nativeWorkerRuntime != nil || server.nativeWorkerBootstrapFactory != nil || server.nativeWorkerPhaseRuntime != nil || server.nativeWorkerAbortRuntime != nil {
			t.Fatal("an unconstructed handle activated runtime, bootstrap or mutation ports")
		}
	}
}
