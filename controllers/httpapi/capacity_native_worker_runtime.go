package httpapi

import "github.com/dakasa-yggdrasil/yggdrasil-core/repository"

// Installation is an explicit protected Go option. It neither enables process
// gates nor installs a controller, mutation sender, readiness or network writer.
// The process owner must retain and Close the successful runtime handle.
func WithConcreteNativeWorkerRuntime(runtime *repository.NativeWorkerConcreteRuntime) ServerOption {
	return func(s *Server) {
		s.nativeWorkerRuntime, s.nativeWorkerBootstrapFactory, s.nativeWorkerPhaseRuntime = nil, nil, nil
		if runtime == nil || !runtime.BoundToDatabase(s.db) {
			return
		}
		s.nativeWorkerRuntime, s.nativeWorkerBootstrapFactory, s.nativeWorkerPhaseRuntime = runtime, runtime, runtime
	}
}
