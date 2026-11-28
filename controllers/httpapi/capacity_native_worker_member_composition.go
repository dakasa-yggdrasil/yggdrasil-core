package httpapi

import "github.com/dakasa-yggdrasil/yggdrasil-core/repository"

// This protected opaque owner is never constructed by an HTTP request. The
// existing provider/phase endpoints retain their old protocol and gain only the
// policy opt-in's additional pre-create/admission/abort fences.
func WithNativeWorkerMemberStore(store *repository.CapacityNativeWorkerMemberStore) ServerOption {
	return func(s *Server) { s.nativeWorkerMembers = store }
}
