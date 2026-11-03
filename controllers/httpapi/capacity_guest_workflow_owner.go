package httpapi

import "context"

// Optional lifetime observation only. It supplies no principal, workflow,
// profile, proof or authority. The native constructor is absent in production.
type guestOriginalAsyncWorkflowOwner interface {
	Begin() (context.Context, func(), error)
}

func (s *Server) beginOriginalGuestAsyncWorkflow() (context.Context, func(), error) {
	if s.originalGuestAsyncWorkflowOwner == nil {
		return context.Background(), func() {}, nil
	}
	return s.originalGuestAsyncWorkflowOwner.Begin()
}
