package httpapi

import "context"

// Lifetime ownership supplies no principal, workflow, profile, proof or
// authority. The production HTTP bootstrap always installs a joining owner;
// a directly constructed test Server can retain the unconfigured parent.
type guestOriginalAsyncWorkflowOwner interface {
	Begin() (context.Context, func(), error)
}

func (s *Server) beginOriginalGuestAsyncWorkflow() (context.Context, func(), error) {
	if s.originalGuestAsyncWorkflowOwner == nil {
		return context.Background(), func() {}, nil
	}
	return s.originalGuestAsyncWorkflowOwner.Begin()
}
