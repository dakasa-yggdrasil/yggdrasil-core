package httpapi

import (
	"context"
	"net/http"
	"sync"
	"time"

	messagecontroller "github.com/dakasa-yggdrasil/yggdrasil-core/controllers/message"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// The ordinary context carries this dormant server closure; only an approved
// release binding consumes it. No wire actor/metadata can install a guard.
func (s *Server) withCapacityReleaseAuthorization(ctx context.Context, req model.RunWorkflowRequest, actor workflowRunActor, originalRequest *http.Request) context.Context {
	var original *model.Manifest
	var originalRBAC, originalPolicy *model.Manifest
	var mu sync.Mutex
	return messagecontroller.WithCapacityReleaseRecoveryAuthorization(ctx, func(owner context.Context) error {
		if originalRequest == nil {
			return errWorkflowAuthorizationDenied
		}
		freshActor, err := s.authenticateWorkflowRunRequest(originalRequest.WithContext(owner))
		if err != nil || freshActor.CollaboratorID != actor.CollaboratorID || freshActor.MachinePrincipalID != actor.MachinePrincipalID || freshActor.Subject != actor.Subject {
			return errWorkflowAuthorizationDenied
		}
		if actor.MachinePrincipal != nil && (actor.MachinePrincipal.Status != "active" || !time.Now().Before(actor.MachinePrincipal.ExpiresAt)) {
			return errWorkflowAuthorizationDenied
		}
		current, spec, err := s.lookupWorkflowManifestSpec(owner, req)
		if err != nil {
			return err
		}
		if !current.Metadata.Active || spec.Authorization == nil {
			return errWorkflowAuthorizationDenied
		}
		rbac, err := resolveWorkflowAuthorizationManifest(owner, s.db, "rbac", spec.Authorization.RBAC)
		if err != nil || !rbac.Metadata.Active {
			return errWorkflowAuthorizationDenied
		}
		var ap *model.Manifest
		if spec.Authorization.Policy != nil {
			value, e := resolveWorkflowAuthorizationManifest(owner, s.db, "policy", *spec.Authorization.Policy)
			if e != nil || !value.Metadata.Active {
				return errWorkflowAuthorizationDenied
			}
			ap = &value
		}
		mu.Lock()
		defer mu.Unlock()
		if original == nil {
			original = &current
			originalRBAC, originalPolicy = &rbac, ap
		} else if current.ID != original.ID || current.Checksum != original.Checksum || current.Version != original.Version || !current.Metadata.Active {
			return errWorkflowAuthorizationDenied
		}
		if rbac.ID != originalRBAC.ID || rbac.Checksum != originalRBAC.Checksum || (ap == nil) != (originalPolicy == nil) || (ap != nil && (ap.ID != originalPolicy.ID || ap.Checksum != originalPolicy.Checksum)) {
			return errWorkflowAuthorizationDenied
		}
		return s.authorizeWorkflowDispatch(owner, req, freshActor)
	})
}
