package message

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"strings"
)

const originalCreateDispositionOperation = "observe_original_create_disposition"

// Native CloudTrail bodies may contain private historical bootstrap data.
// Only the administrative bridge may obtain this output. No JSON, workflow,
// generic RPC or sensitive-output permission can set this private policy bit.
func originalDispositionExecutionAllowed(req model.ExecuteIntegrationRequest, policy integrationExecutionPolicy) bool {
	if policy.originalCreateDisposition {
		return req.Operation == originalCreateDispositionOperation && req.Capability == originalCreateDispositionOperation
	}
	return !strings.EqualFold(strings.TrimSpace(req.Operation), originalCreateDispositionOperation) && !strings.EqualFold(strings.TrimSpace(req.Capability), originalCreateDispositionOperation)
}
