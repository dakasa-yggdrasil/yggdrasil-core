package capacity

import (
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"time"
)

// AWSOriginalCreateLifecycleComplete never interprets requestId as a provider
// job/action. Only an authenticated original AWS SDK return plus a separate
// fresh DescribeInstances/DescribeInstanceStatus projection can use this branch.
func AWSOriginalCreateLifecycleComplete(b model.CapacityMutationBinding, g model.CapacityMutationGrant, settlement *model.CapacityMutationSettleRequest, proof model.CapacityMutationProof, now time.Time) bool {
	l := proof.AWSInstanceLifecycle
	if settlement == nil || settlement.OriginalProviderCreateReturn == nil || settlement.OriginalProviderCreateReturn.Provider != "aws" || settlement.OriginalProviderCreateReturn.Schema != "aws_original_run_instances_return_v1" || settlement.OriginalProviderCreateReturn.AdapterSourceCommit != b.OriginalProviderSourceCommit || !businessSource.MatchString(b.OriginalProviderSourceCommit) || b.EnsureCapability != "ensure_ec2_instance" || b.DestroyCapability != "terminate_ec2_instance" || g.Capability != b.EnsureCapability || g.CompensationOf != "" || !settlement.TransportCompleted || settlement.Outcome != "accepted" || len(settlement.NextActionIDs) != 0 || settlement.ActionID == "" || proof.GrantID != g.GrantID || proof.ObservedCreationGrantID != g.GrantID || proof.ResourceID != settlement.ResourceID || proof.ResourceCreatedAt != settlement.ResourceCreatedAt || proof.ResourceAbsent || !proof.OwnerVerified || !proof.SpecVerified || len(proof.ActionIDs) != 0 || proof.ActionsTerminal || proof.ActionsSuccessful || proof.ActionsFailed || proof.ActionHistoryComplete || l == nil {
		return false
	}
	return l.Schema == "aws_original_request_and_instance_status_v1" && l.RequestID == settlement.ActionID && l.RequestID == settlement.OriginalProviderCreateReturn.ActionID && l.EC2State == "running" && l.SystemStatus == "ok" && l.InstanceStatus == "ok" && l.ObservedAt.Equal(proof.ObservedAt) && Fresh(l.ObservedAt, now, 30)
}
