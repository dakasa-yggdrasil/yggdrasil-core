package capacity

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"slices"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func (f *NativeWorkerPrivateFactory) MatchesPlacementBootstrapPolicy(policySHA string) bool {
	if f == nil || f.nativeWorkerPrivateFactoryState == nil || !marketSHA.MatchString(policySHA) {
		return false
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	return !f.closed && f.guest != nil && f.guest.config.PlacementBootstrapPolicySHA256 == policySHA
}

// A separate GET0 on the same per-Attempt readonly identity. Enabling its
// explicit issuance pin changes the public policy hash; an old Attempt cannot
// gain the endpoint or a later certificate expiry by setting an option now.
func (f *NativeWorkerPrivateFactory) ReadPlacementBootstrap(ctx context.Context, a model.CapacityNativeWorkerAttempt, stored json.RawMessage, policySHA string) (model.CapacityNativeWorkerPlacementBootstrapObservation, error) {
	var zero model.CapacityNativeWorkerPlacementBootstrapObservation
	if f == nil || f.nativeWorkerPrivateFactoryState == nil || ctx == nil || ctx.Err() != nil || a.Physical == nil || a.Physical.ProviderID == "" || !NativeWorkerPhysicalValid(a, *a.Physical) || !marketSHA.MatchString(policySHA) {
		return zero, errNativeGuestRead
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.closed || f.guest == nil || f.guest.config.PlacementBootstrapPolicySHA256 != policySHA || a.Execution.GuestIdentityPolicySHA256 != f.guest.policySHA256 {
		return zero, errNativeGuestRead
	}
	prepared, key, e := f.prepare(a)
	defer nativePrivateWipe(key)
	if e != nil || !bytes.Equal(stored, prepared.PublicJSON) || nativePrivateSHA(stored) != a.LaunchSHA256 {
		return zero, errNativeGuestRead
	}
	return f.guest.readPlacementBootstrap(ctx, a, stored, f.config.SystemBuildSource, policySHA, nil)
}

func (g *nativeGuestReadIdentity) readPlacementBootstrap(ctx context.Context, a model.CapacityNativeWorkerAttempt, stored []byte, source, policySHA string, dial func(context.Context, string, string) (net.Conn, error)) (model.CapacityNativeWorkerPlacementBootstrapObservation, error) {
	var zero model.CapacityNativeWorkerPlacementBootstrapObservation
	if g == nil || a.Physical == nil || a.Physical.ProviderID == "" || !NativeWorkerPhysicalValid(a, *a.Physical) || !marketSHA.MatchString(policySHA) || g.config.PlacementBootstrapPolicySHA256 != policySHA {
		return zero, errNativeGuestRead
	}
	raw, e := g.readOriginal(ctx, a, stored, source, model.CapacityNativeWorkerPlacementBootstrapPath, dial)
	defer clear(raw)
	var out model.CapacityNativeWorkerPlacementBootstrapObservation
	name, ne := NativeWorkerBootstrapNodeName(a)
	if e != nil || ne != nil || DecodeNativeCapacity(json.RawMessage(raw), &out) != nil || out.Schema != model.CapacityNativeWorkerPlacementBootstrapSchema || out.SourceCommit != source || out.AttemptID != a.ID.String() || out.LaunchSHA256 != a.LaunchSHA256 || out.ProviderID != a.Physical.ProviderID || out.NodeName != name || out.AgentPID < 1 || out.AgentStartTicks < 1 || !out.AgentConfigComplete || out.AgentConfigPath == "" || out.ActualAgentArgv == nil || out.ConfiguredKubeletArgs == nil || out.ConfiguredNodeIPv4 != a.OverlayIPv4 || !nativeMemberFresh(out.ObservedAt, time.Now().UTC(), min(g.config.MaxReadAgeSeconds, model.CapacityNativeWorkerMemberMaxGuestAgeSeconds)) {
		return zero, errNativeGuestRead
	}
	out.ActualAgentArgv = slices.Clone(out.ActualAgentArgv)
	out.ConfiguredKubeletArgs = slices.Clone(out.ConfiguredKubeletArgs)
	return out, nil
}
