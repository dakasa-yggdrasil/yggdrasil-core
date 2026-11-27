package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Every pending/uncertain child retains a finite known charge even after its
// parent completes or a different healthy pool profile wins. It is not an
// unknown whole-account quantity. An active parent covers its original group
// once; otherwise each live child plus one group fixed charge is accounted.
func appendNativeAttemptReservationsTx(ctx context.Context, tx *sql.Tx, ledger *capacity.MarketLedgerObservation, p model.CapacityPolicySpec, covered map[string]bool) error {
	rows, err := tx.QueryContext(ctx, `SELECT attempt FROM public.capacity_native_worker_attempts WHERE state<>'absent' LIMIT 100001`)
	if err != nil {
		return err
	}
	defer rows.Close()
	groups := map[string]bool{}
	count := 0
	for rows.Next() {
		count++
		if count > 100000 {
			return fmt.Errorf("native child ledger collection bound exceeded")
		}
		var raw []byte
		var a model.CapacityNativeWorkerAttempt
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &a); err != nil {
			return err
		}
		group := fmt.Sprintf("%s/%d", a.PolicyID, a.Generation)
		if covered[group] {
			continue
		}
		r := a.Reservation
		if a.GroupFixedCostMicros < 0 {
			return fmt.Errorf("negative group charge")
		}
		if !groups[group] {
			if a.GroupFixedCostMicros > int64(^uint64(0)>>1)-r.CostMicros {
				return fmt.Errorf("group charge overflow")
			}
			r.CostMicros += a.GroupFixedCostMicros
			groups[group] = true
		}
		if err = appendMarketReservation(ledger, p, &r); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Only the explicit new mode uses child birth proofs. Legacy mode still reads
// its original confirmed grant format; a child never forges that old protocol.
func marketNativeAttemptBirthsTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, o *model.CapacityNativeWorkerPoolObservation) error {
	if len(o.Nodes) == 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `SELECT a.attempt,e.record->'birth' FROM public.capacity_native_worker_attempts a JOIN public.capacity_native_worker_events e ON e.attempt_id=a.id AND e.record ? 'birth' WHERE a.namespace=$1 AND a.environment=$2 AND a.domain=$3 AND a.dimension=$4 AND a.state IN('acknowledged','registered','admitted','draining') LIMIT 100001`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return err
	}
	defer rows.Close()
	births := map[marketNativeBirthKey]string{}
	count := 0
	for rows.Next() {
		count++
		if count > 100000 {
			return fmt.Errorf("native child birth collection bound exceeded")
		}
		var raw, wire []byte
		var a model.CapacityNativeWorkerAttempt
		var b model.CapacityNativeWorkerBirth
		if err = rows.Scan(&raw, &wire); err != nil {
			return err
		}
		if json.Unmarshal(raw, &a) != nil || json.Unmarshal(wire, &b) != nil {
			return fmt.Errorf("invalid typed native birth")
		}
		canonical, _ := json.Marshal(b)
		digest := fmt.Sprintf("%x", sha256.Sum256(canonical))
		if b.Schema != capacity.NativeWorkerLifecycleMode || a.Physical == nil || b.AttemptID != a.ID ||
			b.PolicyID != a.PolicyID || b.Generation != a.Generation || b.FencingToken != a.FencingToken ||
			b.PoolUID != a.PoolUID || b.PoolEpoch != a.PoolEpoch || b.PoolUID != p.NativeWorkerPoolBinding.PoolUID ||
			b.PoolEpoch != p.NativeWorkerPoolBinding.ExpectedPoolEpoch || b.ExecutionAdapter != a.Execution.Adapter ||
			b.ExecutionScopeSHA256 != a.Execution.ScopeSHA256 || b.LaunchSHA256 != a.LaunchSHA256 || b.Physical != *a.Physical || digest != a.BirthSHA256 ||
			!capacity.ValidDigest(b.OriginalAcceptanceSHA256) || !capacity.ValidDigest(b.IndependentReadSHA256) ||
			!capacity.NativeWorkerPhysicalValid(a, b.Physical) {
			return fmt.Errorf("child birth no longer joins immutable launch and SDK acceptance")
		}
		execMatched := false
		for _, e := range p.NativeWorkerLifecycleBinding.Profiles {
			if e.Profile == a.Profile && e.Adapter == b.ExecutionAdapter {
				execMatched = true
			}
		}
		if !execMatched {
			return fmt.Errorf("birth execution adapter differs from exact source binding")
		}
		births[marketNativeBirthKey{a.PolicyID.String(), a.Generation, a.FencingToken, a.Profile, b.Physical.ResourceID, b.ExecutionAdapter.ManifestID, digest}] = a.NodeUID
	}
	if err = rows.Err(); err != nil {
		return err
	}
	adapters := map[string]string{}
	for _, v := range p.NativeWorkerLifecycleBinding.Profiles {
		adapters[v.Profile] = v.Adapter.ManifestID
	}
	for _, node := range o.Nodes {
		resource := node.ProviderID[strings.LastIndex(node.ProviderID, "/")+1:]
		key := marketNativeBirthKey{node.CapacityPolicyID, node.IntentGeneration, node.FencingToken, node.Profile, resource, adapters[node.Profile], node.RegistrationReceiptSHA256}
		uid, ok := births[key]
		if !ok || uid != "" && uid != node.NodeUID {
			return fmt.Errorf("Node lacks exact original typed child birth")
		}
	}
	return nil
}
