package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// Called by the existing protected PhaseReader outside SQL transactions. The
// local witness is a required authenticated input to an independent producer,
// never a substitute for real bidirectional path MTU and workload startup.
func nativeConcreteGuestReadiness(db *sql.DB, policy model.Manifest, source string, factories map[string]*capacity.NativeWorkerPrivateFactory, independent capacity.NativeWorkerGuestWitnessProofFunc) capacity.NativeWorkerReadinessFunc {
	return func(parent context.Context, a model.CapacityNativeWorkerAttempt) (*model.CapacityNativeWorkerReadinessProof, error) {
		if parent == nil || parent.Err() != nil || db == nil || a.PolicyID != policy.ID || a.PolicyChecksum != policy.Checksum || a.Namespace != policy.Metadata.Namespace || a.SourceCommit != source || a.Execution.GuestIdentityPolicySHA256 == "" || a.Physical == nil || a.NodeUID == "" || !capacity.NativeWorkerPhysicalValid(a, *a.Physical) {
			return nil, errNativeWorkerConcreteRuntime
		}
		ctx, cancel := context.WithTimeout(parent, 65*time.Second)
		defer cancel()
		factory := factories[a.Profile]
		if factory == nil || !factory.MatchesExecution(a.Execution) {
			return nil, errNativeWorkerConcreteRuntime
		}
		launch, err := nativeGuestStoredLaunch(ctx, db, a)
		if err != nil {
			return nil, err
		}
		witness, err := factory.ReadGuestWitness(ctx, a, launch)
		if err != nil {
			return nil, err
		}
		if independent == nil {
			return nil, errNativeWorkerConcreteRuntime
		}
		// Isolate the stored argument from a process callback retaining pointers.
		wire, err := json.Marshal(a)
		var own model.CapacityNativeWorkerAttempt
		if err != nil || json.Unmarshal(wire, &own) != nil {
			return nil, errNativeWorkerConcreteRuntime
		}
		proof, err := independent(ctx, own, witness)
		if err != nil || proof == nil || ctx.Err() != nil {
			return nil, errNativeWorkerConcreteRuntime
		}
		after, err := nativeGuestStoredLaunch(ctx, db, a)
		if err != nil || !bytes.Equal(after, launch) {
			return nil, errNativeWorkerConcreteRuntime
		}
		// The existing PrepareNativeWorkerPhaseFromRead validates every proof
		// field, its freshness, Node/Birth/network/qualification joins and scope.
		return proof, nil
	}
}

func nativeGuestStoredLaunch(ctx context.Context, db *sql.DB, a model.CapacityNativeWorkerAttempt) ([]byte, error) {
	var raw, launch []byte
	if err := db.QueryRowContext(ctx, `SELECT attempt,launch_wire FROM public.capacity_native_worker_attempts WHERE id=$1 AND policy_id=$2 AND namespace=$3`, a.ID, a.PolicyID, a.Namespace).Scan(&raw, &launch); err != nil {
		return nil, errNativeWorkerConcreteRuntime
	}
	var actual model.CapacityNativeWorkerAttempt
	if json.Unmarshal(raw, &actual) != nil {
		return nil, errNativeWorkerConcreteRuntime
	}
	want, err := json.Marshal(a)
	have, e := json.Marshal(actual)
	sum := sha256.Sum256(launch)
	if err != nil || e != nil || !bytes.Equal(want, have) || hex.EncodeToString(sum[:]) != a.LaunchSHA256 {
		return nil, errNativeWorkerConcreteRuntime
	}
	return append([]byte(nil), launch...), nil
}
