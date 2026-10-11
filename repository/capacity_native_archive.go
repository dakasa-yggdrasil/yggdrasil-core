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

func nativeArchiveSHA(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func nativeCanonicalArchiveSHA(raw []byte) string {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return ""
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return nativeArchiveSHA(canonical)
}

func archiveNativeCommand(ctx context.Context, tx *sql.Tx, command model.CapacityNativeCommand) error {
	if command.State != "confirmed" && command.State != "refused_no_redemption" {
		return ErrCapacityConflict
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return err
	}
	var subject struct {
		UID    string `json:"expected_pod_uid"`
		HPAUID string `json:"expected_uid"`
	}
	if json.Unmarshal(command.Request, &subject) != nil {
		return ErrCapacityConflict
	}
	uid := subject.UID
	if uid == "" {
		uid = subject.HPAUID
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_command_identities(id,namespace,environment,domain,dimension,generation,operation,subject_uid,phase,sequence,authority_token_sha256,request_sha256)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)ON CONFLICT(id) DO NOTHING`, command.CommandID, command.Namespace, command.Environment, command.Domain, command.Dimension, command.IntentGeneration, command.Operation, uid, command.Phase, command.Sequence, command.AuthorityTokenSHA256, command.RequestSHA256); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_command_archive(id,record_sha256,command_record)VALUES($1,$2,$3)`, command.CommandID, nativeCanonicalArchiveSHA(raw), raw); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `DELETE FROM public.capacity_native_commands WHERE id=$1 AND state IN ('confirmed','refused_no_redemption')`, command.CommandID)
	return err
}

// Compaction has no age predicate. Only authoritative terminal bundles move:
// the complete durable native witness and the confirmed one-use release remain
// intact in immutable archive, with permanent scope/command/token tombstones.
// Unknown, alive and pending records are never deleted or relabelled complete.
func (s CapacityStore) ArchiveNativeTerminalHistory(ctx context.Context, policy model.Manifest, intent model.CapacityIntent) error {
	return s.mutationTransaction(ctx, policy, false, intent.Generation, intent.FencingToken, intent.LeaseOwner, func(tx *sql.Tx, p model.CapacityPolicySpec, current model.CapacityIntent, now time.Time) error {
		if p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode {
			return ErrCapacityConflict
		}
		rows, err := tx.QueryContext(ctx, `SELECT checkpoint_record FROM public.capacity_native_lifetimes WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND checkpoint_record->>'state'='released' ORDER BY updated_at,pod_uid LIMIT 64 FOR UPDATE`, current.Namespace, p.Environment, p.Domain, p.Dimension)
		if err != nil {
			return err
		}
		closed := []model.CapacityNativePodCheckpoint{}
		for rows.Next() {
			var raw []byte
			var cp model.CapacityNativePodCheckpoint
			if rows.Scan(&raw) != nil || json.Unmarshal(raw, &cp) != nil {
				rows.Close()
				return ErrCapacityConflict
			}
			closed = append(closed, cp)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, cp := range closed {
			var witness model.AdapterCapacityPodTerminationResponse
			var origin model.CapacityPolicySpec
			if cp.PolicyID != policy.ID || nativeCanonicalArchiveSHA(cp.OriginPolicy) != cp.OriginPolicySHA256 || json.Unmarshal(cp.OriginPolicy, &origin) != nil || capacity.ValidatePolicy(origin) != nil || origin.Environment != p.Environment || origin.Domain != p.Domain || origin.Dimension != p.Dimension || origin.Owner != p.Owner || cp.BindingSHA256 != capacity.NativeLifetimeBindingSHA256(origin) || cp.ConfirmedAt == nil || len(cp.NativeTerminationReceipt) == 0 || capacity.DecodeNativeCapacity(cp.NativeTerminationReceipt, &witness) != nil || capacity.NativePodWitness(origin, cp, witness.Observation, *cp.ConfirmedAt) != nil {
				return ErrCapacityConflict
			}
			commands := []model.CapacityNativeCommand{}
			rows, err = tx.QueryContext(ctx, `SELECT command_record FROM public.capacity_native_commands WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND subject_uid=$5 ORDER BY updated_at,id FOR UPDATE`, current.Namespace, p.Environment, p.Domain, p.Dimension, cp.PodUID)
			if err != nil {
				return err
			}
			for rows.Next() {
				var raw []byte
				var command model.CapacityNativeCommand
				if rows.Scan(&raw) != nil || json.Unmarshal(raw, &command) != nil {
					rows.Close()
					return ErrCapacityConflict
				}
				commands = append(commands, command)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			releases := 0
			for _, command := range commands {
				if command.PolicyID != cp.PolicyID || command.PolicyChecksum != cp.PolicyChecksum || (command.State != "confirmed" && command.State != "refused_no_redemption") {
					return ErrCapacityConflict
				}
				if command.Phase == "release" && command.State == "confirmed" {
					var released model.AdapterCapacityPodTerminationResponse
					if command.Operation != capacity.DestroyNativePodProtection || capacity.DecodeNativeCapacity(command.NativeReadback, &released) != nil || released.Operation != capacity.ObserveNativePodTermination || released.Status != "observed" || capacity.NativePodReleaseTarget(origin, cp, released.Observation, command.UpdatedAt) != nil {
						return ErrCapacityConflict
					}
					releases++
				}
			}
			if releases != 1 {
				return ErrCapacityConflict
			}
			bundle := struct {
				Checkpoint model.CapacityNativePodCheckpoint `json:"checkpoint"`
				Commands   []model.CapacityNativeCommand     `json:"commands"`
			}{cp, commands}
			raw, err := json.Marshal(bundle)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_native_lifetime_archive(namespace,environment,domain,dimension,pod_uid,origin_generation,origin_sha256,bundle_sha256,bundle_record,archived_at)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, current.Namespace, p.Environment, p.Domain, p.Dimension, cp.PodUID, cp.IntentGeneration, cp.OriginChallengeSHA256, nativeCanonicalArchiveSHA(raw), raw, now); err != nil {
				return err
			}
			for _, command := range commands {
				if err = archiveNativeCommand(ctx, tx, command); err != nil {
					return err
				}
			}
			if _, err = tx.ExecContext(ctx, `DELETE FROM public.capacity_native_lifetimes WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND pod_uid=$5 AND checkpoint_record->>'state'='released'`, current.Namespace, p.Environment, p.Domain, p.Dimension, cp.PodUID); err != nil {
				return err
			}
		}
		// An old completed envelope is a reservation receipt, not a lifetime
		// receipt. Its immutable command and generation identity survive here.
		rows, err = tx.QueryContext(ctx, `SELECT command_record FROM public.capacity_native_commands c WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND generation<$5 AND operation=$6 AND state IN ('confirmed','refused_no_redemption') AND EXISTS(SELECT 1 FROM public.capacity_intent_events e WHERE e.namespace=c.namespace AND e.environment=c.environment AND e.domain=c.domain AND e.dimension=c.dimension AND e.generation=c.generation AND e.phase='envelope_applied') ORDER BY updated_at,id LIMIT 64 FOR UPDATE`, current.Namespace, p.Environment, p.Domain, p.Dimension, current.Generation, capacity.EnsureBoundHPAEnvelope)
		if err != nil {
			return err
		}
		envelopes := []model.CapacityNativeCommand{}
		for rows.Next() {
			var raw []byte
			var command model.CapacityNativeCommand
			if rows.Scan(&raw) != nil || json.Unmarshal(raw, &command) != nil {
				rows.Close()
				return ErrCapacityConflict
			}
			envelopes = append(envelopes, command)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, command := range envelopes {
			var origin model.CapacityPolicySpec
			if command.PolicyID != policy.ID || nativeCanonicalArchiveSHA(command.OriginPolicy) != command.OriginPolicySHA256 || json.Unmarshal(command.OriginPolicy, &origin) != nil || capacity.ValidatePolicy(origin) != nil || origin.Environment != p.Environment || origin.Domain != p.Domain || origin.Dimension != p.Dimension || origin.Owner != p.Owner {
				return ErrCapacityConflict
			}
			if command.State == "confirmed" {
				var request model.CapacityNativeHPARequest
				var observed model.CapacityHPAEnvelopeResponse
				if capacity.DecodeNativeCapacity(command.Request, &request) != nil || capacity.DecodeNativeCapacity(command.NativeReadback, &observed) != nil {
					return ErrCapacityConflict
				}
				historical := current
				historical.NativeHPAGeneration, historical.Decision.Units = request.Generation, request.MinReplicas
				if nativeEnvelopeMatches(origin, historical, request, observed, command.UpdatedAt) != nil {
					return ErrCapacityConflict
				}
			}
			if err = archiveNativeCommand(ctx, tx, command); err != nil {
				return err
			}
		}
		return nil
	})
}

// ArchivedNativeLifetime reads one permanent terminal origin for a UID still
// present in a bounded native LIST. It never restores a hot record or issues
// permission; a fresh native removal-target read remains separately required.
func (s CapacityStore) ArchivedNativeLifetime(ctx context.Context, policy model.Manifest, uid string) (model.CapacityNativePodCheckpoint, bool, error) {
	var zero model.CapacityNativePodCheckpoint
	p, err := parseCapacityPolicy(policy)
	if err != nil || s.DB == nil || !capacity.NativeProcessNonce(uid) || p.HPAExecutionBinding == nil || p.HPAExecutionBinding.Mode != capacity.HPALifetimeExecutionMode {
		return zero, false, ErrCapacityConflict
	}
	var raw []byte
	var bundleDigest, originDigest string
	var originGeneration int64
	err = s.DB.QueryRowContext(ctx, `SELECT bundle_record,bundle_sha256,origin_sha256,origin_generation FROM public.capacity_native_lifetime_archive WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND pod_uid=$5`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, uid).Scan(&raw, &bundleDigest, &originDigest, &originGeneration)
	if err == sql.ErrNoRows {
		return zero, false, nil
	}
	if err != nil {
		return zero, false, err
	}
	var bundle struct {
		Checkpoint model.CapacityNativePodCheckpoint `json:"checkpoint"`
		Commands   []model.CapacityNativeCommand     `json:"commands"`
	}
	if len(raw) > 2<<20 || nativeCanonicalArchiveSHA(raw) != bundleDigest || json.Unmarshal(raw, &bundle) != nil || len(bundle.Commands) == 0 || len(bundle.Commands) > 64 {
		return zero, false, ErrCapacityConflict
	}
	cp := bundle.Checkpoint
	var origin model.CapacityPolicySpec
	var witness model.AdapterCapacityPodTerminationResponse
	if cp.State != "released" || cp.PodUID != uid || cp.Namespace != p.AssessmentBinding.Snapshot.Namespace || cp.PolicyID != policy.ID || cp.PolicyChecksum != policy.Checksum || cp.BindingSHA256 != capacity.NativeLifetimeBindingSHA256(p) || cp.IntentGeneration != originGeneration || cp.OriginChallengeSHA256 != originDigest || nativeArchiveSHA(cp.OriginChallengeBytes) != originDigest || cp.ConfirmedAt == nil || nativeCanonicalArchiveSHA(cp.OriginPolicy) != cp.OriginPolicySHA256 || json.Unmarshal(cp.OriginPolicy, &origin) != nil || capacity.ValidatePolicy(origin) != nil || origin.Environment != p.Environment || origin.Domain != p.Domain || origin.Dimension != p.Dimension || origin.Owner != p.Owner || cp.BindingSHA256 != capacity.NativeLifetimeBindingSHA256(origin) || capacity.DecodeNativeCapacity(cp.NativeTerminationReceipt, &witness) != nil || capacity.NativePodWitness(origin, cp, witness.Observation, *cp.ConfirmedAt) != nil {
		return zero, false, ErrCapacityConflict
	}
	releases := 0
	seen := map[string]bool{}
	for _, command := range bundle.Commands {
		commandID := command.CommandID.String()
		if !capacity.NativeProcessNonce(commandID) || seen[commandID] || command.Namespace != policy.Metadata.Namespace || command.PolicyID != cp.PolicyID || command.PolicyChecksum != cp.PolicyChecksum || command.Environment != p.Environment || command.Domain != p.Domain || command.Dimension != p.Dimension || (command.State != "confirmed" && command.State != "refused_no_redemption") {
			return zero, false, ErrCapacityConflict
		}
		seen[commandID] = true
		if command.Phase != "release" || command.State != "confirmed" {
			continue
		}
		var released model.AdapterCapacityPodTerminationResponse
		if command.Operation != capacity.DestroyNativePodProtection || capacity.DecodeNativeCapacity(command.NativeReadback, &released) != nil || released.Operation != capacity.ObserveNativePodTermination || released.Status != "observed" || capacity.NativePodReleaseTarget(origin, cp, released.Observation, command.UpdatedAt) != nil {
			return zero, false, ErrCapacityConflict
		}
		var archivedCommand []byte
		var commandDigest string
		err = s.DB.QueryRowContext(ctx, `SELECT a.command_record,a.record_sha256 FROM public.capacity_native_command_archive a JOIN public.capacity_native_command_identities i ON i.id=a.id WHERE i.id=$1 AND i.namespace=$2 AND i.environment=$3 AND i.domain=$4 AND i.dimension=$5 AND i.subject_uid=$6 AND i.operation=$7 AND i.phase='release' AND i.authority_token_sha256=$8 AND i.request_sha256=$9`, command.CommandID, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension, uid, capacity.DestroyNativePodProtection, command.AuthorityTokenSHA256, command.RequestSHA256).Scan(&archivedCommand, &commandDigest)
		expected, _ := json.Marshal(command)
		if err != nil || nativeCanonicalArchiveSHA(archivedCommand) != commandDigest || commandDigest != nativeCanonicalArchiveSHA(expected) {
			return zero, false, ErrCapacityConflict
		}
		releases++
	}
	if releases != 1 {
		return zero, false, ErrCapacityConflict
	}
	return cp, true, nil
}
