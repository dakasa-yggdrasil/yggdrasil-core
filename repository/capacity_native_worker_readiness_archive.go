package repository

import (
	"context"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// This is private immutable receiving, not a caller proof DTO. Explicit tags
// preserve the closed snake-case journal and keep the existing Go-only proof
// wire unchanged. Its timestamps always belong to the original observations.
type nativeReadinessProof struct {
	AttemptID                   uuid.UUID                          `json:"attempt_id"`
	NodeUID                     string                             `json:"node_uid"`
	ProviderID                  string                             `json:"provider_id"`
	WorkerIPv4                  string                             `json:"worker_ipv4"`
	BirthSHA256                 string                             `json:"birth_sha256"`
	Physical                    model.CapacityNativeWorkerPhysical `json:"physical"`
	NetworkBindingSHA256        string                             `json:"network_binding_sha256"`
	NetworkEvidenceSHA256       string                             `json:"network_evidence_sha256"`
	WarmupEvidenceSHA256        string                             `json:"warmup_evidence_sha256"`
	PhysicalQualificationSHA256 string                             `json:"physical_qualification_sha256"`
	ObservedAt                  time.Time                          `json:"observed_at"`
	ValidUntil                  time.Time                          `json:"valid_until"`
}

func archiveNativeReadinessProof(p model.CapacityNativeWorkerReadinessProof) nativeReadinessProof {
	return nativeReadinessProof{AttemptID: p.AttemptID, NodeUID: p.NodeUID, ProviderID: p.ProviderID, WorkerIPv4: p.WorkerIPv4, BirthSHA256: p.BirthSHA256, Physical: p.Physical, NetworkBindingSHA256: p.NetworkBindingSHA256, NetworkEvidenceSHA256: p.NetworkEvidenceSHA256, WarmupEvidenceSHA256: p.WarmupEvidenceSHA256, PhysicalQualificationSHA256: p.PhysicalQualificationSHA256, ObservedAt: p.ObservedAt, ValidUntil: p.ValidUntil}
}

func (p nativeReadinessProof) value() model.CapacityNativeWorkerReadinessProof {
	return model.CapacityNativeWorkerReadinessProof{AttemptID: p.AttemptID, NodeUID: p.NodeUID, ProviderID: p.ProviderID, WorkerIPv4: p.WorkerIPv4, BirthSHA256: p.BirthSHA256, Physical: p.Physical, NetworkBindingSHA256: p.NetworkBindingSHA256, NetworkEvidenceSHA256: p.NetworkEvidenceSHA256, WarmupEvidenceSHA256: p.WarmupEvidenceSHA256, PhysicalQualificationSHA256: p.PhysicalQualificationSHA256, ObservedAt: p.ObservedAt, ValidUntil: p.ValidUntil}
}

func nativeReadinessProofMatches(r nativeReadinessRun, a model.CapacityNativeWorkerAttempt, p nativeReadinessProof) bool {
	i := r.Identity
	if a.ID != i.AttemptID || a.PolicyID != i.PolicyID || a.PolicyChecksum != i.PolicyChecksum || a.Namespace != i.Namespace || a.SourceCommit != i.SourceCommit || a.LaunchSHA256 != i.LaunchSHA256 || a.BirthSHA256 != i.BirthSHA256 || a.NodeUID != i.NodeUID || a.PoolUID != i.PoolUID || a.PoolEpoch != i.PoolEpoch || a.Profile != i.Profile || a.Generation != i.Generation || a.FencingToken != i.FencingToken || a.Physical == nil || !capacity.NativeWorkerPhysicalValid(a, *a.Physical) || a.Physical.ProviderID != i.ProviderID {
		return false
	}
	return p.AttemptID == a.ID && p.NodeUID == a.NodeUID && p.ProviderID == a.Physical.ProviderID && p.Physical == *a.Physical && p.WorkerIPv4 == a.OverlayIPv4 && p.BirthSHA256 == a.BirthSHA256 && p.NetworkBindingSHA256 == a.NetworkBindingSHA256 && nativeReadinessSHA(p.NetworkBindingSHA256) && nativeReadinessSHA(p.NetworkEvidenceSHA256) && nativeReadinessSHA(p.WarmupEvidenceSHA256) && p.PhysicalQualificationSHA256 == a.QualificationEvidenceSHA256 && nativeReadinessSHA(p.PhysicalQualificationSHA256) && !p.ObservedAt.Before(r.CreatedAt) && !p.ObservedAt.After(r.NotAfter) && p.ValidUntil.After(p.ObservedAt) && !p.ValidUntil.After(r.NotAfter) && !p.ValidUntil.After(a.QualificationValidUntil)
}

func nativeReadinessEffectsClosed(r nativeReadinessRun) bool {
	// Every planned slot must exist exactly once. A vacuously empty or partial
	// diagnostic journal can close custody but cannot produce readiness.
	slots := []string{"floor_pod", "candidate_pod", "floor_service", "candidate_service", "admission_secret", "floor_secret", "candidate_secret", "network_policy", "floor_initial", "candidate_initial", "floor_final", "candidate_final", "startup_challenge"}
	if len(r.Effects) != len(slots) {
		return false
	}
	for _, slot := range slots {
		i, ok := nativeReadinessEffectIndex(r, slot)
		if !ok {
			return false
		}
		e := r.Effects[i]
		if nativeReadinessObjectKind(e.Kind) {
			if e.State != "absent" || e.UID == "" || e.PrivateOriginal == nil || e.PrivateAbsence == nil {
				return false
			}
		} else if e.State != "observed" || e.PrivateOriginal == nil {
			return false
		}
	}
	return true
}

// Final proof and cleanup closure are one journal revision. No effect is
// authorized here, including when a late original arrives after the deadline.
func (s *nativeReadinessRunJournal) finishWithProof(ctx context.Context, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun, proof model.CapacityNativeWorkerReadinessProof) (nativeReadinessRun, error) {
	archived := archiveNativeReadinessProof(proof)
	if !nativeReadinessProofMatches(r, a, archived) || r.Proof != nil || r.PendingProof == nil {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	want, we := nativeReadinessDigest(archived)
	got, ge := nativeReadinessDigest(r.PendingProof)
	if we != nil || ge != nil || want != got {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return s.edit(ctx, r, nil, func(current *nativeReadinessRun, now time.Time) error {
		if current.Proof != nil || !nativeReadinessEffectsClosed(*current) || archived.ObservedAt.After(now) {
			return errNativeReadinessRun
		}
		current.Proof, current.Closed = &archived, true
		return nil
	})
}

// Qualification is sealed BEFORE cleanup. Resuming after any delete or crash
// consumes this same evidence and deadline; it never sends another packet or
// constructs a fresh warmup identity to replace an expired proof.
func (s *nativeReadinessRunJournal) sealProof(ctx context.Context, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun, proof model.CapacityNativeWorkerReadinessProof) (nativeReadinessRun, error) {
	p := archiveNativeReadinessProof(proof)
	if r.PendingProof != nil || !nativeReadinessProofMatches(r, a, p) {
		return nativeReadinessRun{}, errNativeReadinessRun
	}
	return s.edit(ctx, r, &a, func(current *nativeReadinessRun, now time.Time) error {
		if current.PendingProof != nil || p.ObservedAt.After(now) || !p.ValidUntil.After(now) {
			return errNativeReadinessRun
		}
		current.PendingProof = &p
		return nil
	})
}

// A fresh GET cannot renew a completed diagnostic. Admission/release/Record use
// the same archived timestamps and hashes after cleanup; expired proof is HOLD.
func nativeReadinessArchivedProof(r nativeReadinessRun, a model.CapacityNativeWorkerAttempt, now time.Time) (*model.CapacityNativeWorkerReadinessProof, error) {
	if !r.Closed || r.Proof == nil || !nativeReadinessEffectsClosed(r) || !nativeReadinessProofMatches(r, a, *r.Proof) || r.Proof.ObservedAt.After(now) || !now.Before(r.Proof.ValidUntil) {
		return nil, errNativeReadinessRun
	}
	p := r.Proof.value()
	return &p, nil
}
