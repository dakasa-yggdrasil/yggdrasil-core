package repository

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/coreprocess"
	lifecycle "github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativelifecycle"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativeworkerprobe"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func (s *nativeReadinessProducerState) configs(r nativeReadinessRun, keys *nativeReadinessKeys, floor, candidate, floorService, candidateService model.NativeWorkerProbeResourceObservation) (nativeworkerprobe.Config, nativeworkerprobe.Config, error) {
	var zero nativeworkerprobe.Config
	cert, key, _, err := keys.leaf(r, 1, "controller", "")
	clear(key)
	if err != nil {
		return zero, zero, err
	}
	controllerSHA, err := nativeReadinessPEMFingerprint(cert)
	if err != nil {
		return zero, zero, err
	}
	roster, err := lifecycle.NativeTerminationRosterSHA256(coreprocess.WorkerLanes())
	if err != nil {
		return zero, zero, err
	}
	makeConfig := func(role string, own, other, ownService, otherService model.NativeWorkerProbeResourceObservation) nativeworkerprobe.Config {
		return nativeworkerprobe.Config{Schema: nativeworkerprobe.ConfigSchema, SourceCommit: s.config.Binding.ProbeSourceCommit, Identity: nativeworkerprobe.Identity{RunID: r.ID.String(), AttemptID: r.Identity.AttemptID.String(), BirthSHA256: r.Identity.BirthSHA256, PoolUID: r.Identity.PoolUID, Role: role, Namespace: s.config.Binding.Namespace, NamespaceUID: s.config.Binding.NamespaceUID, PodName: own.Resource.Name, PodUID: own.Resource.UID, PodIPv4: own.Pod.PodIPv4, ServiceUID: ownService.Resource.UID, ServiceClusterIPv4: ownService.Service.ClusterIPv4, NodeName: own.Node.Name, NodeUID: own.Node.UID}, Peer: nativeworkerprobe.Peer{PodUID: other.Resource.UID, NodeUID: other.Node.UID, PodIPv4: other.Pod.PodIPv4, ServiceUID: otherService.Resource.UID, ServiceClusterIPv4: otherService.Service.ClusterIPv4}, PodCIDR: s.pins.PodCIDR, ServiceCIDR: s.pins.ServiceCIDR, Nonce: base64.StdEncoding.EncodeToString(keys.seeds[6*ed25519.SeedSize : 7*ed25519.SeedSize]), NotBefore: r.CreatedAt, HardNotAfter: r.NotAfter, ControllerLeafSHA256: controllerSHA}
	}
	f := makeConfig("floor", floor, candidate, floorService, candidateService)
	c := makeConfig("candidate", candidate, floor, candidateService, floorService)
	c.Startup = &nativeworkerprobe.StartupConfig{CoreSourceCommit: s.config.Binding.CoreWorkerSourceCommit, ImageDigest: s.config.Binding.CoreWorkerImage[len(s.config.Binding.CoreWorkerImage)-71:], WorkloadUID: candidate.Resource.UID, ContainerName: s.config.CoreWorkerTemplate.Name, LaneRosterSHA256: roster}
	return f, c, nil
}

func (s *nativeReadinessProducerState) startBatch(ctx context.Context, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun, keys *nativeReadinessKeys, c nativeworkerprobe.Config, configSHA, batch string) (nativeReadinessRun, error) {
	slot := c.Identity.Role + "_" + batch
	if _, exists := nativeReadinessEffectIndex(r, slot); exists {
		return r, nil
	}
	path := nativeworkerprobe.InitialPath
	if batch == "final" {
		path = nativeworkerprobe.FinalPath
	} else if batch != "initial" {
		return r, errNativeReadinessRun
	}
	request, err := json.Marshal(struct {
		Method       string                     `json:"method"`
		Path         string                     `json:"path"`
		ConfigSHA256 string                     `json:"config_sha256"`
		Identity     nativeworkerprobe.Identity `json:"identity"`
	}{http.MethodPost, path, configSHA, c.Identity})
	if err != nil {
		return r, err
	}
	sha, err := nativeReadinessDigest(json.RawMessage(request))
	if err != nil {
		return r, err
	}
	r, err = s.journal.beginPrivateRequest(ctx, a, r, slot, sha, request, nil, nil)
	if err != nil {
		return r, err
	}
	var token string
	r, token, err = s.journal.redeem(ctx, a, r, slot)
	if err != nil {
		return r, err
	}
	status, raw, complete := nativeReadinessControl(ctx, keys, r, c, http.MethodPost, path)
	defer clear(raw)
	original := nativeReadinessReceiveControl(s.config.Binding.ResourceWriter.Name, r, slot, token, status, raw, complete)
	receiving, cancel := nativeReadinessCustodyContext(ctx)
	defer cancel()
	r, err = s.journal.captureOriginal(receiving, r, original)
	if err != nil || !complete || status != http.StatusAccepted || ctx.Err() != nil {
		return r, errNativeReadinessRun
	}
	return r, nil
}

func (s *nativeReadinessProducerState) readControl(ctx context.Context, r nativeReadinessRun, keys *nativeReadinessKeys, c nativeworkerprobe.Config, path, archiveSlot string, out any) (nativeReadinessRun, error) {
	status, raw, complete := nativeReadinessControl(ctx, keys, r, c, http.MethodGet, path)
	defer clear(raw)
	receiving, cancel := nativeReadinessCustodyContext(ctx)
	defer cancel()
	latest, err := s.journal.read(receiving, r.Identity.AttemptID)
	if err != nil {
		return r, err
	}
	next, err := s.journal.captureRead(receiving, latest, archiveSlot, status, raw, complete)
	if err != nil {
		return latest, errNativeReadinessRun
	}
	r = next
	if !complete || status != http.StatusOK || ctx.Err() != nil {
		return r, errNativeReadinessRun
	}
	if nativeReadinessDecodeControl(raw, out) != nil {
		return r, errNativeReadinessRun
	}
	return r, nil
}

func nativeReadinessDecodeControl(raw []byte, out any) error {
	// Same canonical recursive codec as resource originals, but only the safe
	// Source-defined report/inspection DTO is accepted by its typed caller.
	return capacity.DecodeNativeProbeResourceJSON(raw, out)
}

func (s *nativeReadinessProducerState) markBatch(ctx context.Context, r nativeReadinessRun, slot string, report nativeworkerprobe.Report) (nativeReadinessRun, error) {
	evidence, err := nativeReadinessDigest(report)
	if err != nil {
		return r, err
	}
	return s.journal.edit(ctx, r, nil, func(current *nativeReadinessRun, now time.Time) error {
		i, ok := nativeReadinessEffectIndex(*current, slot)
		if !ok {
			return errNativeReadinessRun
		}
		e := &current.Effects[i]
		if e.State == "observed" {
			return nil
		}
		if e.PrivateOriginal == nil || e.State != "received" || report.ObservedAt.After(now) {
			return errNativeReadinessRun
		}
		e.State, e.EvidenceSHA256, e.ObservedAt = "observed", evidence, report.ObservedAt
		return nil
	})
}

func (s *nativeReadinessProducerState) awaitReports(ctx context.Context, r nativeReadinessRun, keys *nativeReadinessKeys, f, c nativeworkerprobe.Config, fs, cs, batch string) (nativeReadinessRun, nativeworkerprobe.Report, nativeworkerprobe.Report, error) {
	var floor, candidate nativeworkerprobe.Report
	final := batch == "final"
	floorKey, err := keys.key(4)
	if err != nil {
		return r, floor, candidate, err
	}
	defer clear(floorKey)
	candidateKey, err := keys.key(5)
	if err != nil {
		return r, floor, candidate, err
	}
	defer clear(candidateKey)
	deadline := time.NewTimer(nativeworkerprobe.BatchDeadline)
	defer deadline.Stop()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		r, err = s.readControl(ctx, r, keys, f, nativeworkerprobe.ReportPath, "floor_report_"+batch, &floor)
		if err != nil {
			return r, floor, candidate, err
		}
		r, err = s.readControl(ctx, r, keys, c, nativeworkerprobe.ReportPath, "candidate_report_"+batch, &candidate)
		if err != nil {
			return r, floor, candidate, err
		}
		if nativeReadinessReport(f, fs, floor, floorKey.Public().(ed25519.PublicKey), candidateKey.Public().(ed25519.PublicKey), r, final, time.Now().UTC()) && nativeReadinessReport(c, cs, candidate, candidateKey.Public().(ed25519.PublicKey), floorKey.Public().(ed25519.PublicKey), r, final, time.Now().UTC()) {
			r, err = s.markBatch(ctx, r, "floor_"+batch, floor)
			if err == nil {
				r, err = s.markBatch(ctx, r, "candidate_"+batch, candidate)
			}
			return r, floor, candidate, err
		}
		if floor.Initial.State == "failed" || floor.Initial.State == "unknown" || candidate.Initial.State == "failed" || candidate.Initial.State == "unknown" || final && (floor.Final.State == "failed" || floor.Final.State == "unknown" || candidate.Final.State == "failed" || candidate.Final.State == "unknown") {
			return r, floor, candidate, errNativeReadinessRun
		}
		select {
		case <-ctx.Done():
			return r, floor, candidate, errNativeReadinessRun
		case <-deadline.C:
			return r, floor, candidate, errNativeReadinessRun
		case <-tick.C:
		}
	}
}
