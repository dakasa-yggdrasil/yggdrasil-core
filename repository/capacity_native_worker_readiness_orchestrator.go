package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	lifecycle "github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativelifecycle"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/nativeworkerprobe"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func (s *nativeReadinessProducerState) produce(ctx context.Context, a model.CapacityNativeWorkerAttempt, w model.CapacityNativeWorkerGuestWitness) (*model.CapacityNativeWorkerReadinessProof, error) {
	if a.Physical == nil || a.PolicyID != s.journal.policy.ID || a.PolicyChecksum != s.journal.policy.Checksum || a.SourceCommit != s.journal.source || !capacity.NativeWorkerPhysicalValid(a, *a.Physical) {
		return nil, errNativeReadinessRun
	}
	if old, err := s.journal.read(ctx, a.ID); err == nil {
		if old.Closed {
			return nativeReadinessArchivedProof(old, a, time.Now().UTC())
		}
		if old.PendingProof != nil || !time.Now().Before(old.NotAfter) {
			cleaned, err := s.cleanup(ctx, a, old)
			if err != nil {
				return nil, err
			}
			if old.PendingProof == nil {
				_, _ = s.finishCleanup(ctx, cleaned)
				return nil, errNativeReadinessRun
			}
			closed, err := s.journal.finishWithProof(ctx, a, cleaned, old.PendingProof.value())
			if err != nil {
				return nil, err
			}
			return nativeReadinessArchivedProof(closed, a, time.Now().UTC())
		}
	}
	if !s.guestMatches(a, w, time.Now().UTC()) {
		return nil, errNativeReadinessRun
	}
	node, err := s.candidateNode(ctx, a)
	if err != nil {
		return nil, err
	}
	r, rawKeys, err := s.journal.open(ctx, a, nativeReadinessGenerateKeys)
	defer clear(rawKeys)
	if err != nil {
		return nil, err
	}
	keys, err := newNativeReadinessKeys(rawKeys)
	if err != nil {
		return nil, err
	}
	defer keys.close()
	for _, slot := range []string{"network_policy", "admission_secret", "floor_pod", "candidate_pod", "floor_service", "candidate_service"} {
		name := s.pins.FloorName
		if slot == "candidate_pod" {
			name = node.NodeName
		}
		plan, err := s.plan(r, slot, name)
		if err != nil {
			return nil, err
		}
		if slot == "admission_secret" {
			key, err := keys.admissionKey()
			if err != nil {
				return nil, err
			}
			plan.Data = map[string][]byte{"admission.key": key}
			defer clear(key)
		}
		r, err = s.ensure(ctx, a, r, plan, nil)
		if err != nil {
			return nil, err
		}
	}
	floor, candidate, fs, cs, err := s.awaitResources(ctx, a, r)
	if err != nil {
		return nil, err
	}
	fconfig, cconfig, err := s.configs(r, keys, floor, candidate, fs, cs)
	if err != nil {
		return nil, err
	}
	var floorSHA, candidateSHA string
	for _, row := range []struct {
		slot string
		c    nativeworkerprobe.Config
	}{{"floor_secret", fconfig}, {"candidate_secret", cconfig}} {
		data, sha, err := keys.secret(r, row.c)
		if err != nil {
			return nil, err
		}
		if row.slot == "floor_secret" {
			floorSHA = sha
		} else {
			candidateSHA = sha
		}
		plan, err := s.plan(r, row.slot, "")
		if err == nil {
			plan.Data = data
			r, err = s.ensure(ctx, a, r, plan, nil)
		}
		for _, raw := range data {
			clear(raw)
		}
		if err != nil {
			return nil, err
		}
	}
	var before nativeworkerprobe.StartupInspection
	if _, exists := nativeReadinessEffectIndex(r, "startup_challenge"); !exists {
		r, err = s.awaitInitialControl(ctx, r, keys, fconfig, cconfig, floorSHA, candidateSHA)
		if err != nil {
			return nil, err
		}
		r, err = s.startBatch(ctx, a, r, keys, fconfig, floorSHA, "initial")
		if err != nil {
			return nil, err
		}
		r, err = s.startBatch(ctx, a, r, keys, cconfig, candidateSHA, "initial")
		if err != nil {
			return nil, err
		}
		r, _, _, err = s.awaitReports(ctx, r, keys, fconfig, cconfig, floorSHA, candidateSHA, "initial")
		if err != nil {
			return nil, err
		}
		r, before, err = s.awaitStartup(ctx, r, keys, cconfig, candidateSHA, false)
		if err != nil {
			return nil, err
		}
		current, err := s.observe(ctx, a, r, "candidate_pod")
		if err != nil || nativeReadinessPod(r, a, s.profilePins(a), current, "candidate", false) != nil || !nativeReadinessSamePod(candidate, current) {
			return nil, errNativeReadinessRun
		}
		challenge := lifecycle.NativeAdmissionChallenge{NativeTerminationChallenge: lifecycle.NativeTerminationChallenge{SchemaVersion: 2, Namespace: s.config.Binding.Namespace, PodName: current.Resource.Name, PodUID: current.Resource.UID, WorkloadUID: current.Resource.UID, ContainerName: s.config.CoreWorkerTemplate.Name, ImageDigest: cconfig.Startup.ImageDigest, IntentGeneration: a.Generation, DrainNonce: uuid.NewSHA1(r.ID, []byte("startup-process-admission")).String(), IssuedAt: time.Now().UTC(), LaneRosterSHA256: before.LaneRosterSHA256}, ProcessNonce: before.ProcessNonce}
		raw, err := json.Marshal(challenge)
		if err != nil {
			return nil, err
		}
		plan, err := s.plan(r, "startup_challenge", node.NodeName)
		if err != nil {
			return nil, err
		}
		plan.Context.ExpectedUID, plan.Context.ExpectedResourceVersion = current.Resource.UID, current.Resource.ResourceVersion
		plan.Challenge = raw
		origin := &nativeReadinessOriginalStartupOrigin{Observation: current, Reader: s.config.Binding.ResourceReader}
		r, err = s.ensure(ctx, a, r, plan, origin)
		if err != nil {
			return nil, err
		}
	} else {
		original, err := s.journal.readOriginal(r, "startup_before")
		defer clear(original.Original)
		if err != nil || !original.Complete || original.Status != 200 || nativeReadinessDecodeControl(original.Original, &before) != nil {
			return nil, errNativeReadinessRun
		}
		r, err = s.recoverOriginal(ctx, r, "startup_challenge")
		if err != nil {
			return nil, err
		}
	}
	r, after, err := s.awaitStartup(ctx, r, keys, cconfig, candidateSHA, true)
	if err != nil || !nativeReadinessSameStartup(before, after) {
		return nil, errNativeReadinessRun
	}
	expectedChallenge, err := s.challengeSHA(r)
	if err != nil || expectedChallenge != after.ChallengeSHA256 {
		return nil, errNativeReadinessRun
	}
	r, err = s.startBatch(ctx, a, r, keys, fconfig, floorSHA, "final")
	if err != nil {
		return nil, err
	}
	r, err = s.startBatch(ctx, a, r, keys, cconfig, candidateSHA, "final")
	if err != nil {
		return nil, err
	}
	r, fr, cr, err := s.awaitReports(ctx, r, keys, fconfig, cconfig, floorSHA, candidateSHA, "final")
	if err != nil {
		return nil, err
	}
	lastFloor, lastCandidate, lastFS, lastCS, err := s.awaitResources(ctx, a, r)
	if err != nil || nativeReadinessPod(r, a, s.profilePins(a), lastCandidate, "candidate", true) != nil || !nativeReadinessSamePod(floor, lastFloor) || !nativeReadinessSamePod(candidate, lastCandidate) || fs.Resource.UID != lastFS.Resource.UID || cs.Resource.UID != lastCS.Resource.UID || fs.Service.ClusterIPv4 != lastFS.Service.ClusterIPv4 || cs.Service.ClusterIPv4 != lastCS.Service.ClusterIPv4 {
		return nil, errNativeReadinessRun
	}
	w, err = s.freshGuest(ctx, a)
	if err != nil {
		return nil, err
	}
	// Proof timestamps are the actual oldest final facts, not a new cleanup or
	// phase-Record clock. The early guest witness is never silently renewed.
	observed, err := nativeReadinessFinalObservedAt(w, fr, cr, after, lastFloor, lastCandidate, lastFS, lastCS)
	if err != nil {
		return nil, err
	}
	valid := observed.Add(s.pins.MaxAge)
	for _, t := range []time.Time{r.NotAfter, a.QualificationValidUntil} {
		if t.Before(valid) {
			valid = t
		}
	}
	networkEvidence, err := nativeReadinessDigest(struct {
		Guest                                                  model.CapacityNativeWorkerGuestWitness `json:"guest"`
		Floor, Candidate                                       nativeworkerprobe.Report
		FloorPod, CandidatePod, FloorService, CandidateService model.NativeWorkerProbeResourceObservation
	}{w, fr, cr, lastFloor, lastCandidate, lastFS, lastCS})
	if err != nil {
		return nil, err
	}
	warmupEvidence, err := nativeReadinessDigest(struct {
		Before, After           nativeworkerprobe.StartupInspection
		Candidate               model.NativeWorkerProbeResourceObservation
		Image, Source, Template string
	}{before, after, lastCandidate, s.config.Binding.CoreWorkerImage, s.config.Binding.CoreWorkerSourceCommit, s.config.Binding.StartupTemplateSHA256})
	if err != nil {
		return nil, err
	}
	proof := model.CapacityNativeWorkerReadinessProof{AttemptID: a.ID, NodeUID: a.NodeUID, ProviderID: a.Physical.ProviderID, WorkerIPv4: a.OverlayIPv4, BirthSHA256: a.BirthSHA256, Physical: *a.Physical, NetworkBindingSHA256: a.NetworkBindingSHA256, NetworkEvidenceSHA256: networkEvidence, WarmupEvidenceSHA256: warmupEvidence, PhysicalQualificationSHA256: a.QualificationEvidenceSHA256, ObservedAt: observed, ValidUntil: valid}
	r, err = s.journal.sealProof(ctx, a, r, proof)
	if err != nil {
		return nil, err
	}
	r, err = s.cleanup(ctx, a, r)
	if err != nil {
		return nil, err
	}
	r, err = s.journal.finishWithProof(ctx, a, r, proof)
	if err != nil {
		return nil, err
	}
	return nativeReadinessArchivedProof(r, a, time.Now().UTC())
}

// A fresh report GET cannot refresh old diagnostic frames. Final.StartedAt
// precedes every signed final record; AdmissionObservedAt is the retained final
// admission read bracketing readyz. There is no separate readyz timestamp in the
// delivered StartupInspection wire, so none is invented here.
func nativeReadinessFinalObservedAt(w model.CapacityNativeWorkerGuestWitness, floor, candidate nativeworkerprobe.Report, startup nativeworkerprobe.StartupInspection, resources ...model.NativeWorkerProbeResourceObservation) (time.Time, error) {
	if floor.Final.StartedAt == nil || candidate.Final.StartedAt == nil {
		return time.Time{}, errNativeReadinessRun
	}
	facts := []time.Time{w.ObservedAt, floor.ObservedAt, candidate.ObservedAt, *floor.Final.StartedAt, *candidate.Final.StartedAt, startup.ObservedAt, startup.AdmissionObservedAt}
	for _, resource := range resources {
		facts = append(facts, resource.ObservedAt)
	}
	observed := w.ObservedAt
	for _, fact := range facts {
		if fact.IsZero() {
			return time.Time{}, errNativeReadinessRun
		}
		if fact.Before(observed) {
			observed = fact
		}
	}
	return observed, nil
}

func (s *nativeReadinessProducerState) profilePins(a model.CapacityNativeWorkerAttempt) nativeReadinessObservationPins {
	pins := s.pins
	for _, p := range s.spec.NativeWorkerPoolBinding.Profiles {
		if p.Profile == a.Profile {
			pins.RegistrationBindingSHA256 = p.RegistrationBindingSHA
		}
	}
	return pins
}

func (s *nativeReadinessProducerState) freshGuest(ctx context.Context, a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerGuestWitness, error) {
	var zero model.CapacityNativeWorkerGuestWitness
	f := s.factories[a.Profile]
	if f == nil || !f.MatchesExecution(a.Execution) {
		return zero, errNativeReadinessRun
	}
	launch, err := nativeGuestStoredLaunch(ctx, s.journal.db, a)
	if err != nil {
		return zero, err
	}
	w, err := f.ReadGuestWitness(ctx, a, launch)
	if err != nil || !s.guestMatches(a, w, time.Now().UTC()) {
		return zero, errNativeReadinessRun
	}
	after, err := nativeGuestStoredLaunch(ctx, s.journal.db, a)
	if err != nil || !bytes.Equal(launch, after) {
		return zero, errNativeReadinessRun
	}
	return w, nil
}

func (s *nativeReadinessProducerState) guestMatches(a model.CapacityNativeWorkerAttempt, w model.CapacityNativeWorkerGuestWitness, now time.Time) bool {
	n := s.spec.NativeWorkerLifecycleBinding.Network
	return a.State == "registered" && w.Schema == "native_worker_guest_network_witness_v1" && w.AttemptID == a.ID.String() && w.LaunchSHA256 == a.LaunchSHA256 && w.BindingSHA256 == a.Physical.PhysicalBindingSHA256 && w.NetworkTemplateSHA256 == n.TemplateSHA256 && w.SystemSourceCommit == n.Template.GuestSystemSourceCommit && w.InterfaceName == "wg-dakasa" && w.MTU == 1380 && w.InterfaceUp && w.WorkerIPv4Present && w.FloorTLSVerified && !w.EndToEndPathMTUQualified && !w.IndependentNetworkQualified && !w.SchedulingAdmitted && !w.UsefulCapacityQualified && !w.ObservedAt.IsZero() && !w.ObservedAt.After(now) && now.Sub(w.ObservedAt) < s.pins.MaxAge
}

func (s *nativeReadinessProducerState) awaitResources(ctx context.Context, a model.CapacityNativeWorkerAttempt, r nativeReadinessRun) (model.NativeWorkerProbeResourceObservation, model.NativeWorkerProbeResourceObservation, model.NativeWorkerProbeResourceObservation, model.NativeWorkerProbeResourceObservation, error) {
	var f, c, fs, cs model.NativeWorkerProbeResourceObservation
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		var err error
		f, err = s.observe(ctx, a, r, "floor_pod")
		if err == nil {
			c, err = s.observe(ctx, a, r, "candidate_pod")
		}
		if err == nil {
			fs, err = s.observe(ctx, a, r, "floor_service")
		}
		if err == nil {
			cs, err = s.observe(ctx, a, r, "candidate_service")
		}
		if err == nil && nativeReadinessPod(r, a, s.profilePins(a), f, "floor", false) == nil && nativeReadinessPod(r, a, s.profilePins(a), c, "candidate", false) == nil && nativeReadinessService(r, s.pins, fs, f, "floor") == nil && nativeReadinessService(r, s.pins, cs, c, "candidate") == nil {
			return f, c, fs, cs, nil
		}
		if !time.Now().Before(r.NotAfter) {
			return f, c, fs, cs, errNativeReadinessRun
		}
		select {
		case <-ctx.Done():
			return f, c, fs, cs, errNativeReadinessRun
		case <-tick.C:
		}
	}
}

func (s *nativeReadinessProducerState) awaitStartup(ctx context.Context, r nativeReadinessRun, keys *nativeReadinessKeys, c nativeworkerprobe.Config, configSHA string, ready bool) (nativeReadinessRun, nativeworkerprobe.StartupInspection, error) {
	var out nativeworkerprobe.StartupInspection
	slot := "startup_before"
	if ready {
		slot = "startup_after"
	}
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		var err error
		r, err = s.readControl(ctx, r, keys, c, nativeworkerprobe.StartupPath, slot, &out)
		if err == nil && nativeReadinessStartup(c, configSHA, out, r, ready, time.Now().UTC()) {
			return r, out, nil
		}
		if ctx.Err() != nil || !time.Now().Before(r.NotAfter) {
			return r, out, errNativeReadinessRun
		}
		select {
		case <-ctx.Done():
			return r, out, errNativeReadinessRun
		case <-tick.C:
		}
	}
}

func (s *nativeReadinessProducerState) challengeSHA(r nativeReadinessRun) (string, error) {
	raw, err := s.journal.privateRequest(r, "startup_challenge")
	defer clear(raw)
	var steps []struct {
		Op    string `json:"op"`
		Path  string `json:"path"`
		Value string `json:"value"`
	}
	if err != nil || nativeReadinessDecodeControl(raw, &steps) != nil || len(steps) != 3 {
		return "", errNativeReadinessRun
	}
	sum := sha256.Sum256([]byte(steps[2].Value))
	return hex.EncodeToString(sum[:]), nil
}

func (s *nativeReadinessProducerState) finishCleanup(ctx context.Context, r nativeReadinessRun) (nativeReadinessRun, error) {
	return s.journal.edit(ctx, r, nil, func(current *nativeReadinessRun, _ time.Time) error {
		if current.PendingProof != nil {
			return errNativeReadinessRun
		}
		for _, e := range current.Effects {
			if nativeReadinessObjectKind(e.Kind) && e.State != "absent" {
				return errNativeReadinessRun
			}
		}
		current.Closed = true
		return nil
	})
}
