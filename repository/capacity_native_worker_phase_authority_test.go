package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

type phaseAuthorityTestRuntime struct {
	*nativeAttemptRuntime
	header      model.CapacityNativeWorkerPhaseReadObservation
	probeDB     *sql.DB
	reads       int
	legacyReads int
}

func (r *phaseAuthorityTestRuntime) ObserveAuthority(context.Context, model.Manifest) (*model.CapacityNativeWorkerPoolObservation, error) {
	r.legacyReads++
	return nil, errors.New("phase authority must not synthesize a useful pool")
}

func (r *phaseAuthorityTestRuntime) ObservePhaseAuthority(ctx context.Context, _ model.Manifest) (*model.CapacityNativeWorkerPhaseReadObservation, error) {
	r.reads++
	if r.probeDB != nil {
		// The PG fixture has exactly one connection. This independently acquired
		// query can finish only before the worker store opens its transaction.
		var one int
		if err := r.probeDB.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil || one != 1 {
			return nil, errors.New("authority read ran under the worker transaction")
		}
	}
	return &r.header, nil
}

func phaseAuthorityTestBinding(p *model.CapacityPolicySpec) {
	adapter := p.NativeWorkerLifecycleBinding.Profiles[0].Adapter
	adapter.ManifestID = uuid.NewString() // Separate read-only instance.
	p.NativeWorkerLifecycleBinding.PhaseObserver = &model.CapacityNativeWorkerPhaseReadBinding{
		Mode: capacity.NativeWorkerPhaseReadMode, Name: "ci-phase-read", Adapter: adapter,
		SourceCommit: strings.Repeat("d", 40), ScopeSHA256: strings.Repeat("e", 64),
		RealmNamespace: "infra", MaxAgeSeconds: 30,
		QuarantineTaintKey: "dakasa.io/native-worker-unadmitted",
	}
}

func phaseAuthorityTestHeader(p model.CapacityPolicySpec) model.CapacityNativeWorkerPhaseReadObservation {
	b, pool := p.NativeWorkerLifecycleBinding.PhaseObserver, p.NativeWorkerPoolBinding
	profile := pool.Profiles[0]
	return model.CapacityNativeWorkerPhaseReadObservation{
		Schema: b.Mode, SourceCommit: b.SourceCommit, Adapter: b.Adapter, BindingName: b.Name,
		BindingScopeSHA256: b.ScopeSHA256, ObservedAt: time.Now().UTC(), Complete: true,
		FullCollectionComplete: true, CollectionResourceVersion: "81", RegistryRegistrationsComplete: true,
		EvidenceSHA256: strings.Repeat("f", 64),
		Registry: model.CapacityNativeWorkerPhaseRegistry{Ref: pool.RegistryRef, RealmNamespace: b.RealmNamespace,
			RealmUID: pool.RealmUID, PoolUID: pool.PoolUID, Owner: pool.Owner, Epoch: pool.ExpectedPoolEpoch,
			CurrentProfile: profile.Profile, ResourceVersion: "31", AnnotationSHA256: strings.Repeat("a", 64)},
		// A real quarantined registration remains visible. This header is not an
		// empty NativeWorkerPoolObservation and does not grant useful capacity.
		Registrations: []model.CapacityNativeWorkerRegistryEntry{{NodeUID: uuid.NewString(),
			ProviderID: profile.ProviderIDPrefix + "987654", Profile: profile.Profile,
			PhysicalSpecSHA256: profile.PhysicalSpecSHA256, RegistrationBindingSHA256: profile.RegistrationBindingSHA,
			CapacityPolicyID: uuid.NewString(), IntentGeneration: 1, FencingToken: 1,
			CreationProofSHA256: strings.Repeat("b", 64), Admission: model.CapacityNativeWorkerRegistryAdmission{State: "quarantined"}}},
		Candidates: []model.CapacityNativeWorkerPhaseCandidate{},
	}
}

func TestNativeWorkerPhaseAuthorityPostgresBeforeTransaction(t *testing.T) {
	f, s, base, authority := nativeAttemptFixture(t, phaseAuthorityTestBinding)
	f.db.SetMaxOpenConns(1)
	r := &phaseAuthorityTestRuntime{nativeAttemptRuntime: base, header: phaseAuthorityTestHeader(f.p), probeDB: f.db}
	s.Runtime = r
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	a, err := s.Reserve(ctx, f.policy, authority)
	if err != nil || a.State != "reserved" || r.reads != 1 || r.legacyReads != 0 {
		t.Fatalf("phase authority was not independently received before transaction: state=%s reads=%d legacy=%d err=%v", a.State, r.reads, r.legacyReads, err)
	}
	if len(r.header.Registrations) != 1 || r.header.MutationAuthorized || r.header.UsefulCapacityQualified {
		t.Fatal("phase header was replaced by a fabricated empty/useful snapshot")
	}

	// Retaining a producer-owned pointer would let later callback activity
	// silently rewrite the already authenticated authority inside current().
	owned, err := s.authenticate(ctx, f.policy)
	if err != nil || owned.phaseAuthority == nil || owned.authority != nil {
		t.Fatal("separate phase authority was not retained", err)
	}
	r.header.Registry.Owner = "producer-mutated-owner"
	r.header.Registrations[0].NodeUID = uuid.NewString()
	if owned.phaseAuthority.Registry.Owner != f.p.Owner || owned.phaseAuthority.Registrations[0].NodeUID == r.header.Registrations[0].NodeUID {
		t.Fatal("producer pointer or nested registry slice survived authentication")
	}
	reads := r.reads
	owned.phaseAuthority.Registry.Epoch++
	if _, err = owned.current(ctx, nil, f.policy, f.p, authority, time.Now().UTC()); !errors.Is(err, ErrCapacityLease) || r.reads != reads {
		t.Fatal("current did not refuse changed authority before SQL without SDK reads", err)
	}

	// Invalid headers must be rejected before BeginTx; a mock database with no
	// expectations refuses any query/transaction rather than hiding an effect.
	for _, change := range []func(*model.CapacityNativeWorkerPhaseReadObservation){
		func(o *model.CapacityNativeWorkerPhaseReadObservation) { o.CandidateSelected = true },
		func(o *model.CapacityNativeWorkerPhaseReadObservation) {
			o.BindingScopeSHA256 = strings.Repeat("0", 64)
		},
		func(o *model.CapacityNativeWorkerPhaseReadObservation) { o.SourceCommit = strings.Repeat("0", 40) },
		func(o *model.CapacityNativeWorkerPhaseReadObservation) { o.Registry.Epoch++ },
		func(o *model.CapacityNativeWorkerPhaseReadObservation) { o.ObservedAt = time.Now().Add(-time.Hour) },
	} {
		db, mock, err := sqlmock.New()
		if err != nil {
			t.Fatal(err)
		}
		bad := s
		bad.Capacity.DB = db
		r.probeDB, r.header = nil, phaseAuthorityTestHeader(f.p)
		change(&r.header)
		_, err = bad.Reserve(ctx, f.policy, authority)
		if !errors.Is(err, ErrCapacityConflict) || mock.ExpectationsWereMet() != nil {
			t.Fatal("invalid phase authority reached transaction or another error path", err)
		}
		db.Close()
	}

	// Source without the optional port refuses; it never falls back to the
	// old useful-pool snapshot when a PhaseObserver binding is installed.
	s.Runtime = base
	if _, err = s.authenticate(ctx, f.policy); !errors.Is(err, ErrCapacityDisabled) {
		t.Fatal("missing phase authority port fell back to old pool", err)
	}
	legacy := f.policy
	p := f.p
	p.NativeWorkerLifecycleBinding.PhaseObserver = nil
	legacy.Spec, _ = json.Marshal(p)
	if got, err := s.authenticate(ctx, legacy); err != nil || got.authority == nil || got.phaseAuthority != nil {
		t.Fatal("legacy authority-only path changed", err)
	}
}
