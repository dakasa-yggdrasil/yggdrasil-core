package message

import (
	"context"
	"database/sql"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// No input carries prices, adapter choices, registry identity or worker count.
// Only fixed source binding names are dispatched to protected collectors.
func executeCapacityNativeWorkerBoundStep(ctx context.Context, db *sql.DB, policy model.Manifest, p model.CapacityPolicySpec, workflow model.Manifest, result model.WorkflowRunStepResult, read func(model.CapacityObservationAdapterBinding, string, map[string]any, any) (string, error), fail func(...error) model.WorkflowRunStepResult) model.WorkflowRunStepResult {
	if p.NativeWorkerPoolBinding == nil || p.MarketBinding == nil || result.Operation == "capacity.admit_bound" || result.Operation == "capacity.execute_bound" {
		// Worker execution requires the separate fenced market/provider lifecycle.
		// The legacy HPA executor never receives this new unit or authority.
		return fail()
	}
	observer := func(callCtx context.Context, actual model.Manifest) (*model.CapacityMarketAssessment, *model.CapacityNativeWorkerPoolObservation, error) {
		if actual.ID != policy.ID || actual.Checksum != policy.Checksum || callCtx.Err() != nil {
			return nil, nil, errCapacityBoundAssessment
		}
		pool, market, err := observeCapacityWorkerMarket(p, read, time.Now().UTC())
		return market, pool, err
	}
	a := model.CapacityAssessment{}
	for _, binding := range p.NativeWorkerPoolBinding.Signals {
		var metric model.CapacityMetricRangeObservation
		status, err := read(binding.Adapter, capacity.ObserveMetricRange, map[string]any{"binding": binding.BindingName}, &metric)
		if err != nil || status != "succeeded" {
			return fail(err)
		}
		evidence, err := capacity.BoundMetricEvidence(p, binding, metric, time.Now().UTC())
		if err != nil {
			return fail(err)
		}
		a.Evidence = append(a.Evidence, evidence)
	}
	if result.Operation == "capacity.assess_bound" {
		executor, _ := ctx.Value(capacityInvocationKey{}).(string)
		store := repository.CapacityStore{DB: db, WorkflowID: workflow.ID, ExecutorID: executor, MarketObserver: observer}
		intent, err := store.Assess(ctx, policy, a)
		if err != nil {
			return fail(err)
		}
		result.Metadata = map[string]any{"mode": "native_worker_pool_v1", "intent": intent, "provider_execution_enabled": false}
	} else {
		market, pool, err := observer(ctx, policy)
		if err != nil {
			return fail(err)
		}
		a.Market, a.NativeWorkerPool = market, pool
		a.Snapshot, err = capacity.NativeWorkerPoolSnapshot(p, pool, time.Now().UTC())
		if err != nil {
			return fail(err)
		}
		result.Metadata = map[string]any{"mode": "native_worker_pool_v1", "assessment": a, "provider_execution_enabled": false}
	}
	if capacityDispatchFence(ctx) != nil {
		return fail()
	}
	result.Status, result.Error, result.FinishedAt = "succeeded", "", time.Now().UTC()
	return result
}

func marketObservationAdapter(b model.CapacityMarketAdapterBinding) model.CapacityObservationAdapterBinding {
	return model.CapacityObservationAdapterBinding{IntegrationInstanceID: b.ManifestID, InstanceChecksum: b.Checksum, IntegrationTypeID: b.IntegrationTypeID, TypeChecksum: b.TypeChecksum}
}

func capacityMarketAdapterVersion(p model.CapacityPolicySpec, b model.CapacityObservationAdapterBinding) (int, bool) {
	if p.NativeWorkerPoolBinding != nil && marketObservationAdapter(p.NativeWorkerPoolBinding.Adapter) == b {
		return p.NativeWorkerPoolBinding.Adapter.Version, true
	}
	if p.MarketBinding != nil {
		for _, profile := range p.MarketBinding.Profiles {
			if marketObservationAdapter(profile.Adapter) == b {
				return profile.Adapter.Version, true
			}
		}
	}
	return 0, false
}

func observeCapacityWorkerMarket(p model.CapacityPolicySpec, read func(model.CapacityObservationAdapterBinding, string, map[string]any, any) (string, error), now time.Time) (*model.CapacityNativeWorkerPoolObservation, *model.CapacityMarketAssessment, error) {
	b := p.NativeWorkerPoolBinding
	if b == nil || p.MarketBinding == nil {
		return nil, nil, errCapacityBoundAssessment
	}
	var pool model.CapacityNativeWorkerPoolObservation
	status, err := read(marketObservationAdapter(b.Adapter), capacity.ObserveNativeWorkerPool, map[string]any{"binding_name": b.Name}, &pool)
	if err != nil || status != "observed" || pool.Adapter != b.Adapter {
		return nil, nil, errCapacityBoundAssessment
	}
	if _, err = capacity.NativeWorkerPoolSnapshot(p, &pool, now); err != nil {
		return nil, nil, err
	}
	market := &model.CapacityMarketAssessment{Schema: capacity.CapacityMarketMode, Currency: p.Currency, HorizonSeconds: p.MarketBinding.HorizonSeconds, ObservedAt: now, ValidUntil: now.Add(time.Duration(p.MarketBinding.MaxQuoteAgeSeconds) * time.Second), Profiles: []model.CapacityMarketProfileQuote{}, Unavailable: []model.CapacityMarketUnavailableProfile{}}
	for _, binding := range p.MarketBinding.Profiles {
		var quote model.CapacityMarketProfileQuote
		status, err = read(marketObservationAdapter(binding.Adapter), capacity.ObserveComputeOffer, map[string]any{"binding_name": binding.Profile}, &quote)
		if err != nil || status != "observed" || quote.Adapter != binding.Adapter || quote.Profile != binding.Profile || quote.Currency != p.Currency {
			reason := "collector_contract_refused"
			if err != nil {
				reason = "collector_unavailable"
			}
			market.Unavailable = append(market.Unavailable, model.CapacityMarketUnavailableProfile{Profile: binding.Profile, Provider: binding.Provider, Region: binding.Region, Adapter: binding.Adapter, Reason: reason, ObservedAt: time.Now().UTC()})
			continue
		}
		market.Profiles = append(market.Profiles, quote)
	}
	return &pool, market, nil
}
