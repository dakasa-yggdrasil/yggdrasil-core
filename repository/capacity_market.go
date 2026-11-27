package repository

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

// WAN observations run before BeginTx; only this server-installed callback may
// replace caller fields. The complete batch is checked again at database time.
func (s CapacityStore) observeMarketAssessment(ctx context.Context, policy model.Manifest, a model.CapacityAssessment) (model.CapacityAssessment, error) {
	p, err := parseCapacityPolicy(policy)
	if err != nil {
		return a, err
	}
	if p.MarketBinding == nil {
		if a.Market != nil || a.NativeWorkerPool != nil {
			return a, fmt.Errorf("market observations require protected policy binding")
		}
		return a, nil
	}
	if s.MarketObserver == nil {
		return a, fmt.Errorf("protected server market observer unavailable")
	}
	a.Market, a.NativeWorkerPool, err = s.MarketObserver(ctx, policy)
	if err != nil {
		return a, err
	}
	if err = ctx.Err(); err != nil {
		return a, err
	}
	a.Snapshot, err = capacity.NativeWorkerPoolSnapshot(p, a.NativeWorkerPool, time.Now().UTC())
	return a, err
}

func marketReservationKey(i model.CapacityIntent) string {
	return fmt.Sprintf("%s/%d", i.PolicyID, i.Generation)
}

func lockCapacityMarketTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec) error {
	// Every writer participates before its logical scope lock. Market claims
	// exclude possible legacy starts while inspecting shared account quotas.
	// Legacy writers retain their existing logical/native-UID concurrency:
	// serializing them all here would bypass their original lock handshake.
	query := `SELECT pg_advisory_xact_lock_shared(hashtextextended('capacity-market-shared-reservations-v1', 0))`
	if p.MarketBinding != nil {
		query = `SELECT pg_advisory_xact_lock(hashtextextended('capacity-market-shared-reservations-v1', 0))`
	}
	_, err := tx.ExecContext(ctx, query)
	return err
}

// Called only after the global market advisory lock and logical pool lock.
// No lease expiry turns a possible provider start into free quota.
func (s CapacityStore) marketLedgerTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, a model.CapacityAssessment, now time.Time) (capacity.MarketLedgerObservation, error) {
	var ledger capacity.MarketLedgerObservation
	if p.MarketBinding == nil {
		return ledger, nil
	}
	if p.NativeWorkerPoolBinding == nil {
		return ledger, fmt.Errorf("market requires authoritative native pool")
	}
	if err := marketCatalogCurrentTx(ctx, tx, p); err != nil {
		return ledger, err
	}
	snapshot, err := capacity.NativeWorkerPoolSnapshot(p, a.NativeWorkerPool, now)
	if err != nil || snapshot != a.Snapshot {
		return ledger, fmt.Errorf("native pool snapshot no longer exact or fresh")
	}
	ledger = capacity.MarketLedgerObservation{Complete: true, ObservedAt: now, TargetIdentity: p.TargetIdentity, Owner: p.Owner, BudgetScope: p.MarketBinding.BudgetScope, CurrentProfile: snapshot.Profile, CurrentUnits: snapshot.Units, CurrentPoolEpoch: p.NativeWorkerPoolBinding.ExpectedPoolEpoch}
	rows, err := tx.QueryContext(ctx, `SELECT intent FROM public.capacity_intents WHERE intent ? 'market_reservation' LIMIT 100001`)
	if err != nil {
		return ledger, err
	}
	covered := map[string]bool{}
	count := 0
	for rows.Next() {
		count++
		var raw []byte
		var intent model.CapacityIntent
		if count > 100000 {
			rows.Close()
			return ledger, fmt.Errorf("market ledger collection bound exceeded")
		}
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return ledger, err
		}
		if err = json.Unmarshal(raw, &intent); err != nil {
			rows.Close()
			return ledger, err
		}
		if !pendingCapacityPhase(intent.Phase) || intent.Phase == "proposed" {
			continue
		}
		if err = appendMarketReservation(&ledger, p, intent.MarketReservation); err != nil {
			rows.Close()
			return ledger, err
		}
		covered[marketReservationKey(intent)] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ledger, err
	}
	if err = appendNativeAttemptReservationsTx(ctx, tx, &ledger, p, covered); err != nil {
		return ledger, err
	}
	// Open legacy/unknown sends can share an account quota. When they cannot
	// be assigned an already-counted reservation, quantity remains UNKNOWN.
	rows, err = tx.QueryContext(ctx, `SELECT g.namespace,g.environment,g.domain,g.dimension,g.grant_record,(SELECT m.spec FROM public.manifests m WHERE m.id=(g.grant_record->>'policy_id')::uuid AND m.kind='capacity_policy') FROM public.capacity_mutation_grants g WHERE `+capacityGrantUndisposedSQL+` AND state IN ('issued','redeemed','settled','compensating') LIMIT 100001`)
	if err != nil {
		return ledger, err
	}
	count = 0
	for rows.Next() {
		count++
		var raw []byte
		var realm marketGrantRealm
		var parent sql.NullString
		var grant capacityMutationRecord
		if count > 100000 {
			rows.Close()
			return ledger, fmt.Errorf("market grant collection bound exceeded")
		}
		if err = rows.Scan(&realm.Namespace, &realm.Environment, &realm.Domain, &realm.Dimension, &raw, &parent); err != nil {
			rows.Close()
			return ledger, err
		}
		if err = json.Unmarshal(raw, &grant); err != nil {
			rows.Close()
			return ledger, err
		}
		if grant.Grant.State == "issued" && !grant.Grant.ExpiresAt.After(now) {
			continue
		}
		key := fmt.Sprintf("%s/%d", grant.PolicyID, grant.Generation)
		if covered[key] {
			continue
		}
		if err = appendLegacyMarketGrant(&ledger, p, grant, realm, []byte(parent.String)); err != nil {
			rows.Close()
			return ledger, err
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ledger, err
	}
	if err = marketNativeBirthsTx(ctx, tx, policy, p, a.NativeWorkerPool); err != nil {
		return ledger, err
	}
	return ledger, nil
}

func appendMarketReservation(ledger *capacity.MarketLedgerObservation, p model.CapacityPolicySpec, r *model.CapacityMarketReservation) error {
	if r == nil || r.Schema != capacity.CapacityMarketMode || r.BudgetScope == "" || r.Units < 0 || r.CostMicros < 0 || r.Profile == "" || r.Provider == "" || r.Region == "" || !capacity.ValidDigest(r.QuoteEvidenceSHA256) || r.ObservedAt.IsZero() || len(r.Quotas) == 0 {
		return fmt.Errorf("invalid or unknown persisted market reservation")
	}
	if r.BudgetScope == p.MarketBinding.BudgetScope {
		if r.Currency != p.Currency || r.HorizonSeconds != p.MarketBinding.HorizonSeconds {
			if p.MarketBinding.BudgetMode == "bounded_total" {
				ledger.UnknownReservations = true
			}
		} else {
			if r.CostMicros > math.MaxInt64-ledger.ReservedCostMicros {
				return fmt.Errorf("reserved cost overflow")
			}
			ledger.ReservedCostMicros += r.CostMicros
		}
	}
	seen := map[string]bool{}
	for _, q := range r.Quotas {
		key := q.Provider + "/" + q.Region + "/" + q.Scope + "/" + q.Dimension
		if q.Provider != r.Provider || q.Region != r.Region || q.Scope == "" || q.Dimension == "" || q.Amount < 0 || seen[key] {
			return fmt.Errorf("invalid persisted quota reservation")
		}
		seen[key] = true
		if marketQuotaRelevant(p, q.Provider, q.Region, q.Scope, q.Dimension) {
			ledger.QuotaReservations = append(ledger.QuotaReservations, q)
		}
	}
	return nil
}

type marketGrantRealm struct{ Namespace, Environment, Domain, Dimension string }

func sameCapacityAssessmentResources(p model.CapacityPolicySpec, a, b model.CapacityAssessment) bool {
	if p.NativeWorkerPoolBinding == nil {
		return sameCapacityResources(a.Snapshot, b.Snapshot)
	}
	if !sameCapacityResourceIdentity(a.Snapshot, b.Snapshot) {
		return false
	}
	left, e1 := capacity.NativeWorkerPoolSemanticFingerprint(a.NativeWorkerPool)
	right, e2 := capacity.NativeWorkerPoolSemanticFingerprint(b.NativeWorkerPool)
	return e1 == nil && e2 == nil && left == right
}

func marketQuotaRelevant(p model.CapacityPolicySpec, provider, region, scope, dimension string) bool {
	for _, profile := range p.MarketBinding.Profiles {
		if profile.Provider == provider && profile.Region == region {
			for _, q := range profile.QuotaDimensions {
				if q.Scope == scope && q.Dimension == dimension {
					return true
				}
			}
		}
	}
	return false
}

func appendLegacyMarketGrant(ledger *capacity.MarketLedgerObservation, p model.CapacityPolicySpec, g capacityMutationRecord, realm marketGrantRealm, parentRaw []byte) error {
	if g.Grant.Capability == g.Binding.DestroyCapability && g.Binding.DestroyCapability != "" {
		return nil
	}
	var parent model.CapacityPolicySpec
	if len(parentRaw) == 0 || json.Unmarshal(parentRaw, &parent) != nil || parent.Environment != realm.Environment || parent.Domain != realm.Domain || parent.Dimension != realm.Dimension {
		if g.EventProvider == "" {
			ledger.UnknownReservations = true
		} else {
			ledger.UnknownQuotaScopes = append(ledger.UnknownQuotaScopes, capacity.MarketQuotaUnknownScope{Provider: g.EventProvider})
		}
		return nil
	}
	var original *model.CapacityProfile
	for i := range parent.Profiles {
		if parent.Profiles[i].Name == g.Binding.ProfileName {
			original = &parent.Profiles[i]
		}
	}
	if original == nil || (g.EventProvider != "" && g.EventProvider != original.Provider) {
		if g.EventProvider == "" {
			ledger.UnknownReservations = true
		} else {
			ledger.UnknownQuotaScopes = append(ledger.UnknownQuotaScopes, capacity.MarketQuotaUnknownScope{Provider: g.EventProvider})
		}
		return nil
	}
	relevant := false
	for _, profile := range p.MarketBinding.Profiles {
		if profile.Provider == original.Provider && profile.Region == original.Region {
			relevant = true
		}
	}
	if !relevant {
		return nil
	} // Immutable parent proves a different provider/region.
	var mapping *model.CapacityMarketLegacyAllocatorBinding
	for i := range p.MarketBinding.LegacyAllocators {
		m := &p.MarketBinding.LegacyAllocators[i]
		if m.IntegrationInstanceID == g.Binding.IntegrationInstanceID && m.ScopeChecksum == g.Binding.ScopeChecksum && m.ProfileName == g.Binding.ProfileName && m.Namespace == realm.Namespace && m.Environment == realm.Environment && m.Domain == realm.Domain && m.Dimension == realm.Dimension {
			mapping = m
		}
	}
	if mapping == nil {
		ledger.UnknownQuotaScopes = append(ledger.UnknownQuotaScopes, capacity.MarketQuotaUnknownScope{Provider: original.Provider, Region: original.Region})
		return nil
	}
	for _, q := range mapping.Quotas {
		if q.Provider != original.Provider || q.Region != original.Region {
			return fmt.Errorf("legacy quota mapping disagrees with immutable parent provider/region")
		}
		if marketQuotaRelevant(p, q.Provider, q.Region, q.Scope, q.Dimension) {
			ledger.QuotaReservations = append(ledger.QuotaReservations, capacity.MarketQuotaReservation{Provider: q.Provider, Region: q.Region, Scope: q.Scope, Dimension: q.Dimension, Amount: q.PerUnit})
		}
	}
	// A verified account mapping cannot silently omit another quota dimension
	// required for the same account scope (for example vCPU versus IPv4).
	for _, profile := range p.MarketBinding.Profiles {
		if profile.Provider != original.Provider || profile.Region != original.Region {
			continue
		}
		for _, required := range profile.QuotaDimensions {
			scopeKnown, dimensionKnown := false, false
			for _, q := range mapping.Quotas {
				if q.Scope == required.Scope {
					scopeKnown = true
					if q.Dimension == required.Dimension {
						dimensionKnown = true
					}
				}
			}
			if scopeKnown && !dimensionKnown {
				ledger.UnknownQuotaScopes = append(ledger.UnknownQuotaScopes, capacity.MarketQuotaUnknownScope{Provider: original.Provider, Region: original.Region, Scope: required.Scope, Dimension: required.Dimension})
			}
		}
	}
	return nil
}

func marketCatalogCurrentTx(ctx context.Context, tx *sql.Tx, p model.CapacityPolicySpec) error {
	bindings := []model.CapacityMarketAdapterBinding{p.NativeWorkerPoolBinding.Adapter}
	for _, profile := range p.MarketBinding.Profiles {
		bindings = append(bindings, profile.Adapter)
	}
	for _, b := range bindings {
		var good bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.manifests i JOIN public.manifests t ON t.id=$4::uuid WHERE i.id=$1::uuid AND i.kind='integration_instance' AND i.active AND i.version=$2 AND i.checksum=$3 AND t.kind='integration_type' AND t.active AND t.checksum=$5)`, b.ManifestID, b.Version, b.Checksum, b.IntegrationTypeID, b.TypeChecksum).Scan(&good); err != nil {
			return err
		}
		if !good {
			return fmt.Errorf("protected market catalog revision is no longer active")
		}
	}
	return nil
}

// Native registration labels never self-authorize a birth. Each must join a
// durable historical provider creation proof in the same logical pool scope.
type marketNativeBirthKey struct {
	PolicyID                            string
	Generation, Fence                   int64
	Profile, Resource, Adapter, Receipt string
}

func marketNativeBirthsTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, o *model.CapacityNativeWorkerPoolObservation) error {
	if len(o.Nodes) == 0 {
		return nil
	}
	if p.NativeWorkerLifecycleBinding != nil {
		return marketNativeAttemptBirthsTx(ctx, tx, policy, p, o)
	}
	// One complete bounded read joins every current Node; no per-Node SQL/WAN.
	rows, err := tx.QueryContext(ctx, `SELECT grant_record FROM public.capacity_mutation_grants WHERE namespace=$1 AND environment=$2 AND domain=$3 AND dimension=$4 AND state='confirmed' LIMIT 100001`, policy.Metadata.Namespace, p.Environment, p.Domain, p.Dimension)
	if err != nil {
		return err
	}
	defer rows.Close()
	births := map[marketNativeBirthKey]bool{}
	count := 0
	for rows.Next() {
		count++
		if count > 100000 {
			return fmt.Errorf("native birth lookup bound exceeded")
		}
		var raw []byte
		var record capacityMutationRecord
		if err = rows.Scan(&raw); err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &record); err != nil {
			return err
		}
		if record.Proof == nil || record.Grant.Capability != record.Binding.EnsureCapability || record.Proof.ResourceAbsent || !record.Proof.OwnerVerified || !record.Proof.SpecVerified {
			continue
		}
		proof, _ := json.Marshal(record.Proof)
		births[marketNativeBirthKey{record.PolicyID.String(), record.Generation, record.FencingToken, record.Binding.ProfileName, record.Proof.ResourceID, record.Binding.IntegrationInstanceID, fmt.Sprintf("%x", sha256.Sum256(proof))}] = true
	}
	if err = rows.Err(); err != nil {
		return err
	}
	adapters := map[string]string{}
	for _, profile := range p.MarketBinding.Profiles {
		adapters[profile.Profile] = profile.Adapter.ManifestID
	}
	for _, node := range o.Nodes {
		resource := node.ProviderID[strings.LastIndex(node.ProviderID, "/")+1:]
		if !births[marketNativeBirthKey{node.CapacityPolicyID, node.IntentGeneration, node.FencingToken, node.Profile, resource, adapters[node.Profile], node.RegistrationReceiptSHA256}] {
			return fmt.Errorf("native worker has no exact persisted creation/registration birth")
		}
	}
	return nil
}
