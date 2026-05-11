package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	rpcamqp "github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc/amqp"
)

const (
	queueProductMaterialize               = "yggdrasil-core.product.materialize"
	queueProductInstallationReconcile     = "yggdrasil-core.product.installation.reconcile"
	queueProductInstallationApply         = "yggdrasil-core.product.installation.apply"
	queueProductInstallationObserve       = "yggdrasil-core.product.installation.observe"
	queueProductInstallationUninstall     = "yggdrasil-core.product.installation.uninstall"
	queueProductInstallationStateDiscover = "yggdrasil-core.product.installation_state.discover"
)

func productConsumers(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) []ConsumerConfig {
	return []ConsumerConfig{
		{
			Queue:   queueProductMaterialize,
			Timeout: 30 * time.Second,
			QoS:     5,
			Handler: productMaterializeHandler(conn, db, logger),
		},
		{
			Queue:   queueProductInstallationReconcile,
			Timeout: 30 * time.Second,
			QoS:     5,
			Handler: productReconcileInstallationHandler(conn, db, logger),
		},
		{
			Queue:   queueProductInstallationApply,
			Timeout: 30 * time.Second,
			QoS:     5,
			Handler: productApplyInstallationHandler(conn, db, logger),
		},
		{
			Queue:   queueProductInstallationObserve,
			Timeout: 30 * time.Second,
			QoS:     5,
			Handler: productObserveInstallationHandler(conn, db, logger),
		},
		{
			Queue:   queueProductInstallationUninstall,
			Timeout: 30 * time.Second,
			QoS:     5,
			Handler: productUninstallInstallationHandler(conn, db, logger),
		},
		{
			Queue:   queueProductInstallationStateDiscover,
			Timeout: 30 * time.Second,
			QoS:     5,
			Handler: productDiscoverInstallationStateHandler(conn, db, logger),
		},
	}
}

func productMaterializeHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.MaterializeProductRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		productManifest, err := resolveManifestForKind(ctx, db, "product", req.Product.ManifestID, req.Product.Namespace, req.Product.Name, req.Product.Version)
		if err != nil {
			return replyFailure(ctx, d, manifestLookupErrorCode(err), err, logger)
		}

		spec, err := manifestengine.ParseProductSpec(productManifest.Spec)
		if err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		materializedSpec, components, err := manifestengine.MaterializeProductSpec(
			ctx,
			manifestReferenceFromRecord(productManifest),
			spec,
			rabbitMQProductGenerator{
				conn:   conn,
				db:     db,
				logger: logger,
			},
		)
		if err != nil {
			return replyFailure(ctx, d, integrationAwareErrorCode(err, "materialization_failed"), err, logger)
		}

		record, err := repository.CreateProductMaterialization(ctx, db, productManifest, materializedSpec, components)
		if err != nil {
			return replyFailure(ctx, d, "internal_error", err, logger)
		}

		return replySuccess(ctx, d, model.MaterializeProductResponse{
			Materialization: record,
		}, logger)
	}
}

func productReconcileInstallationHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.ReconcileProductInstallationRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		productManifest, spec, err := resolveProductManifestSpec(ctx, db, req.Product)
		if err != nil {
			return replyFailure(ctx, d, manifestLookupErrorCode(err), err, logger)
		}

		planner := newProductInstallationPlanner(conn, db, logger)
		results, err := planner.planProductReconciliation(ctx, productManifest, spec)
		if err != nil {
			return replyFailure(ctx, d, integrationAwareErrorCode(err, "reconcile_failed"), err, logger)
		}

		return replySuccess(ctx, d, model.ReconcileProductInstallationResponse{
			Product: manifestReferenceFromRecord(productManifest),
			Results: results,
		}, logger)
	}
}

func productDiscoverInstallationStateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.DiscoverProductInstallationStateRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		productManifest, spec, err := resolveProductManifestSpec(ctx, db, req.Product)
		if err != nil {
			return replyFailure(ctx, d, manifestLookupErrorCode(err), err, logger)
		}

		productRef := manifestReferenceFromRecord(productManifest)
		results := make([]model.ProductInstallationStateResult, 0, len(spec.Components))
		for _, component := range spec.Components {
			sourceKind := strings.ToLower(strings.TrimSpace(component.Source.Kind))
			if sourceKind != "integration" {
				// Discover state for non-integration sources (git, oci,
				// inline) is not yet implemented — would need to render
				// then observe each rendered object. Emit a typed
				// result instead of silently skipping so callers see
				// the gap.
				results = append(results, model.ProductInstallationStateResult{
					Name:      component.Name,
					Operation: "discover",
					Status:    "unsupported_source_kind",
					Observed:  false,
					Metadata:  map[string]any{"source_kind": component.Source.Kind, "note": "discover for non-integration source not implemented; render-then-observe pattern pending"},
				})
				continue
			}

			result, err := discoverIntegrationComponentState(ctx, conn, db, productRef, spec, component)
			if err != nil {
				return replyFailure(ctx, d, integrationAwareErrorCode(err, "discover_failed"), err, logger)
			}
			results = append(results, result)
		}

		return replySuccess(ctx, d, model.DiscoverProductInstallationStateResponse{
			Product: productRef,
			Results: results,
		}, logger)
	}
}

func productApplyInstallationHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.ApplyProductInstallationRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		productManifest, spec, err := resolveProductManifestSpec(ctx, db, req.Product)
		if err != nil {
			return replyFailure(ctx, d, manifestLookupErrorCode(err), err, logger)
		}

		// Validate target overrides against the Product components.
		// A key in target_overrides that doesn't match any component is
		// likely a typo and rejected loudly.
		if err := validateTargetOverrides(req.TargetOverrides, spec); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		executor := newProductTargetExecutor(conn, db, logger).withTargetOverrides(req.TargetOverrides)
		results, err := executor.applyProduct(ctx, productManifest, spec)
		if err != nil {
			return replyFailure(ctx, d, integrationAwareErrorCode(err, "apply_failed"), err, logger)
		}

		// Emit product.installation.applied event (best-effort, post-apply).
		// The event payload includes target_overrides_used so the audit
		// trail records which targets were rewritten at apply time.
		emitProductInstallationAppliedEvent(ctx, db, logger, productManifest, spec, results, req.TargetOverrides)

		return replySuccess(ctx, d, model.ApplyProductInstallationResponse{
			Product: manifestReferenceFromRecord(productManifest),
			Results: results,
		}, logger)
	}
}

// validateTargetOverrides returns an error if any override key does not
// match an integration_instance_ref.name used by the Product's components.
// This catches typos that would otherwise silently do nothing.
func validateTargetOverrides(overrides map[string]model.TargetOverride, spec model.ProductManifestSpec) error {
	if len(overrides) == 0 {
		return nil
	}
	usedNames := map[string]bool{}
	for _, component := range spec.Components {
		name := strings.TrimSpace(component.Target.IntegrationInstanceRef.Name)
		if name != "" {
			usedNames[name] = true
		}
	}
	for key := range overrides {
		if !usedNames[key] {
			return fmt.Errorf("target_override key %q does not match any component target", key)
		}
	}
	return nil
}

// emitProductInstallationAppliedEvent is a best-effort side channel that
// records the apply success in the core event stream. Failures are logged
// but do not affect the caller response (the apply already succeeded).
//
// If target_overrides were used, they're recorded in the event payload for
// audit trail purposes (so consumers can reconstruct which cluster a given
// apply went to even though the Product manifest is immutable).
func emitProductInstallationAppliedEvent(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	productManifest model.Manifest,
	spec model.ProductManifestSpec,
	results []model.ProductInstallationApplyResult,
	targetOverrides map[string]model.TargetOverride,
) {
	_ = results // results not currently used in the event payload (reserved for future enrichment)
	components := make([]map[string]interface{}, 0, len(spec.Components))
	for _, c := range spec.Components {
		targetMap := map[string]interface{}{
			"kind":      c.Target.Kind,
			"namespace": c.Target.Namespace,
		}
		if c.Target.IntegrationInstanceRef.Name != "" {
			targetMap["integration_instance_ref"] = map[string]interface{}{
				"name":      c.Target.IntegrationInstanceRef.Name,
				"namespace": c.Target.IntegrationInstanceRef.Namespace,
			}
		}
		components = append(components, map[string]interface{}{
			"name":   c.Name,
			"target": targetMap,
		})
	}

	payload := map[string]interface{}{
		"product_ref": map[string]interface{}{
			"id":        productManifest.ID.String(),
			"name":      productManifest.Metadata.Name,
			"namespace": productManifest.Metadata.Namespace,
			"version":   productManifest.Version,
		},
		"components_applied": components,
	}

	// Include target_overrides_used in the payload when overrides were
	// passed at apply time, so audit consumers can reconstruct the actual
	// target each component was applied to.
	if len(targetOverrides) > 0 {
		overridesMap := make(map[string]interface{}, len(targetOverrides))
		for key, override := range targetOverrides {
			entry := map[string]interface{}{
				"integration_instance_ref": map[string]interface{}{
					"name":      override.IntegrationInstanceRef.Name,
					"namespace": override.IntegrationInstanceRef.Namespace,
				},
			}
			if override.Namespace != "" {
				entry["namespace"] = override.Namespace
			}
			overridesMap[key] = entry
		}
		payload["target_overrides_used"] = overridesMap
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		if logger != nil {
			logger.Warn("emit product.installation.applied: begin tx failed", zap.Error(err))
		}
		return
	}
	defer tx.Rollback()

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "product.installation.applied",
		SchemaVersion: "v1",
		AggregateType: "product",
		AggregateID:   productManifest.ID.String(),
		Payload:       payload,
	}); err != nil {
		if logger != nil {
			logger.Warn("emit product.installation.applied: emit failed", zap.Error(err))
		}
		return
	}

	if err := tx.Commit(); err != nil {
		if logger != nil {
			logger.Warn("emit product.installation.applied: commit failed", zap.Error(err))
		}
	}
}

func productObserveInstallationHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.ObserveProductInstallationRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		productManifest, spec, err := resolveProductManifestSpec(ctx, db, req.Product)
		if err != nil {
			return replyFailure(ctx, d, manifestLookupErrorCode(err), err, logger)
		}

		// Validate target overrides against the Product components.
		if err := validateTargetOverrides(req.TargetOverrides, spec); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		executor := newProductTargetExecutor(conn, db, logger).withTargetOverrides(req.TargetOverrides)
		results, err := executor.observeProduct(ctx, productManifest, spec)
		if err != nil {
			return replyFailure(ctx, d, integrationAwareErrorCode(err, "observe_failed"), err, logger)
		}

		return replySuccess(ctx, d, model.ObserveProductInstallationResponse{
			Product: manifestReferenceFromRecord(productManifest),
			Results: results,
		}, logger)
	}
}

// productUninstallInstallationHandler removes a product installation from
// its declared target integrations. It regenerates the component object
// sets using the same reconcile path as apply, then dispatches a
// declarative_delete to the target adapter.
//
// IMPORTANT: uninstall requires the target adapter (e.g.
// integration-kubernetes) to implement the `declarative_delete` action.
// Adapters that do not implement it will return an RPC error — the core
// surfaces it fail-loud rather than silently succeeding.
func productUninstallInstallationHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.UninstallProductInstallationRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		productManifest, spec, err := resolveProductManifestSpec(ctx, db, req.Product)
		if err != nil {
			return replyFailure(ctx, d, manifestLookupErrorCode(err), err, logger)
		}

		if err := validateTargetOverrides(req.TargetOverrides, spec); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		executor := newProductTargetExecutor(conn, db, logger).withTargetOverrides(req.TargetOverrides)
		results, err := executor.uninstallProduct(ctx, productManifest, spec)
		if err != nil {
			return replyFailure(ctx, d, integrationAwareErrorCode(err, "uninstall_failed"), err, logger)
		}

		emitProductInstallationUninstalledEvent(ctx, db, logger, productManifest, spec, results, req.TargetOverrides)

		return replySuccess(ctx, d, model.UninstallProductInstallationResponse{
			Product: manifestReferenceFromRecord(productManifest),
			Results: results,
		}, logger)
	}
}

// emitProductInstallationUninstalledEvent records the uninstall success
// on the core event stream. Failures are logged best-effort and do not
// affect the caller response.
func emitProductInstallationUninstalledEvent(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	productManifest model.Manifest,
	spec model.ProductManifestSpec,
	results []model.ProductInstallationUninstallResult,
	targetOverrides map[string]model.TargetOverride,
) {
	_ = results
	components := make([]map[string]interface{}, 0, len(spec.Components))
	for _, c := range spec.Components {
		targetMap := map[string]interface{}{
			"kind":      c.Target.Kind,
			"namespace": c.Target.Namespace,
		}
		if c.Target.IntegrationInstanceRef.Name != "" {
			targetMap["integration_instance_ref"] = map[string]interface{}{
				"name":      c.Target.IntegrationInstanceRef.Name,
				"namespace": c.Target.IntegrationInstanceRef.Namespace,
			}
		}
		components = append(components, map[string]interface{}{
			"name":   c.Name,
			"target": targetMap,
		})
	}

	payload := map[string]interface{}{
		"product_ref": map[string]interface{}{
			"id":        productManifest.ID.String(),
			"name":      productManifest.Metadata.Name,
			"namespace": productManifest.Metadata.Namespace,
			"version":   productManifest.Version,
		},
		"components_uninstalled": components,
	}

	if len(targetOverrides) > 0 {
		overridesMap := make(map[string]interface{}, len(targetOverrides))
		for key, override := range targetOverrides {
			entry := map[string]interface{}{
				"integration_instance_ref": map[string]interface{}{
					"name":      override.IntegrationInstanceRef.Name,
					"namespace": override.IntegrationInstanceRef.Namespace,
				},
			}
			if override.Namespace != "" {
				entry["namespace"] = override.Namespace
			}
			overridesMap[key] = entry
		}
		payload["target_overrides_used"] = overridesMap
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		if logger != nil {
			logger.Warn("emit product.installation.uninstalled: begin tx failed", zap.Error(err))
		}
		return
	}
	defer tx.Rollback()

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "product.installation.uninstalled",
		SchemaVersion: "v1",
		AggregateType: "product",
		AggregateID:   productManifest.ID.String(),
		Payload:       payload,
	}); err != nil {
		if logger != nil {
			logger.Warn("emit product.installation.uninstalled: emit failed", zap.Error(err))
		}
		return
	}

	if err := tx.Commit(); err != nil {
		if logger != nil {
			logger.Warn("emit product.installation.uninstalled: commit failed", zap.Error(err))
		}
	}
}

func resolveProductManifestSpec(ctx context.Context, db *sql.DB, selector model.ManifestSelector) (model.Manifest, model.ProductManifestSpec, error) {
	productManifest, err := resolveManifestForKind(ctx, db, "product", selector.ManifestID, selector.Namespace, selector.Name, selector.Version)
	if err != nil {
		return model.Manifest{}, model.ProductManifestSpec{}, err
	}

	spec, err := manifestengine.ParseProductSpec(productManifest.Spec)
	if err != nil {
		return model.Manifest{}, model.ProductManifestSpec{}, err
	}

	return productManifest, spec, nil
}

type productInstallationPlanner struct {
	conn      *amqp.Connection
	db        *sql.DB
	logger    *zap.Logger
	inFlight  map[string]struct{}
	completed map[string]struct{}
}

func newProductInstallationPlanner(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) *productInstallationPlanner {
	return &productInstallationPlanner{
		conn:      conn,
		db:        db,
		logger:    logger,
		inFlight:  map[string]struct{}{},
		completed: map[string]struct{}{},
	}
}

func (p *productInstallationPlanner) planProductReconciliation(
	ctx context.Context,
	productManifest model.Manifest,
	spec model.ProductManifestSpec,
) ([]model.ProductInstallationReconcileResult, error) {
	productRef := manifestReferenceFromRecord(productManifest)
	key := requirementReferenceKey(productRef)

	if _, exists := p.completed[key]; exists {
		return nil, nil
	}
	if _, exists := p.inFlight[key]; exists {
		return nil, fmt.Errorf("cyclic product requirement detected for %s/%s", productRef.Namespace, productRef.Name)
	}

	p.inFlight[key] = struct{}{}
	defer delete(p.inFlight, key)

	results := make([]model.ProductInstallationReconcileResult, 0, len(spec.Components))
	for _, component := range spec.Components {
		// reconcileComponentBySourceKind handles source.kind dispatch
		// and surfaces unsupported kinds as a typed error to the
		// caller, so this loop no longer silently drops non-integration
		// components.
		componentResults, err := p.planComponentReconciliation(ctx, productRef, spec, component)
		if err != nil {
			return nil, err
		}
		results = append(results, componentResults...)
	}

	p.completed[key] = struct{}{}
	return results, nil
}

func (p *productInstallationPlanner) planComponentReconciliation(
	ctx context.Context,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
) ([]model.ProductInstallationReconcileResult, error) {
	requirementResults, prerequisitePlans, err := p.resolveComponentRequirements(ctx, component.Requires)
	if err != nil {
		return nil, err
	}

	result, err := reconcileComponentBySourceKind(ctx, p.conn, p.db, productRef, spec, component)
	if err != nil {
		return nil, err
	}
	result.Requirements = requirementResults

	return append(prerequisitePlans, result), nil
}

func (p *productInstallationPlanner) resolveComponentRequirements(
	ctx context.Context,
	requirements []model.ProductRequirementSpec,
) ([]model.ProductRequirementResult, []model.ProductInstallationReconcileResult, error) {
	results := make([]model.ProductRequirementResult, 0, len(requirements))
	var plans []model.ProductInstallationReconcileResult

	for _, requirement := range requirements {
		kind := manifestengine.NormalizeProductRequirementKind(requirement.Kind)
		state := manifestengine.NormalizeProductRequirementState(requirement)
		policy := manifestengine.NormalizeProductRequirementPolicy(requirement)

		result := model.ProductRequirementResult{
			Kind:     kind,
			Selector: requirement.Selector,
			State:    state,
			Policy:   policy,
			Wait:     requirement.Wait,
		}

		switch kind {
		case "product":
			productManifest, spec, err := resolveProductManifestSpec(ctx, p.db, requirement.Selector)
			if err != nil {
				if policy == "optional" && err == repository.ErrManifestNotFound {
					result.Message = "optional product requirement is not declared"
					results = append(results, result)
					continue
				}
				return nil, nil, fmt.Errorf("resolve product requirement %s/%s: %w", requirement.Selector.Namespace, requirement.Selector.Name, err)
			}

			ref := manifestReferenceFromRecord(productManifest)
			result.Reference = manifestReferencePointer(ref)

			switch state {
			case "declared", "active":
				result.Satisfied = true
				result.Message = "required product is declared"
			case "materialized":
				hasMaterialization, err := repository.HasProductMaterialization(ctx, p.db, productManifest)
				if err != nil {
					return nil, nil, fmt.Errorf("check product materialization %s/%s: %w", ref.Namespace, ref.Name, err)
				}
				if hasMaterialization {
					result.Satisfied = true
					result.Message = "required product is already materialized"
				} else if policy == "install_if_missing" {
					dependencyPlans, err := p.planProductReconciliation(ctx, productManifest, spec)
					if err != nil {
						return nil, nil, fmt.Errorf("plan dependent product %s/%s: %w", ref.Namespace, ref.Name, err)
					}
					result.Satisfied = true
					result.Planned = true
					result.Message = "required product will be reconciled before this component"
					plans = append(plans, dependencyPlans...)
				} else if policy == "optional" {
					result.Message = "optional product requirement is not materialized"
				} else if err := ensureProductMaterialization(ctx, p.conn, p.db, productManifest); err == nil {
					// Auto-materialize the prerequisite. Passthrough
					// for git/oci/inline source; integration source
					// triggers the generate capability. Persisted
					// record satisfies the requirement going forward.
					result.Satisfied = true
					result.Message = "required product auto-materialized"
				} else {
					return nil, nil, fmt.Errorf("required product %s/%s could not be auto-materialized: %w", ref.Namespace, ref.Name, err)
				}
			}

		case "integration_instance":
			manifestRecord, err := resolveManifestForKind(ctx, p.db, "integration_instance", requirement.Selector.ManifestID, requirement.Selector.Namespace, requirement.Selector.Name, requirement.Selector.Version)
			if err != nil {
				if policy == "optional" && err == repository.ErrManifestNotFound {
					result.Message = "optional integration instance requirement is not declared"
					results = append(results, result)
					continue
				}
				return nil, nil, fmt.Errorf("resolve integration_instance requirement %s/%s: %w", requirement.Selector.Namespace, requirement.Selector.Name, err)
			}

			ref := manifestReferenceFromRecord(manifestRecord)
			result.Reference = manifestReferencePointer(ref)
			instanceSpec, err := manifestengine.ParseIntegrationInstanceSpec(manifestRecord.Spec)
			if err != nil {
				return nil, nil, fmt.Errorf("parse integration_instance requirement %s/%s: %w", ref.Namespace, ref.Name, err)
			}

			if state == "active" {
				status := strings.ToLower(strings.TrimSpace(instanceSpec.Status))
				if status == "" {
					status = "active"
				}
				if status != "active" {
					if policy == "optional" {
						result.Message = fmt.Sprintf("optional integration instance is %s", status)
						results = append(results, result)
						continue
					}
					return nil, nil, fmt.Errorf("integration instance %s/%s is %s, expected active", ref.Namespace, ref.Name, status)
				}
			}

			result.Satisfied = true
			result.Message = "required integration instance is available"

		case "resource":
			manifestRecord, err := resolveManifestForKind(ctx, p.db, "resource", requirement.Selector.ManifestID, requirement.Selector.Namespace, requirement.Selector.Name, requirement.Selector.Version)
			if err != nil {
				if policy == "optional" && err == repository.ErrManifestNotFound {
					result.Message = "optional resource requirement is not declared"
					results = append(results, result)
					continue
				}
				return nil, nil, fmt.Errorf("resolve resource requirement %s/%s: %w", requirement.Selector.Namespace, requirement.Selector.Name, err)
			}

			ref := manifestReferenceFromRecord(manifestRecord)
			result.Reference = manifestReferencePointer(ref)
			result.Satisfied = true
			result.Message = "required resource is declared"
		}

		results = append(results, result)
	}

	return results, plans, nil
}

func requirementReferenceKey(reference model.ManifestReference) string {
	return fmt.Sprintf("%s:%s:%s:%d", reference.Kind, reference.Namespace, reference.Name, reference.Version)
}

func reconcileIntegrationComponent(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
) (model.ProductInstallationReconcileResult, error) {
	instanceManifest, instanceSpec, integrationTypeManifest, integrationTypeSpec, err := resolveProductIntegration(ctx, conn, db, *component.Source.IntegrationInstanceRef)
	if err != nil {
		return model.ProductInstallationReconcileResult{}, err
	}

	queue := strings.TrimSpace(integrationTypeSpec.Adapter.Queues.Execute)
	if queue == "" {
		return model.ProductInstallationReconcileResult{}, fmt.Errorf("integration type %s/%s does not expose an execute queue", integrationTypeManifest.Metadata.Namespace, integrationTypeManifest.Metadata.Name)
	}

	timeout := time.Duration(integrationTypeSpec.Adapter.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	rpcCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	capability := manifestengine.NormalizeProductSourceCapability(component.Source)
	request := model.AdapterReconcileInstallationRequest{
		Operation: "reconcile_installation",
		Context: model.AdapterGenerateInstallationContext{
			Product:   productRef,
			Component: component.Name,
			Category:  spec.Category,
			Class:     spec.Class,
		},
		Integration: model.AdapterGenerateInstallationIntegrationContext{
			Type:         manifestReferenceFromRecord(integrationTypeManifest),
			TypeSpec:     integrationTypeSpec,
			Instance:     manifestReferenceFromRecord(instanceManifest),
			InstanceSpec: instanceSpec,
		},
		Capability: capability,
		Input:      component.Source.Input,
		Target:     component.Target,
		Reconcile:  component.Reconcile,
	}

	var response model.AdapterReconcileInstallationResponse
	if err := callContractRPC(rpcCtx, rpcamqp.New(conn), queue, reconcileInstallationContract, request, &response); err != nil {
		return model.ProductInstallationReconcileResult{}, fmt.Errorf("call integration execute queue %q: %w", queue, err)
	}
	if strings.TrimSpace(response.Operation) != "" && response.Operation != "reconcile_installation" {
		return model.ProductInstallationReconcileResult{}, fmt.Errorf("unexpected adapter operation %q", response.Operation)
	}

	return model.ProductInstallationReconcileResult{
		Name:                component.Name,
		Operation:           "reconcile_installation",
		Capability:          capability,
		Mode:                response.Mode,
		Objects:             response.Objects,
		IntegrationType:     manifestReferencePointer(manifestReferenceFromRecord(integrationTypeManifest)),
		IntegrationInstance: manifestReferencePointer(manifestReferenceFromRecord(instanceManifest)),
		Metadata:            response.Metadata,
	}, nil
}

// reconcileGitComponent renders a `source.kind: git` component into K8s
// objects by invoking the source integration's `generate_installation`
// capability with the git URL, revision, and renderer config. The
// integration is expected to clone the repo and apply the renderer
// (kustomize / helm / raw manifests) — typically an instance of
// `manifest-sources-kustomize` type. The returned ReconcileResult
// reuses the existing declarative_apply pipeline downstream, so
// applyComponentTarget / observeComponentTarget / uninstallComponentTarget
// work unchanged.
//
// Before this, `source.kind != "integration"` was silently skipped in
// applyProduct / observeProduct / uninstallProduct / discover paths,
// making installation.apply a no-op for every product whose components
// live in git (which is every DaKasa product). The legacy
// `deploy-via-kustomize-source` workflow covered the apply case but
// observe/uninstall/discover remained dead.
func reconcileGitComponent(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
) (model.ProductInstallationReconcileResult, error) {
	if component.Source.IntegrationInstanceRef == nil {
		return model.ProductInstallationReconcileResult{}, fmt.Errorf("git source component %q requires integration_instance_ref", component.Name)
	}

	instanceManifest, instanceSpec, integrationTypeManifest, integrationTypeSpec, err := resolveProductIntegration(ctx, conn, db, *component.Source.IntegrationInstanceRef)
	if err != nil {
		return model.ProductInstallationReconcileResult{}, err
	}

	// Transport check happens inside AdapterTransportClient.Call below
	// — it picks queue or endpoint based on adapter.transport (rabbitmq
	// or http_json), so we don't need to gate on Queues.Execute being
	// non-empty (that's empty for http_json adapters by design).

	timeout := time.Duration(integrationTypeSpec.Adapter.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		// Git clone + kustomize render can take longer than the
		// integration-RPC default (especially on cold cache). 120s is
		// the same ceiling deploy-via-kustomize-source workflow uses.
		timeout = 120 * time.Second
	}

	rpcCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Translate ProductComponentSpec (git/renderer) into the adapter
	// input shape that integration-kustomize (and similar) expects.
	// Caller-provided source.input wins over the schema-derived fields
	// so manifests can override behaviour without code changes.
	input := map[string]any{}
	if locator := strings.TrimSpace(component.Source.Locator); locator != "" {
		gitURL := locator
		if !strings.Contains(gitURL, "://") {
			gitURL = "https://" + gitURL
		}
		input["git_url"] = gitURL
	}
	if revision := strings.TrimSpace(component.Source.Revision); revision != "" {
		input["revision"] = revision
	}
	if rendererKind := strings.ToLower(strings.TrimSpace(component.Renderer.Kind)); rendererKind != "" {
		input["renderer"] = rendererKind
	}
	if path := strings.TrimSpace(component.Renderer.Path); path != "" {
		input["path"] = path
	}
	for k, v := range component.Source.Input {
		input[k] = v
	}

	const capability = "generate_installation"
	request := model.AdapterGenerateInstallationRequest{
		Operation: capability,
		Context: model.AdapterGenerateInstallationContext{
			Product:   productRef,
			Component: component.Name,
			Category:  spec.Category,
			Class:     spec.Class,
		},
		Integration: model.AdapterGenerateInstallationIntegrationContext{
			Type:         manifestReferenceFromRecord(integrationTypeManifest),
			TypeSpec:     integrationTypeSpec,
			Instance:     manifestReferenceFromRecord(instanceManifest),
			InstanceSpec: instanceSpec,
		},
		Capability: capability,
		Input:      input,
	}

	// Use the generic transport client so this works whether the
	// adapter declares `adapter.transport: rabbitmq` (queue-based) or
	// `adapter.transport: http_json` (HTTP endpoints). The
	// manifest-sources-kustomize adapter is http_json, so the older
	// callContractRPC (AMQP-only) path used by reconcileIntegrationComponent
	// would fail here with "execute queue does not expose" — the typed
	// queue field is empty for HTTP transports.
	transport := NewAdapterTransportClient(rpcamqp.New(conn))
	var response model.AdapterGenerateInstallationResponse
	if err := transport.Call(rpcCtx, generateInstallationContract, integrationTypeSpec, instanceSpec, "execute", request, &response); err != nil {
		return model.ProductInstallationReconcileResult{}, fmt.Errorf("call integration execute transport %q for git+renderer render: %w", integrationTypeSpec.Adapter.Transport, err)
	}
	if strings.TrimSpace(response.Operation) != "" && response.Operation != capability {
		return model.ProductInstallationReconcileResult{}, fmt.Errorf("unexpected adapter operation %q (expected %q)", response.Operation, capability)
	}
	if len(response.Objects) == 0 {
		return model.ProductInstallationReconcileResult{}, fmt.Errorf("git+renderer render returned no objects for component %q", component.Name)
	}

	return model.ProductInstallationReconcileResult{
		Name:                component.Name,
		Operation:           capability,
		Capability:          capability,
		Mode:                "declarative_apply",
		Objects:             response.Objects,
		IntegrationType:     manifestReferencePointer(manifestReferenceFromRecord(integrationTypeManifest)),
		IntegrationInstance: manifestReferencePointer(manifestReferenceFromRecord(instanceManifest)),
		Metadata:            response.Metadata,
	}, nil
}

// reconcileComponentBySourceKind dispatches reconciliation to the right
// implementation based on `component.source.kind`. Centralises the
// switch so apply / observe / uninstall / plan paths all get the same
// dispatch table without divergence — adding a new source kind means
// updating exactly one place.
func reconcileComponentBySourceKind(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
) (model.ProductInstallationReconcileResult, error) {
	kind := strings.ToLower(strings.TrimSpace(component.Source.Kind))
	switch kind {
	case "integration":
		return reconcileIntegrationComponent(ctx, conn, db, productRef, spec, component)
	case "git":
		return reconcileGitComponent(ctx, conn, db, productRef, spec, component)
	default:
		return model.ProductInstallationReconcileResult{}, fmt.Errorf("source kind %q not yet supported by reconcile dispatcher (component %q)", component.Source.Kind, component.Name)
	}
}

func discoverIntegrationComponentState(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
) (model.ProductInstallationStateResult, error) {
	instanceManifest, instanceSpec, integrationTypeManifest, integrationTypeSpec, err := resolveProductIntegration(ctx, conn, db, *component.Source.IntegrationInstanceRef)
	if err != nil {
		return model.ProductInstallationStateResult{}, err
	}

	queue := strings.TrimSpace(integrationTypeSpec.Adapter.Queues.Execute)
	if queue == "" {
		return model.ProductInstallationStateResult{}, fmt.Errorf("integration type %s/%s does not expose an execute queue", integrationTypeManifest.Metadata.Namespace, integrationTypeManifest.Metadata.Name)
	}

	timeout := time.Duration(integrationTypeSpec.Adapter.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	rpcCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	capability := manifestengine.NormalizeProductSourceCapability(component.Source)
	request := model.AdapterDiscoverInstallationStateRequest{
		Operation: "discover_installation_state",
		Context: model.AdapterGenerateInstallationContext{
			Product:   productRef,
			Component: component.Name,
			Category:  spec.Category,
			Class:     spec.Class,
		},
		Integration: model.AdapterGenerateInstallationIntegrationContext{
			Type:         manifestReferenceFromRecord(integrationTypeManifest),
			TypeSpec:     integrationTypeSpec,
			Instance:     manifestReferenceFromRecord(instanceManifest),
			InstanceSpec: instanceSpec,
		},
		Capability: capability,
		Input:      component.Source.Input,
		Target:     component.Target,
	}

	var response model.AdapterDiscoverInstallationStateResponse
	if err := callContractRPC(rpcCtx, rpcamqp.New(conn), queue, discoverInstallationStateContract, request, &response); err != nil {
		return model.ProductInstallationStateResult{}, fmt.Errorf("call integration execute queue %q: %w", queue, err)
	}
	if strings.TrimSpace(response.Operation) != "" && response.Operation != "discover_installation_state" {
		return model.ProductInstallationStateResult{}, fmt.Errorf("unexpected adapter operation %q", response.Operation)
	}

	return model.ProductInstallationStateResult{
		Name:                component.Name,
		Operation:           "discover_installation_state",
		Capability:          capability,
		Status:              response.Status,
		Observed:            response.Observed,
		Resources:           response.Resources,
		IntegrationType:     manifestReferencePointer(manifestReferenceFromRecord(integrationTypeManifest)),
		IntegrationInstance: manifestReferencePointer(manifestReferenceFromRecord(instanceManifest)),
		Metadata:            response.Metadata,
	}, nil
}

// ensureProductMaterialization creates a materialization record for the
// given product if none exists yet. Used by resolveExecutionDependencies
// so that installation.apply can satisfy `requires: {state: materialized}`
// prerequisites on-the-fly instead of failing with "required product is
// not materialized".
//
// For products whose components are entirely `source.kind: git` (or
// `oci`, `inline`), this is effectively a passthrough — MaterializeProductSpec
// just copies the spec into the materialized snapshot without invoking
// any integration. For products with `source.kind: integration`
// components, the integration's `generate` capability is invoked
// (potentially slow). Either way, the resulting record is persisted so
// subsequent calls short-circuit at the `HasProductMaterialization` check.
//
// Idempotent: if a materialization already exists for the product, this
// is a no-op. Concurrent calls race-safe via the underlying repository
// (CreateProductMaterialization handles dedupe by checksum).
func ensureProductMaterialization(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	productManifest model.Manifest,
) error {
	hasMat, err := repository.HasProductMaterialization(ctx, db, productManifest)
	if err != nil {
		return fmt.Errorf("check product materialization: %w", err)
	}
	if hasMat {
		return nil
	}

	spec, err := manifestengine.ParseProductSpec(productManifest.Spec)
	if err != nil {
		return fmt.Errorf("parse product spec for materialize: %w", err)
	}

	materializedSpec, components, err := manifestengine.MaterializeProductSpec(
		ctx,
		manifestReferenceFromRecord(productManifest),
		spec,
		rabbitMQProductGenerator{conn: conn, db: db, logger: zap.NewNop()},
	)
	if err != nil {
		return fmt.Errorf("materialize product %s/%s: %w", productManifest.Metadata.Namespace, productManifest.Metadata.Name, err)
	}

	if _, err := repository.CreateProductMaterialization(ctx, db, productManifest, materializedSpec, components); err != nil {
		return fmt.Errorf("persist product materialization %s/%s: %w", productManifest.Metadata.Namespace, productManifest.Metadata.Name, err)
	}
	return nil
}

type rabbitMQProductGenerator struct {
	conn   *amqp.Connection
	db     *sql.DB
	logger *zap.Logger
}

func (g rabbitMQProductGenerator) Generate(ctx context.Context, input manifestengine.GenerateProductComponentInput) (manifestengine.GenerateProductComponentOutput, error) {
	source := input.Component.Source

	instanceManifest, instanceSpec, integrationTypeManifest, integrationTypeSpec, err := resolveProductIntegration(ctx, g.conn, g.db, *source.IntegrationInstanceRef)
	if err != nil {
		return manifestengine.GenerateProductComponentOutput{}, err
	}

	queue := strings.TrimSpace(integrationTypeSpec.Adapter.Queues.Execute)
	if queue == "" {
		return manifestengine.GenerateProductComponentOutput{}, fmt.Errorf("integration type %s/%s does not expose an execute queue", integrationTypeManifest.Metadata.Namespace, integrationTypeManifest.Metadata.Name)
	}

	timeout := time.Duration(integrationTypeSpec.Adapter.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	rpcCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	operation := manifestengine.NormalizeProductSourceOperation(source)
	capability := manifestengine.NormalizeProductSourceCapability(source)

	request := model.AdapterGenerateInstallationRequest{
		Operation: operation,
		Context: model.AdapterGenerateInstallationContext{
			Product:   input.Product,
			Component: input.Component.Name,
			Category:  input.Category,
			Class:     input.Class,
		},
		Integration: model.AdapterGenerateInstallationIntegrationContext{
			Type:         manifestReferenceFromRecord(integrationTypeManifest),
			TypeSpec:     integrationTypeSpec,
			Instance:     manifestReferenceFromRecord(instanceManifest),
			InstanceSpec: instanceSpec,
		},
		Capability: capability,
		Input:      source.Input,
	}

	var response model.AdapterGenerateInstallationResponse
	if err := callContractRPC(rpcCtx, rpcamqp.New(g.conn), queue, generateInstallationContract, request, &response); err != nil {
		return manifestengine.GenerateProductComponentOutput{}, fmt.Errorf("call integration execute queue %q: %w", queue, err)
	}
	if strings.TrimSpace(response.Operation) != "" && response.Operation != operation {
		return manifestengine.GenerateProductComponentOutput{}, fmt.Errorf("unexpected adapter operation %q", response.Operation)
	}
	if len(response.Objects) == 0 {
		return manifestengine.GenerateProductComponentOutput{}, fmt.Errorf("adapter returned no generated objects")
	}

	return manifestengine.GenerateProductComponentOutput{
		Objects: response.Objects,
		Trace: model.ProductMaterializationComponent{
			SourceKind:          "integration",
			ResolvedSourceKind:  "inline",
			Operation:           operation,
			Capability:          capability,
			Input:               source.Input,
			IntegrationInstance: manifestReferencePointer(manifestReferenceFromRecord(instanceManifest)),
			IntegrationType:     manifestReferencePointer(manifestReferenceFromRecord(integrationTypeManifest)),
			Metadata:            response.Metadata,
		},
	}, nil
}

func resolveProductIntegration(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	selector model.ManifestSelector,
) (model.Manifest, model.IntegrationInstanceManifestSpec, model.Manifest, model.IntegrationTypeManifestSpec, error) {
	return resolveIntegrationInstance(ctx, conn, db, selector)
}

func resolveIntegrationInstance(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	selector model.ManifestSelector,
) (model.Manifest, model.IntegrationInstanceManifestSpec, model.Manifest, model.IntegrationTypeManifestSpec, error) {
	instanceManifest, err := resolveManifestForKind(ctx, db, "integration_instance", selector.ManifestID, selector.Namespace, selector.Name, selector.Version)
	if err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("resolve integration_instance %s/%s: %w", selector.Namespace, selector.Name, err)
	}

	instanceSpec, err := manifestengine.ParseIntegrationInstanceSpec(instanceManifest.Spec)
	if err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("parse integration instance spec: %w", err)
	}
	if err := hydrateIntegrationInstanceSecrets(ctx, db, &instanceSpec); err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("hydrate secrets for instance %s/%s: %w", instanceManifest.Metadata.Namespace, instanceManifest.Metadata.Name, err)
	}

	typeManifest, err := resolveManifestForKind(ctx, db, "integration_type", instanceSpec.TypeRef.ManifestID, instanceSpec.TypeRef.Namespace, instanceSpec.TypeRef.Name, instanceSpec.TypeRef.Version)
	if err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("resolve integration_type %s/%s (from instance %s): %w", instanceSpec.TypeRef.Namespace, instanceSpec.TypeRef.Name, instanceManifest.Metadata.Name, err)
	}

	typeSpec, err := manifestengine.ParseIntegrationTypeSpec(typeManifest.Spec)
	if err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("parse integration type spec: %w", err)
	}
	if err := manifestengine.ValidateHydratedIntegrationInstanceInputs(instanceSpec, typeSpec); err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}

	if err := preflightIntegrationInstanceHealth(
		ctx,
		db,
		instanceManifest,
		instanceSpec,
		typeManifest,
		model.IntegrationRuntimeCheckKindOverall,
	); err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}

	if err := verifyResolvedIntegrationType(ctx, conn, db, instanceManifest, typeManifest, instanceSpec, typeSpec); err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}

	return instanceManifest, instanceSpec, typeManifest, typeSpec, nil
}

func hydrateIntegrationInstanceSecrets(ctx context.Context, db *sql.DB, spec *model.IntegrationInstanceManifestSpec) error {
	if spec == nil || db == nil {
		return nil
	}

	if strings.TrimSpace(spec.CredentialsRef) != "" {
		value, err := repository.ResolveSecretObjectRef(ctx, db, spec.CredentialsRef)
		if err != nil {
			return fmt.Errorf("resolve integration instance credentials_ref: %w", err)
		}
		spec.Credentials = mergeStringAnyMaps(spec.Credentials, value)
	}

	if len(spec.Credentials) > 0 {
		resolved, err := repository.ResolveSecretRefs(ctx, db, cloneAuthorizationInput(spec.Credentials))
		if err != nil {
			return fmt.Errorf("resolve integration instance credentials: %w", err)
		}
		if typed, ok := resolved.(map[string]any); ok {
			spec.Credentials = typed
		}
	}

	if len(spec.Config) > 0 {
		resolved, err := repository.ResolveSecretRefs(ctx, db, cloneAuthorizationInput(spec.Config))
		if err != nil {
			return fmt.Errorf("resolve integration instance config: %w", err)
		}
		if typed, ok := resolved.(map[string]any); ok {
			spec.Config = typed
		}
	}

	return nil
}

func manifestReferencePointer(value model.ManifestReference) *model.ManifestReference {
	return &value
}

type productTargetExecutor struct {
	conn            *amqp.Connection
	db              *sql.DB
	logger          *zap.Logger
	inFlight        map[string]struct{}
	completed       map[string]struct{}
	targetOverrides map[string]model.TargetOverride
}

type productExecutionDependency struct {
	Manifest model.Manifest
	Spec     model.ProductManifestSpec
}

func newProductTargetExecutor(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) *productTargetExecutor {
	return &productTargetExecutor{
		conn:      conn,
		db:        db,
		logger:    logger,
		inFlight:  map[string]struct{}{},
		completed: map[string]struct{}{},
	}
}

// withTargetOverrides returns a copy of the executor with target overrides
// applied. Components whose target.integration_instance_ref.name matches a
// key in the map will be redirected to the override's instance + namespace
// at apply/observe time.
//
// Returns a new executor rather than mutating — the caller may reuse the
// base executor for other products without overrides.
func (e *productTargetExecutor) withTargetOverrides(overrides map[string]model.TargetOverride) *productTargetExecutor {
	return &productTargetExecutor{
		conn:            e.conn,
		db:              e.db,
		logger:          e.logger,
		inFlight:        e.inFlight,
		completed:       e.completed,
		targetOverrides: overrides,
	}
}

// applyTargetOverride returns a copy of the component with its target
// rewritten if a matching override exists. If no override matches, the
// original component is returned unchanged.
func (e *productTargetExecutor) applyTargetOverride(component model.ProductComponentSpec) model.ProductComponentSpec {
	if len(e.targetOverrides) == 0 {
		return component
	}
	key := strings.TrimSpace(component.Target.IntegrationInstanceRef.Name)
	if key == "" {
		return component
	}
	override, ok := e.targetOverrides[key]
	if !ok {
		return component
	}
	// Copy the component to avoid mutating the spec
	overridden := component
	overridden.Target.IntegrationInstanceRef = override.IntegrationInstanceRef
	if strings.TrimSpace(override.Namespace) != "" {
		overridden.Target.Namespace = override.Namespace
	}
	return overridden
}

// imageOverridesForOriginalKey returns a shallow copy of the image
// overrides map attached to the TargetOverride identified by key (the
// component's original target.integration_instance_ref.name before
// applyTargetOverride rewrote it). Returns nil when no entry matches or
// no image overrides were provided.
func (e *productTargetExecutor) imageOverridesForOriginalKey(key string) map[string]string {
	if len(e.targetOverrides) == 0 {
		return nil
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	override, ok := e.targetOverrides[key]
	if !ok {
		return nil
	}
	if len(override.ImageOverrides) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(override.ImageOverrides))
	for k, v := range override.ImageOverrides {
		cloned[k] = v
	}
	return cloned
}

func (e *productTargetExecutor) applyProduct(
	ctx context.Context,
	productManifest model.Manifest,
	spec model.ProductManifestSpec,
) ([]model.ProductInstallationApplyResult, error) {
	productRef := manifestReferenceFromRecord(productManifest)
	key := requirementReferenceKey(productRef)

	if _, exists := e.completed[key]; exists {
		return nil, nil
	}
	if _, exists := e.inFlight[key]; exists {
		return nil, fmt.Errorf("cyclic product requirement detected for %s/%s", productRef.Namespace, productRef.Name)
	}

	e.inFlight[key] = struct{}{}
	defer delete(e.inFlight, key)

	results := make([]model.ProductInstallationApplyResult, 0, len(spec.Components))
	for _, component := range spec.Components {
		// applyComponent dispatches via reconcileComponentBySourceKind
		// — handles source.kind integration, git, and surfaces
		// unsupported kinds explicitly. Previously skipped silently.

		// Capture the original target key BEFORE applyTargetOverride
		// rewrites it — imageOverridesForOriginalKey uses the original
		// key to find the matching override entry. Without this, the
		// map lookup would fail because the rewritten Name is the
		// override's replacement, not the key we used to match.
		originalKey := strings.TrimSpace(component.Target.IntegrationInstanceRef.Name)
		imageOverrides := e.imageOverridesForOriginalKey(originalKey)

		// Apply target overrides (if any) before executing the component.
		// Overrides rewrite target.integration_instance_ref and optionally
		// target.namespace without mutating the Product manifest.
		component = e.applyTargetOverride(component)

		componentResults, err := e.applyComponent(ctx, productRef, spec, component, imageOverrides)
		if err != nil {
			return nil, err
		}
		results = append(results, componentResults...)
	}

	e.completed[key] = struct{}{}
	return results, nil
}

func (e *productTargetExecutor) observeProduct(
	ctx context.Context,
	productManifest model.Manifest,
	spec model.ProductManifestSpec,
) ([]model.ProductInstallationObservationResult, error) {
	productRef := manifestReferenceFromRecord(productManifest)
	key := requirementReferenceKey(productRef)

	if _, exists := e.completed[key]; exists {
		return nil, nil
	}
	if _, exists := e.inFlight[key]; exists {
		return nil, fmt.Errorf("cyclic product requirement detected for %s/%s", productRef.Namespace, productRef.Name)
	}

	e.inFlight[key] = struct{}{}
	defer delete(e.inFlight, key)

	results := make([]model.ProductInstallationObservationResult, 0, len(spec.Components))
	for _, component := range spec.Components {
		// observeComponent dispatches via reconcileComponentBySourceKind.

		// Apply target overrides before observing.
		component = e.applyTargetOverride(component)

		componentResults, err := e.observeComponent(ctx, productRef, spec, component)
		if err != nil {
			return nil, err
		}
		results = append(results, componentResults...)
	}

	e.completed[key] = struct{}{}
	return results, nil
}

// uninstallProduct walks the product's components in iteration order and
// dispatches a declarative_delete for each integration-sourced component
// on the resolved target. It does NOT recursively uninstall product
// requirements — a "product X depends on product Y" relationship is for
// install ordering, not for teardown cascade. Uninstalling a dependent
// should not force uninstall of its dependency (other Products may still
// be using Y). Callers that want a full-cascade teardown must walk the
// dependency graph themselves and call uninstall on each product.
func (e *productTargetExecutor) uninstallProduct(
	ctx context.Context,
	productManifest model.Manifest,
	spec model.ProductManifestSpec,
) ([]model.ProductInstallationUninstallResult, error) {
	productRef := manifestReferenceFromRecord(productManifest)
	key := requirementReferenceKey(productRef)

	if _, exists := e.completed[key]; exists {
		return nil, nil
	}
	if _, exists := e.inFlight[key]; exists {
		return nil, fmt.Errorf("cyclic product requirement detected for %s/%s", productRef.Namespace, productRef.Name)
	}

	e.inFlight[key] = struct{}{}
	defer delete(e.inFlight, key)

	results := make([]model.ProductInstallationUninstallResult, 0, len(spec.Components))
	for _, component := range spec.Components {
		// uninstallComponent dispatches via reconcileComponentBySourceKind.

		// Target overrides matter during uninstall too — if the original
		// apply was redirected, the delete must target the same cluster.
		component = e.applyTargetOverride(component)

		componentResults, err := e.uninstallComponent(ctx, productRef, spec, component)
		if err != nil {
			return nil, err
		}
		results = append(results, componentResults...)
	}

	e.completed[key] = struct{}{}
	return results, nil
}

// uninstallComponent regenerates the component's object set via reconcile
// (same path as apply) and dispatches a declarative_delete. Dependencies
// are NOT uninstalled — see uninstallProduct for rationale.
func (e *productTargetExecutor) uninstallComponent(
	ctx context.Context,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
) ([]model.ProductInstallationUninstallResult, error) {
	reconcileResult, err := reconcileComponentBySourceKind(ctx, e.conn, e.db, productRef, spec, component)
	if err != nil {
		return nil, err
	}

	uninstalled, err := e.uninstallComponentTarget(ctx, productRef, spec, component, reconcileResult)
	if err != nil {
		return nil, err
	}

	return []model.ProductInstallationUninstallResult{uninstalled}, nil
}

func (e *productTargetExecutor) applyComponent(
	ctx context.Context,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
	imageOverrides map[string]string,
) ([]model.ProductInstallationApplyResult, error) {
	dependencies, err := e.resolveExecutionDependencies(ctx, component.Requires)
	if err != nil {
		return nil, err
	}

	results := make([]model.ProductInstallationApplyResult, 0, len(dependencies)+1)
	for _, dependency := range dependencies {
		dependencyResults, err := e.applyProduct(ctx, dependency.Manifest, dependency.Spec)
		if err != nil {
			return nil, err
		}
		results = append(results, dependencyResults...)
	}

	reconcileResult, err := reconcileComponentBySourceKind(ctx, e.conn, e.db, productRef, spec, component)
	if err != nil {
		return nil, err
	}

	applied, err := e.applyComponentTarget(ctx, productRef, spec, component, reconcileResult, imageOverrides)
	if err != nil {
		return nil, err
	}
	results = append(results, applied)

	return results, nil
}

func (e *productTargetExecutor) observeComponent(
	ctx context.Context,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
) ([]model.ProductInstallationObservationResult, error) {
	dependencies, err := e.resolveExecutionDependencies(ctx, component.Requires)
	if err != nil {
		return nil, err
	}

	results := make([]model.ProductInstallationObservationResult, 0, len(dependencies)+1)
	for _, dependency := range dependencies {
		dependencyResults, err := e.observeProduct(ctx, dependency.Manifest, dependency.Spec)
		if err != nil {
			return nil, err
		}
		results = append(results, dependencyResults...)
	}

	reconcileResult, err := reconcileComponentBySourceKind(ctx, e.conn, e.db, productRef, spec, component)
	if err != nil {
		return nil, err
	}

	observed, err := e.observeComponentTarget(ctx, productRef, spec, component, reconcileResult)
	if err != nil {
		return nil, err
	}
	results = append(results, observed)

	return results, nil
}

func (e *productTargetExecutor) resolveExecutionDependencies(
	ctx context.Context,
	requirements []model.ProductRequirementSpec,
) ([]productExecutionDependency, error) {
	dependencies := make([]productExecutionDependency, 0, len(requirements))

	for _, requirement := range requirements {
		kind := manifestengine.NormalizeProductRequirementKind(requirement.Kind)
		state := manifestengine.NormalizeProductRequirementState(requirement)
		policy := manifestengine.NormalizeProductRequirementPolicy(requirement)

		switch kind {
		case "product":
			productManifest, spec, err := resolveProductManifestSpec(ctx, e.db, requirement.Selector)
			if err != nil {
				if policy == "optional" && err == repository.ErrManifestNotFound {
					continue
				}
				return nil, fmt.Errorf("resolve product requirement %s/%s: %w", requirement.Selector.Namespace, requirement.Selector.Name, err)
			}

			if state == "materialized" && policy != "install_if_missing" {
				hasMaterialization, err := repository.HasProductMaterialization(ctx, e.db, productManifest)
				if err != nil {
					return nil, fmt.Errorf("check product materialization %s/%s: %w", productManifest.Metadata.Namespace, productManifest.Metadata.Name, err)
				}
				if !hasMaterialization {
					// Auto-materialize the prerequisite on-the-fly.
					// For git/oci/inline source components this is a
					// cheap passthrough; for integration source it
					// invokes the integration's generate capability.
					// Either way, the resulting record satisfies the
					// "state: materialized" requirement without
					// requiring a separate manual materialize call.
					if err := ensureProductMaterialization(ctx, e.conn, e.db, productManifest); err != nil {
						if policy == "optional" {
							continue
						}
						return nil, fmt.Errorf("auto-materialize required product %s/%s: %w", productManifest.Metadata.Namespace, productManifest.Metadata.Name, err)
					}
				}
			}

			if policy == "install_if_missing" {
				dependencies = append(dependencies, productExecutionDependency{
					Manifest: productManifest,
					Spec:     spec,
				})
			}

		case "integration_instance":
			manifestRecord, err := resolveManifestForKind(ctx, e.db, "integration_instance", requirement.Selector.ManifestID, requirement.Selector.Namespace, requirement.Selector.Name, requirement.Selector.Version)
			if err != nil {
				if policy == "optional" && err == repository.ErrManifestNotFound {
					continue
				}
				return nil, fmt.Errorf("resolve integration_instance requirement %s/%s: %w", requirement.Selector.Namespace, requirement.Selector.Name, err)
			}

			if state == "active" {
				instanceSpec, err := manifestengine.ParseIntegrationInstanceSpec(manifestRecord.Spec)
				if err != nil {
					return nil, fmt.Errorf("parse integration_instance requirement %s/%s: %w", manifestRecord.Metadata.Namespace, manifestRecord.Metadata.Name, err)
				}
				status := strings.ToLower(strings.TrimSpace(instanceSpec.Status))
				if status == "" {
					status = "active"
				}
				if status != "active" {
					if policy == "optional" {
						continue
					}
					return nil, fmt.Errorf("integration instance %s/%s is %s, expected active", manifestRecord.Metadata.Namespace, manifestRecord.Metadata.Name, status)
				}
			}

		case "resource":
			_, err := resolveManifestForKind(ctx, e.db, "resource", requirement.Selector.ManifestID, requirement.Selector.Namespace, requirement.Selector.Name, requirement.Selector.Version)
			if err != nil {
				if policy == "optional" && err == repository.ErrManifestNotFound {
					continue
				}
				return nil, fmt.Errorf("resolve resource requirement %s/%s: %w", requirement.Selector.Namespace, requirement.Selector.Name, err)
			}
		}
	}

	return dependencies, nil
}

func (e *productTargetExecutor) applyComponentTarget(
	ctx context.Context,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
	reconcileResult model.ProductInstallationReconcileResult,
	imageOverrides map[string]string,
) (model.ProductInstallationApplyResult, error) {
	if strings.ToLower(strings.TrimSpace(reconcileResult.Mode)) != "declarative_apply" {
		return model.ProductInstallationApplyResult{}, fmt.Errorf("component %q reconcile mode %q is unsupported for target apply", component.Name, reconcileResult.Mode)
	}

	targetInstance, targetInstanceSpec, targetType, targetTypeSpec, err := resolveIntegrationInstance(ctx, e.conn, e.db, component.Target.IntegrationInstanceRef)
	if err != nil {
		return model.ProductInstallationApplyResult{}, fmt.Errorf("resolve target integration %s/%s: %w", component.Target.IntegrationInstanceRef.Namespace, component.Target.IntegrationInstanceRef.Name, err)
	}

	if err := validateTargetProvider(component.Target.Kind, targetTypeSpec.Provider); err != nil {
		return model.ProductInstallationApplyResult{}, err
	}

	queue := strings.TrimSpace(targetTypeSpec.Adapter.Queues.Execute)
	if queue == "" {
		return model.ProductInstallationApplyResult{}, fmt.Errorf("target integration type %s/%s does not expose an execute queue", targetType.Metadata.Namespace, targetType.Metadata.Name)
	}

	timeout := time.Duration(targetTypeSpec.Adapter.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	rpcCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request := model.AdapterDeclarativeApplyRequest{
		Operation: "declarative_apply",
		Context: model.AdapterGenerateInstallationContext{
			Product:   productRef,
			Component: component.Name,
			Category:  spec.Category,
			Class:     spec.Class,
		},
		Target: model.AdapterTargetIntegrationContext{
			Type:         manifestReferenceFromRecord(targetType),
			TypeSpec:     targetTypeSpec,
			Instance:     manifestReferenceFromRecord(targetInstance),
			InstanceSpec: targetInstanceSpec,
		},
		Objects:        reconcileResult.Objects,
		Namespace:      component.Target.Namespace,
		ImageOverrides: imageOverrides,
		Reconcile:      component.Reconcile,
	}

	var response model.AdapterDeclarativeApplyResponse
	if err := callContractRPC(rpcCtx, rpcamqp.New(e.conn), queue, declarativeApplyContract, request, &response); err != nil {
		return model.ProductInstallationApplyResult{}, fmt.Errorf("call target execute queue %q: %w", queue, err)
	}
	if strings.TrimSpace(response.Operation) != "" && response.Operation != "declarative_apply" {
		return model.ProductInstallationApplyResult{}, fmt.Errorf("unexpected target adapter operation %q", response.Operation)
	}

	metadata := cloneMap(response.Metadata)
	metadata["source_integration_type"] = reconcileResult.IntegrationType
	metadata["source_integration_instance"] = reconcileResult.IntegrationInstance
	metadata["planned_mode"] = reconcileResult.Mode

	return model.ProductInstallationApplyResult{
		Name:           component.Name,
		Operation:      "declarative_apply",
		Mode:           response.Mode,
		Applied:        response.Applied,
		Resources:      response.Resources,
		TargetType:     manifestReferencePointer(manifestReferenceFromRecord(targetType)),
		TargetInstance: manifestReferencePointer(manifestReferenceFromRecord(targetInstance)),
		Metadata:       metadata,
	}, nil
}

func (e *productTargetExecutor) observeComponentTarget(
	ctx context.Context,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
	reconcileResult model.ProductInstallationReconcileResult,
) (model.ProductInstallationObservationResult, error) {
	if strings.ToLower(strings.TrimSpace(reconcileResult.Mode)) != "declarative_apply" {
		return model.ProductInstallationObservationResult{}, fmt.Errorf("component %q reconcile mode %q is unsupported for target observe", component.Name, reconcileResult.Mode)
	}

	targetInstance, targetInstanceSpec, targetType, targetTypeSpec, err := resolveIntegrationInstance(ctx, e.conn, e.db, component.Target.IntegrationInstanceRef)
	if err != nil {
		return model.ProductInstallationObservationResult{}, fmt.Errorf("resolve target integration %s/%s: %w", component.Target.IntegrationInstanceRef.Namespace, component.Target.IntegrationInstanceRef.Name, err)
	}

	if err := validateTargetProvider(component.Target.Kind, targetTypeSpec.Provider); err != nil {
		return model.ProductInstallationObservationResult{}, err
	}

	queue := strings.TrimSpace(targetTypeSpec.Adapter.Queues.Execute)
	if queue == "" {
		return model.ProductInstallationObservationResult{}, fmt.Errorf("target integration type %s/%s does not expose an execute queue", targetType.Metadata.Namespace, targetType.Metadata.Name)
	}

	timeout := time.Duration(targetTypeSpec.Adapter.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	rpcCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request := model.AdapterObserveObjectsRequest{
		Operation: "observe_objects",
		Context: model.AdapterGenerateInstallationContext{
			Product:   productRef,
			Component: component.Name,
			Category:  spec.Category,
			Class:     spec.Class,
		},
		Target: model.AdapterTargetIntegrationContext{
			Type:         manifestReferenceFromRecord(targetType),
			TypeSpec:     targetTypeSpec,
			Instance:     manifestReferenceFromRecord(targetInstance),
			InstanceSpec: targetInstanceSpec,
		},
		Objects:   reconcileResult.Objects,
		Namespace: component.Target.Namespace,
	}

	var response model.AdapterObserveObjectsResponse
	if err := callContractRPC(rpcCtx, rpcamqp.New(e.conn), queue, observeObjectsContract, request, &response); err != nil {
		return model.ProductInstallationObservationResult{}, fmt.Errorf("call target execute queue %q: %w", queue, err)
	}
	if strings.TrimSpace(response.Operation) != "" && response.Operation != "observe_objects" {
		return model.ProductInstallationObservationResult{}, fmt.Errorf("unexpected target adapter operation %q", response.Operation)
	}

	metadata := cloneMap(response.Metadata)
	metadata["source_integration_type"] = reconcileResult.IntegrationType
	metadata["source_integration_instance"] = reconcileResult.IntegrationInstance
	metadata["planned_mode"] = reconcileResult.Mode

	return model.ProductInstallationObservationResult{
		Name:           component.Name,
		Operation:      "observe_objects",
		Status:         response.Status,
		Observed:       response.Observed,
		Resources:      response.Resources,
		TargetType:     manifestReferencePointer(manifestReferenceFromRecord(targetType)),
		TargetInstance: manifestReferencePointer(manifestReferenceFromRecord(targetInstance)),
		Metadata:       metadata,
	}, nil
}

func (e *productTargetExecutor) uninstallComponentTarget(
	ctx context.Context,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
	reconcileResult model.ProductInstallationReconcileResult,
) (model.ProductInstallationUninstallResult, error) {
	if strings.ToLower(strings.TrimSpace(reconcileResult.Mode)) != "declarative_apply" {
		return model.ProductInstallationUninstallResult{}, fmt.Errorf("component %q reconcile mode %q is unsupported for target uninstall", component.Name, reconcileResult.Mode)
	}

	targetInstance, targetInstanceSpec, targetType, targetTypeSpec, err := resolveIntegrationInstance(ctx, e.conn, e.db, component.Target.IntegrationInstanceRef)
	if err != nil {
		return model.ProductInstallationUninstallResult{}, fmt.Errorf("resolve target integration %s/%s: %w", component.Target.IntegrationInstanceRef.Namespace, component.Target.IntegrationInstanceRef.Name, err)
	}

	if err := validateTargetProvider(component.Target.Kind, targetTypeSpec.Provider); err != nil {
		return model.ProductInstallationUninstallResult{}, err
	}

	queue := strings.TrimSpace(targetTypeSpec.Adapter.Queues.Execute)
	if queue == "" {
		return model.ProductInstallationUninstallResult{}, fmt.Errorf("target integration type %s/%s does not expose an execute queue", targetType.Metadata.Namespace, targetType.Metadata.Name)
	}

	timeout := time.Duration(targetTypeSpec.Adapter.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	rpcCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	request := model.AdapterDeclarativeDeleteRequest{
		Operation: "declarative_delete",
		Context: model.AdapterGenerateInstallationContext{
			Product:   productRef,
			Component: component.Name,
			Category:  spec.Category,
			Class:     spec.Class,
		},
		Target: model.AdapterTargetIntegrationContext{
			Type:         manifestReferenceFromRecord(targetType),
			TypeSpec:     targetTypeSpec,
			Instance:     manifestReferenceFromRecord(targetInstance),
			InstanceSpec: targetInstanceSpec,
		},
		Objects:   reconcileResult.Objects,
		Namespace: component.Target.Namespace,
	}

	var response model.AdapterDeclarativeDeleteResponse
	if err := callContractRPC(rpcCtx, rpcamqp.New(e.conn), queue, declarativeDeleteContract, request, &response); err != nil {
		return model.ProductInstallationUninstallResult{}, fmt.Errorf("call target execute queue %q: %w", queue, err)
	}
	if strings.TrimSpace(response.Operation) != "" && response.Operation != "declarative_delete" {
		return model.ProductInstallationUninstallResult{}, fmt.Errorf("unexpected target adapter operation %q", response.Operation)
	}

	metadata := cloneMap(response.Metadata)
	metadata["source_integration_type"] = reconcileResult.IntegrationType
	metadata["source_integration_instance"] = reconcileResult.IntegrationInstance
	metadata["planned_mode"] = reconcileResult.Mode

	return model.ProductInstallationUninstallResult{
		Name:           component.Name,
		Operation:      "declarative_delete",
		Mode:           response.Mode,
		Uninstalled:    response.Uninstalled,
		Resources:      response.Resources,
		TargetType:     manifestReferencePointer(manifestReferenceFromRecord(targetType)),
		TargetInstance: manifestReferencePointer(manifestReferenceFromRecord(targetInstance)),
		Metadata:       metadata,
	}, nil
}

func validateTargetProvider(targetKind, provider string) error {
	targetKind = strings.ToLower(strings.TrimSpace(targetKind))
	provider = strings.ToLower(strings.TrimSpace(provider))
	if targetKind == "" {
		return fmt.Errorf("product target kind is required")
	}
	if provider == "" {
		return fmt.Errorf("target integration provider is required")
	}
	if targetKind != provider {
		return fmt.Errorf("target kind %q does not match target integration provider %q", targetKind, provider)
	}
	return nil
}

func cloneMap(input map[string]any) map[string]any {
	if len(input) == 0 {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}
