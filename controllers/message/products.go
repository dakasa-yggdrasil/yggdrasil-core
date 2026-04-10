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
)

const (
	queueProductMaterialize               = "yggdrasil-core.product.materialize"
	queueProductInstallationReconcile     = "yggdrasil-core.product.installation.reconcile"
	queueProductInstallationApply         = "yggdrasil-core.product.installation.apply"
	queueProductInstallationObserve       = "yggdrasil-core.product.installation.observe"
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
			Queue:   queueProductInstallationStateDiscover,
			Timeout: 30 * time.Second,
			QoS:     5,
			Handler: productDiscoverInstallationStateHandler(conn, db, logger),
		},
	}
}

func productMaterializeHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.MaterializeProductRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		productManifest, err := resolveManifestForKind(ctx, db, "product", req.Product.ManifestID, req.Product.Namespace, req.Product.Name, req.Product.Version)
		if err != nil {
			return replyFailure(ctx, conn, d, manifestLookupErrorCode(err), err, logger)
		}

		spec, err := manifestengine.ParseProductSpec(productManifest.Spec)
		if err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
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
			return replyFailure(ctx, conn, d, integrationAwareErrorCode(err, "materialization_failed"), err, logger)
		}

		record, err := repository.CreateProductMaterialization(ctx, db, productManifest, materializedSpec, components)
		if err != nil {
			return replyFailure(ctx, conn, d, "internal_error", err, logger)
		}

		return replySuccess(ctx, conn, d, model.MaterializeProductResponse{
			Materialization: record,
		}, logger)
	}
}

func productReconcileInstallationHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.ReconcileProductInstallationRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		productManifest, spec, err := resolveProductManifestSpec(ctx, db, req.Product)
		if err != nil {
			return replyFailure(ctx, conn, d, manifestLookupErrorCode(err), err, logger)
		}

		planner := newProductInstallationPlanner(conn, db, logger)
		results, err := planner.planProductReconciliation(ctx, productManifest, spec)
		if err != nil {
			return replyFailure(ctx, conn, d, integrationAwareErrorCode(err, "reconcile_failed"), err, logger)
		}

		return replySuccess(ctx, conn, d, model.ReconcileProductInstallationResponse{
			Product: manifestReferenceFromRecord(productManifest),
			Results: results,
		}, logger)
	}
}

func productDiscoverInstallationStateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.DiscoverProductInstallationStateRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		productManifest, spec, err := resolveProductManifestSpec(ctx, db, req.Product)
		if err != nil {
			return replyFailure(ctx, conn, d, manifestLookupErrorCode(err), err, logger)
		}

		productRef := manifestReferenceFromRecord(productManifest)
		results := make([]model.ProductInstallationStateResult, 0, len(spec.Components))
		for _, component := range spec.Components {
			if strings.ToLower(strings.TrimSpace(component.Source.Kind)) != "integration" {
				continue
			}

			result, err := discoverIntegrationComponentState(ctx, conn, db, productRef, spec, component)
			if err != nil {
				return replyFailure(ctx, conn, d, integrationAwareErrorCode(err, "discover_failed"), err, logger)
			}
			results = append(results, result)
		}

		return replySuccess(ctx, conn, d, model.DiscoverProductInstallationStateResponse{
			Product: productRef,
			Results: results,
		}, logger)
	}
}

func productApplyInstallationHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.ApplyProductInstallationRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		productManifest, spec, err := resolveProductManifestSpec(ctx, db, req.Product)
		if err != nil {
			return replyFailure(ctx, conn, d, manifestLookupErrorCode(err), err, logger)
		}

		executor := newProductTargetExecutor(conn, db, logger)
		results, err := executor.applyProduct(ctx, productManifest, spec)
		if err != nil {
			return replyFailure(ctx, conn, d, integrationAwareErrorCode(err, "apply_failed"), err, logger)
		}

		// Emit product.installation.applied event (best-effort, post-apply).
		// The apply itself involves side effects on external systems (K8s, etc.)
		// so it's not transactional with the core DB. We emit the event in its
		// own transaction after success; on event emit failure we log and
		// return success anyway (the apply already happened).
		emitProductInstallationAppliedEvent(ctx, db, logger, productManifest, spec, results)

		return replySuccess(ctx, conn, d, model.ApplyProductInstallationResponse{
			Product: manifestReferenceFromRecord(productManifest),
			Results: results,
		}, logger)
	}
}

// emitProductInstallationAppliedEvent is a best-effort side channel that
// records the apply success in the core event stream. Failures are logged
// but do not affect the caller response (the apply already succeeded).
func emitProductInstallationAppliedEvent(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	productManifest model.Manifest,
	spec model.ProductManifestSpec,
	results []model.ProductInstallationApplyResult,
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
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.ObserveProductInstallationRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		productManifest, spec, err := resolveProductManifestSpec(ctx, db, req.Product)
		if err != nil {
			return replyFailure(ctx, conn, d, manifestLookupErrorCode(err), err, logger)
		}

		executor := newProductTargetExecutor(conn, db, logger)
		results, err := executor.observeProduct(ctx, productManifest, spec)
		if err != nil {
			return replyFailure(ctx, conn, d, integrationAwareErrorCode(err, "observe_failed"), err, logger)
		}

		return replySuccess(ctx, conn, d, model.ObserveProductInstallationResponse{
			Product: manifestReferenceFromRecord(productManifest),
			Results: results,
		}, logger)
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
		if strings.ToLower(strings.TrimSpace(component.Source.Kind)) != "integration" {
			continue
		}

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

	result, err := reconcileIntegrationComponent(ctx, p.conn, p.db, productRef, spec, component)
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
				} else {
					return nil, nil, fmt.Errorf("required product %s/%s is not materialized", ref.Namespace, ref.Name)
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
	if err := callContractRPC(rpcCtx, conn, queue, reconcileInstallationContract, request, &response); err != nil {
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
	if err := callContractRPC(rpcCtx, conn, queue, discoverInstallationStateContract, request, &response); err != nil {
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
	if err := callContractRPC(rpcCtx, g.conn, queue, generateInstallationContract, request, &response); err != nil {
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
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}

	instanceSpec, err := manifestengine.ParseIntegrationInstanceSpec(instanceManifest.Spec)
	if err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, fmt.Errorf("parse integration instance spec: %w", err)
	}
	if err := hydrateIntegrationInstanceSecrets(ctx, db, &instanceSpec); err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
	}

	typeManifest, err := resolveManifestForKind(ctx, db, "integration_type", instanceSpec.TypeRef.ManifestID, instanceSpec.TypeRef.Namespace, instanceSpec.TypeRef.Name, instanceSpec.TypeRef.Version)
	if err != nil {
		return model.Manifest{}, model.IntegrationInstanceManifestSpec{}, model.Manifest{}, model.IntegrationTypeManifestSpec{}, err
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
	conn      *amqp.Connection
	db        *sql.DB
	logger    *zap.Logger
	inFlight  map[string]struct{}
	completed map[string]struct{}
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
		if strings.ToLower(strings.TrimSpace(component.Source.Kind)) != "integration" {
			continue
		}

		componentResults, err := e.applyComponent(ctx, productRef, spec, component)
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
		if strings.ToLower(strings.TrimSpace(component.Source.Kind)) != "integration" {
			continue
		}

		componentResults, err := e.observeComponent(ctx, productRef, spec, component)
		if err != nil {
			return nil, err
		}
		results = append(results, componentResults...)
	}

	e.completed[key] = struct{}{}
	return results, nil
}

func (e *productTargetExecutor) applyComponent(
	ctx context.Context,
	productRef model.ManifestReference,
	spec model.ProductManifestSpec,
	component model.ProductComponentSpec,
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

	reconcileResult, err := reconcileIntegrationComponent(ctx, e.conn, e.db, productRef, spec, component)
	if err != nil {
		return nil, err
	}

	applied, err := e.applyComponentTarget(ctx, productRef, spec, component, reconcileResult)
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

	reconcileResult, err := reconcileIntegrationComponent(ctx, e.conn, e.db, productRef, spec, component)
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
					if policy == "optional" {
						continue
					}
					return nil, fmt.Errorf("required product %s/%s is not materialized", productManifest.Metadata.Namespace, productManifest.Metadata.Name)
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
		Objects:   reconcileResult.Objects,
		Namespace: component.Target.Namespace,
		Reconcile: component.Reconcile,
	}

	var response model.AdapterDeclarativeApplyResponse
	if err := callContractRPC(rpcCtx, e.conn, queue, declarativeApplyContract, request, &response); err != nil {
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
	if err := callContractRPC(rpcCtx, e.conn, queue, observeObjectsContract, request, &response); err != nil {
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
