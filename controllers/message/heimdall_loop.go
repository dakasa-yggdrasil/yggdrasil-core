package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

const (
	defaultHeimdallGuardianLoopInterval = 2 * time.Minute
	defaultHeimdallGuardianNamespace    = "global"
	defaultHeimdallGuardianInstance     = "heimdall-guardian"
	defaultHeimdallDispatchEnvironment  = "production"
	defaultHeimdallDispatchActor        = "heimdall"
	defaultHeimdallDispatchWorkflow     = "deploy.yml"
	defaultHeimdallDispatchBranch       = "main"
)

var (
	heimdallActionCooldownMu sync.Mutex
	heimdallActionCooldown   = map[string]time.Time{}
)

type heimdallRepositoryBinding struct {
	Manifest model.Manifest
	Spec     model.RepositoryBindingManifestSpec
}

type heimdallRemediationContract struct {
	Manifest model.Manifest
	Spec     model.RemediationContractManifestSpec
}

type heimdallGuardianMemory struct {
	Manifest model.Manifest
	Spec     model.GuardianMemoryManifestSpec
}

type heimdallRemediationBundle struct {
	Manifest model.Manifest
	Spec     model.RemediationBundleManifestSpec
}

type heimdallExecutionOptions struct {
	SkipApproval bool
	SkipCooldown bool
	MemoryName   string
	MemoryNS     string
	Decision     *heimdallAutonomyDecision
}

type heimdallActionConfidenceAssessment struct {
	Confidence               float64
	Attempts                 float64
	RecoveryRate             float64
	AvgTimeToRecoverySeconds float64
	AvgStableWindowSeconds   float64
	ComponentScope           string
	ProviderGroup            string
	IncidentCategory         string
	ConfidenceBand           string
	BlastRadius              string
	BlastRadiusReason        string
	Environment              string
}

type heimdallAutonomyDecision struct {
	Mode                 string
	RequireApproval      bool
	ManualReview         bool
	Escalate             bool
	Confidence           float64
	ConfidenceBand       string
	Reason               string
	EscalationReason     string
	ProviderGroup        string
	IncidentCategory     string
	Attempts             float64
	RecoveryRate         float64
	BlastRadius          string
	BlastRadiusReason    string
	Environment          string
	OutsideBusinessHours bool
	ActiveFreezeWindow   string
	ProtectedEnvironment bool
	MaintenanceActive    bool
	MaintenanceReason    string
}

type heimdallOperationalContext struct {
	Environment                string
	EffectiveAutoBlastRadius   string
	EffectiveBypassBlastRadius string
	ProtectedEnvironment       bool
	OutsideBusinessHours       bool
	BusinessHoursReason        string
	ActiveFreezeWindow         string
	FreezeReason               string
	BusinessHoursAllowsBypass  bool
	FreezeAllowsBypass         bool
	MaintenanceActive          bool
	MaintenanceReason          string
	MaintenanceAllowsBypass    bool
}

// StartHeimdallGuardianLoop runs the periodic closed-loop guardian sweep.
func StartHeimdallGuardianLoop(
	conn *amqp.Connection,
	db *sql.DB,
	logger *zap.Logger,
	interval time.Duration,
) context.CancelFunc {
	if interval <= 0 {
		interval = defaultHeimdallGuardianLoopInterval
	}

	ctx, cancel := context.WithCancel(context.Background())
	go runHeimdallGuardianLoop(ctx, conn, db, logger, interval)
	return cancel
}

func runHeimdallGuardianLoop(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	logger *zap.Logger,
	interval time.Duration,
) {
	runHeimdallGuardianSweep(ctx, conn, db, logger)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runHeimdallGuardianSweep(ctx, conn, db, logger)
		}
	}
}

func runHeimdallGuardianSweep(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	logger *zap.Logger,
) {
	if conn == nil || db == nil {
		return
	}

	instanceManifest, instanceSpec, typeManifest, typeSpec, err := resolveIntegrationInstance(ctx, conn, db, model.ManifestSelector{
		Namespace: defaultHeimdallGuardianNamespace,
		Name:      defaultHeimdallGuardianInstance,
	})
	if err != nil {
		if logger != nil {
			logger.Warn("heimdall guardian sweep skipped because the guardian instance is unavailable", zap.Error(err))
		}
		return
	}

	repositoryBindings, err := loadHeimdallRepositoryBindings(ctx, db)
	if err != nil {
		if logger != nil {
			logger.Warn("heimdall guardian sweep failed to load repository bindings", zap.Error(err))
		}
		return
	}

	policy, err := loadGuardianPolicyForInstance(ctx, db, instanceManifest)
	if err != nil {
		if logger != nil {
			logger.Warn("heimdall guardian sweep failed to load guardian policy", zap.Error(err))
		}
		return
	}

	remediationContracts, err := loadHeimdallRemediationContracts(ctx, db)
	if err != nil {
		if logger != nil {
			logger.Warn("heimdall guardian sweep failed to load remediation contracts", zap.Error(err))
		}
		return
	}

	snapshot, err := buildHeimdallEcosystemSnapshot(ctx, db, repositoryBindings, remediationContracts)
	if err != nil {
		if logger != nil {
			logger.Warn("heimdall guardian sweep failed to build ecosystem snapshot", zap.Error(err))
		}
		return
	}

	assessmentResponse, err := executeIntegrationThroughResolved(
		ctx,
		conn,
		model.ExecuteIntegrationRequest{
			Operation:  "assess_ecosystem",
			Capability: "assess_ecosystem",
			Input: map[string]any{
				"ecosystem":       snapshot,
				"guardian_policy": heimdallPolicyInput(policy),
			},
			Metadata: map[string]any{
				"source": "core.heimdall.assess",
			},
		},
		instanceManifest,
		instanceSpec,
		typeManifest,
		typeSpec,
		0,
	)
	if err != nil {
		if logger != nil {
			logger.Warn("heimdall guardian assessment failed", zap.Error(err))
		}
		return
	}

	if logger != nil {
		logger.Info("heimdall guardian assessment completed",
			zap.Any("metadata", assessmentResponse.Metadata),
		)
	}

	recommendResponse, err := executeIntegrationThroughResolved(
		ctx,
		conn,
		model.ExecuteIntegrationRequest{
			Operation:  "recommend_improvements",
			Capability: "recommend_improvements",
			Input: map[string]any{
				"ecosystem":       snapshot,
				"guardian_policy": heimdallPolicyInput(policy),
			},
			Metadata: map[string]any{
				"source": "core.heimdall.recommend",
			},
		},
		instanceManifest,
		instanceSpec,
		typeManifest,
		typeSpec,
		0,
	)
	if err != nil {
		if logger != nil {
			logger.Warn("heimdall guardian recommendation sweep failed", zap.Error(err))
		}
	} else if logger != nil {
		logger.Info("heimdall guardian recommendations prepared",
			zap.Any("metadata", recommendResponse.Metadata),
		)
	}

	actionsExecuted := 0
	if policy.AutoHeal.Enabled {
		autoHealResponse, err := executeIntegrationThroughResolved(
			ctx,
			conn,
			model.ExecuteIntegrationRequest{
				Operation:  "auto_remediate_critical",
				Capability: "auto_remediate_critical",
				Input: map[string]any{
					"ecosystem":       snapshot,
					"guardian_policy": heimdallPolicyInput(policy),
				},
				Metadata: map[string]any{
					"source": "core.heimdall.auto_heal",
				},
			},
			instanceManifest,
			instanceSpec,
			typeManifest,
			typeSpec,
			0,
		)
		if err != nil {
			if logger != nil {
				logger.Warn("heimdall guardian auto-remediation sweep failed", zap.Error(err))
			}
		} else {
			if heimdallSeverityMeetsThreshold(
				heimdallOutputIncidentSeverity(autoHealResponse.Output),
				policy.AutoHeal.SeverityThreshold,
			) {
				actions := heimdallRemediationActions(autoHealResponse.Output)
				executed, execErr := executeHeimdallActions(
					ctx,
					conn,
					db,
					actions,
					repositoryBindings,
					remediationContracts,
					policy,
					"critical_auto_remediation",
					actionsExecuted,
				)
				actionsExecuted = executed
				if execErr != nil && logger != nil {
					logger.Warn("heimdall guardian auto-remediation execution failed", zap.Error(execErr))
				}
			} else if logger != nil {
				logger.Info("heimdall guardian skipped auto-remediation because the incident severity is below threshold")
			}
		}
	}

	if policy.CostOptimization.Enabled {
		costResponse, err := executeIntegrationThroughResolved(
			ctx,
			conn,
			model.ExecuteIntegrationRequest{
				Operation:  "optimize_cost",
				Capability: "optimize_cost",
				Input: map[string]any{
					"ecosystem":       snapshot,
					"guardian_policy": heimdallPolicyInput(policy),
				},
				Metadata: map[string]any{
					"source": "core.heimdall.optimize_cost",
				},
			},
			instanceManifest,
			instanceSpec,
			typeManifest,
			typeSpec,
			0,
		)
		if err != nil {
			if logger != nil {
				logger.Warn("heimdall guardian cost optimization sweep failed", zap.Error(err))
			}
		} else {
			actions := heimdallCostActions(costResponse.Output, policy)
			executed, execErr := executeHeimdallActions(
				ctx,
				conn,
				db,
				actions,
				repositoryBindings,
				remediationContracts,
				policy,
				"cost_optimization",
				actionsExecuted,
			)
			actionsExecuted = executed
			if execErr != nil && logger != nil {
				logger.Warn("heimdall guardian cost action execution failed", zap.Error(execErr))
			}
		}
	}
}

func loadHeimdallRepositoryBindings(ctx context.Context, db *sql.DB) (map[string]heimdallRepositoryBinding, error) {
	manifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "repository_binding",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}

	bindings := make(map[string]heimdallRepositoryBinding, len(manifests))
	for _, manifestRecord := range manifests {
		spec, err := manifestengine.ParseRepositoryBindingSpec(manifestRecord.Spec)
		if err != nil {
			return nil, err
		}
		spec = manifestengine.NormalizeRepositoryBindingSpec(spec)
		bindings[heimdallComponentKey(spec.ComponentKind, spec.ComponentNamespace, spec.ComponentName)] = heimdallRepositoryBinding{
			Manifest: manifestRecord,
			Spec:     spec,
		}
	}

	return bindings, nil
}

func loadGuardianPolicyForInstance(ctx context.Context, db *sql.DB, instanceManifest model.Manifest) (model.GuardianPolicyManifestSpec, error) {
	manifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "guardian_policy",
		ActiveOnly: true,
	})
	if err != nil {
		return model.GuardianPolicyManifestSpec{}, err
	}

	for _, manifestRecord := range manifests {
		spec, err := manifestengine.ParseGuardianPolicySpec(manifestRecord.Spec)
		if err != nil {
			return model.GuardianPolicyManifestSpec{}, err
		}
		spec = manifestengine.NormalizeGuardianPolicySpec(spec)
		if guardianPolicyTargetsInstance(spec, instanceManifest) {
			return spec, nil
		}
	}

	return manifestengine.NormalizeGuardianPolicySpec(model.GuardianPolicyManifestSpec{
		GuardianRef: model.ManifestSelector{
			Namespace: instanceManifest.Metadata.Namespace,
			Name:      instanceManifest.Metadata.Name,
		},
		AutoHeal: model.GuardianAutoHealPolicySpec{
			Enabled:               true,
			SeverityThreshold:     "critical",
			MaxActionsPerSweep:    1,
			CooldownSeconds:       300,
			AllowDispatchWorkflow: true,
			AllowRightsize:        true,
		},
		Escalation: model.GuardianEscalationPolicySpec{
			Enabled:             true,
			SeverityThreshold:   "critical",
			MaxAutoHealAttempts: 2,
			CreateApproval:      true,
		},
		CostOptimization: model.GuardianCostOptimizationPolicySpec{
			Enabled: false,
		},
	}), nil
}

func loadHeimdallRemediationContracts(ctx context.Context, db *sql.DB) (map[string]heimdallRemediationContract, error) {
	manifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "remediation_contract",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}

	contracts := make(map[string]heimdallRemediationContract, len(manifests))
	for _, manifestRecord := range manifests {
		spec, err := manifestengine.ParseRemediationContractSpec(manifestRecord.Spec)
		if err != nil {
			return nil, err
		}
		spec = manifestengine.NormalizeRemediationContractSpec(spec)
		contracts[heimdallComponentKey(spec.ComponentKind, spec.ComponentNamespace, spec.ComponentName)] = heimdallRemediationContract{
			Manifest: manifestRecord,
			Spec:     spec,
		}
	}

	return contracts, nil
}

func heimdallRemediationContractActionNames(
	contracts map[string]heimdallRemediationContract,
	componentKind string,
	componentNamespace string,
	componentName string,
) []string {
	contract, ok := contracts[heimdallComponentKey(componentKind, componentNamespace, componentName)]
	if !ok {
		return nil
	}

	names := make([]string, 0, len(contract.Spec.Actions))
	seen := map[string]struct{}{}
	for _, action := range contract.Spec.Actions {
		name := strings.ToLower(strings.TrimSpace(action.Name))
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func loadHeimdallGuardianMemories(ctx context.Context, db *sql.DB) ([]heimdallGuardianMemory, error) {
	manifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "guardian_memory",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}

	memories := make([]heimdallGuardianMemory, 0, len(manifests))
	for _, manifestRecord := range manifests {
		spec, err := manifestengine.ParseGuardianMemorySpec(manifestRecord.Spec)
		if err != nil {
			return nil, err
		}
		spec = manifestengine.NormalizeGuardianMemorySpec(spec)
		memories = append(memories, heimdallGuardianMemory{
			Manifest: manifestRecord,
			Spec:     spec,
		})
	}

	sort.SliceStable(memories, func(i, j int) bool {
		if !memories[i].Manifest.CreatedAt.Equal(memories[j].Manifest.CreatedAt) {
			return memories[i].Manifest.CreatedAt.After(memories[j].Manifest.CreatedAt)
		}
		return memories[i].Manifest.Metadata.Name < memories[j].Manifest.Metadata.Name
	})

	return memories, nil
}

func loadHeimdallIntegrationTypeSpecs(ctx context.Context, db *sql.DB) (map[string]model.IntegrationTypeManifestSpec, error) {
	manifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "integration_type",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}

	specs := make(map[string]model.IntegrationTypeManifestSpec, len(manifests))
	for _, manifestRecord := range manifests {
		spec, err := manifestengine.ParseIntegrationTypeSpec(manifestRecord.Spec)
		if err != nil {
			return nil, err
		}
		spec.GuardianSupport = manifestengine.NormalizeIntegrationGuardianSupport(spec.GuardianSupport)
		specs[heimdallManifestKey(manifestRecord.Metadata.Namespace, manifestRecord.Metadata.Name)] = spec
	}

	return specs, nil
}

func guardianPolicyTargetsInstance(spec model.GuardianPolicyManifestSpec, instanceManifest model.Manifest) bool {
	if manifestID := strings.TrimSpace(spec.GuardianRef.ManifestID); manifestID != "" {
		return manifestID == instanceManifest.ID.String()
	}

	namespace := strings.TrimSpace(spec.GuardianRef.Namespace)
	if namespace == "" {
		namespace = "global"
	}

	return strings.EqualFold(namespace, instanceManifest.Metadata.Namespace) &&
		strings.EqualFold(strings.TrimSpace(spec.GuardianRef.Name), instanceManifest.Metadata.Name)
}

func buildHeimdallEcosystemSnapshot(
	ctx context.Context,
	db *sql.DB,
	repositoryBindings map[string]heimdallRepositoryBinding,
	remediationContracts map[string]heimdallRemediationContract,
) (map[string]any, error) {
	integrationTypeSpecs, err := loadHeimdallIntegrationTypeSpecs(ctx, db)
	if err != nil {
		return nil, err
	}

	integrationManifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "integration_instance",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}

	integrations := make([]map[string]any, 0, len(integrationManifests))
	incidents := make([]map[string]any, 0)
	for _, manifestRecord := range integrationManifests {
		health, err := buildIntegrationInstanceHealth(ctx, db, manifestRecord, model.IntegrationRuntimeCheckKindOverall)
		if err != nil {
			return nil, err
		}

		item := map[string]any{
			"name":            manifestRecord.Metadata.Name,
			"namespace":       manifestRecord.Metadata.Namespace,
			"declared_status": health.DeclaredStatus,
			"overall_health":  health.Status,
			"type_name":       health.IntegrationType.Name,
			"type_namespace":  health.IntegrationType.Namespace,
		}
		if binding, ok := repositoryBindings[heimdallComponentKey("integration", manifestRecord.Metadata.Namespace, manifestRecord.Metadata.Name)]; ok {
			item = mergeStringAnyMaps(item, heimdallRepositoryBindingMetadata(binding))
		}
		if actionNames := heimdallRemediationContractActionNames(
			remediationContracts,
			"integration",
			manifestRecord.Metadata.Namespace,
			manifestRecord.Metadata.Name,
		); len(actionNames) > 0 {
			item["remediation_contract_actions"] = actionNames
		}
		typeSpec := integrationTypeSpecs[heimdallManifestKey(health.IntegrationType.Namespace, health.IntegrationType.Name)]
		if representative := health.RuntimeState; representative != nil {
			item["check_kind"] = representative.CheckKind
			item["health_message"] = representative.Message
			item["details"] = representative.Details
			if representative.LastFailureAt != nil {
				item["last_failure_at"] = representative.LastFailureAt.UTC().Format(time.RFC3339)
			}
			if representative.LastSuccessAt != nil {
				item["last_success_at"] = representative.LastSuccessAt.UTC().Format(time.RFC3339)
			}
		}
		item = heimdallApplyIntegrationGuardianSignals(item, health.RuntimeState, typeSpec.GuardianSupport)
		integrations = append(integrations, item)
		incidents = append(incidents, heimdallIntegrationIncidents(health, item)...)
	}

	surfaceManifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "surface",
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}

	surfaces := make([]map[string]any, 0, len(surfaceManifests))
	for _, manifestRecord := range surfaceManifests {
		spec, err := manifestengine.ParseSurfaceSpec(manifestRecord.Spec)
		if err != nil {
			return nil, err
		}
		item := map[string]any{
			"name":           manifestRecord.Metadata.Name,
			"namespace":      manifestRecord.Metadata.Namespace,
			"category":       spec.Category,
			"overall_health": "healthy",
			"runtime_kind":   spec.Runtime.Kind,
			"exposure":       spec.Runtime.Exposure,
		}
		if binding, ok := repositoryBindings[heimdallComponentKey("surface", manifestRecord.Metadata.Namespace, manifestRecord.Metadata.Name)]; ok {
			item = mergeStringAnyMaps(item, heimdallRepositoryBindingMetadata(binding))
		}
		if actionNames := heimdallRemediationContractActionNames(
			remediationContracts,
			"surface",
			manifestRecord.Metadata.Namespace,
			manifestRecord.Metadata.Name,
		); len(actionNames) > 0 {
			item["remediation_contract_actions"] = actionNames
		}
		surfaces = append(surfaces, item)
	}

	secretsRaw, err := repository.ListManagedSecrets(ctx, db, model.ListManagedSecretsRequest{})
	if err != nil {
		return nil, err
	}

	secrets := make([]map[string]any, 0, len(secretsRaw))
	now := time.Now().UTC()
	for _, secret := range secretsRaw {
		item := map[string]any{
			"name":              secret.Name,
			"namespace":         secret.Namespace,
			"status":            secret.Status,
			"rotation_required": secret.IsRotationDue(now),
		}
		if secret.ExpiresAt != nil {
			item["expires_at"] = secret.ExpiresAt.UTC().Format(time.RFC3339)
			item["expires_in_hours"] = secret.ExpiresAt.UTC().Sub(now).Hours()
		}
		secrets = append(secrets, item)

		switch strings.ToLower(strings.TrimSpace(secret.Status)) {
		case "disabled", "revoked":
			incidents = append(incidents, map[string]any{
				"severity":            "critical",
				"status":              "open",
				"category":            "secret",
				"title":               "Managed secret requires remediation",
				"message":             fmt.Sprintf("Managed secret %s/%s is %s.", secret.Namespace, secret.Name, secret.Status),
				"component_kind":      "secret",
				"component_name":      secret.Name,
				"component_namespace": secret.Namespace,
			})
		}
		if secret.IsExpired(now) {
			incidents = append(incidents, map[string]any{
				"severity":            "critical",
				"status":              "open",
				"category":            "secret",
				"title":               "Managed secret expired",
				"message":             fmt.Sprintf("Managed secret %s/%s expired.", secret.Namespace, secret.Name),
				"component_kind":      "secret",
				"component_name":      secret.Name,
				"component_namespace": secret.Namespace,
			})
		}
	}

	repositories := make([]map[string]any, 0, len(repositoryBindings))
	for _, binding := range repositoryBindings {
		repositories = append(repositories, map[string]any{
			"name":                          binding.Spec.ComponentName,
			"component_kind":                binding.Spec.ComponentKind,
			"component_namespace":           binding.Spec.ComponentNamespace,
			"component_name":                binding.Spec.ComponentName,
			"repository":                    binding.Spec.Repository,
			"default_branch":                binding.Spec.DefaultBranch,
			"deploy_workflow":               binding.Spec.DeployWorkflow,
			"observe":                       binding.Spec.Automation.Observe,
			"allow_dispatch_workflow":       binding.Spec.Automation.AllowDispatchWorkflow,
			"allow_pull_request_automation": binding.Spec.Automation.AllowPullRequestAutomation,
			"allow_direct_push":             binding.Spec.Automation.AllowDirectPush,
			"metadata":                      cloneAuthorizationInput(binding.Spec.Metadata),
		})
	}

	snapshot := map[string]any{
		"integrations": integrations,
		"surfaces":     surfaces,
		"secrets":      secrets,
		"incidents":    incidents,
		"signals":      []map[string]any{},
		"repositories": repositories,
		"metadata": map[string]any{
			"generated_at":           now.Format(time.RFC3339),
			"repository_bindings":    len(repositoryBindings),
			"default_guardian_scope": "global",
		},
	}

	memories, err := loadHeimdallGuardianMemories(ctx, db)
	if err != nil {
		return nil, err
	}
	if err := observeHeimdallGuardianMemories(ctx, db, snapshot, memories); err != nil {
		return nil, err
	}
	memories, err = loadHeimdallGuardianMemories(ctx, db)
	if err != nil {
		return nil, err
	}
	snapshot["memories"] = heimdallGuardianMemoryItems(memories)
	metadata := snapshot["metadata"].(map[string]any)
	metadata["guardian_memories"] = len(memories)

	return snapshot, nil
}

func heimdallRepositoryBindingMetadata(binding heimdallRepositoryBinding) map[string]any {
	metadata := map[string]any{
		"repository":                    binding.Spec.Repository,
		"default_branch":                binding.Spec.DefaultBranch,
		"deploy_workflow":               binding.Spec.DeployWorkflow,
		"allow_dispatch_workflow":       binding.Spec.Automation.AllowDispatchWorkflow,
		"allow_direct_push":             binding.Spec.Automation.AllowDirectPush,
		"allow_pull_request_automation": binding.Spec.Automation.AllowPullRequestAutomation,
	}
	return mergeStringAnyMaps(metadata, cloneAuthorizationInput(binding.Spec.Metadata))
}

func heimdallApplyIntegrationGuardianSignals(
	item map[string]any,
	state *model.IntegrationRuntimeState,
	support model.IntegrationGuardianSupportSpec,
) map[string]any {
	if item == nil {
		item = map[string]any{}
	}
	support = manifestengine.NormalizeIntegrationGuardianSupport(support)
	item["guardian_support_mode"] = support.Mode

	if state == nil {
		return item
	}

	supportedSignals := []string{}
	setNumeric := func(label string, keys []string, fallback ...string) {
		if value, ok := heimdallGuardianNumericSignal(state, keys, fallback...); ok {
			item[label] = value
			supportedSignals = append(supportedSignals, label)
		}
	}
	setBool := func(label string, keys []string, fallback ...string) {
		if value, ok := heimdallGuardianBoolSignal(state, keys, fallback...); ok {
			item[label] = value
			supportedSignals = append(supportedSignals, label)
		}
	}

	setBool("oom_killed", support.Signals.OOMKilled, "oom_killed", "oom")
	setNumeric("restart_count", support.Signals.RestartCount, "restart_count", "crash_loop_count")
	setNumeric("error_rate", support.Signals.ErrorRate, "error_rate", "failure_rate")
	setNumeric("queue_backlog", support.Signals.QueueBacklog, "queue_backlog", "backlog", "consumer_backlog")
	setBool("memory_pressure", support.Signals.MemoryPressure, "memory_pressure")
	setBool("disk_pressure", support.Signals.DiskPressure, "disk_pressure")
	setBool("rate_limited", support.Signals.RateLimited, "rate_limited")
	setBool("auth_denied", support.Signals.AuthDenied, "auth_denied")
	setNumeric("sync_lag_seconds", support.Signals.SyncLagSeconds, "sync_lag_seconds", "replication_lag_seconds")
	setNumeric("monthly_cost_usd", support.Signals.MonthlyCostUSD, "monthly_cost_usd")
	setNumeric("utilization", support.Signals.Utilization, "utilization", "cpu_utilization", "avg_utilization")
	setNumeric("idle_hours", support.Signals.IdleHours, "idle_hours", "last_active_hours_ago")
	setBool("overprovisioned", support.Signals.Overprovisioned, "overprovisioned")
	setBool("scheduling_failure", support.Signals.SchedulingFailure, "scheduling_failure", "failed_scheduling", "unschedulable")
	setBool("insufficient_cpu", support.Signals.InsufficientCPU, "insufficient_cpu", "cpu_pressure", "cpu_exhausted")

	if len(supportedSignals) > 0 {
		item["guardian_supported_signals"] = supportedSignals
	}

	return item
}

func heimdallGuardianNumericSignal(
	state *model.IntegrationRuntimeState,
	aliases []string,
	fallbackKeys ...string,
) (float64, bool) {
	if state == nil {
		return 0, false
	}
	keys := append(cloneStringSlice(aliases), fallbackKeys...)
	return heimdallNumericDetail(state.Details, keys...)
}

func heimdallGuardianBoolSignal(
	state *model.IntegrationRuntimeState,
	aliases []string,
	fallbackKeys ...string,
) (bool, bool) {
	if state == nil {
		return false, false
	}
	keys := append(cloneStringSlice(aliases), fallbackKeys...)
	if heimdallBoolDetail(state.Details, keys...) {
		return true, true
	}

	message := strings.ToLower(strings.TrimSpace(state.Message))
	switch {
	case containsAnyString(message, "oom", "out of memory") && containsKey(keys, "oom_killed", "oom"):
		return true, true
	case containsAnyString(message, "unauthorized", "forbidden", "access denied") && containsKey(keys, "auth_denied"):
		return true, true
	case containsAnyString(message, "rate limit", "too many requests", "throttl") && containsKey(keys, "rate_limited"):
		return true, true
	case containsAnyString(message, "disk pressure", "no space left") && containsKey(keys, "disk_pressure"):
		return true, true
	case containsAnyString(message, "memory pressure") && containsKey(keys, "memory_pressure"):
		return true, true
	case containsAnyString(message, "failedscheduling", "failed scheduling", "cannot schedule", "unschedulable", "pending") &&
		containsKey(keys, "scheduling_failure", "failed_scheduling", "unschedulable"):
		return true, true
	case containsAnyString(message, "insufficient cpu", "not enough cpu", "cpu pressure", "cpu exhausted") &&
		containsKey(keys, "insufficient_cpu", "cpu_pressure", "cpu_exhausted"):
		return true, true
	default:
		return false, false
	}
}

func heimdallIntegrationIncidents(health model.IntegrationInstanceHealth, item map[string]any) []map[string]any {
	if health.RuntimeState == nil {
		return nil
	}
	evidence := mergeStringAnyMaps(cloneAuthorizationInput(health.RuntimeState.Details), map[string]any{
		"type_name":             health.IntegrationType.Name,
		"type_namespace":        health.IntegrationType.Namespace,
		"repository":            anyString(item["repository"]),
		"guardian_support_mode": anyString(item["guardian_support_mode"]),
	})

	status := strings.ToLower(strings.TrimSpace(health.RuntimeState.Status))
	severity := ""
	category := ""
	switch status {
	case model.IntegrationRuntimeStatusUnreachable:
		severity = "critical"
		category = "availability"
	case model.IntegrationRuntimeStatusInvalidResponse:
		severity = "critical"
		category = "stability"
	case model.IntegrationRuntimeStatusContractMismatch:
		severity = "high"
		category = "contract"
	default:
		severity = ""
	}

	incidents := make([]map[string]any, 0, 2)
	if severity != "" {
		incidents = append(incidents, map[string]any{
			"severity":            severity,
			"status":              "open",
			"category":            category,
			"title":               fmt.Sprintf("Integration %s is %s", health.IntegrationInstance.Name, status),
			"message":             health.RuntimeState.Message,
			"component_kind":      "integration",
			"component_name":      health.IntegrationInstance.Name,
			"component_namespace": health.IntegrationInstance.Namespace,
			"repository":          anyString(item["repository"]),
			"evidence":            cloneAuthorizationInput(evidence),
		})
	}

	if firstBool(item, []string{"scheduling_failure", "insufficient_cpu"}, false) {
		incidents = append(incidents, map[string]any{
			"severity":            "critical",
			"status":              "open",
			"category":            "capacity_scheduling_failure",
			"title":               fmt.Sprintf("Integration %s cannot schedule workloads due to CPU pressure", health.IntegrationInstance.Name),
			"message":             firstNonEmpty(health.RuntimeState.Message, "The provider reported scheduling failure caused by insufficient CPU capacity."),
			"component_kind":      "integration",
			"component_name":      health.IntegrationInstance.Name,
			"component_namespace": health.IntegrationInstance.Namespace,
			"repository":          anyString(item["repository"]),
			"evidence":            cloneAuthorizationInput(evidence),
		})
	}

	if firstBool(item, []string{"oom_killed", "memory_pressure"}, false) || heimdallRuntimeIndicatesOOM(health.RuntimeState) {
		incidents = append(incidents, map[string]any{
			"severity":            "critical",
			"status":              "open",
			"category":            "capacity",
			"title":               fmt.Sprintf("Integration %s was OOM killed", health.IntegrationInstance.Name),
			"message":             firstNonEmpty(health.RuntimeState.Message, "The runtime reported an OOM termination and likely needs a bounded memory increase."),
			"component_kind":      "integration",
			"component_name":      health.IntegrationInstance.Name,
			"component_namespace": health.IntegrationInstance.Namespace,
			"repository":          anyString(item["repository"]),
			"evidence":            cloneAuthorizationInput(evidence),
		})
	}

	if firstBool(item, []string{"auth_denied"}, false) {
		incidents = append(incidents, map[string]any{
			"severity":            "critical",
			"status":              "open",
			"category":            "auth",
			"title":               fmt.Sprintf("Integration %s lost authentication", health.IntegrationInstance.Name),
			"message":             firstNonEmpty(health.RuntimeState.Message, "The runtime indicates authorization failed and can no longer reach its provider."),
			"component_kind":      "integration",
			"component_name":      health.IntegrationInstance.Name,
			"component_namespace": health.IntegrationInstance.Namespace,
			"repository":          anyString(item["repository"]),
			"evidence":            cloneAuthorizationInput(evidence),
		})
	}

	if firstBool(item, []string{"rate_limited"}, false) {
		incidents = append(incidents, map[string]any{
			"severity":            "high",
			"status":              "open",
			"category":            "quota",
			"title":               fmt.Sprintf("Integration %s is being rate limited", health.IntegrationInstance.Name),
			"message":             firstNonEmpty(health.RuntimeState.Message, "The provider is throttling the integration and ecosystem reconciliation may lag."),
			"component_kind":      "integration",
			"component_name":      health.IntegrationInstance.Name,
			"component_namespace": health.IntegrationInstance.Namespace,
			"repository":          anyString(item["repository"]),
			"evidence":            cloneAuthorizationInput(evidence),
		})
	}

	if firstBool(item, []string{"disk_pressure"}, false) {
		incidents = append(incidents, map[string]any{
			"severity":            "critical",
			"status":              "open",
			"category":            "capacity",
			"title":               fmt.Sprintf("Integration %s is under disk pressure", health.IntegrationInstance.Name),
			"message":             firstNonEmpty(health.RuntimeState.Message, "The runtime reported disk pressure and may fail to reconcile."),
			"component_kind":      "integration",
			"component_name":      health.IntegrationInstance.Name,
			"component_namespace": health.IntegrationInstance.Namespace,
			"repository":          anyString(item["repository"]),
			"evidence":            cloneAuthorizationInput(evidence),
		})
	}

	return incidents
}

func executeHeimdallActions(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	actions []map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
	remediationContracts map[string]heimdallRemediationContract,
	policy model.GuardianPolicyManifestSpec,
	source string,
	executedSoFar int,
) (int, error) {
	executed := executedSoFar
	var firstErr error
	for _, action := range actions {
		if executed >= policy.AutoHeal.MaxActionsPerSweep {
			break
		}
		if err := executeHeimdallAction(ctx, conn, db, action, repositoryBindings, remediationContracts, policy, source); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		executed++
	}
	return executed, firstErr
}

func executeHeimdallAction(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	action map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
	remediationContracts map[string]heimdallRemediationContract,
	policy model.GuardianPolicyManifestSpec,
	source string,
) error {
	return executeHeimdallActionWithOptions(
		ctx,
		conn,
		db,
		action,
		repositoryBindings,
		remediationContracts,
		policy,
		source,
		heimdallExecutionOptions{},
	)
}

func executeHeimdallActionWithOptions(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	action map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
	remediationContracts map[string]heimdallRemediationContract,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
) error {
	action = heimdallEnrichActionOperationalContext(action, repositoryBindings)
	decision := options.Decision
	if decision == nil {
		resolved, err := heimdallResolveAutonomyDecision(ctx, db, action, policy, source)
		if err != nil {
			return err
		}
		decision = &resolved
		options.Decision = decision
	}

	action, _, err := ensureHeimdallRemediationBundleAction(ctx, db, action, policy, source, options)
	if err != nil {
		return err
	}
	if anyString(action["type"]) == "remediation_bundle" && policy.GeneratedBundles.RequireApproval && !options.SkipApproval {
		decision.RequireApproval = true
	}
	if anyString(action["type"]) == "upsert_capacity_hotfix_profile" && policy.ProfilePromotions.RequireApproval && !options.SkipApproval {
		decision.RequireApproval = true
	}

	if decision.Escalate {
		return executeHeimdallEscalation(ctx, conn, db, action, repositoryBindings, policy, source, options)
	}

	if !options.SkipApproval && decision.RequireApproval {
		return createHeimdallApprovalRequest(ctx, db, action, policy, source, *decision)
	}

	memory, err := ensureHeimdallExecutionMemory(ctx, db, action, policy, source, options)
	if err != nil {
		return err
	}

	actionType := strings.ToLower(strings.TrimSpace(anyString(action["type"])))
	switch actionType {
	case "dispatch_workflow":
		if !policy.AutoHeal.AllowDispatchWorkflow {
			return fmt.Errorf("heimdall guardian policy blocks dispatch_workflow actions")
		}
		err = executeHeimdallWorkflowDispatch(ctx, conn, db, action, repositoryBindings, policy, source, options)
	case "rightsize_component":
		allowRightsize := policy.AutoHeal.AllowRightsize
		if source == "cost_optimization" {
			allowRightsize = policy.CostOptimization.AllowRightsize
		}
		if !allowRightsize {
			return fmt.Errorf("heimdall guardian policy blocks rightsize_component actions")
		}
		err = executeHeimdallContractAction(ctx, conn, db, action, repositoryBindings, remediationContracts, policy, source, options)
	case "rotate_secret":
		if !policy.AutoHeal.AllowRotateSecret {
			return fmt.Errorf("heimdall guardian policy blocks rotate_secret actions")
		}
		err = executeHeimdallSecretRotation(ctx, db, action)
	case "page_team":
		err = executeHeimdallHumanEscalation(ctx, db, action, policy, source, options)
	case "remediation_bundle":
		err = executeHeimdallRemediationBundle(ctx, conn, db, action, repositoryBindings, policy, source, options)
	case "upsert_capacity_hotfix_profile":
		if !policy.ProfilePromotions.Enabled {
			return fmt.Errorf("heimdall guardian policy blocks capacity hotfix profile promotions")
		}
		err = executeHeimdallCapacityHotfixProfileUpsert(ctx, db, action)
	default:
		if _, _, contractErr := resolveHeimdallContractAction(action, remediationContracts); contractErr == nil {
			err = executeHeimdallContractAction(ctx, conn, db, action, repositoryBindings, remediationContracts, policy, source, options)
			break
		}
		err = fmt.Errorf("heimdall action type %q is not executable by the core loop", actionType)
	}

	if memoryErr := finalizeHeimdallExecutionMemory(ctx, db, memory, action, err); memoryErr != nil && err == nil {
		return memoryErr
	}
	return err
}

func executeHeimdallCapacityHotfixProfileUpsert(
	ctx context.Context,
	db *sql.DB,
	action map[string]any,
) error {
	if db == nil {
		return fmt.Errorf("database connection is required to persist capacity hotfix profiles")
	}

	profile, err := heimdallCapacityHotfixProfileFromAction(action)
	if err != nil {
		return err
	}

	target := asObject(action["target"])
	guardianRef := asObject(target["guardian"])
	guardianNamespace := firstNonEmpty(
		anyString(guardianRef["namespace"]),
		anyString(action["component_namespace"]),
		defaultHeimdallGuardianNamespace,
	)
	guardianName := firstNonEmpty(
		anyString(guardianRef["name"]),
		anyString(action["component_name"]),
		defaultHeimdallGuardianInstance,
	)

	manifestRecord, err := repository.ResolveManifest(ctx, db, "integration_instance", guardianNamespace, guardianName, nil, true)
	if err != nil {
		return err
	}

	spec, err := manifestengine.ParseIntegrationInstanceSpec(manifestRecord.Spec)
	if err != nil {
		return fmt.Errorf("parse guardian integration_instance spec: %w", err)
	}
	if spec.Config == nil {
		spec.Config = map[string]any{}
	}

	existingProfiles := objectSlice(spec.Config["capacity_hotfix_profiles"])
	spec.Config["capacity_hotfix_profiles"] = heimdallMergeCapacityHotfixProfiles(existingProfiles, profile)

	specRaw, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("marshal guardian integration_instance spec: %w", err)
	}

	active := manifestRecord.Metadata.Active
	_, err = heimdallCreateManifestVersion(ctx, db, model.ManifestDocument{
		APIVersion: manifestRecord.APIVersion,
		Kind:       manifestRecord.Kind,
		Metadata: model.ManifestMetadataInput{
			Name:        manifestRecord.Metadata.Name,
			Namespace:   manifestRecord.Metadata.Namespace,
			Description: manifestRecord.Metadata.Description,
			Labels:      heimdallCloneStringMap(manifestRecord.Metadata.Labels),
			Active:      &active,
		},
		Spec: specRaw,
	})
	return err
}

// ExecuteHeimdallApprovedAction executes a previously approved guardian action
// without re-requesting approval or blocking on the original cooldown window.
func ExecuteHeimdallApprovedAction(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	approval model.GuardianApprovalManifestSpec,
) error {
	if db == nil {
		return fmt.Errorf("database connection is required to execute approved guardian actions")
	}
	if approval.Action == nil {
		return fmt.Errorf("guardian approval does not contain an action payload")
	}

	guardianNamespace := firstNonEmpty(approval.GuardianRef.Namespace, defaultHeimdallGuardianNamespace)
	guardianName := firstNonEmpty(approval.GuardianRef.Name, defaultHeimdallGuardianInstance)
	guardianManifest, err := repository.ResolveManifest(ctx, db, "integration_instance", guardianNamespace, guardianName, nil, true)
	if err != nil {
		return err
	}

	policy, err := loadGuardianPolicyForInstance(ctx, db, guardianManifest)
	if err != nil {
		return err
	}
	policy.Autonomy.Mode = "policy_bound"

	repositoryBindings, err := loadHeimdallRepositoryBindings(ctx, db)
	if err != nil {
		return err
	}
	remediationContracts, err := loadHeimdallRemediationContracts(ctx, db)
	if err != nil {
		return err
	}

	return executeHeimdallActionWithOptions(
		ctx,
		conn,
		db,
		cloneAuthorizationInput(approval.Action),
		repositoryBindings,
		remediationContracts,
		policy,
		firstNonEmpty(approval.Source, "approved_guardian_action"),
		heimdallExecutionOptions{
			SkipApproval: true,
			SkipCooldown: true,
			MemoryName:   anyString(approval.Metadata["memory_name"]),
			MemoryNS:     anyString(approval.Metadata["memory_namespace"]),
		},
	)
}

func heimdallResolveAutonomyDecision(
	ctx context.Context,
	db *sql.DB,
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
) (heimdallAutonomyDecision, error) {
	assessment, err := heimdallAssessActionConfidence(ctx, db, action)
	if err != nil {
		return heimdallAutonomyDecision{}, err
	}
	return heimdallDecisionFromAssessmentAt(action, policy, source, assessment, time.Now().UTC()), nil
}

func heimdallDecisionFromAssessment(
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
	assessment heimdallActionConfidenceAssessment,
) heimdallAutonomyDecision {
	return heimdallDecisionFromAssessmentAt(action, policy, source, assessment, time.Now().UTC())
}

func heimdallDecisionFromAssessmentAt(
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
	assessment heimdallActionConfidenceAssessment,
	now time.Time,
) heimdallAutonomyDecision {
	blastRadius, blastRadiusReason := heimdallResolveActionBlastRadius(action)
	if strings.TrimSpace(assessment.BlastRadius) != "" {
		blastRadius = assessment.BlastRadius
	}
	if strings.TrimSpace(assessment.BlastRadiusReason) != "" {
		blastRadiusReason = assessment.BlastRadiusReason
	}
	operational := heimdallResolveOperationalContext(action, policy, now)

	decision := heimdallAutonomyDecision{
		Mode:                 policy.Autonomy.Mode,
		Confidence:           assessment.Confidence,
		ConfidenceBand:       heimdallConfidenceBand(policy, assessment.Confidence),
		ProviderGroup:        assessment.ProviderGroup,
		IncidentCategory:     assessment.IncidentCategory,
		Attempts:             assessment.Attempts,
		RecoveryRate:         assessment.RecoveryRate,
		BlastRadius:          blastRadius,
		BlastRadiusReason:    blastRadiusReason,
		Environment:          firstNonEmpty(assessment.Environment, operational.Environment),
		OutsideBusinessHours: operational.OutsideBusinessHours,
		ActiveFreezeWindow:   operational.ActiveFreezeWindow,
		ProtectedEnvironment: operational.ProtectedEnvironment,
		MaintenanceActive:    operational.MaintenanceActive,
		MaintenanceReason:    operational.MaintenanceReason,
	}
	autoExecuteAllowed := heimdallBlastRadiusWithinLimit(blastRadius, operational.EffectiveAutoBlastRadius)
	hotfixBypassAllowed := heimdallBlastRadiusWithinLimit(blastRadius, operational.EffectiveBypassBlastRadius)
	if operational.MaintenanceActive {
		autoExecuteAllowed = false
		if !operational.MaintenanceAllowsBypass {
			hotfixBypassAllowed = false
		}
	}
	if operational.OutsideBusinessHours {
		autoExecuteAllowed = false
		if !operational.BusinessHoursAllowsBypass {
			hotfixBypassAllowed = false
		}
	}
	if operational.ActiveFreezeWindow != "" {
		autoExecuteAllowed = false
		if !operational.FreezeAllowsBypass {
			hotfixBypassAllowed = false
		}
	}
	if shouldEscalate, reason := heimdallShouldEscalateAction(action, policy, source, assessment, operational); shouldEscalate {
		decision.Escalate = true
		decision.ConfidenceBand = "escalation"
		decision.EscalationReason = reason
		decision.Reason = heimdallAppendOperationalReason(reason, operational)
		decision.ManualReview = policy.Escalation.CreateApproval
		return decision
	}

	if policy.Autonomy.Mode == "approval_required" {
		decision.RequireApproval = true
		decision.ManualReview = assessment.Confidence <= policy.Autonomy.ManualReviewBelowConfidence || !hotfixBypassAllowed || operational.ActiveFreezeWindow != ""
		decision.Reason = "guardian policy requires approval for every action"
		if !autoExecuteAllowed {
			decision.Reason = fmt.Sprintf("%s Blast radius %q is above the auto-execute limit %q.", decision.Reason, blastRadius, operational.EffectiveAutoBlastRadius)
		}
		decision.Reason = heimdallAppendOperationalReason(decision.Reason, operational)
		return decision
	}

	if policy.Autonomy.Mode == "bypass_hotfix" && source == "critical_auto_remediation" &&
		heimdallSeverityMeetsThreshold(firstNonEmpty(anyString(heimdallIncidentFromAction(action)["severity"]), "critical"), policy.Autonomy.HotfixSeverityThreshold) {
		if hotfixBypassAllowed {
			decision.ConfidenceBand = "bypass_hotfix"
			decision.Reason = "guardian policy allows emergency bypass for this hotfix severity"
			decision.Reason = heimdallAppendOperationalReason(decision.Reason, operational)
			return decision
		}
		decision.RequireApproval = true
		decision.ManualReview = true
		decision.ConfidenceBand = "manual_review"
		decision.Reason = fmt.Sprintf(
			"incident qualifies for hotfix bypass, but blast radius %q exceeds the bypass limit %q",
			blastRadius,
			operational.EffectiveBypassBlastRadius,
		)
		decision.Reason = heimdallAppendOperationalReason(decision.Reason, operational)
		return decision
	}

	if assessment.Confidence >= policy.Autonomy.AutoExecuteMinConfidence {
		if autoExecuteAllowed {
			decision.Reason = "historical memory shows this playbook is safe enough to auto-execute"
			decision.Reason = heimdallAppendOperationalReason(decision.Reason, operational)
			return decision
		}
		decision.RequireApproval = true
		decision.ManualReview = !hotfixBypassAllowed || operational.ActiveFreezeWindow != ""
		if decision.ManualReview {
			decision.ConfidenceBand = "manual_review"
		} else {
			decision.ConfidenceBand = "approval"
		}
		decision.Reason = fmt.Sprintf(
			"historical memory is strong, but blast radius %q exceeds the auto-execute limit %q",
			blastRadius,
			operational.EffectiveAutoBlastRadius,
		)
		decision.Reason = heimdallAppendOperationalReason(decision.Reason, operational)
		return decision
	}

	decision.RequireApproval = true
	if assessment.Confidence <= policy.Autonomy.ManualReviewBelowConfidence {
		decision.ManualReview = true
		decision.Reason = "historical confidence is low and requires manual review"
	} else {
		decision.Reason = "historical confidence is moderate, so approval is required before execution"
	}
	if !hotfixBypassAllowed {
		decision.ManualReview = true
		decision.ConfidenceBand = "manual_review"
		decision.Reason = fmt.Sprintf(
			"%s Blast radius %q exceeds the bypass limit %q.",
			decision.Reason,
			blastRadius,
			operational.EffectiveBypassBlastRadius,
		)
	} else if !autoExecuteAllowed {
		decision.Reason = fmt.Sprintf(
			"%s Blast radius %q exceeds the auto-execute limit %q.",
			decision.Reason,
			blastRadius,
			operational.EffectiveAutoBlastRadius,
		)
	}
	if operational.ActiveFreezeWindow != "" {
		decision.ManualReview = true
		decision.ConfidenceBand = "manual_review"
	}
	decision.Reason = heimdallAppendOperationalReason(decision.Reason, operational)
	return decision
}

func heimdallConfidenceBand(policy model.GuardianPolicyManifestSpec, confidence float64) string {
	switch {
	case confidence >= policy.Autonomy.AutoExecuteMinConfidence:
		return "trusted"
	case confidence <= policy.Autonomy.ManualReviewBelowConfidence:
		return "manual_review"
	default:
		return "approval"
	}
}

func heimdallShouldEscalateAction(
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
	assessment heimdallActionConfidenceAssessment,
	operational heimdallOperationalContext,
) (bool, string) {
	if !policy.Escalation.Enabled {
		return false, ""
	}
	if !heimdallEnvironmentMatches(operational.Environment, policy.Escalation.Environments) {
		return false, ""
	}

	incident := heimdallIncidentFromAction(action)
	severity := firstNonEmpty(anyString(incident["severity"]), anyString(action["incident_severity"]), "critical")
	if !heimdallSeverityMeetsThreshold(severity, policy.Escalation.SeverityThreshold) {
		return false, ""
	}

	if operational.MaintenanceActive && source == "critical_auto_remediation" {
		return true, "maintenance mode is active, so Heimdall will stop healing and escalate this incident"
	}

	if source != "critical_auto_remediation" {
		return false, ""
	}
	if assessment.Attempts >= float64(policy.Escalation.MaxAutoHealAttempts) {
		recoveryRate := math.Round(assessment.RecoveryRate*100) / 100
		return true, fmt.Sprintf(
			"automatic remediation already tried this playbook %.0f times with recovery rate %.2f, so Heimdall is escalating",
			assessment.Attempts,
			recoveryRate,
		)
	}

	return false, ""
}

func heimdallResolveActionBlastRadius(action map[string]any) (string, string) {
	if explicit := heimdallNormalizeBlastRadius(anyString(action["blast_radius"])); explicit != "" {
		return explicit, "declared by the action payload"
	}

	actionType := strings.ToLower(strings.TrimSpace(anyString(action["type"])))
	switch actionType {
	case "dispatch_workflow":
		if strings.TrimSpace(anyString(action["component_name"])) != "" {
			return "medium", "workflow dispatch redeploys or reconciles one component"
		}
		return "high", "workflow dispatch without a narrow component target is treated as broader impact"
	case "rightsize_component":
		changePercent, _ := heimdallNumericDetail(action, "max_change_percent")
		switch {
		case changePercent <= 0:
			return "medium", "right-size remediation changes live capacity on a bounded component"
		case changePercent <= 25:
			return "medium", fmt.Sprintf("right-size remediation is bounded to %.0f%% change", changePercent)
		case changePercent <= 50:
			return "high", fmt.Sprintf("right-size remediation can change live capacity by %.0f%%", changePercent)
		default:
			return "critical", fmt.Sprintf("right-size remediation can change live capacity by %.0f%%", changePercent)
		}
	case "rotate_secret":
		return "medium", "secret rotation changes live credentials and may affect running components"
	case "pull_request":
		return "medium", "pull request automation proposes code changes without merging directly"
	case "direct_push":
		return "critical", "direct push mutates the repository without human review"
	case "page_team":
		return "low", "paging humans does not mutate runtime state"
	default:
		if strings.TrimSpace(anyString(action["repository"])) != "" {
			return "high", "repository-targeted action is treated conservatively without an explicit blast radius"
		}
		return "high", "unknown action type defaults to a conservative blast radius"
	}
}

func heimdallNormalizeBlastRadius(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low", "medium", "high", "critical":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return ""
	}
}

func heimdallBlastRadiusWithinLimit(radius string, limit string) bool {
	return heimdallBlastRadiusRank(radius) > 0 &&
		heimdallBlastRadiusRank(limit) > 0 &&
		heimdallBlastRadiusRank(radius) <= heimdallBlastRadiusRank(limit)
}

func heimdallBlastRadiusRank(value string) int {
	switch heimdallNormalizeBlastRadius(value) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}

func heimdallEnrichActionOperationalContext(
	action map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
) map[string]any {
	enriched := cloneAuthorizationInput(action)
	if strings.TrimSpace(anyString(enriched["environment"])) != "" {
		return enriched
	}
	if binding, err := resolveHeimdallActionBinding(enriched, repositoryBindings); err == nil {
		environment := strings.ToLower(strings.TrimSpace(anyString(binding.Spec.Metadata["environment"])))
		if environment != "" {
			enriched["environment"] = environment
		}
	}
	return enriched
}

func heimdallResolveOperationalContext(
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	now time.Time,
) heimdallOperationalContext {
	environment := heimdallActionEnvironment(action)
	context := heimdallOperationalContext{
		Environment:                environment,
		EffectiveAutoBlastRadius:   policy.Autonomy.MaxAutoExecuteBlastRadius,
		EffectiveBypassBlastRadius: policy.Autonomy.MaxBypassHotfixBlastRadius,
		BusinessHoursAllowsBypass:  policy.Autonomy.BusinessHours.AllowHotfixBypass,
		MaintenanceAllowsBypass:    policy.MaintenanceMode.AllowHotfixBypass,
	}
	if heimdallEnvironmentMatches(environment, policy.Autonomy.ProtectedEnvironments.Environments) {
		context.ProtectedEnvironment = true
		context.EffectiveAutoBlastRadius = heimdallMinBlastRadius(context.EffectiveAutoBlastRadius, policy.Autonomy.ProtectedEnvironments.MaxAutoExecuteBlastRadius)
		context.EffectiveBypassBlastRadius = heimdallMinBlastRadius(context.EffectiveBypassBlastRadius, policy.Autonomy.ProtectedEnvironments.MaxBypassHotfixBlastRadius)
	}
	if policy.Autonomy.BusinessHours.Enabled && heimdallEnvironmentMatches(environment, policy.Autonomy.BusinessHours.Environments) {
		context.OutsideBusinessHours, context.BusinessHoursReason = heimdallOutsideBusinessHours(policy.Autonomy.BusinessHours, now)
	}
	if active, reason, allowBypass := heimdallActiveFreezeWindow(policy.Autonomy.FreezeWindows, environment, now); active != "" {
		context.ActiveFreezeWindow = active
		context.FreezeReason = reason
		context.FreezeAllowsBypass = allowBypass
	}
	if policy.MaintenanceMode.Enabled && heimdallEnvironmentMatches(environment, policy.MaintenanceMode.Environments) {
		context.MaintenanceActive = true
		context.MaintenanceReason = firstNonEmpty(policy.MaintenanceMode.Reason, "Maintenance mode is active for this environment.")
	}
	if context.EffectiveAutoBlastRadius == "" {
		context.EffectiveAutoBlastRadius = policy.Autonomy.MaxAutoExecuteBlastRadius
	}
	if context.EffectiveBypassBlastRadius == "" {
		context.EffectiveBypassBlastRadius = policy.Autonomy.MaxBypassHotfixBlastRadius
	}
	return context
}

func heimdallAppendOperationalReason(reason string, context heimdallOperationalContext) string {
	if context.Environment != "" {
		reason = fmt.Sprintf("%s Environment=%s.", strings.TrimSpace(reason), context.Environment)
	}
	if context.ProtectedEnvironment {
		reason = fmt.Sprintf("%s Protected-environment limits apply.", strings.TrimSpace(reason))
	}
	if context.OutsideBusinessHours && context.BusinessHoursReason != "" {
		reason = fmt.Sprintf("%s %s", strings.TrimSpace(reason), context.BusinessHoursReason)
	}
	if context.ActiveFreezeWindow != "" {
		if context.FreezeReason != "" {
			reason = fmt.Sprintf("%s %s", strings.TrimSpace(reason), context.FreezeReason)
		} else {
			reason = fmt.Sprintf("%s Freeze window %q is active.", strings.TrimSpace(reason), context.ActiveFreezeWindow)
		}
	}
	if context.MaintenanceActive {
		if context.MaintenanceReason != "" {
			reason = fmt.Sprintf("%s %s", strings.TrimSpace(reason), context.MaintenanceReason)
		} else {
			reason = fmt.Sprintf("%s Maintenance mode is active.", strings.TrimSpace(reason))
		}
	}
	return strings.TrimSpace(reason)
}

func heimdallActionEnvironment(action map[string]any) string {
	target := heimdallActionObject(action, "target")
	incident := heimdallActionObject(action, "incident")
	return strings.ToLower(strings.TrimSpace(firstNonEmpty(
		anyString(action["environment"]),
		anyString(target["environment"]),
		anyString(incident["environment"]),
	)))
}

func heimdallEnvironmentMatches(environment string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	normalized := strings.ToLower(strings.TrimSpace(environment))
	if normalized == "" {
		return false
	}
	for _, candidate := range allowed {
		if normalized == strings.ToLower(strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func heimdallOutsideBusinessHours(spec model.GuardianBusinessHoursPolicySpec, now time.Time) (bool, string) {
	location, err := time.LoadLocation(spec.Timezone)
	if err != nil {
		location = time.UTC
	}
	local := now.In(location)
	weekday := heimdallNormalizeWeekday(local.Weekday())
	allowedDay := false
	for _, candidate := range spec.Weekdays {
		if weekday == candidate {
			allowedDay = true
			break
		}
	}
	if !allowedDay {
		return true, fmt.Sprintf("Current local weekday %s is outside configured business days in %s.", weekday, location.String())
	}
	if !heimdallHourInWindow(local.Hour(), spec.StartHour, spec.EndHour) {
		return true, fmt.Sprintf("Current local hour %02d:00 is outside configured business hours in %s.", local.Hour(), location.String())
	}
	return false, ""
}

func heimdallHourInWindow(hour, start, end int) bool {
	if start == end {
		return true
	}
	if start < end {
		return hour >= start && hour < end
	}
	return hour >= start || hour < end
}

func heimdallActiveFreezeWindow(
	windows []model.GuardianFreezeWindowPolicySpec,
	environment string,
	now time.Time,
) (string, string, bool) {
	for _, window := range windows {
		if !heimdallEnvironmentMatches(environment, window.Environments) {
			continue
		}
		start, err := time.Parse(time.RFC3339, window.StartsAt)
		if err != nil {
			continue
		}
		end, err := time.Parse(time.RFC3339, window.EndsAt)
		if err != nil {
			continue
		}
		if now.Before(start) || !now.Before(end) {
			continue
		}
		return window.Name, fmt.Sprintf("Freeze window %q is active until %s.", window.Name, end.UTC().Format(time.RFC3339)), window.AllowHotfixBypass
	}
	return "", "", false
}

func heimdallMinBlastRadius(left, right string) string {
	if heimdallBlastRadiusRank(left) == 0 {
		return right
	}
	if heimdallBlastRadiusRank(right) == 0 {
		return left
	}
	if heimdallBlastRadiusRank(left) <= heimdallBlastRadiusRank(right) {
		return left
	}
	return right
}

func heimdallNormalizeWeekday(weekday time.Weekday) string {
	switch weekday {
	case time.Monday:
		return "mon"
	case time.Tuesday:
		return "tue"
	case time.Wednesday:
		return "wed"
	case time.Thursday:
		return "thu"
	case time.Friday:
		return "fri"
	case time.Saturday:
		return "sat"
	default:
		return "sun"
	}
}

func createHeimdallApprovalRequest(
	ctx context.Context,
	db *sql.DB,
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
	decision heimdallAutonomyDecision,
) error {
	if db == nil {
		return fmt.Errorf("database connection is required to persist guardian approvals")
	}
	binding := heimdallActionCooldownBinding(action)
	if !heimdallActionCooldownAllowed(action, binding, policy) {
		return fmt.Errorf("heimdall approval request for %s/%s is still in cooldown", binding.ComponentNamespace, binding.ComponentName)
	}

	componentKind := firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"]), "component")
	componentNamespace := firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), "global")
	componentName := firstNonEmpty(anyString(action["component_name"]), anyString(action["name"]), "unknown")
	actionType := firstNonEmpty(anyString(action["type"]), "action")
	approvalName := normalizeHeimdallApprovalName(componentKind, componentName, actionType)
	summary := firstNonEmpty(
		anyString(action["description"]),
		fmt.Sprintf("Approval required for %s on %s/%s", actionType, componentNamespace, componentName),
	)
	if decision.BlastRadius != "" {
		summary = fmt.Sprintf("%s [blast %s]", summary, decision.BlastRadius)
	}
	if decision.Confidence > 0 {
		summary = fmt.Sprintf("%s (confidence %.0f%%, %s)", summary, decision.Confidence*100, firstNonEmpty(decision.ConfidenceBand, "review"))
	}
	if decision.ManualReview {
		summary = fmt.Sprintf("%s Manual review recommended.", summary)
	}
	if decision.Escalate {
		summary = fmt.Sprintf("%s Escalation requested.", summary)
	}

	spec := manifestengine.NormalizeGuardianApprovalSpec(model.GuardianApprovalManifestSpec{
		GuardianRef: policy.GuardianRef,
		Status:      model.GuardianApprovalStatusPending,
		Source:      source,
		Summary:     summary,
		Action:      cloneAuthorizationInput(action),
		Incident:    heimdallIncidentFromAction(action),
		Metadata: map[string]any{
			"autonomy_mode":      policy.Autonomy.Mode,
			"requested_at":       time.Now().UTC().Format(time.RFC3339),
			"confidence":         round2(decision.Confidence),
			"confidence_band":    decision.ConfidenceBand,
			"confidence_reason":  decision.Reason,
			"escalate":           decision.Escalate,
			"escalation_reason":  decision.EscalationReason,
			"manual_review":      decision.ManualReview,
			"blast_radius":       decision.BlastRadius,
			"blast_reason":       decision.BlastRadiusReason,
			"auto_blast_limit":   strings.TrimSpace(policy.Autonomy.MaxAutoExecuteBlastRadius),
			"bypass_blast_limit": strings.TrimSpace(policy.Autonomy.MaxBypassHotfixBlastRadius),
			"provider_group":     decision.ProviderGroup,
			"incident_category":  decision.IncidentCategory,
			"attempts":           round2(decision.Attempts),
			"recovery_rate":      round2(decision.RecoveryRate),
		},
	})

	memory, err := createHeimdallPendingApprovalMemory(ctx, db, action, policy, source, decision)
	if err != nil {
		return err
	}
	spec.Metadata["memory_name"] = memory.Manifest.Metadata.Name
	spec.Metadata["memory_namespace"] = memory.Manifest.Metadata.Namespace
	if bundleRef := asObject(action["target"])["remediation_bundle"]; bundleRef != nil {
		spec.Metadata["bundle_name"] = anyString(asObject(bundleRef)["name"])
		spec.Metadata["bundle_namespace"] = firstNonEmpty(anyString(asObject(bundleRef)["namespace"]), "global")
	}

	specRaw, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("marshal guardian_approval spec: %w", err)
	}

	approvalManifest, err := heimdallCreateManifestVersion(ctx, db, model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "guardian_approval",
		Metadata: model.ManifestMetadataInput{
			Name:        approvalName,
			Namespace:   "global",
			Description: summary,
			Labels: map[string]string{
				"guardian":        "heimdall",
				"component_kind":  componentKind,
				"component_name":  componentName,
				"component_ns":    componentNamespace,
				"approval_status": model.GuardianApprovalStatusPending,
				"approval_source": source,
				"approval_action": actionType,
			},
		},
		Spec: specRaw,
	})
	if err != nil {
		return err
	}
	if bundleName := strings.TrimSpace(anyString(spec.Metadata["bundle_name"])); bundleName != "" {
		if err := updateHeimdallApprovalLinkedBundle(ctx, db, firstNonEmpty(anyString(spec.Metadata["bundle_namespace"]), "global"), bundleName, approvalManifest); err != nil {
			return err
		}
	}

	markHeimdallActionCooldown(action, binding)
	return nil
}

func executeHeimdallWorkflowDispatch(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	action map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
) error {
	binding, err := resolveHeimdallActionBinding(action, repositoryBindings)
	if err != nil {
		return err
	}
	if !binding.Spec.Automation.AllowDispatchWorkflow {
		return fmt.Errorf("repository binding %s disables workflow dispatch", binding.Spec.Repository)
	}

	workflow := firstNonEmpty(heimdallWorkflowNameFromAction(action), binding.Spec.DeployWorkflow, defaultHeimdallDispatchWorkflow)
	ref := firstNonEmpty(heimdallWorkflowRefFromAction(action), binding.Spec.DefaultBranch, defaultHeimdallDispatchBranch)
	repositoryName := firstNonEmpty(anyString(action["repository"]), binding.Spec.Repository)
	inputs := heimdallBuildWorkflowInputs(action, binding.Spec, source, nil)
	if bundleInputs := heimdallEscalationBundleInputs(ctx, db, action); len(bundleInputs) > 0 {
		inputs = mergeStringAnyMaps(inputs, bundleInputs)
	}

	if !options.SkipCooldown && !heimdallActionCooldownAllowed(action, binding.Spec, policy) {
		return fmt.Errorf("heimdall action for %s is still in cooldown", binding.Spec.Repository)
	}

	_, err = executeIntegrationRequest(ctx, conn, db, model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{
			Namespace: "global",
			Name:      "github-caller",
		},
		Operation:  "dispatch_workflow",
		Capability: "dispatch_workflow",
		Input: map[string]any{
			"repository": repositoryName,
			"workflow":   workflow,
			"ref":        ref,
			"inputs":     inputs,
			"metadata": map[string]any{
				"source":              "core.heimdall.guardian_loop",
				"action":              action,
				"binding":             binding.Spec.Repository,
				"policy":              policy.Scope,
				"component_namespace": binding.Spec.ComponentNamespace,
				"dispatched":          time.Now().UTC().Format(time.RFC3339),
			},
		},
	}, 0)
	if err != nil {
		return err
	}

	if !options.SkipCooldown {
		markHeimdallActionCooldown(action, binding.Spec)
	}
	return nil
}

func executeHeimdallEscalation(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	action map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
) error {
	decision := options.Decision
	if decision == nil {
		resolved, err := heimdallResolveAutonomyDecision(ctx, db, action, policy, source)
		if err != nil {
			return err
		}
		decision = &resolved
	}

	var firstErr error
	if policy.Escalation.CreateApproval {
		escalationDecision := *decision
		escalationDecision.RequireApproval = true
		escalationDecision.ManualReview = true
		escalationDecision.ConfidenceBand = "manual_review"
		if strings.TrimSpace(escalationDecision.Reason) == "" {
			escalationDecision.Reason = "Heimdall escalated this incident for human review."
		}
		if err := createHeimdallApprovalRequest(ctx, db, action, policy, firstNonEmpty(source, "incident_escalation"), escalationDecision); err != nil {
			firstErr = err
		}
	}

	if policy.Escalation.DispatchWorkflow {
		escalationAction, ok := heimdallEscalationWorkflowAction(ctx, db, action, policy)
		if ok {
			dispatchOptions := options
			dispatchOptions.SkipApproval = true
			dispatchOptions.SkipCooldown = true
			dispatchOptions.MemoryName = ""
			dispatchOptions.MemoryNS = ""
			if err := executeHeimdallWorkflowDispatch(
				ctx,
				conn,
				db,
				escalationAction,
				repositoryBindings,
				policy,
				"incident_escalation",
				dispatchOptions,
			); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}

	return firstErr
}

func executeHeimdallHumanEscalation(
	ctx context.Context,
	db *sql.DB,
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
) error {
	decision := options.Decision
	if decision == nil {
		fallback := heimdallAutonomyDecision{
			Mode:            policy.Autonomy.Mode,
			RequireApproval: true,
			ManualReview:    true,
			ConfidenceBand:  "manual_review",
			Reason:          "Heimdall requested human escalation for this incident.",
		}
		decision = &fallback
	}
	forced := *decision
	forced.RequireApproval = true
	forced.ManualReview = true
	forced.ConfidenceBand = "manual_review"
	if strings.TrimSpace(forced.Reason) == "" {
		forced.Reason = "Heimdall requested human escalation for this incident."
	}
	return createHeimdallApprovalRequest(ctx, db, action, policy, firstNonEmpty(source, "incident_escalation"), forced)
}

func ensureHeimdallRemediationBundleAction(
	ctx context.Context,
	db *sql.DB,
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
) (map[string]any, heimdallRemediationBundle, error) {
	if normalizeState(anyString(action["type"])) != "remediation_bundle" {
		return action, heimdallRemediationBundle{}, nil
	}
	if !policy.GeneratedBundles.Enabled {
		return nil, heimdallRemediationBundle{}, fmt.Errorf("heimdall guardian policy blocks generated remediation bundles")
	}

	action = cloneAuthorizationInput(action)
	target := asObject(action["target"])
	if target == nil {
		target = map[string]any{}
	}
	ref := asObject(target["remediation_bundle"])
	if name := strings.TrimSpace(anyString(ref["name"])); name != "" {
		namespace := firstNonEmpty(anyString(ref["namespace"]), "global")
		manifestRecord, err := repository.ResolveManifest(ctx, db, "remediation_bundle", namespace, name, nil, true)
		if err != nil {
			return nil, heimdallRemediationBundle{}, err
		}
		spec, err := manifestengine.ParseRemediationBundleSpec(manifestRecord.Spec)
		if err != nil {
			return nil, heimdallRemediationBundle{}, err
		}
		spec = manifestengine.NormalizeRemediationBundleSpec(spec)
		target["remediation_bundle"] = heimdallRemediationBundleRef(manifestRecord, spec)
		action["target"] = target
		return action, heimdallRemediationBundle{Manifest: manifestRecord, Spec: spec}, nil
	}

	now := time.Now().UTC()
	spec, err := heimdallRemediationBundleSpecFromAction(action, policy, source, options, now)
	if err != nil {
		return nil, heimdallRemediationBundle{}, err
	}
	name := normalizeHeimdallRemediationBundleName(spec.ComponentKind, spec.ComponentName, spec.BundleKind, now)
	specRaw, err := json.Marshal(spec)
	if err != nil {
		return nil, heimdallRemediationBundle{}, fmt.Errorf("marshal remediation_bundle spec: %w", err)
	}
	manifestRecord, err := heimdallCreateManifestVersion(ctx, db, model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "remediation_bundle",
		Metadata: model.ManifestMetadataInput{
			Name:        name,
			Namespace:   "global",
			Description: firstNonEmpty(spec.Summary, fmt.Sprintf("Generated Heimdall remediation bundle for %s/%s", spec.ComponentNamespace, spec.ComponentName)),
			Labels: map[string]string{
				"guardian":         "heimdall",
				"bundle_kind":      spec.BundleKind,
				"bundle_status":    spec.Status,
				"component_kind":   spec.ComponentKind,
				"component_name":   spec.ComponentName,
				"component_ns":     spec.ComponentNamespace,
				"bundle_source":    spec.Source,
				"promotion_target": strings.TrimSpace(anyString(spec.Metadata["promotion_target"])),
			},
		},
		Spec: specRaw,
	})
	if err != nil {
		return nil, heimdallRemediationBundle{}, err
	}

	target["remediation_bundle"] = heimdallRemediationBundleRef(manifestRecord, spec)
	action["target"] = target
	return action, heimdallRemediationBundle{Manifest: manifestRecord, Spec: spec}, nil
}

func heimdallRemediationBundleSpecFromAction(
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
	now time.Time,
) (model.RemediationBundleManifestSpec, error) {
	bundle := asObject(action["bundle"])
	if len(bundle) == 0 {
		return model.RemediationBundleManifestSpec{}, fmt.Errorf("remediation_bundle action requires a bundle payload")
	}

	bundleKind := normalizeState(firstNonEmpty(anyString(bundle["kind"]), anyString(bundle["bundle_kind"]), model.RemediationBundleKindIntegrationComposition))
	if !heimdallGeneratedBundleKindAllowed(bundleKind, policy.GeneratedBundles) {
		return model.RemediationBundleManifestSpec{}, fmt.Errorf("heimdall guardian policy blocks remediation bundle kind %q", bundleKind)
	}

	ttlSeconds := positiveInt(anyInt(bundle["ttl_seconds"]), policy.GeneratedBundles.MaxTTLSeconds)
	if ttlSeconds <= 0 {
		ttlSeconds = policy.GeneratedBundles.MaxTTLSeconds
	}
	if policy.GeneratedBundles.MaxTTLSeconds > 0 && ttlSeconds > policy.GeneratedBundles.MaxTTLSeconds {
		ttlSeconds = policy.GeneratedBundles.MaxTTLSeconds
	}
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)
	if explicitExpiresAt := strings.TrimSpace(anyString(bundle["expires_at"])); explicitExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, explicitExpiresAt)
		if err != nil {
			return model.RemediationBundleManifestSpec{}, fmt.Errorf("parse remediation bundle expires_at: %w", err)
		}
		if parsed.Before(expiresAt) {
			expiresAt = parsed
		}
	}

	steps, err := heimdallRemediationBundleStepsFromAction(bundle, action)
	if err != nil {
		return model.RemediationBundleManifestSpec{}, err
	}
	status := model.RemediationBundleStatusProposed
	if policy.GeneratedBundles.RequireApproval && !options.SkipApproval {
		status = model.RemediationBundleStatusPendingApproval
	}
	spec := manifestengine.NormalizeRemediationBundleSpec(model.RemediationBundleManifestSpec{
		GuardianRef:        policy.GuardianRef,
		Status:             status,
		Source:             firstNonEmpty(normalizeState(anyString(action["proposed_by"])), source, "llm_generated"),
		BundleKind:         bundleKind,
		Summary:            firstNonEmpty(anyString(bundle["summary"]), anyString(action["description"]), "Generated remediation bundle"),
		ComponentKind:      firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"]), "component"),
		ComponentNamespace: firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), "global"),
		ComponentName:      firstNonEmpty(anyString(action["component_name"]), anyString(action["name"]), "unknown"),
		ExpiresAt:          expiresAt.Format(time.RFC3339),
		TriggerAction:      cloneAuthorizationInput(action),
		Incident:           heimdallIncidentFromAction(action),
		CreationReason:     heimdallRemediationBundleCreationReason(action, bundle, policy, source, steps, now),
		Steps:              steps,
		Metadata: map[string]any{
			"ttl_seconds":       ttlSeconds,
			"created_at":        now.Format(time.RFC3339),
			"created_from":      "heimdall_action",
			"source":            source,
			"approval_required": policy.GeneratedBundles.RequireApproval && !options.SkipApproval,
			"promotion_target":  heimdallBundlePromotionTarget(bundleKind, steps),
		},
	})
	return spec, nil
}

func heimdallRemediationBundleStepsFromAction(bundle map[string]any, action map[string]any) ([]model.RemediationBundleStepSpec, error) {
	rawSteps := asObjectSlice(bundle["steps"])
	if len(rawSteps) == 0 {
		return nil, fmt.Errorf("remediation bundle requires at least one step")
	}
	steps := make([]model.RemediationBundleStepSpec, 0, len(rawSteps))
	for index, raw := range rawSteps {
		name := firstNonEmpty(anyString(raw["name"]), fmt.Sprintf("step-%d", index+1))
		mode := normalizeState(firstNonEmpty(anyString(raw["mode"]), anyString(raw["type"])))
		if mode == "" {
			if len(asObject(raw["workflow_dispatch"])) > 0 || len(asObject(raw["workflow"])) > 0 {
				mode = model.RemediationContractActionModeWorkflowDispatch
			} else {
				mode = model.RemediationContractActionModeIntegrationExecute
			}
		}
		step := model.RemediationBundleStepSpec{
			Name:        name,
			Mode:        mode,
			Description: strings.TrimSpace(anyString(raw["description"])),
			BlastRadius: normalizeSeverity(anyString(raw["blast_radius"])),
			Metadata:    cloneAuthorizationInput(asObject(raw["metadata"])),
		}
		switch mode {
		case model.RemediationContractActionModeWorkflowDispatch:
			workflow := mergeStringAnyMaps(asObject(raw["workflow_dispatch"]), asObject(raw["workflow"]))
			step.WorkflowDispatch = &model.RemediationWorkflowDispatchSpec{
				Repository: firstNonEmpty(anyString(workflow["repository"]), anyString(action["repository"])),
				Workflow:   firstNonEmpty(anyString(workflow["workflow"]), defaultHeimdallDispatchWorkflow),
				Ref:        firstNonEmpty(anyString(workflow["ref"]), defaultHeimdallDispatchBranch),
				Inputs:     cloneAuthorizationInput(asObject(workflow["inputs"])),
			}
		case model.RemediationContractActionModeIntegrationExecute:
			execute := mergeStringAnyMaps(asObject(raw["integration_execute"]), raw)
			selector := model.ManifestSelector{
				ManifestID: anyString(execute["manifest_id"]),
				Namespace:  firstNonEmpty(anyString(execute["namespace"]), firstNonEmpty(anyString(asObject(execute["integration"])["namespace"]), "global")),
				Name:       firstNonEmpty(anyString(execute["name"]), anyString(asObject(execute["integration"])["name"])),
			}
			step.IntegrationExecute = &model.RemediationIntegrationExecuteSpec{
				Integration: selector,
				Operation:   firstNonEmpty(anyString(execute["operation"]), anyString(raw["operation"])),
				Capability:  firstNonEmpty(anyString(execute["capability"]), anyString(raw["capability"])),
				Input:       cloneAuthorizationInput(asObject(firstNonEmptyMap(execute["input"], raw["input"]))),
			}
		default:
			return nil, fmt.Errorf("remediation bundle step %q mode %q is unsupported", name, mode)
		}
		steps = append(steps, step)
	}
	return steps, nil
}

func executeHeimdallRemediationBundle(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	action map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
) error {
	action, bundle, err := ensureHeimdallRemediationBundleAction(ctx, db, action, policy, source, options)
	if err != nil {
		return err
	}
	if bundle.Manifest.ID == uuid.Nil {
		return fmt.Errorf("remediation bundle is missing")
	}

	expiresAt, err := time.Parse(time.RFC3339, bundle.Spec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse remediation bundle expires_at: %w", err)
	}
	if time.Now().UTC().After(expiresAt) {
		_, updateErr := updateHeimdallRemediationBundleStatus(ctx, db, bundle, model.RemediationBundleStatusExpired, nil, fmt.Errorf("bundle expired before execution"))
		if updateErr != nil {
			return updateErr
		}
		return fmt.Errorf("remediation bundle %s/%s expired before execution", bundle.Manifest.Metadata.Namespace, bundle.Manifest.Metadata.Name)
	}

	bundle, err = updateHeimdallRemediationBundleStatus(ctx, db, bundle, model.RemediationBundleStatusExecuting, nil, nil)
	if err != nil {
		return err
	}

	executedSteps := make([]string, 0, len(bundle.Spec.Steps))
	for _, step := range bundle.Spec.Steps {
		switch step.Mode {
		case model.RemediationContractActionModeWorkflowDispatch:
			if err := executeHeimdallBundleWorkflowDispatch(ctx, conn, db, action, step, source); err != nil {
				_, updateErr := updateHeimdallRemediationBundleStatus(ctx, db, bundle, model.RemediationBundleStatusExecutionFailed, executedSteps, err)
				if updateErr != nil {
					return updateErr
				}
				return err
			}
		case model.RemediationContractActionModeIntegrationExecute:
			if err := executeHeimdallBundleIntegrationExecute(ctx, conn, db, action, step, source); err != nil {
				_, updateErr := updateHeimdallRemediationBundleStatus(ctx, db, bundle, model.RemediationBundleStatusExecutionFailed, executedSteps, err)
				if updateErr != nil {
					return updateErr
				}
				return err
			}
		default:
			err := fmt.Errorf("remediation bundle step mode %q is unsupported", step.Mode)
			_, updateErr := updateHeimdallRemediationBundleStatus(ctx, db, bundle, model.RemediationBundleStatusExecutionFailed, executedSteps, err)
			if updateErr != nil {
				return updateErr
			}
			return err
		}
		executedSteps = append(executedSteps, step.Name)
	}

	_, err = updateHeimdallRemediationBundleStatus(ctx, db, bundle, model.RemediationBundleStatusExecuted, executedSteps, nil)
	return err
}

func executeHeimdallBundleWorkflowDispatch(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	action map[string]any,
	step model.RemediationBundleStepSpec,
	source string,
) error {
	if step.WorkflowDispatch == nil {
		return fmt.Errorf("workflow_dispatch remediation bundle step is missing workflow_dispatch settings")
	}
	inputs := mergeStringAnyMaps(
		cloneAuthorizationInput(step.WorkflowDispatch.Inputs),
		map[string]any{
			"incident_title":      firstNonEmpty(anyString(action["incident_title"]), anyString(action["title"])),
			"component_kind":      firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"])),
			"component_name":      firstNonEmpty(anyString(action["component_name"]), anyString(action["name"])),
			"component_namespace": firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), "global"),
			"reason":              firstNonEmpty(anyString(action["reason"]), anyString(action["description"]), source),
			"remediation_payload": heimdallActionPayload(action),
		},
	)
	if bundleInputs := heimdallEscalationBundleInputs(ctx, db, action); len(bundleInputs) > 0 {
		inputs = mergeStringAnyMaps(inputs, bundleInputs)
	}
	_, err := executeIntegrationRequest(ctx, conn, db, model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{
			Namespace: "global",
			Name:      "github-caller",
		},
		Operation:  "dispatch_workflow",
		Capability: "dispatch_workflow",
		Input: map[string]any{
			"repository": step.WorkflowDispatch.Repository,
			"workflow":   step.WorkflowDispatch.Workflow,
			"ref":        step.WorkflowDispatch.Ref,
			"inputs":     inputs,
		},
		Metadata: map[string]any{
			"source": "core.heimdall.remediation_bundle",
			"action": action,
			"step":   step.Name,
		},
	}, 0)
	return err
}

func executeHeimdallBundleIntegrationExecute(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	action map[string]any,
	step model.RemediationBundleStepSpec,
	source string,
) error {
	if step.IntegrationExecute == nil {
		return fmt.Errorf("integration_execute remediation bundle step is missing integration_execute settings")
	}
	input := mergeStringAnyMaps(
		cloneAuthorizationInput(step.IntegrationExecute.Input),
		map[string]any{
			"source":              source,
			"component_kind":      firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"])),
			"component_namespace": firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), "global"),
			"component_name":      firstNonEmpty(anyString(action["component_name"]), anyString(action["name"])),
			"reason":              firstNonEmpty(anyString(action["reason"]), anyString(action["description"]), source),
		},
	)
	_, err := executeIntegrationRequest(ctx, conn, db, model.ExecuteIntegrationRequest{
		Integration: step.IntegrationExecute.Integration,
		Operation:   step.IntegrationExecute.Operation,
		Capability:  step.IntegrationExecute.Capability,
		Input:       input,
		Metadata: map[string]any{
			"source": "core.heimdall.remediation_bundle",
			"action": action,
			"step":   step.Name,
		},
	}, 0)
	return err
}

func updateHeimdallRemediationBundleStatus(
	ctx context.Context,
	db *sql.DB,
	current heimdallRemediationBundle,
	status string,
	executedSteps []string,
	executionErr error,
) (heimdallRemediationBundle, error) {
	current.Spec = manifestengine.NormalizeRemediationBundleSpec(current.Spec)
	current.Spec.Status = status
	if current.Spec.Metadata == nil {
		current.Spec.Metadata = map[string]any{}
	}
	current.Spec.Metadata["last_status_at"] = time.Now().UTC().Format(time.RFC3339)
	current.Spec.Execution.AttemptedAt = firstNonEmpty(current.Spec.Execution.AttemptedAt, time.Now().UTC().Format(time.RFC3339))
	switch status {
	case model.RemediationBundleStatusExecuting:
		current.Spec.Execution.AttemptedAt = time.Now().UTC().Format(time.RFC3339)
		current.Spec.Execution.CompletedAt = ""
		current.Spec.Execution.Error = ""
	case model.RemediationBundleStatusExecuted, model.RemediationBundleStatusExecutionFailed, model.RemediationBundleStatusRejected, model.RemediationBundleStatusExpired, model.RemediationBundleStatusApproved:
		current.Spec.Execution.CompletedAt = time.Now().UTC().Format(time.RFC3339)
		if executionErr != nil {
			current.Spec.Execution.Error = strings.TrimSpace(executionErr.Error())
		} else {
			current.Spec.Execution.Error = ""
		}
	}
	if executedSteps != nil {
		current.Spec.Execution.ExecutedSteps = cloneStringSlice(executedSteps)
	}

	specRaw, err := json.Marshal(current.Spec)
	if err != nil {
		return heimdallRemediationBundle{}, fmt.Errorf("marshal remediation_bundle spec: %w", err)
	}
	manifestRecord, err := heimdallCreateManifestVersion(ctx, db, model.ManifestDocument{
		APIVersion: current.Manifest.APIVersion,
		Kind:       current.Manifest.Kind,
		Metadata: model.ManifestMetadataInput{
			Name:        current.Manifest.Metadata.Name,
			Namespace:   current.Manifest.Metadata.Namespace,
			Description: current.Manifest.Metadata.Description,
			Labels: map[string]string{
				"guardian":         "heimdall",
				"bundle_kind":      current.Spec.BundleKind,
				"bundle_status":    current.Spec.Status,
				"component_kind":   current.Spec.ComponentKind,
				"component_name":   current.Spec.ComponentName,
				"component_ns":     current.Spec.ComponentNamespace,
				"bundle_source":    current.Spec.Source,
				"promotion_target": strings.TrimSpace(anyString(current.Spec.Metadata["promotion_target"])),
			},
		},
		Spec: specRaw,
	})
	if err != nil {
		return heimdallRemediationBundle{}, err
	}
	current.Manifest = manifestRecord
	return current, nil
}

func updateHeimdallApprovalLinkedBundle(
	ctx context.Context,
	db *sql.DB,
	namespace string,
	name string,
	approvalManifest model.Manifest,
) error {
	manifestRecord, err := repository.ResolveManifest(ctx, db, "remediation_bundle", namespace, name, nil, true)
	if err != nil {
		return err
	}
	spec, err := manifestengine.ParseRemediationBundleSpec(manifestRecord.Spec)
	if err != nil {
		return err
	}
	spec = manifestengine.NormalizeRemediationBundleSpec(spec)
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}
	spec.Metadata["approval_name"] = approvalManifest.Metadata.Name
	spec.Metadata["approval_namespace"] = approvalManifest.Metadata.Namespace
	spec.Metadata["approval_status"] = model.GuardianApprovalStatusPending
	spec.ApprovalDecision = &model.RemediationBundleReasonSpec{
		Kind:       "approval_pending",
		Status:     model.GuardianApprovalStatusPending,
		Summary:    "Waiting for a human to approve the generated remediation bundle.",
		Source:     "guardian_approval",
		RecordedAt: time.Now().UTC().Format(time.RFC3339),
		Metadata: map[string]any{
			"approval_name":      approvalManifest.Metadata.Name,
			"approval_namespace": approvalManifest.Metadata.Namespace,
		},
	}
	_, err = updateHeimdallRemediationBundleStatus(ctx, db, heimdallRemediationBundle{
		Manifest: manifestRecord,
		Spec:     spec,
	}, model.RemediationBundleStatusPendingApproval, spec.Execution.ExecutedSteps, nil)
	return err
}

func UpdateHeimdallApprovalBundleStatus(
	ctx context.Context,
	db *sql.DB,
	approval model.GuardianApprovalManifestSpec,
	status string,
) error {
	bundleName := strings.TrimSpace(anyString(approval.Metadata["bundle_name"]))
	if bundleName == "" {
		return nil
	}
	bundleNS := firstNonEmpty(anyString(approval.Metadata["bundle_namespace"]), "global")
	manifestRecord, err := repository.ResolveManifest(ctx, db, "remediation_bundle", bundleNS, bundleName, nil, true)
	if err != nil {
		return err
	}
	spec, err := manifestengine.ParseRemediationBundleSpec(manifestRecord.Spec)
	if err != nil {
		return err
	}
	spec = manifestengine.NormalizeRemediationBundleSpec(spec)
	nextStatus := model.RemediationBundleStatusApproved
	switch strings.TrimSpace(status) {
	case model.GuardianApprovalStatusRejected:
		nextStatus = model.RemediationBundleStatusRejected
	case model.GuardianApprovalStatusApproved:
		nextStatus = model.RemediationBundleStatusApproved
	}
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}
	spec.Metadata["approval_status"] = strings.TrimSpace(status)
	spec.ApprovalDecision = heimdallRemediationBundleApprovalReason(approval, status)
	_, err = updateHeimdallRemediationBundleStatus(ctx, db, heimdallRemediationBundle{
		Manifest: manifestRecord,
		Spec:     spec,
	}, nextStatus, spec.Execution.ExecutedSteps, nil)
	return err
}

func heimdallRemediationBundleRef(manifestRecord model.Manifest, spec model.RemediationBundleManifestSpec) map[string]any {
	return map[string]any{
		"id":               manifestRecord.ID.String(),
		"namespace":        manifestRecord.Metadata.Namespace,
		"name":             manifestRecord.Metadata.Name,
		"status":           spec.Status,
		"bundle_kind":      spec.BundleKind,
		"expires_at":       spec.ExpiresAt,
		"promotion_target": anyString(spec.Metadata["promotion_target"]),
	}
}

func heimdallRemediationBundleCreationReason(
	action map[string]any,
	bundle map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
	steps []model.RemediationBundleStepSpec,
	now time.Time,
) *model.RemediationBundleReasonSpec {
	reason := firstNonEmptyMap(bundle["reason"], action["bundle_reason"])
	metadata := map[string]any{
		"bundle_kind":         normalizeState(firstNonEmpty(anyString(bundle["kind"]), anyString(bundle["bundle_kind"]))),
		"step_count":          len(steps),
		"approval_required":   policy.GeneratedBundles.RequireApproval,
		"incident_category":   firstNonEmpty(anyString(asObject(action["target"])["guardian_memory_incident_category"]), anyString(asObject(action["incident"])["category"])),
		"provider_group":      firstNonEmpty(anyString(asObject(action["target"])["guardian_memory_provider_group"]), anyString(asObject(action["target"])["provider_group"])),
		"component_kind":      firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"]), "component"),
		"component_namespace": firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), "global"),
		"component_name":      firstNonEmpty(anyString(action["component_name"]), anyString(action["name"]), "unknown"),
	}
	for key, value := range asObject(reason["metadata"]) {
		metadata[key] = value
	}
	summary := firstNonEmpty(
		anyString(reason["summary"]),
		anyString(reason["message"]),
		anyString(bundle["summary"]),
		"Generated a temporary remediation bundle because the existing bounded execute path was insufficient.",
	)
	return &model.RemediationBundleReasonSpec{
		Kind:       firstNonEmpty(normalizeState(anyString(reason["kind"])), "generated_hotfix_bundle"),
		Summary:    summary,
		Comment:    firstNonEmpty(anyString(reason["comment"]), anyString(action["reason"])),
		Source:     firstNonEmpty(normalizeState(anyString(reason["source"])), normalizeState(anyString(action["proposed_by"])), source, "heimdall"),
		Actor:      firstNonEmpty(anyString(reason["actor"]), "heimdall"),
		RecordedAt: now.UTC().Format(time.RFC3339),
		Metadata:   metadata,
	}
}

func heimdallRemediationBundleApprovalReason(
	approval model.GuardianApprovalManifestSpec,
	status string,
) *model.RemediationBundleReasonSpec {
	summary := "Generated remediation bundle approved for execution."
	if strings.TrimSpace(status) == model.GuardianApprovalStatusRejected {
		summary = "Generated remediation bundle rejected and left unexecuted."
	}
	metadata := map[string]any{
		"approval_name":      firstNonEmpty(anyString(approval.Metadata["bundle_name"]), ""),
		"approval_namespace": firstNonEmpty(anyString(approval.Metadata["bundle_namespace"]), "global"),
	}
	return &model.RemediationBundleReasonSpec{
		Kind:       "approval_decision",
		Status:     strings.TrimSpace(status),
		Summary:    summary,
		Comment:    strings.TrimSpace(anyString(approval.Metadata["decision_comment"])),
		Source:     "guardian_approval",
		Actor:      firstNonEmpty(anyString(approval.Metadata["decision_actor"]), "console"),
		RecordedAt: firstNonEmpty(anyString(approval.Metadata["decided_at"]), time.Now().UTC().Format(time.RFC3339)),
		Metadata:   metadata,
	}
}

func heimdallGeneratedBundleKindAllowed(kind string, policy model.GuardianGeneratedBundlePolicySpec) bool {
	switch normalizeState(kind) {
	case model.RemediationBundleKindWorkflowPatch:
		return policy.AllowWorkflowPatch
	case model.RemediationBundleKindIntegrationComposition:
		return policy.AllowIntegrationComposition
	case model.RemediationBundleKindEphemeralExecutor:
		return policy.AllowEphemeralExecutor
	default:
		return false
	}
}

func heimdallBundlePromotionTarget(kind string, steps []model.RemediationBundleStepSpec) string {
	if len(steps) == 1 {
		switch steps[0].Mode {
		case model.RemediationContractActionModeWorkflowDispatch, model.RemediationContractActionModeIntegrationExecute:
			return "learned_lightweight"
		}
	}
	switch normalizeState(kind) {
	case model.RemediationBundleKindIntegrationComposition:
		return "remediation_contract"
	case model.RemediationBundleKindEphemeralExecutor:
		return "capability_formalization"
	default:
		return "learned_lightweight"
	}
}

func normalizeHeimdallRemediationBundleName(componentKind, componentName, bundleKind string, now time.Time) string {
	componentKind = normalizeState(componentKind)
	componentName = normalizeIntegrationToken(componentName)
	bundleKind = normalizeState(bundleKind)
	return fmt.Sprintf("heimdall-%s-%s-%s-%s", componentKind, componentName, bundleKind, now.UTC().Format("20060102150405"))
}

func firstNonEmptyMap(values ...any) map[string]any {
	for _, value := range values {
		item := asObject(value)
		if len(item) > 0 {
			return item
		}
	}
	return nil
}

func executeHeimdallContractAction(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	action map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
	remediationContracts map[string]heimdallRemediationContract,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
) error {
	contract, contractAction, err := resolveHeimdallContractAction(action, remediationContracts)
	if err != nil {
		return err
	}
	if !contractAction.AutoExecute {
		return fmt.Errorf("remediation contract %s/%s action %q is not marked auto_execute", contract.Manifest.Metadata.Namespace, contract.Manifest.Metadata.Name, contractAction.Name)
	}

	switch contractAction.Mode {
	case model.RemediationContractActionModeWorkflowDispatch:
		return executeHeimdallContractWorkflowDispatch(ctx, conn, db, action, repositoryBindings, contract, contractAction, policy, source, options)
	case model.RemediationContractActionModeIntegrationExecute:
		return executeHeimdallContractIntegrationExecute(ctx, conn, db, action, contract, contractAction, policy, source, options)
	default:
		return fmt.Errorf("remediation contract action mode %q is unsupported", contractAction.Mode)
	}
}

func executeHeimdallContractWorkflowDispatch(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	action map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
	contract heimdallRemediationContract,
	contractAction model.RemediationContractActionSpec,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
) error {
	binding, err := heimdallWorkflowDispatchBinding(action, repositoryBindings, contract, contractAction)
	if err != nil {
		return err
	}
	if !options.SkipCooldown && !heimdallActionCooldownAllowed(action, binding.Spec, policy) {
		return fmt.Errorf("heimdall action for %s is still in cooldown", binding.Spec.Repository)
	}

	repositoryName := firstNonEmpty(binding.Spec.Repository, contractAction.WorkflowDispatch.Repository)
	workflow := firstNonEmpty(contractAction.WorkflowDispatch.Workflow, binding.Spec.DeployWorkflow, defaultHeimdallDispatchWorkflow)
	ref := firstNonEmpty(contractAction.WorkflowDispatch.Ref, binding.Spec.DefaultBranch, defaultHeimdallDispatchBranch)
	inputs := heimdallBuildWorkflowInputs(action, binding.Spec, source, contractAction.WorkflowDispatch.Inputs)
	if bundleInputs := heimdallEscalationBundleInputs(ctx, db, action); len(bundleInputs) > 0 {
		inputs = mergeStringAnyMaps(inputs, bundleInputs)
	}
	inputs["remediation_type"] = strings.ToLower(strings.TrimSpace(contractAction.Name))
	inputs["remediation_reason"] = firstNonEmpty(anyString(action["reason"]), anyString(action["description"]), source)
	inputs["remediation_payload"] = heimdallActionPayload(action)

	_, err = executeIntegrationRequest(ctx, conn, db, model.ExecuteIntegrationRequest{
		Integration: model.ManifestSelector{
			Namespace: "global",
			Name:      "github-caller",
		},
		Operation:  "dispatch_workflow",
		Capability: "dispatch_workflow",
		Input: map[string]any{
			"repository": repositoryName,
			"workflow":   workflow,
			"ref":        ref,
			"inputs":     inputs,
			"metadata": map[string]any{
				"source":              "core.heimdall.guardian_loop",
				"action":              action,
				"binding":             binding.Spec.Repository,
				"policy":              policy.Scope,
				"component_namespace": binding.Spec.ComponentNamespace,
				"dispatched":          time.Now().UTC().Format(time.RFC3339),
				"remediation_contract": map[string]any{
					"namespace": contract.Manifest.Metadata.Namespace,
					"name":      contract.Manifest.Metadata.Name,
					"action":    contractAction.Name,
					"mode":      contractAction.Mode,
				},
			},
		},
	}, 0)
	if err != nil {
		return err
	}

	if !options.SkipCooldown {
		markHeimdallActionCooldown(action, binding.Spec)
	}
	return nil
}

func executeHeimdallContractIntegrationExecute(
	ctx context.Context,
	conn *amqp.Connection,
	db *sql.DB,
	action map[string]any,
	contract heimdallRemediationContract,
	contractAction model.RemediationContractActionSpec,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
) error {
	if contractAction.IntegrationExecute == nil {
		return fmt.Errorf("remediation contract action does not define integration_execute settings")
	}

	binding := heimdallActionCooldownBinding(action)
	if binding.ComponentKind == "" {
		binding.ComponentKind = contract.Spec.ComponentKind
		binding.ComponentNamespace = contract.Spec.ComponentNamespace
		binding.ComponentName = contract.Spec.ComponentName
	}
	if !options.SkipCooldown && !heimdallActionCooldownAllowed(action, binding, policy) {
		return fmt.Errorf("heimdall action for %s/%s is still in cooldown", binding.ComponentNamespace, binding.ComponentName)
	}

	renderedInput, err := manifestengine.RenderWorkflowInput(
		contractAction.IntegrationExecute.Input,
		manifestengine.WorkflowExecutionContext{
			Inputs: mergeStringAnyMaps(
				cloneAuthorizationInput(action),
				map[string]any{
					"source":              source,
					"component_kind":      contract.Spec.ComponentKind,
					"component_namespace": contract.Spec.ComponentNamespace,
					"component_name":      contract.Spec.ComponentName,
				},
			),
			Metadata: map[string]any{
				"source": "core.heimdall.guardian_loop",
			},
		},
	)
	if err != nil {
		return fmt.Errorf("render remediation integration_execute input: %w", err)
	}

	input, ok := renderedInput.(map[string]any)
	if !ok {
		return fmt.Errorf("remediation contract integration_execute input must render to an object")
	}

	selector := contractAction.IntegrationExecute.Integration
	_, err = executeIntegrationRequest(ctx, conn, db, model.ExecuteIntegrationRequest{
		Integration: selector,
		Operation:   contractAction.IntegrationExecute.Operation,
		Capability:  contractAction.IntegrationExecute.Capability,
		Input:       input,
		Metadata: map[string]any{
			"source":              "core.heimdall.guardian_loop",
			"action":              action,
			"policy":              policy.Scope,
			"component_kind":      contract.Spec.ComponentKind,
			"component_namespace": contract.Spec.ComponentNamespace,
			"component_name":      contract.Spec.ComponentName,
			"remediation_contract": map[string]any{
				"namespace": contract.Manifest.Metadata.Namespace,
				"name":      contract.Manifest.Metadata.Name,
				"action":    contractAction.Name,
				"mode":      contractAction.Mode,
			},
		},
	}, 0)
	if err != nil {
		return err
	}

	if !options.SkipCooldown {
		markHeimdallActionCooldown(action, binding)
	}
	return nil
}

func executeHeimdallSecretRotation(ctx context.Context, db *sql.DB, action map[string]any) error {
	namespace := firstNonEmpty(anyString(action["namespace"]), "global")
	name := strings.TrimSpace(anyString(action["name"]))
	if name == "" {
		return fmt.Errorf("rotate_secret action requires a secret name")
	}

	data := map[string]string{}
	switch typed := action["data"].(type) {
	case map[string]string:
		data = typed
	case map[string]any:
		for key, value := range typed {
			data[key] = anyString(value)
		}
	}
	if len(data) == 0 {
		return fmt.Errorf("rotate_secret action requires replacement data")
	}

	_, err := repository.RotateManagedSecret(ctx, db, model.RotateManagedSecretRequest{
		Namespace: namespace,
		Name:      name,
		Data:      data,
		Metadata: map[string]any{
			"source": "core.heimdall.guardian_loop",
		},
	})
	return err
}

func heimdallActionCooldownAllowed(action map[string]any, binding model.RepositoryBindingManifestSpec, policy model.GuardianPolicyManifestSpec) bool {
	cooldown := time.Duration(policy.AutoHeal.CooldownSeconds) * time.Second
	if cooldown <= 0 {
		return true
	}

	key := heimdallActionKey(action, binding)

	heimdallActionCooldownMu.Lock()
	defer heimdallActionCooldownMu.Unlock()

	lastRun, exists := heimdallActionCooldown[key]
	if !exists {
		return true
	}
	return time.Since(lastRun) >= cooldown
}

func markHeimdallActionCooldown(action map[string]any, binding model.RepositoryBindingManifestSpec) {
	heimdallActionCooldownMu.Lock()
	defer heimdallActionCooldownMu.Unlock()
	heimdallActionCooldown[heimdallActionKey(action, binding)] = time.Now()
}

func heimdallActionKey(action map[string]any, binding model.RepositoryBindingManifestSpec) string {
	return strings.Join([]string{
		strings.ToLower(strings.TrimSpace(anyString(action["type"]))),
		strings.ToLower(strings.TrimSpace(binding.ComponentKind)),
		strings.ToLower(strings.TrimSpace(binding.ComponentNamespace)),
		strings.ToLower(strings.TrimSpace(binding.ComponentName)),
		strings.ToLower(strings.TrimSpace(binding.Repository)),
	}, "|")
}

func heimdallActionCooldownBinding(action map[string]any) model.RepositoryBindingManifestSpec {
	return model.RepositoryBindingManifestSpec{
		ComponentKind:      firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"]), "component"),
		ComponentNamespace: firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), "global"),
		ComponentName:      firstNonEmpty(anyString(action["component_name"]), anyString(action["name"]), "unknown"),
		Repository:         firstNonEmpty(anyString(action["repository"]), anyString(action["repo"])),
	}
}

func resolveHeimdallActionBinding(
	action map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
) (heimdallRepositoryBinding, error) {
	target := heimdallActionObject(action, "target")
	workflow := heimdallActionObject(action, "workflow")
	componentKind := firstNonEmpty(
		anyString(action["component_kind"]),
		anyString(action["kind"]),
		anyString(target["component_kind"]),
		anyString(target["kind"]),
	)
	componentNamespace := firstNonEmpty(
		anyString(action["component_namespace"]),
		anyString(action["namespace"]),
		anyString(target["component_namespace"]),
		anyString(target["namespace"]),
		"global",
	)
	componentName := firstNonEmpty(
		anyString(action["component_name"]),
		anyString(action["name"]),
		anyString(target["component_name"]),
		anyString(target["name"]),
	)
	if componentKind != "" && componentName != "" {
		if binding, ok := repositoryBindings[heimdallComponentKey(componentKind, componentNamespace, componentName)]; ok {
			return binding, nil
		}
	}

	repositoryName := strings.TrimSpace(anyString(action["repository"]))
	if repositoryName == "" {
		repositoryName = strings.TrimSpace(anyString(action["repo"]))
	}
	if repositoryName == "" {
		repositoryName = strings.TrimSpace(anyString(workflow["repository"]))
	}
	if repositoryName != "" {
		for _, binding := range repositoryBindings {
			if strings.EqualFold(binding.Spec.Repository, repositoryName) {
				return binding, nil
			}
		}
	}

	return heimdallRepositoryBinding{}, fmt.Errorf("no repository binding matched Heimdall action")
}

func resolveHeimdallContractAction(
	action map[string]any,
	contracts map[string]heimdallRemediationContract,
) (heimdallRemediationContract, model.RemediationContractActionSpec, error) {
	target := heimdallActionObject(action, "target")
	componentKind := firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"]), anyString(target["component_kind"]), anyString(target["kind"]))
	componentNamespace := firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), anyString(target["component_namespace"]), anyString(target["namespace"]), "global")
	componentName := firstNonEmpty(anyString(action["component_name"]), anyString(action["name"]), anyString(target["component_name"]), anyString(target["name"]))
	if componentKind == "" || componentName == "" {
		return heimdallRemediationContract{}, model.RemediationContractActionSpec{}, fmt.Errorf("heimdall remediation action is missing component identity")
	}

	contract, ok := contracts[heimdallComponentKey(componentKind, componentNamespace, componentName)]
	if !ok {
		return heimdallRemediationContract{}, model.RemediationContractActionSpec{}, fmt.Errorf("no remediation contract matched Heimdall action for %s/%s", componentNamespace, componentName)
	}

	actionType := strings.ToLower(strings.TrimSpace(anyString(action["type"])))
	for _, candidate := range contract.Spec.Actions {
		if strings.EqualFold(candidate.Name, actionType) {
			return contract, candidate, nil
		}
	}

	return heimdallRemediationContract{}, model.RemediationContractActionSpec{}, fmt.Errorf("remediation contract %s/%s does not expose action %q", contract.Manifest.Metadata.Namespace, contract.Manifest.Metadata.Name, actionType)
}

func heimdallWorkflowDispatchBinding(
	action map[string]any,
	repositoryBindings map[string]heimdallRepositoryBinding,
	contract heimdallRemediationContract,
	contractAction model.RemediationContractActionSpec,
) (heimdallRepositoryBinding, error) {
	if binding, err := resolveHeimdallActionBinding(action, repositoryBindings); err == nil {
		if contractAction.WorkflowDispatch != nil {
			binding.Spec.Repository = firstNonEmpty(contractAction.WorkflowDispatch.Repository, binding.Spec.Repository)
			binding.Spec.DeployWorkflow = firstNonEmpty(contractAction.WorkflowDispatch.Workflow, binding.Spec.DeployWorkflow)
			binding.Spec.DefaultBranch = firstNonEmpty(contractAction.WorkflowDispatch.Ref, binding.Spec.DefaultBranch)
		}
		return binding, nil
	}

	if contractAction.WorkflowDispatch == nil {
		return heimdallRepositoryBinding{}, fmt.Errorf("remediation contract action does not define workflow dispatch settings")
	}

	repositoryName := strings.TrimSpace(contractAction.WorkflowDispatch.Repository)
	if repositoryName == "" {
		return heimdallRepositoryBinding{}, fmt.Errorf("remediation contract %s/%s requires either a repository binding or workflow_dispatch.repository", contract.Manifest.Metadata.Namespace, contract.Manifest.Metadata.Name)
	}

	return heimdallRepositoryBinding{
		Spec: model.RepositoryBindingManifestSpec{
			ComponentKind:      contract.Spec.ComponentKind,
			ComponentNamespace: contract.Spec.ComponentNamespace,
			ComponentName:      contract.Spec.ComponentName,
			Repository:         repositoryName,
			DefaultBranch:      contractAction.WorkflowDispatch.Ref,
			DeployWorkflow:     contractAction.WorkflowDispatch.Workflow,
			Automation: model.RepositoryBindingAutomationSpec{
				AllowDispatchWorkflow: true,
			},
			Metadata: cloneAuthorizationInput(contract.Spec.Metadata),
		},
	}, nil
}

func heimdallComponentKey(kind, namespace, name string) string {
	kind = strings.ToLower(strings.TrimSpace(kind))
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	if namespace == "" {
		namespace = "global"
	}
	name = strings.ToLower(strings.TrimSpace(name))
	return kind + "|" + namespace + "|" + name
}

func heimdallManifestKey(namespace, name string) string {
	namespace = strings.ToLower(strings.TrimSpace(namespace))
	if namespace == "" {
		namespace = "global"
	}
	name = strings.ToLower(strings.TrimSpace(name))
	return namespace + "|" + name
}

func heimdallNumericDetail(details map[string]any, keys ...string) (float64, bool) {
	for _, key := range keys {
		value, ok := details[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case float64:
			return typed, true
		case int:
			return float64(typed), true
		case int64:
			return float64(typed), true
		}
	}
	return 0, false
}

func heimdallRemediationActions(output any) []map[string]any {
	return heimdallMapSliceField(output, "actions")
}

func heimdallOutputIncidentSeverity(output any) string {
	object, ok := output.(map[string]any)
	if !ok {
		return ""
	}
	incident, ok := object["incident"].(map[string]any)
	if !ok {
		return ""
	}
	return anyString(incident["severity"])
}

func heimdallSeverityMeetsThreshold(severity string, threshold string) bool {
	order := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}
	current := order[strings.ToLower(strings.TrimSpace(severity))]
	required := order[strings.ToLower(strings.TrimSpace(threshold))]
	if current == 0 || required == 0 {
		return false
	}
	return current >= required
}

func heimdallCostActions(output any, policy model.GuardianPolicyManifestSpec) []map[string]any {
	opportunities := heimdallMapSliceField(output, "opportunities")
	actions := make([]map[string]any, 0, len(opportunities))
	for _, opportunity := range opportunities {
		savings, _ := heimdallNumericDetail(opportunity, "estimated_monthly_save_usd", "estimated_monthly_savings_usd")
		if savings < policy.CostOptimization.MinEstimatedMonthlySavingsUSD {
			continue
		}
		action, ok := opportunity["action"].(map[string]any)
		if !ok || len(action) == 0 {
			continue
		}
		actions = append(actions, cloneAuthorizationInput(action))
	}
	return actions
}

func heimdallRuntimeIndicatesOOM(state *model.IntegrationRuntimeState) bool {
	if state == nil {
		return false
	}
	if heimdallBoolDetail(state.Details, "oom_killed", "oom", "memory_pressure") {
		return true
	}
	message := strings.ToLower(strings.TrimSpace(state.Message))
	return strings.Contains(message, "oom") || strings.Contains(message, "out of memory")
}

func heimdallBoolDetail(details map[string]any, keys ...string) bool {
	for _, key := range keys {
		value, ok := details[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			if typed {
				return true
			}
		case string:
			normalized := strings.ToLower(strings.TrimSpace(typed))
			if normalized == "true" || normalized == "yes" || normalized == "1" || normalized == "oomkilled" {
				return true
			}
		}
	}
	return false
}

func heimdallBuildWorkflowInputs(
	action map[string]any,
	binding model.RepositoryBindingManifestSpec,
	source string,
	extraInputs map[string]any,
) map[string]any {
	inputs := map[string]any{}
	if workflowInputs := heimdallWorkflowInputsFromAction(action); len(workflowInputs) > 0 {
		inputs = mergeStringAnyMaps(inputs, workflowInputs)
	}
	if len(extraInputs) > 0 {
		inputs = mergeStringAnyMaps(inputs, cloneAuthorizationInput(extraInputs))
	}

	inputs["component_kind"] = firstNonEmpty(anyString(action["component_kind"]), binding.ComponentKind)
	inputs["component_name"] = firstNonEmpty(anyString(action["component_name"]), binding.ComponentName)
	inputs["component_namespace"] = firstNonEmpty(anyString(action["component_namespace"]), binding.ComponentNamespace, "global")
	inputs["commit_sha"] = ""
	inputs["actor"] = defaultHeimdallDispatchActor
	inputs["event_name"] = source
	inputs["environment"] = firstNonEmpty(anyString(binding.Metadata["environment"]), defaultHeimdallDispatchEnvironment)
	inputs["commit_message"] = firstNonEmpty(anyString(action["reason"]), source)
	inputs["source_run_url"] = ""
	inputs["source_run_id"] = "heimdall-guardian-loop"

	return inputs
}

func heimdallEscalationWorkflowAction(
	ctx context.Context,
	db *sql.DB,
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
) (map[string]any, bool) {
	incident := heimdallIncidentFromAction(action)
	severity := firstNonEmpty(anyString(incident["severity"]), anyString(action["incident_severity"]), "critical")
	workflow := strings.TrimSpace(policy.Escalation.IssueWorkflow)
	escalationKind := "issue"
	if heimdallSeverityMeetsThreshold(severity, policy.Escalation.PostmortemSeverityThreshold) &&
		strings.TrimSpace(policy.Escalation.PostmortemWorkflow) != "" {
		workflow = strings.TrimSpace(policy.Escalation.PostmortemWorkflow)
		escalationKind = "postmortem"
	}
	if workflow == "" {
		return nil, false
	}

	next := cloneAuthorizationInput(action)
	next["type"] = "dispatch_workflow"
	next["description"] = firstNonEmpty(anyString(action["description"]), fmt.Sprintf("Heimdall escalation (%s) for %s", escalationKind, firstNonEmpty(anyString(incident["title"]), "incident")))
	next["reason"] = firstNonEmpty(anyString(action["reason"]), "Heimdall escalated this incident after reaching a policy boundary.")
	next["incident"] = mergeStringAnyMaps(incident, map[string]any{
		"escalation_kind": escalationKind,
	})
	next["workflow"] = map[string]any{
		"workflow": workflow,
		"ref":      firstNonEmpty(strings.TrimSpace(policy.Escalation.Ref), defaultHeimdallDispatchBranch),
		"inputs": map[string]any{
			"escalation_kind":     escalationKind,
			"escalation_reason":   firstNonEmpty(anyString(action["reason"]), anyString(action["description"]), "Heimdall escalation"),
			"incident_severity":   severity,
			"incident_title":      firstNonEmpty(anyString(incident["title"]), anyString(action["incident_title"])),
			"incident_category":   firstNonEmpty(anyString(incident["category"]), anyString(action["incident_category"])),
			"postmortem_required": escalationKind == "postmortem",
		},
	}
	if workflowInputs, ok := next["workflow"].(map[string]any); ok {
		if inputs, ok := workflowInputs["inputs"].(map[string]any); ok {
			for key, value := range heimdallEscalationBundleInputs(ctx, db, action) {
				inputs[key] = value
			}
		}
	}
	return next, true
}

func heimdallEscalationBundleInputs(ctx context.Context, db *sql.DB, action map[string]any) map[string]any {
	contextPayload := heimdallEscalationBundleContext(ctx, db, action)
	if len(contextPayload) == 0 {
		return nil
	}

	encoded, err := json.Marshal(contextPayload)
	if err != nil {
		return nil
	}

	creation := asObject(contextPayload["creation_reason"])
	approval := asObject(contextPayload["approval_decision"])
	promotion := asObject(contextPayload["promotion_review"])

	return map[string]any{
		"remediation_bundle_name":                    anyString(contextPayload["name"]),
		"remediation_bundle_namespace":               anyString(contextPayload["namespace"]),
		"remediation_bundle_kind":                    anyString(contextPayload["kind"]),
		"remediation_bundle_status":                  anyString(contextPayload["status"]),
		"remediation_bundle_summary":                 anyString(contextPayload["summary"]),
		"remediation_bundle_context":                 string(encoded),
		"remediation_bundle_creation_reason_summary": anyString(creation["summary"]),
		"remediation_bundle_creation_reason_comment": anyString(creation["comment"]),
		"remediation_bundle_approval_status":         anyString(approval["status"]),
		"remediation_bundle_approval_summary":        anyString(approval["summary"]),
		"remediation_bundle_approval_comment":        anyString(approval["comment"]),
		"remediation_bundle_promotion_status":        anyString(promotion["status"]),
		"remediation_bundle_promotion_summary":       anyString(promotion["summary"]),
		"remediation_bundle_promotion_comment":       anyString(promotion["comment"]),
	}
}

func heimdallEscalationBundleContext(ctx context.Context, db *sql.DB, action map[string]any) map[string]any {
	target := asObject(action["target"])
	ref := asObject(target["remediation_bundle"])
	namespace := firstNonEmpty(anyString(ref["namespace"]), "global")
	name := anyString(ref["name"])

	if db != nil && name != "" {
		if manifestRecord, err := repository.ResolveManifest(ctx, db, "remediation_bundle", namespace, name, nil, true); err == nil {
			if spec, err := manifestengine.ParseRemediationBundleSpec(manifestRecord.Spec); err == nil {
				spec = manifestengine.NormalizeRemediationBundleSpec(spec)
				return map[string]any{
					"id":                manifestRecord.ID.String(),
					"name":              manifestRecord.Metadata.Name,
					"namespace":         manifestRecord.Metadata.Namespace,
					"kind":              spec.BundleKind,
					"status":            spec.Status,
					"summary":           spec.Summary,
					"expires_at":        spec.ExpiresAt,
					"creation_reason":   heimdallReasonMap(spec.CreationReason),
					"approval_decision": heimdallReasonMap(spec.ApprovalDecision),
					"promotion_review":  heimdallReasonMap(spec.PromotionReview),
				}
			}
		}
	}

	bundle := asObject(action["bundle"])
	if len(bundle) == 0 && len(ref) == 0 {
		return nil
	}
	return map[string]any{
		"name":            name,
		"namespace":       namespace,
		"kind":            firstNonEmpty(anyString(bundle["kind"]), anyString(bundle["bundle_kind"]), anyString(ref["bundle_kind"])),
		"status":          anyString(ref["status"]),
		"summary":         firstNonEmpty(anyString(bundle["summary"]), anyString(action["description"])),
		"creation_reason": firstNonEmptyMap(bundle["reason"], action["bundle_reason"]),
	}
}

func heimdallReasonMap(reason *model.RemediationBundleReasonSpec) map[string]any {
	if reason == nil {
		return nil
	}
	output := map[string]any{
		"kind":        reason.Kind,
		"status":      reason.Status,
		"summary":     reason.Summary,
		"comment":     reason.Comment,
		"source":      reason.Source,
		"actor":       reason.Actor,
		"recorded_at": reason.RecordedAt,
	}
	if len(reason.Metadata) > 0 {
		output["metadata"] = cloneAuthorizationInput(reason.Metadata)
	}
	return output
}

func heimdallWorkflowInputsFromAction(action map[string]any) map[string]any {
	workflow, ok := action["workflow"].(map[string]any)
	if !ok {
		return nil
	}
	switch typed := workflow["inputs"].(type) {
	case map[string]any:
		return cloneAuthorizationInput(typed)
	case map[string]string:
		result := make(map[string]any, len(typed))
		for key, value := range typed {
			result[key] = value
		}
		return result
	default:
		return nil
	}
}

func heimdallWorkflowNameFromAction(action map[string]any) string {
	if workflow, ok := action["workflow"].(map[string]any); ok {
		if value := firstNonEmpty(anyString(workflow["workflow"]), anyString(workflow["name"])); value != "" {
			return value
		}
	}
	return firstNonEmpty(anyString(action["workflow_name"]), anyString(action["workflow"]))
}

func heimdallWorkflowRefFromAction(action map[string]any) string {
	if workflow, ok := action["workflow"].(map[string]any); ok {
		if value := anyString(workflow["ref"]); value != "" {
			return value
		}
	}
	return anyString(action["ref"])
}

func heimdallActionPayload(action map[string]any) string {
	payload := cloneAuthorizationInput(action)
	data, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func heimdallMapSliceField(output any, field string) []map[string]any {
	object, ok := output.(map[string]any)
	if !ok {
		return nil
	}
	rawItems, ok := object[field].([]any)
	if !ok {
		return nil
	}
	items := make([]map[string]any, 0, len(rawItems))
	for _, rawItem := range rawItems {
		if item, ok := rawItem.(map[string]any); ok {
			items = append(items, cloneAuthorizationInput(item))
		}
	}
	return items
}

func anyString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	default:
		return ""
	}
}

func anyInt(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int32:
		return int(typed)
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		value, _ := typed.Int64()
		return int(value)
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(typed))
		if err == nil {
			return parsed
		}
	}
	return 0
}

func positiveInt(value int, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func asObject(value any) map[string]any {
	object, ok := value.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return cloneAuthorizationInput(object)
}

func asObjectSlice(value any) []map[string]any {
	switch typed := value.(type) {
	case []map[string]any:
		items := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			items = append(items, cloneAuthorizationInput(item))
		}
		return items
	case []any:
		items := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			object, ok := item.(map[string]any)
			if !ok {
				continue
			}
			items = append(items, cloneAuthorizationInput(object))
		}
		return items
	default:
		return nil
	}
}

func heimdallActionObject(action map[string]any, key string) map[string]any {
	object, ok := action[key].(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return cloneAuthorizationInput(object)
}

func normalizeHeimdallApprovalName(componentKind, componentName, actionType string) string {
	values := []string{
		"heimdall",
		"approval",
		normalizeIntegrationToken(componentKind),
		normalizeIntegrationToken(componentName),
		normalizeIntegrationToken(actionType),
	}
	return strings.Trim(strings.Join(values, "-"), "-")
}

func normalizeHeimdallMemoryName(componentKind, componentName, actionType string, now time.Time) string {
	values := []string{
		"heimdall",
		"memory",
		normalizeIntegrationToken(componentKind),
		normalizeIntegrationToken(componentName),
		normalizeIntegrationToken(actionType),
		fmt.Sprintf("%d", now.UTC().UnixNano()),
	}
	return strings.Trim(strings.Join(values, "-"), "-")
}

func heimdallIncidentFromAction(action map[string]any) map[string]any {
	incident, ok := action["incident"].(map[string]any)
	if ok {
		return cloneAuthorizationInput(incident)
	}

	return map[string]any{
		"severity":            firstNonEmpty(anyString(action["incident_severity"]), anyString(action["severity"]), "critical"),
		"title":               firstNonEmpty(anyString(action["incident_title"]), anyString(action["description"])),
		"message":             firstNonEmpty(anyString(action["reason"]), anyString(action["description"])),
		"component_kind":      firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"]), "component"),
		"component_namespace": firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), "global"),
		"component_name":      firstNonEmpty(anyString(action["component_name"]), anyString(action["name"]), "unknown"),
		"repository":          firstNonEmpty(anyString(action["repository"]), anyString(action["repo"])),
	}
}

func heimdallActionEvidence(action map[string]any) map[string]any {
	if evidence, ok := action["evidence"].(map[string]any); ok {
		return cloneAuthorizationInput(evidence)
	}
	incident := heimdallIncidentFromAction(action)
	if evidence, ok := incident["evidence"].(map[string]any); ok {
		return cloneAuthorizationInput(evidence)
	}
	return map[string]any{}
}

func heimdallActionLearningMetadata(
	action map[string]any,
	incident map[string]any,
	evidence map[string]any,
) map[string]any {
	componentKind := firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"]), anyString(incident["component_kind"]), anyString(incident["kind"]), "component")
	componentNamespace := firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), anyString(incident["component_namespace"]), anyString(incident["namespace"]), "global")
	componentName := firstNonEmpty(anyString(action["component_name"]), anyString(action["name"]), anyString(incident["component_name"]), anyString(incident["name"]), "unknown")
	actionType := firstNonEmpty(anyString(action["type"]), "action")
	repository := firstNonEmpty(anyString(action["repository"]), anyString(incident["repository"]), anyString(evidence["repository"]))
	typeNamespace := firstNonEmpty(anyString(evidence["type_namespace"]), "global")
	typeName := anyString(evidence["type_name"])
	runtimeKind := anyString(evidence["runtime_kind"])

	providerKey := ""
	switch {
	case typeName != "":
		providerKey = fmt.Sprintf("integration_type:%s/%s", typeNamespace, typeName)
	case runtimeKind != "":
		providerKey = fmt.Sprintf("runtime_kind:%s", strings.ToLower(strings.TrimSpace(runtimeKind)))
	case repository != "":
		providerKey = fmt.Sprintf("repository:%s", strings.ToLower(strings.TrimSpace(repository)))
	default:
		providerKey = fmt.Sprintf("component_kind:%s", strings.ToLower(strings.TrimSpace(componentKind)))
	}
	providerGroup := heimdallActionProviderGroup(typeName, runtimeKind, repository, componentKind)

	return map[string]any{
		"component_key":     heimdallComponentKey(componentKind, componentNamespace, componentName),
		"action_type":       actionType,
		"repository":        repository,
		"provider_key":      providerKey,
		"provider_group":    providerGroup,
		"incident_category": firstNonEmpty(anyString(incident["category"]), "incident"),
		"incident_severity": firstNonEmpty(anyString(incident["severity"]), "unknown"),
		"type_name":         typeName,
		"type_namespace":    typeNamespace,
		"runtime_kind":      runtimeKind,
	}
}

func heimdallDecisionMetadata(decision heimdallAutonomyDecision) map[string]any {
	return map[string]any{
		"confidence":             round2(decision.Confidence),
		"confidence_band":        strings.TrimSpace(decision.ConfidenceBand),
		"confidence_reason":      strings.TrimSpace(decision.Reason),
		"escalate":               decision.Escalate,
		"escalation_reason":      strings.TrimSpace(decision.EscalationReason),
		"manual_review":          decision.ManualReview,
		"blast_radius":           strings.TrimSpace(decision.BlastRadius),
		"blast_reason":           strings.TrimSpace(decision.BlastRadiusReason),
		"environment":            strings.TrimSpace(decision.Environment),
		"outside_business_hours": decision.OutsideBusinessHours,
		"freeze_window":          strings.TrimSpace(decision.ActiveFreezeWindow),
		"maintenance_active":     decision.MaintenanceActive,
		"maintenance_reason":     strings.TrimSpace(decision.MaintenanceReason),
		"protected_environment":  decision.ProtectedEnvironment,
		"provider_group":         strings.TrimSpace(decision.ProviderGroup),
		"incident_category":      strings.TrimSpace(decision.IncidentCategory),
		"attempts":               round2(decision.Attempts),
		"recovery_rate":          round2(decision.RecoveryRate),
	}
}

func heimdallAssessActionConfidence(
	ctx context.Context,
	db *sql.DB,
	action map[string]any,
) (heimdallActionConfidenceAssessment, error) {
	if db == nil {
		return heimdallDefaultActionConfidence(action), nil
	}
	memories, err := loadHeimdallGuardianMemories(ctx, db)
	if err != nil {
		return heimdallActionConfidenceAssessment{}, err
	}
	return heimdallAssessActionConfidenceFromMemories(action, memories), nil
}

func heimdallAssessActionConfidenceFromMemories(
	action map[string]any,
	memories []heimdallGuardianMemory,
) heimdallActionConfidenceAssessment {
	incident := heimdallIncidentFromAction(action)
	evidence := heimdallActionEvidence(action)
	current := heimdallActionLearningMetadata(action, incident, evidence)
	actionType := anyString(current["action_type"])
	providerGroup := anyString(current["provider_group"])
	incidentCategory := anyString(current["incident_category"])
	blastRadius, blastRadiusReason := heimdallResolveActionBlastRadius(action)
	environment := heimdallActionEnvironment(action)

	if actionType == "" {
		return heimdallDefaultActionConfidence(action)
	}

	recovered := 0.0
	unchanged := 0.0
	failed := 0.0
	totalWeight := 0.0
	recoveryTimingWeight := 0.0
	avgTimeToRecovery := 0.0
	avgStableWindow := 0.0
	bestScope := ""

	for _, memory := range memories {
		if !heimdallMemoryCanInformConfidence(memory.Spec.Status) {
			continue
		}
		memoryActionType := strings.TrimSpace(anyString(memory.Spec.Action["type"]))
		if !strings.EqualFold(memoryActionType, actionType) {
			continue
		}
		weight, scope := heimdallMemoryMatchWeight(current, memory)
		if weight <= 0 {
			continue
		}
		totalWeight += weight
		if heimdallScopeRank(scope) > heimdallScopeRank(bestScope) {
			bestScope = scope
		}

		switch strings.TrimSpace(memory.Spec.Status) {
		case model.GuardianMemoryStatusObservedRecovered:
			recovered += weight
			speed := heimdallObservationSpeedScore(memory.Spec.Observation.TimeToRecoverySeconds)
			stability := heimdallObservationStabilityScore(memory.Spec.Observation.StableWindowSeconds)
			avgTimeToRecovery = heimdallWeightedAverage(avgTimeToRecovery, float64(memory.Spec.Observation.TimeToRecoverySeconds), recoveryTimingWeight, weight)
			avgStableWindow = heimdallWeightedAverage(avgStableWindow, float64(memory.Spec.Observation.StableWindowSeconds), recoveryTimingWeight, weight)
			recoveryTimingWeight += weight
			recovered += weight * (0.35*speed + 0.45*stability)
		case model.GuardianMemoryStatusObservedUnchanged:
			unchanged += weight * heimdallObservationUnchangedPenalty(memory.Spec.Observation)
		case model.GuardianMemoryStatusExecutionFailed, model.GuardianMemoryStatusObservedRegressed:
			failed += weight * heimdallObservationFailurePenalty(memory.Spec)
		}
	}

	if totalWeight == 0 {
		return heimdallDefaultActionConfidence(action)
	}

	recoveryRate := recovered / (recovered + unchanged + failed)
	stabilityScore := heimdallObservationStabilityScore(int(avgStableWindow))
	speedScore := heimdallObservationSpeedScore(int(avgTimeToRecovery))
	sampleScore := heimdallMinFloat(1, totalWeight/3)
	confidence := 0.45*recoveryRate + 0.25*stabilityScore + 0.15*speedScore + 0.15*sampleScore
	if confidence < 0 {
		confidence = 0
	}
	if confidence > 1 {
		confidence = 1
	}

	return heimdallActionConfidenceAssessment{
		Confidence:               confidence,
		Attempts:                 totalWeight,
		RecoveryRate:             recoveryRate,
		AvgTimeToRecoverySeconds: avgTimeToRecovery,
		AvgStableWindowSeconds:   avgStableWindow,
		ComponentScope:           bestScope,
		ProviderGroup:            providerGroup,
		IncidentCategory:         incidentCategory,
		BlastRadius:              blastRadius,
		BlastRadiusReason:        blastRadiusReason,
		Environment:              environment,
	}
}

func heimdallDefaultActionConfidence(action map[string]any) heimdallActionConfidenceAssessment {
	incident := heimdallIncidentFromAction(action)
	evidence := heimdallActionEvidence(action)
	current := heimdallActionLearningMetadata(action, incident, evidence)
	blastRadius, blastRadiusReason := heimdallResolveActionBlastRadius(action)
	return heimdallActionConfidenceAssessment{
		Confidence:        0.3,
		Attempts:          0,
		RecoveryRate:      0,
		ComponentScope:    "unknown",
		ProviderGroup:     anyString(current["provider_group"]),
		IncidentCategory:  anyString(current["incident_category"]),
		BlastRadius:       blastRadius,
		BlastRadiusReason: blastRadiusReason,
		Environment:       heimdallActionEnvironment(action),
	}
}

func heimdallMemoryCanInformConfidence(status string) bool {
	switch strings.TrimSpace(status) {
	case model.GuardianMemoryStatusObservedRecovered,
		model.GuardianMemoryStatusObservedUnchanged,
		model.GuardianMemoryStatusExecutionFailed,
		model.GuardianMemoryStatusObservedRegressed:
		return true
	default:
		return false
	}
}

func heimdallMemoryMatchWeight(
	current map[string]any,
	memory heimdallGuardianMemory,
) (float64, string) {
	memoryComponentKey := strings.TrimSpace(anyString(memory.Spec.Metadata["component_key"]))
	memoryProviderKey := strings.TrimSpace(anyString(memory.Spec.Metadata["provider_key"]))
	memoryProviderGroup := strings.TrimSpace(anyString(memory.Spec.Metadata["provider_group"]))
	memoryIncidentCategory := strings.TrimSpace(anyString(memory.Spec.Metadata["incident_category"]))

	currentComponentKey := strings.TrimSpace(anyString(current["component_key"]))
	currentProviderKey := strings.TrimSpace(anyString(current["provider_key"]))
	currentProviderGroup := strings.TrimSpace(anyString(current["provider_group"]))
	currentIncidentCategory := strings.TrimSpace(anyString(current["incident_category"]))
	currentComponentKind := strings.TrimSpace(anyString(current["component_kind"]))

	switch {
	case memoryComponentKey != "" && strings.EqualFold(memoryComponentKey, currentComponentKey) &&
		strings.EqualFold(memoryIncidentCategory, currentIncidentCategory):
		return 1.0, "component"
	case memoryProviderKey != "" && strings.EqualFold(memoryProviderKey, currentProviderKey) &&
		strings.EqualFold(memoryIncidentCategory, currentIncidentCategory):
		return 0.75, "provider"
	case memoryProviderGroup != "" && strings.EqualFold(memoryProviderGroup, currentProviderGroup) &&
		strings.EqualFold(memoryIncidentCategory, currentIncidentCategory):
		return 0.6, "provider_group"
	case strings.EqualFold(memoryIncidentCategory, currentIncidentCategory) &&
		strings.EqualFold(memory.Spec.ComponentKind, currentComponentKind):
		return 0.35, "incident_category"
	case memoryProviderGroup != "" && strings.EqualFold(memoryProviderGroup, currentProviderGroup):
		return 0.2, "provider_group"
	case strings.EqualFold(memory.Spec.ComponentKind, currentComponentKind):
		return 0.1, "component_kind"
	default:
		return 0, ""
	}
}

func heimdallScopeRank(scope string) int {
	switch strings.TrimSpace(scope) {
	case "component":
		return 5
	case "provider":
		return 4
	case "provider_group":
		return 3
	case "incident_category":
		return 2
	case "component_kind":
		return 1
	default:
		return 0
	}
}

func heimdallObservationSpeedScore(seconds int) float64 {
	switch {
	case seconds <= 0:
		return 0.6
	case seconds <= 5*60:
		return 1
	case seconds <= 30*60:
		return 0.85
	case seconds <= 2*60*60:
		return 0.65
	case seconds <= 24*60*60:
		return 0.35
	default:
		return 0.15
	}
}

func heimdallObservationStabilityScore(seconds int) float64 {
	switch {
	case seconds >= 24*60*60:
		return 1
	case seconds >= 6*60*60:
		return 0.8
	case seconds >= 60*60:
		return 0.6
	case seconds >= 10*60:
		return 0.35
	case seconds > 0:
		return 0.15
	default:
		return 0.05
	}
}

func heimdallObservationUnchangedPenalty(observation model.GuardianMemoryObservationSpec) float64 {
	penalty := 1.0
	if observation.StableWindowSeconds >= 60*60 {
		penalty += 0.35
	}
	if observation.ObservationCount > 1 {
		penalty += heimdallMinFloat(0.3, float64(observation.ObservationCount-1)*0.05)
	}
	return penalty
}

func heimdallObservationFailurePenalty(spec model.GuardianMemoryManifestSpec) float64 {
	penalty := 1.3
	if strings.TrimSpace(spec.Execution.Error) != "" {
		penalty += 0.4
	}
	if spec.Observation.StableWindowSeconds > 0 && spec.Observation.StableWindowSeconds < 10*60 {
		penalty += 0.3
	}
	return penalty
}

func heimdallWeightedAverage(currentAverage, sample, currentWeight, newWeight float64) float64 {
	if newWeight <= 0 {
		return currentAverage
	}
	if currentWeight <= 0 {
		return sample
	}
	return ((currentAverage * currentWeight) + (sample * newWeight)) / (currentWeight + newWeight)
}

func heimdallMinFloat(left, right float64) float64 {
	if left < right {
		return left
	}
	return right
}

func round2(value float64) float64 {
	return math.Round(value*100) / 100
}

func heimdallActionProviderGroup(typeName, runtimeKind, repository, componentKind string) string {
	switch {
	case strings.TrimSpace(typeName) != "":
		return strings.ToLower(strings.TrimSpace(typeName))
	case strings.TrimSpace(runtimeKind) != "":
		return strings.ToLower(strings.TrimSpace(runtimeKind))
	case strings.TrimSpace(repository) != "":
		parts := strings.Split(strings.TrimSpace(repository), "/")
		return strings.ToLower(strings.TrimSpace(parts[len(parts)-1]))
	default:
		return strings.ToLower(strings.TrimSpace(componentKind))
	}
}

func createHeimdallPendingApprovalMemory(
	ctx context.Context,
	db *sql.DB,
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
	decision heimdallAutonomyDecision,
) (heimdallGuardianMemory, error) {
	now := time.Now().UTC()
	actionType := firstNonEmpty(anyString(action["type"]), "action")
	componentKind := firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"]), "component")
	componentNamespace := firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), "global")
	componentName := firstNonEmpty(anyString(action["component_name"]), anyString(action["name"]), "unknown")

	spec := manifestengine.NormalizeGuardianMemorySpec(model.GuardianMemoryManifestSpec{
		GuardianRef:        policy.GuardianRef,
		Status:             model.GuardianMemoryStatusPendingApproval,
		Source:             source,
		ComponentKind:      componentKind,
		ComponentNamespace: componentNamespace,
		ComponentName:      componentName,
		Action:             cloneAuthorizationInput(action),
		Incident:           heimdallIncidentFromAction(action),
		Evidence:           heimdallActionEvidence(action),
		Metadata: map[string]any{
			"autonomy_mode": policy.Autonomy.Mode,
			"requested_at":  now.Format(time.RFC3339),
		},
	})
	spec.Metadata = mergeStringAnyMaps(spec.Metadata, heimdallActionLearningMetadata(spec.Action, spec.Incident, spec.Evidence))
	spec.Metadata = mergeStringAnyMaps(spec.Metadata, heimdallDecisionMetadata(decision))

	return createHeimdallGuardianMemory(ctx, db, normalizeHeimdallMemoryName(componentKind, componentName, actionType, now), spec)
}

func ensureHeimdallExecutionMemory(
	ctx context.Context,
	db *sql.DB,
	action map[string]any,
	policy model.GuardianPolicyManifestSpec,
	source string,
	options heimdallExecutionOptions,
) (heimdallGuardianMemory, error) {
	now := time.Now().UTC()
	if strings.TrimSpace(options.MemoryName) != "" {
		memoryNS := firstNonEmpty(options.MemoryNS, "global")
		manifestRecord, err := repository.ResolveManifest(ctx, db, "guardian_memory", memoryNS, options.MemoryName, nil, true)
		if err != nil {
			return heimdallGuardianMemory{}, err
		}
		spec, err := manifestengine.ParseGuardianMemorySpec(manifestRecord.Spec)
		if err != nil {
			return heimdallGuardianMemory{}, err
		}
		spec = manifestengine.NormalizeGuardianMemorySpec(spec)
		spec.Status = model.GuardianMemoryStatusExecuting
		spec.Execution.AttemptedAt = now.Format(time.RFC3339)
		spec.Execution.CompletedAt = ""
		spec.Execution.Error = ""
		spec.Metadata["approval_executed"] = true
		if options.Decision != nil {
			spec.Metadata = mergeStringAnyMaps(spec.Metadata, heimdallDecisionMetadata(*options.Decision))
		}
		return updateHeimdallGuardianMemory(ctx, db, heimdallGuardianMemory{
			Manifest: manifestRecord,
			Spec:     spec,
		})
	}

	actionType := firstNonEmpty(anyString(action["type"]), "action")
	componentKind := firstNonEmpty(anyString(action["component_kind"]), anyString(action["kind"]), "component")
	componentNamespace := firstNonEmpty(anyString(action["component_namespace"]), anyString(action["namespace"]), "global")
	componentName := firstNonEmpty(anyString(action["component_name"]), anyString(action["name"]), "unknown")

	spec := manifestengine.NormalizeGuardianMemorySpec(model.GuardianMemoryManifestSpec{
		GuardianRef:        policy.GuardianRef,
		Status:             model.GuardianMemoryStatusExecuting,
		Source:             source,
		ComponentKind:      componentKind,
		ComponentNamespace: componentNamespace,
		ComponentName:      componentName,
		Action:             cloneAuthorizationInput(action),
		Incident:           heimdallIncidentFromAction(action),
		Evidence:           heimdallActionEvidence(action),
		Execution: model.GuardianMemoryExecutionSpec{
			AttemptedAt: now.Format(time.RFC3339),
		},
		Metadata: map[string]any{
			"autonomy_mode": policy.Autonomy.Mode,
		},
	})
	spec.Metadata = mergeStringAnyMaps(spec.Metadata, heimdallActionLearningMetadata(spec.Action, spec.Incident, spec.Evidence))
	if options.Decision != nil {
		spec.Metadata = mergeStringAnyMaps(spec.Metadata, heimdallDecisionMetadata(*options.Decision))
	}

	return createHeimdallGuardianMemory(ctx, db, normalizeHeimdallMemoryName(componentKind, componentName, actionType, now), spec)
}

func finalizeHeimdallExecutionMemory(
	ctx context.Context,
	db *sql.DB,
	memory heimdallGuardianMemory,
	action map[string]any,
	executionErr error,
) error {
	if memory.Manifest.ID == uuid.Nil {
		return nil
	}

	spec := memory.Spec
	spec.Action = cloneAuthorizationInput(action)
	spec.Incident = heimdallIncidentFromAction(action)
	spec.Evidence = heimdallActionEvidence(action)
	spec.Metadata = mergeStringAnyMaps(spec.Metadata, heimdallActionLearningMetadata(spec.Action, spec.Incident, spec.Evidence))
	spec.Execution.CompletedAt = time.Now().UTC().Format(time.RFC3339)
	if executionErr != nil {
		spec.Status = model.GuardianMemoryStatusExecutionFailed
		spec.Execution.Error = strings.TrimSpace(executionErr.Error())
	} else {
		spec.Status = model.GuardianMemoryStatusExecuted
		spec.Execution.Error = ""
	}

	_, err := updateHeimdallGuardianMemory(ctx, db, heimdallGuardianMemory{
		Manifest: memory.Manifest,
		Spec:     spec,
	})
	return err
}

func UpdateHeimdallApprovalMemoryStatus(
	ctx context.Context,
	db *sql.DB,
	approval model.GuardianApprovalManifestSpec,
	status string,
	comment string,
) error {
	memoryName := strings.TrimSpace(anyString(approval.Metadata["memory_name"]))
	if memoryName == "" {
		return nil
	}
	memoryNS := firstNonEmpty(anyString(approval.Metadata["memory_namespace"]), "global")
	manifestRecord, err := repository.ResolveManifest(ctx, db, "guardian_memory", memoryNS, memoryName, nil, true)
	if err != nil {
		return err
	}
	spec, err := manifestengine.ParseGuardianMemorySpec(manifestRecord.Spec)
	if err != nil {
		return err
	}
	spec = manifestengine.NormalizeGuardianMemorySpec(spec)
	spec.Status = strings.TrimSpace(status)
	if spec.Metadata == nil {
		spec.Metadata = map[string]any{}
	}
	if strings.TrimSpace(comment) != "" {
		spec.Metadata["decision_comment"] = strings.TrimSpace(comment)
	}
	spec.Metadata["decided_at"] = time.Now().UTC().Format(time.RFC3339)
	_, err = updateHeimdallGuardianMemory(ctx, db, heimdallGuardianMemory{
		Manifest: manifestRecord,
		Spec:     spec,
	})
	return err
}

func createHeimdallGuardianMemory(
	ctx context.Context,
	db *sql.DB,
	name string,
	spec model.GuardianMemoryManifestSpec,
) (heimdallGuardianMemory, error) {
	spec = manifestengine.NormalizeGuardianMemorySpec(spec)
	specRaw, err := json.Marshal(spec)
	if err != nil {
		return heimdallGuardianMemory{}, fmt.Errorf("marshal guardian_memory spec: %w", err)
	}

	manifestRecord, err := heimdallCreateManifestVersion(ctx, db, model.ManifestDocument{
		APIVersion: "yggdrasil.io/v1alpha1",
		Kind:       "guardian_memory",
		Metadata: model.ManifestMetadataInput{
			Name:        name,
			Namespace:   "global",
			Description: fmt.Sprintf("Heimdall memory for %s/%s", spec.ComponentNamespace, spec.ComponentName),
			Labels:      heimdallGuardianMemoryLabels(spec),
		},
		Spec: specRaw,
	})
	if err != nil {
		return heimdallGuardianMemory{}, err
	}
	return heimdallGuardianMemory{Manifest: manifestRecord, Spec: spec}, nil
}

func updateHeimdallGuardianMemory(
	ctx context.Context,
	db *sql.DB,
	current heimdallGuardianMemory,
) (heimdallGuardianMemory, error) {
	current.Spec = manifestengine.NormalizeGuardianMemorySpec(current.Spec)
	specRaw, err := json.Marshal(current.Spec)
	if err != nil {
		return heimdallGuardianMemory{}, fmt.Errorf("marshal guardian_memory spec: %w", err)
	}
	manifestRecord, err := heimdallCreateManifestVersion(ctx, db, model.ManifestDocument{
		APIVersion: current.Manifest.APIVersion,
		Kind:       current.Manifest.Kind,
		Metadata: model.ManifestMetadataInput{
			Name:        current.Manifest.Metadata.Name,
			Namespace:   current.Manifest.Metadata.Namespace,
			Description: current.Manifest.Metadata.Description,
			Labels:      heimdallGuardianMemoryLabels(current.Spec),
		},
		Spec: specRaw,
	})
	if err != nil {
		return heimdallGuardianMemory{}, err
	}
	current.Manifest = manifestRecord
	return current, nil
}

func heimdallGuardianMemoryLabels(spec model.GuardianMemoryManifestSpec) map[string]string {
	labels := map[string]string{
		"guardian":       "heimdall",
		"memory_status":  spec.Status,
		"component_kind": spec.ComponentKind,
		"component_name": spec.ComponentName,
		"component_ns":   spec.ComponentNamespace,
		"memory_source":  spec.Source,
		"action_type":    strings.TrimSpace(anyString(spec.Action["type"])),
	}
	for key, value := range labels {
		labels[key] = strings.TrimSpace(value)
	}
	return labels
}

func observeHeimdallGuardianMemories(
	ctx context.Context,
	db *sql.DB,
	snapshot map[string]any,
	memories []heimdallGuardianMemory,
) error {
	for _, memory := range memories {
		if !heimdallMemoryNeedsObservation(memory.Spec.Status) {
			continue
		}
		nextStatus, observation, ok := heimdallEvaluateMemoryObservation(snapshot, memory.Spec)
		if !ok {
			continue
		}
		memory.Spec.Status = nextStatus
		memory.Spec.Observation = observation
		if _, err := updateHeimdallGuardianMemory(ctx, db, memory); err != nil {
			return err
		}
	}
	return nil
}

func heimdallMemoryNeedsObservation(status string) bool {
	switch strings.TrimSpace(status) {
	case model.GuardianMemoryStatusExecuted,
		model.GuardianMemoryStatusObservedRecovered,
		model.GuardianMemoryStatusObservedUnchanged:
		return true
	default:
		return false
	}
}

func heimdallEvaluateMemoryObservation(
	snapshot map[string]any,
	spec model.GuardianMemoryManifestSpec,
) (string, model.GuardianMemoryObservationSpec, bool) {
	component := heimdallSnapshotComponent(snapshot, spec.ComponentKind, spec.ComponentNamespace, spec.ComponentName)
	incidents := heimdallSnapshotIncidents(snapshot, spec.ComponentKind, spec.ComponentNamespace, spec.ComponentName)

	health := "unknown"
	if len(component) > 0 {
		health = normalizeState(firstNonEmpty(anyString(component["overall_health"]), anyString(component["status"]), "unknown"))
	}
	criticalIncidents := 0
	for _, incident := range incidents {
		if normalizeSeverity(anyString(incident["severity"])) == "critical" {
			criticalIncidents++
		}
	}

	now := time.Now().UTC()
	observation := spec.Observation
	if observation.ObservedAt == "" {
		observation.ObservedAt = now.Format(time.RFC3339)
	}
	observation.LastObservedAt = now.Format(time.RFC3339)
	observation.ComponentHealth = health
	observation.IncidentCount = len(incidents)
	observation.ObservationCount++
	if observation.ObservationCount <= 0 {
		observation.ObservationCount = 1
	}
	if observation.TimeToRecoverySeconds == 0 {
		if completedAt, ok := heimdallParseRFC3339(spec.Execution.CompletedAt); ok {
			observation.TimeToRecoverySeconds = heimdallMaxInt(0, int(now.Sub(completedAt).Seconds()))
		} else if attemptedAt, ok := heimdallParseRFC3339(spec.Execution.AttemptedAt); ok {
			observation.TimeToRecoverySeconds = heimdallMaxInt(0, int(now.Sub(attemptedAt).Seconds()))
		}
	}
	if observedAt, ok := heimdallParseRFC3339(observation.ObservedAt); ok {
		observation.StableWindowSeconds = heimdallMaxInt(0, int(now.Sub(observedAt).Seconds()))
	}
	componentHealthy := criticalIncidents == 0 && !containsAnyString(health, "unreachable", "invalid_response", "contract_mismatch", "degraded", "failed", "disabled")

	switch {
	case len(component) == 0:
		observation.Summary = "The component was not found in the latest ecosystem snapshot."
		return model.GuardianMemoryStatusObservedUnchanged, observation, true
	case componentHealthy:
		if observation.TimeToRecoverySeconds == 0 {
			observation.TimeToRecoverySeconds = 1
		}
		if observation.StableWindowSeconds >= 24*60*60 {
			observation.Summary = "The component recovered and has stayed healthy for at least 24 hours."
		} else if observation.StableWindowSeconds >= 60*60 {
			observation.Summary = "The component recovered and has remained healthy for a meaningful stability window."
		} else {
			observation.Summary = "The component looks healthy after the action."
		}
		return model.GuardianMemoryStatusObservedRecovered, observation, true
	case criticalIncidents > 0 || containsAnyString(health, "unreachable", "invalid_response", "contract_mismatch"):
		observation.Summary = "The component still looks unhealthy after the action."
		return model.GuardianMemoryStatusObservedRegressed, observation, true
	default:
		observation.Summary = "The component changed, but the issue was not clearly resolved."
		return model.GuardianMemoryStatusObservedUnchanged, observation, true
	}
}

func heimdallParseRFC3339(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return time.Time{}, false
	}
	return parsed, true
}

func heimdallMaxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

func heimdallSnapshotComponent(snapshot map[string]any, componentKind, componentNamespace, componentName string) map[string]any {
	var collections [][]map[string]any
	switch normalizeState(componentKind) {
	case "surface":
		collections = [][]map[string]any{objectSlice(snapshot["surfaces"])}
	case "integration":
		collections = [][]map[string]any{objectSlice(snapshot["integrations"])}
	default:
		collections = [][]map[string]any{objectSlice(snapshot["integrations"]), objectSlice(snapshot["surfaces"])}
	}
	for _, collection := range collections {
		for _, item := range collection {
			if normalizeState(firstNonEmpty(anyString(item["component_kind"]), anyString(item["kind"]), componentKind)) != normalizeState(componentKind) {
				continue
			}
			if firstNonEmpty(anyString(item["component_namespace"]), anyString(item["namespace"]), "global") != firstNonEmpty(componentNamespace, "global") {
				continue
			}
			if firstNonEmpty(anyString(item["component_name"]), anyString(item["name"])) != componentName {
				continue
			}
			return cloneAuthorizationInput(item)
		}
	}
	return map[string]any{}
}

func heimdallSnapshotIncidents(snapshot map[string]any, componentKind, componentNamespace, componentName string) []map[string]any {
	items := objectSlice(snapshot["incidents"])
	filtered := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if normalizeState(firstNonEmpty(anyString(item["component_kind"]), anyString(item["kind"]), componentKind)) != normalizeState(componentKind) {
			continue
		}
		if firstNonEmpty(anyString(item["component_namespace"]), anyString(item["namespace"]), "global") != firstNonEmpty(componentNamespace, "global") {
			continue
		}
		if firstNonEmpty(anyString(item["component_name"]), anyString(item["name"])) != componentName {
			continue
		}
		filtered = append(filtered, cloneAuthorizationInput(item))
	}
	return filtered
}

func heimdallGuardianMemoryItems(memories []heimdallGuardianMemory) []map[string]any {
	limit := len(memories)
	if limit > 50 {
		limit = 50
	}
	items := make([]map[string]any, 0, limit)
	for _, memory := range memories[:limit] {
		items = append(items, map[string]any{
			"name":                memory.Manifest.Metadata.Name,
			"namespace":           memory.Manifest.Metadata.Namespace,
			"status":              memory.Spec.Status,
			"source":              memory.Spec.Source,
			"component_kind":      memory.Spec.ComponentKind,
			"component_namespace": memory.Spec.ComponentNamespace,
			"component_name":      memory.Spec.ComponentName,
			"action_type":         strings.TrimSpace(anyString(memory.Spec.Action["type"])),
			"action":              cloneAuthorizationInput(memory.Spec.Action),
			"incident":            cloneAuthorizationInput(memory.Spec.Incident),
			"evidence":            cloneAuthorizationInput(memory.Spec.Evidence),
			"metadata":            cloneAuthorizationInput(memory.Spec.Metadata),
			"execution": map[string]any{
				"attempted_at": memory.Spec.Execution.AttemptedAt,
				"completed_at": memory.Spec.Execution.CompletedAt,
				"error":        memory.Spec.Execution.Error,
			},
			"observation": map[string]any{
				"observed_at":              memory.Spec.Observation.ObservedAt,
				"last_observed_at":         memory.Spec.Observation.LastObservedAt,
				"summary":                  memory.Spec.Observation.Summary,
				"component_health":         memory.Spec.Observation.ComponentHealth,
				"incident_count":           memory.Spec.Observation.IncidentCount,
				"observation_count":        memory.Spec.Observation.ObservationCount,
				"time_to_recovery_seconds": memory.Spec.Observation.TimeToRecoverySeconds,
				"stable_window_seconds":    memory.Spec.Observation.StableWindowSeconds,
			},
			"created_at": memory.Manifest.CreatedAt.UTC().Format(time.RFC3339),
			"updated_at": memory.Manifest.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	return items
}

func heimdallCreateManifestVersion(ctx context.Context, db *sql.DB, doc model.ManifestDocument) (model.Manifest, error) {
	doc = manifestengine.NormalizeDocument(doc)
	if err := manifestengine.ValidateDocument(doc); err != nil {
		return model.Manifest{}, err
	}

	checksum, err := manifestengine.Checksum(doc)
	if err != nil {
		return model.Manifest{}, err
	}

	return repository.CreateManifestVersion(ctx, db, doc, checksum)
}

func heimdallCapacityHotfixProfileFromAction(action map[string]any) (map[string]any, error) {
	profile := asObject(action["profile"])
	if len(profile) == 0 {
		profile = asObject(asObject(action["target"])["profile"])
	}
	if len(profile) == 0 {
		return nil, fmt.Errorf("heimdall action type upsert_capacity_hotfix_profile requires a profile payload")
	}

	normalized := map[string]any{
		"name": firstNonEmpty(anyString(profile["name"]), anyString(profile["profile_name"])),
	}
	if strings.TrimSpace(anyString(normalized["name"])) == "" {
		return nil, fmt.Errorf("capacity hotfix profile name is required")
	}

	environments := heimdallStringArray(profile["environments"])
	if len(environments) > 0 {
		normalized["environments"] = environments
	}
	namespaces := heimdallStringArray(profile["namespaces"])
	if len(namespaces) > 0 {
		normalized["namespaces"] = namespaces
	}
	workloadNames := heimdallStringArray(firstNonEmptyValue(profile["workload_names"], profile["workloadNames"]))
	if len(workloadNames) > 0 {
		normalized["workload_names"] = workloadNames
	}
	workloadPrefixes := heimdallStringArray(firstNonEmptyValue(profile["workload_name_prefixes"], profile["workloadNamePrefixes"]))
	if len(workloadPrefixes) > 0 {
		normalized["workload_name_prefixes"] = workloadPrefixes
	}

	if value, ok := heimdallOptionalInt(firstNonEmptyValue(profile["default_request_millicores"], profile["defaultRequestMillicores"])); ok {
		normalized["default_request_millicores"] = value
	}
	if value, ok := heimdallOptionalInt(firstNonEmptyValue(profile["default_limit_millicores"], profile["defaultLimitMillicores"])); ok {
		normalized["default_limit_millicores"] = value
	}
	if value, ok := heimdallOptionalInt(firstNonEmptyValue(profile["max_request_delta_millicores"], profile["maxRequestDeltaMillicores"])); ok {
		normalized["max_request_delta_millicores"] = value
	}
	if value, ok := heimdallOptionalInt(firstNonEmptyValue(profile["max_limit_delta_millicores"], profile["maxLimitDeltaMillicores"])); ok {
		normalized["max_limit_delta_millicores"] = value
	}

	return normalized, nil
}

func heimdallMergeCapacityHotfixProfiles(existing []map[string]any, profile map[string]any) []map[string]any {
	next := make([]map[string]any, 0, len(existing)+1)
	profileName := strings.TrimSpace(anyString(profile["name"]))
	for _, entry := range existing {
		if strings.EqualFold(strings.TrimSpace(anyString(entry["name"])), profileName) {
			continue
		}
		normalized, err := heimdallCapacityHotfixProfileFromAction(map[string]any{"profile": entry})
		if err != nil {
			continue
		}
		next = append(next, normalized)
	}
	next = append(next, profile)
	sort.SliceStable(next, func(left, right int) bool {
		return strings.TrimSpace(anyString(next[left]["name"])) < strings.TrimSpace(anyString(next[right]["name"]))
	})
	return next
}

func heimdallStringArray(value any) []string {
	values := objectSliceValueToStrings(value)
	if len(values) == 0 {
		return nil
	}
	return values
}

func objectSliceValueToStrings(value any) []string {
	items, ok := value.([]string)
	if ok {
		output := make([]string, 0, len(items))
		for _, item := range items {
			normalized := strings.TrimSpace(item)
			if normalized == "" {
				continue
			}
			output = append(output, normalized)
		}
		return output
	}

	rawItems, ok := value.([]any)
	if !ok {
		return nil
	}
	output := make([]string, 0, len(rawItems))
	for _, item := range rawItems {
		normalized := strings.TrimSpace(fmt.Sprintf("%v", item))
		if normalized == "" {
			continue
		}
		output = append(output, normalized)
	}
	return output
}

func heimdallOptionalInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case float64:
		return int(math.Round(typed)), true
	case float32:
		return int(math.Round(float64(typed))), true
	case json.Number:
		parsed, err := typed.Int64()
		if err == nil {
			return int(parsed), true
		}
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		parsed, err := strconv.ParseFloat(trimmed, 64)
		if err == nil {
			return int(math.Round(parsed)), true
		}
	}
	return 0, false
}

func firstNonEmptyValue(values ...any) any {
	for _, value := range values {
		switch typed := value.(type) {
		case nil:
			continue
		case string:
			if strings.TrimSpace(typed) != "" {
				return typed
			}
		case []string:
			if len(typed) > 0 {
				return typed
			}
		case []any:
			if len(typed) > 0 {
				return typed
			}
		default:
			return typed
		}
	}
	return nil
}

func heimdallCloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func firstBool(values map[string]any, keys []string, fallback bool) bool {
	for _, key := range keys {
		raw, ok := values[key]
		if !ok {
			continue
		}
		switch typed := raw.(type) {
		case bool:
			return typed
		case string:
			normalized := strings.ToLower(strings.TrimSpace(typed))
			if normalized == "true" || normalized == "1" || normalized == "yes" {
				return true
			}
			if normalized == "false" || normalized == "0" || normalized == "no" {
				return false
			}
		}
	}
	return fallback
}

func objectSlice(value any) []map[string]any {
	items, ok := value.([]map[string]any)
	if ok {
		return items
	}
	typed, ok := value.([]any)
	if !ok {
		return nil
	}
	output := make([]map[string]any, 0, len(typed))
	for _, item := range typed {
		mapped, ok := item.(map[string]any)
		if !ok {
			continue
		}
		output = append(output, mapped)
	}
	return output
}

func normalizeState(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeSeverity(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func containsAnyString(value string, patterns ...string) bool {
	for _, pattern := range patterns {
		if strings.Contains(value, strings.ToLower(strings.TrimSpace(pattern))) {
			return true
		}
	}
	return false
}

func containsKey(values []string, patterns ...string) bool {
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		for _, pattern := range patterns {
			if normalized == strings.ToLower(strings.TrimSpace(pattern)) {
				return true
			}
		}
	}
	return false
}

func heimdallPolicyInput(policy model.GuardianPolicyManifestSpec) map[string]any {
	return map[string]any{
		"scope": policy.Scope,
		"auto_heal": map[string]any{
			"enabled":                 policy.AutoHeal.Enabled,
			"severity_threshold":      policy.AutoHeal.SeverityThreshold,
			"max_actions_per_sweep":   policy.AutoHeal.MaxActionsPerSweep,
			"cooldown_seconds":        policy.AutoHeal.CooldownSeconds,
			"allow_dispatch_workflow": policy.AutoHeal.AllowDispatchWorkflow,
			"allow_rotate_secret":     policy.AutoHeal.AllowRotateSecret,
			"allow_rightsize":         policy.AutoHeal.AllowRightsize,
		},
		"repository_automation": map[string]any{
			"allow_pull_request_automation": policy.RepositoryAutomation.AllowPullRequestAutomation,
			"allow_direct_push":             policy.RepositoryAutomation.AllowDirectPush,
		},
		"generated_bundles": map[string]any{
			"enabled":                       policy.GeneratedBundles.Enabled,
			"require_approval":              policy.GeneratedBundles.RequireApproval,
			"max_ttl_seconds":               policy.GeneratedBundles.MaxTTLSeconds,
			"allow_workflow_patch":          policy.GeneratedBundles.AllowWorkflowPatch,
			"allow_integration_composition": policy.GeneratedBundles.AllowIntegrationComposition,
			"allow_ephemeral_executor":      policy.GeneratedBundles.AllowEphemeralExecutor,
		},
		"cost_optimization": map[string]any{
			"enabled":                           policy.CostOptimization.Enabled,
			"min_estimated_monthly_savings_usd": policy.CostOptimization.MinEstimatedMonthlySavingsUSD,
			"allow_rightsize":                   policy.CostOptimization.AllowRightsize,
		},
		"maintenance_mode": map[string]any{
			"enabled":             policy.MaintenanceMode.Enabled,
			"environments":        cloneStringSlice(policy.MaintenanceMode.Environments),
			"reason":              policy.MaintenanceMode.Reason,
			"allow_hotfix_bypass": policy.MaintenanceMode.AllowHotfixBypass,
		},
		"escalation": map[string]any{
			"enabled":                       policy.Escalation.Enabled,
			"severity_threshold":            policy.Escalation.SeverityThreshold,
			"max_auto_heal_attempts":        policy.Escalation.MaxAutoHealAttempts,
			"create_approval":               policy.Escalation.CreateApproval,
			"dispatch_workflow":             policy.Escalation.DispatchWorkflow,
			"issue_workflow":                policy.Escalation.IssueWorkflow,
			"postmortem_workflow":           policy.Escalation.PostmortemWorkflow,
			"ref":                           policy.Escalation.Ref,
			"postmortem_severity_threshold": policy.Escalation.PostmortemSeverityThreshold,
			"environments":                  cloneStringSlice(policy.Escalation.Environments),
		},
		"autonomy": map[string]any{
			"mode":                           policy.Autonomy.Mode,
			"allow_llm_fallback":             policy.Autonomy.AllowLLMFallback,
			"hotfix_severity":                policy.Autonomy.HotfixSeverityThreshold,
			"auto_execute_min_confidence":    policy.Autonomy.AutoExecuteMinConfidence,
			"manual_review_below_confidence": policy.Autonomy.ManualReviewBelowConfidence,
			"max_auto_execute_blast_radius":  policy.Autonomy.MaxAutoExecuteBlastRadius,
			"max_bypass_hotfix_blast_radius": policy.Autonomy.MaxBypassHotfixBlastRadius,
			"protected_environments": map[string]any{
				"environments":                   cloneStringSlice(policy.Autonomy.ProtectedEnvironments.Environments),
				"max_auto_execute_blast_radius":  policy.Autonomy.ProtectedEnvironments.MaxAutoExecuteBlastRadius,
				"max_bypass_hotfix_blast_radius": policy.Autonomy.ProtectedEnvironments.MaxBypassHotfixBlastRadius,
			},
			"business_hours": map[string]any{
				"enabled":             policy.Autonomy.BusinessHours.Enabled,
				"timezone":            policy.Autonomy.BusinessHours.Timezone,
				"weekdays":            cloneStringSlice(policy.Autonomy.BusinessHours.Weekdays),
				"start_hour":          policy.Autonomy.BusinessHours.StartHour,
				"end_hour":            policy.Autonomy.BusinessHours.EndHour,
				"environments":        cloneStringSlice(policy.Autonomy.BusinessHours.Environments),
				"allow_hotfix_bypass": policy.Autonomy.BusinessHours.AllowHotfixBypass,
			},
			"freeze_windows": heimdallPolicyFreezeWindowsInput(policy.Autonomy.FreezeWindows),
		},
	}
}

func heimdallPolicyFreezeWindowsInput(windows []model.GuardianFreezeWindowPolicySpec) []map[string]any {
	if len(windows) == 0 {
		return nil
	}
	items := make([]map[string]any, 0, len(windows))
	for _, window := range windows {
		items = append(items, map[string]any{
			"name":                window.Name,
			"starts_at":           window.StartsAt,
			"ends_at":             window.EndsAt,
			"environments":        cloneStringSlice(window.Environments),
			"allow_hotfix_bypass": window.AllowHotfixBypass,
		})
	}
	return items
}
