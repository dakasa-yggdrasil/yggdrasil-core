package message

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

const integrationRuntimeFastFailWindow = 2 * defaultIntegrationRuntimeMonitorInterval

type integrationHealthGateError struct {
	Health model.IntegrationInstanceHealth
	Reason string
}

func (e *integrationHealthGateError) Error() string {
	if e == nil {
		return ""
	}

	return fmt.Sprintf(
		"integration instance %s/%s is unavailable for operations: status=%s reason=%s",
		e.Health.IntegrationInstance.Namespace,
		e.Health.IntegrationInstance.Name,
		e.Health.Status,
		strings.TrimSpace(e.Reason),
	)
}

func getIntegrationInstanceHealth(
	ctx context.Context,
	db *sql.DB,
	selector model.ManifestSelector,
	checkKind string,
) (model.IntegrationInstanceHealth, error) {
	instanceManifest, err := resolveManifestForKind(
		ctx,
		db,
		"integration_instance",
		selector.ManifestID,
		selector.Namespace,
		selector.Name,
		selector.Version,
	)
	if err != nil {
		return model.IntegrationInstanceHealth{}, err
	}

	return buildIntegrationInstanceHealth(ctx, db, instanceManifest, checkKind)
}

func listIntegrationInstanceHealth(
	ctx context.Context,
	db *sql.DB,
	req model.ListIntegrationInstanceHealthRequest,
) ([]model.IntegrationInstanceHealth, error) {
	checkKind := normalizeIntegrationInstanceHealthCheckKind(req.CheckKind)

	manifests, err := repository.ListManifests(ctx, db, model.ListManifestFilters{
		Kind:       "integration_instance",
		Namespace:  req.Namespace,
		Name:       req.Name,
		ActiveOnly: true,
	})
	if err != nil {
		return nil, err
	}

	filterStatus := strings.ToLower(strings.TrimSpace(req.Status))
	items := make([]model.IntegrationInstanceHealth, 0, len(manifests))
	for _, manifestRecord := range manifests {
		health, err := buildIntegrationInstanceHealth(ctx, db, manifestRecord, checkKind)
		if err != nil {
			return nil, err
		}
		if filterStatus != "" && health.Status != filterStatus {
			continue
		}
		items = append(items, health)
	}

	return items, nil
}

func buildIntegrationInstanceHealth(
	ctx context.Context,
	db *sql.DB,
	instanceManifest model.Manifest,
	checkKind string,
) (model.IntegrationInstanceHealth, error) {
	checkKind = normalizeIntegrationInstanceHealthCheckKind(checkKind)

	instanceSpec, err := manifestengine.ParseIntegrationInstanceSpec(instanceManifest.Spec)
	if err != nil {
		return model.IntegrationInstanceHealth{}, err
	}

	typeManifest, err := resolveManifestForKind(
		ctx,
		db,
		"integration_type",
		instanceSpec.TypeRef.ManifestID,
		instanceSpec.TypeRef.Namespace,
		instanceSpec.TypeRef.Name,
		instanceSpec.TypeRef.Version,
	)
	if err != nil {
		return model.IntegrationInstanceHealth{}, err
	}

	declaredStatus := normalizeIntegrationInstanceDeclaredStatus(instanceSpec.Status)
	health := model.IntegrationInstanceHealth{
		IntegrationInstance: manifestReferenceFromRecord(instanceManifest),
		IntegrationType:     manifestReferenceFromRecord(typeManifest),
		DeclaredStatus:      declaredStatus,
		CheckKind:           checkKind,
		Status:              integrationInstanceOverallStatus(declaredStatus, checkKind, nil),
	}

	if declaredStatus != "active" {
		return health, nil
	}

	runtimeStates, err := loadIntegrationRuntimeStatesForHealth(ctx, db, instanceManifest, checkKind)
	if err != nil {
		if errors.Is(err, repository.ErrIntegrationRuntimeStateNotFound) {
			health.Status = integrationInstanceOverallStatus(declaredStatus, checkKind, nil)
			return health, nil
		}
		return model.IntegrationInstanceHealth{}, err
	}

	health.Status = integrationInstanceOverallStatus(declaredStatus, checkKind, runtimeStates)
	health.RuntimeChecks = runtimeStates
	if representative := representativeIntegrationRuntimeState(runtimeStates); representative != nil {
		health.RuntimeState = representative
	}
	return health, nil
}

func preflightIntegrationInstanceHealth(
	ctx context.Context,
	db *sql.DB,
	instanceManifest model.Manifest,
	instanceSpec model.IntegrationInstanceManifestSpec,
	typeManifest model.Manifest,
	checkKind string,
) error {
	checkKind = normalizeIntegrationInstanceHealthCheckKind(checkKind)
	declaredStatus := normalizeIntegrationInstanceDeclaredStatus(instanceSpec.Status)
	health := model.IntegrationInstanceHealth{
		IntegrationInstance: manifestReferenceFromRecord(instanceManifest),
		IntegrationType:     manifestReferenceFromRecord(typeManifest),
		DeclaredStatus:      declaredStatus,
		CheckKind:           checkKind,
		Status:              integrationInstanceOverallStatus(declaredStatus, checkKind, nil),
	}

	if declaredStatus != "active" {
		return &integrationHealthGateError{
			Health: health,
			Reason: "integration instance is not active",
		}
	}

	runtimeStates, err := loadIntegrationRuntimeStatesForHealth(ctx, db, instanceManifest, checkKind)
	if err != nil {
		if errors.Is(err, repository.ErrIntegrationRuntimeStateNotFound) {
			return nil
		}
		return err
	}

	health.RuntimeChecks = runtimeStates
	health.Status = integrationInstanceOverallStatus(declaredStatus, checkKind, runtimeStates)
	if representative := representativeIntegrationRuntimeState(runtimeStates); representative != nil {
		health.RuntimeState = representative
	}
	if shouldFastFailIntegrationRuntimeStates(runtimeStates, time.Now().UTC()) {
		return &integrationHealthGateError{
			Health: health,
			Reason: "recent runtime state is unhealthy",
		}
	}

	return nil
}

func normalizeIntegrationInstanceHealthCheckKind(checkKind string) string {
	checkKind = strings.ToLower(strings.TrimSpace(checkKind))
	if checkKind == "" {
		return model.IntegrationRuntimeCheckKindOverall
	}
	return checkKind
}

func normalizeIntegrationInstanceDeclaredStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		return "active"
	}
	return status
}

func integrationInstanceOverallStatus(declaredStatus string, checkKind string, runtimeStates []model.IntegrationRuntimeState) string {
	declaredStatus = normalizeIntegrationInstanceDeclaredStatus(declaredStatus)
	if declaredStatus != "active" {
		return declaredStatus
	}
	if len(runtimeStates) == 0 {
		return model.IntegrationInstanceHealthStatusUnknown
	}
	representative := representativeIntegrationRuntimeState(runtimeStates)
	if representative == nil {
		return model.IntegrationInstanceHealthStatusUnknown
	}
	if checkKind == model.IntegrationRuntimeCheckKindOverall && len(runtimeStates) < len(integrationHealthRequiredCheckKinds(checkKind)) {
		if !isIntegrationRuntimeStateUnhealthy(*representative) {
			return model.IntegrationInstanceHealthStatusUnknown
		}
	}
	return strings.ToLower(strings.TrimSpace(representative.Status))
}

func shouldFastFailIntegrationRuntimeState(state model.IntegrationRuntimeState, now time.Time) bool {
	status := strings.ToLower(strings.TrimSpace(state.Status))
	switch status {
	case model.IntegrationRuntimeStatusContractMismatch,
		model.IntegrationRuntimeStatusInvalidResponse,
		model.IntegrationRuntimeStatusUnreachable:
	default:
		return false
	}

	if state.LastCheckedAt.IsZero() {
		return true
	}

	return now.Sub(state.LastCheckedAt.UTC()) <= integrationRuntimeFastFailWindow
}

func shouldFastFailIntegrationRuntimeStates(states []model.IntegrationRuntimeState, now time.Time) bool {
	for _, state := range states {
		if shouldFastFailIntegrationRuntimeState(state, now) {
			return true
		}
	}
	return false
}

func loadIntegrationRuntimeStatesForHealth(
	ctx context.Context,
	db *sql.DB,
	instanceManifest model.Manifest,
	checkKind string,
) ([]model.IntegrationRuntimeState, error) {
	kinds := integrationHealthRequiredCheckKinds(checkKind)
	states := make([]model.IntegrationRuntimeState, 0, len(kinds))
	for _, kind := range kinds {
		state, err := repository.GetIntegrationRuntimeState(ctx, db, model.ManifestSelector{
			ManifestID: instanceManifest.ID.String(),
			Namespace:  instanceManifest.Metadata.Namespace,
			Name:       instanceManifest.Metadata.Name,
			Version:    &instanceManifest.Version,
		}, kind)
		if err != nil {
			if errors.Is(err, repository.ErrIntegrationRuntimeStateNotFound) {
				continue
			}
			return nil, err
		}
		states = append(states, state)
	}
	if len(states) == 0 {
		return nil, repository.ErrIntegrationRuntimeStateNotFound
	}
	return states, nil
}

func integrationHealthRequiredCheckKinds(checkKind string) []string {
	switch normalizeIntegrationInstanceHealthCheckKind(checkKind) {
	case model.IntegrationRuntimeCheckKindOverall:
		return []string{
			model.IntegrationRuntimeCheckKindTransportConnectivity,
			model.IntegrationRuntimeCheckKindDescribeHandshake,
		}
	default:
		return []string{normalizeIntegrationInstanceHealthCheckKind(checkKind)}
	}
}

func representativeIntegrationRuntimeState(states []model.IntegrationRuntimeState) *model.IntegrationRuntimeState {
	if len(states) == 0 {
		return nil
	}
	bestIndex := 0
	bestScore := integrationRuntimeStatusSeverity(states[0].Status)
	for index := 1; index < len(states); index++ {
		score := integrationRuntimeStatusSeverity(states[index].Status)
		if score > bestScore {
			bestIndex = index
			bestScore = score
		}
	}
	best := states[bestIndex]
	return &best
}

func integrationRuntimeStatusSeverity(status string) int {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case model.IntegrationRuntimeStatusUnreachable:
		return 4
	case model.IntegrationRuntimeStatusContractMismatch:
		return 3
	case model.IntegrationRuntimeStatusInvalidResponse:
		return 2
	case model.IntegrationRuntimeStatusHealthy:
		return 1
	default:
		return 0
	}
}

func isIntegrationRuntimeStateUnhealthy(state model.IntegrationRuntimeState) bool {
	switch strings.ToLower(strings.TrimSpace(state.Status)) {
	case model.IntegrationRuntimeStatusContractMismatch,
		model.IntegrationRuntimeStatusInvalidResponse,
		model.IntegrationRuntimeStatusUnreachable:
		return true
	default:
		return false
	}
}

func integrationInstanceHealthErrorCode(err error) string {
	if isIntegrationHealthGateError(err) {
		return "integration_unhealthy"
	}
	if errors.Is(err, repository.ErrManifestNotFound) {
		return "not_found"
	}
	message := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(message, "integration") || strings.Contains(message, "manifest") || strings.Contains(message, "parse") {
		return "bad_request"
	}
	return "internal_error"
}

func isIntegrationHealthGateError(err error) bool {
	var target *integrationHealthGateError
	return errors.As(err, &target)
}

func integrationAwareErrorCode(err error, fallback string) string {
	if isIntegrationHealthGateError(err) {
		return "integration_unhealthy"
	}

	code := manifestLookupErrorCode(err)
	if code != "internal_error" {
		return code
	}

	return fallback
}
