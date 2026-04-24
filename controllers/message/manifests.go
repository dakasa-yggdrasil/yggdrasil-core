package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
)

const (
	queueManifestValidate     = "yggdrasil-core.manifest.validate"
	queueManifestCreate       = "yggdrasil-core.manifest.create"
	queueManifestList         = "yggdrasil-core.manifest.list"
	queueManifestGet          = "yggdrasil-core.manifest.get"
	queueManifestRBACEvaluate = "yggdrasil-core.manifest.rbac.evaluate"
	queueManifestPolicyEval   = "yggdrasil-core.manifest.policy.evaluate"
	queueAuthorizationEval    = "yggdrasil-core.authorization.evaluate"
)

type rpcError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	OK    bool      `json:"ok"`
	Data  any       `json:"data,omitempty"`
	Error *rpcError `json:"error,omitempty"`
}

func manifestConsumers(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) []ConsumerConfig {
	return []ConsumerConfig{
		{
			Queue:   queueManifestValidate,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: manifestValidateHandler(conn, logger),
		},
		{
			Queue:   queueManifestCreate,
			Timeout: 10 * time.Second,
			QoS:     5,
			Handler: manifestCreateHandler(conn, db, logger),
		},
		{
			Queue:   queueManifestList,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: manifestListHandler(conn, db, logger),
		},
		{
			Queue:   queueManifestGet,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: manifestGetHandler(conn, db, logger),
		},
		{
			Queue:   queueManifestRBACEvaluate,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: manifestRBACEvaluateHandler(conn, db, logger),
		},
		{
			Queue:   queueManifestPolicyEval,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: manifestPolicyEvaluateHandler(conn, db, logger),
		},
		{
			Queue:   queueAuthorizationEval,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: authorizationEvaluateHandler(conn, db, logger),
		},
	}
}

func manifestValidateHandler(conn *amqp.Connection, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var doc model.ManifestDocument
		if err := json.Unmarshal(d.Body, &doc); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		doc = manifestengine.NormalizeDocument(doc)
		if err := manifestengine.ValidateDocument(doc); err != nil {
			return replyFailure(ctx, d, "validation_failed", err, logger)
		}

		checksum, err := manifestengine.Checksum(doc)
		if err != nil {
			return replyFailure(ctx, d, "internal_error", err, logger)
		}

		return replySuccess(ctx, d, map[string]any{
			"valid":    true,
			"kind":     doc.Kind,
			"checksum": checksum,
		}, logger)
	}
}

func manifestCreateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var doc model.ManifestDocument
		if err := json.Unmarshal(d.Body, &doc); err != nil {
			return replyFailure(ctx, d, manifestPersistCodeBadRequest, err, logger)
		}

		manifestRecord, err := persistManifestVersion(ctx, db, doc)
		if err != nil {
			persistErr, ok := err.(*manifestPersistError)
			if !ok {
				return replyFailure(ctx, d, manifestPersistCodeInternalError, err, logger)
			}
			return replyFailure(ctx, d, persistErr.Code, persistErr.Err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"manifest": manifestRecord}, logger)
	}
}

func manifestListHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		req := model.ListManifestRequest{}
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, d, "bad_request", err, logger)
			}
		}

		manifests, pagination, err := repository.ListManifestsPaginated(ctx, db, model.ListManifestFilters{
			Kind:       req.Kind,
			Namespace:  req.Namespace,
			Name:       req.Name,
			Labels:     req.Labels,
			ActiveOnly: req.ActiveOnly,
		}, req.Pagination)
		if err != nil {
			return replyFailure(ctx, d, "internal_error", err, logger)
		}

		return replySuccess(ctx, d, map[string]any{
			"manifests":  manifests,
			"pagination": pagination,
		}, logger)
	}
}

func manifestGetHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.GetManifestRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		manifestID, err := uuid.Parse(strings.TrimSpace(req.ID))
		if err != nil {
			return replyFailure(ctx, d, "bad_request", fmt.Errorf("invalid manifest id"), logger)
		}

		manifestRecord, err := repository.GetManifestByID(ctx, db, manifestID)
		if err != nil {
			code := "internal_error"
			if errors.Is(err, repository.ErrManifestNotFound) {
				code = "not_found"
			}
			return replyFailure(ctx, d, code, err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"manifest": manifestRecord}, logger)
	}
}

func manifestRBACEvaluateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.EvaluateRBACRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		manifestRecord, err := resolveManifestForRBAC(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, manifestLookupErrorCode(err), err, logger)
		}

		spec, err := manifestengine.ParseRBACSpec(manifestRecord.Spec)
		if err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		allowed, roles, matches, err := manifestengine.EvaluateRBAC(spec, req.Subject, req.Resource, req.Action)
		if err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		decision := "deny"
		if allowed {
			decision = "allow"
		}

		return replySuccess(ctx, d, model.EvaluateRBACResponse{
			Allowed:  allowed,
			Decision: decision,
			Manifest: model.ManifestReference{
				ID:        manifestRecord.ID,
				Kind:      manifestRecord.Kind,
				Namespace: manifestRecord.Metadata.Namespace,
				Name:      manifestRecord.Metadata.Name,
				Version:   manifestRecord.Version,
			},
			MatchedRoles: roles,
			MatchedRules: matches,
		}, logger)
	}
}

func manifestPolicyEvaluateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.EvaluatePolicyRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		manifestRecord, err := resolveManifestForKind(ctx, db, "policy", req.ManifestID, req.Namespace, req.Name, req.Version)
		if err != nil {
			return replyFailure(ctx, d, manifestLookupErrorCode(err), err, logger)
		}

		spec, err := manifestengine.ParsePolicySpec(manifestRecord.Spec)
		if err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		allowed, decision, matches, err := manifestengine.EvaluatePolicy(spec, req.Resource, req.Action, req.Input)
		if err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		return replySuccess(ctx, d, model.EvaluatePolicyResponse{
			Allowed:  allowed,
			Decision: decision,
			Manifest: model.ManifestReference{
				ID:        manifestRecord.ID,
				Kind:      manifestRecord.Kind,
				Namespace: manifestRecord.Metadata.Namespace,
				Name:      manifestRecord.Metadata.Name,
				Version:   manifestRecord.Version,
			},
			MatchedRules: matches,
		}, logger)
	}
}

func authorizationEvaluateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.EvaluateAuthorizationRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		rbacManifest, err := resolveManifestForKind(
			ctx,
			db,
			"rbac",
			req.RBAC.ManifestID,
			req.RBAC.Namespace,
			req.RBAC.Name,
			req.RBAC.Version,
		)
		if err != nil {
			return replyFailure(ctx, d, manifestLookupErrorCode(err), err, logger)
		}

		rbacSpec, err := manifestengine.ParseRBACSpec(rbacManifest.Spec)
		if err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		var (
			policyManifest model.Manifest
			policySpec     *model.PolicyManifestSpec
		)

		if manifestSelectorProvided(req.Policy) {
			policyManifest, err = resolveManifestForKind(
				ctx,
				db,
				"policy",
				req.Policy.ManifestID,
				req.Policy.Namespace,
				req.Policy.Name,
				req.Policy.Version,
			)
			if err != nil {
				return replyFailure(ctx, d, manifestLookupErrorCode(err), err, logger)
			}

			spec, err := manifestengine.ParsePolicySpec(policyManifest.Spec)
			if err != nil {
				return replyFailure(ctx, d, "bad_request", err, logger)
			}

			policySpec = &spec
		}

		subjects := []model.RBACSubject{}
		input := cloneAuthorizationInput(req.Input)
		var (
			collaboratorRef *model.CollaboratorReference
			teamRefs        []model.TeamReference
		)

		if collaboratorID := strings.TrimSpace(req.CollaboratorID); collaboratorID != "" {
			collaborator, teams, resolvedSubjects, err := repository.ResolveAuthorizationSubjects(ctx, db, collaboratorID)
			if err != nil {
				return replyFailure(ctx, d, identityErrorCode(err), err, logger)
			}

			subjects = append(subjects, resolvedSubjects...)
			collaboratorRef = &model.CollaboratorReference{
				ID:     collaborator.ID,
				Slug:   collaborator.Slug,
				Status: collaborator.Status,
			}
			teamRefs = teamReferencesFromTeams(teams)
			input = authorizationContextInput(input, collaborator, teams)
		}

		if subject := normalizeAuthorizationRequestSubject(req.Subject); subject.Type != "" && subject.ID != "" {
			subjects = append(subjects, subject)
		}

		response, err := manifestengine.EvaluateAuthorizationSubjects(
			rbacSpec,
			policySpec,
			subjects,
			req.Resource,
			req.Action,
			input,
		)
		if err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		response.Collaborator = collaboratorRef
		response.Teams = teamRefs
		response.RBAC.Manifest = manifestReferenceFromRecord(rbacManifest)
		if response.Policy != nil {
			response.Policy.Manifest = manifestReferenceFromRecord(policyManifest)
		}

		// Emit authorization.evaluated event (best-effort, post-decision).
		// The authorization evaluation is pure compute + DB reads; the event
		// records the decision for audit trail.
		emitAuthorizationEvaluatedEvent(ctx, db, logger, req, response, rbacManifest, policyManifest)

		return replySuccess(ctx, d, response, logger)
	}
}

// emitAuthorizationEvaluatedEvent records an authorization decision in the
// core event stream. Best-effort: failures are logged but do not affect the
// caller response.
func emitAuthorizationEvaluatedEvent(
	ctx context.Context,
	db *sql.DB,
	logger *zap.Logger,
	req model.EvaluateAuthorizationRequest,
	response model.EvaluateAuthorizationResponse,
	rbacManifest model.Manifest,
	policyManifest model.Manifest,
) {
	decision := string(response.Decision)
	if decision == "" {
		decision = "not_applicable"
	}

	payload := map[string]interface{}{
		"resource": req.Resource,
		"action":   req.Action,
		"decision": decision,
	}
	if collabID := strings.TrimSpace(req.CollaboratorID); collabID != "" {
		payload["collaborator_id"] = collabID
	}

	// Collect matched roles from RBAC results
	matchedRoles := append(make([]string, 0, len(response.RBAC.MatchedRoles)), response.RBAC.MatchedRoles...)
	if len(matchedRoles) > 0 {
		payload["matched_roles"] = matchedRoles
	}

	matchedRules := make([]string, 0)
	for _, rule := range response.RBAC.MatchedRules {
		label := rule.Role
		if rule.Effect != "" {
			label += "/" + rule.Effect
		}
		matchedRules = append(matchedRules, label)
	}
	if len(matchedRules) > 0 {
		payload["matched_rules"] = matchedRules
	}

	payload["rbac_manifest_ref"] = map[string]interface{}{
		"id":        rbacManifest.ID.String(),
		"name":      rbacManifest.Metadata.Name,
		"namespace": rbacManifest.Metadata.Namespace,
	}

	if policyManifest.ID != (uuid.UUID{}) {
		payload["policy_manifest_ref"] = map[string]interface{}{
			"id":        policyManifest.ID.String(),
			"name":      policyManifest.Metadata.Name,
			"namespace": policyManifest.Metadata.Namespace,
		}
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		if logger != nil {
			logger.Warn("emit authorization.evaluated: begin tx failed", zap.Error(err))
		}
		return
	}
	defer tx.Rollback()

	if _, err := repository.EmitEvent(ctx, tx, model.EmitEventRequest{
		Type:          "authorization.evaluated",
		SchemaVersion: "v1",
		AggregateType: "authorization",
		AggregateID:   req.Resource,
		Payload:       payload,
	}); err != nil {
		if logger != nil {
			logger.Warn("emit authorization.evaluated: emit failed", zap.Error(err))
		}
		return
	}

	if err := tx.Commit(); err != nil {
		if logger != nil {
			logger.Warn("emit authorization.evaluated: commit failed", zap.Error(err))
		}
	}
}

func resolveManifestForRBAC(ctx context.Context, db *sql.DB, req model.EvaluateRBACRequest) (model.Manifest, error) {
	return resolveManifestForKind(ctx, db, "rbac", req.ManifestID, req.Namespace, req.Name, req.Version)
}

func manifestSelectorProvided(selector *model.ManifestSelector) bool {
	if selector == nil {
		return false
	}

	return strings.TrimSpace(selector.ManifestID) != "" ||
		strings.TrimSpace(selector.Namespace) != "" ||
		strings.TrimSpace(selector.Name) != "" ||
		selector.Version != nil
}

func resolveManifestForKind(ctx context.Context, db *sql.DB, kind, manifestID, namespace, name string, version *int) (model.Manifest, error) {
	if manifestID := strings.TrimSpace(manifestID); manifestID != "" {
		parsedID, err := uuid.Parse(manifestID)
		if err != nil {
			return model.Manifest{}, errors.New("invalid manifest id")
		}
		return repository.GetManifestByID(ctx, db, parsedID)
	}

	name = strings.TrimSpace(name)
	if name == "" {
		return model.Manifest{}, errors.New("manifest name is required when manifest_id is not provided")
	}

	namespace = strings.TrimSpace(namespace)
	if namespace == "" {
		namespace = "global"
	}

	return repository.ResolveManifest(ctx, db, kind, namespace, name, version, true)
}

func manifestLookupErrorCode(err error) string {
	if errors.Is(err, repository.ErrManifestNotFound) {
		return "not_found"
	}
	if strings.Contains(err.Error(), "manifest") {
		return "bad_request"
	}
	return "internal_error"
}

func manifestReferenceFromRecord(manifestRecord model.Manifest) model.ManifestReference {
	return model.ManifestReference{
		ID:        manifestRecord.ID,
		Kind:      manifestRecord.Kind,
		Namespace: manifestRecord.Metadata.Namespace,
		Name:      manifestRecord.Metadata.Name,
		Version:   manifestRecord.Version,
	}
}

func normalizeAuthorizationRequestSubject(subject model.RBACSubject) model.RBACSubject {
	subject.Type = strings.ToLower(strings.TrimSpace(subject.Type))
	subject.ID = strings.TrimSpace(subject.ID)
	return subject
}

func cloneAuthorizationInput(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}

	normalized := make(map[string]any, len(input))
	for key, value := range input {
		normalized[key] = value
	}
	return normalized
}

func authorizationContextInput(input map[string]any, collaborator model.Collaborator, teams []model.Team) map[string]any {
	if input == nil {
		input = map[string]any{}
	}

	if _, exists := input["collaborator"]; !exists {
		input["collaborator"] = map[string]any{
			"id":                     collaborator.ID.String(),
			"slug":                   collaborator.Slug,
			"status":                 collaborator.Status,
			"display_name":           collaborator.DisplayName,
			"primary_email":          collaborator.PrimaryEmail,
			"personal_data":          collaborator.PersonalData,
			"employment_data":        collaborator.EmploymentData,
			"third_party_identities": collaborator.ThirdPartyIdentities,
			"traits":                 collaborator.Traits,
			"metadata":               collaborator.Metadata,
		}
	}

	if _, exists := input["teams"]; !exists {
		items := make([]map[string]any, 0, len(teams))
		for _, team := range teams {
			items = append(items, map[string]any{
				"id":       team.ID.String(),
				"slug":     team.Slug,
				"name":     team.Name,
				"type":     team.Type,
				"status":   team.Status,
				"owners":   team.Owners,
				"traits":   team.Traits,
				"metadata": team.Metadata,
			})
		}
		input["teams"] = items
	}

	return input
}

func teamReferencesFromTeams(teams []model.Team) []model.TeamReference {
	references := make([]model.TeamReference, 0, len(teams))
	for _, team := range teams {
		references = append(references, model.TeamReference{
			ID:   team.ID,
			Slug: team.Slug,
			Name: team.Name,
			Type: team.Type,
		})
	}
	return references
}

// replySuccess and replyFailure are the single points where handler
// results turn into an RPC reply to the caller. Transport-agnostic:
// d.Reply dispatches through whichever rpc.Transport delivered the
// message (AMQP, HTTP, gRPC, Kafka, …).
func replySuccess(ctx context.Context, d rpc.Delivery, data any, logger *zap.Logger) error {
	return replyJSON(ctx, d, rpcResponse{
		OK:   true,
		Data: data,
	}, logger)
}

func replyFailure(ctx context.Context, d rpc.Delivery, code string, err error, logger *zap.Logger) error {
	if logger != nil {
		logger.Error("rpc handler failed",
			zap.String("endpoint", d.Endpoint),
			zap.String("reply_to", d.ReplyTo),
			zap.String("correlation_id", d.CorrelationID),
			zap.String("error_code", code),
			zap.Error(err),
		)
	}

	return replyJSON(ctx, d, rpcResponse{
		OK: false,
		Error: &rpcError{
			Code:    code,
			Message: err.Error(),
		},
	}, logger)
}

func replyJSON(ctx context.Context, d rpc.Delivery, response rpcResponse, logger *zap.Logger) error {
	if strings.TrimSpace(d.ReplyTo) == "" {
		return errors.New("reply_to is required for yggdrasil-core rpc consumers")
	}

	body, err := json.Marshal(response)
	if err != nil {
		return err
	}

	if err := d.Reply(ctx, body, "application/json"); err != nil {
		return err
	}

	if logger != nil {
		logger.Debug("rpc reply sent",
			zap.String("endpoint", d.Endpoint),
			zap.String("reply_to", d.ReplyTo),
			zap.String("correlation_id", d.CorrelationID),
		)
	}

	return nil
}

func bytesTrimSpace(data []byte) []byte {
	return []byte(strings.TrimSpace(string(data)))
}
