package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	manifestengine "github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var (
	ErrTopologyNodeNotFound               = errors.New("topology node not found")
	ErrTopologyDocumentNotFound           = errors.New("topology document not found")
	ErrTopologyAuthorizationNotConfigured = errors.New("topology authorization not configured")
	ErrBuildProjectNotFound               = errors.New("build project not found")
)

func UpsertTopologyNode(ctx context.Context, db *sql.DB, req model.UpsertTopologyNodeRequest) (model.TopologyNode, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return model.TopologyNode{}, fmt.Errorf("topology node name is required")
	}

	kind := normalizeTopologyType(req.Kind)
	if kind == "" {
		return model.TopologyNode{}, fmt.Errorf("topology node kind is required")
	}

	nodeID, err := resolveOrGenerateTopologyUUID(req.ID)
	if err != nil {
		return model.TopologyNode{}, err
	}

	parentID, err := resolveOptionalTopologyUUID(req.ParentID)
	if err != nil {
		return model.TopologyNode{}, fmt.Errorf("parent_id: %w", err)
	}

	slug := normalizeTopologySlug(req.Slug)
	if slug == "" {
		slug = normalizeTopologySlug(name)
	}
	if slug == "" {
		return model.TopologyNode{}, fmt.Errorf("topology node slug is required")
	}

	status := normalizeTopologyStatus(req.Status)
	metadata, err := marshalJSONObject(req.Metadata)
	if err != nil {
		return model.TopologyNode{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.topology_nodes (
				id,
				slug,
				kind,
				name,
				description,
				status,
				parent_id,
				metadata
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5,
				$6,
				$7,
				$8::jsonb
			)
			ON CONFLICT (id) DO UPDATE SET
				slug = EXCLUDED.slug,
				kind = EXCLUDED.kind,
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				status = EXCLUDED.status,
				parent_id = EXCLUDED.parent_id,
				metadata = EXCLUDED.metadata
			RETURNING
				id,
				slug,
				kind,
				name,
				description,
				status,
				parent_id,
				metadata,
				created_at,
				updated_at
		`,
		nodeID,
		slug,
		kind,
		name,
		strings.TrimSpace(req.Description),
		status,
		parentID,
		metadata,
	)

	return scanTopologyNode(row)
}

func GetTopologyNode(ctx context.Context, db *sql.DB, identity string) (model.TopologyNode, error) {
	nodeID, err := parseTopologyUUID(identity)
	if err != nil {
		return model.TopologyNode{}, err
	}

	node, err := scanTopologyNode(db.QueryRowContext(
		ctx,
		`
			SELECT
				id,
				slug,
				kind,
				name,
				description,
				status,
				parent_id,
				metadata,
				created_at,
				updated_at
			FROM public.topology_nodes
			WHERE id = $1
		`,
		nodeID,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.TopologyNode{}, ErrTopologyNodeNotFound
		}
		return model.TopologyNode{}, err
	}

	return node, nil
}

func ListTopologyNodeChildren(ctx context.Context, db *sql.DB, parentIdentity string) ([]model.TopologyNode, error) {
	parentID, err := parseTopologyUUID(parentIdentity)
	if err != nil {
		return nil, err
	}

	rows, err := db.QueryContext(
		ctx,
		`
			SELECT
				id,
				slug,
				kind,
				name,
				description,
				status,
				parent_id,
				metadata,
				created_at,
				updated_at
			FROM public.topology_nodes
			WHERE parent_id = $1
			ORDER BY kind ASC, name ASC, created_at ASC
		`,
		parentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nodes := make([]model.TopologyNode, 0)
	for rows.Next() {
		node, err := scanTopologyNode(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nodes, nil
}

func UpsertTopologyEdge(ctx context.Context, db *sql.DB, req model.UpsertTopologyEdgeRequest) (model.TopologyEdge, error) {
	sourceID, err := parseTopologyUUID(req.SourceID)
	if err != nil {
		return model.TopologyEdge{}, fmt.Errorf("source_id: %w", err)
	}

	targetID, err := parseTopologyUUID(req.TargetID)
	if err != nil {
		return model.TopologyEdge{}, fmt.Errorf("target_id: %w", err)
	}

	relation := normalizeTopologyType(req.Relation)
	if relation == "" {
		return model.TopologyEdge{}, fmt.Errorf("topology edge relation is required")
	}

	status := normalizeTopologyStatus(req.Status)
	metadata, err := marshalJSONObject(req.Metadata)
	if err != nil {
		return model.TopologyEdge{}, err
	}

	if strings.TrimSpace(req.ID) != "" {
		edgeID, err := parseTopologyUUID(req.ID)
		if err != nil {
			return model.TopologyEdge{}, err
		}

		row := db.QueryRowContext(
			ctx,
			`
				INSERT INTO public.topology_edges (
					id,
					source_id,
					relation,
					target_id,
					status,
					metadata
				) VALUES (
					$1,
					$2,
					$3,
					$4,
					$5,
					$6::jsonb
				)
				ON CONFLICT (id) DO UPDATE SET
					source_id = EXCLUDED.source_id,
					relation = EXCLUDED.relation,
					target_id = EXCLUDED.target_id,
					status = EXCLUDED.status,
					metadata = EXCLUDED.metadata
				RETURNING
					id,
					source_id,
					relation,
					target_id,
					status,
					metadata,
					created_at,
					updated_at
			`,
			edgeID,
			sourceID,
			relation,
			targetID,
			status,
			metadata,
		)

		return scanTopologyEdge(row)
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.topology_edges (
				source_id,
				relation,
				target_id,
				status,
				metadata
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5::jsonb
			)
			ON CONFLICT (source_id, relation, target_id) DO UPDATE SET
				status = EXCLUDED.status,
				metadata = EXCLUDED.metadata
			RETURNING
				id,
				source_id,
				relation,
				target_id,
				status,
				metadata,
				created_at,
				updated_at
		`,
		sourceID,
		relation,
		targetID,
		status,
		metadata,
	)

	return scanTopologyEdge(row)
}

func ListTopologyEdges(ctx context.Context, db *sql.DB, req model.ListTopologyEdgesRequest) ([]model.TopologyEdge, error) {
	query := `
		SELECT
			id,
			source_id,
			relation,
			target_id,
			status,
			metadata,
			created_at,
			updated_at
		FROM public.topology_edges
	`

	args := make([]any, 0, 3)
	clauses := make([]string, 0, 3)

	if strings.TrimSpace(req.SourceID) != "" {
		sourceID, err := parseTopologyUUID(req.SourceID)
		if err != nil {
			return nil, fmt.Errorf("source_id: %w", err)
		}
		args = append(args, sourceID)
		clauses = append(clauses, fmt.Sprintf("source_id = $%d", len(args)))
	}

	if relation := normalizeTopologyType(req.Relation); relation != "" {
		args = append(args, relation)
		clauses = append(clauses, fmt.Sprintf("relation = $%d", len(args)))
	}

	if strings.TrimSpace(req.TargetID) != "" {
		targetID, err := parseTopologyUUID(req.TargetID)
		if err != nil {
			return nil, fmt.Errorf("target_id: %w", err)
		}
		args = append(args, targetID)
		clauses = append(clauses, fmt.Sprintf("target_id = $%d", len(args)))
	}

	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY relation ASC, created_at ASC"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	edges := make([]model.TopologyEdge, 0)
	for rows.Next() {
		edge, err := scanTopologyEdge(rows)
		if err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return edges, nil
}

func UpsertTopologyDocument(ctx context.Context, db *sql.DB, req model.UpsertTopologyDocumentRequest) (model.TopologyDocument, error) {
	nodeID, err := parseTopologyUUID(req.NodeID)
	if err != nil {
		return model.TopologyDocument{}, fmt.Errorf("node_id: %w", err)
	}

	documentID, err := resolveOrGenerateTopologyUUID(req.ID)
	if err != nil {
		return model.TopologyDocument{}, err
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		return model.TopologyDocument{}, fmt.Errorf("topology document name is required")
	}

	kind := normalizeTopologyType(req.Kind)
	if kind == "" {
		return model.TopologyDocument{}, fmt.Errorf("topology document kind is required")
	}

	body := req.Body
	if len(bytes.TrimSpace(body)) == 0 {
		body = json.RawMessage(`{}`)
	}

	metadata, err := marshalJSONObject(req.Metadata)
	if err != nil {
		return model.TopologyDocument{}, err
	}

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.topology_documents (
				id,
				node_id,
				name,
				kind,
				description,
				body,
				metadata
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5,
				$6::jsonb,
				$7::jsonb
			)
			ON CONFLICT (id) DO UPDATE SET
				node_id = EXCLUDED.node_id,
				name = EXCLUDED.name,
				kind = EXCLUDED.kind,
				description = EXCLUDED.description,
				body = EXCLUDED.body,
				metadata = EXCLUDED.metadata
			RETURNING
				id,
				node_id,
				name,
				kind,
				description,
				body,
				metadata,
				created_at,
				updated_at
		`,
		documentID,
		nodeID,
		name,
		kind,
		strings.TrimSpace(req.Description),
		[]byte(body),
		metadata,
	)

	return scanTopologyDocument(row)
}

func GetTopologyDocument(ctx context.Context, db *sql.DB, req model.GetTopologyDocumentRequest) (model.TopologyDocument, error) {
	if strings.TrimSpace(req.ID) != "" {
		documentID, err := parseTopologyUUID(req.ID)
		if err != nil {
			return model.TopologyDocument{}, err
		}

		document, err := scanTopologyDocument(db.QueryRowContext(
			ctx,
			`
				SELECT
					id,
					node_id,
					name,
					kind,
					description,
					body,
					metadata,
					created_at,
					updated_at
				FROM public.topology_documents
				WHERE id = $1
			`,
			documentID,
		))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return model.TopologyDocument{}, ErrTopologyDocumentNotFound
			}
			return model.TopologyDocument{}, err
		}
		return document, nil
	}

	nodeID, err := parseTopologyUUID(req.NodeID)
	if err != nil {
		return model.TopologyDocument{}, fmt.Errorf("node_id: %w", err)
	}

	kind := normalizeTopologyType(req.Kind)
	if kind == "" {
		return model.TopologyDocument{}, fmt.Errorf("topology document kind is required")
	}

	document, err := scanTopologyDocument(db.QueryRowContext(
		ctx,
		`
			SELECT
				id,
				node_id,
				name,
				kind,
				description,
				body,
				metadata,
				created_at,
				updated_at
			FROM public.topology_documents
			WHERE node_id = $1 AND kind = $2
			ORDER BY created_at ASC
			LIMIT 1
		`,
		nodeID,
		kind,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.TopologyDocument{}, ErrTopologyDocumentNotFound
		}
		return model.TopologyDocument{}, err
	}

	return document, nil
}

func ListTopologyDocuments(ctx context.Context, db *sql.DB, req model.ListTopologyDocumentsRequest) ([]model.TopologyDocument, error) {
	query := `
		SELECT
			id,
			node_id,
			name,
			kind,
			description,
			body,
			metadata,
			created_at,
			updated_at
		FROM public.topology_documents
	`

	args := make([]any, 0, 2)
	clauses := make([]string, 0, 2)
	if strings.TrimSpace(req.NodeID) != "" {
		nodeID, err := parseTopologyUUID(req.NodeID)
		if err != nil {
			return nil, fmt.Errorf("node_id: %w", err)
		}
		args = append(args, nodeID)
		clauses = append(clauses, fmt.Sprintf("node_id = $%d", len(args)))
	}

	if kind := normalizeTopologyType(req.Kind); kind != "" {
		args = append(args, kind)
		clauses = append(clauses, fmt.Sprintf("kind = $%d", len(args)))
	}

	if len(clauses) > 0 {
		query += " WHERE " + strings.Join(clauses, " AND ")
	}
	query += " ORDER BY created_at ASC, name ASC"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	documents := make([]model.TopologyDocument, 0)
	for rows.Next() {
		document, err := scanTopologyDocument(rows)
		if err != nil {
			return nil, err
		}
		documents = append(documents, document)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return documents, nil
}

func GetTopologyDocumentValue(ctx context.Context, db *sql.DB, req model.GetTopologyDocumentValueRequest) ([]byte, error) {
	document, err := GetTopologyDocument(ctx, db, model.GetTopologyDocumentRequest{
		ID:     req.ID,
		NodeID: req.NodeID,
		Kind:   req.Kind,
	})
	if err != nil {
		return nil, err
	}

	if len(req.Path) == 0 {
		return []byte(document.Body), nil
	}

	var decoded any
	if err := json.Unmarshal(document.Body, &decoded); err != nil {
		return nil, err
	}

	value, ok := lookupTopologyJSONValue(decoded, req.Path)
	if !ok || value == nil {
		return nil, nil
	}

	return encodeTopologyValue(value)
}

func EvaluateTopologyAccess(ctx context.Context, db *sql.DB, req model.EvaluateTopologyAccessRequest) (model.EvaluateTopologyAccessResponse, error) {
	provider := normalizeTopologyType(req.Provider)
	if provider == "" {
		provider = "github"
	}
	if provider != "github" {
		return model.EvaluateTopologyAccessResponse{}, fmt.Errorf("unsupported access provider %q", req.Provider)
	}

	node, err := GetTopologyNode(ctx, db, req.NodeID)
	if err != nil {
		return model.EvaluateTopologyAccessResponse{}, err
	}

	scope, authorizationNodeID, err := resolveTopologyAuthorizationScope(ctx, db, node)
	if err != nil {
		if errors.Is(err, ErrTopologyAuthorizationNotConfigured) {
			return model.EvaluateTopologyAccessResponse{
				Allowed:   false,
				Authority: 0,
				Reason:    "authorization_not_configured",
			}, nil
		}
		return model.EvaluateTopologyAccessResponse{}, err
	}

	collaborator, teams, subjects, err := resolveTopologyAccessSubjects(ctx, db, provider, req.Login)
	if err != nil {
		if errors.Is(err, ErrCollaboratorNotFound) {
			return model.EvaluateTopologyAccessResponse{
				Allowed:   false,
				Authority: 0,
				Reason:    "identity_not_found",
			}, nil
		}
		return model.EvaluateTopologyAccessResponse{}, err
	}

	resource := topologyAuthorizationResource(scope, node.ID)
	input := topologyAuthorizationInput(scope.Input, node, authorizationNodeID, provider, req.Login, collaborator, teams)

	authority, err := evaluateTopologyAuthorization(ctx, db, scope, subjects, resource, input)
	if err != nil {
		if errors.Is(err, ErrTopologyAuthorizationNotConfigured) {
			return model.EvaluateTopologyAccessResponse{
				Allowed:             false,
				Authority:           0,
				CollaboratorID:      &collaborator.ID,
				AuthorizationNodeID: &authorizationNodeID,
				Resource:            resource,
				Reason:              "authorization_not_configured",
			}, nil
		}
		return model.EvaluateTopologyAccessResponse{}, err
	}

	if authority < 0 {
		return model.EvaluateTopologyAccessResponse{
			Allowed:             false,
			Authority:           0,
			CollaboratorID:      &collaborator.ID,
			AuthorizationNodeID: &authorizationNodeID,
			Resource:            resource,
			Reason:              "insufficient_permissions",
		}, nil
	}

	return model.EvaluateTopologyAccessResponse{
		Allowed:             true,
		Authority:           authority,
		CollaboratorID:      &collaborator.ID,
		AuthorizationNodeID: &authorizationNodeID,
		Resource:            resource,
		Reason:              "authorized",
	}, nil
}

func CreateBuildProject(ctx context.Context, db *sql.DB, req model.CreateBuildProjectRequest) (model.BuildProject, error) {
	projectNodeID, err := parseTopologyUUID(req.ProjectNodeID)
	if err != nil {
		return model.BuildProject{}, fmt.Errorf("project_node_id: %w", err)
	}

	build := req.Build
	if strings.TrimSpace(build.BuildName) == "" {
		return model.BuildProject{}, fmt.Errorf("build.build-name is required")
	}
	if strings.TrimSpace(build.EnvType) == "" {
		return model.BuildProject{}, fmt.Errorf("build.env-type is required")
	}
	if strings.TrimSpace(build.Cloud) == "" {
		return model.BuildProject{}, fmt.Errorf("build.cloud is required")
	}
	if build.ProjectEnvResourceID == uuid.Nil {
		return model.BuildProject{}, fmt.Errorf("build.project-env-resource-id is required")
	}

	infraMap, err := GetTopologyDocument(ctx, db, model.GetTopologyDocumentRequest{
		NodeID: projectNodeID.String(),
		Kind:   "infra-map",
	})
	if err != nil {
		if errors.Is(err, ErrTopologyDocumentNotFound) {
			return model.BuildProject{}, fmt.Errorf("project infra-map document not found: %w", err)
		}
		return model.BuildProject{}, err
	}

	if _, err := GetTopologyDocument(ctx, db, model.GetTopologyDocumentRequest{ID: build.ProjectEnvResourceID.String()}); err != nil {
		if errors.Is(err, ErrTopologyDocumentNotFound) {
			return model.BuildProject{}, fmt.Errorf("project env resource document not found: %w", err)
		}
		return model.BuildProject{}, err
	}

	if build.ID == uuid.Nil {
		build.ID = uuid.New()
	}
	build.InfraMapID = infraMap.ID

	row := db.QueryRowContext(
		ctx,
		`
			INSERT INTO public.topology_build_projects (
				id,
				project_node_id,
				infra_map_document_id,
				project_env_resource_id,
				build_name,
				env_type,
				cloud,
				ephemeral,
				expires_at,
				cluster_name,
				cluster_zone,
				immutable
			) VALUES (
				$1,
				$2,
				$3,
				$4,
				$5,
				$6,
				$7,
				$8,
				$9,
				$10,
				$11,
				$12
			)
			ON CONFLICT (id) DO UPDATE SET
				project_node_id = EXCLUDED.project_node_id,
				infra_map_document_id = EXCLUDED.infra_map_document_id,
				project_env_resource_id = EXCLUDED.project_env_resource_id,
				build_name = EXCLUDED.build_name,
				env_type = EXCLUDED.env_type,
				cloud = EXCLUDED.cloud,
				ephemeral = EXCLUDED.ephemeral,
				expires_at = EXCLUDED.expires_at,
				cluster_name = EXCLUDED.cluster_name,
				cluster_zone = EXCLUDED.cluster_zone,
				immutable = EXCLUDED.immutable
			RETURNING
				id,
				infra_map_document_id,
				project_env_resource_id,
				build_name,
				env_type,
				cloud,
				ephemeral,
				expires_at,
				cluster_name,
				cluster_zone,
				immutable
		`,
		build.ID,
		projectNodeID,
		build.InfraMapID,
		build.ProjectEnvResourceID,
		build.BuildName,
		build.EnvType,
		build.Cloud,
		build.Ephemeral,
		strings.TrimSpace(build.ExpiresAt),
		strings.TrimSpace(build.ClusterName),
		strings.TrimSpace(build.ClusterZone),
		build.Immutable,
	)

	return scanBuildProject(row)
}

func GetBuildProject(ctx context.Context, db *sql.DB, identity string) (model.BuildProject, error) {
	buildProjectID, err := parseTopologyUUID(identity)
	if err != nil {
		return model.BuildProject{}, err
	}

	build, err := scanBuildProject(db.QueryRowContext(
		ctx,
		`
			SELECT
				id,
				infra_map_document_id,
				project_env_resource_id,
				build_name,
				env_type,
				cloud,
				ephemeral,
				expires_at,
				cluster_name,
				cluster_zone,
				immutable
			FROM public.topology_build_projects
			WHERE id = $1
		`,
		buildProjectID,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.BuildProject{}, ErrBuildProjectNotFound
		}
		return model.BuildProject{}, err
	}

	return build, nil
}

func ListBuildProjects(ctx context.Context, db *sql.DB, req model.ListBuildProjectsRequest) ([]model.BuildProject, error) {
	projectNodeID, err := parseTopologyUUID(req.ProjectNodeID)
	if err != nil {
		return nil, fmt.Errorf("project_node_id: %w", err)
	}

	query := `
		SELECT
			id,
			infra_map_document_id,
			project_env_resource_id,
			build_name,
			env_type,
			cloud,
			ephemeral,
			expires_at,
			cluster_name,
			cluster_zone,
			immutable
		FROM public.topology_build_projects
		WHERE project_node_id = $1
	`

	args := []any{projectNodeID}
	if req.MutableOnly {
		query += " AND immutable = FALSE"
	}
	query += " ORDER BY build_name ASC, id ASC"

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	builds := make([]model.BuildProject, 0)
	for rows.Next() {
		build, err := scanBuildProject(rows)
		if err != nil {
			return nil, err
		}
		builds = append(builds, build)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return builds, nil
}

func DeleteBuildProject(ctx context.Context, db *sql.DB, identity string) (model.BuildProject, error) {
	build, err := GetBuildProject(ctx, db, identity)
	if err != nil {
		return model.BuildProject{}, err
	}

	result, err := db.ExecContext(ctx, `DELETE FROM public.topology_build_projects WHERE id = $1`, build.ID)
	if err != nil {
		return model.BuildProject{}, err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return model.BuildProject{}, err
	}
	if rows == 0 {
		return model.BuildProject{}, ErrBuildProjectNotFound
	}

	return build, nil
}

func scanTopologyNode(row scanner) (model.TopologyNode, error) {
	var (
		node     model.TopologyNode
		parentID sql.NullString
		metadata []byte
		err      error
	)

	err = row.Scan(
		&node.ID,
		&node.Slug,
		&node.Kind,
		&node.Name,
		&node.Description,
		&node.Status,
		&parentID,
		&metadata,
		&node.CreatedAt,
		&node.UpdatedAt,
	)
	if err != nil {
		return model.TopologyNode{}, err
	}

	node.ParentID, err = parseNullableUUID(parentID)
	if err != nil {
		return model.TopologyNode{}, err
	}
	if node.Metadata, err = unmarshalJSONObject(metadata); err != nil {
		return model.TopologyNode{}, err
	}

	return node, nil
}

func scanTopologyEdge(row scanner) (model.TopologyEdge, error) {
	var (
		edge     model.TopologyEdge
		metadata []byte
		err      error
	)

	err = row.Scan(
		&edge.ID,
		&edge.SourceID,
		&edge.Relation,
		&edge.TargetID,
		&edge.Status,
		&metadata,
		&edge.CreatedAt,
		&edge.UpdatedAt,
	)
	if err != nil {
		return model.TopologyEdge{}, err
	}

	if edge.Metadata, err = unmarshalJSONObject(metadata); err != nil {
		return model.TopologyEdge{}, err
	}

	return edge, nil
}

func scanTopologyDocument(row scanner) (model.TopologyDocument, error) {
	var (
		document model.TopologyDocument
		metadata []byte
		err      error
	)

	err = row.Scan(
		&document.ID,
		&document.NodeID,
		&document.Name,
		&document.Kind,
		&document.Description,
		&document.Body,
		&metadata,
		&document.CreatedAt,
		&document.UpdatedAt,
	)
	if err != nil {
		return model.TopologyDocument{}, err
	}

	if document.Metadata, err = unmarshalJSONObject(metadata); err != nil {
		return model.TopologyDocument{}, err
	}

	return document, nil
}

func scanBuildProject(row scanner) (model.BuildProject, error) {
	var build model.BuildProject
	err := row.Scan(
		&build.ID,
		&build.InfraMapID,
		&build.ProjectEnvResourceID,
		&build.BuildName,
		&build.EnvType,
		&build.Cloud,
		&build.Ephemeral,
		&build.ExpiresAt,
		&build.ClusterName,
		&build.ClusterZone,
		&build.Immutable,
	)
	if err != nil {
		return model.BuildProject{}, err
	}
	return build, nil
}

func normalizeTopologyType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeTopologyStatus(value string) string {
	value = normalizeTopologyType(value)
	if value == "" {
		return "active"
	}
	return value
}

var topologySlugPattern = regexp.MustCompile(`[^a-z0-9]+`)

func normalizeTopologySlug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = topologySlugPattern.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	return value
}

func resolveTopologyAuthorizationScope(ctx context.Context, db *sql.DB, node model.TopologyNode) (model.TopologyAuthorizationScope, uuid.UUID, error) {
	current := node

	for {
		document, err := GetTopologyDocument(ctx, db, model.GetTopologyDocumentRequest{
			NodeID: current.ID.String(),
			Kind:   "authorization",
		})
		if err == nil {
			var scope model.TopologyAuthorizationScope
			if err := json.Unmarshal(document.Body, &scope); err != nil {
				return model.TopologyAuthorizationScope{}, uuid.Nil, err
			}
			if !manifestSelectorConfigured(scope.RBAC) {
				return model.TopologyAuthorizationScope{}, uuid.Nil, ErrTopologyAuthorizationNotConfigured
			}

			scope.Resource = strings.TrimSpace(scope.Resource)
			if scope.Input == nil {
				scope.Input = map[string]any{}
			}

			return scope, current.ID, nil
		}
		if !errors.Is(err, ErrTopologyDocumentNotFound) {
			return model.TopologyAuthorizationScope{}, uuid.Nil, err
		}
		if current.ParentID == nil || *current.ParentID == uuid.Nil {
			return model.TopologyAuthorizationScope{}, uuid.Nil, ErrTopologyAuthorizationNotConfigured
		}

		parent, err := GetTopologyNode(ctx, db, current.ParentID.String())
		if err != nil {
			return model.TopologyAuthorizationScope{}, uuid.Nil, err
		}
		current = parent
	}
}

func resolveTopologyAccessSubjects(ctx context.Context, db *sql.DB, provider, login string) (model.Collaborator, []model.Team, []model.RBACSubject, error) {
	switch provider {
	case "github":
		collaborator, err := GetCollaboratorByThirdPartyLogin(ctx, db, provider, login)
		if err != nil {
			return model.Collaborator{}, nil, nil, err
		}
		return ResolveAuthorizationSubjects(ctx, db, collaborator.ID.String())
	default:
		return model.Collaborator{}, nil, nil, fmt.Errorf("unsupported access provider %q", provider)
	}
}

func evaluateTopologyAuthorization(
	ctx context.Context,
	db *sql.DB,
	scope model.TopologyAuthorizationScope,
	subjects []model.RBACSubject,
	resource string,
	input map[string]any,
) (int, error) {
	rbacManifest, err := resolveTopologyManifestSelector(ctx, db, "rbac", scope.RBAC)
	if err != nil {
		if errors.Is(err, ErrManifestNotFound) {
			return -1, ErrTopologyAuthorizationNotConfigured
		}
		return -1, err
	}

	rbacSpec, err := manifestengine.ParseRBACSpec(rbacManifest.Spec)
	if err != nil {
		return -1, err
	}

	var policySpec *model.PolicyManifestSpec
	if scope.Policy != nil && manifestSelectorConfigured(*scope.Policy) {
		policyManifest, err := resolveTopologyManifestSelector(ctx, db, "policy", *scope.Policy)
		if err != nil {
			if errors.Is(err, ErrManifestNotFound) {
				return -1, ErrTopologyAuthorizationNotConfigured
			}
			return -1, err
		}

		spec, err := manifestengine.ParsePolicySpec(policyManifest.Spec)
		if err != nil {
			return -1, err
		}
		policySpec = &spec
	}

	for _, candidate := range []struct {
		Action    string
		Authority int
	}{
		{Action: "manage", Authority: 2},
		{Action: "write", Authority: 1},
		{Action: "read", Authority: 0},
	} {
		response, err := manifestengine.EvaluateAuthorizationSubjects(
			rbacSpec,
			policySpec,
			subjects,
			resource,
			candidate.Action,
			topologyCloneInput(input),
		)
		if err != nil {
			return -1, err
		}
		if response.Allowed {
			return candidate.Authority, nil
		}
	}

	return -1, nil
}

func resolveTopologyManifestSelector(ctx context.Context, db *sql.DB, kind string, selector model.ManifestSelector) (model.Manifest, error) {
	if manifestID := strings.TrimSpace(selector.ManifestID); manifestID != "" {
		parsedID, err := uuid.Parse(manifestID)
		if err != nil {
			return model.Manifest{}, fmt.Errorf("invalid manifest id")
		}
		return GetManifestByID(ctx, db, parsedID)
	}

	name := strings.TrimSpace(selector.Name)
	if name == "" {
		return model.Manifest{}, ErrTopologyAuthorizationNotConfigured
	}

	namespace := strings.TrimSpace(selector.Namespace)
	if namespace == "" {
		namespace = "global"
	}

	return ResolveManifest(ctx, db, kind, namespace, name, selector.Version, true)
}

func manifestSelectorConfigured(selector model.ManifestSelector) bool {
	return strings.TrimSpace(selector.ManifestID) != "" ||
		strings.TrimSpace(selector.Name) != ""
}

func topologyAuthorizationResource(scope model.TopologyAuthorizationScope, nodeID uuid.UUID) string {
	if resource := strings.TrimSpace(scope.Resource); resource != "" {
		return resource
	}

	return fmt.Sprintf("core.topology.node.%s", nodeID.String())
}

func topologyAuthorizationInput(
	base map[string]any,
	node model.TopologyNode,
	authorizationNodeID uuid.UUID,
	provider string,
	login string,
	collaborator model.Collaborator,
	teams []model.Team,
) map[string]any {
	input := topologyCloneInput(base)
	if input == nil {
		input = map[string]any{}
	}

	if _, exists := input["authn"]; !exists {
		input["authn"] = map[string]any{
			"provider": provider,
			"login":    strings.TrimSpace(login),
		}
	}

	if _, exists := input["topology"]; !exists {
		payload := map[string]any{
			"id":          node.ID.String(),
			"slug":        node.Slug,
			"kind":        node.Kind,
			"name":        node.Name,
			"description": node.Description,
			"status":      node.Status,
			"metadata":    node.Metadata,
		}
		if node.ParentID != nil && *node.ParentID != uuid.Nil {
			payload["parent_id"] = node.ParentID.String()
		}

		input["topology"] = map[string]any{
			"node":                  payload,
			"authorization_node_id": authorizationNodeID.String(),
			"full_node":             payload,
		}
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
			payload := map[string]any{
				"id":       team.ID.String(),
				"slug":     team.Slug,
				"name":     team.Name,
				"type":     team.Type,
				"status":   team.Status,
				"owners":   team.Owners,
				"traits":   team.Traits,
				"metadata": team.Metadata,
			}
			if team.ParentTeamID != nil && *team.ParentTeamID != uuid.Nil {
				payload["parent_team_id"] = team.ParentTeamID.String()
			}
			items = append(items, payload)
		}
		input["teams"] = items
	}

	return input
}

func topologyCloneInput(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}

	cloned := make(map[string]any, len(input))
	for key, value := range input {
		cloned[key] = value
	}
	return cloned
}

func resolveOrGenerateTopologyUUID(value string) (uuid.UUID, error) {
	if strings.TrimSpace(value) == "" {
		return uuid.New(), nil
	}
	return parseTopologyUUID(value)
}

func resolveOptionalTopologyUUID(value string) (any, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	parsed, err := parseTopologyUUID(value)
	if err != nil {
		return nil, err
	}
	return parsed, nil
}

func parseTopologyUUID(value string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil || parsed == uuid.Nil {
		return uuid.Nil, fmt.Errorf("invalid uuid %q", value)
	}
	return parsed, nil
}

func lookupTopologyJSONValue(value any, path []string) (any, bool) {
	current := value
	for _, segment := range path {
		switch typed := current.(type) {
		case map[string]any:
			next, ok := typed[segment]
			if !ok {
				return nil, false
			}
			current = next
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, false
			}
			current = typed[index]
		default:
			return nil, false
		}
	}

	return current, true
}

func encodeTopologyValue(value any) ([]byte, error) {
	switch typed := value.(type) {
	case nil:
		return nil, nil
	case string:
		return []byte(typed), nil
	case bool:
		if typed {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case json.Number:
		return []byte(typed.String()), nil
	case float32, float64, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return []byte(fmt.Sprint(typed)), nil
	default:
		return json.Marshal(value)
	}
}
