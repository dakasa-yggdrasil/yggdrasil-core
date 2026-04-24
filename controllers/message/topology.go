package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/rpc"
)

const (
	queueTopologyNodeUpsert     = "yggdrasil-core.topology.node.upsert"
	queueTopologyNodeGet        = "yggdrasil-core.topology.node.get"
	queueTopologyNodeChildren   = "yggdrasil-core.topology.node.children"
	queueTopologyEdgeUpsert     = "yggdrasil-core.topology.edge.upsert"
	queueTopologyEdgeList       = "yggdrasil-core.topology.edge.list"
	queueTopologyDocumentUpsert = "yggdrasil-core.topology.document.upsert"
	queueTopologyDocumentGet    = "yggdrasil-core.topology.document.get"
	queueTopologyDocumentList   = "yggdrasil-core.topology.document.list"
	queueTopologyDocumentValue  = "yggdrasil-core.topology.document.value"
	queueTopologyAccessEvaluate = "yggdrasil-core.topology.access.evaluate"
	queueBuildProjectCreate     = "yggdrasil-core.topology.build_project.create"
	queueBuildProjectGet        = "yggdrasil-core.topology.build_project.get"
	queueBuildProjectList       = "yggdrasil-core.topology.build_project.list"
	queueBuildProjectDelete     = "yggdrasil-core.topology.build_project.delete"
)

func topologyConsumers(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) []ConsumerConfig {
	return []ConsumerConfig{
		{
			Queue:   queueTopologyNodeUpsert,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: topologyNodeUpsertHandler(conn, db, logger),
		},
		{
			Queue:   queueTopologyNodeGet,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: topologyNodeGetHandler(conn, db, logger),
		},
		{
			Queue:   queueTopologyNodeChildren,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: topologyNodeChildrenHandler(conn, db, logger),
		},
		{
			Queue:   queueTopologyEdgeUpsert,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: topologyEdgeUpsertHandler(conn, db, logger),
		},
		{
			Queue:   queueTopologyEdgeList,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: topologyEdgeListHandler(conn, db, logger),
		},
		{
			Queue:   queueTopologyDocumentUpsert,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: topologyDocumentUpsertHandler(conn, db, logger),
		},
		{
			Queue:   queueTopologyDocumentGet,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: topologyDocumentGetHandler(conn, db, logger),
		},
		{
			Queue:   queueTopologyDocumentList,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: topologyDocumentListHandler(conn, db, logger),
		},
		{
			Queue:   queueTopologyDocumentValue,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: topologyDocumentValueHandler(conn, db, logger),
		},
		{
			Queue:   queueTopologyAccessEvaluate,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: topologyAccessEvaluateHandler(conn, db, logger),
		},
		{
			Queue:   queueBuildProjectCreate,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: buildProjectCreateHandler(conn, db, logger),
		},
		{
			Queue:   queueBuildProjectGet,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: buildProjectGetHandler(conn, db, logger),
		},
		{
			Queue:   queueBuildProjectList,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: buildProjectListHandler(conn, db, logger),
		},
		{
			Queue:   queueBuildProjectDelete,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: buildProjectDeleteHandler(conn, db, logger),
		},
	}
}

func topologyNodeUpsertHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.UpsertTopologyNodeRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		node, err := repository.UpsertTopologyNode(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"node": node}, logger)
	}
}

func topologyNodeGetHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.GetTopologyNodeRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		node, err := repository.GetTopologyNode(ctx, db, req.ID)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"node": node}, logger)
	}
}

func topologyNodeChildrenHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.ListTopologyNodeChildrenRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		nodes, err := repository.ListTopologyNodeChildren(ctx, db, req.ParentID)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"nodes": nodes}, logger)
	}
}

func topologyEdgeUpsertHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.UpsertTopologyEdgeRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		edge, err := repository.UpsertTopologyEdge(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"edge": edge}, logger)
	}
}

func topologyEdgeListHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		req := model.ListTopologyEdgesRequest{}
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, d, "bad_request", err, logger)
			}
		}

		edges, err := repository.ListTopologyEdges(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"edges": edges}, logger)
	}
}

func topologyDocumentUpsertHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.UpsertTopologyDocumentRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		document, err := repository.UpsertTopologyDocument(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"document": document}, logger)
	}
}

func topologyDocumentGetHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.GetTopologyDocumentRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		document, err := repository.GetTopologyDocument(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"document": document}, logger)
	}
}

func topologyDocumentListHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		req := model.ListTopologyDocumentsRequest{}
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, d, "bad_request", err, logger)
			}
		}

		documents, err := repository.ListTopologyDocuments(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"documents": documents}, logger)
	}
}

func topologyDocumentValueHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.GetTopologyDocumentValueRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		value, err := repository.GetTopologyDocumentValue(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"value": string(value)}, logger)
	}
}

func topologyAccessEvaluateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.EvaluateTopologyAccessRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		response, err := repository.EvaluateTopologyAccess(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, response, logger)
	}
}

func buildProjectCreateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.CreateBuildProjectRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		buildProject, err := repository.CreateBuildProject(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"build_project": buildProject}, logger)
	}
}

func buildProjectGetHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.GetBuildProjectRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		buildProject, err := repository.GetBuildProject(ctx, db, req.ID)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"build_project": buildProject}, logger)
	}
}

func buildProjectListHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.ListBuildProjectsRequest
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, d, "bad_request", err, logger)
			}
		}

		buildProjects, err := repository.ListBuildProjects(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"build_projects": buildProjects}, logger)
	}
}

func buildProjectDeleteHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d rpc.Delivery) error {
		var req model.DeleteBuildProjectRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, d, "bad_request", err, logger)
		}

		buildProject, err := repository.DeleteBuildProject(ctx, db, req.ID)
		if err != nil {
			return replyFailure(ctx, d, topologyErrorCode(err), err, logger)
		}

		return replySuccess(ctx, d, map[string]any{"build_project": buildProject}, logger)
	}
}

func topologyErrorCode(err error) string {
	switch {
	case errors.Is(err, repository.ErrTopologyNodeNotFound),
		errors.Is(err, repository.ErrTopologyDocumentNotFound),
		errors.Is(err, repository.ErrBuildProjectNotFound):
		return "not_found"
	default:
		return "internal_error"
	}
}
