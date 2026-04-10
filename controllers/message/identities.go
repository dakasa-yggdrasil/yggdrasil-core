package message

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	amqp "github.com/rabbitmq/amqp091-go"
	"go.uber.org/zap"
)

const (
	queueCollaboratorCreate   = "yggdrasil-core.collaborator.create"
	queueCollaboratorUpdate   = "yggdrasil-core.collaborator.update"
	queueCollaboratorDelete   = "yggdrasil-core.collaborator.delete"
	queueCollaboratorGet      = "yggdrasil-core.collaborator.get"
	queueCollaboratorList     = "yggdrasil-core.collaborator.list"
	queueTeamCreate           = "yggdrasil-core.team.create"
	queueTeamUpdate           = "yggdrasil-core.team.update"
	queueTeamDelete           = "yggdrasil-core.team.delete"
	queueTeamGet              = "yggdrasil-core.team.get"
	queueTeamList             = "yggdrasil-core.team.list"
	queueTeamMembershipUpsert = "yggdrasil-core.team.membership.upsert"
	queueTeamMembershipList   = "yggdrasil-core.team.membership.list"
)

func identityConsumers(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) []ConsumerConfig {
	return []ConsumerConfig{
		{
			Queue:   queueCollaboratorCreate,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: collaboratorCreateHandler(conn, db, logger),
		},
		{
			Queue:   queueCollaboratorUpdate,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: collaboratorUpdateHandler(conn, db, logger),
		},
		{
			Queue:   queueCollaboratorDelete,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: collaboratorDeleteHandler(conn, db, logger),
		},
		{
			Queue:   queueCollaboratorGet,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: collaboratorGetHandler(conn, db, logger),
		},
		{
			Queue:   queueCollaboratorList,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: collaboratorListHandler(conn, db, logger),
		},
		{
			Queue:   queueTeamCreate,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: teamCreateHandler(conn, db, logger),
		},
		{
			Queue:   queueTeamUpdate,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: teamUpdateHandler(conn, db, logger),
		},
		{
			Queue:   queueTeamDelete,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: teamDeleteHandler(conn, db, logger),
		},
		{
			Queue:   queueTeamGet,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: teamGetHandler(conn, db, logger),
		},
		{
			Queue:   queueTeamList,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: teamListHandler(conn, db, logger),
		},
		{
			Queue:   queueTeamMembershipUpsert,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: teamMembershipUpsertHandler(conn, db, logger),
		},
		{
			Queue:   queueTeamMembershipList,
			Timeout: 10 * time.Second,
			QoS:     10,
			Handler: teamMembershipListHandler(conn, db, logger),
		},
	}
}

func collaboratorCreateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.CreateCollaboratorRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		collaborator, err := repository.CreateCollaborator(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, conn, d, identityErrorCode(err), err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"collaborator": collaborator}, logger)
	}
}

func collaboratorUpdateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.UpdateCollaboratorRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		collaborator, err := repository.UpdateCollaborator(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, conn, d, identityErrorCode(err), err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"collaborator": collaborator}, logger)
	}
}

func collaboratorDeleteHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.DeleteCollaboratorRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		collaborator, err := repository.DeleteCollaborator(ctx, db, req.ID)
		if err != nil {
			return replyFailure(ctx, conn, d, identityErrorCode(err), err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"collaborator": collaborator}, logger)
	}
}

func collaboratorGetHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.GetCollaboratorRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		collaborator, err := repository.GetCollaborator(ctx, db, req.ID)
		if err != nil {
			return replyFailure(ctx, conn, d, identityErrorCode(err), err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"collaborator": collaborator}, logger)
	}
}

func collaboratorListHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		req := model.ListCollaboratorsRequest{}
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, conn, d, "bad_request", err, logger)
			}
		}

		collaborators, err := repository.ListCollaborators(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, conn, d, "internal_error", err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"collaborators": collaborators}, logger)
	}
}

func teamCreateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.CreateTeamRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		team, err := repository.CreateTeam(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, conn, d, identityErrorCode(err), err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"team": team}, logger)
	}
}

func teamUpdateHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.UpdateTeamRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		team, err := repository.UpdateTeam(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, conn, d, identityErrorCode(err), err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"team": team}, logger)
	}
}

func teamDeleteHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.DeleteTeamRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		team, err := repository.DeleteTeam(ctx, db, req.ID)
		if err != nil {
			return replyFailure(ctx, conn, d, identityErrorCode(err), err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"team": team}, logger)
	}
}

func teamGetHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.GetTeamRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		team, err := repository.GetTeam(ctx, db, req.ID)
		if err != nil {
			return replyFailure(ctx, conn, d, identityErrorCode(err), err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"team": team}, logger)
	}
}

func teamListHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		req := model.ListTeamsRequest{}
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, conn, d, "bad_request", err, logger)
			}
		}

		teams, err := repository.ListTeams(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, conn, d, "internal_error", err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"teams": teams}, logger)
	}
}

func teamMembershipUpsertHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		var req model.UpsertTeamMembershipRequest
		if err := json.Unmarshal(d.Body, &req); err != nil {
			return replyFailure(ctx, conn, d, "bad_request", err, logger)
		}

		membership, err := repository.UpsertTeamMembership(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, conn, d, identityErrorCode(err), err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"membership": membership}, logger)
	}
}

func teamMembershipListHandler(conn *amqp.Connection, db *sql.DB, logger *zap.Logger) ConsumerHandler {
	return func(ctx context.Context, d amqp.Delivery) error {
		req := model.ListTeamMembershipsRequest{}
		if len(bytesTrimSpace(d.Body)) > 0 {
			if err := json.Unmarshal(d.Body, &req); err != nil {
				return replyFailure(ctx, conn, d, "bad_request", err, logger)
			}
		}

		memberships, err := repository.ListTeamMemberships(ctx, db, req)
		if err != nil {
			return replyFailure(ctx, conn, d, identityErrorCode(err), err, logger)
		}

		return replySuccess(ctx, conn, d, map[string]any{"memberships": memberships}, logger)
	}
}

func identityErrorCode(err error) string {
	switch {
	case errors.Is(err, repository.ErrCollaboratorNotFound), errors.Is(err, repository.ErrTeamNotFound):
		return "not_found"
	default:
		message := strings.ToLower(err.Error())
		if strings.Contains(message, "required") ||
			strings.Contains(message, "cannot reference") ||
			strings.Contains(message, "duplicate key") ||
			strings.Contains(message, "unique") {
			return "bad_request"
		}
		return "internal_error"
	}
}
