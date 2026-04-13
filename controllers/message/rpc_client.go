package message

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

type rpcEnvelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error *rpcError       `json:"error,omitempty"`
}

func callRabbitRPC(ctx context.Context, conn *amqp.Connection, queue string, request any, response any) error {
	ch, err := conn.Channel()
	if err != nil {
		return err
	}
	defer func() { _ = ch.Close() }()

	replyQueue, err := ch.QueueDeclare("", false, true, true, false, nil)
	if err != nil {
		return err
	}

	deliveries, err := ch.Consume(replyQueue.Name, "", true, true, false, false, nil)
	if err != nil {
		return err
	}

	body, err := json.Marshal(request)
	if err != nil {
		return err
	}

	correlationID := uuid.NewString()
	if err := ch.PublishWithContext(ctx, "", queue, false, false, amqp.Publishing{
		ContentType:   "application/json",
		CorrelationId: correlationID,
		ReplyTo:       replyQueue.Name,
		Body:          body,
	}); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case delivery, ok := <-deliveries:
			if !ok {
				return fmt.Errorf("rabbitmq rpc reply channel closed")
			}
			if delivery.CorrelationId != correlationID {
				continue
			}
			return decodeRPCBody(delivery.Body, response)
		}
	}
}

func decodeRPCBody(body []byte, response any) error {
	if len(bytesTrimSpace(body)) == 0 {
		return fmt.Errorf("rabbitmq rpc response body is empty")
	}

	var envelope rpcEnvelope
	if err := json.Unmarshal(body, &envelope); err == nil {
		if envelope.Error != nil {
			return fmt.Errorf("%s: %s", envelope.Error.Code, envelope.Error.Message)
		}
		if len(envelope.Data) > 0 {
			if response == nil {
				return nil
			}
			return json.Unmarshal(envelope.Data, response)
		}
		if envelope.OK {
			return nil
		}
	}

	if response == nil {
		return nil
	}
	return json.Unmarshal(body, response)
}
