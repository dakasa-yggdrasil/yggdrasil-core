//go:build nativequalification

// Package capacityqualification implements the source-only QEMU fixture's
// advertised Describe endpoint. It is absent from production builds.
package capacityqualification

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

const DescribeQueue = "qualification.original.describe"

// NativeDescribe is the source-owned QEMU adapter contract. Its values are
// independent of the database manifest whose live handshake compares it.
func NativeDescribe() (model.AdapterDescribeResponse, error) {
	spec := model.IntegrationTypeManifestSpec{
		Provider: "native-qemu", Domain: "infrastructure",
		Adapter:          model.IntegrationAdapterSpec{Transport: "rabbitmq", Version: "1.0.0", TimeoutSeconds: 65, Queues: model.IntegrationAdapterQueue{Describe: DescribeQueue, Execute: "qualification.original.execute"}},
		Capabilities:     []string{"describe", "execute"},
		CredentialSchema: model.IntegrationSchemaSpec{Mode: "none"}, InstanceSchema: model.IntegrationSchemaSpec{Mode: "none"},
		ResourceTypes: []model.IntegrationResourceType{{Name: "server", CanonicalPrefix: "thirdparty.native-qemu.server", IdentityTemplate: "server.{id}", DefaultActions: []string{"ensure_server", "destroy_server", capacity.VMObserveServer, capacity.VMObserveAction}}},
		ActionCatalog: []model.IntegrationActionDefinition{{Name: "ensure_server", ResourceTypes: []string{"server"}, Idempotent: true}, {Name: "destroy_server", ResourceTypes: []string{"server"}, Idempotent: true}, {Name: capacity.VMObserveServer, Category: "capability", ResourceTypes: []string{"server"}, Idempotent: true}, {Name: capacity.VMObserveAction, Category: "capability", ResourceTypes: []string{"server"}, Idempotent: true}},
		Discovery:     model.IntegrationDiscoverySpec{Mode: "push", Cursor: "none"}, Normalization: model.IntegrationNormalizationSpec{ExternalIDPath: "id", FallbackResourcePrefix: "thirdparty.native-qemu.server"}, Execution: model.IntegrationExecutionSpec{SupportsDryRun: true, IdempotentActions: []string{"ensure_server", "destroy_server"}},
	}
	wire, err := json.Marshal(spec)
	if err != nil {
		return model.AdapterDescribeResponse{}, err
	}
	var response model.AdapterDescribeResponse
	if err = json.Unmarshal(wire, &response); err != nil {
		return response, err
	}
	return response, nil
}

// ConsumePredeclared consumes a queue installed by the qualification broker
// definitions. Unlike the SDK consumer, it does not redeclare the quorum queue.
// It owns and joins the single handler before closing its channel.
func ConsumePredeclared(ctx context.Context, broker *amqp.Connection, cfg rpc.ConsumerConfig) (rpc.Subscription, error) {
	if ctx == nil || ctx.Err() != nil || broker == nil || broker.IsClosed() || (cfg.Endpoint != DescribeQueue && cfg.Endpoint != "qualification.original.execute") || cfg.Handler == nil || cfg.Concurrency != 1 || cfg.Timeout <= 0 {
		return nil, errors.New("qualification consumer scope required")
	}
	ch, err := broker.Channel()
	if err != nil {
		return nil, err
	}
	if err = ch.Qos(1, 0, false); err != nil {
		_ = ch.Close()
		return nil, err
	}
	tag := "qualification-original-" + uuid.NewString()
	deliveries, err := ch.Consume(cfg.Endpoint, tag, false, false, false, false, nil)
	if err != nil {
		_ = ch.Close()
		return nil, err
	}
	s := &subscription{ch: ch, tag: tag, endpoint: cfg.Endpoint}
	s.worker.Add(1)
	go func() {
		defer s.worker.Done()
		for delivery := range deliveries {
			callCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
			headers := stringHeaders(delivery.Headers)
			var settled, replied sync.Once
			var settleErr, replyErr error
			d := rpc.Delivery{Endpoint: cfg.Endpoint, Body: delivery.Body, ContentType: delivery.ContentType, Headers: headers, CorrelationID: delivery.CorrelationId, ReplyTo: delivery.ReplyTo,
				AckFn: func() error { settled.Do(func() { settleErr = delivery.Ack(false) }); return settleErr },
				NackFn: func(requeue bool) error {
					settled.Do(func() { settleErr = delivery.Nack(false, requeue) })
					return settleErr
				},
				ReplyFn: func(replyCtx context.Context, body []byte, contentType string) error {
					replied.Do(func() {
						if delivery.ReplyTo == "" {
							replyErr = errors.New("qualification reply destination required")
							return
						}
						replyErr = ch.PublishWithContext(replyCtx, "", delivery.ReplyTo, false, false, amqp.Publishing{ContentType: contentType, CorrelationId: delivery.CorrelationId, Body: body})
					})
					return replyErr
				},
			}
			handlerErr := cfg.Handler(callCtx, d)
			if handlerErr != nil {
				settled.Do(func() { settleErr = delivery.Nack(false, false) })
			} else {
				settled.Do(func() { settleErr = delivery.Ack(false) })
			}
			cancel()
			s.workerErr = errors.Join(s.workerErr, handlerErr, settleErr, replyErr)
		}
	}()
	return s, nil
}

// stringHeaders mirrors the SDK's AMQP delivery conversion.
func stringHeaders(headers amqp.Table) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	result := make(map[string]string, len(headers))
	for key, value := range headers {
		switch typed := value.(type) {
		case string:
			result[key] = typed
		case []byte:
			result[key] = string(typed)
		default:
			if encoded, err := json.Marshal(typed); err == nil {
				result[key] = string(encoded)
			}
		}
	}
	return result
}

type subscription struct {
	ch                  *amqp.Channel
	tag, endpoint       string
	worker              sync.WaitGroup
	once                sync.Once
	workerErr, closeErr error
}

func (s *subscription) Endpoint() string { return s.endpoint }
func (s *subscription) Close() error {
	s.once.Do(func() {
		cancelErr := s.ch.Cancel(s.tag, false)
		if cancelErr != nil {
			_ = s.ch.Close()
		}
		s.worker.Wait()
		s.closeErr = errors.Join(cancelErr, s.ch.Close(), s.workerErr)
	})
	return s.closeErr
}

// StartDescribe exposes the fixed source-owned adapter response over AMQP.
func StartDescribe(ctx context.Context, broker *amqp.Connection) (func() error, error) {
	response, err := NativeDescribe()
	if err != nil {
		return nil, err
	}
	sub, err := ConsumePredeclared(ctx, broker, rpc.ConsumerConfig{Endpoint: DescribeQueue, Concurrency: 1, Timeout: 65 * time.Second, Handler: func(callCtx context.Context, d rpc.Delivery) error {
		var request model.AdapterDescribeRequest
		valid := len(d.Body) > 0 && len(d.Body) < 4096 && d.ReplyTo != "" && d.CorrelationID != "" && capacity.DecodeGuestLifecycle(d.Body, &request) == nil && request.Provider == "native-qemu" && (request.ExpectedVersion == "" || request.ExpectedVersion == "1.0.0")
		var body []byte
		var err error
		if valid {
			body, err = json.Marshal(struct {
				OK   bool                          `json:"ok"`
				Data model.AdapterDescribeResponse `json:"data"`
			}{true, response})
		} else {
			body, err = json.Marshal(struct {
				OK    bool `json:"ok"`
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}{Error: struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{"original_native_describe_refused", "original native describe request refused"}})
		}
		if err != nil {
			return errors.Join(err, d.Nack(false))
		}
		if d.ReplyTo == "" || d.CorrelationID == "" {
			return errors.Join(fmt.Errorf("qualification describe route required"), d.Nack(false))
		}
		if err = d.Reply(callCtx, body, "application/json"); err != nil {
			return errors.Join(err, d.Nack(false))
		}
		return d.Ack()
	}})
	if err != nil {
		return nil, err
	}
	return sub.Close, nil
}
