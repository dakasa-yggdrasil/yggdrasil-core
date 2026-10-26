//go:build linux && nativequalification

package message

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	q "github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacitynativeqemu"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacityqualification"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/dakasa-yggdrasil/yggdrasil-sdk-go/rpc"
	amqp "github.com/rabbitmq/amqp091-go"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

var pg17OriginalReadBrokerMu sync.Mutex
var pg17OriginalReadBroker *amqp.Connection

// StartPG17OriginalReadConsumer uses the dedicated original fixture broker connection, SDK
// RPC codec and advertised endpoint. It cannot declare a differently named
// queue outside that fixed advertised contract, spawn an executor, send
// provider mutations or read another Realm.
// Its returned Close first seals deliveries, then joins every actual handler.
// Subscription.Close is an unsubscribe request, not an observed SDK driver
// goroutine Wait. Only the original outer Core process Wait/EOF/retirement
// can close that process-scoped driver boundary; this helper claims none.
func StartPG17OriginalReadConsumer(ctx context.Context, clientBroker, broker *amqp.Connection, store repository.CapacityStore, policy model.Manifest, realm *q.Realm) (func() error, error) {
	if clientBroker == nil || broker == nil || clientBroker == broker || realm == nil || realm != originalGuestNativeRealm || store.DB == nil || realm.Request.NativeCase != "positive_original_lifecycle" || ctx.Err() != nil {
		return nil, q.ErrOriginalUnknown
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, q.ErrOriginalUnknown
	}
	pg17OriginalReadBrokerMu.Lock()
	if pg17OriginalReadBroker != nil {
		pg17OriginalReadBrokerMu.Unlock()
		return nil, q.ErrOriginalUnknown
	}
	pg17OriginalReadBroker = clientBroker
	pg17OriginalReadBrokerMu.Unlock()
	var mu sync.Mutex
	var owners sync.WaitGroup
	closing := false
	reads := 0
	var workerErr error
	failWorker := func(err error) { mu.Lock(); workerErr = errors.Join(workerErr, err); mu.Unlock() }
	closeDescribe, err := capacityqualification.StartDescribe(ctx, broker)
	if err != nil {
		pg17OriginalReadBrokerMu.Lock()
		pg17OriginalReadBroker = nil
		pg17OriginalReadBrokerMu.Unlock()
		return nil, err
	}
	subscription, err := capacityqualification.ConsumePredeclared(ctx, broker, rpc.ConsumerConfig{Endpoint: "qualification.original.execute", Concurrency: 1, Timeout: 65 * time.Second, Handler: func(deliveryContext context.Context, d rpc.Delivery) (returnErr error) {
		defer func() {
			if returnErr != nil {
				failWorker(returnErr)
			}
		}()
		mu.Lock()
		if closing {
			mu.Unlock()
			return d.Nack(false)
		}
		owners.Add(1)
		mu.Unlock()
		defer owners.Done()
		limit, _ := ctx.Deadline()
		if deliveryLimit, ok := deliveryContext.Deadline(); ok && deliveryLimit.Before(limit) {
			limit = deliveryLimit
		}
		original, cancel := context.WithDeadline(ctx, limit)
		defer cancel()
		// Neither transport timeout nor its cancellation can extend the original
		// parent deadline; propagate cancellation without granting another epoch.
		done := make(chan struct{})
		go func() {
			defer close(done)
			select {
			case <-deliveryContext.Done():
				cancel()
			case <-original.Done():
			}
		}()
		defer func() { cancel(); <-done }()
		reply := func(data any, failure bool) error {
			var wire []byte
			var encodeErr error
			if failure {
				wire, encodeErr = jsonMarshalPG17Failure()
			} else {
				wire, encodeErr = jsonMarshalPG17Success(data)
			}
			if encodeErr != nil {
				return d.Nack(false)
			}
			if err := d.Reply(original, wire, "application/json"); err != nil {
				_ = d.Nack(false)
				return err
			}
			return d.Ack()
		}
		var request model.AdapterExecuteIntegrationRequest
		if d.Endpoint != "qualification.original.execute" || d.ReplyTo == "" || d.CorrelationID == "" || len(d.Body) == 0 || len(d.Body) >= 2<<20 || capacity.DecodeGuestLifecycle(d.Body, &request) != nil || len(request.Auth) != 0 || len(request.Metadata) != 0 || request.Operation != request.Capability || (request.Operation != capacity.VMObserveServer && request.Operation != capacity.VMObserveAction) {
			failWorker(q.ErrOriginalUnknown)
			return reply(nil, true)
		}
		mu.Lock()
		reads++
		ordinal := reads
		mu.Unlock()
		if ordinal > 4 {
			failWorker(q.ErrOriginalUnknown)
			return reply(nil, true)
		}
		startedAt := time.Now().UTC()
		response, readErr := realm.PG17NativeRead(original, store, policy, request)
		if readErr != nil || original.Err() != nil {
			failWorker(q.ErrOriginalUnknown)
			return reply(nil, true)
		}
		nativeFile, fileOK := response.Metadata["original_native_read_file"].(string)
		nativeSHA, shaOK := response.Metadata["original_native_read_sha256"].(string)
		if !fileOK || !shaOK || !capacity.ValidDigest(nativeSHA) || filepath.Base(nativeFile) != nativeFile {
			failWorker(q.ErrOriginalUnknown)
			return reply(nil, true)
		}
		prefix := "pg17-rpc-" + strconv.Itoa(ordinal)
		requestFile, responseFile := prefix+"-request.private.json", prefix+"-response.private.json"
		slotDirectory := q.SlotDirectory(realm.PrivateDirectory, 2)
		if _, err := q.PublishBytes(original, filepath.Join(slotDirectory, requestFile), d.Body); err != nil {
			failWorker(q.ErrOriginalUnknown)
			return reply(nil, true)
		}
		wire, encodeErr := jsonMarshalPG17Success(response)
		if encodeErr != nil {
			failWorker(q.ErrOriginalUnknown)
			return reply(nil, true)
		}
		if _, err := q.PublishBytes(original, filepath.Join(slotDirectory, responseFile), wire); err != nil {
			failWorker(q.ErrOriginalUnknown)
			return reply(nil, true)
		}
		replyErr := d.Reply(original, wire, "application/json")
		replyReturnedAt := time.Now().UTC()
		var ackErr error
		if replyErr == nil {
			ackErr = d.Ack()
		} else {
			ackErr = d.Nack(false)
		}
		record := struct {
			Schema                    string    `json:"schema"`
			Scope                     string    `json:"scope"`
			CoreSource                string    `json:"core_source"`
			Case                      string    `json:"case"`
			Ordinal                   int       `json:"ordinal"`
			Operation                 string    `json:"operation"`
			RequestFile               string    `json:"request_file"`
			RequestSHA256             string    `json:"request_sha256"`
			ResponseFile              string    `json:"response_file"`
			ResponseSHA256            string    `json:"response_sha256"`
			NativeReadFile            string    `json:"native_read_file"`
			NativeReadSHA256          string    `json:"native_read_sha256"`
			StartedAt                 time.Time `json:"started_at"`
			ReplyReturnedAt           time.Time `json:"reply_returned_at"`
			AcknowledgementReturnedAt time.Time `json:"acknowledgement_returned_at"`
			ReplySucceeded            bool      `json:"reply_succeeded"`
			AcknowledgementSucceeded  bool      `json:"acknowledgement_succeeded"`
			SDKDriverJoinObserved     bool      `json:"sdk_driver_join_observed"`
			NativeQualified           bool      `json:"native_qualified"`
		}{"pg17_original_rpc_read_return_v1", "SOURCE_ONLY_TYPED_RPC_NOT_NATIVE_OR_DRIVER_RETIREMENT", capacity.CurrentGuestCoreSource(), realm.Request.NativeCase, ordinal, request.Operation, requestFile, capacity.BusinessCreationSHA256(d.Body), responseFile, capacity.BusinessCreationSHA256(wire), nativeFile, nativeSHA, startedAt, replyReturnedAt, time.Now().UTC(), replyErr == nil, replyErr == nil && ackErr == nil, false, false}
		_, retainErr := q.Publish(original, filepath.Join(slotDirectory, prefix+"-return.json"), record)
		if retainErr != nil {
			return retainErr
		}
		if replyErr != nil {
			return replyErr
		}
		return ackErr
	}})
	if err != nil {
		_ = closeDescribe()
		pg17OriginalReadBrokerMu.Lock()
		pg17OriginalReadBroker = nil
		pg17OriginalReadBrokerMu.Unlock()
		return nil, err
	}
	var once sync.Once
	var joined error
	return func() error {
		once.Do(func() {
			mu.Lock()
			closing = true
			mu.Unlock()
			joined = errors.Join(subscription.Close(), closeDescribe())
			owners.Wait()
			mu.Lock()
			joined = errors.Join(joined, workerErr)
			mu.Unlock()
			pg17OriginalReadBrokerMu.Lock()
			pg17OriginalReadBroker = nil
			pg17OriginalReadBrokerMu.Unlock()
		})
		return joined
	}, nil
}

func jsonMarshalPG17Success(data any) ([]byte, error) {
	return json.Marshal(rpcResponse{OK: true, Data: data})
}
func jsonMarshalPG17Failure() ([]byte, error) {
	return json.Marshal(rpcResponse{OK: false, Error: &rpcError{Code: "original_native_read_refused", Message: "original native source read unavailable"}})
}
