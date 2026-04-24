// Package transportplugin defines the contract between yggdrasil-core
// and out-of-process transport backends. It uses hashicorp/go-plugin
// in netrpc mode (no protobuf) to keep the contract minimal and the
// plugin author's surface small.
//
// Plugin authors implement the Transport interface in a binary main()
// and call plugin.Serve with the HandshakeConfig below. The core
// discovers plugins in a configured directory, spawns them on demand,
// and talks to them over the local-only netrpc pipe go-plugin
// provides.
//
// This is deliberately NOT the same interface as
// yggdrasil-sdk-go/rpc.Transport:
//
//   - rpc.Transport uses Go func values (Handler) and channel-like
//     semantics that don't cross a process boundary without
//     serialization. Making it work over netrpc would require either
//     a streaming RPC (not available in netrpc mode) or a heavy
//     bidirectional scaffolding that defeats the simplicity of v1.
//   - The plugin contract here is "pull one delivery, act, return
//     the reply" — a request/reply shape that netrpc expresses
//     naturally.
//
// A future phase (9b) will bridge rpc.Transport ↔ this interface so
// the workflow dispatcher can route through plugins transparently.
// For v1 the plugin system ships as experimental infrastructure:
// loaded, addressable, but not yet wired to the dispatcher.
package transportplugin

import (
	"net/rpc"

	"github.com/hashicorp/go-plugin"
)

// ProtocolVersion bumps whenever the Transport interface changes in
// a way that makes older plugins incompatible. Both sides check this
// during the handshake; a mismatch aborts the subprocess early with
// a clear error.
const ProtocolVersion = 1

// MagicCookieKey/Value are the process-env handshake go-plugin uses
// to prove "you are actually being spawned by a yggdrasil-core"
// rather than by some other parent. Security-theater-ish but the
// convention.
const (
	MagicCookieKey   = "YGGDRASIL_TRANSPORT_PLUGIN"
	MagicCookieValue = "4af4e3d2-9c6e-4f88-9e7f-b0d2c5a51e9e"
)

// Handshake is the full handshake config both core and plugin import.
var Handshake = plugin.HandshakeConfig{
	ProtocolVersion:  ProtocolVersion,
	MagicCookieKey:   MagicCookieKey,
	MagicCookieValue: MagicCookieValue,
}

// Transport is the request/reply contract the plugin implements. It
// is deliberately small: plugin authors port one Dispatch handler,
// not a whole transport state machine. If a plugin needs long-lived
// state (AMQP connection, Kafka consumer group), it maintains that
// state internally and exposes only request-shaped methods.
type Transport interface {
	// Name returns a short identifier (e.g. "amqp", "kafka"). The
	// core uses it for logging and to pick the plugin when multiple
	// are loaded.
	Name() (string, error)

	// Dispatch sends a single RPC request through the plugin's
	// transport and blocks until the plugin has a reply. Body +
	// headers are opaque to the plugin except where the plugin
	// itself interprets them (e.g. a Kafka plugin might read
	// `headers["topic"]`).
	Dispatch(req DispatchRequest) (DispatchReply, error)

	// Close releases any long-lived resources. Called when the core
	// is shutting down; the plugin process is killed a moment later
	// by go-plugin regardless.
	Close() error
}

// DispatchRequest is the payload Dispatch receives. Kept as plain
// structs (not interface{}) so go-plugin's gob encoder handles it
// without custom type registration.
type DispatchRequest struct {
	Endpoint      string
	Body          []byte
	ContentType   string
	Headers       map[string]string
	CorrelationID string
	TimeoutMS     int64
}

// DispatchReply is what the plugin returns. Error is non-empty when
// the plugin itself encountered an error; the body typically carries
// the adapter's ok/error envelope independently.
type DispatchReply struct {
	Body        []byte
	ContentType string
	Headers     map[string]string
	Error       string
}

// PluginMap is what both core and plugin register with go-plugin. The
// single key "transport" covers the whole interface — a plugin can
// only expose one Transport today.
func PluginMap(impl Transport) map[string]plugin.Plugin {
	return map[string]plugin.Plugin{
		"transport": &transportPlugin{impl: impl},
	}
}

// transportPlugin is the go-plugin adapter binding our Transport
// interface to net/rpc Client / Server. Plugin authors don't touch
// this — it's machinery.
type transportPlugin struct {
	impl Transport
}

func (p *transportPlugin) Server(*plugin.MuxBroker) (any, error) {
	return &transportRPCServer{impl: p.impl}, nil
}

func (p *transportPlugin) Client(_ *plugin.MuxBroker, client *rpc.Client) (any, error) {
	return &transportRPCClient{client: client}, nil
}
