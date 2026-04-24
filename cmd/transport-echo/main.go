// yggdrasil-transport-echo is a demo transport plugin: every
// Dispatch call is echoed back with a predictable envelope. Used
// only in tests + as a worked example in the transport plugin docs;
// not shipped in production images.
//
// Installation (manual):
//
//	go build -o /var/lib/yggdrasil/plugins/yggdrasil-transport-echo ./cmd/transport-echo
//
// Then start yggdrasil-core with YGGDRASIL_TRANSPORT_PLUGIN_DIR
// pointing at /var/lib/yggdrasil/plugins. The core discovers the
// binary by its filename prefix and loads it on demand.
package main

import (
	"fmt"

	"github.com/hashicorp/go-plugin"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/transportplugin"
)

type echoTransport struct{}

func (echoTransport) Name() (string, error) { return "echo", nil }

func (echoTransport) Dispatch(req transportplugin.DispatchRequest) (transportplugin.DispatchReply, error) {
	// A real plugin would forward the request through its actual
	// transport (Kafka, NATS, SQS, etc.) and block on the reply.
	// Here we synthesize a deterministic echo body so integration
	// tests can assert the round-trip shape without external deps.
	body := []byte(fmt.Sprintf(`{"echo":true,"endpoint":%q,"received":%d}`, req.Endpoint, len(req.Body)))
	return transportplugin.DispatchReply{
		Body:        body,
		ContentType: "application/json",
		Headers:     map[string]string{"x-echo-correlation": req.CorrelationID},
	}, nil
}

func (echoTransport) Close() error { return nil }

func main() {
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: transportplugin.Handshake,
		Plugins:         transportplugin.PluginMap(echoTransport{}),
	})
}
