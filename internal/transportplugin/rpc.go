package transportplugin

import (
	"errors"
	"net/rpc"
)

// transportRPCClient is what the core holds — every Transport method
// it calls flows out as a net/rpc call to the plugin subprocess.
type transportRPCClient struct {
	client *rpc.Client
}

// Name calls the plugin's Name method.
func (c *transportRPCClient) Name() (string, error) {
	var reply string
	if err := c.client.Call("Plugin.Name", struct{}{}, &reply); err != nil {
		return "", err
	}
	return reply, nil
}

// Dispatch forwards the request through net/rpc. We pass the whole
// DispatchRequest as the argument and let gob serialize it.
func (c *transportRPCClient) Dispatch(req DispatchRequest) (DispatchReply, error) {
	var reply DispatchReply
	if err := c.client.Call("Plugin.Dispatch", req, &reply); err != nil {
		return DispatchReply{}, err
	}
	if reply.Error != "" {
		return reply, errors.New(reply.Error)
	}
	return reply, nil
}

// Close tells the plugin to release any long-lived state. go-plugin
// still SIGKILLs the subprocess right after, so this is best-effort.
func (c *transportRPCClient) Close() error {
	var reply struct{}
	return c.client.Call("Plugin.Close", struct{}{}, &reply)
}

// transportRPCServer runs inside the plugin process. net/rpc calls
// methods on it by name ("Plugin.Dispatch" etc.), matching the
// signatures below: one argument, one *reply, error return. The
// argument and reply types are exported so gob can decode them.
type transportRPCServer struct {
	impl Transport
}

// Name is the server-side for transportRPCClient.Name.
func (s *transportRPCServer) Name(_ struct{}, reply *string) error {
	name, err := s.impl.Name()
	if err != nil {
		return err
	}
	*reply = name
	return nil
}

// Dispatch is the server-side for transportRPCClient.Dispatch. Errors
// returned from impl flow back two ways: the net/rpc layer surfaces
// them as errors (which is what the client sees), AND we also
// populate reply.Error so the caller can tell plugin-level failures
// apart from transport-level ones (the plugin might reply "ok but
// with an error envelope in the body").
func (s *transportRPCServer) Dispatch(req DispatchRequest, reply *DispatchReply) error {
	result, err := s.impl.Dispatch(req)
	if err != nil {
		reply.Error = err.Error()
		return err
	}
	*reply = result
	return nil
}

// Close is the server-side for transportRPCClient.Close.
func (s *transportRPCServer) Close(_ struct{}, _ *struct{}) error {
	return s.impl.Close()
}
