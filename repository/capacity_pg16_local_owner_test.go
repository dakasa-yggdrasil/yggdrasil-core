package repository

import (
	"net"
	"strings"
)

// pg16LocalDSN admits only a loopback TCP or Unix-socket DSN.
func pg16LocalDSN(host, socket string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || (host == "" && strings.HasPrefix(socket, "/"))
}

// pg16LocalServer admits the server's own address only when it is the local
// owner: a Unix socket or loopback, or, behind a loopback TCP DSN, the private
// address of a port-mapped container on this same host (a CI service).
func pg16LocalServer(host, addr string) bool {
	if addr == "unix" {
		return true
	}
	ip := net.ParseIP(strings.SplitN(addr, "/", 2)[0])
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || (host != "" && ip.IsPrivate())
}
