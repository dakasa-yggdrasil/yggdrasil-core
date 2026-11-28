package model

import "time"

// Exact read-only System NetworkWitness wire. This is a guest-local report;
// mTLS authenticates its producer, not independent path MTU, startup warmup,
// floor effects, scheduling admission or useful workload capacity.
type CapacityNativeWorkerGuestWitness struct {
	Schema                      string                           `json:"schema"`
	SystemSourceCommit          string                           `json:"system_source_commit"`
	AttemptID                   string                           `json:"attempt_id"`
	LaunchSHA256                string                           `json:"launch_sha256"`
	BindingSHA256               string                           `json:"binding_sha256"`
	NetworkTemplateSHA256       string                           `json:"network_template_sha256"`
	ObservedAt                  time.Time                        `json:"observed_at"`
	InterfaceName               string                           `json:"interface_name"`
	InterfaceIndex              int                              `json:"interface_index"`
	MTU                         int                              `json:"mtu"`
	InterfaceUp                 bool                             `json:"interface_up"`
	WorkerIPv4Present           bool                             `json:"worker_ipv4_present"`
	WireGuardPublicKey          string                           `json:"wireguard_public_key"`
	FloorPeerPublicKey          string                           `json:"floor_peer_public_key"`
	FloorPeerEndpoint           string                           `json:"floor_peer_endpoint"`
	FloorPeerLastHandshakeUnix  int64                            `json:"floor_peer_last_handshake_unix"`
	Routes                      []CapacityNativeWorkerGuestRoute `json:"routes"`
	DNSName                     string                           `json:"dns_name"`
	DNSResolverIPv4             string                           `json:"dns_resolver_ipv4"`
	DNSAnswerIPv4               []string                         `json:"dns_answer_ipv4"`
	FloorTLSVerified            bool                             `json:"floor_tls_verified"`
	EndToEndPathMTUQualified    bool                             `json:"end_to_end_path_mtu_qualified"`
	IndependentNetworkQualified bool                             `json:"independent_network_qualified"`
	SchedulingAdmitted          bool                             `json:"scheduling_admitted"`
	UsefulCapacityQualified     bool                             `json:"useful_capacity_qualified"`
}

type CapacityNativeWorkerGuestRoute struct {
	TargetIPv4 string `json:"target_ipv4"`
	Device     string `json:"device"`
	SourceIPv4 string `json:"source_ipv4"`
}
