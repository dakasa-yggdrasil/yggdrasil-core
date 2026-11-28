package model

import "time"

// These closed public DTOs mirror System nativefloornetwork. Their declaration
// order is retained for safe typed configuration hashes; no private key, bearer
// or original return digest is a public observation or mutation permission.
const CapacityNativeWorkerNetworkPermitSchema = "native_worker_network_permit_v1"
const CapacityNativeWorkerNetworkObservationSchema = "native_worker_network_observation_v1"

// The optional network binding is independent of provider purchase and the
// Kubernetes registry writer. AdapterID names the actual dedicated System
// process identity; it is not a fabricated provider SDK integration.
type CapacityNativeWorkerNetworkBinding struct {
	Mode             string                                   `json:"mode"`
	Writer           CapacityNativeWorkerNetworkWriterBinding `json:"writer"`
	Reader           CapacityNativeWorkerNetworkReaderBinding `json:"reader"`
	Floor            CapacityNativeWorkerNetworkFloorIdentity `json:"floor"`
	Template         CapacityNativeWorkerNetworkTemplate      `json:"template"`
	TemplateSHA256   string                                   `json:"template_sha256"`
	MaxPermitSeconds int                                      `json:"max_permit_seconds"`
}

type CapacityNativeWorkerNetworkWriterBinding struct {
	AdapterID          string `json:"adapter_id"`
	PrincipalID        string `json:"principal_id"`
	BindingName        string `json:"binding_name"`
	SystemSourceCommit string `json:"system_source_commit"`
	ScopeSHA256        string `json:"scope_sha256"`
}

type CapacityNativeWorkerNetworkReaderBinding struct {
	AdapterID          string `json:"adapter_id"`
	BindingName        string `json:"binding_name"`
	SystemSourceCommit string `json:"system_source_commit"`
	ScopeSHA256        string `json:"scope_sha256"`
}

// Declaration order mirrors the separately qualified System network template.
// This is separate from LaunchBinding schema1 and adds no implicit old-guest
// MTU or DNS witness to an existing launch.
type CapacityNativeWorkerNetworkTemplate struct {
	Schema                  int    `json:"schema"`
	GuestSystemSourceCommit string `json:"guest_system_source_commit"`
	Interface               string `json:"interface"`
	MTU                     int    `json:"mtu"`
	TransportCIDR           string `json:"transport_cidr"`
	FloorPeerIPv4           string `json:"floor_peer_ipv4"`
	FloorPublicKey          string `json:"floor_public_key"`
	ListenPort              int    `json:"listen_port"`
	FirewallChain           string `json:"firewall_chain"`
	PodCIDR                 string `json:"pod_cidr"`
	ServiceCIDR             string `json:"service_cidr"`
	ClusterDNSIPv4          string `json:"cluster_dns_ipv4"`
	DNSName                 string `json:"dns_name"`
}

// CapacityNativeWorkerNetworkMutationInput has no caller-selected peer, address, action or command.
type CapacityNativeWorkerNetworkMutationInput struct {
	BindingName string `json:"binding_name"`
	PermitID    string `json:"permit_id"`
}

// CapacityNativeWorkerNetworkObserveInput selects a projection. Requested values never establish peer
// ownership or substitute for the separately reported actual kernel facts.
type CapacityNativeWorkerNetworkObserveInput struct {
	BindingName     string `json:"binding_name"`
	AttemptID       string `json:"attempt_id"`
	LaunchSHA256    string `json:"launch_sha256"`
	WorkerPublicKey string `json:"worker_public_key"`
	WorkerIPv4      string `json:"worker_ipv4"`
}

type CapacityNativeWorkerNetworkPeer struct {
	WorkerPublicKey       string `json:"worker_public_key"`
	WorkerIPv4            string `json:"worker_ipv4"`
	TransportEndpointIPv4 string `json:"transport_endpoint_ipv4"`
}

// CapacityNativeWorkerNetworkGrant is returned by the protected Core authority. Owner is the public pool
// owner, never the controller's private lease bearer. The floor learns the UDP
// endpoint port from an actual authenticated WireGuard handshake.
type CapacityNativeWorkerNetworkGrant struct {
	Schema                 string                          `json:"schema"`
	PermitID               string                          `json:"permit_id"`
	AttemptID              string                          `json:"attempt_id"`
	BindingName            string                          `json:"binding_name"`
	Action                 string                          `json:"action"`
	Capability             string                          `json:"capability"`
	State                  string                          `json:"state"`
	MutationPermitted      bool                            `json:"mutation_permitted"`
	Redeemable             bool                            `json:"redeemable"`
	ExpiresAt              time.Time                       `json:"expires_at"`
	SystemSourceCommit     string                          `json:"system_source_commit"`
	WriterScopeSHA256      string                          `json:"writer_scope_sha256"`
	Owner                  string                          `json:"owner"`
	PolicyID               string                          `json:"policy_id"`
	PoolUID                string                          `json:"pool_uid"`
	RegistryUID            string                          `json:"registry_uid"`
	PoolEpoch              int64                           `json:"pool_epoch"`
	IntentGeneration       int64                           `json:"intent_generation"`
	FencingToken           int64                           `json:"fencing_token"`
	LaunchSHA256           string                          `json:"launch_sha256"`
	CreationProofSHA256    string                          `json:"creation_proof_sha256"`
	NetworkTemplateSHA256  string                          `json:"network_template_sha256"`
	FloorNodeUID           string                          `json:"floor_node_uid"`
	ExpectedPreimageSHA256 string                          `json:"expected_preimage_sha256"`
	Peer                   CapacityNativeWorkerNetworkPeer `json:"peer"`
	MTU                    int                             `json:"mtu"`
}

type CapacityNativeWorkerNetworkFloorIdentity struct {
	NodeName        string `json:"node_name"`
	NodeUID         string `json:"node_uid"`
	ProviderID      string `json:"provider_id"`
	ClusterUID      string `json:"cluster_uid"`
	CASHA256        string `json:"ca_sha256"`
	NativeIPv4      string `json:"native_ipv4"`
	NativeInterface string `json:"native_interface"`
}

// CapacityNativeWorkerNetworkHostIdentity includes only locally read facts. Kubernetes Node UID, provider
// identity and cluster UID remain explicitly bound expectations above; a host
// network reader does not manufacture an independent Kubernetes/provider read.
type CapacityNativeWorkerNetworkHostIdentity struct {
	Hostname             string `json:"hostname"`
	CASHA256             string `json:"ca_sha256"`
	CAOrigin             string `json:"ca_origin"`
	NativeInterfaceIndex int    `json:"native_interface_index"`
	NativeInterfaceUp    bool   `json:"native_interface_up"`
	NativeIPv4Present    bool   `json:"native_ipv4_present"`
}

type CapacityNativeWorkerNetworkFloorFacts struct {
	Bound    CapacityNativeWorkerNetworkFloorIdentity `json:"bound"`
	Observed CapacityNativeWorkerNetworkHostIdentity  `json:"observed"`
}

type CapacityNativeWorkerNetworkInterfaceFacts struct {
	Present    bool     `json:"present"`
	Name       string   `json:"name"`
	IfIndex    int      `json:"ifindex"`
	MTU        int      `json:"mtu"`
	Up         bool     `json:"up"`
	Addresses  []string `json:"addresses"`
	PublicKey  string   `json:"public_key"`
	ListenPort int      `json:"listen_port"`
}

type CapacityNativeWorkerNetworkPeerFacts struct {
	PublicKey         string   `json:"public_key"`
	AllowedIPs        []string `json:"allowed_ips"`
	Endpoint          string   `json:"endpoint"`
	LastHandshakeUnix int64    `json:"last_handshake_unix"`
}

type CapacityNativeWorkerNetworkRouteFacts struct {
	Destination     string `json:"destination"`
	Device          string `json:"device"`
	PreferredSource string `json:"preferred_source"`
}

type CapacityNativeWorkerNetworkFirewallFacts struct {
	Chain       string   `json:"chain"`
	Rules       []string `json:"rules"`
	RulesSHA256 string   `json:"rules_sha256"`
	Complete    bool     `json:"complete"`
}

type CapacityNativeWorkerNetworkKernelSettings struct {
	IPForward                 int  `json:"ip_forward"`
	AllRPFilter               int  `json:"all_rp_filter"`
	NativeRPFilter            int  `json:"native_rp_filter"`
	WireGuardRPFilter         int  `json:"wireguard_rp_filter"`
	WireGuardRPFilterObserved bool `json:"wireguard_rp_filter_observed"`
}

// CapacityNativeWorkerNetworkObservation is a safe typed projection, never an admission receipt. A failed
// tool/read/parser returns ErrHold instead of fabricating an absent interface.
type CapacityNativeWorkerNetworkObservation struct {
	Schema                  string                                    `json:"schema"`
	BindingName             string                                    `json:"binding_name"`
	AdapterSourceCommit     string                                    `json:"adapter_source_commit"`
	ReaderScopeSHA256       string                                    `json:"reader_scope_sha256"`
	Requested               CapacityNativeWorkerNetworkObserveInput   `json:"requested"`
	ObservedAt              time.Time                                 `json:"observed_at"`
	Floor                   CapacityNativeWorkerNetworkFloorFacts     `json:"floor"`
	NetworkTemplateSHA256   string                                    `json:"network_template_sha256"`
	MTU                     int                                       `json:"mtu"`
	Interface               CapacityNativeWorkerNetworkInterfaceFacts `json:"interface"`
	Peers                   []CapacityNativeWorkerNetworkPeerFacts    `json:"peers"`
	Routes                  []CapacityNativeWorkerNetworkRouteFacts   `json:"routes"`
	Firewall                CapacityNativeWorkerNetworkFirewallFacts  `json:"firewall"`
	KernelSettings          CapacityNativeWorkerNetworkKernelSettings `json:"kernel_settings"`
	KernelInventoryComplete bool                                      `json:"kernel_inventory_complete"`
}

// CapacityNativeWorkerNetworkOriginalReturn is private custody, not a public observation or permission.
// It contains only the original fixed host-batch return, never a private key.
type CapacityNativeWorkerNetworkOriginalReturn struct {
	Schema          string `json:"schema"`
	PermitID        string `json:"permit_id"`
	BindingName     string `json:"binding_name"`
	OriginalReturn  []byte `json:"original_return"`
	CaptureComplete bool   `json:"capture_complete"`
	ErrorClass      string `json:"error_class,omitempty"`
}
