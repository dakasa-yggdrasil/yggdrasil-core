// Package nativeworkerprobe owns a finite diagnostic process inside one Pod.
// It has no Kubernetes, provider, business-dispatch or admission authority.
package nativeworkerprobe

import "time"

const (
	ConfigSchema  = "native_worker_probe_config_v1"
	ReportSchema  = "native_worker_probe_report_v1"
	StartupSchema = "native_worker_probe_startup_v1"
	ConfigPath    = "/run/dakasa-native-worker-probe/config.json"
	Port          = 9446
	WorkloadMTU   = 1330
	PayloadBytes  = 1302
	BatchDeadline = 30 * time.Second
	InitialPath   = "/probe/initial"
	FinalPath     = "/probe/final"
	ReportPath    = "/probe/report"
	StartupPath   = "/probe/startup"
)

// Config is public run selection, mounted by the protected controller. Its
// exact original bytes are hashed; certificates and private keys are sibling
// Secret files and never become fields in this value or its reports.
type Config struct {
	Schema               string         `json:"schema"`
	SourceCommit         string         `json:"source_commit"`
	Identity             Identity       `json:"identity"`
	Peer                 Peer           `json:"peer"`
	PodCIDR              string         `json:"pod_cidr"`
	ServiceCIDR          string         `json:"service_cidr"`
	Nonce                string         `json:"nonce"`
	NotBefore            time.Time      `json:"not_before"`
	HardNotAfter         time.Time      `json:"hard_not_after"`
	ControllerLeafSHA256 string         `json:"controller_leaf_sha256"`
	Startup              *StartupConfig `json:"startup,omitempty"`
}

type Identity struct {
	RunID              string `json:"run_id"`
	AttemptID          string `json:"attempt_id"`
	BirthSHA256        string `json:"birth_sha256"`
	PoolUID            string `json:"pool_uid"`
	Role               string `json:"role"` // floor or candidate; never a process role override.
	Namespace          string `json:"namespace"`
	NamespaceUID       string `json:"namespace_uid"`
	PodName            string `json:"pod_name"`
	PodUID             string `json:"pod_uid"`
	PodIPv4            string `json:"pod_ipv4"`
	ServiceUID         string `json:"service_uid"`
	ServiceClusterIPv4 string `json:"service_cluster_ipv4"`
	NodeName           string `json:"node_name"`
	NodeUID            string `json:"node_uid"`
}

type Peer struct {
	PodUID             string `json:"pod_uid"`
	NodeUID            string `json:"node_uid"`
	PodIPv4            string `json:"pod_ipv4"`
	ServiceUID         string `json:"service_uid"`
	ServiceClusterIPv4 string `json:"service_cluster_ipv4"`
}

// The only startup destination is compiled: http://127.0.0.1:9080, with
// /internal-runtime/native-admission and /readyz. No URL or bearer is input.
// admission.key is a separate sibling Secret file, not the Guest/WG identity.
type StartupConfig struct {
	CoreSourceCommit string `json:"core_source_commit"`
	ImageDigest      string `json:"image_digest"`
	WorkloadUID      string `json:"workload_uid"`
	ContainerName    string `json:"container_name"`
	LaneRosterSHA256 string `json:"lane_roster_sha256"`
}

type BatchReport struct {
	State       string           `json:"state"` // idle, running, complete, failed, unknown.
	StartedAt   *time.Time       `json:"started_at,omitempty"`
	CompletedAt *time.Time       `json:"completed_at,omitempty"`
	Sent        []DatagramRecord `json:"sent"`
	Received    []DatagramRecord `json:"received"`
	Echoed      []DatagramRecord `json:"echoed"`
	ErrorClass  string           `json:"error_class,omitempty"`
}

// Selectors are configured claims; the controller must independently join the
// actual Kubernetes lifetimes. Datagram evidence never replaces those GETs.
type DatagramRecord struct {
	Batch         string `json:"batch"`
	Path          string `json:"path"` // pod or service, fixed by Source.
	Sequence      int    `json:"sequence"`
	PayloadBytes  int    `json:"payload_bytes"`
	PayloadSHA256 string `json:"payload_sha256"`
	// Original diagnostic frame only: no credentials or private key material.
	Packet     []byte    `json:"packet"`
	Address    string    `json:"address"`
	ObservedAt time.Time `json:"observed_at"`
}

type Report struct {
	Schema           string      `json:"schema"`
	SourceCommit     string      `json:"source_commit"`
	ConfigSHA256     string      `json:"config_sha256"`
	Identity         Identity    `json:"identity"`
	ObservedAt       time.Time   `json:"observed_at"`
	HardNotAfter     time.Time   `json:"hard_not_after"`
	SigningPublicKey string      `json:"signing_public_key"`
	Initial          BatchReport `json:"initial"`
	Final            BatchReport `json:"final"`
}

// StartupInspection is a safe projection of actual original loopback reads.
// It returns neither the admission key nor raw database/error response bodies.
// roots_open is process startup, never Node/pool useful-capacity admission.
type StartupInspection struct {
	Schema              string    `json:"schema"`
	SourceCommit        string    `json:"source_commit"`
	ConfigSHA256        string    `json:"config_sha256"`
	Identity            Identity  `json:"identity"`
	ObservedAt          time.Time `json:"observed_at"`
	AdmissionHTTPStatus int       `json:"admission_http_status"`
	AdmissionState      string    `json:"admission_state"`
	AdmissionObservedAt time.Time `json:"admission_observed_at"`
	ImageDigest         string    `json:"image_digest"`
	LaneRosterSHA256    string    `json:"lane_roster_sha256"`
	ProcessNonce        string    `json:"process_nonce"`
	ChallengeSHA256     string    `json:"challenge_sha256,omitempty"`
	ReadyHTTPStatus     int       `json:"ready_http_status"`
	ReadyStatus         string    `json:"ready_status"`
	RabbitMQStatus      string    `json:"rabbitmq_status"`
	ErrorClass          string    `json:"error_class,omitempty"`
}
