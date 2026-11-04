package model

import "time"

// Mirrored closed native observer protocol; no caller installation proofs.
type BirthGuardNativeIdentity struct {
	Kind            string `json:"kind"`
	Namespace       string `json:"namespace,omitempty"`
	Name            string `json:"name"`
	UID             string `json:"uid"`
	ResourceVersion string `json:"resource_version"`
	SHA256          string `json:"sha256"`
}

type BirthGuardProcess struct {
	PodName         string    `json:"pod_name"`
	PodUID          string    `json:"pod_uid"`
	ResourceVersion string    `json:"resource_version"`
	ReplicaSetUID   string    `json:"replica_set_uid"`
	NodeName        string    `json:"node_name"`
	ContainerName   string    `json:"container_name"`
	ContainerID     string    `json:"container_id"`
	ImageDigest     string    `json:"image_digest"`
	StartedAt       time.Time `json:"started_at"`
	RestartCount    int32     `json:"restart_count"`
}

type CurrentBirthGuardObservation struct {
	Operation     string                     `json:"operation"`
	Status        string                     `json:"status"`
	BindingName   string                     `json:"binding_name"`
	BindingSHA256 string                     `json:"binding_sha256"`
	Namespace     string                     `json:"namespace"`
	WorkloadUID   string                     `json:"workload_uid"`
	ObservedAt    time.Time                  `json:"observed_at"`
	Resources     []BirthGuardNativeIdentity `json:"resources"`
	Processes     []BirthGuardProcess        `json:"processes"`
	// These reads establish current installed source/config/process tuples.
	// They never establish atomicity with HPA writes or useful capacity.
	AtomicSnapshot            bool `json:"atomic_snapshot"`
	BusinessReadinessKnown    bool `json:"business_readiness_known"`
	RuntimeConfigSelfAttested bool `json:"runtime_config_self_attested"`
}
