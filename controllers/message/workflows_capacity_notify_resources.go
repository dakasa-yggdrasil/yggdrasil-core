package message

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

const (
	originalNotifyPoolKind         = "postgres_retained_session_v1"
	originalNotifyPoolResourceName = "notify_primary_pg_session"
)

// The private producer encloses two actual reads from the same retained
// original sql.Conn, around its original publish/handler return. Static library
// declarations are retained as unverified data, never as Pod or lease proof.
type originalNotifyPoolPrerequisite struct {
	Schema       string                         `json:"schema"`
	Kind         string                         `json:"kind"`
	ResourceName string                         `json:"resource_name"`
	WindowSHA    string                         `json:"window_sha256"`
	MessageSHA   string                         `json:"message_sha256"`
	Actor        OriginalNotifyNativeIdentity   `json:"actor"`
	Before       *originalNotifyPoolObservation `json:"before"`
	After        *originalNotifyPoolObservation `json:"after"`
}

// Literal closed mirror of Commons' NativePoolObservation. Core imports no
// product library and does not interpret its declarations as native authority.
type originalNotifyPoolObservation struct {
	SchemaVersion               int                       `json:"schema_version"`
	Kind                        string                    `json:"kind"`
	ResourceName                string                    `json:"resource_name"`
	SelectedRoster              []string                  `json:"selected_roster"`
	SelectedCount               int                       `json:"selected_count"`
	RosterSHA256                string                    `json:"roster_sha256"`
	BindingSHA256               string                    `json:"binding_sha256"`
	InstanceNonce               string                    `json:"instance_nonce"`
	Process                     originalNotifyPoolProcess `json:"process"`
	Session                     originalNotifyPoolSession `json:"session"`
	InitializedAt               time.Time                 `json:"initialized_at"`
	ObservedAt                  time.Time                 `json:"observed_at"`
	OriginalAcquisitionCalls    int                       `json:"original_acquisition_calls"`
	OriginalAcquisitionReturned *bool                     `json:"original_acquisition_returned"`
	OriginalPingReturned        *bool                     `json:"original_ping_returned"`
	IdentityRowsClosed          *bool                     `json:"identity_rows_closed"`
	OriginalIdentityReplySHA256 string                    `json:"original_identity_reply_sha256"`
	CurrentIdentityReplySHA256  string                    `json:"current_identity_reply_sha256"`
	Declarations                struct {
		SourceCommit string `json:"source_commit"`
		ImageDigest  string `json:"image_digest"`
		PodUID       string `json:"pod_uid"`
		CoreLease    string `json:"core_lease"`
	} `json:"declarations"`
	DeclarationStatus string `json:"declaration_status"`
}

type originalNotifyPoolProcess struct {
	BootID           string `json:"boot_id"`
	PID              int    `json:"pid"`
	StartTicks       uint64 `json:"start_ticks"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ExecutableBytes  int64  `json:"executable_bytes"`
}

type originalNotifyPoolSession struct {
	Database         string    `json:"database"`
	DatabaseOID      string    `json:"database_oid"`
	SystemIdentifier string    `json:"system_identifier"`
	Role             string    `json:"role"`
	BackendPID       int       `json:"backend_pid"`
	BackendStart     time.Time `json:"backend_start"`
}

// A declared dependency with no original producer refuses before possible-start
// or any arm. Price, readiness, one available pool or a missing body cannot
// remove an entry from the full sealed resource roster.
func originalNotifyResourcesSupported(p model.CapacityPolicySpec) bool {
	if p.NativeNotifyWindowBinding == nil {
		return true
	}
	for _, resource := range p.NativeNotifyWindowBinding.RequiredResources {
		if resource.Kind != originalNotifyPoolKind || resource.ResourceName != originalNotifyPoolResourceName {
			return false
		}
	}
	return true
}

func originalNotifyPoolNonce(s string) bool {
	decoded, err := hex.DecodeString(s)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == s
}

func originalNotifyPoolRead(p model.CapacityPolicySpec, scope OriginalNotifyWindowScope, resource model.CapacityNativeNotifyResource, read originalNotifyPoolObservation, now time.Time) bool {
	roster, err := json.Marshal([]string{resource.ResourceName})
	if err != nil || read.SchemaVersion != 1 || read.Kind != originalNotifyPoolKind || read.ResourceName != resource.ResourceName || read.BindingSHA256 != resource.BindingSHA256 || read.SelectedCount != 1 || len(read.SelectedRoster) != 1 || read.SelectedRoster[0] != resource.ResourceName || read.RosterSHA256 != capacity.BusinessCreationSHA256(roster) || !originalNotifyPoolNonce(read.InstanceNonce) || read.DeclarationStatus != "declared_unverified" || read.OriginalAcquisitionCalls != 1 || !originalNotifyTrue(read.OriginalAcquisitionReturned, read.OriginalPingReturned, read.IdentityRowsClosed) {
		return false
	}
	process, session := read.Process, read.Session
	if !capacity.NativeProcessNonce(process.BootID) || process.PID < 1 || process.StartTicks == 0 || !originalNotifySHA(process.ExecutableSHA256) || process.ExecutableBytes < 1 || process.ExecutableBytes > 128<<20 || session.Database != resource.Database || session.DatabaseOID != resource.DatabaseOID || session.SystemIdentifier != resource.SystemIdentifier || session.Role != resource.Role || session.BackendPID < 1 || session.BackendStart.IsZero() || read.InitializedAt.IsZero() || session.BackendStart.After(read.InitializedAt.Add(time.Second)) || read.InitializedAt.After(read.ObservedAt) || !capacity.Fresh(read.ObservedAt, now, p.MaxEvidenceAgeSeconds) || read.ObservedAt.After(scope.Deadline) || !originalNotifySHA(read.OriginalIdentityReplySHA256) || !originalNotifySHA(read.CurrentIdentityReplySHA256) {
		return false
	}
	return true
}

func originalNotifyPoolPair(p model.CapacityPolicySpec, scope OriginalNotifyWindowScope, scopeSHA, messageSHA string, identity OriginalNotifyNativeIdentity, resource model.CapacityNativeNotifyResource, record originalNotifyPoolPrerequisite, now time.Time) bool {
	a, e := json.Marshal(record.Actor)
	z, f := json.Marshal(identity)
	if e != nil || f != nil || !bytes.Equal(a, z) || resource.PodName != identity.PodName || !originalNotifySHA(scopeSHA) || !originalNotifySHA(messageSHA) || !now.Before(scope.Deadline) || record.Schema != "notify_native_pool_prerequisite_v1" || record.Kind != originalNotifyPoolKind || record.ResourceName != resource.ResourceName || record.WindowSHA != scopeSHA || record.MessageSHA != messageSHA || record.Before == nil || record.After == nil || !originalNotifyPoolRead(p, scope, resource, *record.Before, now) || !originalNotifyPoolRead(p, scope, resource, *record.After, now) {
		return false
	}
	b, after := record.Before, record.After
	return b.Process == after.Process && b.Session.Database == after.Session.Database && b.Session.DatabaseOID == after.Session.DatabaseOID && b.Session.SystemIdentifier == after.Session.SystemIdentifier && b.Session.Role == after.Session.Role && b.Session.BackendPID == after.Session.BackendPID && b.Session.BackendStart.Equal(after.Session.BackendStart) && b.InstanceNonce == after.InstanceNonce && b.BindingSHA256 == after.BindingSHA256 && b.Declarations == after.Declarations && b.InitializedAt.Equal(after.InitializedAt) && !b.ObservedAt.After(after.ObservedAt) && b.OriginalIdentityReplySHA256 == after.OriginalIdentityReplySHA256 && b.CurrentIdentityReplySHA256 == after.CurrentIdentityReplySHA256
}

func originalNotifyPoolRoster(p model.CapacityPolicySpec, scope OriginalNotifyWindowScope, scopeSHA, messageSHA string, identity OriginalNotifyNativeIdentity, records []originalNotifyPoolPrerequisite) error {
	if p.NativeNotifyWindowBinding == nil {
		return errCapacityBoundAssessment
	}
	var required []model.CapacityNativeNotifyResource
	for _, resource := range p.NativeNotifyWindowBinding.RequiredResources {
		if resource.PodName == identity.PodName {
			required = append(required, resource)
		}
	}
	if len(records) != len(required) || len(records) > 32 || !originalNotifyResourcesSupported(p) {
		return errCapacityBoundAssessment
	}
	now := time.Now().UTC()
	for index, resource := range required {
		if !originalNotifyPoolPair(p, scope, scopeSHA, messageSHA, identity, resource, records[index], now) {
			return errCapacityBoundAssessment
		}
	}
	return nil
}
