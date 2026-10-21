package model

import "time"

// ProviderNativeIdentity is the independent native provider read that Core
// joins to the original authenticated creation before signing Guest evidence.
// It carries immutable identity, not kernel boot identity or application health.
type CapacityGuestProviderNativeIdentity struct {
	Schema              string    `json:"schema"`
	Provider            string    `json:"provider"`
	ResourceID          string    `json:"resource_id"`
	ResourceCreatedAt   string    `json:"resource_created_at"`
	Region              string    `json:"region"`
	Location            string    `json:"location"`
	Zone                string    `json:"zone"`
	TypeID              string    `json:"type_id"`
	ImageID             string    `json:"image_id"`
	AccountID           string    `json:"account_id"`
	Hostname            string    `json:"hostname"`
	ObservedAt          time.Time `json:"observed_at"`
	AdapterSourceCommit string    `json:"adapter_source_commit"`
}
