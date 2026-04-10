package model

import (
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ManagedSecretRotationPolicy describes when one secret should be rotated.
type ManagedSecretRotationPolicy struct {
	Mode            string `json:"mode,omitempty"`
	RotateAfterDays int    `json:"rotate_after_days,omitempty"`
}

// ManagedSecret stores one namespaced secret owned by the core.
type ManagedSecret struct {
	ID            uuid.UUID                   `json:"id"`
	Namespace     string                      `json:"namespace"`
	Name          string                      `json:"name"`
	Status        string                      `json:"status"`
	Version       int                         `json:"version"`
	Data          map[string]string           `json:"data,omitempty"`
	Metadata      map[string]any              `json:"metadata,omitempty"`
	Rotation      ManagedSecretRotationPolicy `json:"rotation,omitempty"`
	LastRotatedAt time.Time                   `json:"last_rotated_at"`
	ExpiresAt     *time.Time                  `json:"expires_at,omitempty"`
	CreatedAt     time.Time                   `json:"created_at"`
	UpdatedAt     time.Time                   `json:"updated_at"`
}

// UpsertManagedSecretRequest creates or updates one secret record.
type UpsertManagedSecretRequest struct {
	Namespace string                      `json:"namespace,omitempty"`
	Name      string                      `json:"name"`
	Status    string                      `json:"status,omitempty"`
	Data      map[string]string           `json:"data"`
	Metadata  map[string]any              `json:"metadata,omitempty"`
	Rotation  ManagedSecretRotationPolicy `json:"rotation,omitempty"`
	ExpiresAt *time.Time                  `json:"expires_at,omitempty"`
}

// RotateManagedSecretRequest replaces the stored secret material for one existing secret.
type RotateManagedSecretRequest struct {
	Namespace string                      `json:"namespace,omitempty"`
	Name      string                      `json:"name"`
	Data      map[string]string           `json:"data"`
	Metadata  map[string]any              `json:"metadata,omitempty"`
	Rotation  ManagedSecretRotationPolicy `json:"rotation,omitempty"`
	ExpiresAt *time.Time                  `json:"expires_at,omitempty"`
}

// DisableManagedSecretRequest marks one secret as temporarily unavailable.
type DisableManagedSecretRequest struct {
	Namespace string         `json:"namespace,omitempty"`
	Name      string         `json:"name"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// RevokeManagedSecretRequest irreversibly invalidates one secret and clears the stored material.
type RevokeManagedSecretRequest struct {
	Namespace string         `json:"namespace,omitempty"`
	Name      string         `json:"name"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// GetManagedSecretRequest resolves one secret by namespace and name.
type GetManagedSecretRequest struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// ListManagedSecretsRequest filters secret listing.
type ListManagedSecretsRequest struct {
	Namespace string `json:"namespace,omitempty"`
	Status    string `json:"status,omitempty"`
}

// ManagedSecretView is the redacted HTTP-facing representation of one core-managed secret.
type ManagedSecretView struct {
	ID            uuid.UUID                   `json:"id"`
	Namespace     string                      `json:"namespace"`
	Name          string                      `json:"name"`
	Status        string                      `json:"status"`
	Version       int                         `json:"version"`
	Keys          []string                    `json:"keys,omitempty"`
	Data          map[string]string           `json:"data,omitempty"`
	MaskedData    map[string]string           `json:"masked_data,omitempty"`
	Metadata      map[string]any              `json:"metadata,omitempty"`
	Rotation      ManagedSecretRotationPolicy `json:"rotation,omitempty"`
	RotationDue   bool                        `json:"rotation_due,omitempty"`
	Expired       bool                        `json:"expired,omitempty"`
	LastRotatedAt time.Time                   `json:"last_rotated_at"`
	ExpiresAt     *time.Time                  `json:"expires_at,omitempty"`
	CreatedAt     time.Time                   `json:"created_at"`
	UpdatedAt     time.Time                   `json:"updated_at"`
}

// BuildManagedSecretView returns one redacted or full HTTP-safe representation of a managed secret.
func BuildManagedSecretView(secret ManagedSecret, includeValues bool) ManagedSecretView {
	view := ManagedSecretView{
		ID:            secret.ID,
		Namespace:     secret.Namespace,
		Name:          secret.Name,
		Status:        secret.Status,
		Version:       secret.Version,
		Metadata:      secret.Metadata,
		Rotation:      secret.Rotation,
		LastRotatedAt: secret.LastRotatedAt,
		ExpiresAt:     secret.ExpiresAt,
		CreatedAt:     secret.CreatedAt,
		UpdatedAt:     secret.UpdatedAt,
	}
	view.Expired = secret.IsExpired(time.Now().UTC())
	view.RotationDue = secret.IsRotationDue(time.Now().UTC())

	if len(secret.Data) == 0 {
		return view
	}

	view.Keys = make([]string, 0, len(secret.Data))
	view.MaskedData = make(map[string]string, len(secret.Data))
	if includeValues {
		view.Data = make(map[string]string, len(secret.Data))
	}

	for key, value := range secret.Data {
		view.Keys = append(view.Keys, key)
		view.MaskedData[key] = maskManagedSecretValue(value)
		if includeValues {
			view.Data[key] = value
		}
	}
	sort.Strings(view.Keys)
	return view
}

func maskManagedSecretValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if len(value) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(value)-4) + value[len(value)-4:]
}

// IsExpired reports whether the secret should no longer be used.
func (s ManagedSecret) IsExpired(now time.Time) bool {
	if s.ExpiresAt == nil {
		return false
	}
	return !now.Before(s.ExpiresAt.UTC())
}

// IsRotationDue reports whether the stored rotation policy says the secret should be rotated.
func (s ManagedSecret) IsRotationDue(now time.Time) bool {
	if strings.ToLower(strings.TrimSpace(s.Rotation.Mode)) != "scheduled" {
		return false
	}
	if s.Rotation.RotateAfterDays <= 0 || s.LastRotatedAt.IsZero() {
		return false
	}
	deadline := s.LastRotatedAt.UTC().Add(time.Duration(s.Rotation.RotateAfterDays) * 24 * time.Hour)
	return !now.Before(deadline)
}
