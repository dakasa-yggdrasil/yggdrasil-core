package model

// UserPreferences contains Yggdrasil-owned profile fields plus per-user visual
// settings. Profile fields such as preferred name and avatar are canonical
// identity data: connected directory providers must converge to them.
type UserPreferences struct {
	PreferredName string `json:"preferred_name,omitempty"`
	AvatarDataURL string `json:"avatar_data_url,omitempty"`
	AccentColor   string `json:"accent_color,omitempty"`
}

// UpdateUserPreferencesRequest patches the current collaborator's preferences.
// Empty strings clear the corresponding value.
type UpdateUserPreferencesRequest struct {
	PreferredName *string `json:"preferred_name,omitempty"`
	AvatarDataURL *string `json:"avatar_data_url,omitempty"`
	AccentColor   *string `json:"accent_color,omitempty"`
}
