package model

import "time"

// PhoneContact is returned only by an explicitly authorized contact route.
// Neither assurance nor E.164 formatting proves verification or consent.
type PhoneContact struct {
	CollaboratorID    string    `json:"collaborator_id"`
	PhoneE164         string    `json:"phone_e164"`
	Assurance         string    `json:"assurance"`
	DeclarationSource string    `json:"declaration_source"`
	DeclaredAt        time.Time `json:"declared_at"`
	Version           int64     `json:"version"`
}

type SelfPhoneContactResponse struct {
	Required     bool          `json:"required"`
	PhoneContact *PhoneContact `json:"phone_contact,omitempty"`
}
