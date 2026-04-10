package model

// PingResponse is the canonical template response payload.
type PingResponse struct {
	Service string `json:"service"`
	Message string `json:"message"`
}
