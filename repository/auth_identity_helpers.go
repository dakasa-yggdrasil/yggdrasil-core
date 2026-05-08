package repository

import (
	"encoding/json"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/lib/pq"
)

// pgTextArray wraps a Go []string for use with lib/pq's TEXT[] driver.
func pgTextArray(in []string) interface{} {
	if in == nil {
		in = []string{}
	}
	return pq.Array(in)
}

// decodeWebAuthnCredentials parses the JSONB column into typed values; on
// malformed JSON it returns an empty slice rather than failing the caller.
func decodeWebAuthnCredentials(blob []byte) []model.WebAuthnCredential {
	if len(blob) == 0 {
		return nil
	}
	var creds []model.WebAuthnCredential
	if err := json.Unmarshal(blob, &creds); err != nil {
		return nil
	}
	return creds
}
