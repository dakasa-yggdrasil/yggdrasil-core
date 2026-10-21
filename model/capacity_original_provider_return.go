package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// CapacityOriginalProviderCreateReturn is the authenticated adapter's original
// native create return, retained in its single immutable settlement. It contains
// no native body, token, credential, admission or product-readiness assertion.
type CapacityOriginalProviderCreateReturn struct {
	Schema              string   `json:"schema"`
	Provider            string   `json:"provider"`
	AdapterSourceCommit string   `json:"adapter_source_commit"`
	GrantID             string   `json:"grant_id"`
	AttemptID           string   `json:"attempt_id"`
	RequestSHA256       string   `json:"request_sha256"`
	ResourceID          string   `json:"resource_id"`
	ResourceCreatedAt   string   `json:"resource_created_at"`
	ActionID            string   `json:"action_id"`
	NextActionIDs       []string `json:"next_action_ids"`
	CalledAt            string   `json:"called_at"`
	ReturnedAt          string   `json:"returned_at"`
	ContextDeadline     string   `json:"context_deadline"`
	ResponseStatus      int      `json:"response_status"`
	ResponseBodySHA256  string   `json:"response_body_sha256"`
	ResponseBytes       int64    `json:"response_bytes"`
}

// An optional outer field does not make the inner original optional or permit
// case folding, duplicate members, unknown authority or omitted zero values.
func (r *CapacityOriginalProviderCreateReturn) UnmarshalJSON(raw []byte) error {
	if len(raw) > 16384 {
		return fmt.Errorf("original provider return exceeds bound")
	}
	keys := map[string]bool{"schema": false, "provider": false, "adapter_source_commit": false, "grant_id": false, "attempt_id": false, "request_sha256": false, "resource_id": false, "resource_created_at": false, "action_id": false, "next_action_ids": false, "called_at": false, "returned_at": false, "context_deadline": false, "response_status": false, "response_body_sha256": false, "response_bytes": false}
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return fmt.Errorf("closed original provider object required")
	}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		seen, known := keys[key]
		if err != nil || !ok || !known || seen {
			return fmt.Errorf("original provider member refused")
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("original provider value missing")
		}
		keys[key] = true
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("original provider trailing data")
	}
	for _, seen := range keys {
		if !seen {
			return fmt.Errorf("original provider member missing")
		}
	}
	type plain CapacityOriginalProviderCreateReturn
	var parsed plain
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return err
	}
	*r = CapacityOriginalProviderCreateReturn(parsed)
	return nil
}

// The wire is equally closed, while its distinct settlement field/schema
// prevent any create reply from being repurposed as TerminateInstances truth.
type CapacityOriginalProviderDestroyReturn = CapacityOriginalProviderCreateReturn
