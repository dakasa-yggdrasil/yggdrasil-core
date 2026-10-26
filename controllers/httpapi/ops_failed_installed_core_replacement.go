package httpapi

import (
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"io"
)

// IDs and an optional closed mode only: no caller-supplied Core, Guest, profile,
// retirement authority, deadline or readiness assertion can enter the ledger.
func decodeFailedInstalledGuestDisposalRequest(r io.Reader) (string, string, string, error) {
	d := json.NewDecoder(r)
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return "", "", "", repository.ErrCapacityMutationAuthorization
	}
	values := map[string]string{}
	for d.More() {
		token, e := d.Token()
		key, ok := token.(string)
		_, duplicate := values[key]
		if e != nil || !ok || duplicate || (key != "preregistration_id" && key != "expected_failed_run_id" && key != "replacement_mode") {
			return "", "", "", repository.ErrCapacityMutationAuthorization
		}
		var value string
		if d.Decode(&value) != nil {
			return "", "", "", repository.ErrCapacityMutationAuthorization
		}
		if key == "replacement_mode" {
			if value != repository.FailedInstalledCoreReplacementMode {
				return "", "", "", repository.ErrCapacityMutationAuthorization
			}
		} else if !dispositionGrantID(value) {
			return "", "", "", repository.ErrCapacityMutationAuthorization
		}
		values[key] = value
	}
	if token, e := d.Token(); e != nil || token != json.Delim('}') {
		return "", "", "", repository.ErrCapacityMutationAuthorization
	}
	if values["preregistration_id"] == "" || values["expected_failed_run_id"] == "" || d.Decode(new(any)) != io.EOF {
		return "", "", "", repository.ErrCapacityMutationAuthorization
	}
	return values["preregistration_id"], values["expected_failed_run_id"], values["replacement_mode"], nil
}
