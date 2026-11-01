package repository

import (
	"bytes"
	"encoding/json"
	"io"
	"regexp"
)

// FailedInstalledDisposalRead is an observation only. The fallback does not
// support claims, retirement, cleanup or replacement under the newer contract.
type FailedInstalledDisposalRead struct {
	ReplacementMode                string `json:"replacement_mode,omitempty"`
	OriginalFailedIssuerCoreSource string `json:"original_failed_issuer_core_source,omitempty"`
	ReplacementCoreSource          string `json:"replacement_core_source,omitempty"`
	FailedInstalledGuestDisposal
}

var failedInstalledReadSource = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Keep this separate from decodeFailedInstalledDisposal, which protects the
// mutating paths. Exact bytes and the closed new marker are required.
func decodeFailedInstalledDisposalRead(raw []byte) (FailedInstalledDisposalRead, error) {
	var legacy FailedInstalledGuestDisposal
	if err := decodeFailedInstalledDisposal(raw, &legacy); err == nil {
		return FailedInstalledDisposalRead{FailedInstalledGuestDisposal: legacy}, nil
	}
	var read FailedInstalledDisposalRead
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&read) != nil || d.Decode(new(any)) != io.EOF {
		return FailedInstalledDisposalRead{}, ErrCapacityConflict
	}
	canonical, err := json.Marshal(read)
	if err != nil || !bytes.Equal(canonical, raw) ||
		read.ReplacementMode != "original_canary_core_bound_v1" || read.RetirementMode != failedInstalledV2Mode ||
		!failedInstalledReadSource.MatchString(read.OriginalFailedIssuerCoreSource) ||
		!failedInstalledReadSource.MatchString(read.ReplacementCoreSource) ||
		read.OriginalFailedIssuerCoreSource == read.ReplacementCoreSource || read.ReplacementCoreSource != read.ActualCoreSource {
		return FailedInstalledDisposalRead{}, ErrCapacityConflict
	}
	return read, nil
}
