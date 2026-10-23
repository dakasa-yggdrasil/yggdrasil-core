package repository

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var ErrOriginalCreateDisposition = errors.New("original accepted create disposition held")

const originalDispositionAWSOriginalSource = "f81697fe298a1df63956af6ac65dd5b7ca937a3d"
const originalDispositionAWS1653OriginalSource = "39bdd1da87adba6ac03432e1602ec62dc63baaad"

func originalDispositionDigest(raw []byte) string {
	s := sha256.Sum256(raw)
	return hex.EncodeToString(s[:])
}
func originalDispositionJSONSHA(value any) string {
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return originalDispositionDigest(raw)
}
func originalDispositionHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// This is validation of a bridge-produced native GET return, never acceptance
// of Root/HTTP input flags. The bridge separately authenticates observer pins.
func validateOriginalDispositionObservation(c model.CapacityOriginalCreateDispositionCandidate, o model.CapacityOriginalCreateDispositionObservation, began, now time.Time, maxAge time.Duration) error {
	r := c.Request
	if maxAge <= 0 {
		return ErrOriginalCreateDisposition
	}
	if maxAge > 30*time.Second {
		maxAge = 30 * time.Second
	}
	adjunct := !r.OriginalAuxiliaryInventoryComplete
	if !adjunct {
		if o.InventoryBasis != "original_accepted_auxiliary_inventory_v1" || r.OriginalCreateActionID != "" {
			return ErrOriginalCreateDisposition
		}
	} else {
		action, err := uuid.Parse(r.OriginalCreateActionID)
		if (r.OriginalAdapterSourceCommit != originalDispositionAWSOriginalSource && r.OriginalAdapterSourceCommit != originalDispositionAWS1653OriginalSource) || err != nil || action == uuid.Nil || action.String() != r.OriginalCreateActionID || c.Receipt.ActionID != r.OriginalCreateActionID || len(r.AuxiliaryResources) != 0 || o.Provider != "aws" || o.InventoryBasis != "aws_original_run_instances_cloudtrail_root_snapshot_absence_v1" || len(o.AuxiliaryResources) != 2 || len(o.NativeReads) != 6 {
			return ErrOriginalCreateDisposition
		}
		if o.AuxiliaryResources[0].Kind != "aws_ebs_snapshot_descendants" || !regexp.MustCompile(`^snap-[0-9a-f]{8,17}$`).MatchString(o.AuxiliaryResources[0].ID) || o.AuxiliaryResources[1].Kind != "aws_network_interface" || !regexp.MustCompile(`^eni-[0-9a-f]{8,17}$`).MatchString(o.AuxiliaryResources[1].ID) {
			return ErrOriginalCreateDisposition
		}
	}
	if o.Schema != model.OriginalCreateDispositionObservationSchema || (o.Provider != "aws" && o.Provider != "hetzner") || o.Provider != originalDispositionProvider(c) ||
		o.Profile != r.Profile || o.Slot != r.Slot || o.GrantID != r.GrantID || o.AttemptID != r.AttemptID || o.RequestSHA256 != r.RequestSHA256 || o.ResourceID != r.ExpectedResourceID || o.ResourceCreatedAt != r.ExpectedResourceCreatedAt || o.OriginalAdapterSourceCommit != r.OriginalAdapterSourceCommit || !originalDispositionHex(o.AdapterSourceCommit, 40) ||
		!o.ResourceAbsenceComplete || !o.AuxiliaryInventoryComplete || !o.SharedResourcesPreserved || o.NativeMutations != 0 || o.GuestAdmissionOrBusinessOrSavingsAuthority || o.AuxiliaryResources == nil || o.NativeReads == nil || len(o.NativeReads) < 1 || len(o.NativeReads) > 64 ||
		o.ObservationStartedAt.IsZero() || o.ObservedAt.Before(o.ObservationStartedAt) || o.ObservationStartedAt.Before(began.Add(-5*time.Second)) || o.ObservedAt.After(now.Add(5*time.Second)) || now.Sub(o.ObservedAt) > maxAge || o.ObservedAt.Sub(o.ObservationStartedAt) > 60*time.Second {
		return ErrOriginalCreateDisposition
	}
	if o.ResourceState != "absent" && !(o.Provider == "aws" && o.ResourceState == "terminated") {
		return ErrOriginalCreateDisposition
	}
	var expected []model.CapacityMutationAuxiliaryResource
	for _, a := range r.AuxiliaryResources {
		if a.RequiresAbsence {
			expected = append(expected, a)
		}
	}
	if adjunct {
		for _, a := range o.AuxiliaryResources {
			expected = append(expected, model.CapacityMutationAuxiliaryResource{Kind: a.Kind, ID: a.ID, RequiresAbsence: true})
		}
	}
	if len(expected) == 0 || len(expected) > 16 || len(o.AuxiliaryResources) != len(expected) {
		return ErrOriginalCreateDisposition
	}
	for i, a := range expected {
		got := o.AuxiliaryResources[i]
		at, err := time.Parse(time.RFC3339Nano, got.ObservedAt)
		if got.Kind != a.Kind || got.ID != a.ID || !got.Absent || err != nil || at.Before(o.ObservationStartedAt) || at.After(o.ObservedAt) {
			return ErrOriginalCreateDisposition
		}
	}
	serverRead := false
	covered := map[string]bool{}
	var previous time.Time
	totalBytes := int64(0)
	for _, read := range o.NativeReads {
		if read.Operation == "" || len(read.Operation) > 128 || read.ResourceKind == "" || read.ResourceID == "" || len(read.ResourceID) > 256 || read.Status < 200 || read.Status > 499 || read.Status >= 300 && read.Status != 400 && read.Status != 404 || !originalDispositionHex(read.ResponseSHA256, 64) || read.ResponseBytes < 1 || read.ResponseBytes > 64<<10 || read.CalledAt.Before(o.ObservationStartedAt) || read.ReturnedAt.Before(read.CalledAt) || read.ReturnedAt.After(o.ObservedAt) || !previous.IsZero() && read.CalledAt.Before(previous) {
			return ErrOriginalCreateDisposition
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(read.ResponseBodyBase64)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != read.ResponseBodyBase64 || int64(len(raw)) != read.ResponseBytes || originalDispositionDigest(raw) != read.ResponseSHA256 || (read.ResponseRepresentation != "raw_http_body_v1" && read.ResponseRepresentation != "canonical_provider_SDK_result_v1") {
			return ErrOriginalCreateDisposition
		}
		if read.ResponseRepresentation == "canonical_provider_SDK_result_v1" && !json.Valid(raw) {
			return ErrOriginalCreateDisposition
		}
		totalBytes += read.ResponseBytes
		if totalBytes > 1<<20 {
			return ErrOriginalCreateDisposition
		}
		previous = read.ReturnedAt
		if read.ResourceID == o.ResourceID && (o.Provider == "aws" && read.ResourceKind == "aws_ec2_instance" || o.Provider == "hetzner" && read.ResourceKind == "server") {
			serverRead = true
		}
		covered[read.ResourceKind+"/"+read.ResourceID] = true
	}
	if !serverRead {
		return ErrOriginalCreateDisposition
	}
	if adjunct && validateOriginalDispositionAWSAdjunctCoverage(o) != nil {
		return ErrOriginalCreateDisposition
	}
	for _, a := range expected {
		if !covered[a.Kind+"/"+a.ID] {
			return ErrOriginalCreateDisposition
		}
	}
	return nil
}

func originalDispositionProvider(c model.CapacityOriginalCreateDispositionCandidate) string {
	var spec model.CapacityPolicySpec
	if json.Unmarshal(c.OriginalPolicy.Spec, &spec) != nil {
		return ""
	}
	for _, p := range spec.Profiles {
		if p.Name == c.Binding.ProfileName {
			return p.Provider
		}
	}
	return ""
}

// Completeness is produced by the independently pinned observer. These six
// separately retained native originals cannot be replaced by duplicate labels,
// a Root flag, filtered tag emptiness, or an unchanged false owning inventory.
func validateOriginalDispositionAWSAdjunctCoverage(o model.CapacityOriginalCreateDispositionObservation) error {
	expected := map[string]string{"GetCallerIdentity": "aws_account", "DescribeInstances": "aws_ec2_instance", "LookupEvents": "aws_cloudtrail_event", "DescribeImages": "aws_ami", "DescribeVolumes": "aws_ebs_snapshot_descendants", "DescribeNetworkInterfaces": "aws_network_interface"}
	seen := map[string]bool{}
	for _, r := range o.NativeReads {
		kind, ok := expected[r.Operation]
		if !ok || kind != r.ResourceKind || seen[r.Operation] {
			return ErrOriginalCreateDisposition
		}
		seen[r.Operation] = true
		switch r.Operation {
		case "GetCallerIdentity":
			if r.Status != 200 || !regexp.MustCompile(`^[0-9]{12}$`).MatchString(r.ResourceID) {
				return ErrOriginalCreateDisposition
			}
		case "DescribeInstances":
			if r.ResourceID != o.ResourceID || (r.Status != 200 && r.Status != 400) || r.Status == 200 && o.ResourceState != "terminated" && !(o.ResourceState == "absent" && originalDispositionAWSExplicitEmptyInstances(r)) || r.Status == 400 && o.ResourceState != "absent" {
				return ErrOriginalCreateDisposition
			}
		case "LookupEvents":
			id, e := uuid.Parse(r.ResourceID)
			if r.Status != 200 || e != nil || id == uuid.Nil || id.String() != r.ResourceID {
				return ErrOriginalCreateDisposition
			}
		case "DescribeImages":
			if r.Status != 200 || !regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`).MatchString(r.ResourceID) {
				return ErrOriginalCreateDisposition
			}
		case "DescribeVolumes":
			if r.Status != 200 || r.ResourceID != o.AuxiliaryResources[0].ID {
				return ErrOriginalCreateDisposition
			}
		case "DescribeNetworkInterfaces":
			if r.Status != 400 || r.ResourceID != o.AuxiliaryResources[1].ID {
				return ErrOriginalCreateDisposition
			}
		}
	}
	if len(seen) != 6 {
		return ErrOriginalCreateDisposition
	}
	return nil
}
