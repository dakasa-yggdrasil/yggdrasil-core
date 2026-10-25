package repository

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

var guestIssueKind = regexp.MustCompile(`^[a-z_]{1,64}$`)

// This insert shares the issue transaction. Failure aborts the issue; ordinary
// best-effort ops logging never substitutes for actual-issuer provenance.
func (s CapacityStore) recordGuestAuthorityIssueTx(ctx context.Context, tx *sql.Tx, policy model.Manifest, p model.CapacityPolicySpec, binding model.CapacityGuestRetirementBinding, kind, id, wireSHA string, payload ...[]byte) error {
	if binding.EvidenceClass != "owned_provisioner_original" {
		return nil
	}
	actual := capacity.CurrentGuestCoreSource()
	identifier, err := uuid.Parse(id)
	if err != nil || identifier == uuid.Nil || identifier.String() != id || !guestIssueKind.MatchString(kind) || !capacity.ValidDigest(wireSHA) || !capacity.GuestBindingAuthorityCurrent(p, binding) || !validCapacityExecutor(s.ExecutorID) || s.WorkflowID == uuid.Nil {
		return ErrCapacityConflict
	}
	marker := ""
	if kind == "installed_reconcile" {
		if len(payload) != 1 || len(payload[0]) == 0 || capacity.BusinessCreationSHA256(payload[0]) != wireSHA {
			return ErrCapacityConflict
		}
		marker = base64.StdEncoding.EncodeToString(payload[0])
	} else if len(payload) != 0 {
		return ErrCapacityConflict
	}
	record := struct {
		Schema        string `json:"schema"`
		Kind          string `json:"issue_kind"`
		ID            string `json:"issue_id"`
		Actual        string `json:"issuer_actual_source_commit"`
		Authority     string `json:"protocol_authority_source_commit"`
		Compatibility string `json:"compatibility_map_sha256"`
		Profile       string `json:"profile"`
		Policy        string `json:"policy_id"`
		Workflow      string `json:"workflow_id"`
		Executor      string `json:"executor_id"`
		Wire          string `json:"issued_wire_sha256"`
		Marker        string `json:"installed_reconcile_marker_base64,omitempty"`
	}{"guest_authority_issue_v1", kind, id, actual, binding.CoreAuthoritySourceCommit, capacity.GuestProtocolCompatibilityMapSHA256(), binding.ProfileManifest.Profile, policy.ID.String(), s.WorkflowID.String(), s.ExecutorID, wireSHA, marker}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(raw) > 16*1024 {
		return ErrCapacityConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO public.capacity_guest_authority_issues(issue_kind,issue_id,issuer_actual_source_commit,protocol_authority_source_commit,compatibility_map_sha256,profile,policy_id,workflow_id,executor_id,issued_wire_sha256,original_wire,original_record) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb)`, kind, id, actual, binding.CoreAuthoritySourceCommit, record.Compatibility, record.Profile, policy.ID, s.WorkflowID, s.ExecutorID, wireSHA, raw, string(raw))
	return err
}

// Historical C11 contexts remain their original C11 facts. A successor context
// must carry the separately atomic actual-issuer record; it never rewrites the
// legacy signed authority field or treats that field as a new build identity.
func verifyGuestAuthorityIssuerTx(ctx context.Context, tx *sql.Tx, kind, id, actual string, binding model.CapacityGuestRetirementBinding) error {
	if actual == binding.CoreAuthoritySourceCommit {
		return nil
	}
	if len(actual) != 40 {
		return ErrCapacityConflict
	}
	var valid bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM public.capacity_guest_authority_issues WHERE issue_kind=$1 AND issue_id=$2 AND issuer_actual_source_commit=$3 AND protocol_authority_source_commit=$4 AND compatibility_map_sha256=$5 AND profile=$6)`, kind, id, actual, binding.CoreAuthoritySourceCommit, capacity.GuestProtocolCompatibilityMapSHA256(), binding.ProfileManifest.Profile).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrCapacityConflict
	}
	return nil
}
