package repository

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

// Parse only in private custody. Configz may contain secrets in unrelated
// fields; neither its body, digest nor a parse error is returned publicly.
func nativeMemberConfigzProjection(raw []byte) (string, string, error) {
	var outer map[string]json.RawMessage
	if len(raw) > model.CapacityNativeWorkerMemberMaxOriginalBytes || capacity.DecodeNativeProbeResourceJSON(raw, &outer) != nil || outer == nil {
		return "", "", errNativeMember
	}
	for k := range outer {
		if !nativeMemberASCII(k) || strings.EqualFold(k, "kubeletconfig") && k != "kubeletconfig" {
			return "", "", errNativeMember
		}
	}
	var config map[string]json.RawMessage
	if json.Unmarshal(outer["kubeletconfig"], &config) != nil || config == nil {
		return "", "", errNativeMember
	}
	if !nativeMemberExactKeys(config, "apiVersion", "kind", "enableServer", "enableDebuggingHandlers", "port", "authorization", "authentication", "featureGates", "staticPodPath", "staticPodURL") {
		return "", "", errNativeMember
	}

	// Effective K3s1.34 config carries these actual serving/authentication facts;
	// omitted static strings alone are not enough to qualify an empty object.
	var enabled, debugging bool
	var port int
	if json.Unmarshal(config["enableServer"], &enabled) != nil || !enabled || json.Unmarshal(config["enableDebuggingHandlers"], &debugging) != nil || !debugging || json.Unmarshal(config["port"], &port) != nil || port != 10250 {
		return "", "", errNativeMember
	}
	var authz struct {
		Mode string `json:"mode"`
	}
	var authn struct {
		X509 struct {
			ClientCAFile string `json:"clientCAFile"`
		} `json:"x509"`
		Anonymous struct {
			Enabled bool `json:"enabled"`
		} `json:"anonymous"`
	}
	// These API objects are extensible. Selected members are read by exact map
	// keys below, so aliases cannot overwrite a typed field through foldName.
	var az, an, x509, anon map[string]json.RawMessage
	if json.Unmarshal(config["authorization"], &az) != nil || az == nil || json.Unmarshal(az["mode"], &authz.Mode) != nil || authz.Mode != "Webhook" || json.Unmarshal(config["authentication"], &an) != nil || an == nil || json.Unmarshal(an["x509"], &x509) != nil || x509 == nil || json.Unmarshal(x509["clientCAFile"], &authn.X509.ClientCAFile) != nil || authn.X509.ClientCAFile == "" {
		return "", "", errNativeMember
	}
	if !nativeMemberExactKeys(az, "mode") || !nativeMemberExactKeys(an, "x509", "anonymous") || !nativeMemberExactKeys(x509, "clientCAFile") {
		return "", "", errNativeMember
	}
	if a, ok := an["anonymous"]; ok {
		if json.Unmarshal(a, &anon) != nil || anon == nil {
			return "", "", errNativeMember
		}
		if !nativeMemberExactKeys(anon, "enabled") {
			return "", "", errNativeMember
		}
		if v, ok := anon["enabled"]; ok {
			if bytes.Equal(bytes.TrimSpace(v), []byte("null")) || json.Unmarshal(v, &authn.Anonymous.Enabled) != nil || authn.Anonymous.Enabled {
				return "", "", errNativeMember
			}
		}
	}
	for key, want := range map[string]string{"apiVersion": "kubelet.config.k8s.io/v1beta1", "kind": "KubeletConfiguration"} {
		if value, ok := config[key]; ok {
			var actual string
			if json.Unmarshal(value, &actual) != nil || actual != want {
				return "", "", errNativeMember
			}
		}
	}
	if gates, ok := config["featureGates"]; ok {
		var values map[string]json.RawMessage
		if json.Unmarshal(gates, &values) != nil || values == nil {
			return "", "", errNativeMember
		}
		if !nativeMemberExactKeys(values, "KubeletFineGrainedAuthz") {
			return "", "", errNativeMember
		}
		if raw, ok := values["KubeletFineGrainedAuthz"]; ok {
			var enabled bool
			if json.Unmarshal(raw, &enabled) != nil || !enabled {
				return "", "", errNativeMember
			}
		}
	}
	var path, url string
	if r, ok := config["staticPodPath"]; ok {
		if json.Unmarshal(r, &path) != nil || bytes.Equal(bytes.TrimSpace(r), []byte("null")) {
			return "", "", errNativeMember
		}
	}
	if r, ok := config["staticPodURL"]; ok {
		if json.Unmarshal(r, &url) != nil || bytes.Equal(bytes.TrimSpace(r), []byte("null")) {
			return "", "", errNativeMember
		}
	}
	return path, url, nil
}
func nativeMemberExactKeys(m map[string]json.RawMessage, selected ...string) bool {
	for k := range m {
		if !nativeMemberASCII(k) {
			return false
		}
		for _, want := range selected {
			if strings.EqualFold(k, want) && k != want {
				return false
			}
		}
	}
	return true
}
func nativeMemberASCII(s string) bool {
	for _, r := range s {
		if r > 127 || r == utf8.RuneError {
			return false
		}
	}
	return true
}

func (st *nativeMemberStoreState) verifyConfigz(ctx context.Context, c model.CapacityNativeWorkerMemberContext, o model.CapacityNativeWorkerMemberObservation, now time.Time) error {
	if o.Configuration == nil {
		if c.Action == "delete_node" || c.Action == "retire_registry" {
			return nil
		}
		return errNativeMember
	}
	id, e := nativeMemberUUID(o.ReadID)
	if e != nil {
		return e
	}
	var raw []byte
	e = st.workers.Capacity.DB.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_reads WHERE id=$1 AND permit_id=$2 AND policy_id=$3 AND namespace=$4 AND state='captured'`, id, c.PermitID, st.policy.ID, st.policy.Metadata.Namespace).Scan(&raw)
	var r nativeMemberReadRecord
	if e != nil || nativeMemberDecode(raw, &r) != nil || r.ReadID != id || r.PermitID.String() != c.PermitID || r.ContextSHA256 != capacity.NativeWorkerMemberContextSHA(c) || r.SubjectNodeUID != o.Configuration.NodeUID || r.SDKSourceCommit != c.Observer.SourceCommit || r.ScopeSHA256 != c.Observer.ScopeSHA256 || r.Kind != "kubelet_configz" || r.PrivateOriginal == nil {
		return errNativeMember
	}
	_, plain, e := st.crypt(c, "read/"+id.String(), r.PrivateOriginal, nil)
	defer clear(plain)
	var original model.CapacityNativeWorkerMemberReadOriginal
	var envelope nativeMemberPrivateOriginal
	if e == nil {
		e = nativeMemberDecode(plain, &envelope)
	}
	if e != nil || nativeMemberDecode(envelope.Wire, &original) != nil || envelope.BodySHA256 != nativeMemberRawSHA(original.OriginalReturn) || original.Schema != model.CapacityNativeWorkerMemberReadOriginalSchema || original.BindingName != c.Observer.BindingName || original.ReadID != id.String() || original.PermitID != c.PermitID || original.Kind != r.Kind || !original.CaptureComplete || !original.TransportCompleted || original.ErrorClass != "" || original.HTTPStatus != 200 || original.CompletedAt.Before(r.CreatedAt) || original.CompletedAt.After(now) || !original.CompletedAt.Equal(o.Configuration.ObservedAt) {
		return errNativeMember
	}
	path, url, e := nativeMemberConfigzProjection(original.OriginalReturn)
	if e != nil || path != o.Configuration.StaticPodPath || url != o.Configuration.StaticPodURL || path != "" || url != "" {
		return errNativeMember
	}
	return nil
}

func nativeMemberReadLoadTx(ctx context.Context, tx *sql.Tx, p model.Manifest, id uuid.UUID) (nativeMemberReadRecord, error) {
	var r nativeMemberReadRecord
	var raw []byte
	e := tx.QueryRowContext(ctx, `SELECT CASE WHEN octet_length(record::text)<=8388608 THEN record END FROM public.capacity_native_worker_member_reads WHERE id=$1 AND policy_id=$2 AND namespace=$3 FOR UPDATE`, id, p.ID, p.Metadata.Namespace).Scan(&raw)
	if e != nil || nativeMemberDecode(raw, &r) != nil || r.ReadID != id {
		return r, errNativeMember
	}
	return r, nil
}

// Status is an ACK only. In particular Eviction 429/409 may already have PDB
// or DisruptionTarget effects: neither code releases the in-flight right.
// Only the atomic cordon JSON-Patch precondition failure has a closed no-effect
// classifier, inherited from the already qualified native PATCH implementation.
func nativeMemberDefinitiveNoEffect(c model.CapacityNativeWorkerMemberContext, o model.CapacityNativeWorkerMemberReceive) bool {
	return c.Action == "cordon" && o.CaptureComplete && o.TransportCompleted && o.ErrorClass == "" && nativePhaseDefinitiveNoEffect(o.HTTPStatus, o.OriginalReturn)
}

// Raw original and raw SHA are encrypted together. Neither this envelope nor
// any parse error crosses a public DTO, event, log or workflow metadata.
type nativeMemberPrivateOriginal struct {
	Wire       json.RawMessage `json:"wire"`
	BodySHA256 string          `json:"body_sha256"`
}

func (nativeMemberPrivateOriginal) String() string {
	return "[private native member original envelope]"
}
func (v nativeMemberPrivateOriginal) GoString() string           { return v.String() }
func (nativeMemberPrivateOriginal) MarshalJSON() ([]byte, error) { return nil, errNativeMember }
func nativeMemberPackOriginal(wire, body []byte) ([]byte, error) {
	type private nativeMemberPrivateOriginal
	return json.Marshal(private{Wire: append(json.RawMessage(nil), wire...), BodySHA256: nativeMemberRawSHA(body)})
}
