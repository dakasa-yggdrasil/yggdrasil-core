package capacity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

const ObserveGuestBootstrap = "observe_guest_bootstrap"
const GuestBootstrapSchema = "original_guest_bootstrap_v1"
const GuestBootstrapLimit = 65536

func guestUUID(s string) bool {
	v, err := uuid.Parse(s)
	return err == nil && v != uuid.Nil && v.String() == s
}
func guestText(s string, limit int) bool {
	return s != "" && len(s) <= limit && strings.TrimSpace(s) == s && !strings.ContainsAny(s, "\x00\r\n\t")
}

// Validate only the newly declared optional field. Ordinary policy JSON and
// its existing decoder keep their behavior when this field is absent.
func ValidateGuestBootstrapPolicyJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	opening, err := d.Token()
	if err != nil || opening != json.Delim('{') {
		return fmt.Errorf("capacity policy object required")
	}
	seen := false
	for d.More() {
		token, e := d.Token()
		name, ok := token.(string)
		if e != nil || !ok {
			return fmt.Errorf("capacity policy incomplete")
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return fmt.Errorf("capacity policy incomplete")
		}
		if strings.EqualFold(name, "guest_bootstrap_binding") {
			if name != "guest_bootstrap_binding" || seen || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return fmt.Errorf("noncanonical optional Guest binding")
			}
			seen = true
			if e = guestClosedJSON(value, reflect.TypeOf(model.CapacityGuestBootstrapBinding{}), 0); e != nil {
				return e
			}
		}
	}
	_, err = d.Token()
	return err
}

func ValidateGuestBootstrapBinding(p model.CapacityPolicySpec) error {
	g := p.GuestBootstrapBinding
	if g == nil {
		return nil
	}
	n := p.VMNodeMembershipBinding
	if n == nil || ValidateVMNodeMembershipBinding(p) != nil || p.AssessmentBinding != nil || p.HPAExecutionBinding != nil || p.ControllerBinding != nil || !validObservationAdapter(g.Adapter) || g.Mode != GuestBootstrapSchema || g.MaxEvidenceAgeSeconds < 1 || g.MaxEvidenceAgeSeconds > min(30, p.MaxEvidenceAgeSeconds) || (g.EvidenceClass != "owned_provisioner_original" && g.EvidenceClass != "native_qemu_qualification") {
		return fmt.Errorf("fixed optional original Guest binding required")
	}
	u, err := url.Parse(g.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" || !guestText(g.ReadTokenRef, 4096) || !strings.HasPrefix(g.ReadTokenRef, "secret://") {
		return fmt.Errorf("fixed private Guest HTTPS origin required")
	}
	b, err := VMObservationBinding(p, n.MutationBindingName)
	if err != nil || len(g.Members) > b.MaxSlots || len(g.Members) == 0 {
		return fmt.Errorf("bounded original enrolled Guest slots required")
	}
	provider := ""
	for _, profile := range p.Profiles {
		if profile.Name == b.ProfileName {
			provider = profile.Provider
		}
	}
	seenNames, seenResources := map[string]bool{}, map[string]bool{}
	lastSlot := 0
	for _, m := range g.Members {
		e := m.Enrollment
		slot, eSlot := vmApprovedSlot(b, e.Tuple.Slot)
		created, eTime := time.Parse(time.RFC3339Nano, e.Tuple.CreatedAt)
		key, eKey := base64.StdEncoding.DecodeString(m.EnrollmentIssuerKey)
		sig, eSig := base64.StdEncoding.DecodeString(m.EnrollmentSignature)
		raw, eRaw := json.Marshal(e)
		if eSlot != nil || e.Tuple.Slot <= lastSlot || !guestText(m.Name, 64) || seenNames[m.Name] || seenResources[e.Tuple.ResourceID] || e.Schema != "original_guest_enrollment_v1" || e.SourceClass != g.EvidenceClass || e.BindingName != m.Name || e.Tuple.Provider != provider || e.Tuple.InstanceID != b.IntegrationInstanceID || e.Tuple.InstanceChecksum != b.IntegrationChecksum || e.Tuple.TypeID != b.IntegrationTypeID || e.Tuple.TypeChecksum != b.IntegrationTypeChecksum || e.Tuple.ScopeChecksum != b.ScopeChecksum || e.Tuple.ProfileChecksum != slot.DesiredSpec.ProfileChecksum || e.Tuple.Profile != b.ProfileName || !guestText(e.Tuple.ResourceID, 128) || eTime != nil || created.IsZero() || created.UTC().Format(time.RFC3339Nano) != e.Tuple.CreatedAt || !guestUUID(e.BootID) || e.UserDataSHA256 != slot.DesiredSpec.BootstrapSHA256 || !businessSource.MatchString(e.GuestSourceCommit) || !businessSource.MatchString(e.ProvisionerSourceCommit) || e.IssuedAt.IsZero() || eKey != nil || eSig != nil || eRaw != nil || len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), raw, sig) {
			return fmt.Errorf("original operator Guest enrollment refused")
		}
		for _, digest := range []string{e.OriginalNativeResultSHA256, e.HostKeySHA256, e.CredentialPublicKeySHA256, e.ForcedReaderCommandSHA256, e.PayloadSHA256, e.OwnerBinarySHA256, e.ReaderBinarySHA256} {
			if !ValidDigest(digest) {
				return fmt.Errorf("original Guest source digest required")
			}
		}
		seenNames[m.Name], seenResources[e.Tuple.ResourceID] = true, true
		lastSlot = e.Tuple.Slot
	}
	return nil
}

// Closed tags plus required presence, including false/zero native facts. This
// runs on the ORIGINAL HTTP bytes before any Output:any or envelope remarshal.
func guestClosedJSON(raw []byte, typ reflect.Type, depth int) error {
	if depth > 48 || len(raw) > GuestBootstrapLimit || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("closed Guest source unavailable")
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf([]byte{}) {
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return fmt.Errorf("canonical bounded Guest byte string required")
		}
		value, err := base64.StdEncoding.DecodeString(text)
		if err != nil || len(value) > GuestBootstrapLimit || base64.StdEncoding.EncodeToString(value) != text {
			return fmt.Errorf("canonical bounded Guest byte string required")
		}
		return nil
	}
	if typ.Kind() == reflect.Slice {
		var values []json.RawMessage
		if json.Unmarshal(raw, &values) != nil || values == nil || len(values) > 64 {
			return fmt.Errorf("closed Guest array required")
		}
		for _, v := range values {
			if err := guestClosedJSON(v, typ.Elem(), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if typ.Kind() != reflect.Struct || typ.PkgPath() == "time" {
		return nil
	}
	allowed, fields, optional := map[string]bool{}, map[string]reflect.Type{}, map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := strings.Split(f.Tag.Get("json"), ",")
		if tag[0] == "" || tag[0] == "-" {
			continue
		}
		allowed[tag[0]], fields[tag[0]] = true, f.Type
		optional[tag[0]] = len(tag) > 1 && tag[1] == "omitempty"
	}
	members, err := NativeCanonicalObject(raw, allowed)
	if err != nil {
		return err
	}
	for name, t := range fields {
		v, ok := members[name]
		if !ok {
			if optional[name] {
				continue
			}
			return fmt.Errorf("required original Guest fact absent")
		}
		if err := guestClosedJSON(v, t, depth+1); err != nil {
			return err
		}
	}
	return nil
}

func DecodeGuestBootstrapReply(raw []byte, response *model.AdapterExecuteIntegrationResponse) error {
	var envelope struct {
		Operation  string                             `json:"operation"`
		Capability string                             `json:"capability"`
		Status     string                             `json:"status"`
		Output     model.CapacityGuestBootstrapResult `json:"output"`
		Metadata   map[string]json.RawMessage         `json:"metadata"`
	}
	if response == nil || guestClosedJSON(raw, reflect.TypeOf(envelope), 0) != nil || json.Unmarshal(raw, &envelope) != nil || envelope.Operation != ObserveGuestBootstrap || envelope.Capability != ObserveGuestBootstrap || envelope.Status != "observed" || envelope.Metadata == nil || len(envelope.Metadata) != 0 {
		return fmt.Errorf("original Guest reply refused")
	}
	*response = model.AdapterExecuteIntegrationResponse{Operation: envelope.Operation, Capability: envelope.Capability, Status: envelope.Status, Output: envelope.Output, Metadata: map[string]any{}}
	return nil
}

func guestAncestry(ancestry []int, pid int) bool {
	if len(ancestry) == 0 || len(ancestry) > 64 {
		return false
	}
	seen, found := map[int]bool{}, false
	for _, n := range ancestry {
		if n < 1 || seen[n] {
			return false
		}
		seen[n] = true
		found = found || n == pid
	}
	return found
}

// Recompute the native lifecycle join. Source-supplied booleans cannot create
// useful capacity, physical provenance, provider quiescence or caller return.
func JoinGuestBootstrap(p model.CapacityPolicySpec, member model.CapacityGuestMemberBinding, node model.CapacityVMNodeJoin, r model.CapacityGuestBootstrapResult, now time.Time) (model.CapacityGuestBootstrapJoin, error) {
	zero := model.CapacityGuestBootstrapJoin{}
	if ValidateGuestBootstrapBinding(p) != nil || p.GuestBootstrapBinding == nil {
		return zero, fmt.Errorf("optional fixed Guest source unavailable")
	}
	e, o, j := member.Enrollment, r.Observation, r.Observation.Journal
	knownMember := false
	for _, fixed := range p.GuestBootstrapBinding.Members {
		if fixed.Name == member.Name && reflect.DeepEqual(fixed, member) {
			knownMember = true
		}
	}
	raw, err := json.Marshal(j)
	if !knownMember || err != nil || e.IssuedAt.After(now) || e.Tuple.Slot != node.Slot || e.Tuple.ResourceID != node.ResourceID || e.Tuple.CreatedAt != node.ResourceCreatedAt || e.BootID != node.Node.BootID || r.BindingName != member.Name || r.EnrollmentSourceClass != e.SourceClass || !r.OriginalPayloadReturnObserved || r.ProviderMutationQuiescenceKnown || r.WarmResourcesKnown || r.UsefulCapacityKnown || r.RoutingWithdrawnKnown || r.BusinessDrainKnown || r.PhysicalCapacityReleased || o.Schema != GuestBootstrapSchema || o.ReaderSourceCommit != e.GuestSourceCommit || o.ReaderBinarySHA256 != e.ReaderBinarySHA256 || o.ReaderPID < 1 || o.ReaderStartTicks == 0 || o.BootID != e.BootID || o.UserDataSHA256 != e.UserDataSHA256 || !Fresh(o.ObservedAt, now, p.GuestBootstrapBinding.MaxEvidenceAgeSeconds) || BusinessCreationSHA256(raw) != o.JournalSHA256 || j.Schema != GuestBootstrapSchema || j.AdmissionProtocol != "original_guest_bootstrap_prestarter_v1" || !guestUUID(j.InvocationNonce) || j.BootID != e.BootID || j.Tuple != e.Tuple || j.UserDataSHA256 != e.UserDataSHA256 || j.PayloadSHA256 != e.PayloadSHA256 || j.OwnerSourceCommit != e.GuestSourceCommit || j.OwnerBinarySHA256 != e.OwnerBinarySHA256 || j.OwnerPID < 1 || j.OwnerStartTicks == 0 || j.PossibleStartAt.IsZero() || j.PossibleStartAt.After(o.ObservedAt) || !regexpInvocation(j.UnitAtAdmission.InvocationID) || j.UnitAtAdmission.MainPID < 1 || j.UnitAtAdmission.MainPID != j.UnitAtAdmission.ExecMainPID || j.UnitAtAdmission.StartMonotonic == 0 || j.UnitAtAdmission.ExitMonotonic != 0 || !guestAncestry(j.ParentAncestry, j.UnitAtAdmission.MainPID) || o.Unit.InvocationID != j.UnitAtAdmission.InvocationID || o.Unit.ExecMainPID != j.UnitAtAdmission.ExecMainPID || o.Unit.StartMonotonic != j.UnitAtAdmission.StartMonotonic || j.State != "returned" || j.ChildPID < 1 || j.ChildStartTicks == 0 || j.StartedAt == nil || j.OriginalWaitReturnedAt == nil || j.FinalRecordPreparedAt == nil || j.ExitCode == nil || *j.ExitCode != 0 || j.Signal != "" || j.OriginalContextFailed || j.StartedAt.Before(j.PossibleStartAt) || j.OriginalWaitReturnedAt.Before(*j.StartedAt) || j.FinalRecordPreparedAt.Before(*j.OriginalWaitReturnedAt) || j.FinalRecordPreparedAt.After(o.ObservedAt) || math.IsNaN(o.CloudInitFinalFinished) || math.IsInf(o.CloudInitFinalFinished, 0) || o.CloudInitFinalFinished < 0 {
		return zero, fmt.Errorf("original Guest and VM Node lifetimes do not join")
	}
	complete := o.Unit.MainPID == 0 && o.Unit.ExecMainCode == 1 && o.Unit.ExecMainStatus == 0 && o.Unit.ExitMonotonic > o.Unit.StartMonotonic && o.Unit.Result == "success" && (o.Unit.ActiveState == "inactive" || o.Unit.ActiveState == "active") && (o.Unit.SubState == "dead" || o.Unit.SubState == "exited") && o.CloudInitStatus == "done" && o.CloudInitFinalFinished > 0 && !o.CloudInitHasErrors
	if r.BootstrapCompletedKnown != complete {
		return zero, fmt.Errorf("guest completion projection differs from original source")
	}
	return model.CapacityGuestBootstrapJoin{Slot: node.Slot, ResourceID: node.ResourceID, ResourceCreatedAt: node.ResourceCreatedAt, BootID: e.BootID, InvocationNonce: j.InvocationNonce, JournalSHA256: o.JournalSHA256, ObservedAt: o.ObservedAt, EnclosingBootstrapRead: complete, OriginalCallerReturnKnown: false, PhysicalCertificate: false, EvidenceClass: e.SourceClass}, nil
}

func regexpInvocation(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

// Full selected roster only. Zero, duplicate, extra or missing reads HOLD.
func JoinGuestBootstrapRoster(p model.CapacityPolicySpec, nodes []model.CapacityVMNodeJoin, results []model.CapacityGuestBootstrapResult, now time.Time) ([]model.CapacityGuestBootstrapJoin, error) {
	if p.GuestBootstrapBinding == nil || ValidateGuestBootstrapBinding(p) != nil || len(nodes) == 0 || len(nodes) != len(results) || len(nodes) != len(p.GuestBootstrapBinding.Members) {
		return nil, fmt.Errorf("complete selected Guest roster required")
	}
	out := make([]model.CapacityGuestBootstrapJoin, 0, len(nodes))
	last := 0
	for i, node := range nodes {
		if node.Slot <= last {
			return nil, fmt.Errorf("ordered selected Guest roster required")
		}
		last = node.Slot
		member, err := GuestBootstrapMember(p, node.Slot)
		if err != nil {
			return nil, err
		}
		joined, err := JoinGuestBootstrap(p, member, node, results[i], now)
		if err != nil {
			return nil, err
		}
		out = append(out, joined)
	}
	return out, nil
}

func GuestBootstrapMember(p model.CapacityPolicySpec, slot int) (model.CapacityGuestMemberBinding, error) {
	if p.GuestBootstrapBinding != nil {
		for _, member := range p.GuestBootstrapBinding.Members {
			if member.Enrollment.Tuple.Slot == slot {
				return member, nil
			}
		}
	}
	return model.CapacityGuestMemberBinding{}, fmt.Errorf("selected registered Guest enrollment absent")
}

// Decode a typed Result again only for in-process fixtures; production consumes
// the typed original reply assigned by DecodeGuestBootstrapReply above.
func GuestBootstrapResult(value any) (model.CapacityGuestBootstrapResult, error) {
	r, ok := value.(model.CapacityGuestBootstrapResult)
	if !ok {
		return r, fmt.Errorf("original typed Guest reply required")
	}
	return r, nil
}
