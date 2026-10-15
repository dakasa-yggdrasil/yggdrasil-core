//go:build linux && nativequalification

package capacityhostfactory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"golang.org/x/sys/unix"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Source assembly input: source9-original-test-prefix.go.txt
// These ADD Source/protocol cases. Their fixture identities/primitive hashes
// cannot install a realm or qualify a native observation, NoStart, old45,
// ordinary QEMU, physical provider, capacity permission or a production class.
const fixtureOnly = "source_fixture_only_no_native_seal"

func fixtureLedger(t *testing.T) (*originalLedger, *callHandle) {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	t.Cleanup(cancel)
	l, err := newLedger(ctx, "00000000-0000-4000-8000-000000000001", "host_exterior", strings.Repeat("1", 64), "original_host_factory_source_approval_v4", strings.Repeat("2", 64))
	if err != nil {
		t.Fatal(fixtureOnly, " ledger refusal")
	}
	h, err := l.handle()
	if err != nil {
		t.Fatal(fixtureOnly, " handle refusal")
	}
	return l, h
}

func TestOriginalFactoryDefaultRegistryUnavailable(t *testing.T) {
	for _, directory := range []string{"", t.TempDir(), "/tmp/foreign-root", "../relative"} {
		if realm, err := NewOriginalFactoryRealm(context.Background(), directory); err == nil || realm != nil {
			t.Fatal(fixtureOnly, " registry installed from directory")
		}
	}
	if _, err := capacity.ApprovedHostFactorySource(); err == nil {
		t.Fatal(fixtureOnly, " empty approval selector admitted")
	}
}

func TestOriginalFactoryZeroRealmCannotAuthorize(t *testing.T) {
	ctx := context.Background()
	r := &OriginalFactoryRealm{}
	cases := []struct {
		name  string
		check func() error
	}{
		{"live", func() error { return r.VerifyLive(ctx) }},
		{"initial", func() error { _, _, e := r.InitialObservation(ctx); return e }},
		{"assessment", func() error { _, e := r.InitialAssessment(ctx); return e }},
		{"identity", func() error { _, _, _, e := r.OriginalRootIdentity(ctx); return e }},
		{"rootstages", func() error { _, e := r.OriginalRootStages(ctx); return e }},
		{"awaitingcheck", func() error { return r.CheckOriginalAwaitingOwnerTransaction(ctx, "", []byte(`{}`)) }},
		{"awaitingreturn", func() error {
			return r.CaptureOriginalAwaitingOwnerReturn(ctx, "", []byte(`{}`), time.Now(), time.Now())
		}},
		{"claimbind", func() error {
			return r.BindOriginalInvocation(ctx, "00000000-0000-4000-8000-000000000001", model.Manifest{}, model.Manifest{}, model.WorkflowStepSpec{}, model.WorkflowStepSpec{}, model.WorkflowStepSpec{}, model.CapacityAssessment{})
		}},
		{"claimtx", func() error { return r.CheckOriginalClaimTransaction(ctx, "", model.CapacityIntent{}, []byte(`{}`)) }},
		{"claimreturn", func() error {
			return r.CaptureOriginalClaimReturn(ctx, "", model.CapacityIntent{}, []byte(`{}`), time.Now(), time.Now())
		}},
		{"currentlease", func() error {
			return r.CaptureOriginalCurrentLeaseRead(ctx, "", model.CapacityIntent{}, time.Now(), time.Now())
		}},
		{"leaseraw", func() error { _, _, e := r.OriginalLeaseProvenance(ctx, ""); return e }},
		{"bodygetter", func() error { _, e := r.OriginalAuthorityBody(ctx, "preauthority-scope"); return e }},
		{"signatureoracle", func() error { _, e := r.SignOriginalAuthority(ctx, "preauthority-scope", []byte(`{}`)); return e }},
		{"stage", func() error { return r.VerifyOriginalStage(ctx, "native-leaf-worker", []byte(`{}`)) }},
		{"grant", func() error {
			return r.CaptureOriginalGrantBinding(ctx, model.CapacityMutationGrant{}, model.CapacityGuestOriginalProvisioningPreregistration{}, []byte(`{}`), []byte(`{}`))
		}},
		{"seal", func() error { _, e := r.SealOriginal(ctx, []byte(`{}`)); return e }},
		{"ordinary", func() error { return r.VerifyOriginalOrdinaryGuard(ctx, model.FactoryOrdinaryGuardRead{}, nil, nil) }},
		{"guardfirst", func() error { _, e := r.OriginalOrdinaryGuardEnvelope(ctx, "before_redeem", "", "", ""); return e }},
		{"guardreserve", func() error { return r.ReserveOriginalOrdinaryGuardRead(ctx, "before_redeem", "", "", "") }},
		{"guardcapture", func() error {
			_, _, e := r.CaptureOriginalOrdinaryGuardRead(ctx, "before_redeem", "", nil, nil, nil, nil, nil, time.Now(), time.Now())
			return e
		}},
		{"guardfailure", func() error {
			return r.CaptureOriginalOrdinaryGuardFailure(ctx, "before_redeem", "", nil, nil, nil, nil, nil, time.Now(), time.Now(), errors.New("original failure"))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.check() == nil {
				t.Fatal(fixtureOnly, " zero realm admitted")
			}
		})
	}
}

func TestOriginalFactoryPrivateFullGrantRecordDecode(t *testing.T) {
	// Closed-record grammar ONLY. This fixture cannot provide an approved
	// Realm/key/Claim/native owner/Issue or establish a capacity permission.
	record := privateIssuedGrantRecord{Grant: model.CapacityMutationGrant{GrantID: "00000000-0000-4000-8000-000000000001", State: "issued"}, Binding: model.CapacityMutationBinding{Slots: []model.CapacityMutationSlotBinding{}}, CreatedAt: time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)}
	raw, e := json.Marshal(record)
	if e != nil {
		t.Fatal(fixtureOnly, " marshal refused")
	}
	var nullProjection map[string]json.RawMessage
	if json.Unmarshal(raw, &nullProjection) != nil {
		t.Fatal(fixtureOnly, " fixture invalid")
	}
	nullProjection["grant"] = json.RawMessage("null")
	nullRaw, e := json.Marshal(nullProjection)
	if e != nil {
		t.Fatal(fixtureOnly, " fixture null invalid")
	}
	cases := []struct {
		name  string
		raw   []byte
		valid bool
	}{
		{"full_record", raw, true},
		{"whitespace_retained_not_remarshal", append(append([]byte("\n "), raw...), byte('\n')), true},
		{"bare_grant_not_full_record", []byte(`{"grant_id":"00000000-0000-4000-8000-000000000001","state":"issued"}`), false},
		{"duplicate_outer", bytes.Replace(raw, []byte(`"policy_id":`), []byte(`"policy_id":"foreign","policy_id":`), 1), false},
		{"folded_key_alias", bytes.Replace(raw, []byte(`"policy_id":`), []byte(`"Policy_ID":`), 1), false},
		{"nested_unknown", bytes.Replace(raw, []byte(`"grant":{`), []byte(`"grant":{"unknown":true,`), 1), false},
		{"prior_redeem_in_first", bytes.Replace(raw, []byte(`"grant":`), []byte(`"attempt_id":"00000000-0000-4000-8000-000000000002","grant":`), 1), false},
		{"trailing_json", append(bytes.Clone(raw), []byte(`{}`)...), false},
		{"non_utf8", append(bytes.Clone(raw), byte(0xff)), false},
		{"required_null", nullRaw, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			original := bytes.Clone(c.raw)
			var decoded privateIssuedGrantRecord
			err := decodePrivateOriginalJSON(c.raw, &decoded)
			if (err == nil) != c.valid || !bytes.Equal(c.raw, original) {
				t.Fatal(fixtureOnly, " decode/retained-original mismatch")
			}
			if c.valid && decoded.Grant.GrantID != record.Grant.GrantID {
				t.Fatal(fixtureOnly, " projection mismatch")
			}
		})
	}
}

func TestOriginalFactoryPrivateOriginalByteCodec(t *testing.T) {
	// Private byte representation ONLY. Successful decoding is not Source
	// custody, a transferred-file classification or a native permission.
	type privateByteRecord struct {
		Raw *[]byte `json:"raw"`
	}
	cases := []struct {
		name  string
		raw   []byte
		valid bool
		known bool
		want  []byte
	}{
		{"original_binary_bytes", []byte(`{"raw":"AP+A"}`), true, true, []byte{0, 0xff, 0x80}},
		{"known_empty_is_not_null", []byte(`{"raw":""}`), true, true, []byte{}},
		{"explicit_null_stays_unavailable", []byte(`{"raw":null}`), true, false, nil},
		{"required_null_cannot_be_omitted", []byte(`{}`), false, false, nil},
		{"numeric_byte_array_refused", []byte(`{"raw":[0,255,128]}`), false, false, nil},
		{"utf8_string_is_not_byte_encoding", []byte(`{"raw":"não"}`), false, false, nil},
		{"base64_newline_refused", []byte(`{"raw":"AP+A\n"}`), false, false, nil},
		{"url_base64_refused", []byte(`{"raw":"_w=="}`), false, false, nil},
		{"noncanonical_padding_bits_refused", []byte(`{"raw":"/x=="}`), false, false, nil},
		{"missing_padding_refused", []byte(`{"raw":"/w"}`), false, false, nil},
		{"escaped_base64_alias_refused", []byte(`{"raw":"\/w=="}`), false, false, nil},
		{"numeric_scalar_refused", []byte(`{"raw":255}`), false, false, nil},
		{"oversized_private_record_refused", []byte(`{"raw":"` + strings.Repeat("A", bodyLimit) + `"}`), false, false, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			original := bytes.Clone(c.raw)
			var decoded privateByteRecord
			err := decodePrivateOriginalJSON(c.raw, &decoded)
			if (err == nil) != c.valid || !bytes.Equal(c.raw, original) {
				t.Fatal(fixtureOnly, " private byte grammar or original bytes changed")
			}
			if c.valid && ((decoded.Raw != nil) != c.known || c.known && (!bytes.Equal(*decoded.Raw, c.want) || *decoded.Raw == nil)) {
				t.Fatal(fixtureOnly, " known bytes were aliased to unknown or changed")
			}
		})
	}
	// Keep the existing non-byte slice grammar rather than interpreting every
	// uint8-related or custom JSON type as the built-in byte representation.
	type privateByteAlias []byte
	if privateOriginalJSONShape([]byte(`"AP+A"`), reflect.TypeOf(privateByteAlias{}), 0) == nil ||
		privateOriginalJSONShape([]byte(`[0,255,128]`), reflect.TypeOf(privateByteAlias{}), 0) != nil ||
		privateOriginalJSONShape([]byte(`[1,2]`), reflect.TypeOf([]int{}), 0) != nil {
		t.Fatal(fixtureOnly, " unrelated slice grammar changed")
	}
}

func TestOriginalFactoryOpaqueFormatting(t *testing.T) {
	secret := "SOURCE_PRIVATE_SENTINEL_NO_ARTIFACT"
	err := refused("role_or_signature_refused", errors.New(secret))
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		if strings.Contains(fmt.Sprintf(format, err), secret) {
			t.Fatal(fixtureOnly, " error privacy")
		}
	}
	r := &OriginalFactoryRealm{issuerKey: []byte(secret)}
	c := &OrdinaryOriginalCreate{settlementNonce: secret, credential: model.FactoryOrdinaryCredentialFrame{MutationBearer: secret, OrdinaryGuardBearer: secret}}
	for _, v := range []any{r, c} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, v), secret) {
				t.Fatal(fixtureOnly, " owner privacy")
			}
		}
	}
}

func TestOriginalFactoryPendingSingletonEvolution(t *testing.T) {
	for _, scenario := range []string{"fifteen_returned_then_pending_actual_successor", "two_sequential_pending"} {
		t.Run(scenario, func(t *testing.T) {
			l, h := fixtureLedger(t)
			// Synthetic call-return grammar fixture ONLY, not a native File.Read
			// proof. The production entry still has an EMPTY trust catalog.
			terminal := 15
			if scenario == "two_sequential_pending" {
				terminal = 0
			}
			for i := 0; i < terminal; i++ {
				c, e := h.begin("bootstrap_challenge32_read", "host_exterior", "root_bootstrap", false)
				if e != nil {
					t.Fatal(e)
				}
				h.finish(c, time.Now().UTC(), ptr(int64(1)), ptr(digest([]byte{byte(i)})), "actual_public_bytes", "success", ptr(false))
			}
			iterations := 1
			if terminal == 0 {
				iterations = 2
			}
			for i := 0; i < iterations; i++ {
				pending, e := h.begin("bootstrap_challenge32_read", "host_exterior", "root_bootstrap", false)
				if e != nil {
					t.Fatal(e)
				}
				ref, e := l.vector(h, "bootstrap_challenge32_read", "host_exterior")
				if e != nil || ref.CollectionState != "same_original_call_pending" {
					t.Fatal(fixtureOnly, " pending not retained")
				}
				pendingRaw, e := l.collection.Resolve(pending.firstSHA)
				if e != nil {
					t.Fatal(e)
				}
				var chunk model.HostFactoryCallVectorChunk
				if capacity.DecodeHostFactory(pendingRaw, &chunk) != nil || len(chunk.OriginalCalls) != 1 || chunk.FirstOrdinal != chunk.LastOrdinal {
					t.Fatal(fixtureOnly, " mixed pending chunk")
				}
				h.finish(pending, time.Now().UTC(), ptr(int64(0)), ptr(digest(nil)), "actual_public_bytes", "eof", ptr(true))
				ref, e = l.vector(h, "bootstrap_challenge32_read", "host_exterior")
				if e != nil || ref.CollectionState != "complete_original_calls" {
					t.Fatal(fixtureOnly, " original successor missing")
				}
				original, e := l.collection.Resolve(pending.firstSHA)
				if e != nil || !bytes.Equal(original, pendingRaw) {
					t.Fatal(fixtureOnly, " pending rewritten")
				}
				previous, index, e := l.collection.Predecessor(pending.finalSHA, 0)
				if e != nil || index != 0 || !bytes.Equal(previous, pendingRaw) {
					t.Fatal(fixtureOnly, " predecessor lost")
				}
				if _, e = checkOriginalSourceCallVector(ref, l.collection); e != nil {
					t.Fatal(fixtureOnly, " Source retained-custody vector refused; no SQL FIRST claimed")
				}
			}
		})
	}
}

func TestOriginalFactoryMissingPredecessorUnknown(t *testing.T) {
	l, _ := fixtureLedger(t)
	if _, _, err := l.collection.Predecessor(strings.Repeat("a", 64), 0); err == nil {
		t.Fatal(fixtureOnly, " missing relation treated FIRST")
	}
}

func TestOriginalFactorySourcePendingRequestIdentity(t *testing.T) {
	// Metadata discriminants only: no OS call, Source installation, SQL FIRST
	// relation or native qualification is supplied by these fixture values.
	at := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	id := "00000000-0000-4000-8000-000000000001:1"
	base := model.HostFactoryPrimitiveIOReturn{Operation: "fcntl_getfl", OriginalHandleID: "00000000-0000-4000-8000-000000000001", OwnerPrimitiveRawSHA256: ptr(strings.Repeat("1", 64)), SubjectOwnerID: "00000000-0000-4000-8000-000000000002", OriginalState: "called_pending", OriginalCallID: &id, OriginalCallOrdinal: ptr(uint64(1)), OriginalCalledAt: &at, OriginalOperationDeadline: at.Add(time.Minute), OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "fcntl_getfl", InputDescriptorNumber: ptr(3), RequestedFcntlCommand: ptr(unix.F_GETFL), RequestedArgument: ptr(int64(0))}}
	copyFact := func() model.HostFactoryPrimitiveIOReturn {
		x := base
		n := *base.OriginalNativeReturn
		x.OriginalNativeReturn = &n
		return x
	}
	cases := []struct {
		name   string
		mutate func(*model.HostFactoryPrimitiveIOReturn)
		match  bool
	}{
		{"same_request", func(x *model.HostFactoryPrimitiveIOReturn) {}, true},
		{"actual_outputs_new", func(x *model.HostFactoryPrimitiveIOReturn) {
			x.OriginalState = "returned"
			x.OriginalReturnedAt = ptr(at.Add(time.Second))
			x.OriginalNativeReturn.OriginalScalar = ptr(int64(2048))
			x.OriginalNativeReturn.OriginalErrorPresent = ptr(false)
			x.OriginalNativeReturn.OriginalErrno = ptr(uint32(0))
		}, true},
		{"subject_changed", func(x *model.HostFactoryPrimitiveIOReturn) { x.SubjectOwnerID = "00000000-0000-4000-8000-000000000003" }, false},
		{"primitive_changed", func(x *model.HostFactoryPrimitiveIOReturn) { x.OwnerPrimitiveRawSHA256 = ptr(strings.Repeat("2", 64)) }, false},
		{"call_id_changed", func(x *model.HostFactoryPrimitiveIOReturn) { x.OriginalCallID = ptr(id + "0") }, false},
		{"ordinal_changed", func(x *model.HostFactoryPrimitiveIOReturn) { x.OriginalCallOrdinal = ptr(uint64(2)) }, false},
		{"called_at_changed", func(x *model.HostFactoryPrimitiveIOReturn) { x.OriginalCalledAt = ptr(at.Add(time.Nanosecond)) }, false},
		{"deadline_changed", func(x *model.HostFactoryPrimitiveIOReturn) {
			x.OriginalOperationDeadline = x.OriginalOperationDeadline.Add(time.Nanosecond)
		}, false},
		{"handle_changed", func(x *model.HostFactoryPrimitiveIOReturn) {
			x.OriginalHandleID = "00000000-0000-4000-8000-000000000003"
		}, false},
		{"operation_changed", func(x *model.HostFactoryPrimitiveIOReturn) { x.Operation = "source_descriptor_getfd" }, false},
		{"native_request_lost", func(x *model.HostFactoryPrimitiveIOReturn) { x.OriginalNativeReturn = nil }, false},
		{"native_fd_changed", func(x *model.HostFactoryPrimitiveIOReturn) { x.OriginalNativeReturn.InputDescriptorNumber = ptr(4) }, false},
		{"native_command_changed", func(x *model.HostFactoryPrimitiveIOReturn) {
			x.OriginalNativeReturn.RequestedFcntlCommand = ptr(unix.F_GETFD)
		}, false},
		{"native_argument_changed", func(x *model.HostFactoryPrimitiveIOReturn) { x.OriginalNativeReturn.RequestedArgument = ptr(int64(1)) }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := copyFact()
			c.mutate(&x)
			if originalSourcePendingRequestEqual(base, x) != c.match {
				t.Fatal(fixtureOnly, " immutable pending request mismatch")
			}
		})
	}
}

func TestOriginalFactoryOriginalCallCounterAndCloseReserve(t *testing.T) {
	_, h := fixtureLedger(t)
	h.next = callLimit - 1
	if _, err := h.begin("bootstrap_challenge32_read", "host_exterior", "root_bootstrap", false); err == nil {
		t.Fatal(fixtureOnly, " exhausted read called")
	}
	if _, err := h.begin("bootstrap_reader_close", "host_exterior", "root_bootstrap", true); err != nil {
		t.Fatal(fixtureOnly, " original Close reserve lost")
	}
	if _, err := h.begin("bootstrap_reader_close", "host_exterior", "root_bootstrap", true); err == nil {
		t.Fatal(fixtureOnly, " second Close beyond bound")
	}
}

func TestOriginalFactoryByteEOFAndLengthCompletionDistinct(t *testing.T) {
	for _, scenario := range []string{"actual_empty_eof", "length_only_not_eof", "extra_byte_refuses"} {
		t.Run(scenario, func(t *testing.T) {
			l, h := fixtureLedger(t)
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(fixtureOnly, " pipe acquire")
			}
			h.file = r
			h.fd = int(r.Fd())
			// Protocol fixture pipe on owning CI; never a native basal/bootstrap
			// authority or a production credential. No process/VM is started.
			if scenario == "length_only_not_eof" {
				if _, e := w.Write([]byte{1}); e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "extra_byte_refuses" {
				if _, e := w.Write([]byte{1}); e != nil {
					t.Fatal(e)
				}
			}
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			if scenario == "length_only_not_eof" {
				_, read := readOwned(h, "bootstrap_challenge32_read", "host_exterior", "root_bootstrap", 1, false, 1)
				if read.err != nil || read.eof {
					t.Fatal(fixtureOnly, " length manufactured EOF")
				}
			}
			err = frameEOF(h, "bootstrap_eof_read", "host_exterior", "root_bootstrap")
			if (scenario == "extra_byte_refuses") != (err != nil) {
				t.Fatal(fixtureOnly, " EOF probe result")
			}
			if _, err = closeOwned(h, "bootstrap_reader_close", "host_exterior", "root_bootstrap"); err != nil {
				t.Fatal(err)
			}
			ref, err := l.vector(h, "bootstrap_eof_read", "host_exterior")
			if err != nil || ref.OriginalCallCount != 1 {
				t.Fatal(fixtureOnly, " EOF call ownership")
			}
		})
	}
}

func TestOriginalFactoryPrivateHashWithheld(t *testing.T) {
	l, h := fixtureLedger(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	h.file = r
	h.fd = int(r.Fd())
	secret := []byte("PRIVATE_FIXTURE_KEY_MATERIAL")
	if _, err = w.Write(secret); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	_, read := readOwned(h, "bootstrap_key64_read", "host_exterior", "root_bootstrap", 64, true, int64(len(secret)))
	if read.err != nil {
		t.Fatal(err)
	}
	if _, err = closeOwned(h, "bootstrap_reader_close", "host_exterior", "root_bootstrap"); err != nil {
		t.Fatal(err)
	}
	_, err = l.vector(h, "bootstrap_key64_read", "host_exterior")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range l.collection.OriginalBodies() {
		if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte(digest(secret))) {
			t.Fatal(fixtureOnly, " private bytes/hash retained publicly")
		}
	}
}

func TestOriginalFactoryClosedArgv(t *testing.T) {
	for _, argv := range [][]string{nil, {"--ordinary-original-create", "--unreviewed"}, {"--allow-native"}, {"--sealed-original-factory", "arbitrary"}} {
		if RunOriginalWorker(context.Background(), argv) == nil {
			t.Fatal(fixtureOnly, " arbitrary argv installed")
		}
	}
}

func TestOriginalFactoryManualPipeDeadlineOwner(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(fixtureOnly, err)
	}
	t.Cleanup(func() {
		if err := reader.Close(); err != nil {
			t.Error(fixtureOnly, err)
		}
		if err := writer.Close(); err != nil {
			t.Error(fixtureOnly, err)
		}
	})
	if _, err = originalFileNumber(reader); err != nil {
		t.Fatal(fixtureOnly, err)
	}
	if err = reader.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(fixtureOnly, "descriptor observation removed actual deadline", err)
	}
	// The original writer remains open with no bytes. This is an actual
	// deadline refusal, never EOF or a synthetic owner-return/NoStart proof.
	n, err := reader.Read(make([]byte, 1))
	if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(fixtureOnly, "original reader deadline unavailable", n, err)
	}
	if number, err := originalFileNumber(nil); err == nil || number != -1 {
		t.Fatal(fixtureOnly, "missing original handle admitted")
	}
}

func TestOriginalFactoryFixedQEMUChildAnchorNamespace(t *testing.T) {
	i := fixedInstallation{slot: 1, qemuUUID: "00000000-0000-4000-8000-000000000003", artifacts: [4]approvedArtifact{{}, {name: "original-disk.qcow2"}, {name: "seed-image.qcow2"}, {name: "source.iso"}}}
	args := fixedQEMUArguments("/source-fixture-only", i)
	if args[0] != "/usr/bin/qemu-system-x86_64" || strings.Contains(strings.Join(args, " "), "sh -c") || strings.Contains(strings.Join(args, " "), "tcg") {
		t.Fatal(fixtureOnly, " arbitrary executable")
	}
	if !reflect.DeepEqual(args[1:9], []string{"-machine", "accel=kvm", "-cpu", "max", "-m", "1536", "-smp", "2"}) {
		t.Fatal(fixtureOnly, " fixed resource catalog drift")
	}
	if !strings.Contains(strings.Join(args, " "), "hostfwd=tcp:127.0.0.1:19447-:9447") || strings.Contains(strings.Join(args, " "), "-:22") {
		t.Fatal(fixtureOnly, "fixed original Guest retirement route drift")
	}
}

// PATCH_ONLY for Source9's existing Linux test file. These remote Source-only
// tests exercise file custody. They install no Source/native tuple and start
// no child, VM, provider or original factory. Never execute on this machine.
func rootRegistrarSourceFilesFixture(t *testing.T) (context.Context, *originalLedger, *callHandle, string, uint32, uint32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	fd, err := originalFileNumber(f)
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		t.Fatal(err)
	}
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	l, err := newLedger(ctx, id, "host_exterior", strings.Repeat("a", 64), "original_host_factory_root_preparation_v4", strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	// This is an uninstalled unit-test anchor, not an original Native owner or
	// proof. The test makes no native/source approval from this File pointer.
	return ctx, l, &callHandle{file: f, fd: fd}, directory, stat.Uid, stat.Gid
}

func TestHostFactorySourceRegistrarFilesOriginalCustody(t *testing.T) {
	ctx, audit, anchor, _, uid, gid := rootRegistrarSourceFilesFixture(t)
	want := []byte(`{"schema":"source_only_file_fixture","value":7}`)
	if err := controlRegistrarPublishFile(ctx, audit, anchor, "one.tmp", "one.json", want, uid, gid); err != nil {
		t.Fatal(err)
	}
	got, err := controlRegistrarReadFile(ctx, audit, anchor, "one.json", uid, gid)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("original whole file refused/mismatched: %v", err)
	}
	var writes, reads, eof, closes, methods int
	for _, h := range audit.handles {
		for _, actual := range h.unclassified {
			if actual.callID == "" || actual.calledAt.IsZero() || actual.returnedAt.Before(actual.calledAt) || !actual.private {
				t.Fatal("lost original private call identity/return")
			}
			switch actual.operation {
			case "source_file_write":
				writes++
				if actual.cause != nil || actual.scalar != int64(len(actual.raw)) || !bytes.Equal(actual.raw, want) {
					t.Fatal("write was not the original whole buffer")
				}
			case "source_file_read":
				reads++
				if actual.cause == io.EOF {
					eof++
				}
			case "source_file_close":
				closes++
			case "source_file_rename_noreplace", "source_directory_sync":
				methods++
				if h.file != nil || actual.scalarObserved || actual.stat != nil {
					t.Fatal("publication method fabricated an acquired FD/scalar/stat")
				}
			}
		}
	}
	if writes != 1 || reads < 1 || eof != 1 || closes != 2 || methods != 2 {
		t.Fatalf("original custody incomplete: write=%d read=%d eof=%d close=%d method=%d", writes, reads, eof, closes, methods)
	}
}

func TestHostFactorySourceRegistrarFilesNoReplacement(t *testing.T) {
	ctx, audit, anchor, directory, uid, gid := rootRegistrarSourceFilesFixture(t)
	first, second := []byte("first original"), []byte("second original")
	if err := controlRegistrarPublishFile(ctx, audit, anchor, "first.tmp", "reply.json", first, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err := controlRegistrarPublishFile(ctx, audit, anchor, "second.tmp", "reply.json", second, uid, gid); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("replacement was not refused with original EEXIST: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(directory, "reply.json"))
	if err != nil || !bytes.Equal(got, first) {
		t.Fatal("first immutable original changed")
	}
	left, err := os.ReadFile(filepath.Join(directory, "second.tmp"))
	if err != nil || !bytes.Equal(left, second) {
		t.Fatal("uncertain/refused publication artifact was lost")
	}
}

func TestHostFactorySourceRegistrarFilesFailedOpenNoFakeClose(t *testing.T) {
	ctx, audit, anchor, _, uid, gid := rootRegistrarSourceFilesFixture(t)
	if _, err := controlRegistrarReadFile(ctx, audit, anchor, "missing.json", uid, gid); err == nil {
		t.Fatal("missing original input accepted")
	}
	if len(audit.handles) != 1 {
		t.Fatal("failed acquisition lost or duplicated its original handle")
	}
	for _, h := range audit.handles {
		if h.file != nil || len(h.unclassified) != 1 || h.unclassified[0].operation != "source_file_open" || !errors.Is(h.unclassified[0].cause, unix.ENOENT) {
			t.Fatal("failed Open manufactured FD/Close/EOF or lost literal error")
		}
	}
}

func TestHostFactorySourceRegistrarFilesSymlinkRefused(t *testing.T) {
	ctx, audit, anchor, directory, uid, gid := rootRegistrarSourceFilesFixture(t)
	if err := os.WriteFile(filepath.Join(directory, "target.json"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.json", filepath.Join(directory, "link.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := controlRegistrarReadFile(ctx, audit, anchor, "link.json", uid, gid); err == nil {
		t.Fatal("symlink supplied an original RPC input")
	}
	for _, h := range audit.handles {
		if len(h.unclassified) != 1 || !errors.Is(h.unclassified[0].cause, unix.ELOOP) || h.file != nil {
			t.Fatal("symlink refusal lost literal failed Open custody")
		}
	}
}

func TestHostFactorySourceRegistrarFilesOversizeRefused(t *testing.T) {
	ctx, audit, anchor, directory, uid, gid := rootRegistrarSourceFilesFixture(t)
	if err := os.WriteFile(filepath.Join(directory, "oversize.json"), bytes.Repeat([]byte{'x'}, bodyLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := controlRegistrarReadFile(ctx, audit, anchor, "oversize.json", uid, gid); err == nil {
		t.Fatal("oversize original file accepted")
	}
	for _, h := range audit.handles {
		var closes int
		for _, actual := range h.unclassified {
			if actual.operation == "source_file_read" {
				t.Fatal("oversize stat became a truncated accepted byte read")
			}
			if actual.operation == "source_file_close" {
				closes++
			}
		}
		if closes != 1 || !h.closed {
			t.Fatal("oversize refusal leaked the actual acquired endpoint")
		}
	}
}

// These real-file Source custody cases install no approved catalog or Realm.
// Successful private key selection is not a native observation/registration.
func TestHostFactorySourceRegistrarOriginalKeyRoleSelection(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, ed25519.SeedSize))
	defer clear(key)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{29}, ed25519.SeedSize))
	defer clear(other)
	public := key.Public().(ed25519.PublicKey)
	otherPublic := other.Public().(ed25519.PublicKey)
	for _, tc := range []struct {
		name string
		keys []approvedKey
		want bool
	}{
		{"own_selected_key", []approvedKey{{id: "registrar", role: "host_registrar", public: public}}, true},
		{"foreign_role_alias", []approvedKey{{id: "registrar", role: "host_registrar", public: public}, {id: "exterior", role: "host_exterior", public: public}}, false},
		{"different_selected_registrar", []approvedKey{{id: "first", role: "host_registrar", public: otherPublic}, {id: "second", role: "host_registrar", public: public}}, false},
		{"conflicting_same_role_key_id", []approvedKey{{id: "registrar", role: "host_registrar", public: public}, {id: "registrar", role: "host_registrar", public: otherPublic}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, audit, anchor, directory, uid, gid := rootRegistrarSourceFilesFixture(t)
			if err := os.WriteFile(filepath.Join(directory, "registrar.key"), key, 0600); err != nil {
				t.Fatal(err)
			}
			r := &OriginalFactoryRealm{rootFD: anchor.fd, preparedRootHandle: anchor, installation: fixedInstallation{keys: tc.keys, controlRegistrarKey: approvedArtifact{name: "registrar.key", bytes: ed25519.PrivateKeySize, uid: uid, gid: gid, mode: unix.S_IFREG | 0600}}, basal: &basalOwner{}, control: &originalControl{policyAuditLedger: audit}}
			r.basal.body.Calls[2].OriginalScalar = int64(uid)
			r.basal.body.Calls[3].OriginalScalar = int64(gid)
			got, err := controlRegistrarReadKey(ctx, r)
			defer clear(got)
			if (err == nil) != tc.want || (tc.want && !bytes.Equal(got, key)) || (!tc.want && len(got) != 0) {
				t.Fatal(fixtureOnly, " registrar selected/foreign role key gate mismatched")
			}
			handles, e := audit.originalHandles()
			if e != nil || len(handles) != 1 || !handles[0].closed {
				t.Fatal(fixtureOnly, " original key reader Close lost after refusal")
			}
			var eof, closes int
			for _, actual := range handles[0].unclassified {
				if actual.operation == "source_file_read" && actual.cause == io.EOF {
					eof++
				}
				if actual.operation == "source_file_close" {
					closes++
				}
			}
			if eof != 1 || closes != 1 {
				t.Fatal(fixtureOnly, " key role refusal fabricated/lost original EOF or Close")
			}
		})
	}
}

// PATCH_ONLY new remote Source-only cases. Use the existing original Source
// file fixture. No compiled registry/native approval, child or VM is installed.
// These are written only: never execute on the owner machine.
func TestHostFactorySourceRegistrarFilesKnownEmptyCustody(t *testing.T) {
	ctx, audit, anchor, _, uid, gid := rootRegistrarSourceFilesFixture(t)
	if err := controlRegistrarPublishGetdentsFile(ctx, audit, anchor, "raw-zero.tmp", "raw-zero.bin", []byte{}, uid, gid); err != nil {
		t.Fatal(err)
	}
	got, err := controlRegistrarReadGetdentsFile(ctx, audit, anchor, "raw-zero.bin", uid, gid)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatal("actual acquired empty custody lost or changed into unknown")
	}
	var writes, reads, eof, closes, syncs, stats, renames, directorySyncs int
	for _, h := range audit.handles {
		for _, call := range h.unclassified {
			switch call.operation {
			case "source_file_write":
				writes++
			case "source_file_read":
				reads++
				if call.scalar != 0 || call.cause != io.EOF {
					t.Fatal("empty file did not retain literal File.Read zero/EOF")
				}
				eof++
			case "source_file_close":
				closes++
			case "source_file_sync":
				syncs++
			case "source_file_fstat":
				stats++
			case "source_file_rename_noreplace":
				renames++
			case "source_directory_sync":
				directorySyncs++
			}
		}
	}
	if writes != 0 || reads != 1 || eof != 1 || closes != 2 || syncs != 1 || stats != 3 || renames != 1 || directorySyncs != 1 {
		t.Fatal("empty original custody invented Write0 or lost an actual owning return")
	}
	// This returned empty byte slice is Source file custody only. No native-zero
	// fact is constructed here; actual signed getdents CallID/count/FIRST joins
	// remain independently required by the native producer/consumer pair.
}

func TestHostFactorySourceRegistrarFilesUnknownEmptyRefused(t *testing.T) {
	ctx, audit, anchor, directory, uid, gid := rootRegistrarSourceFilesFixture(t)
	if err := controlRegistrarPublishGetdentsFile(ctx, audit, anchor, "unknown.tmp", "unknown.bin", nil, uid, gid); err == nil {
		t.Fatal("unknown NULL buffer became an acquired known-zero file")
	}
	if len(audit.handles) != 0 {
		t.Fatal("NULL refusal executed a source publication")
	}
	if err := os.WriteFile(filepath.Join(directory, "empty.json"), []byte{}, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := controlRegistrarReadFile(ctx, audit, anchor, "empty.json", uid, gid); err == nil {
		t.Fatal("empty file supplied a nonempty whole request/record")
	}
	for _, h := range audit.handles {
		if h.file == nil || !h.closed {
			t.Fatal("empty whole-file refusal leaked the acquired endpoint")
		}
		for _, call := range h.unclassified {
			if call.operation == "source_file_read" {
				t.Fatal("empty forbidden whole body was accepted as an original read")
			}
		}
	}
}

func TestHostFactorySourceRegistrarFilesLiteralMissingOnly(t *testing.T) {
	ctx, audit, anchor, directory, uid, gid := rootRegistrarSourceFilesFixture(t)
	if _, missing, err := controlRegistrarReadFileAttempt(ctx, audit, anchor, "not-published.json", uid, gid); err == nil || !missing {
		t.Fatal("literal failed Open ENOENT lost its private poll classification")
	}
	if err := os.WriteFile(filepath.Join(directory, "target.json"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target.json", filepath.Join(directory, "alias.json")); err != nil {
		t.Fatal(err)
	}
	if _, missing, err := controlRegistrarReadFileAttempt(ctx, audit, anchor, "alias.json", uid, gid); err == nil || missing {
		t.Fatal("a different original refusal became an ENOENT poll/retry")
	}
	var missingOpen, symlinkOpen int
	for _, h := range audit.handles {
		if h.file != nil || len(h.unclassified) != 1 || h.unclassified[0].operation != "source_file_open" {
			t.Fatal("failed acquisition fabricated FD/Read/Close")
		}
		if errors.Is(h.unclassified[0].cause, unix.ENOENT) {
			missingOpen++
		}
		if errors.Is(h.unclassified[0].cause, unix.ELOOP) {
			symlinkOpen++
		}
	}
	if missingOpen != 1 || symlinkOpen != 1 {
		t.Fatal("literal private failed Open causes were dropped or merged")
	}
}

func TestHostFactorySourceNativeProcessPhaseBounds(t *testing.T) {
	for _, c := range []struct {
		name     string
		which    string
		accepted bool
	}{
		{"lower_actual_phase_keeps_original_ledger", "lower", true},
		{"phase_cannot_extend_original_ledger", "extend", false},
		{"actual_return_after_phase_is_retained_hold", "late", false},
		{"zero_actual_return_is_unknown", "zero", false},
		{"cancelled_actual_phase_has_no_new_io", "cancel", false},
		{"cancelled_original_ledger_has_no_new_io", "originalcancel", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			sampled := time.Now().UTC()
			original, stopOriginal := context.WithDeadline(context.Background(), sampled.Add(60*time.Second))
			defer stopOriginal()
			d := sampled.Add(30 * time.Second)
			if c.which == "extend" {
				d = sampled.Add(90 * time.Second)
			}
			phase, stopPhase := context.WithDeadline(context.Background(), d)
			defer stopPhase()
			l := &originalLedger{ctx: original, deadline: sampled.Add(60 * time.Second)}
			returned := sampled
			switch c.which {
			case "late":
				returned = d.Add(time.Nanosecond)
			case "zero":
				returned = time.Time{}
			case "cancel":
				stopPhase()
			case "originalcancel":
				stopOriginal()
			}
			err := nativeProcessPhase(phase, l, returned)
			if (err == nil) != c.accepted {
				t.Fatalf("timing guard accepted=%v: %v", c.accepted, err)
			}
			if !l.deadline.Equal(sampled.Add(60 * time.Second)) {
				t.Fatal("original ledger deadline rewritten")
			}
		})
	}
}

func TestHostFactorySourceNativeProcessOriginalCallCustody(t *testing.T) {
	for _, c := range []struct {
		name, which string
		accepted    bool
	}{
		{"same_original_returned_metadata_only", "returned", true},
		{"missing_actual_row_is_not_first", "missing", false},
		{"pending_original_is_not_returned", "pending", false},
		{"other_handle_stat_cannot_substitute", "foreign", false},
		{"missing_actual_return_time", "notime", false},
		{"copied_metadata_is_not_original_reserved_pointer", "copy", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			called := time.Now().UTC()
			returned := called.Add(time.Nanosecond)
			id := "11111111-1111-4111-8111-111111111111:1"
			l := &originalLedger{calls: map[string][]*retainedCall{}}
			h := &callHandle{id: "11111111-1111-4111-8111-111111111111", ledger: l}
			r := &retainedCall{fact: model.HostFactoryPrimitiveIOReturn{Operation: "native_reader_fstat", OriginalHandleID: h.id, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalCallID: &id}}
			switch c.which {
			case "pending":
				r.fact.OriginalState = "called_pending"
			case "foreign":
				r.fact.OriginalHandleID = "22222222-2222-4222-8222-222222222222"
			case "notime":
				r.fact.OriginalReturnedAt = nil
			}
			if c.which != "missing" {
				l.calls[h.id+"\x00native_reader_fstat"] = []*retainedCall{r}
				if c.which == "copy" {
					clone := *r
					r = &clone
				}
			}
			err := nativeProcessOriginalCall(h, r, "native_reader_fstat")
			if (err == nil) != c.accepted {
				t.Fatalf("custody guard accepted=%v: %v", c.accepted, err)
			}
			if c.accepted && (l.calls[h.id+"\x00native_reader_fstat"][0] != r || *r.fact.OriginalCallID != id) {
				t.Fatal("same reserved pointer/call identity was changed")
			}
		})
	}
}

// Synthetic unsigned consistency facts only. No Realm, native/Source supplier,
// SQL-FIRST, key, file/process, corpus completion or effect permission exists.
func mergeSourceAuditFixture(handle string, origin time.Time) []originalSourceAuditProjection {
	closeID := handle + ":4"
	out := make([]originalSourceAuditProjection, 4)
	for i, op := range []string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_close"} {
		f := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: "00000000-0000-4000-8000-000000000001", OriginalAuditHandleID: handle, OriginalCallID: ptr(fmt.Sprintf("%s:%d", handle, i+1)), Operation: op, OriginalState: "returned", OriginalCalledAt: ptr(origin.Add(time.Duration(i*2) * time.Second)), OriginalReturnedAt: ptr(origin.Add(time.Duration(i*2+1) * time.Second)), OriginalOperationDeadline: origin.Add(600 * time.Second), OriginalErrorPresent: ptr(false), OriginalHashState: "not_byte_operation"}
		if op == "source_file_read" {
			f.OriginalCount = ptr(int64(0))
			f.OriginalEOF = ptr(true)
			f.OriginalErrorPresent = ptr(true)
			f.OriginalHashState = "private_withheld"
		}
		out[i] = originalSourceAuditProjection{Family: "source_audit", SubjectIdentity: originalSourceAuditSubject{SubjectKind: "source_file"}, Fact: f, OriginalCloseReference: ptr(closeID)}
	}
	return out
}
func mergeSourceAuditOrigin() time.Time { return time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC) }
func mergeSourceAuditFailedOpen(handle string) originalSourceAuditProjection {
	f := mergeSourceAuditFixture(handle, mergeSourceAuditOrigin())[0]
	f.OriginalCloseReference = nil
	f.Fact.OriginalErrorPresent = ptr(true)
	return f
}

func TestHostOriginalFactorySourceAuditMergeOriginalStreams(t *testing.T) {
	own := mergeSourceAuditFixture("00000000-0000-4000-8000-000000000002", mergeSourceAuditOrigin().Add(20*time.Second))
	newer := mergeSourceAuditFixture("00000000-0000-4000-8000-000000000003", mergeSourceAuditOrigin())
	for _, tc := range []struct {
		name          string
		own, imported []originalSourceAuditProjection
		want          int
	}{
		{"keep_own_acquisition_order_without_time_sort", own, newer, 8},
		{"same_original_full_duplicate_keeps_first", own, own, 4},
		{"reused_complete_imported_stream_restart_is_exact_duplicate", own, append(append([]originalSourceAuditProjection{}, newer...), newer...), 8},
		{"known_empty_imports_are_no_entries_not_absence", own, []originalSourceAuditProjection{}, 4},
		{"known_empty_arrays_have_no_native_completion", []originalSourceAuditProjection{}, []originalSourceAuditProjection{}, 0},
		{"failed_open_diagnostic_has_no_close_or_absence", []originalSourceAuditProjection{mergeSourceAuditFailedOpen("00000000-0000-4000-8000-000000000004")}, []originalSourceAuditProjection{}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mergeOriginalSourceAuditProjections(tc.own, tc.imported)
			if err != nil || got == nil || len(got) != tc.want {
				t.Fatal("unsigned original merge disposition", err)
			}
			if len(tc.own) > 0 && !reflect.DeepEqual(got[:len(tc.own)], tc.own) {
				t.Fatal("own acquisition order changed")
			}
			if tc.want == 8 && !reflect.DeepEqual(got[4:], newer) {
				t.Fatal("imported order changed by timestamps")
			}
			if len(got) > 2 && got[2].Fact.Operation == "source_file_read" && (!*got[2].Fact.OriginalEOF || !*got[2].Fact.OriginalErrorPresent || got[2].Fact.OriginalSHA256 != nil) {
				t.Fatal("actual EOF error/privacy was normalized")
			}
		})
	}
}

func TestHostOriginalFactorySourceAuditMergeRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*[]originalSourceAuditProjection, *[]originalSourceAuditProjection)
	}{
		{"unknown_own_nil", func(a, b *[]originalSourceAuditProjection) { *a = nil }},
		{"unknown_imported_nil", func(a, b *[]originalSourceAuditProjection) { *b = nil }},
		{"own_duplicate_cannot_lose_sequence", func(a, b *[]originalSourceAuditProjection) { *a = append(*a, (*a)...) }},
		{"imported_partial_duplicate_is_not_original_whole_stream", func(a, b *[]originalSourceAuditProjection) { *b = (*b)[:3] }},
		{"imported_changed_fact_same_id", func(a, b *[]originalSourceAuditProjection) { (*b)[2].Fact.OriginalCount = ptr(int64(1)) }},
		{"imported_changed_close_reference_same_id", func(a, b *[]originalSourceAuditProjection) {
			(*b)[0].OriginalCloseReference = ptr((*b)[0].Fact.OriginalAuditHandleID + ":1")
		}},
		{"imported_extension_of_original_closed_handle", func(a, b *[]originalSourceAuditProjection) {
			x := mergeOriginalSourceAuditCopy((*b)[3])
			x.Fact.OriginalCallID = ptr(x.Fact.OriginalAuditHandleID + ":5")
			*b = append(*b, x)
		}},
		{"missing_original_call_id", func(a, b *[]originalSourceAuditProjection) { (*b)[0].Fact.OriginalCallID = nil }},
		{"noncanonical_ordinal_alias", func(a, b *[]originalSourceAuditProjection) {
			(*b)[0].Fact.OriginalCallID = ptr((*b)[0].Fact.OriginalAuditHandleID + ":01")
		}},
		{"gap_in_original_stream", func(a, b *[]originalSourceAuditProjection) { *b = append((*b)[:1], (*b)[2:]...) }},
		{"reversed_original_stream", func(a, b *[]originalSourceAuditProjection) { (*b)[1], (*b)[2] = (*b)[2], (*b)[1] }},
		{"pending_original_never_returned", func(a, b *[]originalSourceAuditProjection) {
			(*b)[1].Fact.OriginalState = "called_pending"
			(*b)[1].Fact.OriginalReturnedAt = nil
			(*b)[1].Fact.OriginalErrorPresent = nil
		}},
		{"different_root_rejected", func(a, b *[]originalSourceAuditProjection) {
			for i := range *b {
				(*b)[i].Fact.FactoryRootID = "00000000-0000-4000-8000-000000000009"
			}
		}},
		{"foreign_subject_kind_is_not_source_directory_alias", func(a, b *[]originalSourceAuditProjection) { (*b)[0].SubjectIdentity.SubjectKind = "source_directory" }},
		{"http_subject_fields_cannot_enter_file_merger", func(a, b *[]originalSourceAuditProjection) { (*b)[0].SubjectIdentity.Method = ptr("GET") }},
		{"private_digest_cannot_be_published", func(a, b *[]originalSourceAuditProjection) {
			(*b)[2].Fact.OriginalSHA256 = ptr("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		}},
		{"private_prefix_digest_cannot_be_published", func(a, b *[]originalSourceAuditProjection) {
			(*b)[2].Fact.RetainedPrefixSHA256 = ptr("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		}},
		{"literal_eof_error_must_not_be_normalized", func(a, b *[]originalSourceAuditProjection) { (*b)[2].Fact.OriginalErrorPresent = ptr(false) }},
		{"unknown_count_is_not_zero", func(a, b *[]originalSourceAuditProjection) { (*b)[2].Fact.OriginalCount = nil }},
		{"unknown_return_is_not_fresh", func(a, b *[]originalSourceAuditProjection) { (*b)[2].Fact.OriginalReturnedAt = ptr(time.Time{}) }},
		{"actual_return_at_original_bound_holds", func(a, b *[]originalSourceAuditProjection) {
			(*b)[3].Fact.OriginalReturnedAt = ptr((*b)[3].Fact.OriginalOperationDeadline)
		}},
		{"original_deadline_changed_inside_handle", func(a, b *[]originalSourceAuditProjection) {
			(*b)[2].Fact.OriginalOperationDeadline = (*b)[2].Fact.OriginalOperationDeadline.Add(time.Second)
		}},
		{"original_calls_overlap", func(a, b *[]originalSourceAuditProjection) {
			(*b)[2].Fact.OriginalCalledAt = ptr(*(*b)[1].Fact.OriginalCalledAt)
		}},
		{"close_reference_mismatch_missing_close", func(a, b *[]originalSourceAuditProjection) {
			for i := range *b {
				(*b)[i].OriginalCloseReference = nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			own := mergeSourceAuditFixture("00000000-0000-4000-8000-000000000002", mergeSourceAuditOrigin())
			imported := make([]originalSourceAuditProjection, len(own))
			for i := range own {
				imported[i] = mergeOriginalSourceAuditCopy(own[i])
			}
			tc.mutate(&own, &imported)
			if got, err := mergeOriginalSourceAuditProjections(own, imported); err == nil || got != nil {
				t.Fatal("unknown/changed original merge accepted")
			}
		})
	}
	t.Run("canonical_equal_bytes_still_require_full_typed_equality", func(t *testing.T) {
		own := mergeSourceAuditFixture("00000000-0000-4000-8000-000000000002", mergeSourceAuditOrigin())
		duplicate := make([]originalSourceAuditProjection, len(own))
		for i := range own {
			duplicate[i] = mergeOriginalSourceAuditCopy(own[i])
		}
		duplicate[0].Fact.OriginalCalledAt = ptr(own[0].Fact.OriginalCalledAt.In(time.FixedZone("synthetic-source-alias", 0)))
		a, _ := json.Marshal(own[0])
		b, _ := json.Marshal(duplicate[0])
		if !bytes.Equal(a, b) || reflect.DeepEqual(own[0], duplicate[0]) {
			t.Fatal("synthetic equality discriminator changed")
		}
		if _, err := mergeOriginalSourceAuditProjections(own, duplicate); err == nil {
			t.Fatal("typed changed original accepted by bytes alone")
		}
	})
}

func TestHostOriginalFactorySourceAuditMergeCopies(t *testing.T) {
	t.Run("original_input_and_return_do_not_share_pointers", func(t *testing.T) {
		own := mergeSourceAuditFixture("00000000-0000-4000-8000-000000000002", mergeSourceAuditOrigin())
		own[2].Fact.FailureCode = ptr("original_pipe_refused")
		if own[2].Fact.FailureCode == nil || capacity.ValidateHostFactory(own[2].Fact) != nil {
			t.Fatal("copy fixture must contain a valid nonnil diagnostic code")
		}
		original, _ := json.Marshal(own)
		got, err := mergeOriginalSourceAuditProjections(own, []originalSourceAuditProjection{})
		if err != nil {
			t.Fatal(err)
		}
		*own[2].Fact.OriginalCount = 11
		*own[2].Fact.OriginalEOF = false
		*own[2].Fact.OriginalErrorPresent = false
		*own[2].Fact.OriginalCallID = "changed"
		*own[2].Fact.FailureCode = "changed"
		*own[2].Fact.OriginalCalledAt = time.Time{}
		*own[2].Fact.OriginalReturnedAt = time.Time{}
		*own[0].OriginalCloseReference = "changed"
		copy, _ := json.Marshal(got)
		if !bytes.Equal(copy, original) {
			t.Fatal("input mutation changed original retained output")
		}
		*got[0].Fact.OriginalCallID = "output_mutation"
		if *own[0].Fact.OriginalCallID == "output_mutation" {
			t.Fatal("output mutation shared input pointer")
		}
	})
}

func TestHostOriginalFactorySourceAuditMergeBounds(t *testing.T) {
	t.Run("input_stream_over4096_cannot_hide_duplicate_work", func(t *testing.T) {
		row := mergeSourceAuditFailedOpen("00000000-0000-4000-8000-000000000002")
		imported := make([]originalSourceAuditProjection, 4097)
		for i := range imported {
			imported[i] = mergeOriginalSourceAuditCopy(row)
		}
		if got, err := mergeOriginalSourceAuditProjections([]originalSourceAuditProjection{}, imported); err == nil || got != nil {
			t.Fatal("unbounded imported stream accepted")
		}
	})
	t.Run("combined_unique_4097_refused_without_trim", func(t *testing.T) {
		own := []originalSourceAuditProjection{mergeSourceAuditFailedOpen("00000000-0000-4000-8000-000000000002")}
		imported := make([]originalSourceAuditProjection, 4096)
		for i := range imported {
			imported[i] = mergeSourceAuditFailedOpen(fmt.Sprintf("10000000-0000-4000-8000-%012x", i+1))
		}
		if got, err := mergeOriginalSourceAuditProjections(own, imported); err == nil || got != nil {
			t.Fatal("combined cap overflow trimmed/accepted")
		}
	})
	t.Run("ordered_canonical_array_over_1MiB_refused", func(t *testing.T) {
		own := make([]originalSourceAuditProjection, 2048)
		for i := range own {
			own[i] = mergeSourceAuditFailedOpen(fmt.Sprintf("10000000-0000-4000-8000-%012x", i+1))
		}
		raw, err := json.Marshal(own)
		if err != nil || len(raw) <= 1024*1024 {
			t.Fatal("synthetic bounded ARRAY discriminator no longer oversize", err)
		}
		if got, err := mergeOriginalSourceAuditProjections(own, []originalSourceAuditProjection{}); err == nil || got != nil {
			t.Fatal("ARRAY cap overflow trimmed/accepted")
		}
	})
}

func TestHostOriginalFactorySourceAuditMergeSourceOperationShapes(t *testing.T) {
	for _, tc := range []struct {
		name             string
		ops              []string
		actualErrorIndex int
		closed           bool
	}{
		{"directory_retains_explicit_source_file_subject", []string{"source_directory_open", "source_directory_fstat", "source_directory_close"}, -1, true},
		{"zero_writer_has_no_fabricated_write", []string{"source_file_open", "source_file_fstat", "source_file_sync", "source_file_close"}, -1, true},
		{"actual_writer_count_is_retained", []string{"source_file_open", "source_file_fstat", "source_file_write", "source_file_sync", "source_file_close"}, -1, true},
		{"publication_method_is_not_closed_file", []string{"source_file_rename_noreplace", "source_directory_sync"}, -1, false},
		{"failed_rename_retains_single_diagnostic", []string{"source_file_rename_noreplace"}, 0, false},
		{"failed_directory_sync_is_retained_unchanged", []string{"source_file_rename_noreplace", "source_directory_sync"}, 1, false},
		{"failed_actual_file_close_is_retained_without_native_success", []string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_close"}, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := "00000000-0000-4000-8000-000000000005"
			rows := make([]originalSourceAuditProjection, len(tc.ops))
			for i, op := range tc.ops {
				rows[i] = mergeSourceAuditFailedOpen(h)
				f := &rows[i].Fact
				f.OriginalCallID = ptr(fmt.Sprintf("%s:%d", h, i+1))
				f.Operation = op
				f.OriginalCalledAt = ptr(mergeSourceAuditOrigin().Add(time.Duration(i*2) * time.Second))
				f.OriginalReturnedAt = ptr(mergeSourceAuditOrigin().Add(time.Duration(i*2+1) * time.Second))
				f.OriginalErrorPresent = ptr(i == tc.actualErrorIndex)
				if tc.closed {
					rows[i].OriginalCloseReference = ptr(fmt.Sprintf("%s:%d", h, len(tc.ops)))
				}
				if op == "source_file_write" {
					f.OriginalCount = ptr(int64(3))
					f.OriginalHashState = "private_withheld"
				}
				if op == "source_file_read" {
					f.OriginalCount = ptr(int64(0))
					f.OriginalHashState = "private_withheld"
					f.OriginalEOF = ptr(true)
					f.OriginalErrorPresent = ptr(true)
				}
			}
			got, err := mergeOriginalSourceAuditProjections(rows, []originalSourceAuditProjection{})
			if err != nil || !reflect.DeepEqual(got, rows) {
				t.Fatal("actual operation/diagnostic changed", err)
			}
		})
	}
}

// Source assembly input: native_authority_builder_source_test_fragment.go
// Source-only failure ownership; no Source installation, signatures, Native
// observations, SQL reservation or new epoch is supplied by these fixtures.
func TestOriginalAuthorityFailedBodyAttemptCannotBecomeFresh(t *testing.T) {
	for _, stage := range []string{"alive-registration", "unissued-choice-reservation", "issued-choice-reservation", "unissued-disposition", "issued-disposition"} {
		t.Run(stage, func(t *testing.T) {
			r := &OriginalFactoryRealm{originalBodies: map[string][]byte{}, records: map[string][]byte{}}
			first := r.buildOriginalAuthorityLocked(stage)
			if first == nil || r.authorityBodyAttempts[stage] == nil {
				t.Fatal("missing original Source installed a body")
			}
			// Even a later retained diagnostic BODY cannot renew the consumed attempt.
			r.originalBodies[stage] = []byte("retained private diagnostic")
			if again := r.buildOriginalAuthorityLocked(stage); again == nil || !errors.Is(again, first) {
				t.Fatal("failed original attempt was retried/reset")
			}
		})
	}
}

func TestOriginalAuthorityFailedSignKeepsOriginalErrorAndEnvelope(t *testing.T) {
	stage := "unissued-choice-reservation"
	cause := errors.New("actual original sign-return deadline")
	retained := []byte("actual returned envelope retained privately")
	r := &OriginalFactoryRealm{records: map[string][]byte{stage: bytes.Clone(retained)}, originalBodies: map[string][]byte{stage: []byte("actual body")}, authoritySignAttempts: map[string]error{stage: cause}}
	wire, err := r.signOriginalAuthorityLocked(context.Background(), stage, r.originalBodies[stage])
	if !errors.Is(err, cause) || !bytes.Equal(wire, retained) {
		t.Fatal("late original signing return was erased or promoted")
	}
	wire[0] = '!'
	if !bytes.Equal(r.records[stage], retained) {
		t.Fatal("diagnostic envelope aliases mutable caller memory")
	}
	if r.verifyOriginalStageLocked(stage, retained) == nil {
		t.Fatal("cached late signature became a trusted stage")
	}
}

// These exercise the production current-return fence, independently of Source
// installation or any cryptographic/SQL/Native qualification.
func TestOriginalAuthoritySigningKeepsChoiceAndIssueWindows(t *testing.T) {
	now := time.Now()
	worker, cancelWorker := context.WithDeadline(context.Background(), now.Add(time.Hour))
	defer cancelWorker()
	expiredChoice, cancelChoice := context.WithDeadline(worker, now.Add(-time.Hour))
	defer cancelChoice()
	for _, c := range []struct {
		name, stage string
		actual      context.Context
		grant, pre  time.Time
	}{
		{"choice_expired_worker_live", "unissued-choice-reservation", expiredChoice, time.Time{}, time.Time{}},
		{"issued_choice_expired_worker_live", "issued-choice-reservation", expiredChoice, now.Add(time.Hour), now.Add(time.Hour)},
		{"attachment_grant_expired_worker_live", "issued-attachment", worker, now.Add(-time.Hour), now.Add(time.Hour)},
		{"attachment_pre_expired_worker_live", "issued-attachment", worker, now.Add(time.Hour), now.Add(-time.Hour)},
	} {
		t.Run(c.name, func(t *testing.T) {
			if worker.Err() != nil || originalAuthoritySigningWindow(worker, c.actual, c.stage, c.grant, c.pre) == nil {
				t.Fatal("current signing return escaped its actual narrower original window")
			}
		})
	}
	t.Run("complete_current_window_is_only_source_fence", func(t *testing.T) {
		if err := originalAuthoritySigningWindow(worker, worker, "issued-attachment", now.Add(time.Hour), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	})
}

// Source assembly input: native_closing_seal_source_test_fragment.go
// Source-memory refusal fixtures only. EMPTY installation means no actual
// process, file, key, Native, SQL, successful join or live approval is supplied.
func TestOriginalClosingRefusalPermanentlySealsEffects(t *testing.T) {
	for _, name := range []string{"expired_caller_root_still_live", "Source_selection_unavailable", "unknown_admission_keeps_original_reservation"} {
		t.Run(name, func(t *testing.T) {
			started := time.Now().UTC()
			root, cancel := context.WithDeadline(context.Background(), started.Add(time.Minute))
			defer cancel()
			original := controlOwnerReservation{FactoryAttemptID: "retained Source-memory attempt", CreatorOwnerID: "retained Source-memory owner", State: "unknown_original_start"}
			control := &originalControl{admission: controlAdmissionState{state: "Source-memory admission before close", reservations: map[string]controlOwnerReservation{"original": original}}}
			if name == "unknown_admission_keeps_original_reservation" {
				control.admission.reservations = nil // unknown remains unknown, never an EMPTY proof
			}
			r := &OriginalFactoryRealm{ctx: root, started: started, deadline: started.Add(time.Minute), basal: &basalOwner{body: model.HostFactoryBasalOwnerObservation{OriginalContextDeadline: started.Add(time.Minute)}}, control: control, closeDone: make(chan struct{})}
			caller := root
			if name == "expired_caller_root_still_live" {
				expired, stop := context.WithDeadline(root, started.Add(-time.Second))
				defer stop()
				caller = expired
			}
			if e := r.CloseAndJoin(caller); e == nil {
				t.Fatal("refused close became successful native/source completion")
			}
			select {
			case <-r.closeDone:
			default:
				t.Fatal("actual close helper did not return")
			}
			if !r.closing || !control.publicationSealed || control.admission.state != "permanently_closed_for_completion" || control.closureReturned || control.closureCause == nil || root.Err() != nil {
				t.Fatal("consumed closer left live effects open or fabricated completion")
			}
			if control.admission.reservations != nil && control.admission.reservations["original"] != original {
				t.Fatal("closing reconstructed an unknown original reservation")
			}
			if name == "unknown_admission_keeps_original_reservation" && control.admission.reservations != nil {
				t.Fatal("unknown admission was converted to EMPTY")
			}
			first := r.closeErr
			if e := r.CloseAndJoin(root); e == nil || r.closeErr != first || len(control.ledgerSnapshots) != 0 || len(control.ownerReturns) != 0 || r.worker != nil || r.registrar != nil {
				t.Fatal("broader replay reopened effects, retried cleanup or synthesized owner facts")
			}
		})
	}
}

// Source assembly input: native_control_request_originals_source_test_fragment.go
// PATCH_ONLY CI corpus. These expectations and private token fixtures perform
// no IO/signing and install no original Realm, Source approval or native fact.
func rootRegistrarTerminalSyntaxFixture(t *testing.T, ordinary bool) controlRegistrarRequest {
	t.Helper()
	request, _ := rootRegistrarRPCSyntaxFixture(t)
	request.Phase, request.Ordinary = "terminal", ordinary
	request.SubjectOwnerID = ptr("00000000-0000-4000-8000-000000000005")
	request.InputFiles = []controlRegistrarInputFile{}
	_, _, files, err := controlRegistrarPhaseFiles("terminal", ordinary)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		original := []byte(`{"source_only_fixture":1}`)
		request.InputFiles = append(request.InputFiles, controlRegistrarInputFile{Basename: file.basename, OriginalBytes: len(original), OriginalSHA256: digest(original), StageSelector: file.selector})
	}
	return request
}

func TestHostFactorySourceRegistrarTerminalInputsPrecedeObservation(t *testing.T) {
	for _, ordinary := range []bool{false, true} {
		if err := controlRegistrarValidateRequest(rootRegistrarTerminalSyntaxFixture(t, ordinary)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name     string
		ordinary bool
		mutate   func(*controlRegistrarRequest)
	}{
		{"future-issued-disposition", false, func(r *controlRegistrarRequest) { r.InputFiles[1].StageSelector = "issued-disposition" }},
		{"future-unissued-disposition", false, func(r *controlRegistrarRequest) { r.InputFiles[1].StageSelector = "unissued-disposition" }},
		{"missing-actual-parent-join", false, func(r *controlRegistrarRequest) { r.InputFiles = r.InputFiles[:2] }},
		{"caller-selected-choice-stage", false, func(r *controlRegistrarRequest) { r.InputFiles[1].StageSelector = "choice-return" }},
		{"foreign-choice-path", false, func(r *controlRegistrarRequest) { r.InputFiles[1].Basename = "../creator.choice" }},
		{"future-ordinary-independent-read", true, func(r *controlRegistrarRequest) {
			r.InputFiles[1].Basename = "ordinary-independent-native-read.json"
			r.InputFiles[1].StageSelector = "core_independent_original_qemu_read_v1"
		}},
		{"future-ordinary-settlement", true, func(r *controlRegistrarRequest) { r.InputFiles[1].StageSelector = "settlement-return" }},
		{"ordinary-cannot-import-sealed-choice", true, func(r *controlRegistrarRequest) { r.InputFiles[1].StageSelector = "sealed-choice" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := rootRegistrarTerminalSyntaxFixture(t, tc.ordinary)
			tc.mutate(&r)
			if controlRegistrarValidateRequest(r) == nil {
				t.Fatal("terminal input requires a future result or changes the original recipe")
			}
		})
	}
}

func TestHostFactorySourceRegistrarPhaseTokenRetainsActualContext(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*originalNativePublisher, *originalNativePhaseReservation, *basalOwner, context.Context) context.Context
	}{
		{"missing-original-token", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			delete(p.phaseReservations, x.requestID)
			return c
		}},
		{"same-deadline-different-context", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			return context.WithValue(c, struct{}{}, 1)
		}},
		{"foreign-request-reservation", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			x.requestID = "00000000-0000-4000-8000-000000000099"
			return c
		}},
		{"foreign-root", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			x.factoryRoot = "foreign"
			return c
		}},
		{"foreign-owner", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			x.ownerID = "foreign"
			return c
		}},
		{"foreign-original-basal", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			x.primitiveSHA = "foreign"
			return c
		}},
		{"copied-basal-pointer", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			copy := *b
			p.basal = &copy
			return c
		}},
		{"already-completed", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			x.completed = true
			return c
		}},
		{"publication-sealed", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			p.sealed = true
			return c
		}},
		{"sticky-import-failure", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			p.importFailure = errors.New("original unknown")
			return c
		}},
		{"phase-called-at-bound", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			x.calledAt, _ = c.Deadline()
			return c
		}},
		{"phase-without-called-at", func(p *originalNativePublisher, x *originalNativePhaseReservation, b *basalOwner, c context.Context) context.Context {
			x.calledAt = time.Time{}
			return c
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
			defer cancel()
			ledger := &originalLedger{ownerID: "source-only-owner", ownerRole: "host_exterior", primitiveSHA: "source-only-basal"}
			basal := &basalOwner{ledger: ledger, sha: "source-only-basal"}
			basal.body.OriginalOwnerID, basal.body.Role = ledger.ownerID, ledger.ownerRole
			id := "00000000-0000-4000-8000-000000000001"
			x := &originalNativePhaseReservation{ctx: ctx, requestID: id, factoryRoot: "source-only-root", ownerID: ledger.ownerID, primitiveSHA: basal.sha, calledAt: time.Now().UTC()}
			p := &originalNativePublisher{basal: basal, rootContext: ctx, ledger: ledger, root: x.factoryRoot, phaseReservations: map[string]*originalNativePhaseReservation{id: x}}
			if err := controlRegistrarRequireOriginalPhase(p, ctx, id, basal); err != nil {
				t.Fatal(err) // private exact-pointer predicate only, no native capability
			}
			changed := tc.mutate(p, x, basal, ctx)
			if controlRegistrarRequireOriginalPhase(p, changed, id, basal) == nil {
				t.Fatal("changed original Source phase token accepted")
			}
		})
	}
}

func TestHostFactorySourceRegistrarParentGraphIsRequiredBeforeRequest(t *testing.T) {
	// Syntax expectations only. The real exporter must return under the SAME
	// Source phase before this recipe's last input is available; these bytes
	// never stand in for an original graph, syscall, signature or SQL FIRST.
	for _, recipe := range []struct {
		phase    string
		ordinary bool
		count    int
	}{
		{"initial", false, 6},
		{"worker", false, 5},
		{"worker", true, 5},
		{"terminal", false, 4},
		{"terminal", true, 3},
		{"closing", false, 0},
	} {
		_, _, inputs, err := controlRegistrarPhaseFiles(recipe.phase, recipe.ordinary)
		if err != nil || len(inputs) != recipe.count {
			t.Fatal("original phase recipe changed")
		}
		if recipe.phase != "closing" {
			last := inputs[len(inputs)-1]
			if last.basename != "registrar-"+recipe.phase+"-parent-native-export.json" || last.selector != "source-private-original-parent-native-export" {
				t.Fatal("actual parent graph must be the final normal-phase input")
			}
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*controlRegistrarRequest)
	}{
		{"missing-parent-graph", func(r *controlRegistrarRequest) { r.InputFiles = r.InputFiles[:len(r.InputFiles)-1] }},
		{"foreign-phase-parent-path", func(r *controlRegistrarRequest) {
			r.InputFiles[len(r.InputFiles)-1].Basename = "registrar-worker-parent-native-export.json"
		}},
		{"signed-stage-is-not-private-parent-graph", func(r *controlRegistrarRequest) {
			r.InputFiles[len(r.InputFiles)-1].StageSelector = "native-leaf-registrar-by-core"
		}},
		{"parent-graph-reordered", func(r *controlRegistrarRequest) {
			r.InputFiles[0], r.InputFiles[len(r.InputFiles)-1] = r.InputFiles[len(r.InputFiles)-1], r.InputFiles[0]
		}},
		{"parent-graph-duplicated", func(r *controlRegistrarRequest) { r.InputFiles[0] = r.InputFiles[len(r.InputFiles)-1] }},
		{"future-terminal-result-is-not-parent-graph", func(r *controlRegistrarRequest) {
			r.InputFiles[len(r.InputFiles)-1].StageSelector = "issued-disposition"
		}},
		{"closing-cannot-resample-parent", func(r *controlRegistrarRequest) {
			r.Phase, r.OriginalPhaseCalledAt = "closing", nil
			r.InputFiles = r.InputFiles[len(r.InputFiles)-1:]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, _ := rootRegistrarRPCSyntaxFixture(t)
			tc.mutate(&request)
			if controlRegistrarValidateRequest(request) == nil {
				t.Fatal("missing, future or changed parent-original input accepted")
			}
		})
	}
}

// This synthetic context isolates the deadline comparison when Err has not
// observed expiry. It supplies no approved Source context or publication owner.
type rootRegistrarDeadlineOnlyContext struct {
	context.Context
	deadline time.Time
}

func (c rootRegistrarDeadlineOnlyContext) Deadline() (time.Time, bool) {
	return c.deadline, true
}

func TestHostFactorySourceRegistrarPublicationRetainsSmallerBound(t *testing.T) {
	future := time.Now().Add(time.Minute)
	current, cancel := context.WithDeadline(context.Background(), future)
	defer cancel()
	if err := controlRegistrarPublicationBound(current, future); err != nil {
		t.Fatal(err)
	}
	canceled, canceledRelease := context.WithDeadline(context.Background(), future)
	canceledRelease()
	past := time.Now().Add(-time.Minute)
	for _, tc := range []struct {
		name  string
		ctx   context.Context
		bound time.Time
	}{
		{"nil-original-context", nil, future},
		{"unbounded-original-context", context.Background(), future},
		{"actual-deadline-before-cancel-observed", rootRegistrarDeadlineOnlyContext{context.Background(), past}, past},
		{"canceled-before-deadline", canceled, future},
		{"different-retained-deadline", current, future.Add(time.Nanosecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if controlRegistrarPublicationBound(tc.ctx, tc.bound) == nil {
				t.Fatal("late, missing or different publication context accepted")
			}
		})
	}
}

// Source assembly input: native_control_rpc_source_test_fragment.go
// PATCH_ONLY remote Source-only boundary corpus. No approved tuple, key,
// original actor, VM, registrar process or native observation is installed.
func rootRegistrarRPCSyntaxFixture(t *testing.T) (controlRegistrarRequest, [][]byte) {
	t.Helper()
	started := time.Now().UTC()
	request := controlRegistrarRequest{Schema: "original_private_registrar_request_v1", RequestID: "00000000-0000-4000-8000-000000000001", Phase: "initial", FactoryRootID: "00000000-0000-4000-8000-000000000002", CoreOwnerID: "00000000-0000-4000-8000-000000000003", RegistrarOwnerID: "00000000-0000-4000-8000-000000000004", SourceApprovalSHA256: strings.Repeat("a", 64), RootPreparationSHA256: strings.Repeat("b", 64), OriginalContextStartedAt: started.Format(time.RFC3339Nano), OriginalContextDeadline: started.Add(600 * time.Second).Format(time.RFC3339Nano), OriginalEffectivePhaseDeadline: started.Add(30 * time.Second).Format(time.RFC3339Nano), OriginalPhaseCalledAt: ptr(started.Format(time.RFC3339Nano)), InputFiles: []controlRegistrarInputFile{}}
	_, _, fixed, err := controlRegistrarPhaseFiles("initial", false)
	if err != nil {
		t.Fatal(err)
	}
	inputs := [][]byte{}
	for _, file := range fixed {
		raw := []byte(`{"source_only_fixture":1}`)
		request.InputFiles = append(request.InputFiles, controlRegistrarInputFile{Basename: file.basename, OriginalBytes: len(raw), OriginalSHA256: digest(raw), StageSelector: file.selector})
		inputs = append(inputs, raw)
	}
	return request, inputs
}

func TestHostFactorySourceRegistrarRPCClosedPrivateExpectations(t *testing.T) {
	request, inputs := rootRegistrarRPCSyntaxFixture(t)
	raw, err := controlRegistrarEncodeRequest(request, inputs)
	if err != nil {
		t.Fatal(err)
	}
	// Codec success creates syntax expectations only. It cannot install the
	// compiled EMPTY registry, read/approve keys or make any native capacity.
	for name, mutate := range map[string]func([]byte) []byte{
		"duplicate-request-id": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"request_id":`), []byte(`"request_id":"00000000-0000-4000-8000-000000000099","request_id":`), 1)
		},
		"case-alias":                    func(b []byte) []byte { return bytes.Replace(b, []byte(`"request_id":`), []byte(`"Request_ID":`), 1) },
		"missing-explicit-null-subject": func(b []byte) []byte { return bytes.Replace(b, []byte(`"subject_owner_id":null,`), nil, 1) },
		"unknown-native-fact":           func(b []byte) []byte { return append([]byte(`{"native_absence":true,`), b[1:]...) },
		"null-input-list": func(b []byte) []byte {
			var fields map[string]json.RawMessage
			if json.Unmarshal(b, &fields) != nil {
				t.Fatal("fixture decode")
			}
			fields["input_files"] = json.RawMessage(`null`)
			out, _ := json.Marshal(fields)
			return out
		},
		"arbitrary-input-path": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`registrar-initial-source-approval.json`), []byte(`../foreign.json`), 1)
		},
		"wrong-selected-stage": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"stage_selector":"source-approval"`), []byte(`"stage_selector":"latest"`), 1)
		},
		"duplicate-original-phase-origin": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"original_phase_called_at":`), []byte(`"original_phase_called_at":null,"original_phase_called_at":`), 1)
		},
		"null-positive-phase-origin": func(b []byte) []byte {
			var fields map[string]json.RawMessage
			if json.Unmarshal(b, &fields) != nil {
				t.Fatal("fixture decode")
			}
			fields["original_phase_called_at"] = json.RawMessage(`null`)
			out, _ := json.Marshal(fields)
			return out
		},
		"missing-source-phase-origin": func(b []byte) []byte {
			var fields map[string]json.RawMessage
			if json.Unmarshal(b, &fields) != nil {
				t.Fatal("fixture decode")
			}
			delete(fields, "original_phase_called_at")
			out, _ := json.Marshal(fields)
			return out
		},
		"trailing-second-document": func(b []byte) []byte { return append(b, []byte(`{}`)...) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := controlRegistrarDecodeRequest(mutate(bytes.Clone(raw))); err == nil {
				t.Fatal("private request changed original custody/meaning")
			}
		})
	}
	t.Run("phase-origin-at-deadline", func(t *testing.T) {
		changed := request
		changed.OriginalPhaseCalledAt = ptr(changed.OriginalEffectivePhaseDeadline)
		if controlRegistrarValidateRequest(changed) == nil {
			t.Fatal("phase starts at its bound")
		}
	})
	t.Run("closing-has-no-native-phase-origin", func(t *testing.T) {
		changed := request
		changed.Phase, changed.InputFiles = "closing", []controlRegistrarInputFile{}
		if controlRegistrarValidateRequest(changed) == nil {
			t.Fatal("closing imported native origin")
		}
		changed.OriginalPhaseCalledAt = nil
		if err := controlRegistrarValidateRequest(changed); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("different-input-original", func(t *testing.T) {
		wrong := append([][]byte(nil), inputs...)
		wrong[0] = []byte("foreign original")
		if _, err := controlRegistrarEncodeRequest(request, wrong); err == nil {
			t.Fatal("foreign original input accepted by cached byte relation")
		}
	})
	t.Run("request-cannot-extend-actual-parent", func(t *testing.T) {
		started, _ := controlRegistrarCanonicalTime(request.OriginalContextStartedAt)
		parent, cancel := context.WithDeadline(context.Background(), started.Add(10*time.Second))
		defer cancel()
		if child, childCancel, err := controlRegistrarOriginalPhaseContext(parent, request); err == nil {
			childCancel()
			_ = child
			t.Fatal("private expected deadline extended actual original actor")
		}
	})
	t.Run("derive-exact-before-observation", func(t *testing.T) {
		declared, _ := controlRegistrarCanonicalTime(request.OriginalContextDeadline)
		parent, cancel := context.WithDeadline(context.Background(), declared)
		defer cancel()
		child, childCancel, err := controlRegistrarOriginalPhaseContext(parent, request)
		if err != nil {
			t.Fatal(err)
		}
		defer childCancel()
		actual, ok := child.Deadline()
		bound, _ := controlRegistrarCanonicalTime(request.OriginalEffectivePhaseDeadline)
		if !ok || !actual.Equal(bound) {
			t.Fatal("child phase bound differs from original Source expectation")
		}
	})
}

func TestHostFactorySourceRegistrarRPCClosedReplyWithoutNativeAuthority(t *testing.T) {
	valid := []byte(`{"schema":"original_private_registrar_reply_v1","request_id":"00000000-0000-4000-8000-000000000001","phase":"initial","factory_root_id":"00000000-0000-4000-8000-000000000002","registrar_owner_id":"00000000-0000-4000-8000-000000000004","root_preparation_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","result":"refused_original","original_export_manifest":null}`)
	for name, mutate := range map[string]func([]byte) []byte{
		"duplicate-result": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"result":`), []byte(`"result":"returned_original","result":`), 1)
		},
		"case-alias": func(b []byte) []byte { return bytes.Replace(b, []byte(`"phase":`), []byte(`"Phase":`), 1) },
		"refused-cannot-smuggle-manifest": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"original_export_manifest":null`), []byte(`"original_export_manifest":{"capacity":1}`), 1)
		},
		"returned-cannot-drop-manifest": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`refused_original`), []byte(`returned_original`), 1)
		},
		"unknown-authority-flag":   func(b []byte) []byte { return append([]byte(`{"native_approved":true,`), b[1:]...) },
		"trailing-second-document": func(b []byte) []byte { return append(b, []byte(`{}`)...) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := controlRegistrarDecodeReply(mutate(bytes.Clone(valid))); err == nil {
				t.Fatal("unknown/ambiguous/refused reply changed phase meaning")
			}
		})
	}
	// Even a syntactically valid returned object is not Native authority. The
	// fixed Source9 complete manifest+custody/source basis verifier is mandatory
	// in Exchange before any original bytes can become an accepted result.
	if _, err := controlRegistrarDecodeReply(valid); err != nil {
		t.Fatal(err)
	}
}

// Source assembly input: native_exterior_composer_source_test_fragment.go
// Synthetic chronology/identity discriminants only: no native reader, trust,
// Source installation, signature, SQL-FIRST or original child is fabricated.
func TestHostExteriorComposerFreshWindowSource(t *testing.T) {
	origin := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithDeadline(context.Background(), origin.Add(30*time.Second))
	defer cancel()
	for _, tc := range []struct {
		name   string
		mutate func(*originalNativePhaseReservation, *originalExteriorChildSnapshot, *model.HostFactoryNativeProcess, *model.HostFactoryNativeProcess, *model.HostFactoryNativeProcess, *time.Time)
	}{
		{"same_lifetime_fresh_after_original_child_close", func(*originalNativePhaseReservation, *originalExteriorChildSnapshot, *model.HostFactoryNativeProcess, *model.HostFactoryNativeProcess, *model.HostFactoryNativeProcess, *time.Time) {
		}},
		{"cached_reader_before_child_close", func(_ *originalNativePhaseReservation, c *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, _ *time.Time) {
			f.OriginalNativeReadStartedAt = c.pinClose.OriginalReturnedAt.Add(-time.Nanosecond)
		}},
		{"fresh_before_phase_origin", func(p *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, _ *time.Time) {
			f.OriginalNativeReadStartedAt = p.calledAt.Add(-time.Nanosecond)
		}},
		{"reused_pid_changed_start_ticks", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, _ *time.Time) {
			f.StartTicks++
		}},
		{"foreign_host_boot", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, _ *time.Time) {
			f.HostBootID = "foreign"
		}},
		{"foreign_bootstrap", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, _ *time.Time) {
			f.BootstrapReturnSHA256 = "foreign"
		}},
		{"foreign_nonce", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, _ *time.Time) {
			f.ProcessNonceSHA256 = "foreign"
		}},
		{"changed_uid", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, _ *time.Time) {
			f.UID++
		}},
		{"changed_executable", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, _ *time.Time) {
			f.Execution.ExecutableInode++
		}},
		{"foreign_worker_parent", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, w, _ *model.HostFactoryNativeProcess, _ *time.Time) {
			w.PPID++
		}},
		{"outer_return_unknown", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, _ *model.HostFactoryNativeProcess, r *time.Time) {
			*r = time.Time{}
		}},
		{"stat_close_cannot_replace_later_actual_poll_return", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, r *time.Time) {
			*r = f.OriginalNativeCloseReturnedAt
		}},
		{"missing_fresh_executable_close", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, _ *time.Time) {
			f.Execution.OriginalExecutableCloseReturnedAt = time.Time{}
		}},
		{"cmdline_close_before_its_original_return", func(_ *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, f *model.HostFactoryNativeProcess, _ *time.Time) {
			f.Execution.OriginalCmdlineCloseReturnedAt = f.Execution.OriginalCmdlineReadReturnedAt.Add(-time.Nanosecond)
		}},
		{"return_at_actual_deadline", func(p *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, _ *model.HostFactoryNativeProcess, r *time.Time) {
			*r, _ = p.ctx.Deadline()
		}},
		{"unbounded_replacement_context", func(p *originalNativePhaseReservation, _ *originalExteriorChildSnapshot, _, _, _ *model.HostFactoryNativeProcess, _ *time.Time) {
			p.ctx = context.Background()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			phase := &originalNativePhaseReservation{ctx: ctx, calledAt: origin}
			child := originalExteriorChildSnapshot{pinClose: model.HostFactoryPrimitiveIOReturn{OriginalReturnedAt: ptr(origin.Add(time.Second))}}
			old := model.HostFactoryNativeProcess{PID: 42, PPID: 41, StartTicks: 7, HostBootID: "synthetic-boot", UID: 1, GID: 2, BootstrapReturnSHA256: "synthetic-bootstrap", ProcessNonceSHA256: "synthetic-nonce"}
			old.Execution.OriginalExecutableReadStartedAt = origin.Add(100 * time.Millisecond)
			old.Execution.OriginalExecutableReadReturnedAt = origin.Add(200 * time.Millisecond)
			old.Execution.OriginalExecutableCloseReturnedAt = origin.Add(300 * time.Millisecond)
			old.Execution.OriginalCmdlineReadReturnedAt = origin.Add(400 * time.Millisecond)
			old.Execution.OriginalCmdlineCloseReturnedAt = origin.Add(500 * time.Millisecond)
			worker := model.HostFactoryNativeProcess{PID: 43, PPID: 42, HostBootID: old.HostBootID}
			fresh := old
			fresh.OriginalNativeReadStartedAt = origin.Add(2 * time.Second)
			fresh.Execution.OriginalExecutableReadStartedAt = origin.Add(2200 * time.Millisecond)
			fresh.Execution.OriginalExecutableReadReturnedAt = origin.Add(2300 * time.Millisecond)
			fresh.Execution.OriginalExecutableCloseReturnedAt = origin.Add(2400 * time.Millisecond)
			fresh.Execution.OriginalCmdlineReadReturnedAt = origin.Add(2500 * time.Millisecond)
			fresh.Execution.OriginalCmdlineCloseReturnedAt = origin.Add(2600 * time.Millisecond)
			fresh.OriginalNativeReadReturnedAt = origin.Add(2800 * time.Millisecond)
			fresh.OriginalNativeCloseReturnedAt = origin.Add(3 * time.Second)
			fresh.OriginalSubjectNativePin.OriginalObservedAt = origin.Add(4 * time.Second)
			returned := origin.Add(5 * time.Second)
			tc.mutate(phase, &child, &old, &worker, &fresh, &returned)
			if (exteriorOriginalFreshWindow(phase, child, old, worker, fresh, returned) == nil) != (tc.name == "same_lifetime_fresh_after_original_child_close") {
				t.Fatal("fresh current identity/window disposition")
			}
		})
	}
}

func TestHostExteriorComposerOriginalChildBindingSource(t *testing.T) {
	o := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func(*originalExteriorChildSnapshot, *exteriorOriginalSources)
	}{
		{"same_original_start_scope_creator_choice", func(*originalExteriorChildSnapshot, *exteriorOriginalSources) {}},
		{"foreign_original_scope", func(c *originalExteriorChildSnapshot, _ *exteriorOriginalSources) { c.originalBindingSHA = "foreign" }},
		{"subject_owner_is_not_primitive_hash", func(c *originalExteriorChildSnapshot, _ *exteriorOriginalSources) { c.workerOwnerID = "primitive-hash" }},
		{"another_original_command", func(c *originalExteriorChildSnapshot, _ *exteriorOriginalSources) { c.commandID = "foreign" }},
		{"rewritten_original_start_return", func(c *originalExteriorChildSnapshot, _ *exteriorOriginalSources) {
			c.start.OriginalReturnedAt = ptr(o.Add(2 * time.Second))
		}},
		{"wait_precedes_actual_choice_close", func(c *originalExteriorChildSnapshot, b *exteriorOriginalSources) {
			c.wait.OriginalReturnedAt = ptr(b.choice.OriginalDirectoryCloseReturnedAt.Add(-time.Nanosecond))
		}},
		{"worker_leaf_after_actual_registration", func(_ *originalExteriorChildSnapshot, b *exteriorOriginalSources) {
			b.workerLeaf.ObservedAt = b.registration.CoreRegisteredAt.Add(time.Nanosecond)
		}},
		{"registration_after_choice_write", func(_ *originalExteriorChildSnapshot, b *exteriorOriginalSources) {
			b.registration.CoreRegisteredAt = b.choice.OriginalWriteStartedAt.Add(time.Nanosecond)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := exteriorOriginalSources{scopeSHA: "scope", scope: model.HostFactoryPreAuthorityScope{CreatorOwnerID: "creator"}, start: model.HostFactoryOriginalStartReturn{OriginalCommandHandleID: "command", OriginalWorkerPID: 43, OriginalWorkerStartCalledAt: o, OriginalWorkerStartReturnedAt: o.Add(time.Second)}, workerLeaf: model.HostFactoryNativeLeaf{ObservedAt: o.Add(2 * time.Second)}, registration: model.HostFactoryAliveRegistration{CoreRegisteredAt: o.Add(3 * time.Second)}, choice: model.HostFactoryChoiceReturn{OriginalWriteStartedAt: o.Add(4 * time.Second), OriginalDirectoryCloseReturnedAt: o.Add(5 * time.Second)}}
			c := originalExteriorChildSnapshot{commandID: "command", workerPID: 43, workerOwnerID: "creator", originalBindingSHA: "scope", start: model.HostFactoryPrimitiveIOReturn{OriginalCalledAt: ptr(o), OriginalReturnedAt: ptr(o.Add(time.Second))}, wait: model.HostFactoryPrimitiveIOReturn{OriginalReturnedAt: ptr(o.Add(6 * time.Second))}, pinClose: model.HostFactoryPrimitiveIOReturn{OriginalReturnedAt: ptr(o.Add(7 * time.Second))}}
			tc.mutate(&c, &b)
			if (exteriorOriginalChildBasis(c, b) == nil) != (tc.name == "same_original_start_scope_creator_choice") {
				t.Fatal("original child basis disposition")
			}
		})
	}
}

func TestHostExteriorComposerUnavailableSource(t *testing.T) {
	t.Run("missing_original_source_does_not_create_join", func(t *testing.T) {
		if _, body, env, err := composeOriginalExteriorJoin(context.Background(), nil, nil, nil, nil); err == nil || body != nil || env != nil {
			t.Fatal("absent original supplier produced join")
		}
	})
	t.Run("missing_original_acquisition_does_not_repin", func(t *testing.T) {
		if exteriorOriginalScopedPin(nil, nil, nil) == nil {
			t.Fatal("missing acquisition accepted")
		}
	})
}

func TestHostExteriorComposerOriginalAttemptSource(t *testing.T) {
	// Private membership/once kernel only. No original source constructor,
	// profile/authority, native observer or SQL-FIRST is supplied by this test.
	t.Run("first_pending_attempt_cannot_take_a_second_observation", func(t *testing.T) {
		phase := &originalNativePhaseReservation{requestID: "synthetic-original-slot", aggregateAttempts: map[string]*originalNativeAggregateAttempt{}}
		p := &originalNativePublisher{activePhase: phase, phaseReservations: map[string]*originalNativePhaseReservation{phase.requestID: phase}}
		if exteriorOriginalReserveComposer(p, phase) != nil || exteriorOriginalReserveComposer(p, phase) == nil {
			t.Fatal("pending original attempt was repeated")
		}
		if phase.completed || len(phase.aggregateAttempts) != 0 {
			t.Fatal("source latch fabricated publication or consumed other stages")
		}
	})
	t.Run("same_id_foreign_phase_pointer_cannot_reserve", func(t *testing.T) {
		phase := &originalNativePhaseReservation{requestID: "synthetic-original-slot"}
		p := &originalNativePublisher{activePhase: phase, phaseReservations: map[string]*originalNativePhaseReservation{phase.requestID: phase}}
		foreign := &originalNativePhaseReservation{requestID: phase.requestID}
		if exteriorOriginalReserveComposer(p, foreign) == nil || phase.exteriorJoinAttempted || foreign.exteriorJoinAttempted {
			t.Fatal("foreign phase consumed original slot")
		}
	})
}

func TestHostExteriorComposerPreparedCommandCustodySource(t *testing.T) {
	// Synthetic relationship checks only. The two command identities model
	// different actual owners; this case supplies no process or native proof.
	for _, tc := range []struct {
		name   string
		mutate func(*model.HostFactoryPreparedCreatePlan, *string, *string, *exteriorOriginalSources)
	}{
		{"worker_launch_and_worker_owned_create_are_distinct", func(*model.HostFactoryPreparedCreatePlan, *string, *string, *exteriorOriginalSources) {}},
		{"parent_launch_cannot_replace_worker_owned_create", func(p *model.HostFactoryPreparedCreatePlan, _, _ *string, b *exteriorOriginalSources) {
			p.OriginalCreateCommandHandleID = b.start.OriginalCommandHandleID
		}},
		{"foreign_worker_plan", func(p *model.HostFactoryPreparedCreatePlan, _, _ *string, _ *exteriorOriginalSources) {
			p.OwnerPrimitiveRawSHA256 = "another-worker"
		}},
		{"start_worker_differs_from_plan_worker", func(_ *model.HostFactoryPreparedCreatePlan, _, _ *string, b *exteriorOriginalSources) {
			b.start.WorkerPrimitiveRawSHA256 = "another-worker"
		}},
		{"plan_not_original_registered_body", func(_ *model.HostFactoryPreparedCreatePlan, sha, _ *string, _ *exteriorOriginalSources) {
			*sha = "another-plan"
		}},
		{"plan_under_another_scope", func(p *model.HostFactoryPreparedCreatePlan, _, _ *string, _ *exteriorOriginalSources) {
			p.BindingSHA256 = "another-scope"
		}},
		{"plan_under_legacy_root_binding", func(p *model.HostFactoryPreparedCreatePlan, _, _ *string, _ *exteriorOriginalSources) {
			p.BindingSchema = "original_host_factory_root_preparation_v4"
		}},
		{"plan_for_another_target", func(p *model.HostFactoryPreparedCreatePlan, _, _ *string, _ *exteriorOriginalSources) {
			p.StableOriginalTargetSHA256 = "another-target"
		}},
		{"plan_for_another_registry", func(p *model.HostFactoryPreparedCreatePlan, _, _ *string, _ *exteriorOriginalSources) {
			p.FactoryRegistrySHA256 = "another-registry"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := exteriorOriginalSources{scopeSHA: "scope", scope: model.HostFactoryPreAuthorityScope{StableOriginalTargetSHA256: "target", FactoryRegistrySHA256: "registry"}, start: model.HostFactoryOriginalStartReturn{OriginalCommandHandleID: "parent-worker-launch", WorkerPrimitiveRawSHA256: "worker"}, registration: model.HostFactoryAliveRegistration{PreparedCreatePlanSHA256: "plan"}}
			plan := model.HostFactoryPreparedCreatePlan{OriginalCreateCommandHandleID: "worker-qemu-create", OwnerPrimitiveRawSHA256: "worker", BindingSchema: "original_host_factory_pre_authority_scope_v4", BindingSHA256: "scope", StableOriginalTargetSHA256: "target", FactoryRegistrySHA256: "registry"}
			planSHA, workerSHA := "plan", "worker"
			tc.mutate(&plan, &planSHA, &workerSHA, &b)
			if (exteriorOriginalPlanBasis(plan, planSHA, workerSHA, b) == nil) != (tc.name == "worker_launch_and_worker_owned_create_are_distinct") {
				t.Fatal("prepared command custody disposition")
			}
		})
	}
}

// Source assembly input: native_final_cold_metadata_source_test_fragment.go
// These private codec discriminants install no Source profile, key or Realm.
// They are written for remote Source CI, and have not been executed locally.
func TestHostOriginalFinalColdCanonicalMetadata(t *testing.T) {
	value := originalWorkerSignedFrame{Schema: "source_private_original_final_source_audit_signed_frame_v1", Selector: "final-source-audit-worker", EnvelopeRaw: []byte(`{"public_metadata":true}`)}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("same_exact_bytes_roundtrip", func(t *testing.T) {
		var decoded originalWorkerSignedFrame
		if coldOriginalFinalCanonical(raw, &decoded, len(raw)) != nil || !bytes.Equal(decoded.EnvelopeRaw, value.EnvelopeRaw) {
			t.Fatal("canonical original changed")
		}
	})
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"whitespace_alias", func(b []byte) []byte { return append([]byte(" "), b...) }},
		{"trailing_second_value", func(b []byte) []byte { return append(b, []byte(`{}`)...) }},
		{"unknown_member", func(b []byte) []byte { return append([]byte(`{"extra":1,`), b[1:]...) }},
		{"duplicate_member", func(b []byte) []byte { return append([]byte(`{"schema":"other",`), b[1:]...) }},
		{"missing_required_member", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"selector":"final-source-audit-worker",`), nil, 1)
		}},
		{"byte_array_not_base64_string", func(b []byte) []byte {
			start := bytes.Index(b, []byte(`"envelope_raw":`)) + len(`"envelope_raw":`)
			return append(append(bytes.Clone(b[:start]), []byte(`[1,2]`)...), byte('}'))
		}},
		{"escaped_base64_json_alias", func(b []byte) []byte {
			start := bytes.Index(b, []byte(`"envelope_raw":"`)) + len(`"envelope_raw":"`)
			// The fixture's first base64 byte is 'e'. Same decoded string is
			// deliberately rejected by exact original JSON custody.
			return append(append(bytes.Clone(b[:start]), []byte(`\u0065`)...), b[start+1:]...)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoded originalWorkerSignedFrame
			if coldOriginalFinalCanonical(test.mutate(bytes.Clone(raw)), &decoded, 65536) == nil {
				t.Fatal("non-original wire accepted")
			}
		})
	}
	t.Run("null_original_stays_unknown_not_known_empty", func(t *testing.T) {
		start := bytes.Index(raw, []byte(`"envelope_raw":`)) + len(`"envelope_raw":`)
		unknown := append(append(bytes.Clone(raw[:start]), []byte(`null`)...), byte('}'))
		var decoded originalWorkerSignedFrame
		// Null is a retained unavailable value. The later envelope/body/auth
		// gates must refuse it; this codec must not synthesize empty bytes.
		if coldOriginalFinalCanonical(unknown, &decoded, 65536) != nil || decoded.EnvelopeRaw != nil {
			t.Fatal("unknown original normalized")
		}
	})
	t.Run("exact_limit_no_lift", func(t *testing.T) {
		var decoded originalWorkerSignedFrame
		if coldOriginalFinalCanonical(raw, &decoded, len(raw)-1) == nil {
			t.Fatal("caller cap lifted")
		}
	})
	t.Run("missing_typed_destination", func(t *testing.T) {
		if coldOriginalFinalCanonical(raw, nil, 65536) == nil {
			t.Fatal("unknown target accepted")
		}
	})
}

// Source assembly input: native_final_cold_source_test_fragment.go
// These metadata/native-return shapes have NO compiled installation, signing
// key, authentic Basal/bootstrap, SQL FIRST or native permission. They exercise
// the named private comparisons only; the exported default remains unavailable.
func coldFinalTestID(n int) string       { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }
func coldFinalTestTime(n int) time.Time  { return time.Date(2026, 10, 15, 0, 0, n, 0, time.UTC) }
func coldFinalTestPointer[T any](v T) *T { return &v }
func coldFinalTestStream(operations []string, count int64) originalFinalSourceAuditStream {
	root, owner, handle := coldFinalTestID(1), coldFinalTestID(2), coldFinalTestID(3)
	rows := []originalSourceAuditProjection{}
	closeID := handle + ":" + fmt.Sprint(len(operations))
	for n, operation := range operations {
		called := coldFinalTestTime(10 + n)
		fact := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: root, OriginalAuditHandleID: handle, OriginalCallID: coldFinalTestPointer(handle + ":" + fmt.Sprint(n+1)), Operation: operation, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: coldFinalTestPointer(called.Add(time.Nanosecond)), OriginalOperationDeadline: coldFinalTestTime(59), OriginalErrorPresent: coldFinalTestPointer(false), OriginalHashState: "not_byte_operation"}
		if operation == "source_file_read" {
			fact.OriginalCount = coldFinalTestPointer(count)
			fact.OriginalEOF = coldFinalTestPointer(false)
			fact.OriginalHashState = "private_withheld"
			if n == len(operations)-3 && len(operations) > 5 {
				fact.OriginalCount = coldFinalTestPointer(int64(0))
				fact.OriginalEOF = coldFinalTestPointer(true)
				fact.OriginalErrorPresent = coldFinalTestPointer(true)
			}
		}
		rows = append(rows, originalSourceAuditProjection{Family: "source_audit", SubjectIdentity: originalSourceAuditSubject{SubjectKind: "source_file"}, Fact: fact, OriginalCloseReference: &closeID})
	}
	return originalFinalSourceAuditStream{1, owner, "host_exterior", "original_host_factory_source_approval_v4", digest([]byte("approval")), handle, rows}
}
func coldFinalTestInputs() coldOriginalFinalInputs {
	return coldOriginalFinalInputs{installation: fixedInstallation{approval: model.HostFactorySourceApproval{OriginalApprovalDeadline: coldFinalTestTime(59)}}, preparation: model.HostFactoryRootPreparation{FactoryRootID: coldFinalTestID(1), SourceApprovalSHA256: digest([]byte("approval")), OriginalContextStartedAt: coldFinalTestTime(0)}, core: model.HostFactoryBasalOwnerObservation{OriginalOwnerID: coldFinalTestID(2)}}
}

func TestHostOriginalFinalColdSourceStream(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*originalFinalSourceAuditStream)
		accept bool
	}{
		{"count65537_complete_private_diagnostic", func(s *originalFinalSourceAuditStream) {}, true},
		{"count65538_refused", func(s *originalFinalSourceAuditStream) {
			s.OriginalSourceAuditProjections[2].Fact.OriginalCount = coldFinalTestPointer(int64(65538))
		}, false},
		{"private_whole_hash_refused", func(s *originalFinalSourceAuditStream) {
			s.OriginalSourceAuditProjections[2].Fact.OriginalSHA256 = coldFinalTestPointer(digest([]byte("withheld")))
		}, false},
		{"private_prefix_hash_refused", func(s *originalFinalSourceAuditStream) {
			s.OriginalSourceAuditProjections[2].Fact.RetainedPrefixSHA256 = coldFinalTestPointer(digest([]byte("withheld")))
		}, false},
		{"actual_read_error_metadata_retained", func(s *originalFinalSourceAuditStream) {
			s.OriginalSourceAuditProjections[2].Fact.OriginalErrorPresent = coldFinalTestPointer(true)
		}, true},
		{"missing_literal_close_refused", func(s *originalFinalSourceAuditStream) {
			s.OriginalSourceAuditProjections = s.OriginalSourceAuditProjections[:3]
		}, false},
		{"close_as_read_refused", func(s *originalFinalSourceAuditStream) {
			s.OriginalSourceAuditProjections[3].Fact.Operation = "source_file_read"
		}, false},
		{"call_ordinal_gap_refused", func(s *originalFinalSourceAuditStream) {
			s.OriginalSourceAuditProjections[2].Fact.OriginalCallID = coldFinalTestPointer(s.OriginalHandleID + ":7")
		}, false},
		{"foreign_binding_refused", func(s *originalFinalSourceAuditStream) { s.OriginalSourceBindingSHA256 = digest([]byte("foreign")) }, false},
		{"ordinary_role_alias_refused", func(s *originalFinalSourceAuditStream) { s.OriginalSourceOwnerRole = "factory_ordinary_worker" }, false},
		{"return_at_deadline_refused", func(s *originalFinalSourceAuditStream) {
			s.OriginalSourceAuditProjections[2].Fact.OriginalReturnedAt = coldFinalTestPointer(coldFinalTestTime(59))
		}, false},
		{"normalized_EOF_error_refused", func(s *originalFinalSourceAuditStream) {
			s.OriginalSourceAuditProjections[2].Fact.OriginalEOF = coldFinalTestPointer(true)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := coldFinalTestInputs()
			s := coldFinalTestStream([]string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_close"}, 65537)
			tc.change(&s)
			rows, err := c.sourceStream(s, digest([]byte("scope")), map[string]bool{}, nil)
			if (err == nil) != tc.accept {
				t.Fatal("Source-only stream disposition", err)
			}
			if tc.accept {
				raw, err := coldOriginalFinalArray(rows, uint32(len(rows)))
				if err != nil || len(raw) == 0 {
					t.Fatal("diagnostic dropped from complete Source-only array", err)
				}
			}
		})
	}
	t.Run("duplicate_handle_refused", func(t *testing.T) {
		c := coldFinalTestInputs()
		s := coldFinalTestStream([]string{"source_directory_open", "source_directory_fstat", "source_directory_close"}, 0)
		if _, err := c.sourceStream(s, "", map[string]bool{s.OriginalHandleID: true}, nil); err == nil {
			t.Fatal("duplicate stream accepted")
		}
	})
	t.Run("whole_census_mismatch_refused", func(t *testing.T) {
		s := coldFinalTestStream([]string{"source_directory_open", "source_directory_fstat", "source_directory_close"}, 0)
		if _, err := coldOriginalFinalArray(s.OriginalSourceAuditProjections, 2); err == nil {
			t.Fatal("subset census accepted")
		}
	})
}

func TestHostOriginalFinalColdArtifactReader(t *testing.T) {
	makeRead := func() originalFinalSourceAuditArtifactReadCustody {
		stream := coldFinalTestStream([]string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_read", "source_file_fstat", "source_file_close"}, 3)
		closeID := *stream.OriginalSourceAuditProjections[0].OriginalCloseReference
		selection := postStartSourceSelection{OriginalSourceOwnerID: coldFinalTestID(2), OriginalSourceOwnerRole: "host_exterior", OriginalSourceBindingSchema: stream.OriginalSourceBindingSchema, OriginalSourceBindingSHA256: stream.OriginalSourceBindingSHA256, OriginalHandleID: stream.OriginalHandleID, OriginalAnchorHandleID: coldFinalTestPointer(coldFinalTestID(4)), OriginalCallReferences: []string{}, OriginalCloseCallID: &closeID, OriginalStreamState: "closed_file"}
		for _, row := range stream.OriginalSourceAuditProjections {
			selection.OriginalCallReferences = append(selection.OriginalCallReferences, *row.Fact.OriginalCallID)
		}
		return originalFinalSourceAuditArtifactReadCustody{Schema: "source_private_original_final_source_audit_artifact_read_custody_v1", OriginalBodyWire: []byte("abc"), OriginalReaderSelection: selection, OriginalReaderProjections: stream.OriginalSourceAuditProjections}
	}
	for _, tc := range []struct {
		name   string
		change func(*originalFinalSourceAuditArtifactReadCustody)
		accept bool
	}{
		{"whole_closed_reader_structural_only", func(r *originalFinalSourceAuditArtifactReadCustody) {}, true},
		{"EOF_error_not_normalized", func(r *originalFinalSourceAuditArtifactReadCustody) {
			r.OriginalReaderProjections[3].Fact.OriginalErrorPresent = coldFinalTestPointer(false)
		}, false},
		{"terminal_EOF_must_have_count_zero", func(r *originalFinalSourceAuditArtifactReadCustody) {
			r.OriginalReaderProjections[3].Fact.OriginalCount = coldFinalTestPointer(int64(3))
		}, false},
		{"missing_postFstat_refused", func(r *originalFinalSourceAuditArtifactReadCustody) {
			r.OriginalReaderProjections[4].Fact.Operation = "source_file_sync"
		}, false},
		{"reader_65537_is_not_valid_whole_artifact", func(r *originalFinalSourceAuditArtifactReadCustody) {
			r.OriginalReaderProjections[2].Fact.OriginalCount = coldFinalTestPointer(int64(65537))
		}, false},
		{"whole_file_count_mismatch_refused", func(r *originalFinalSourceAuditArtifactReadCustody) { r.OriginalBodyWire = []byte("abcd") }, false},
		{"actual_read_error_not_successful_custody", func(r *originalFinalSourceAuditArtifactReadCustody) {
			r.OriginalReaderProjections[2].Fact.OriginalErrorPresent = coldFinalTestPointer(true)
		}, false},
		{"different_held_anchor_refused", func(r *originalFinalSourceAuditArtifactReadCustody) {
			r.OriginalReaderSelection.OriginalAnchorHandleID = coldFinalTestPointer(coldFinalTestID(5))
		}, false},
		{"selection_callid_not_reconstructed", func(r *originalFinalSourceAuditArtifactReadCustody) {
			r.OriginalReaderSelection.OriginalCallReferences[2] = coldFinalTestID(5) + ":3"
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := makeRead()
			tc.change(&r)
			err := coldOriginalFinalArtifactReader(coldFinalTestID(1), originalCurrentNativeRootAnchor{OriginalHandleID: coldFinalTestID(4)}, coldFinalTestID(2), r)
			if (err == nil) != tc.accept {
				t.Fatal("artifact reader disposition", err)
			}
		})
	}
}

func TestHostOriginalFinalColdOwningReturn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*controlCurrentSourceReturn)
		accept bool
	}{
		{"actual_source_helper_return", func(r *controlCurrentSourceReturn) {}, true},
		{"real_helper_error_is_safe_metadata", func(r *controlCurrentSourceReturn) { r.OriginalErrorPresent = true }, true},
		{"unknown_return_not_Wait_alias", func(r *controlCurrentSourceReturn) { r.OriginalReturnedAt = time.Time{} }, false},
		{"internal_marker_operation_alias", func(r *controlCurrentSourceReturn) { r.Operation = "publish_snapshot" }, false},
		{"late_owning_return", func(r *controlCurrentSourceReturn) { r.OriginalReturnedAt = coldFinalTestTime(59) }, false},
		{"foreign_actor_owner", func(r *controlCurrentSourceReturn) { r.OriginalOwnerID = coldFinalTestID(8) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := controlCurrentSourceReturn{"serve_original_registrar", coldFinalTestID(7), "host_registrar", coldFinalTestTime(1), coldFinalTestTime(2), coldFinalTestTime(59), "returned", false}
			tc.change(&r)
			err := coldOriginalFinalSourceReturn(r, "serve_original_registrar", coldFinalTestID(7), "host_registrar")
			if (err == nil) != tc.accept {
				t.Fatal("owning return disposition", err)
			}
		})
	}
}

func TestHostOriginalFinalColdDefaultCompiledUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	calls := 0
	io := func(string) ([]byte, []byte, error) { calls++; return nil, nil, errors.New("no original SQL supplier") }
	prior := func(string, uint32) ([]byte, []byte, uint32, error) {
		calls++
		return nil, nil, 0, errors.New("unknown FIRST")
	}
	basis := func(string, string, string, string, string) ([]byte, []byte, []byte, error) {
		calls++
		return nil, nil, nil, errors.New("no original basis")
	}
	raw, err := VerifyOriginalHistoricalFinalSourceAuditCustody(ctx, []byte(`{}`), []byte(`{}`), []byte(`{}`), []byte(`{}`), []byte(`{}`), io, prior, basis)
	if err == nil || raw != nil || calls != 0 {
		t.Fatal("unapproved input reached original suppliers or installed Source", err, calls)
	}
}

func TestHostOriginalFinalColdProjectionIdentity(t *testing.T) {
	row := coldFinalTestStream([]string{"source_directory_open", "source_directory_fstat", "source_directory_close"}, 0).OriginalSourceAuditProjections[0]
	original, _ := json.Marshal(row)
	copied := mergeOriginalSourceAuditCopy(row)
	if !coldOriginalFinalProjectionEqual(row, copied) {
		t.Fatal("exact projection rejected")
	}
	*copied.OriginalCloseReference = coldFinalTestID(4) + ":3"
	if coldOriginalFinalProjectionEqual(row, copied) {
		t.Fatal("different Close accepted")
	}
	retained, _ := json.Marshal(row)
	if !bytes.Equal(original, retained) {
		t.Fatal("clone rewrote original pointer")
	}
	if _, err := capacity.ApprovedHostFactorySource(); err == nil {
		t.Fatal("Source-only vectors installed a native supplier")
	}
}

func TestHostOriginalFinalColdWholeFraming(t *testing.T) {
	workerWire := func(count int) []byte {
		raw := []byte{}
		for n := 0; n < count; n++ {
			payload := []byte(fmt.Sprintf(`{"n":%d}`, n))
			prefix := make([]byte, 4)
			binary.BigEndian.PutUint32(prefix, uint32(len(payload)))
			raw = append(raw, prefix...)
			raw = append(raw, payload...)
		}
		return raw
	}
	for _, tc := range []struct {
		name   string
		worker bool
		wire   func() []byte
		accept bool
	}{
		{"worker_four_stages_and_separate_final", true, func() []byte { return workerWire(5) }, true},
		{"worker_missing_stage_prefix_HOLD", true, func() []byte { return workerWire(4) }, false},
		{"worker_extra_bytes_not_filtered", true, func() []byte { return append(workerWire(5), 'x') }, false},
		{"worker_zero_length_not_EOF", true, func() []byte { raw := workerWire(5); clear(raw[:4]); return raw }, false},
		{"worker_declared_payload_exceeds_wire", true, func() []byte { raw := workerWire(5); binary.BigEndian.PutUint32(raw, uint32(len(raw))); return raw }, false},
		{"registrar_two_bootstrap_and_final", false, func() []byte { return []byte("a\nb\nc\n") }, true},
		{"registrar_missing_actual_LF", false, func() []byte { return []byte("a\nb\nc") }, false},
		{"registrar_empty_line_not_frame", false, func() []byte { return []byte("a\n\nc\n") }, false},
		{"registrar_extra_frame_not_filtered", false, func() []byte { return []byte("a\nb\nc\nd\n") }, false},
		{"ALL_stdout_whole_cap", true, func() []byte { return bytes.Repeat([]byte{'x'}, 65537) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := tc.wire()
			original := bytes.Clone(wire)
			frames, offsets, err := coldOriginalFinalWireFrames(wire, tc.worker)
			if (err == nil) != tc.accept {
				t.Fatal("framing disposition", err)
			}
			if !bytes.Equal(original, wire) {
				t.Fatal("original wire rewritten")
			}
			if tc.accept {
				for n, frame := range frames {
					offset := offsets[n]
					if !bytes.Equal(frame, wire[int(offset):int(offset)+len(frame)]) {
						t.Fatal("payload range lost actual bytes")
					}
				}
				if tc.worker && offsets[0] != 4 {
					t.Fatal("length prefix aliased payload")
				}
				if !tc.worker && len(frames[2]) != 1 {
					t.Fatal("LF aliased payload")
				}
			}
		})
	}
}

func TestHostOriginalFinalColdHeldNativeKinds(t *testing.T) {
	makeFacts := func() (model.HostFactoryRootPreparation, model.HostFactoryBasalOwnerObservation, originalCurrentNativeRootAnchor, []model.HostFactoryPrimitiveIOReturn) {
		owner, handle, rootID := coldFinalTestID(2), coldFinalTestID(4), coldFinalTestID(1)
		primitive := digest([]byte("NO_SOURCE_BASAL_FIXTURE"))
		stat := model.HostFactoryNativeStatReturn{Device: 1, Inode: 2, Mode: 0040700, LinkCount: 2, UID: 1000, GID: 1000}
		root := model.HostFactoryRootPreparation{FactoryRootID: rootID, CoreBasalOwnerRawSHA256: primitive, OriginalContextStartedAt: coldFinalTestTime(0), OriginalContextDeadline: coldFinalTestTime(59), RootDirectorySource: model.HostFactoryBootstrapDescriptorSource{OriginalHandleID: coldFinalTestID(5), Device: stat.Device, Inode: stat.Inode, Mode: stat.Mode, LinkCount: stat.LinkCount, UID: stat.UID, GID: stat.GID}}
		core := model.HostFactoryBasalOwnerObservation{FactoryRootID: rootID, OriginalOwnerID: owner, Role: "host_exterior"}
		ref := originalCurrentNativeRootAnchor{OriginalHandleID: handle}
		facts := []model.HostFactoryPrimitiveIOReturn{}
		for n, op := range []string{"root_directory_open", "descriptor_fstat", "fcntl_getfl", "fcntl_getfd"} {
			at := coldFinalTestTime(10 + n)
			native := &model.HostFactoryNativeCallReturn{OriginalErrorPresent: coldFinalTestPointer(false), OriginalErrno: coldFinalTestPointer(uint32(0))}
			fact := model.HostFactoryPrimitiveIOReturn{Operation: op, OriginalHandleID: handle, OwnerPrimitiveRawSHA256: &primitive, SubjectOwnerID: owner, OriginalState: "returned", OriginalReturnClass: "success", OriginalCallID: coldFinalTestPointer(handle + ":" + fmt.Sprint(n+1)), OriginalCalledAt: &at, OriginalReturnedAt: coldFinalTestPointer(at.Add(time.Nanosecond)), OriginalOperationDeadline: coldFinalTestTime(59), OriginalNativeReturn: native}
			facts = append(facts, fact)
		}
		facts[0].OriginalNativeReturn.Kind = "unix_openat"
		facts[0].OriginalNativeReturn.OriginalScalar = coldFinalTestPointer(int64(7))
		facts[0].OriginalNativeReturn.RequestedFlags = coldFinalTestPointer(uint32(0))
		facts[0].OriginalNativeReturn.ReturnedDescriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: handle, OriginalDescriptorNumber: 7}}
		facts[1].OriginalNativeReturn.Kind = "unix_fstat"
		facts[1].OriginalNativeReturn.InputDescriptorNumber = coldFinalTestPointer(7)
		facts[1].OriginalNativeReturn.OriginalStat = &stat
		for n := 2; n < 4; n++ {
			native := facts[n].OriginalNativeReturn
			native.Kind = []string{"fcntl_getfl", "fcntl_getfd"}[n-2]
			native.InputDescriptorNumber = coldFinalTestPointer(7)
			native.RequestedFcntlCommand = coldFinalTestPointer([]int{3, 1}[n-2])
			native.RequestedArgument = coldFinalTestPointer(int64(0))
			native.OriginalScalar = coldFinalTestPointer(int64(0))
		}
		return root, core, ref, facts
	}
	for _, tc := range []struct {
		name   string
		change func([]model.HostFactoryPrimitiveIOReturn)
		accept bool
	}{
		{"exact_original_operation_kinds_structural_only", func(f []model.HostFactoryPrimitiveIOReturn) {}, true},
		{"generic_unix_fcntl_is_not_actual_getfl", func(f []model.HostFactoryPrimitiveIOReturn) { f[2].OriginalNativeReturn.Kind = "unix_fcntl" }, false},
		{"getfd_cannot_alias_getfl", func(f []model.HostFactoryPrimitiveIOReturn) { f[2].OriginalNativeReturn.Kind = "fcntl_getfd" }, false},
		{"same_stat_foreign_descriptor", func(f []model.HostFactoryPrimitiveIOReturn) {
			f[1].OriginalNativeReturn.InputDescriptorNumber = coldFinalTestPointer(8)
		}, false},
		{"nonzero_fcntl_argument", func(f []model.HostFactoryPrimitiveIOReturn) {
			f[3].OriginalNativeReturn.RequestedArgument = coldFinalTestPointer(int64(1))
		}, false},
		{"actual_native_error_not_normalized", func(f []model.HostFactoryPrimitiveIOReturn) {
			f[3].OriginalNativeReturn.OriginalErrorPresent = coldFinalTestPointer(true)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, core, ref, facts := makeFacts()
			tc.change(facts)
			err := coldOriginalFinalHeldFacts(root, core, ref, facts)
			if (err == nil) != tc.accept {
				t.Fatal("held comparison disposition", err)
			}
		})
	}
}

// The private cryptographic comparison uses a test-only key that is NEVER
// installed in compiledInstallations. This is not an original native supplier.
func TestHostOriginalFinalColdCarrierSignature(t *testing.T) {
	makeCarrier := func(t *testing.T) (fixedInstallation, model.HostFactoryRootPreparation, model.HostFactoryBasalOwnerObservation, originalFinalSourceAuditCarrier, ed25519.PrivateKey) {
		t.Helper()
		sha := digest([]byte("SOURCE_METADATA_TEST_ONLY"))
		now := coldFinalTestTime(0)
		approval := model.HostFactorySourceApproval{Schema: "original_host_factory_source_approval_v4", Purpose: "original_host_factory_source_approval_v4", FactoryRegistrySHA256: sha, FactorySourceClosureSHA256: sha, ApprovedPeerSourceCODE: strings.Repeat("a", 40), ActualBuildSourceCommit: strings.Repeat("b", 40), BuildReceiptSHA256: sha, SourceInputsSHA256: sha, MetadataEquivalenceRawSHA256: sha, CredentialRoleInventorySHA256: sha, AllowedNamespace: "fixture", AllowedPolicyID: coldFinalTestID(10), AllowedWorkflowID: coldFinalTestID(11), AllowedOriginalStepID: "create", AllowedMutationBindingName: "native-qemu", AllowedSlot: 1, ScopeRootID: coldFinalTestID(12), ApprovedAt: now.Add(-time.Second), OriginalApprovalDeadline: now.Add(600 * time.Second), AllowedFactoryEntryClasses: []string{"sealed_a0", "sealed_a1"}, AllowedAssessStepID: "assess", AllowedClaimStepID: "claim"}
		if _, err := capacity.CanonicalHostFactory(approval); err != nil {
			t.Fatal("Source-only approval shape", err)
		}
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
		i := fixedInstallation{approval: approval, keys: []approvedKey{{id: coldFinalTestID(13), role: "host_worker", public: key.Public().(ed25519.PublicKey)}}}
		root := model.HostFactoryRootPreparation{FactoryRootID: coldFinalTestID(1), SourceApprovalSHA256: originalNativeApprovalSHA(i)}
		basal := model.HostFactoryBasalOwnerObservation{Role: "host_worker", OriginalOwnerID: coldFinalTestID(2), FactoryRootID: root.FactoryRootID, SourceApprovalSHA256: root.SourceApprovalSHA256, ActualBinarySourceCommit: approval.ActualBuildSourceCommit}
		stream := coldFinalTestStream([]string{"source_directory_open", "source_directory_fstat", "source_directory_close"}, 0)
		stream.OriginalSourceOwnerRole = "host_worker"
		stream.OriginalSourceBindingSchema = "original_host_factory_pre_authority_scope_v4"
		stream.OriginalSourceBindingSHA256 = sha
		helper := controlCurrentSourceReturn{"receive_original_sealed_worker", basal.OriginalOwnerID, "host_worker", now, now.Add(30 * time.Second), now.Add(59 * time.Second), "returned", false}
		carrier := originalFinalSourceAuditCarrier{Schema: "source_private_original_final_source_audit_carrier_v1", FactoryRootID: root.FactoryRootID, SourceApprovalSHA256: root.SourceApprovalSHA256, RootPreparationSHA256: sha, OriginalOwnerID: basal.OriginalOwnerID, OriginalOwnerRole: "host_worker", OriginalBasalSHA256: sha, BindingSchema: "original_host_factory_pre_authority_scope_v4", BindingSHA256: sha, SnapshotID: coldFinalTestID(14), OriginalStreamCount: 1, OriginalArtifactReferences: []originalFinalSourceAuditArtifactReference{}, OriginalRemainingStreams: []originalFinalSourceAuditStream{stream}, OriginalHelperReturn: helper}
		return i, root, basal, carrier, key
	}
	for _, tc := range []struct {
		name   string
		change func(*originalFinalSourceAuditCarrier, *originalFinalSourceAuditEnvelope)
		resign bool
		accept bool
	}{
		{"exact_private_domain_metadata_only", func(c *originalFinalSourceAuditCarrier, e *originalFinalSourceAuditEnvelope) {}, false, true},
		{"signed_real_helper_error_metadata_only", func(c *originalFinalSourceAuditCarrier, e *originalFinalSourceAuditEnvelope) {
			c.OriginalHelperReturn.OriginalErrorPresent = true
		}, true, true},
		{"body_changed_without_original_signature", func(c *originalFinalSourceAuditCarrier, e *originalFinalSourceAuditEnvelope) {
			c.SnapshotID = coldFinalTestID(99)
		}, false, false},
		{"foreign_envelope_role", func(c *originalFinalSourceAuditCarrier, e *originalFinalSourceAuditEnvelope) {
			e.Role = "host_registrar"
		}, false, false},
		{"foreign_envelope_key", func(c *originalFinalSourceAuditCarrier, e *originalFinalSourceAuditEnvelope) {
			e.KeyID = coldFinalTestID(99)
		}, false, false},
		{"signature_wrong_private_domain", func(c *originalFinalSourceAuditCarrier, e *originalFinalSourceAuditEnvelope) {
			e.ReportDomain = "wrong_domain"
		}, false, false},
		{"unsigned_signature_bytes", func(c *originalFinalSourceAuditCarrier, e *originalFinalSourceAuditEnvelope) {
			e.SignatureBase64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}, false, false},
		{"signed_unknown_helper_return", func(c *originalFinalSourceAuditCarrier, e *originalFinalSourceAuditEnvelope) {
			c.OriginalHelperReturn.OriginalState = "called_pending"
		}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, root, basal, carrier, key := makeCarrier(t)
			body, _ := json.Marshal(carrier)
			envelope := originalFinalSourceAuditEnvelope{Schema: "source_private_original_final_source_audit_envelope_v1", KeyID: keyIDFor(i, "host_worker"), Role: "host_worker", ReportDomain: originalFinalSourceAuditDomain, BodyBase64: base64.StdEncoding.EncodeToString(body), SignatureBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(key, originalFinalSourceAuditMessage(carrier, body)))}
			tc.change(&carrier, &envelope)
			body, _ = json.Marshal(carrier)
			if tc.resign {
				envelope.BodyBase64 = base64.StdEncoding.EncodeToString(body)
				envelope.SignatureBase64 = base64.StdEncoding.EncodeToString(ed25519.Sign(key, originalFinalSourceAuditMessage(carrier, body)))
			}
			wire, _ := json.Marshal(envelope)
			_, err := coldOriginalFinalCarrier(i, capacity.ProposedHostFactorySourceProfileV1(), body, wire, root, carrier.RootPreparationSHA256, "host_worker", basal, carrier.OriginalBasalSHA256, carrier.BindingSchema, carrier.BindingSHA256)
			if (err == nil) != tc.accept {
				t.Fatal("private Source-only signature disposition", err)
			}
		})
	}
}

// A parent Source cleanup owner has its own original fixed deadline. Complete
// diagnostic metadata after approval/native expiry does not grant current or
// Native/Main acceptance. Actor owning-return upper bounds remain independent.
func TestHostOriginalFinalColdSourceCleanupDeadline(t *testing.T) {
	for _, name := range []string{"parent_cleanup_after_approval_before_own_deadline", "parent_return_at_own_deadline_refused", "parent_return_after_own_deadline_refused", "own_deadline_cannot_be_replaced_by_approval", "actor_return_upper_still_refuses", "actor_return_upper_preserved", "Root_origin_lower_bound_preserved"} {
		t.Run(name, func(t *testing.T) {
			c := coldFinalTestInputs()
			s := coldFinalTestStream([]string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_close"}, 65537)
			deadline := c.installation.approval.OriginalApprovalDeadline.Add(150 * time.Second)
			for n := range s.OriginalSourceAuditProjections {
				f := &s.OriginalSourceAuditProjections[n].Fact
				called := coldFinalTestTime(60 + n)
				f.OriginalCalledAt = &called
				f.OriginalReturnedAt = coldFinalTestPointer(called.Add(time.Nanosecond))
				f.OriginalOperationDeadline = deadline
			}
			// Real errors are Source metadata, never a positive native result.
			s.OriginalSourceAuditProjections[2].Fact.OriginalErrorPresent = coldFinalTestPointer(true)
			var upper *time.Time
			accept := name == "parent_cleanup_after_approval_before_own_deadline" || name == "actor_return_upper_preserved"
			switch name {
			case "parent_return_at_own_deadline_refused":
				s.OriginalSourceAuditProjections[3].Fact.OriginalReturnedAt = &deadline
			case "parent_return_after_own_deadline_refused":
				s.OriginalSourceAuditProjections[3].Fact.OriginalReturnedAt = coldFinalTestPointer(deadline.Add(time.Nanosecond))
			case "own_deadline_cannot_be_replaced_by_approval":
				// This actual narrower owner is already late even though a
				// different later approval date could otherwise admit it.
				c.installation.approval.OriginalApprovalDeadline = deadline.Add(time.Second)
				for n := range s.OriginalSourceAuditProjections {
					s.OriginalSourceAuditProjections[n].Fact.OriginalOperationDeadline = coldFinalTestTime(62)
				}
			case "actor_return_upper_still_refuses":
				upper = coldFinalTestPointer(coldFinalTestTime(63))
			case "actor_return_upper_preserved":
				upper = coldFinalTestPointer(coldFinalTestTime(64))
			case "Root_origin_lower_bound_preserved":
				s.OriginalSourceAuditProjections[0].Fact.OriginalCalledAt = coldFinalTestPointer(c.preparation.OriginalContextStartedAt.Add(-time.Nanosecond))
			}
			before, _ := json.Marshal(s)
			rows, err := c.sourceStream(s, digest([]byte("scope")), map[string]bool{}, upper)
			if (err == nil) != accept {
				t.Fatal("original own Source deadline/actor upper disposition", err)
			}
			after, _ := json.Marshal(s)
			if !bytes.Equal(before, after) {
				t.Fatal("original deadline or clocks rewritten")
			}
			if accept {
				raw, err := coldOriginalFinalArray(rows, uint32(len(rows)))
				if err != nil || len(raw) == 0 || !*rows[2].Fact.OriginalErrorPresent || rows[2].Fact.OriginalSHA256 != nil || rows[2].Fact.RetainedPrefixSHA256 != nil {
					t.Fatal("complete private cleanup diagnostic altered", err)
				}
			}
		})
	}
}

// Source assembly input: native_final_source_audit_cache_source_test_fragment.go
// Synthetic Source collector custody only: no IO, installation, Native/FIRST
// or admission result. Owning CI alone executes these cases.
func finalSourceWorkerTransportFixture() (*originalChild, []byte) {
	child := &originalChild{parentFramesBySelector: map[string]*originalParentWorkerFrameResult{}}
	wire := []byte{}
	for _, selector := range []string{"basal-owner-worker", "bootstrap-return-worker", "prepared-create-plan", "choice-return", "final-source-audit-worker"} {
		payload := []byte(`{"schema":"` + selector + `","selector":"` + selector + `","envelope_raw":"eA=="}`)
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, uint32(len(payload)))
		read := &originalParentWorkerFrameRead{prefix: prefix, raw: payload, classified: true, rows: []*retainedCall{{}}}
		frame := &originalParentWorkerFrameResult{read: read, selector: selector}
		if selector == "final-source-audit-worker" {
			frame.finalAudit = &originalFinalSourceAuditActorRead{read: read}
		}
		child.parentFramesBySelector[selector] = frame
		child.parentWorkerFrames = append(child.parentWorkerFrames, frame)
		wire = append(wire, prefix...)
		wire = append(wire, payload...)
	}
	eof := &retainedCall{cause: io.EOF, fact: model.HostFactoryPrimitiveIOReturn{OriginalCount: ptr(int64(0)), OriginalEOF: ptr(true)}}
	child.parentWorkerFrames = append(child.parentWorkerFrames, &originalParentWorkerFrameResult{cause: io.EOF, read: &originalParentWorkerFrameRead{cause: io.EOF, classified: true, rows: []*retainedCall{eof}}})
	return child, wire
}

func TestOriginalFinalWorkerTransportPayloadAndWholeEOF(t *testing.T) {
	child, whole := finalSourceWorkerTransportFixture()
	final, rows, offset, count, err := originalFinalWorkerFrameSelection(child)
	if err != nil || final == nil || len(rows) != 6 || len(whole) > bodyLimit {
		t.Fatalf("synthetic Source selection refused: %v", err)
	}
	actual := child.parentWorkerFrames[4].read
	if !bytes.Equal(whole[int(offset):int(offset+count)], actual.raw) || binary.BigEndian.Uint32(whole[int(offset)-4:int(offset)]) != count || offset == 0 || int(offset+count) != len(whole) {
		t.Fatal("payload selector included framing or lost whole stdout boundary")
	}
	if rows[5] != child.parentWorkerFrames[5].read.rows[0] || rows[5].cause != io.EOF || *rows[5].fact.OriginalCount != 0 || !*rows[5].fact.OriginalEOF {
		t.Fatal("literal original EOF was dropped or normalized")
	}
}

func TestOriginalFinalWorkerTransportRefusesUnclosedRoster(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*originalChild)
	}{
		{"missing-whole-eof", func(c *originalChild) { c.parentWorkerFrames = c.parentWorkerFrames[:5] }},
		{"extra-frame", func(c *originalChild) { c.parentWorkerFrames = append(c.parentWorkerFrames, c.parentWorkerFrames[4]) }},
		{"reordered-frames", func(c *originalChild) {
			c.parentWorkerFrames[0], c.parentWorkerFrames[1] = c.parentWorkerFrames[1], c.parentWorkerFrames[0]
		}},
		{"unknown-frame-bytes", func(c *originalChild) { c.parentWorkerFrames[2].read.classified = false }},
		{"foreign-map-pointer", func(c *originalChild) {
			copy := *c.parentWorkerFrames[4]
			c.parentFramesBySelector["final-source-audit-worker"] = &copy
		}},
		{"wrong-prefix-length", func(c *originalChild) { c.parentWorkerFrames[1].read.prefix = []byte{1} }},
		{"prefix-count-mismatch", func(c *originalChild) { c.parentWorkerFrames[1].read.prefix[3]++ }},
		{"private-extra-payload", func(c *originalChild) { c.parentWorkerFrames[3].read.raw = bytes.Repeat([]byte{'x'}, bodyLimit) }},
		{"frame-refusal-retained", func(c *originalChild) { c.parentWorkerFrames[2].cause = errors.New("actual refusal") }},
		{"foreign-auth-reader", func(c *originalChild) { c.parentWorkerFrames[4].finalAudit.read = c.parentWorkerFrames[3].read }},
		{"actual-eof-error-not-normalized", func(c *originalChild) { c.parentWorkerFrames[5].cause = nil }},
		{"eof-count-positive", func(c *originalChild) { c.parentWorkerFrames[5].read.rows[0].fact.OriginalCount = ptr(int64(1)) }},
		{"eof-unknown", func(c *originalChild) { c.parentWorkerFrames[5].read.rows[0].fact.OriginalEOF = nil }},
		{"trailing-after-eof", func(c *originalChild) { c.parentWorkerFrames[5].read.raw = []byte("private") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := finalSourceWorkerTransportFixture()
			tc.mutate(c)
			if _, _, _, _, err := originalFinalWorkerFrameSelection(c); err == nil {
				t.Fatal("incomplete or foreign Source transport accepted")
			}
		})
	}
}

// Source assembly input: native_initial_composer_source_test_fragment.go
// Source-only pure projections/refusals. These structs are synthetic byte
// inputs, never original kernel/Source approval/SQL-FIRST or native positives.
func TestHostInitialComposerIdentityProjectionSource(t *testing.T) {
	root := model.HostFactoryRootPreparation{FactoryRootID: "00000000-0000-4000-8000-000000000001", CoreBasalOwnerRawSHA256: strings.Repeat("a", 64)}
	root.RootDirectorySource.Device, root.RootDirectorySource.Inode = 0, 12
	core := model.HostFactoryNativeProcess{HostBootID: "00000000-0000-4000-8000-000000000002", PID: 42, StartTicks: 7}
	tests := []struct {
		name                       string
		mutate                     func(*model.HostFactoryRootPreparation, *model.HostFactoryNativeProcess)
		sameDirectory, sameProcess bool
		refuse                     bool
	}{
		{"same_original_projection", func(*model.HostFactoryRootPreparation, *model.HostFactoryNativeProcess) {}, true, true, false},
		{"directory_inode_changed", func(r *model.HostFactoryRootPreparation, _ *model.HostFactoryNativeProcess) {
			r.RootDirectorySource.Inode++
		}, false, true, false},
		{"directory_device_changed", func(r *model.HostFactoryRootPreparation, _ *model.HostFactoryNativeProcess) {
			r.RootDirectorySource.Device++
		}, false, true, false},
		{"process_ticks_changed", func(_ *model.HostFactoryRootPreparation, p *model.HostFactoryNativeProcess) { p.StartTicks++ }, true, false, false},
		{"process_pid_changed", func(_ *model.HostFactoryRootPreparation, p *model.HostFactoryNativeProcess) { p.PID++ }, true, false, false},
		{"boot_changed_both", func(_ *model.HostFactoryRootPreparation, p *model.HostFactoryNativeProcess) {
			p.HostBootID = "00000000-0000-4000-8000-000000000003"
		}, false, false, false},
		{"root_changed_both", func(r *model.HostFactoryRootPreparation, _ *model.HostFactoryNativeProcess) {
			r.FactoryRootID = "00000000-0000-4000-8000-000000000003"
		}, false, false, false},
		{"basal_changed_process", func(r *model.HostFactoryRootPreparation, _ *model.HostFactoryNativeProcess) {
			r.CoreBasalOwnerRawSHA256 = strings.Repeat("b", 64)
		}, true, false, false},
		{"missing_original_directory", func(r *model.HostFactoryRootPreparation, _ *model.HostFactoryNativeProcess) {
			r.RootDirectorySource.Inode = 0
		}, false, false, true},
		{"missing_original_process", func(_ *model.HostFactoryRootPreparation, p *model.HostFactoryNativeProcess) { p.StartTicks = 0 }, false, false, true},
	}
	baseDir, baseProc, err := initialOriginalIdentityProjection(root, core)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, p := root, core
			tt.mutate(&r, &p)
			d, w, e := initialOriginalIdentityProjection(r, p)
			if tt.refuse {
				if e == nil {
					t.Fatal("missing original identity accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if (d == baseDir) != tt.sameDirectory || (w == baseProc) != tt.sameProcess {
				t.Fatal("projection dependency changed")
			}
		})
	}
}

func TestHostInitialComposerPrerequisiteRefusalSource(t *testing.T) {
	t.Run("absent_source_publisher", func(t *testing.T) {
		if _, _, _, e := composeOriginalInitialEmpty(context.Background(), nil, nil, nil, nil, nil); e == nil {
			t.Fatal("absent source accepted")
		}
	})
	t.Run("syntactic_publisher_no_actual_owner", func(t *testing.T) {
		if _, _, _, e := composeOriginalInitialEmpty(context.Background(), &originalNativePublisher{}, nil, nil, nil, nil); e == nil {
			t.Fatal("empty source accepted")
		}
	})
	t.Run("no_realm_assessment", func(t *testing.T) {
		if _, _, e := controlDeriveInitialAssessment(nil, nil, model.HostFactoryRootPreparation{}, model.HostFactoryInitialEmptyRealmRead{}, nil, nil); e == nil {
			t.Fatal("no original realm accepted")
		}
	})
	t.Run("no_source_policy_assessment", func(t *testing.T) {
		if _, _, e := controlDeriveInitialAssessment(&OriginalFactoryRealm{}, nil, model.HostFactoryRootPreparation{}, model.HostFactoryInitialEmptyRealmRead{}, nil, nil); e == nil {
			t.Fatal("absent policy accepted")
		}
	})
	t.Run("metadata_null_reservations", func(t *testing.T) {
		r := model.HostFactoryRootPreparation{}
		raw, _ := json.Marshal(controlInitialLedgerBody{})
		if initialOriginalLedgerInput(r, raw) == nil {
			t.Fatal("null reservations accepted")
		}
	})
	t.Run("metadata_unknown_field", func(t *testing.T) {
		if initialOriginalLedgerInput(model.HostFactoryRootPreparation{}, []byte(`{"unknown_native_complete":true}`)) == nil {
			t.Fatal("unknown field accepted")
		}
	})
	t.Run("metadata_oversize", func(t *testing.T) {
		if initialOriginalLedgerInput(model.HostFactoryRootPreparation{}, []byte(strings.Repeat("x", bodyLimit+1))) == nil {
			t.Fatal("oversize input accepted")
		}
	})
	t.Run("fresh_record_unowned_cache", func(t *testing.T) {
		p := &originalNativePublisher{}
		if initialOriginalFreshRecord(p, model.HostFactoryNativeObservationReference{}, nil) == nil {
			t.Fatal("missing source custody accepted")
		}
	})
}

func TestHostInitialComposerThreadChronologySource(t *testing.T) {
	// Synthetic Source-kernel chronology only: no syscall, signer, native pass or
	// original custody is supplied by these private values.
	origin := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithDeadline(context.Background(), origin.Add(30*time.Second))
	defer cancel()
	tests := []struct {
		name   string
		mutate func([]*originalNativePublication)
	}{
		{"same_original_order", func([]*originalNativePublication) {}},
		{"sibling_overlap", func(x []*originalNativePublication) { x[1].calledAt = x[0].returnedAt.Add(-time.Nanosecond) }},
		{"missing_ordinal", func(x []*originalNativePublication) { x[1].identity.OriginalCensusOrdinal = nil }},
		{"ordinal_gap", func(x []*originalNativePublication) { x[1].identity.OriginalCensusOrdinal = ptr(uint32(3)) }},
		{"late_original_return", func(x []*originalNativePublication) {
			x[1].returnedAt = origin.Add(30 * time.Second)
			x[1].thread.OriginalThreadStatAfterRead.OriginalCloseReturnedAt = x[1].returnedAt
		}},
		{"earlier_than_source_origin", func(x []*originalNativePublication) { x[0].calledAt = origin.Add(-time.Nanosecond) }},
		{"return_not_actual_close", func(x []*originalNativePublication) { x[1].returnedAt = x[1].returnedAt.Add(time.Nanosecond) }},
		{"foreign_original_context", func(x []*originalNativePublication) { x[1].ctx = context.Background() }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			phase := &originalNativePhaseReservation{ctx: ctx, calledAt: origin}
			rows := make([]*originalNativePublication, 2)
			for i := range rows {
				called := origin.Add(time.Duration(i*3+1) * time.Second)
				returned := called.Add(time.Second)
				rows[i] = &originalNativePublication{ctx: ctx, completed: true, calledAt: called, returnedAt: returned, identity: model.HostFactoryNativeObservationRecord{OriginalCensusOrdinal: ptr(uint32(i + 1)), OriginalOperationDeadline: origin.Add(30 * time.Second)}, thread: &model.HostFactoryNativeThreadChildRead{OriginalThreadStatBeforeRead: model.HostFactoryOriginalIOFact{OriginalCalledAt: called}, OriginalThreadStatAfterRead: model.HostFactoryOriginalIOFact{OriginalCloseReturnedAt: returned}}}
			}
			tt.mutate(rows)
			err := initialOriginalThreadOrder(rows, phase)
			if (err == nil) != (tt.name == "same_original_order") {
				t.Fatal("chronology disposition differs")
			}
		})
	}
}

func TestHostInitialComposerPrimitiveIdentitySource(t *testing.T) {
	// Synthetic identity grammar, not a native/SQL/source custody supplier.
	h := "00000000-0000-4000-8000-000000000001"
	cases := []struct {
		name, handle, id string
		ordinal          uint64
		valid            bool
	}{
		{"same_actual_handle_ordinal", h, h + ":1", 1, true},
		{"last_native_ordinal", h, h + ":65536", 65536, true},
		{"observation_uuid_is_not_call", h, h, 1, false},
		{"foreign_handle", h, "00000000-0000-4000-8000-000000000002:1", 1, false},
		{"counter_mismatch", h, h + ":2", 1, false},
		{"leading_zero_alias", h, h + ":01", 1, false},
		{"zero_counter", h, h + ":0", 0, false},
		{"above_native_counter_cap", h, h + ":65537", 65537, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if initialOriginalPrimitiveCallIdentity(c.handle, c.id, c.ordinal) != c.valid {
				t.Fatal("actual identity grammar disposition differs")
			}
		})
	}
}

// Source assembly input: native_metadata_tree_source_test_fragment.go
// Synthetic metadata syntax only. No key, syscall, actor, approval, VM, native
// record or real private file custody is installed by this remote Source corpus.
func metadataTreeSourceRequest(t *testing.T) controlRegistrarRequest {
	t.Helper()
	request := controlRegistrarRequest{Schema: "original_private_registrar_request_v1", RequestID: "00000000-0000-4000-8000-000000000001", Phase: "initial", FactoryRootID: "00000000-0000-4000-8000-000000000002", CoreOwnerID: "00000000-0000-4000-8000-000000000003", RegistrarOwnerID: "00000000-0000-4000-8000-000000000004", SourceApprovalSHA256: strings.Repeat("a", 64), RootPreparationSHA256: strings.Repeat("b", 64), OriginalContextStartedAt: "2026-10-13T00:00:00Z", OriginalContextDeadline: "2026-10-13T00:10:00Z", OriginalEffectivePhaseDeadline: "2026-10-13T00:00:30Z", OriginalPhaseCalledAt: ptr("2026-10-13T00:00:00Z"), InputFiles: []controlRegistrarInputFile{}}
	_, _, inputs, e := controlRegistrarPhaseFiles(request.Phase, false)
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range inputs {
		request.InputFiles = append(request.InputFiles, controlRegistrarInputFile{Basename: f.basename, OriginalBytes: 1, OriginalSHA256: strings.Repeat("c", 64), StageSelector: f.selector})
	}
	return request
}
func metadataTreeSourceDescriptors(request controlRegistrarRequest, count int) originalNativeExportManifest {
	x := originalNativeMetadataEmpty(request)
	for i := 1; i <= count; i++ {
		body, envelope := fmt.Sprintf("%064x", i), fmt.Sprintf("%064x", i+100000)
		x.NativeArtifacts = append(x.NativeArtifacts, originalNativeExportRecord{RecordKind: "record", NativeIdentity: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), BodyBasename: request.RequestID + "-" + body + ".body", BodyBytes: 1, BodySHA256: body, EnvelopeBasename: request.RequestID + "-" + envelope + ".env", EnvelopeBytes: 1, EnvelopeSHA256: envelope})
	}
	return x
}
func metadataTreeSourceAllCategories(request controlRegistrarRequest) originalNativeExportManifest {
	x := metadataTreeSourceDescriptors(request, 1)
	body, envelope := strings.Repeat("d", 64), strings.Repeat("e", 64)
	stage := originalNativeExportStage{StageSelector: "source-only-syntax", BodyBasename: request.RequestID + "-" + body + ".body", BodyBytes: 1, BodySHA256: body, EnvelopeBasename: request.RequestID + "-" + envelope + ".env", EnvelopeBytes: 1, EnvelopeSHA256: envelope}
	x.StageArtifacts = append(x.StageArtifacts, stage)
	stage.StageSelector = "source-only-io-syntax"
	x.IOArtifacts = append(x.IOArtifacts, stage)
	id := "00000000-0000-4000-8000-000000000099"
	x.NativeCollections = append(x.NativeCollections, model.HostFactoryNativeObservationCollectionReference{CollectionID: id, ObservationKind: "thread_children", BindingSchema: "original_host_factory_root_preparation_v4", BindingSHA256: request.RootPreparationSHA256, ObserverOwnerID: request.RegistrarOwnerID, ObserverPrimitiveRawSHA256: strings.Repeat("f", 64), OriginalObservationCount: 1, ManifestRootBodySHA256: body, ManifestRootEnvelopeSHA256: envelope})
	callID := id + ":1"
	// Descriptor syntax only: this is not a signed writer artifact or an actual
	// acquired reader/writer. The current metadata codec requires its explicit
	// paired reference; Source-owned transfer verification remains independent.
	writer, method := "00000000-0000-4000-8000-000000000097", "00000000-0000-4000-8000-000000000096"
	x.GetdentsArtifacts = append(x.GetdentsArtifacts, originalNativeExportGetdents{OriginalCallID: callID, Basename: request.RequestID + "-" + digest([]byte(callID)) + ".raw", OriginalBytes: 0, OriginalSHA256: digest([]byte{}), OriginalChunkBodySHA256: body, OriginalChunkEnvelopeSHA256: envelope, OriginalOwnerID: request.RegistrarOwnerID, BindingSchema: "original_host_factory_root_preparation_v4", BindingSHA256: request.RootPreparationSHA256,
		WriterAudit: &originalNativeExportGetdentsWriterAudit{Basename: request.RequestID + "-" + digest([]byte(callID)) + ".writer-audit", OriginalBytes: 1, OriginalSHA256: strings.Repeat("1", 64), RequestID: request.RequestID, OriginalCallID: callID, OriginalChunkBodySHA256: body, OriginalChunkEnvelopeSHA256: envelope, OriginalOwnerID: request.RegistrarOwnerID, BindingSchema: "original_host_factory_root_preparation_v4", BindingSHA256: request.RootPreparationSHA256, OriginalWriterHandleID: writer, OriginalWriterCloseCallID: writer + ":4", OriginalPublicationMethodHandleID: method, OriginalWriterCallReferences: []string{writer + ":1", writer + ":2", writer + ":3", writer + ":4"}, OriginalPublicationCallReferences: []string{method + ":1", method + ":2"}}})
	x.InventoryRelationArtifacts = append(x.InventoryRelationArtifacts, originalNativeExportRelations{ObservationID: id, Basename: request.RequestID + "-" + id + ".rel", OriginalBytes: 1, OriginalSHA256: body})
	x.PhaseContextArtifacts = append(x.PhaseContextArtifacts, originalNativeExportPhase{AggregateBodySHA256: body, Basename: request.RequestID + "-" + body + ".phase", OriginalBytes: 1, OriginalSHA256: envelope})
	return x
}
func metadataTreeSourceBuild(t *testing.T, request controlRegistrarRequest, descriptors originalNativeExportManifest) ([]byte, map[string][]byte) {
	t.Helper()
	top, files, e := buildOriginalNativeExportMetadataTree(request, descriptors)
	if e != nil {
		t.Fatal(e)
	}
	nodes := map[string][]byte{}
	for _, file := range files {
		if file.getdents || nodes[file.basename] != nil || len(file.raw) < 1 || len(file.raw) > bodyLimit {
			t.Fatal("metadata file shape")
		}
		nodes[file.basename] = bytes.Clone(file.raw)
	}
	return top, nodes
}
func metadataTreeSourceResolver(nodes map[string][]byte, reads map[string]int) func(string, int, string) ([]byte, error) {
	return func(name string, size int, sha string) ([]byte, error) {
		reads[name]++
		raw, ok := nodes[name]
		if !ok || len(raw) != size || digest(raw) != sha {
			return nil, refused("storage_unknown", nil)
		}
		return bytes.Clone(raw), nil
	}
}
func metadataTreeSourceRewriteRoot(t *testing.T, topRaw []byte, nodes map[string][]byte, mutate func(*originalNativeExportMetadataNode)) []byte {
	t.Helper()
	var top originalNativeExportTreeManifest
	if json.Unmarshal(topRaw, &top) != nil {
		t.Fatal("synthetic top")
	}
	ref := &top.NativeArtifacts
	raw := nodes[*ref.NodeBasename]
	var node originalNativeExportMetadataNode
	if json.Unmarshal(raw, &node) != nil {
		t.Fatal("synthetic node")
	}
	mutate(&node)
	changed, e := json.Marshal(node)
	if e != nil {
		t.Fatal(e)
	}
	name := top.RequestID + "-" + digest(changed) + ".meta"
	nodes[name] = changed
	ref.NodeBasename, ref.NodeBytes, ref.NodeSHA256 = ptr(name), ptr(len(changed)), ptr(digest(changed))
	result, e := json.Marshal(top)
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func TestHostFactorySourcePrivateMetadataTreeRoundtrip(t *testing.T) {
	request := metadataTreeSourceRequest(t)
	for _, category := range originalNativeMetadataCategories() {
		t.Run(category, func(t *testing.T) {
			all := metadataTreeSourceAllCategories(request)
			node := originalNativeMetadataNode(request, category)
			originalNativeMetadataLeaf(&node, all, 0, 1)
			only := originalNativeMetadataEmpty(request)
			originalNativeMetadataAppend(&only, node)
			top, nodes := metadataTreeSourceBuild(t, request, only)
			reads := map[string]int{}
			decoded, e := resolveOriginalNativeExportMetadataTree(request, top, metadataTreeSourceResolver(nodes, reads))
			if e != nil || !reflect.DeepEqual(only, decoded) || len(reads) != len(nodes) {
				t.Fatal("whole descriptor/category roundtrip", e)
			}
			for _, n := range reads {
				if n != 1 {
					t.Fatal("repeated metadata callback")
				}
			}
		})
	}
	t.Run("all-seven-categories", func(t *testing.T) {
		x := metadataTreeSourceAllCategories(request)
		top, nodes := metadataTreeSourceBuild(t, request, x)
		out, e := resolveOriginalNativeExportMetadataTree(request, top, metadataTreeSourceResolver(nodes, map[string]int{}))
		if e != nil || !reflect.DeepEqual(x, out) {
			t.Fatal("mixed descriptor metadata", e)
		}
	})
	t.Run("explicit-empty-roots", func(t *testing.T) {
		x := originalNativeMetadataEmpty(request)
		top, nodes := metadataTreeSourceBuild(t, request, x)
		if len(nodes) != 0 {
			t.Fatal("empty category caused node")
		}
		out, e := resolveOriginalNativeExportMetadataTree(request, top, func(string, int, string) ([]byte, error) { t.Fatal("empty root read"); return nil, nil })
		if e != nil || !reflect.DeepEqual(x, out) {
			t.Fatal("empty metadata not native absence", e)
		}
	})
	t.Run("128-whole-record-descriptors-flat-over-cap", func(t *testing.T) {
		x := metadataTreeSourceDescriptors(request, 128)
		flat, _ := json.Marshal(x)
		if len(flat) <= bodyLimit {
			t.Fatal("fixture lacks flat cap pressure")
		}
		top, nodes := metadataTreeSourceBuild(t, request, x)
		out, e := resolveOriginalNativeExportMetadataTree(request, top, metadataTreeSourceResolver(nodes, map[string]int{}))
		if e != nil || !reflect.DeepEqual(x, out) {
			t.Fatal("metadata pages lost whole descriptors", e)
		}
	})
	for _, size := range []int{17, 257, 4097} {
		t.Run(fmt.Sprintf("structural-level-for-%d", size), func(t *testing.T) {
			x := metadataTreeSourceDescriptors(request, size)
			top, nodes := metadataTreeSourceBuild(t, request, x)
			var header originalNativeExportTreeManifest
			if json.Unmarshal(top, &header) != nil {
				t.Fatal("synthetic top")
			}
			expected := uint32(1)
			if size == 257 {
				expected = 2
			}
			if size == 4097 {
				expected = 3
			}
			if header.NativeArtifacts.Level == nil || *header.NativeArtifacts.Level != expected {
				t.Fatal("four layer boundary")
			}
			out, e := resolveOriginalNativeExportMetadataTree(request, top, metadataTreeSourceResolver(nodes, map[string]int{}))
			if e != nil || !reflect.DeepEqual(out, x) {
				t.Fatal("structural tree range", e)
			}
		})
	}
}

func TestHostFactorySourcePrivateMetadataTreeClosedShape(t *testing.T) {
	request := metadataTreeSourceRequest(t)
	for _, name := range []string{"case-alias", "missing-root", "null-root", "empty-root-with-file", "unknown-category", "trailing-document", "noncanonical-top", "oversize-top"} {
		t.Run(name, func(t *testing.T) {
			top, nodes := metadataTreeSourceBuild(t, request, metadataTreeSourceDescriptors(request, 1))
			switch name {
			case "case-alias":
				top = bytes.Replace(top, []byte(`"stage_artifacts":`), []byte(`"Stage_Artifacts":`), 1)
			case "missing-root":
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(top, &fields)
				delete(fields, "stage_artifacts")
				top, _ = json.Marshal(fields)
			case "null-root":
				var header originalNativeExportTreeManifest
				_ = json.Unmarshal(top, &header)
				rootRaw, _ := json.Marshal(header.StageArtifacts)
				top = bytes.Replace(top, append([]byte(`"stage_artifacts":`), rootRaw...), []byte(`"stage_artifacts":null`), 1)
			case "empty-root-with-file":
				var header originalNativeExportTreeManifest
				_ = json.Unmarshal(top, &header)
				header.StageArtifacts.NodeBasename = ptr("not-null")
				top, _ = json.Marshal(header)
			case "unknown-category":
				var header originalNativeExportTreeManifest
				_ = json.Unmarshal(top, &header)
				header.StageArtifacts.Category = "unknown"
				top, _ = json.Marshal(header)
			case "trailing-document":
				top = append(top, []byte("{}")...)
			case "noncanonical-top":
				top = append([]byte(" "), top...)
			case "oversize-top":
				top = bytes.Repeat([]byte(" "), bodyLimit+1)
			}
			if _, e := resolveOriginalNativeExportMetadataTree(request, top, metadataTreeSourceResolver(nodes, map[string]int{})); e == nil {
				t.Fatal("closed top accepted contradiction")
			}
		})
	}
	for _, name := range []string{"empty-child", "leaf-wrong-category-array", "branch-with-descriptor", "leaf-null-list", "unknown-level-four", "foreign-request", "foreign-root", "foreign-root-preparation"} {
		t.Run(name, func(t *testing.T) {
			count := 1
			if name == "empty-child" || name == "branch-with-descriptor" {
				count = 17
			}
			top, nodes := metadataTreeSourceBuild(t, request, metadataTreeSourceDescriptors(request, count))
			top = metadataTreeSourceRewriteRoot(t, top, nodes, func(node *originalNativeExportMetadataNode) {
				switch name {
				case "empty-child":
					node.Children[0] = originalNativeExportMetadataReference{Category: node.Category}
				case "leaf-wrong-category-array":
					node.IOArtifacts = []originalNativeExportStage{}
				case "branch-with-descriptor":
					node.NativeArtifacts = []originalNativeExportRecord{}
				case "leaf-null-list":
					node.NativeArtifacts = nil
				case "unknown-level-four":
					node.Level = 4
				case "foreign-request":
					node.RequestID = "00000000-0000-4000-8000-000000000098"
				case "foreign-root":
					node.FactoryRootID = "00000000-0000-4000-8000-000000000098"
				case "foreign-root-preparation":
					node.RootPreparationSHA256 = strings.Repeat("9", 64)
				}
			})
			if _, e := resolveOriginalNativeExportMetadataTree(request, top, metadataTreeSourceResolver(nodes, map[string]int{})); e == nil {
				t.Fatal("closed node accepted contradiction")
			}
		})
	}
}

func TestHostFactorySourcePrivateMetadataTreeOriginalGraph(t *testing.T) {
	request := metadataTreeSourceRequest(t)
	for _, name := range []string{"missing-callback", "missing-original-node", "nil-original-buffer", "wrong-original-count", "wrong-original-sha", "range-gap", "range-overlap", "wrong-child-level", "duplicate-native-identity", "duplicate-stage-across-io", "descriptor-count-over-maximum", "orphan-owner-roster"} {
		t.Run(name, func(t *testing.T) {
			count := 1
			if name == "range-gap" || name == "range-overlap" || name == "wrong-child-level" {
				count = 17
			}
			x := metadataTreeSourceDescriptors(request, count)
			if name == "duplicate-native-identity" {
				x.NativeArtifacts = append(x.NativeArtifacts, x.NativeArtifacts[0])
				if _, _, e := buildOriginalNativeExportMetadataTree(request, x); e == nil {
					t.Fatal("duplicate semantic identity")
				}
				return
			}
			if name == "duplicate-stage-across-io" {
				x = metadataTreeSourceAllCategories(request)
				x.IOArtifacts = x.StageArtifacts
				if _, _, e := buildOriginalNativeExportMetadataTree(request, x); e == nil {
					t.Fatal("duplicate semantic stage")
				}
				return
			}
			top, nodes := metadataTreeSourceBuild(t, request, x)
			var header originalNativeExportTreeManifest
			_ = json.Unmarshal(top, &header)
			switch name {
			case "missing-original-node":
				delete(nodes, *header.NativeArtifacts.NodeBasename)
			case "range-gap", "range-overlap", "wrong-child-level":
				top = metadataTreeSourceRewriteRoot(t, top, nodes, func(node *originalNativeExportMetadataNode) {
					if name == "range-gap" {
						node.Children[1].FirstOrdinal = ptr(*node.Children[1].FirstOrdinal + 1)
					}
					if name == "range-overlap" {
						node.Children[1].FirstOrdinal = ptr(*node.Children[1].FirstOrdinal - 1)
					}
					if name == "wrong-child-level" {
						node.Children[0].Level = ptr(uint32(3))
					}
				})
			case "descriptor-count-over-maximum":
				header.NativeArtifacts.OriginalDescriptorCount = 65537
				top, _ = json.Marshal(header)
			case "orphan-owner-roster":
				// Decoder cannot see an unprovided file. The Source-owned custody
				// owner compares its actual supplied roster with recorded reads.
				nodes[request.RequestID+"-orphan.meta"] = []byte("not referenced")
				reads := map[string]int{}
				if _, e := resolveOriginalNativeExportMetadataTree(request, top, metadataTreeSourceResolver(nodes, reads)); e != nil {
					t.Fatal(e)
				}
				if len(reads) == len(nodes) {
					t.Fatal("owner roster check failed to expose orphan")
				}
				return
			}
			resolve := metadataTreeSourceResolver(nodes, map[string]int{})
			switch name {
			case "missing-callback":
				resolve = nil
			case "nil-original-buffer":
				resolve = func(string, int, string) ([]byte, error) { return nil, nil }
			case "wrong-original-count":
				resolve = func(name string, _ int, _ string) ([]byte, error) { return append(bytes.Clone(nodes[name]), ' '), nil }
			case "wrong-original-sha":
				resolve = func(name string, size int, _ string) ([]byte, error) { return bytes.Repeat([]byte("x"), size), nil }
			}
			if _, e := resolveOriginalNativeExportMetadataTree(request, top, resolve); e == nil {
				t.Fatal("unknown/foreign/gapped original metadata graph")
			}
		})
	}
}

func TestHostFactorySourcePrivateMetadataTreeDescriptorCustody(t *testing.T) {
	request := metadataTreeSourceRequest(t)
	for _, name := range []string{"foreign-request-basename", "path-basename", "zero-body-count", "oversize-body-count", "unknown-native-kind", "empty-getdents-wrong-sha", "unknown-getdents-binding", "noncanonical-call-id"} {
		t.Run(name, func(t *testing.T) {
			x := metadataTreeSourceAllCategories(request)
			switch name {
			case "foreign-request-basename":
				x.NativeArtifacts[0].BodyBasename = "00000000-0000-4000-8000-000000000098-" + x.NativeArtifacts[0].BodySHA256 + ".body"
			case "path-basename":
				x.NativeArtifacts[0].BodyBasename = "../" + x.NativeArtifacts[0].BodyBasename
			case "zero-body-count":
				x.NativeArtifacts[0].BodyBytes = 0
			case "oversize-body-count":
				x.NativeArtifacts[0].BodyBytes = bodyLimit + 1
			case "unknown-native-kind":
				x.NativeArtifacts[0].RecordKind = "complete_from_flag"
			case "empty-getdents-wrong-sha":
				x.GetdentsArtifacts[0].OriginalSHA256 = strings.Repeat("f", 64)
			case "unknown-getdents-binding":
				x.GetdentsArtifacts[0].BindingSchema = "unknown"
			case "noncanonical-call-id":
				x.GetdentsArtifacts[0].OriginalCallID = strings.Split(x.GetdentsArtifacts[0].OriginalCallID, ":")[0] + ":01"
			}
			if _, _, e := buildOriginalNativeExportMetadataTree(request, x); e == nil {
				t.Fatal("metadata cannot repair original artifact custody")
			}
		})
	}
}

// Source assembly input: native_ordinary_bootstrap_bound_source_test_fragment.go
func TestOriginalOrdinaryBootstrapBoundPrivateDomain(t *testing.T) {
	seed := bytes.Repeat([]byte{3}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	raw := []byte(`{"schema":"source_private_original_ordinary_bootstrap_bound_v2"}`)
	sig := ed25519.Sign(key, originalOrdinaryBootstrapMessage(raw))
	for _, tc := range []struct {
		name    string
		message []byte
		valid   bool
	}{
		{"exact_private_domain", originalOrdinaryBootstrapMessage(raw), true},
		{"bare_BODY", raw, false},
		{"Host_domain", append([]byte("HostFactorySignedEnvelope\x00"), raw...), false},
		{"changed_BODY", originalOrdinaryBootstrapMessage(append(bytes.Clone(raw), ' ')), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ed25519.Verify(key.Public().(ed25519.PublicKey), tc.message, sig) != tc.valid {
				t.Fatal("private Source framing domain crossed")
			}
		})
	}
}
func TestOriginalOrdinaryBootstrapBoundClosedPrivateCodec(t *testing.T) {
	at := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	root := at.Add(600 * time.Second)
	worker := at.Add(420 * time.Second)
	if !worker.Before(root) {
		t.Fatal("fixture origin invalid")
	}
	value := originalOrdinaryBootstrapBound{Schema: "source_private_original_ordinary_bootstrap_bound_v2", OriginalBootstrapBody: []byte{0, 255}, OriginalRootPreparationEnvelope: []byte{}, OriginalParentBasalEnvelope: []byte{}, OriginalPhaseCalledAt: at.Format(time.RFC3339Nano), OriginalWorkerContextDeadline: worker.Format(time.RFC3339Nano)}
	raw, _ := json.Marshal(value)
	for _, tc := range []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"original_binary_private", raw, true},
		{"unknown_key", append(bytes.Clone(raw[:len(raw)-1]), []byte(`,"caller_ready":true}`)...), false},
		{"numeric_byte_array", bytes.Replace(raw, []byte(`"AP8="`), []byte(`[0,255]`), 1), false},
		{"case_alias", bytes.Replace(raw, []byte(`"schema"`), []byte(`"Schema"`), 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var decoded originalOrdinaryBootstrapBound
			err := decodePrivateOriginalJSON(tc.raw, &decoded)
			if (err == nil) != tc.ok {
				t.Fatal("private bound codec widened")
			}
			if err == nil && (!bytes.Equal(decoded.OriginalBootstrapBody, []byte{0, 255}) || decoded.OriginalWorkerContextDeadline != worker.Format(time.RFC3339Nano)) {
				t.Fatal("original bound/raw rewritten")
			}
		})
	}
	env := originalOrdinaryBootstrapBoundEnvelope{Schema: "source_private_original_ordinary_bootstrap_bound_envelope_v2", Domain: originalOrdinaryBootstrapBoundDomain, BodyBase64: base64.StdEncoding.EncodeToString(raw)}
	encoded, _ := json.Marshal(env)
	var decoded originalOrdinaryBootstrapBoundEnvelope
	if decodePrivateOriginalJSON(encoded, &decoded) != nil || decoded.BodyBase64 != env.BodyBase64 {
		t.Fatal("private envelope changed")
	}
}

func TestOriginalOrdinaryBootstrapBoundKeepsOriginalStartClock(t *testing.T) {
	at := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	called, returned := at.Add(time.Second), at.Add(2*time.Second)
	root, worker := at.Add(600*time.Second), at.Add(420*time.Second)
	sha := digest([]byte("original Core basal"))
	pid := 42
	f := model.HostFactoryPrimitiveIOReturn{Operation: "worker_start", OriginalState: "returned", OriginalReturnClass: "success", SubjectOwnerID: "original-worker", OwnerPrimitiveRawSHA256: &sha, OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: worker, OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "original_cmd_start", ReturnedPID: &pid}}
	for _, tc := range []struct {
		name     string
		deadline time.Time
		phase    time.Time
		pid      int
		sha      string
		ok       bool
	}{
		{"original420_under_declared600", worker, at, pid, sha, true},
		{"Root600_cannot_replace420", root, at, pid, sha, false},
		{"child_fresh420_not_original", worker.Add(time.Second), at, pid, sha, false},
		{"foreign_process", worker, at, pid + 1, sha, false},
		{"foreign_Core", worker, at, pid, digest([]byte("other basal")), false},
		{"phase_after_Start", worker, returned, pid, sha, false},
		{"deadline_at_return", returned, at, pid, sha, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if originalOrdinaryBoundStart(f, tc.phase, tc.deadline, root, "original-worker", tc.sha, tc.pid) != tc.ok {
				t.Fatal("Source bound replaced original Start lineage")
			}
		})
	}
}

func TestOriginalOrdinaryBootstrapBodyCanonicalBeforeAcceptance(t *testing.T) {
	value := originalOrdinaryBootstrapBound{Schema: "source_private_original_ordinary_bootstrap_bound_v2", OriginalBootstrapBody: []byte{}, OriginalRootPreparationEnvelope: []byte{}, OriginalParentBasalEnvelope: []byte{}}
	raw, _ := json.Marshal(value)
	for _, tc := range []struct {
		name string
		wire []byte
		ok   bool
	}{
		{"canonical_BODY8", raw, true},
		{"whitespace_outside_private_bytes", bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema": `), 1), false},
		{"outer_whitespace", append([]byte(" "), raw...), false},
		{"old_BODY7_family", bytes.Replace(raw, []byte("ordinary_bootstrap_bound_v2"), []byte("ordinary_bootstrap_bound_v1"), 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out originalOrdinaryBootstrapBound
			if (originalOrdinaryBootstrapBody(tc.wire, &out) == nil) != tc.ok {
				t.Fatal("noncanonical or prior BODY family accepted")
			}
		})
	}
}
func TestOriginalOrdinaryDirectoriesKeepDistinctOriginalIdentities(t *testing.T) {
	parent := model.HostFactoryNativeStatReturn{Device: 1, Inode: 10, Mode: unix.S_IFDIR | 0700, UID: 1000, GID: 1000, LinkCount: 2, Size: 40}
	child := model.HostFactoryBootstrapDescriptorSource{Device: 1, Inode: 11, Mode: unix.S_IFDIR | 0700, UID: 1000, GID: 1000, LinkCount: 2}
	actualChild := model.HostFactoryNativeStatReturn{Device: 1, Inode: 11, Mode: unix.S_IFDIR | 0700, UID: 1000, GID: 1000, LinkCount: 2}
	for _, name := range []string{"distinct_genuine_parent_and_child", "actual_parent_size_and_links_changed", "foreign_parent", "foreign_child", "forced_parent_child_alias"} {
		t.Run(name, func(t *testing.T) {
			actualParent, observed := parent, actualChild
			expected := child
			switch name {
			case "actual_parent_size_and_links_changed":
				actualParent.LinkCount++
				actualParent.Size++
			case "foreign_parent":
				actualParent.Inode++
			case "foreign_child":
				observed.Inode++
			case "forced_parent_child_alias":
				expected.Inode = parent.Inode
				observed.Inode = parent.Inode
			}
			before, _ := json.Marshal(actualParent)
			ok := originalOrdinaryDirectoryPair(parent, actualParent, expected, observed)
			if ok != (name == "distinct_genuine_parent_and_child" || name == "actual_parent_size_and_links_changed") {
				t.Fatal("directory original provenance mixed")
			}
			after, _ := json.Marshal(actualParent)
			if !bytes.Equal(before, after) {
				t.Fatal("actual directory stat rewritten")
			}
		})
	}
}

// Source assembly input: native_ordinary_credential_source_test_fragment.go
func ordinaryCredentialSourceInputFixture(t *testing.T) (originalOrdinaryCredentialInput, []byte) {
	t.Helper()
	v := originalOrdinaryCredentialInput{"source_private_original_ordinary_credential_input_v1", "mutation-source-principal", "guard-private-fixture-token", "mutation-private-fixture-token"}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal("structural fixture marshal failed")
	}
	return v, raw
}

// Structural private decoding does not install compiled Source or authority.
func TestOriginalOrdinaryCredentialPrivateInputBoundary(t *testing.T) {
	input, raw := ordinaryCredentialSourceInputFixture(t)
	binding, inventory := strings.Repeat("a", 64), strings.Repeat("b", 64)
	t.Run("complete_private_input_exact_tokens_and_public_inventory", func(t *testing.T) {
		frame, err := parseOriginalOrdinaryCredentialInput(raw, binding, input.MutationPrincipalID, inventory)
		if err != nil || frame.OrdinaryGuardBearer != input.OrdinaryGuardBearer || frame.MutationBearer != input.MutationBearer || frame.OrdinarySourceBindingSHA256 != binding || frame.OriginalCredentialInventorySHA256 != inventory || frame.MutationPrincipalID != input.MutationPrincipalID {
			t.Fatal("private projection changed actual values or public lineage")
		}
		if _, err := capacity.ApprovedHostFactorySource(); err == nil {
			t.Fatal("private parser installed a Source supplier")
		}
	})
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"unknown_private_key", bytes.Replace(raw, []byte(`"schema":`), []byte(`"guard-private-fixture-token":"private","schema":`), 1)},
		{"duplicate_principal", bytes.Replace(raw, []byte(`"mutation_principal_id":`), []byte(`"mutation_principal_id":"different","mutation_principal_id":`), 1)},
		{"case_alias", bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1)},
		{"missing_token", bytes.Replace(raw, []byte(`,"mutation_bearer":"mutation-private-fixture-token"`), nil, 1)},
		{"null_token", bytes.Replace(raw, []byte(`"mutation-private-fixture-token"`), []byte(`null`), 1)},
		{"empty_token", bytes.Replace(raw, []byte(`"mutation-private-fixture-token"`), []byte(`""`), 1)},
		{"wrong_compiled_principal", bytes.Replace(raw, []byte(`"mutation-source-principal"`), []byte(`"different-principal"`), 1)},
		{"aliased_two_credentials", bytes.Replace(raw, []byte(`"mutation-private-fixture-token"`), []byte(`"guard-private-fixture-token"`), 1)},
		{"trailing_document", append(bytes.Clone(raw), []byte(`{}`)...)},
		{"noncanonical_whitespace", append(bytes.Clone(raw), '\n')},
		{"oversized_private_input", bytes.Repeat([]byte("x"), bodyLimit+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			frame, err := parseOriginalOrdinaryCredentialInput(tc.raw, binding, input.MutationPrincipalID, inventory)
			if err == nil || !reflect.DeepEqual(frame, model.FactoryOrdinaryCredentialFrame{}) {
				t.Fatal("malformed private input exposed a credential frame")
			}
			if strings.Contains(err.Error(), input.OrdinaryGuardBearer) || strings.Contains(err.Error(), input.MutationBearer) || strings.Contains(err.Error(), "different-principal") {
				t.Fatal("private input leaked through decoder error text")
			}
		})
	}
}

func TestOriginalOrdinaryCredentialOriginalAttemptUnavailable(t *testing.T) {
	t.Run("missing_realm_unavailable", func(t *testing.T) {
		frame, err := controlReadOriginalOrdinaryCredential(context.Background(), nil)
		if err == nil || !reflect.DeepEqual(frame, model.FactoryOrdinaryCredentialFrame{}) {
			t.Fatal("missing realm supplied credentials")
		}
	})
	t.Run("missing_compiled_source_consumes_attempt_without_io", func(t *testing.T) {
		state := &ordinaryOriginalState{}
		r := &OriginalFactoryRealm{ordinary: state}
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
		defer cancel()
		frame, first := controlReadOriginalOrdinaryCredential(ctx, r)
		if first == nil || !reflect.DeepEqual(frame, model.FactoryOrdinaryCredentialFrame{}) || !state.credentialAttempted || state.credentialCause == nil || state.credentialReader != nil || state.credentialAudit != nil || state.credentialRaw != nil {
			t.Fatal("missing Source created file observations or an unconsumed attempt")
		}
		// Later cached bytes/frame and another context cannot renew an attempt.
		state.credentialRaw = []byte("actual private diagnostic retained")
		state.credentialFrame = model.FactoryOrdinaryCredentialFrame{MutationBearer: "private-never-returned"}
		frame, again := controlReadOriginalOrdinaryCredential(context.Background(), r)
		if !errors.Is(again, first) || !reflect.DeepEqual(frame, model.FactoryOrdinaryCredentialFrame{}) || string(state.credentialRaw) != "actual private diagnostic retained" {
			t.Fatal("failed original attempt retried, erased or exposed cached secrets")
		}
	})
	t.Run("pending_attempt_not_success", func(t *testing.T) {
		pending := refused("storage_unknown", nil)
		state := &ordinaryOriginalState{credentialAttempted: true, credentialCause: pending}
		r := &OriginalFactoryRealm{ordinary: state}
		frame, err := controlReadOriginalOrdinaryCredential(context.Background(), r)
		if !errors.Is(err, pending) || !reflect.DeepEqual(frame, model.FactoryOrdinaryCredentialFrame{}) || state.credentialReader != nil || state.credentialAudit != nil {
			t.Fatal("concurrent pending owner became successful or retried IO")
		}
	})
}

// Source assembly input: native_ordinary_http_source_test_fragment.go
type ordinaryHTTPBodyFixture struct {
	data          []byte
	lastError     error
	zero          bool
	separateEOF   bool
	cancel        context.CancelFunc
	closeError    error
	afterRead     func()
	reads, closes int
}

func (b *ordinaryHTTPBodyFixture) Read(p []byte) (int, error) {
	b.reads++
	if b.cancel != nil {
		b.cancel()
	}
	if b.zero {
		return 0, nil
	}
	n := copy(p, b.data)
	b.data = b.data[n:]
	if b.afterRead != nil {
		b.afterRead()
	}
	if len(b.data) == 0 {
		if b.separateEOF && n > 0 {
			return n, nil
		}
		return n, b.lastError
	}
	return n, nil
}

func TestOriginalOrdinaryAuthorityCompletePrivateBudget(t *testing.T) {
	for _, name := range []string{"exact_complete_boundary", "one_retained_byte_over", "row_only_fits_headers_do_not", "aliased_data_once_clones_distinct", "same_audit_cannot_reset", "late_trailer_excess_preserves_actual_eof_close"} {
		t.Run(name, func(t *testing.T) {
			ctx, l := ordinaryQMPTestLedger(t)
			h, _ := l.handle()
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://127.0.0.1:19449/api/v1/capacity/mutations/00000000-0000-4000-8000-000000000001", nil)
			response := &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1", Request: request, Header: http.Header{"X-Source-Private": []string{""}}}
			owner := &originalOrdinaryAuthorityReturn{handle: h, request: request, response: response}
			h.ordinaryAuthorityReturn = owner
			switch name {
			case "exact_complete_boundary", "one_retained_byte_over", "row_only_fits_headers_do_not":
				n, e := originalOrdinaryHTTPPrivateSize(l)
				if e != nil {
					t.Fatal(e)
				}
				extra := 0
				if name != "exact_complete_boundary" {
					extra = 1
				}
				response.Header.Set("X-Source-Private", strings.Repeat("p", 1048576-n+extra))
				if e := ordinaryQMPAuditBudget(l, 0); e != nil {
					t.Fatal("fixture row-only budget not independent")
				}
				e = originalOrdinaryHTTPBudget(l, 0)
				if (e == nil) != (name == "exact_complete_boundary") {
					t.Fatal("complete private byte boundary ignored")
				}
				if originalOrdinaryHTTPBudget(l, 2048) == nil {
					t.Fatal("pre-Do prospective original row not reserved")
				}
			case "aliased_data_once_clones_distinct":
				shared := []byte("private original buffer")
				owner.requestInput = shared
				owner.requestBody = shared
				owner.raw = shared
				cert := &x509.Certificate{Raw: []byte("synthetic certificate DER, not trust")}
				certAlias := &x509.Certificate{Raw: cert.Raw}
				response.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert, certAlias}, VerifiedChains: [][]*x509.Certificate{{cert, certAlias}}}
				copy := *response.TLS
				owner.tls = &copy
				n, e := originalOrdinaryHTTPPrivateSize(l)
				if e != nil {
					t.Fatal(e)
				}
				owner.requestBody = bytes.Clone(shared)
				after, e := originalOrdinaryHTTPPrivateSize(l)
				if e != nil || after-n != len(shared) {
					t.Fatal("clone bytes omitted or alias counted as allocation")
				}
				certAlias.Raw = bytes.Clone(cert.Raw)
				same, e := originalOrdinaryHTTPPrivateSize(l)
				if e != nil || same-after != len(cert.Raw) {
					t.Fatal("new TLS raw clone omitted or shared raw counted twice")
				}
			case "same_audit_cannot_reset":
				response.Header.Set("X-Source-Private", strings.Repeat("p", 600000))
				if originalOrdinaryHTTPBudget(l, 0) != nil {
					t.Fatal("fixture first request unexpectedly refused")
				}
				second, _ := l.handle()
				second.ordinaryAuthorityReturn = &originalOrdinaryAuthorityReturn{handle: second, response: &http.Response{Header: http.Header{"X-Source-Private": []string{strings.Repeat("q", 600000)}}}}
				if originalOrdinaryHTTPBudget(l, 0) == nil || len(l.handleOrder) != 2 {
					t.Fatal("second request reset original authority custody")
				}
			case "late_trailer_excess_preserves_actual_eof_close":
				body := &ordinaryHTTPBodyFixture{data: []byte("actual private partial response"), lastError: io.EOF, afterRead: func() {
					response.Trailer = http.Header{"X-Source-Private-Trailer": []string{strings.Repeat("p", 1048576)}}
				}}
				raw, e := readOriginalOrdinaryAuthorityBody(ctx, h, body)
				if e == nil || string(raw) != "actual private partial response" || !bytes.Equal(owner.raw, raw) || body.closes != 1 || !h.closed {
					t.Fatal("late excess erased actual response or skipped Close")
				}
				found := false
				for _, row := range h.unclassified {
					if row.operation == "ordinary_authority_body_read" && row.cause == io.EOF && bytes.Equal(row.raw, raw) {
						found = true
					}
				}
				if !found || len(response.Trailer.Get("X-Source-Private-Trailer")) != 1048576 {
					t.Fatal("over-cap original was trimmed/normalized")
				}
			}
		})
	}
}
func (b *ordinaryHTTPBodyFixture) Close() error { b.closes++; return b.closeError }

// In-memory Source IO, executed only by owning CI. No network, approved
// installation, SQL, SDK response authentication or Native admission fixture.
func TestOriginalOrdinaryAuthorityBodyOriginalReturns(t *testing.T) {
	for _, name := range []string{"literal_empty_eof", "data_with_eof", "full_65536_then_eof", "actual_65537_refused_retained", "partial_error", "zero_without_eof", "cancel_during_read", "close_error", "pending_census_keeps_actual_close"} {
		t.Run(name, func(t *testing.T) {
			parent, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			ctx, stop := context.WithCancel(parent)
			defer stop()
			l, _ := newLedger(ctx, "00000000-0000-4000-8000-000000000001", "factory_ordinary_worker", digest([]byte("Source-only basal")), "factory_ordinary_source_binding_v4", digest([]byte("Source-only binding")))
			h, _ := l.handle()
			sentinel := errors.New("Source-only private read cause")
			body := &ordinaryHTTPBodyFixture{data: []byte("private actual response"), lastError: io.EOF}
			switch name {
			case "literal_empty_eof":
				body.data = []byte{}
			case "full_65536_then_eof":
				body.data = bytes.Repeat([]byte{0xff}, bodyLimit)
				body.separateEOF = true
			case "actual_65537_refused_retained":
				body.data = bytes.Repeat([]byte{0xfe}, bodyLimit+1)
			case "partial_error":
				body.lastError = sentinel
			case "zero_without_eof":
				body.zero = true
			case "cancel_during_read":
				body.cancel = stop
			case "close_error":
				body.closeError = sentinel
			case "pending_census_keeps_actual_close":
				h.next = callLimit
			}
			expected := bytes.Clone(body.data)
			raw, e := readOriginalOrdinaryAuthorityBody(ctx, h, body)
			ok := name == "literal_empty_eof" || name == "data_with_eof" || name == "full_65536_then_eof"
			if (e == nil) != ok || body.closes != 1 || !h.closed {
				t.Fatal("transport success or owning Close mismatch")
			}
			if name != "zero_without_eof" && name != "pending_census_keeps_actual_close" && !bytes.Equal(raw, expected) {
				t.Fatal("actual partial/oversize bytes discarded")
			}
			if name == "pending_census_keeps_actual_close" && (body.reads != 0 || len(h.unclassified) != 1 || h.unclassified[0].callID != "" || h.unclassified[0].ordinal != 0 || h.unclassified[0].returnedAt.IsZero()) {
				t.Fatal("unencoded Close fabricated Native identity or skipped")
			}
			var retained []byte
			literalEOF := false
			for _, r := range h.unclassified {
				if !r.private || r.stage != "source_audit" || r.bindingSHA != l.bindingSHA || r.rawOmitted {
					t.Fatal("private Source return relabeled")
				}
				if r.operation == "ordinary_authority_body_read" {
					retained = append(retained, r.raw...)
					literalEOF = literalEOF || r.cause == io.EOF
					if r.scalar != int64(len(r.raw)) {
						t.Fatal("count changed")
					}
				}
			}
			if !bytes.Equal(raw, retained) || ok && !literalEOF {
				t.Fatal("literal original bytes/EOF missing")
			}
			if name == "partial_error" {
				found := false
				for _, r := range h.unclassified {
					if r.operation == "ordinary_authority_body_read" && r.cause == sentinel {
						found = true
					}
				}
				if !found || e == nil {
					t.Fatal("private actual cause lost")
				}
			}
			if name == "cancel_during_read" && (!literalEOF || ctx.Err() != context.Canceled || e == nil) {
				t.Fatal("late EOF normalized or original cancel absent")
			}
			before := len(h.unclassified)
			_ = closeOriginalOrdinaryAuthorityBody(ctx, h, body)
			if body.closes != 1 || len(h.unclassified) != before {
				t.Fatal("Close replayed")
			}
		})
	}
}

func TestOriginalOrdinaryAuthorityHTTPDefaultSourceHasNoEffects(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, name := range []string{"guard", "redeem", "settle", "unknown_operation", "unbounded_context"} {
		t.Run(name, func(t *testing.T) {
			l, _ := newLedger(ctx, "00000000-0000-4000-8000-000000000001", "factory_ordinary_worker", digest([]byte("Source fixture")), "factory_ordinary_source_binding_v4", digest([]byte("Source binding")))
			operation := "ordinary_guard_before_read"
			method := http.MethodGet
			path := "/internal/capacity/host-original-factories/ordinary/attempts/fixture/grant-guard"
			nonce := ""
			actual := ctx
			switch name {
			case "redeem":
				operation = "ordinary_redeem_response_read"
				method = http.MethodPost
				path = "/api/v1/capacity/mutations/redeem"
			case "settle":
				operation = "ordinary_settle_response_read"
				method = http.MethodPost
				path = "/api/v1/capacity/mutations/settle"
				nonce = string(bytes.Repeat([]byte{'a'}, 64))
			case "unknown_operation":
				operation = "invented_native_settle"
			case "unbounded_context":
				actual = context.Background()
			}
			if raw, status, e := originalHTTPWithSettlement(actual, &http.Client{}, l, "https://127.0.0.1:19449", path, method, "private fixture bearer", operation, nil, nonce); e == nil || raw != nil || status != 0 {
				t.Fatal("EMPTY Source performed authority HTTP")
			}
			handles, _ := l.originalHandles()
			if len(handles) != 0 {
				t.Fatal("unavailable Source reserved HTTP effect")
			}
		})
	}
}

// Source assembly input: native_ordinary_independent_receipt_source_test_fragment.go
// Synthetic key is confined to the private codec test. The full decoder still
// rejects it at compiled Source selection; no original Basal/IO is supplied.
func TestOriginalOrdinaryIndependentReceiptPrivateSignature(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	defer clear(key)
	for _, name := range []string{"exact_private_wire_only", "wrong_expected_root", "wrong_expected_root_body", "wrong_expected_binding", "wrong_fixed_key", "wrong_key_id", "wrong_role", "wrong_domain", "Host_envelope_schema", "foreign_request_after_signature", "foreign_owner_after_signature", "foreign_basal_after_signature", "noncanonical_signed_body", "noncanonical_envelope", "byte_array_alias_signed", "wire_overhead_over_cap"} {
		t.Run(name, func(t *testing.T) {
			v := ordinaryIndependentReceiptFixture()
			rootID, rootSHA, binding := v.FactoryRootID, digest([]byte("synthetic original RootPreparation")), v.OrdinarySourceBindingSHA256
			i := fixedInstallation{keys: []approvedKey{{id: "00000000-0000-4000-8000-000000000009", role: "host_registrar", public: bytes.Clone(key.Public().(ed25519.PublicKey))}}}
			if name == "wire_overhead_over_cap" {
				v.OriginalIndependentRaw = bytes.Repeat([]byte{0xff}, bodyLimit*5/8)
			}
			body, _ := json.Marshal(v)
			if name == "noncanonical_signed_body" {
				body = append([]byte(" "), body...)
			}
			if name == "byte_array_alias_signed" {
				body = bytes.Replace(body, []byte(`"original_independent_raw":"cHJpdmF0ZSBvcmlnaW5hbCBmaXh0dXJlLCBub3QgUU1Q"`), []byte(`"original_independent_raw":[1,2,3]`), 1)
			}
			env := originalOrdinaryIndependentEnvelope{"source_private_original_ordinary_independent_envelope_v1", i.keys[0].id, "host_registrar", originalOrdinaryIndependentDomain, base64.StdEncoding.EncodeToString(body), base64.StdEncoding.EncodeToString(ed25519.Sign(key, originalOrdinaryIndependentMessage(v, rootSHA, body)))}
			switch name {
			case "wrong_expected_root":
				rootID = "00000000-0000-4000-8000-000000000008"
			case "wrong_expected_root_body":
				rootSHA = digest([]byte("foreign root"))
			case "wrong_expected_binding":
				binding = digest([]byte("foreign binding"))
			case "wrong_fixed_key":
				other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x62}, ed25519.SeedSize))
				i.keys[0].public = bytes.Clone(other.Public().(ed25519.PublicKey))
				clear(other)
			case "wrong_key_id":
				env.KeyID = "00000000-0000-4000-8000-000000000008"
			case "wrong_role":
				env.Role = "factory_ordinary_worker"
			case "wrong_domain":
				env.Domain = "host-native-stage"
			case "Host_envelope_schema":
				env.Schema = "original_host_factory_root_signed_envelope_v4"
			case "foreign_request_after_signature":
				v.RequestID = "00000000-0000-4000-8000-000000000008"
				body, _ = json.Marshal(v)
				env.BodyBase64 = base64.StdEncoding.EncodeToString(body)
			case "foreign_owner_after_signature":
				v.RegistrarOwnerID = "00000000-0000-4000-8000-000000000008"
				body, _ = json.Marshal(v)
				env.BodyBase64 = base64.StdEncoding.EncodeToString(body)
			case "foreign_basal_after_signature":
				v.RegistrarBasalSHA256 = digest([]byte("foreign basal"))
				body, _ = json.Marshal(v)
				env.BodyBase64 = base64.StdEncoding.EncodeToString(body)
			}
			wire, _ := json.Marshal(env)
			if name == "wire_overhead_over_cap" {
				var control originalOrdinaryIndependentReceipt
				if len(body) == 0 || len(body) > bodyLimit || originalOrdinaryIndependentBody(body, &control) != nil || !bytes.Equal(control.OriginalIndependentRaw, v.OriginalIndependentRaw) || len(wire) <= bodyLimit {
					t.Fatal("wire cap fixture must retain a valid bounded signed BODY inside an oversized envelope")
				}
			}
			if name == "noncanonical_envelope" {
				wire = append(wire, ' ')
			}
			before := bytes.Clone(wire)
			got, actual, e := originalOrdinaryIndependentEnvelopeBody(i, rootID, rootSHA, binding, wire)
			if (e == nil) != (name == "exact_private_wire_only") {
				t.Fatal("foreign/noncanonical private signed wire accepted")
			}
			if !bytes.Equal(before, wire) {
				t.Fatal("wire normalized/repaired")
			}
			if e == nil && (!bytes.Equal(actual, body) || !bytes.Equal(got.OriginalIndependentRaw, v.OriginalIndependentRaw)) {
				t.Fatal("signed original inner bytes changed")
			}
		})
	}
}

// These are private Source-memory codec/chronology fixtures, not signed
// originals, an approved installation, a QEMU/SDK run or Native permission.
func ordinaryIndependentReceiptFixture() originalOrdinaryIndependentReceipt {
	return originalOrdinaryIndependentReceipt{Schema: "source_private_original_ordinary_independent_receipt_v1", FactoryRootID: "00000000-0000-4000-8000-000000000001", OrdinarySourceBindingSHA256: digest([]byte("Source binding")), RequestID: "00000000-0000-4000-8000-000000000002", RegistrarOwnerID: "00000000-0000-4000-8000-000000000003", RegistrarBasalSHA256: digest([]byte("Source basal")), OriginalRegistrarBasalEnvelope: []byte("original basal fixture, not signature"), OriginalRegistrarBootstrapEnvelope: []byte("original bootstrap fixture, not signature"), OriginalIndependentRaw: []byte("private original fixture, not QMP")}
}

func TestOriginalOrdinaryIndependentReceiptClosedBody(t *testing.T) {
	for _, name := range []string{"canonical_original_bytes", "outer_space", "unknown_field", "missing_raw", "null_raw", "numeric_byte_array", "escaped_base64", "wrong_schema", "unknown_root", "unknown_request", "unknown_owner", "unknown_binding", "unknown_basal", "empty_basal", "empty_bootstrap", "empty_inner", "overhead_exceeds_whole_cap"} {
		t.Run(name, func(t *testing.T) {
			v := ordinaryIndependentReceiptFixture()
			switch name {
			case "wrong_schema":
				v.Schema = "host_native"
			case "unknown_root":
				v.FactoryRootID = ""
			case "unknown_request":
				v.RequestID = ""
			case "unknown_owner":
				v.RegistrarOwnerID = ""
			case "unknown_binding":
				v.OrdinarySourceBindingSHA256 = ""
			case "unknown_basal":
				v.RegistrarBasalSHA256 = ""
			case "empty_basal":
				v.OriginalRegistrarBasalEnvelope = []byte{}
			case "empty_bootstrap":
				v.OriginalRegistrarBootstrapEnvelope = []byte{}
			case "empty_inner":
				v.OriginalIndependentRaw = []byte{}
			case "overhead_exceeds_whole_cap":
				v.OriginalIndependentRaw = bytes.Repeat([]byte{0xff}, bodyLimit)
			}
			raw, e := json.Marshal(v)
			if e != nil {
				t.Fatal(e)
			}
			switch name {
			case "outer_space":
				raw = append([]byte(" "), raw...)
			case "unknown_field":
				raw = append(raw[:len(raw)-1], []byte(",\"approval\":true}")...)
			case "missing_raw":
				var fields map[string]json.RawMessage
				_ = json.Unmarshal(raw, &fields)
				delete(fields, "original_independent_raw")
				raw, _ = json.Marshal(fields)
			case "null_raw":
				raw = bytes.Replace(raw, []byte(`"original_independent_raw":"cHJpdmF0ZSBvcmlnaW5hbCBmaXh0dXJlLCBub3QgUU1Q"`), []byte(`"original_independent_raw":null`), 1)
			case "numeric_byte_array":
				raw = bytes.Replace(raw, []byte(`"original_independent_raw":"cHJpdmF0ZSBvcmlnaW5hbCBmaXh0dXJlLCBub3QgUU1Q"`), []byte(`"original_independent_raw":[1,2,3]`), 1)
			case "escaped_base64":
				raw = bytes.Replace(raw, []byte(`"original_independent_raw":"c`), []byte(`"original_independent_raw":"\u0063`), 1)
			}
			original := bytes.Clone(raw)
			var out originalOrdinaryIndependentReceipt
			e = originalOrdinaryIndependentBody(raw, &out)
			if (e == nil) != (name == "canonical_original_bytes") {
				t.Fatal("noncanonical or incomplete private BODY admitted")
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("original wire repaired")
			}
			if e == nil && !bytes.Equal(out.OriginalIndependentRaw, v.OriginalIndependentRaw) {
				t.Fatal("legacy raw changed")
			}
		})
	}
}

func TestOriginalOrdinaryIndependentReceiptMessageIdentity(t *testing.T) {
	base := ordinaryIndependentReceiptFixture()
	raw, _ := json.Marshal(base)
	root := digest([]byte("original RootPreparation"))
	message := originalOrdinaryIndependentMessage(base, root, raw)
	for _, name := range []string{"factory_root", "root_preparation", "ordinary_binding", "request", "registrar_owner", "registrar_basal", "exact_body"} {
		t.Run(name, func(t *testing.T) {
			v := base
			r := root
			b := bytes.Clone(raw)
			switch name {
			case "factory_root":
				v.FactoryRootID = "00000000-0000-4000-8000-000000000009"
			case "root_preparation":
				r = digest([]byte("foreign RootPreparation"))
			case "ordinary_binding":
				v.OrdinarySourceBindingSHA256 = digest([]byte("foreign binding"))
			case "request":
				v.RequestID = "00000000-0000-4000-8000-000000000009"
			case "registrar_owner":
				v.RegistrarOwnerID = "00000000-0000-4000-8000-000000000009"
			case "registrar_basal":
				v.RegistrarBasalSHA256 = digest([]byte("foreign basal"))
			case "exact_body":
				b = append(b, ' ')
			}
			if bytes.Equal(message, originalOrdinaryIndependentMessage(v, r, b)) {
				t.Fatal("private signature domain omitted original identity")
			}
		})
	}
	if !bytes.HasPrefix(message, []byte(originalOrdinaryIndependentDomain+"\x00")) || bytes.Contains(message, []byte("source_host_factory_signed_envelope")) {
		t.Fatal("private receipt became Host-stage domain")
	}
}

func TestOriginalOrdinaryIndependentReceiptOwningReturn(t *testing.T) {
	start := time.Date(2026, 10, 15, 1, 0, 0, 0, time.UTC)
	bound := start.Add(60 * time.Second)
	owner := ordinaryIndependentReceiptFixture().RegistrarOwnerID
	for _, name := range []string{"actual_external_return_after_close", "kernel_marker_before_close", "returned_before_call", "helper_error", "called_pending", "unknown_called", "unknown_returned", "unknown_deadline", "foreign_owner", "foreign_role", "foreign_operation", "before_root", "after_root_bound", "equal_deadline", "independent_before_helper", "read_before_start", "close_before_read", "non_utc_time"} {
		t.Run(name, func(t *testing.T) {
			h := controlCurrentSourceReturn{"read_original_ordinary_independent_qmp", owner, "host_registrar", start.Add(time.Second), start.Add(8 * time.Second), bound, "returned", false}
			inner := originalOrdinaryIndependentReturn{StartedAt: start.Add(2 * time.Second), ReadReturnedAt: start.Add(5 * time.Second), CloseReturnedAt: start.Add(7 * time.Second)}
			switch name {
			case "kernel_marker_before_close":
				h.OriginalReturnedAt = inner.CloseReturnedAt.Add(-time.Nanosecond)
			case "returned_before_call":
				h.OriginalReturnedAt = start
			case "helper_error":
				h.OriginalErrorPresent = true
			case "called_pending":
				h.OriginalState = "called_pending"
			case "unknown_called":
				h.OriginalCalledAt = time.Time{}
			case "unknown_returned":
				h.OriginalReturnedAt = time.Time{}
			case "unknown_deadline":
				h.OriginalContextDeadline = time.Time{}
			case "foreign_owner":
				h.OriginalOwnerID = "00000000-0000-4000-8000-000000000009"
			case "foreign_role":
				h.OriginalOwnerRole = "factory_ordinary_worker"
			case "foreign_operation":
				h.Operation = "read_original_parent_worker_frame"
			case "before_root":
				h.OriginalCalledAt = start.Add(-time.Second)
			case "after_root_bound":
				h.OriginalContextDeadline = bound.Add(time.Second)
			case "equal_deadline":
				h.OriginalReturnedAt = bound
			case "independent_before_helper":
				inner.StartedAt = start
			case "read_before_start":
				inner.ReadReturnedAt = start
			case "close_before_read":
				inner.CloseReturnedAt = start
			case "non_utc_time":
				h.OriginalCalledAt = h.OriginalCalledAt.In(time.FixedZone("foreign", 3600))
			}
			before, _ := json.Marshal(inner)
			if originalOrdinaryIndependentHelper(h, owner, start, bound, inner) != (name == "actual_external_return_after_close") {
				t.Fatal("internal marker/error/foreign lifetime admitted")
			}
			after, _ := json.Marshal(inner)
			if !bytes.Equal(before, after) {
				t.Fatal("legacy timestamps rewritten")
			}
		})
	}
}

func TestOriginalOrdinaryIndependentReceiptUnavailableSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, wire := range [][]byte{[]byte(`{}`), []byte(strings.Repeat("x", bodyLimit+1))} {
		if _, _, _, e := decodeOriginalOrdinaryIndependentReceipt(ctx, fixedInstallation{}, model.HostFactoryRootPreparation{}, digest([]byte("Source fixture")), wire); e == nil {
			t.Fatal("private bytes installed EMPTY Source")
		}
	}
	l, _ := newLedger(ctx, "00000000-0000-4000-8000-000000000001", "host_registrar", digest([]byte("Source basal")), "factory_ordinary_source_binding_v4", digest([]byte("Source binding")))
	phase := &originalNativePhaseReservation{ctx: ctx, name: "terminal", requestID: "00000000-0000-4000-8000-000000000002"}
	p := &originalNativePublisher{ledger: l, phaseReservations: map[string]*originalNativePhaseReservation{phase.requestID: phase}}
	x := &originalRegistrarActorPhase{ctx: ctx, reservation: phase, ordinaryIndependentAttempted: true, ordinaryIndependentAudit: l, ordinaryIndependentRaw: []byte("private actual diagnostic"), request: controlRegistrarRequest{RequestID: phase.requestID, Phase: "terminal", Ordinary: true}}
	a := &originalRegistrarActor{publisher: p, basal: &basalOwner{ledger: l}}
	before := bytes.Clone(x.ordinaryIndependentRaw)
	for n := 0; n < 2; n++ {
		if _, e := a.sealOriginalOrdinaryIndependentReceipt(x); e == nil {
			t.Fatal("unavailable Source signed original")
		}
	}
	if !x.ordinaryReceiptAttempted || len(x.ordinaryReceiptEnvelope) != 0 || !bytes.Equal(before, x.ordinaryIndependentRaw) {
		t.Fatal("refusal reset once or destroyed private original")
	}
}

// Source assembly input: native_ordinary_io_transfer_source_test_fragment.go
// Original Source-memory reservations only. No Cmd/Read/Wait is performed,
// installed Source/Native permission is absent and no SQL FIRST is supplied.
func ordinaryIOSourcePendingFixture(t *testing.T) (context.Context, *originalLedger, *callHandle, *retainedCall) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	owner := "11111111-1111-4111-8111-111111111111"
	subject := "22222222-2222-4222-8222-222222222222"
	l, e := newLedger(ctx, owner, "host_exterior", digest([]byte("original Core basal")), "factory_ordinary_source_binding_v4", digest([]byte("original ordinary binding")))
	if e != nil {
		t.Fatal(e)
	}
	l.subjects["factory_ordinary_worker"] = subject
	h, e := l.handle()
	if e != nil {
		t.Fatal(e)
	}
	r, e := h.beginWithNative("worker_wait", "factory_ordinary_worker", "worker_exterior_join", false, &model.HostFactoryNativeCallReturn{Kind: "original_cmd_wait"})
	if e != nil {
		t.Fatal(e)
	}
	return ctx, l, h, r
}
func ordinaryIOSourceGraph(l *originalLedger) *originalNativeSourceGraph {
	g := &originalNativeSourceGraph{sourceProfile: capacity.ProposedHostFactorySourceProfileV1(), io: map[string]originalNativeSignedIO{}, selectedPurposes: map[string]originalNativeAuthenticatedCallPurpose{}}
	for sha, body := range l.collection.OriginalBodies() {
		g.io[sha] = originalNativeSignedIO{body: body, purposes: []capacity.HostFactorySourceCallPurpose{}}
	}
	return g
}
func TestOriginalOrdinarySourcePendingInventoryIsNotNativePositive(t *testing.T) {
	for _, name := range []string{"truthful_pending", "missing_chunk", "forged_pending_return", "forged_complete_label", "Closing_still_refuses_pending"} {
		t.Run(name, func(t *testing.T) {
			ctx, l, h, _ := ordinaryIOSourcePendingFixture(t)
			shas, e := publishOriginalOrdinarySourceInventories(ctx, l)
			if e != nil || len(shas) != 1 {
				t.Fatalf("Source original pending could not be preserved: %v", e)
			}
			raw, e := l.collection.Resolve(shas[0])
			if e != nil {
				t.Fatal(e)
			}
			var inv model.HostFactoryHandleCallInventory
			if capacity.DecodeHostFactory(raw, &inv) != nil || inv.CollectionState != "same_original_call_pending" {
				t.Fatal("pending metadata rewritten")
			}
			if name == "Closing_still_refuses_pending" {
				if _, e := publishOriginalLedgerInventories(ctx, l); e == nil {
					t.Fatal("positive/Closing inventory accepted pending")
				}
				return
			}
			g := ordinaryIOSourceGraph(l)
			switch name {
			case "missing_chunk":
				delete(g.io, *inv.OperationVectors[0].ManifestRootSHA256)
			case "forged_complete_label":
				inv.CollectionState = "complete_original_calls"
			case "forged_pending_return":
				for sha, x := range g.io {
					var c model.HostFactoryCallVectorChunk
					if capacity.DecodeHostFactory(x.body, &c) == nil {
						c.OriginalCalls[0].OriginalReturnedAt = c.OriginalCalls[0].OriginalCalledAt
						wire, _ := json.Marshal(c)
						x.body = wire
						g.io[sha] = x
					}
				}
			}
			e = ordinaryOriginalSourceInventoryValue(g, inv.OperationVectors[0], inv)
			if (e == nil) != (name == "truthful_pending") {
				t.Fatalf("pending union classifier %s: %v", name, e)
			}
			if _, e := g.vector(inv.OperationVectors[0]); e == nil {
				t.Fatal("Native positive vector widened")
			}
			if !h.pending {
				t.Fatal("pending owner marked returned")
			}
		})
	}
}
func TestOriginalOrdinarySourcePendingSuccessorKeepsRequest(t *testing.T) {
	for _, name := range []string{"same_actual_successor", "changed_original_request"} {
		t.Run(name, func(t *testing.T) {
			ctx, l, h, row := ordinaryIOSourcePendingFixture(t)
			if _, e := publishOriginalOrdinarySourceInventories(ctx, l); e != nil {
				t.Fatal(e)
			}
			native := model.HostFactoryNativeCallReturn{Kind: "original_cmd_wait", OriginalErrorPresent: ptr(false), OriginalErrno: ptr(uint32(0)), OriginalExitCode: ptr(0)}
			h.finishOriginal(row, time.Now().UTC(), nil, nil, "not_byte_operation", "success", nil, &native, nil)
			if _, e := publishOriginalOrdinarySourceInventories(ctx, l); e != nil {
				t.Fatal(e)
			}
			g := ordinaryIOSourceGraph(l)
			if name == "changed_original_request" {
				for sha, x := range g.io {
					var c model.HostFactoryCallVectorChunk
					if capacity.DecodeHostFactory(x.body, &c) == nil && c.OriginalCalls[0].OriginalState == "returned" {
						c.OriginalCalls[0].SubjectOwnerID = "33333333-3333-4333-8333-333333333333"
						x.body, _ = json.Marshal(c)
						g.io[sha] = x
					}
				}
			}
			if e := ordinaryOriginalPendingHistory(g); (e == nil) != (name == "same_actual_successor") {
				t.Fatalf("original predecessor changed %v", e)
			}
		})
	}
}

func TestOriginalOrdinarySourceInventoryKeepsExactNamespace(t *testing.T) {
	for _, name := range []string{"same_original", "foreign_handle", "foreign_owner", "foreign_primitive", "foreign_namespace", "foreign_deadline"} {
		t.Run(name, func(t *testing.T) {
			ctx, l, _, _ := ordinaryIOSourcePendingFixture(t)
			shas, err := publishOriginalOrdinarySourceInventories(ctx, l)
			if err != nil || len(shas) != 1 {
				t.Fatalf("original pending source: %v", err)
			}
			g := ordinaryIOSourceGraph(l)
			var inv model.HostFactoryHandleCallInventory
			if capacity.DecodeHostFactory(g.io[shas[0]].body, &inv) != nil {
				t.Fatal("original inventory")
			}
			ref := inv.OperationVectors[0]
			switch name {
			case "foreign_handle":
				inv.OriginalHandleID = "44444444-4444-4444-8444-444444444444"
			case "foreign_owner":
				inv.OriginalOwnerID = "44444444-4444-4444-8444-444444444444"
			case "foreign_primitive":
				inv.OwnerPrimitiveRawSHA256 = ptr(digest([]byte("foreign basal")))
			case "foreign_namespace":
				inv.BindingSHA256 = digest([]byte("foreign ordinary binding"))
			case "foreign_deadline":
				inv.OriginalOperationDeadline = inv.OriginalOperationDeadline.Add(time.Second)
			}
			if err := ordinaryOriginalSourceInventoryValue(g, ref, inv); (err == nil) != (name == "same_original") {
				t.Fatalf("namespace %s: %v", name, err)
			}
		})
	}
}

func TestOriginalOrdinarySourceTransferRetainsActorRoles(t *testing.T) {
	request := controlRegistrarRequest{Ordinary: true, CoreOwnerID: "11111111-1111-4111-8111-111111111111", RegistrarOwnerID: "22222222-2222-4222-8222-222222222222", SubjectOwnerID: ptr("33333333-3333-4333-8333-333333333333")}
	for _, tc := range []struct {
		name, role, owner string
		want              bool
	}{
		{"Core_ancestor", "host_exterior", request.CoreOwnerID, true},
		{"registrar_original", "host_registrar", request.RegistrarOwnerID, true},
		{"worker_ancestor", "factory_ordinary_worker", *request.SubjectOwnerID, true},
		{"registrar_not_worker", "host_registrar", *request.SubjectOwnerID, false},
		{"worker_not_Core", "factory_ordinary_worker", request.CoreOwnerID, false},
		{"no_sealed_alias", "host_worker", *request.SubjectOwnerID, false},
		{"no_foreign_owner", "host_exterior", "44444444-4444-4444-8444-444444444444", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ordinaryOriginalTransferOwner(request, tc.role, tc.owner) != tc.want {
				t.Fatal("owner role changed")
			}
		})
	}
}

// Source assembly input: native_ordinary_output_source_test_fragment.go
// Pure delimiter custody only. No stdout, HTTP, SDK, Source approval, Native
// fact, signature, creation or settlement permission is supplied by this test.
func TestOriginalOrdinaryOutputKeepsOriginalLF(t *testing.T) {
	for _, name := range []string{"original_http_one_lf", "payload_gets_one_lf", "escaped_json_newline", "empty", "blank_lf", "two_lf", "two_frames", "multiline_json", "invalid_json", "whole65536_with_lf", "payload65536_no_room", "whole65537", "output_copy_preserves_input"} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{"status":"settled"}` + "\n")
			ok := true
			switch name {
			case "payload_gets_one_lf":
				raw = raw[:len(raw)-1]
			case "escaped_json_newline":
				raw = []byte(`{"value":"actual\nJSONescape"}`)
			case "empty":
				raw, ok = nil, false
			case "blank_lf":
				raw, ok = []byte("\n"), false
			case "two_lf":
				raw, ok = append(raw, '\n'), false
			case "two_frames":
				raw, ok = append(raw, []byte("{}\n")...), false
			case "multiline_json":
				raw, ok = []byte("{\n\"status\":\"settled\"}\n"), false
			case "invalid_json":
				raw, ok = []byte("actual private invalid partial\n"), false
			case "whole65536_with_lf":
				raw = append(append([]byte{'"'}, bytes.Repeat([]byte{'x'}, bodyLimit-3)...), '"', '\n')
			case "payload65536_no_room":
				raw, ok = append(append([]byte{'"'}, bytes.Repeat([]byte{'x'}, bodyLimit-2)...), '"'), false
			case "whole65537":
				raw, ok = append(append([]byte{'"'}, bytes.Repeat([]byte{'x'}, bodyLimit-2)...), '"', '\n'), false
			}
			before := bytes.Clone(raw)
			wire, e := originalOrdinaryOutputWire(raw)
			if (e == nil) != ok || !bytes.Equal(raw, before) {
				t.Fatal("framing changed original input or accepted adjacent/oversized frame")
			}
			if !ok {
				if wire != nil {
					t.Fatal("refused private bytes produced a transport frame")
				}
				return
			}
			expected := bytes.Clone(before)
			if expected[len(expected)-1] != '\n' {
				expected = append(expected, '\n')
			}
			if !bytes.Equal(wire, expected) || len(wire) > bodyLimit || bytes.Count(wire, []byte{'\n'}) != 1 {
				t.Fatal("literal HTTP LF duplicated, trimmed or reserialized")
			}
			wire[0] ^= 1
			if !bytes.Equal(raw, before) {
				t.Fatal("output aliases immutable original HTTP body")
			}
		})
	}
}

// Actual temporary-file Openat/EOF/Close cases for remote CI only. The borrowed
// fixture directory is not an authenticated Native/Root anchor. These cases
// qualify only the lower captured-reader/missing classifier and its exact row.
func TestOriginalOrdinaryIndependentCapturedMissing(t *testing.T) {
	for _, name := range []string{"actual_missing_then_original_file", "missing_flag_false", "nil_helper_error", "foreign_audit", "unregistered_original_pointer", "cancel_after_actual_missing", "literal_symlink_error", "opened_directory_not_missing", "wrong_file_mode_not_missing"} {
		t.Run(name, func(t *testing.T) {
			parent, basis := ordinaryQMPTestLedger(t)
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			audit, e := newLedger(ctx, basis.ownerID, basis.ownerRole, basis.primitiveSHA, basis.bindingSchema, basis.bindingSHA)
			if e != nil {
				t.Fatal(e)
			}
			path := t.TempDir()
			file, e := os.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			fd, e := originalFileNumber(file)
			if e != nil {
				t.Fatal(e)
			}
			anchor := &callHandle{file: file, fd: fd}
			target := "ordinary-original-independent-return.json"
			switch name {
			case "literal_symlink_error":
				e = os.Symlink("missing-target", filepath.Join(path, target))
			case "opened_directory_not_missing":
				e = os.Mkdir(filepath.Join(path, target), 0700)
			case "wrong_file_mode_not_missing":
				e = os.WriteFile(filepath.Join(path, target), []byte("private"), 0400)
			}
			if e != nil {
				t.Fatal(e)
			}
			raw, h, missing, cause := controlRegistrarReadCustodyFileCaptured(ctx, audit, anchor, target, uint32(os.Getuid()), uint32(os.Getgid()), false)
			if cause == nil || h == nil || len(raw) != 0 {
				t.Fatal("fixture did not produce its actual failed original read")
			}
			other := audit
			switch name {
			case "missing_flag_false":
				missing = false
			case "nil_helper_error":
				cause = nil
			case "foreign_audit":
				other, _ = newLedger(ctx, audit.ownerID, audit.ownerRole, audit.primitiveSHA, audit.bindingSchema, audit.bindingSHA)
			case "unregistered_original_pointer":
				audit.mu.Lock()
				delete(audit.handles, h.id)
				audit.mu.Unlock()
			case "cancel_after_actual_missing":
				cancel()
			}
			if retry := originalOrdinaryIndependentMissing(ctx, other, h, missing, cause); retry != (name == "actual_missing_then_original_file") {
				t.Fatal("retry was inferred from an opaque/helper/foreign error")
			}
			if name != "actual_missing_then_original_file" {
				return
			}
			if errors.Is(cause, unix.ENOENT) || !missing || h.file != nil || h.closed || len(h.unclassified) != 1 || h.unclassified[0].cause != unix.ENOENT {
				t.Fatal("opaque policy error normalized or literal failed Open erased")
			}
			original := []byte(`{"private":"source-reader-fixture"}`)
			if e := os.WriteFile(filepath.Join(path, target), original, 0600); e != nil {
				t.Fatal(e)
			}
			actual, acquired, again, e := controlRegistrarReadCustodyFileCaptured(ctx, audit, anchor, target, uint32(os.Getuid()), uint32(os.Getgid()), false)
			if e != nil || again || acquired == h || !bytes.Equal(actual, original) || !acquired.closed || originalOrdinaryIndependentMissing(ctx, audit, acquired, again, e) {
				t.Fatal("same-file later actual return was fabricated, lost or still classified missing")
			}
			eof := false
			for _, row := range acquired.unclassified {
				if row.operation == "source_file_read" && row.cause == io.EOF && row.scalarObserved && row.scalar == 0 && len(row.raw) == 0 {
					eof = true
				}
			}
			if !eof || len(h.unclassified) != 1 || h.unclassified[0].cause != unix.ENOENT || h.closed {
				t.Fatal("literal EOF/Close replaced earlier actual failed Open identity")
			}
		})
	}
}

// Complete captured file custody must still fit after all actual variable
// returns. These lower Source IO fixtures do not authenticate a receipt or
// send HTTP; they exercise the exact final gate used before SDK authentication.
func TestOriginalOrdinaryIndependentReadPostcondition(t *testing.T) {
	for _, name := range []string{"complete_original_read", "actual_private_bytes_over_budget", "actual_return_census_over_budget", "cancel_after_actual_close", "foreign_context_after_actual_close"} {
		t.Run(name, func(t *testing.T) {
			parent, basis := ordinaryQMPTestLedger(t)
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			audit, e := newLedger(ctx, basis.ownerID, basis.ownerRole, basis.primitiveSHA, basis.bindingSchema, basis.bindingSHA)
			if e != nil || ordinaryQMPAuditBudget(audit, bodyLimit+1+4096) != nil {
				t.Fatal("original prospective reservation unavailable")
			}
			path := t.TempDir()
			original := []byte(`{"private":"original captured file, not a signed receipt"}`)
			if e := os.WriteFile(filepath.Join(path, "ordinary-original-independent-return.json"), original, 0600); e != nil {
				t.Fatal(e)
			}
			file, e := os.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			fd, e := originalFileNumber(file)
			if e != nil {
				t.Fatal(e)
			}
			raw, h, missing, readErr := controlRegistrarReadCustodyFileCaptured(ctx, audit, &callHandle{file: file, fd: fd}, "ordinary-original-independent-return.json", uint32(os.Getuid()), uint32(os.Getgid()), false)
			if readErr != nil || missing || !bytes.Equal(raw, original) || h == nil || !h.closed {
				t.Fatal("actual original file reader did not finish")
			}
			before := len(h.unclassified)
			if name == "actual_private_bytes_over_budget" || name == "actual_return_census_over_budget" {
				// Other actual Source reads on this same owned audit may consume
				// the prospective room. This uses real in-memory Read returns,
				// not manufactured Host facts, returned flags or budget setters.
				other, e := audit.handle()
				if e != nil {
					t.Fatal(e)
				}
				count, size := 17, bodyLimit
				if name == "actual_return_census_over_budget" {
					count, size = 4097, 1
				}
				for n := 0; n < count; n++ {
					payload := bytes.NewReader(bytes.Repeat([]byte{'p'}, size))
					buffer := make([]byte, size)
					_, e := currentOriginalAuditCall(ctx, other, "source_file_read", func() unclassifiedNativeReturn {
						actual, cause := payload.Read(buffer)
						return unclassifiedNativeReturn{scalarObserved: true, scalar: int64(actual), raw: buffer[:actual], cause: cause}
					})
					if e != nil {
						t.Fatal("lower fixture did not retain its actual read")
					}
				}
			}
			actual := ctx
			if name == "cancel_after_actual_close" {
				cancel()
			}
			if name == "foreign_context_after_actual_close" {
				actual = context.WithValue(ctx, struct{}{}, "foreign Source fixture")
			}
			if e := originalOrdinaryIndependentReadAdmission(actual, audit); (e == nil) != (name == "complete_original_read") {
				t.Fatal("pre-reservation/reader success escaped final budget/context admission")
			}
			eof := false
			for _, row := range h.unclassified {
				eof = eof || row.operation == "source_file_read" && row.cause == io.EOF && row.scalar == 0
			}
			if !bytes.Equal(raw, original) || !eof || !h.closed || len(h.unclassified) != before {
				t.Fatal("budget/context refusal rewrote original bytes, EOF, Close or rows")
			}
		})
	}
}

// Source assembly input: native_ordinary_qmp_source_test_fragment.go
// All fixtures below are Source-memory/temporary-file cases. No installed
// Source, native QEMU, socket, Start, Wait, SQL or creation proof is supplied.
func ordinaryQMPTestLedger(t *testing.T) (context.Context, *originalLedger) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	l, e := newLedger(ctx, "00000000-0000-4000-8000-000000000001", "factory_ordinary_worker", digest([]byte("source-only-basal")), "factory_ordinary_source_binding_v4", digest([]byte("source-only-binding")))
	if e != nil {
		t.Fatal(e)
	}
	return ctx, l
}
func TestOriginalOrdinaryQMPDefaultEmptyHasNoEffects(t *testing.T) {
	ctx, l := ordinaryQMPTestLedger(t)
	t.Run("creator", func(t *testing.T) {
		if raw, e := captureOriginalOrdinaryCreator(ctx, fixedInstallation{}, nil, l, nil, model.FactoryOrdinaryGuardRead{}); e == nil || raw != nil {
			t.Fatal("EMPTY Source became a creator")
		}
	})
	t.Run("independent", func(t *testing.T) {
		if raw, e := readOriginalOrdinaryIndependent(ctx, fixedInstallation{}, l, nil, []byte("{}")); e == nil || raw != nil {
			t.Fatal("EMPTY Source became an observer")
		}
	})
	handles, e := l.originalHandles()
	if e != nil || len(handles) != 0 {
		t.Fatal("default refusal performed Source IO")
	}
}

func TestOriginalOrdinaryQMPStreamingRealFileReturns(t *testing.T) {
	for _, c := range []struct {
		name  string
		data  []byte
		limit int64
		ok    bool
	}{{"zero", []byte{}, 8, true}, {"exact_bound", []byte("1234"), 4, true}, {"oversize", []byte("12345"), 4, false}} {
		t.Run(c.name, func(t *testing.T) {
			ctx, l := ordinaryQMPTestLedger(t)
			path := filepath.Join(t.TempDir(), "source-executable-bytes")
			if e := os.WriteFile(path, c.data, 0600); e != nil {
				t.Fatal(e)
			}
			data, sha, _, called, closed, e := ordinaryQMPReadFile(ctx, l, -1, path, false, false, true, c.limit)
			if (e == nil) != c.ok || len(data) != 0 || called.IsZero() || closed.Before(called) {
				t.Fatal("stream result/custody invalid")
			}
			if c.ok && sha != digest(c.data) {
				t.Fatal("hash was not actual integral EOF bytes")
			}
			if !c.ok && sha != "" {
				t.Fatal("oversize became complete hash")
			}
			handles, he := l.originalHandles()
			if he != nil || len(handles) != 1 {
				t.Fatal("file owner absent")
			}
			h := handles[0]
			h.mu.Lock()
			defer h.mu.Unlock()
			eof, closeSeen := false, false
			count := int64(0)
			for _, r := range h.unclassified {
				if r.operation == "source_audit_private_read" {
					count += r.scalar
					if len(r.raw) != 0 {
						t.Fatal("executable raw retained as integral audit payload")
					}
					if r.cause == io.EOF {
						eof = true
					}
				}
				if r.operation == "source_audit_private_close" {
					closeSeen = !r.returnedAt.IsZero() && r.cause == nil
				}
			}
			if count != int64(len(c.data)) || !closeSeen || c.ok && !eof {
				t.Fatal("actual counts/EOF/Close omitted")
			}
		})
	}
	t.Run("open_error_no_fabricated_close", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		_, sha, _, _, closed, e := ordinaryQMPReadFile(ctx, l, -1, filepath.Join(t.TempDir(), "absent"), false, false, true, 8)
		if e == nil || sha != "" || !closed.IsZero() {
			t.Fatal("failed Open fabricated EOF/Close")
		}
	})
}
func TestOriginalOrdinaryQMPPrivateReturnRetention(t *testing.T) {
	t.Run("partial_error", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		h, e := l.handle()
		if e != nil {
			t.Fatal(e)
		}
		cause := errors.New("synthetic Source-only partial return")
		r, e := ordinaryQMPSourceReturn(ctx, h, "source_audit_qmp_read", false, false, func() (unclassifiedNativeReturn, error) {
			return unclassifiedNativeReturn{scalarObserved: true, scalar: 2, raw: []byte("ab")}, cause
		})
		if !errors.Is(e, cause) || r.cause != cause || !bytes.Equal(r.raw, []byte("ab")) || r.returnedAt.Before(r.calledAt) {
			t.Fatal("partial original erased")
		}
		r.raw[0] = '!'
		if h.unclassified[0].raw[0] != 'a' {
			t.Fatal("returned copy aliases retained original")
		}
		// The method supplies a private owned copy of input, not mutable source data.
		input := []byte("xy")
		_, _ = ordinaryQMPSourceReturn(ctx, h, "source_audit_qmp_read", false, false, func() (unclassifiedNativeReturn, error) {
			return unclassifiedNativeReturn{scalarObserved: true, scalar: 2, raw: input}, nil
		})
		input[0] = '!'
		if h.unclassified[1].raw[0] != 'x' {
			t.Fatal("input aliases retained original")
		}
	})
	t.Run("cancel_during_actual_return_preserves_original_cause", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		child, cancel := context.WithCancel(ctx)
		l, _ = newLedger(child, l.ownerID, l.ownerRole, l.primitiveSHA, l.bindingSchema, l.bindingSHA)
		h, _ := l.handle()
		r, e := ordinaryQMPSourceReturn(child, h, "source_audit_qmp_write", false, false, func() (unclassifiedNativeReturn, error) {
			cancel()
			return unclassifiedNativeReturn{scalarObserved: true, scalar: 1, raw: []byte("x")}, nil
		})
		if e == nil || r.cause != nil || r.scalar != 1 || r.returnedAt.IsZero() {
			t.Fatal("late policy overwrote actual nil syscall return")
		}
	})
	t.Run("cancel_before_effect_has_no_return", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		child, cancel := context.WithCancel(ctx)
		l, _ = newLedger(child, l.ownerID, l.ownerRole, l.primitiveSHA, l.bindingSchema, l.bindingSHA)
		h, _ := l.handle()
		cancel()
		called := false
		r, e := ordinaryQMPSourceReturn(child, h, "source_audit_qmp_read", false, false, func() (unclassifiedNativeReturn, error) { called = true; return unclassifiedNativeReturn{}, nil })
		if e == nil || called || !r.returnedAt.IsZero() || len(h.unclassified) != 0 {
			t.Fatal("refusal invented actual Read")
		}
	})
	t.Run("stream_omission_is_not_empty_raw_proof", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		h, _ := l.handle()
		r, e := ordinaryQMPSourceReturn(ctx, h, "source_audit_private_read", true, false, func() (unclassifiedNativeReturn, error) {
			return unclassifiedNativeReturn{scalarObserved: true, scalar: 3, raw: []byte("exe")}, io.EOF
		})
		if !errors.Is(e, io.EOF) || r.cause != io.EOF || r.scalar != 3 || r.raw != nil || !r.rawOmitted {
			t.Fatal("stream omission mislabeled/erased")
		}
	})
}
func TestOriginalOrdinaryQMPTranscriptAndStrictABI(t *testing.T) {
	at := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	rows := make([]ordinaryQMPIO, 7)
	for n := range rows {
		d := "read"
		if n == 1 || n == 3 || n == 5 {
			d = "write"
		}
		rows[n] = ordinaryQMPIO{Direction: d, SHA256: digest([]byte{byte(n)}), Bytes: 1, ReturnedAt: at.Add(time.Duration(n) * time.Nanosecond)}
	}
	for _, c := range []struct {
		name   string
		change func([]ordinaryQMPIO) []ordinaryQMPIO
		ok     bool
	}{{"complete_source_transcript", func(v []ordinaryQMPIO) []ordinaryQMPIO { return v }, true}, {"unknown_hash", func(v []ordinaryQMPIO) []ordinaryQMPIO { v[0].SHA256 = ""; return v }, false}, {"late_return", func(v []ordinaryQMPIO) []ordinaryQMPIO { v[6].ReturnedAt = at.Add(time.Hour); return v }, false}, {"wrong_write_count", func(v []ordinaryQMPIO) []ordinaryQMPIO { v[1].Direction = "read"; return v }, false}, {"sixty_five_entries", func(v []ordinaryQMPIO) []ordinaryQMPIO { return append(v, make([]ordinaryQMPIO, 58)...) }, false}} {
		t.Run(c.name, func(t *testing.T) {
			v := c.change(append([]ordinaryQMPIO(nil), rows...))
			if (ordinaryQMPTranscript(v, at, at.Add(time.Second)) == nil) != c.ok {
				t.Fatal("transcript guard ineffective")
			}
		})
	}
	for _, c := range []struct{ name, raw string }{{"unknown_field", `{"schema":"original_native_qemu_identity_readback_v1","new_authority":true}`}, {"duplicate_field", `{"schema":"a","schema":"b"}`}, {"case_alias", `{"Schema":"a"}`}} {
		t.Run(c.name, func(t *testing.T) {
			var out originalOrdinaryCreatorReturn
			if decodePrivateOriginalJSON([]byte(c.raw), &out) == nil {
				t.Fatal("untrusted JSON acquired authority shape")
			}
		})
	}
	t.Run("uuid_argument_unique", func(t *testing.T) {
		id := "00000000-0000-4000-8000-000000000002"
		if !ordinaryQMPUUIDArgument([]byte("qemu\x00-uuid\x00"+id+"\x00"), id) || ordinaryQMPUUIDArgument([]byte("qemu\x00-uuid\x00"+id+"\x00-uuid\x00"+id+"\x00"), id) {
			t.Fatal("duplicate UUID argument accepted")
		}
	})
	t.Run("fixed_commands_only", func(t *testing.T) {
		q := &originalOrdinaryQMP{}
		if q.command("quit", "not-permitted", nil) == nil {
			t.Fatal("observer admitted mutation command")
		}
	})
	t.Run("frame_ceiling_before_io", func(t *testing.T) {
		q := &originalOrdinaryQMP{io: make([]ordinaryQMPIO, 64)}
		if _, e := q.readRow(); e == nil {
			t.Fatal("frame cap allowed another read")
		}
	})
	t.Run("whole_wire_exact_64k", func(t *testing.T) {
		raw, e := ordinaryQMPWire(strings.Repeat("x", bodyLimit-2))
		if e != nil || len(raw) != bodyLimit {
			t.Fatal("exact whole wire cap refused")
		}
	})
	t.Run("whole_wire_cap", func(t *testing.T) {
		raw, e := ordinaryQMPWire(strings.Repeat("x", bodyLimit))
		if e == nil || len(raw) <= bodyLimit {
			t.Fatal("whole private ABI cap ignored")
		}
	})
}
func TestOriginalOrdinaryQMPBudgetAndPointerCustody(t *testing.T) {
	t.Run("one_mib_exact_and_oversize", func(t *testing.T) {
		_, l := ordinaryQMPTestLedger(t)
		if ordinaryQMPAuditBudget(l, 1048576) != nil || ordinaryQMPAuditBudget(l, 1048577) == nil {
			t.Fatal("audit admission bound shifted")
		}
	})
	t.Run("stream_128mib_ceiling_before_effect", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		missing := filepath.Join(t.TempDir(), "missing")
		_, _, _, _, _, e := ordinaryQMPReadFile(ctx, l, -1, missing, false, false, true, 128<<20)
		handles, _ := l.originalHandles()
		if e == nil || len(handles) != 1 || len(handles[0].unclassified) != 1 {
			t.Fatal("exact stream bound did not reach actual Open refusal")
		}
		ctx2, l2 := ordinaryQMPTestLedger(t)
		_, _, _, _, _, e = ordinaryQMPReadFile(ctx2, l2, -1, missing, false, false, true, (128<<20)+1)
		handles, _ = l2.originalHandles()
		if e == nil || len(handles) != 0 {
			t.Fatal("oversize stream bound performed IO")
		}
	})
	t.Run("typed_source_outputs_copied", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		h, _ := l.handle()
		fs := unix.Statfs_t{Type: unix.PROC_SUPER_MAGIC}
		peer := unix.Ucred{Pid: 7, Uid: 8, Gid: 9}
		_, e := ordinaryQMPSourceReturn(ctx, h, "source_only_typed_test", false, false, func() (unclassifiedNativeReturn, error) {
			return unclassifiedNativeReturn{statfs: &fs, ucred: &peer}, nil
		})
		fs.Type = 0
		peer.Pid = 0
		if e != nil || h.unclassified[0].statfs.Type != unix.PROC_SUPER_MAGIC || h.unclassified[0].ucred.Pid != 7 {
			t.Fatal("typed Source outputs lost/aliased")
		}
	})

	t.Run("retained_raw_budget", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		h, _ := l.handle()
		h.unclassified = []unclassifiedNativeReturn{{raw: make([]byte, 1048576)}}
		if ordinaryQMPAuditBudget(l, 0) == nil {
			t.Fatal("metadata plus raw exceeded budget silently")
		}
		called := false
		_, e := ordinaryQMPSourceReturn(ctx, h, "source_audit_qmp_read", false, false, func() (unclassifiedNativeReturn, error) { called = true; return unclassifiedNativeReturn{}, nil })
		if e == nil || called {
			t.Fatal("over-budget owner performed new IO")
		}
	})
	t.Run("exact_pointer_not_copied_row", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		_ = ctx
		h, _ := l.handle()
		now := time.Now().UTC()
		id := h.id + ":1"
		r := &retainedCall{fact: model.HostFactoryPrimitiveIOReturn{Operation: "qemu_start", OriginalHandleID: h.id, OriginalState: "returned", OriginalCallID: &id, OriginalCalledAt: &now, OriginalReturnedAt: &now}}
		l.calls[h.id+"\x00qemu_start"] = []*retainedCall{r}
		copy := *r
		if nativeProcessOriginalCall(h, r, "qemu_start") != nil || nativeProcessOriginalCall(h, &copy, "qemu_start") == nil {
			t.Fatal("copied metadata replaced actual Start pointer")
		}
	})
	t.Run("foreign_context", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		other, cancel := context.WithDeadline(context.Background(), l.deadline)
		defer cancel()
		if ordinaryQMPWindow(ctx, l) != nil || ordinaryQMPWindow(other, l) == nil {
			t.Fatal("same date replaced actual original context")
		}
	})
}

func TestOriginalOrdinaryQMPDistinctDirectoryLineage(t *testing.T) {
	parent := unix.Stat_t{Dev: 1, Ino: 11, Mode: unix.S_IFDIR | 0700, Uid: 7, Gid: 8, Nlink: 3}
	control := unix.Stat_t{Dev: 1, Ino: 12, Mode: unix.S_IFDIR | 0700, Uid: 7, Gid: 8, Nlink: 2}
	for _, tc := range []struct {
		name   string
		change func(*unix.Stat_t, *unix.Stat_t, *unix.Stat_t)
		ok     bool
	}{
		{"distinct_parent_child", func(_, _, _ *unix.Stat_t) {}, true},
		{"parent_dynamic_size_links", func(p, _, _ *unix.Stat_t) { p.Size = 900; p.Nlink = 9 }, true},
		{"parent_is_control_alias", func(p, _, a *unix.Stat_t) { *p = *a }, false},
		{"foreign_child_inode", func(_, c, _ *unix.Stat_t) { c.Ino++ }, false},
		{"foreign_child_device", func(_, c, _ *unix.Stat_t) { c.Dev++ }, false},
		{"foreign_child_mode", func(_, c, _ *unix.Stat_t) { c.Mode = unix.S_IFDIR | 0755 }, false},
		{"foreign_child_uid", func(_, c, _ *unix.Stat_t) { c.Uid++ }, false},
		{"foreign_child_gid", func(_, c, _ *unix.Stat_t) { c.Gid++ }, false},
		{"unsafe_parent_mode", func(p, _, _ *unix.Stat_t) { p.Mode = unix.S_IFDIR | 0755 }, false},
		{"foreign_parent_owner", func(p, _, _ *unix.Stat_t) { p.Uid++ }, false},
		{"parent_is_regular", func(p, _, _ *unix.Stat_t) { p.Mode = unix.S_IFREG | 0700 }, false},
		{"missing_control_inode", func(_, _, a *unix.Stat_t) { a.Ino = 0 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, child, anchor := parent, control, control
			tc.change(&p, &child, &anchor)
			if ordinaryQMPArtifactLineage(p, child, anchor) != tc.ok {
				t.Fatal("artifact parent and actual control child lineage crossed")
			}
		})
	}
}

func ordinaryQMPTestDirectories(t *testing.T) (string, unix.Stat_t) {
	t.Helper()
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	child := filepath.Join(parent, "original-control-root")
	if e := os.Mkdir(child, 0700); e != nil {
		t.Fatal(e)
	}
	var stat unix.Stat_t
	if e := unix.Stat(child, &stat); e != nil {
		t.Fatal(e)
	}
	return parent, stat
}

// These are CI-only small Source file/memory fixtures, not Native acquisition
// receipts, approved installation fixtures or an actual QEMU/Source success.
func TestOriginalOrdinaryQMPArtifactDirectoryCustody(t *testing.T) {
	t.Run("real_distinct_dirs_and_owned_close", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		path, control := ordinaryQMPTestDirectories(t)
		h, parent, e := ordinaryQMPOpenArtifactParent(ctx, fixedInstallation{privateDirectory: path}, l, control)
		if h != nil && h.file != nil {
			defer func() {
				if !h.closed {
					_ = h.file.Close()
				}
			}()
		}
		if e != nil || h == nil || h.file == nil || parent.Ino == control.Ino && parent.Dev == control.Dev || len(h.unclassified) != 3 {
			t.Fatal("actual distinct parent refused")
		}
		if h.unclassified[0].operation != "source_audit_artifact_parent_open" || !h.unclassified[0].scalarObserved || h.unclassified[0].scalar != int64(h.fd) || h.unclassified[1].stat == nil || h.unclassified[2].stat == nil || !ordinaryQMPDirectoryStable(*h.unclassified[2].stat, control) {
			t.Fatal("actual directory returns absent")
		}
		at, e := ordinaryQMPClose(ctx, h)
		if e != nil || at.IsZero() || !h.closed || len(h.unclassified) != 4 || h.unclassified[3].cause != nil || h.unclassified[3].returnedAt != at {
			t.Fatal("owned actual Close missing")
		}
	})
	t.Run("foreign_child_refusal_retains_actual_stat_and_close", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		path, actual := ordinaryQMPTestDirectories(t)
		_, foreign := ordinaryQMPTestDirectories(t)
		h, _, e := ordinaryQMPOpenArtifactParent(ctx, fixedInstallation{privateDirectory: path}, l, foreign)
		if h != nil && h.file != nil {
			defer func() {
				if !h.closed {
					_ = h.file.Close()
				}
			}()
		}
		if e == nil || h == nil || h.file == nil || len(h.unclassified) != 3 || h.unclassified[2].cause != nil || h.unclassified[2].stat == nil || !ordinaryQMPDirectoryStable(*h.unclassified[2].stat, actual) {
			t.Fatal("foreign child became evidence or original overwritten")
		}
		if _, e = ordinaryQMPClose(ctx, h); e != nil || !h.closed {
			t.Fatal("refused actual owner was not closed")
		}
	})
	t.Run("borrowed_anchor_has_no_native_counter_or_close", func(t *testing.T) {
		ctx, audit := ordinaryQMPTestLedger(t)
		path, expected := ordinaryQMPTestDirectories(t)
		fd, e := unix.Open(filepath.Join(path, "original-control-root"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if e != nil {
			t.Fatal(e)
		}
		file := os.NewFile(uintptr(fd), "Source-only-borrowed-fixture")
		defer file.Close()
		native, _ := newLedger(ctx, audit.ownerID, audit.ownerRole, audit.primitiveSHA, "original_host_factory_root_preparation_v4", digest([]byte("Source-only-root")))
		anchor, _ := native.handle()
		anchor.file, anchor.fd = file, fd
		anchor.mu.Lock()
		observed, e := ordinaryQMPBorrowedDirectoryStat(ctx, audit, anchor)
		anchor.mu.Unlock()
		if e != nil || !ordinaryQMPDirectoryStable(observed, expected) || anchor.next != 0 || anchor.closed || len(native.calls) != 0 || len(anchor.unclassified) != 0 {
			t.Fatal("borrowed original Native owner mutated")
		}
		handles, _ := audit.originalHandles()
		if len(handles) != 1 || handles[0].file != nil || len(handles[0].unclassified) != 1 || handles[0].unclassified[0].stat == nil {
			t.Fatal("separate method return not retained")
		}
	})
	t.Run("failed_open_no_fake_close", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		path, control := ordinaryQMPTestDirectories(t)
		h, _, e := ordinaryQMPOpenArtifactParent(ctx, fixedInstallation{privateDirectory: filepath.Join(path, "absent")}, l, control)
		if e == nil || h == nil || h.file != nil || h.closed || len(h.unclassified) != 1 || !errors.Is(h.unclassified[0].cause, unix.ENOENT) || h.unclassified[0].returnedAt.IsZero() {
			t.Fatal("failed Open original lost or Close invented")
		}
	})
	t.Run("cancel_before_acquisition_has_no_effect", func(t *testing.T) {
		parent, l := ordinaryQMPTestLedger(t)
		ctx, cancel := context.WithCancel(parent)
		l, _ = newLedger(ctx, l.ownerID, l.ownerRole, l.primitiveSHA, l.bindingSchema, l.bindingSHA)
		path, control := ordinaryQMPTestDirectories(t)
		cancel()
		h, _, e := ordinaryQMPOpenArtifactParent(ctx, fixedInstallation{privateDirectory: path}, l, control)
		handles, _ := l.originalHandles()
		if e == nil || h != nil || len(handles) != 0 {
			t.Fatal("cancelled context acquired new owner")
		}
	})
	t.Run("symlink_child_policy_refusal_keeps_nil_syscall_cause", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		path := t.TempDir()
		if e := os.Chmod(path, 0700); e != nil {
			t.Fatal(e)
		}
		target, control := ordinaryQMPTestDirectories(t)
		if e := os.Symlink(filepath.Join(target, "original-control-root"), filepath.Join(path, "original-control-root")); e != nil {
			t.Fatal(e)
		}
		h, _, e := ordinaryQMPOpenArtifactParent(ctx, fixedInstallation{privateDirectory: path}, l, control)
		if h != nil && h.file != nil {
			defer func() {
				if !h.closed {
					_ = h.file.Close()
				}
			}()
		}
		if e == nil || h == nil || len(h.unclassified) != 3 || h.unclassified[2].cause != nil || h.unclassified[2].stat == nil || h.unclassified[2].stat.Mode&unix.S_IFMT != unix.S_IFLNK {
			t.Fatal("NOFOLLOW output erased or admitted")
		}
		if _, e = ordinaryQMPClose(ctx, h); e != nil {
			t.Fatal(e)
		}
	})
	t.Run("unsafe_source_path_has_no_effect", func(t *testing.T) {
		ctx, l := ordinaryQMPTestLedger(t)
		_, control := ordinaryQMPTestDirectories(t)
		h, _, e := ordinaryQMPOpenArtifactParent(ctx, fixedInstallation{privateDirectory: "relative/artifacts"}, l, control)
		handles, _ := l.originalHandles()
		if e == nil || h != nil || len(handles) != 0 {
			t.Fatal("noncompiled path recipe reached Open")
		}
	})
}

func TestOriginalOrdinaryQMPCreatorPreparedArtifactPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*preparedOriginal, *originalOrdinaryWorker)
		ok     bool
	}{
		{"exact_prepared_parent", func(_ *preparedOriginal, _ *originalOrdinaryWorker) {}, true},
		{"control_fd_cannot_replace_parent", func(p *preparedOriginal, _ *originalOrdinaryWorker) { p.choice.rootFD++ }, false},
		{"foreign_artifact_argv_path", func(p *preparedOriginal, _ *originalOrdinaryWorker) {
			p.cmd.Args = append([]string{}, p.cmd.Args...)
			p.cmd.Args[0] = "/foreign/qemu"
		}, false},
		{"foreign_signed_parent_proof", func(_ *preparedOriginal, w *originalOrdinaryWorker) { w.artifactProof.OriginalStat.Inode++ }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, audit := ordinaryQMPTestLedger(t)
			path, _ := ordinaryQMPTestDirectories(t)
			file, e := os.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			fd, e := originalFileNumber(file)
			if e != nil {
				t.Fatal(e)
			}
			var st unix.Stat_t
			if e = unix.Fstat(fd, &st); e != nil {
				t.Fatal(e)
			}
			source, _ := newLedger(ctx, audit.ownerID, audit.ownerRole, audit.primitiveSHA, audit.bindingSchema, audit.bindingSHA)
			native, _ := newLedger(ctx, audit.ownerID, audit.ownerRole, audit.primitiveSHA, audit.bindingSchema, audit.bindingSHA)
			h, _ := source.handle()
			h.file, h.fd = file, fd
			at := time.Now().UTC()
			for n, op := range []string{"source_directory_open", "source_directory_fstat"} {
				row := unclassifiedNativeReturn{operation: op, ownerID: audit.ownerID, subjectRole: audit.ownerRole, stage: "source_audit", bindingSchema: audit.bindingSchema, bindingSHA: audit.bindingSHA, handleID: h.id, callID: h.id + ":" + strconv.Itoa(n+1), ordinal: uint64(n + 1), calledAt: at, returnedAt: at, deadline: source.deadline, private: true}
				if n == 0 {
					row.scalarObserved, row.scalar = true, int64(fd)
				} else {
					copy := st
					row.stat = &copy
				}
				h.unclassified = append(h.unclassified, row)
			}
			h.next = 2
			i := fixedInstallation{privateDirectory: path, slot: 1, qemuUUID: "00000000-0000-4000-8000-000000000002"}
			args := fixedQEMUArguments(path, i)
			argv, _ := json.Marshal(args)
			p := &preparedOriginal{choice: &originalChoice{rootFD: fd, rootIdentity: st, ledger: native, sourceRoot: h, sourceRootCall: h.unclassified[1]}, cmd: &exec.Cmd{Args: args}, plan: model.HostFactoryPreparedCreatePlan{FixedArgvSHA256: digest(argv)}}
			id := "00000000-0000-4000-8000-000000000003"
			w := &originalOrdinaryWorker{prepared: p, installation: i, publisher: &originalNativePublisher{ledger: native, originalLedgers: []*originalLedger{native}}, basal: &basalOwner{sha: audit.primitiveSHA}, artifactDirectory: h, artifactProof: originalOrdinaryArtifactDirectory{OriginalHandleID: id, OriginalOpenCallID: id + ":1", OriginalFstatCallID: id + ":2", OriginalStat: nativeStat(st)}}
			p.ordinaryWorker = w
			tc.change(p, w)
			actual, e := ordinaryQMPPreparedParent(ctx, i, p, audit)
			if (e == nil) != tc.ok || tc.ok && actual != h {
				t.Fatal("prepared Source artifact path/proof replaced")
			}
			handles, _ := audit.originalHandles()
			if len(handles) != 0 {
				t.Fatal("readonly prepared-cache guard performed IO")
			}
		})
	}
}

// Structural Source-memory membership only. No compiled installation, real
// command/Start, IO, Native receipt, permission or SQL relation is supplied.
func TestOriginalOrdinaryQMPCreateLedgerMembership(t *testing.T) {
	for _, name := range []string{"primary420_member60", "missing_member", "duplicate_member", "metadata_equal_pointer_is_not_member", "foreign_owner", "foreign_role", "foreign_primitive", "foreign_binding", "same_date_foreign_context", "wider_than_primary"} {
		t.Run(name, func(t *testing.T) {
			at := time.Now()
			primaryContext, stop := context.WithDeadline(context.Background(), at.Add(420*time.Second))
			defer stop()
			ctx, cancel := context.WithDeadline(primaryContext, at.Add(60*time.Second))
			defer cancel()
			owner := "00000000-0000-4000-8000-000000000001"
			primitive, binding := digest([]byte("Source-only-basal")), digest([]byte("Source-only-ordinary-binding"))
			primary, _ := newLedger(primaryContext, owner, "factory_ordinary_worker", primitive, "factory_ordinary_source_binding_v4", binding)
			native, _ := newLedger(ctx, owner, primary.ownerRole, primitive, primary.bindingSchema, binding)
			audit, _ := newLedger(ctx, owner, primary.ownerRole, primitive, primary.bindingSchema, binding)
			publisher := &originalNativePublisher{ledger: primary, originalLedgers: []*originalLedger{primary, native}}
			before := primary.deadline
			switch name {
			case "missing_member":
				publisher.originalLedgers = []*originalLedger{primary}
			case "duplicate_member":
				publisher.originalLedgers = append(publisher.originalLedgers, native)
			case "metadata_equal_pointer_is_not_member":
				other, _ := newLedger(ctx, owner, primary.ownerRole, primitive, primary.bindingSchema, binding)
				publisher.originalLedgers = []*originalLedger{primary, other}
			case "foreign_owner":
				native.ownerID = "00000000-0000-4000-8000-000000000002"
			case "foreign_role":
				native.ownerRole = "host_worker"
			case "foreign_primitive":
				native.primitiveSHA = digest([]byte("foreign basal"))
			case "foreign_binding":
				native.bindingSHA = digest([]byte("foreign ordinary binding"))
			case "same_date_foreign_context":
				other, finish := context.WithDeadline(context.Background(), native.deadline)
				defer finish()
				native.ctx = other
			case "wider_than_primary":
				native.deadline = primary.deadline.Add(time.Second)
			}
			ok := ordinaryQMPCreateLedgerMember(ctx, publisher, native, audit)
			if ok != (name == "primary420_member60") {
				t.Fatal("Source original create ledger selected by metadata or primary rebound")
			}
			if publisher.ledger != primary || !primary.deadline.Equal(before) || len(primary.calls) != 0 || len(native.calls) != 0 || len(audit.calls) != 0 {
				t.Fatal("readonly membership check mutated original owners")
			}
		})
	}
}

// Source assembly input: native_ordinary_recovery_source_test_fragment.go
func TestOriginalOrdinaryRecoveryExactExistingRoute(t *testing.T) {
	for _, id := range []string{"00000000-0000-4000-8000-000000000001", "", "00000000-0000-0000-0000-000000000000", "../settle", "00000000-0000-4000-8000-000000000001/redeem", "00000000-0000-4000-8000-000000000001?retry=true"} {
		t.Run(id, func(t *testing.T) {
			path, e := originalOrdinaryRecoveryPath(id)
			ok := id == "00000000-0000-4000-8000-000000000001"
			if (e == nil) != ok || ok && path != "/api/v1/capacity/mutations/"+id {
				t.Fatal("recovery selected another route/identity")
			}
		})
	}
}

// This exercises sticky refusal/preservation only, not a real GET, Source
// selection or mutation. The actual caller contains no POST replay branch.
func TestOriginalOrdinaryRecoveryRefusalPreservesPOST(t *testing.T) {
	for _, phase := range []string{"redeem", "settle", "foreign"} {
		t.Run(phase, func(t *testing.T) {
			original := []byte("actual private partial POST response\n")
			c := &OrdinaryOriginalCreate{responseRaw: bytes.Clone(original), settlementResponseRaw: bytes.Clone(original)}
			for n := 0; n < 2; n++ {
				if c.recoverOriginalMutation(context.Background(), nil, "https://127.0.0.1:19449", phase) == nil {
					t.Fatal("unavailable Source recovered permission")
				}
			}
			if !bytes.Equal(c.responseRaw, original) || !bytes.Equal(c.settlementResponseRaw, original) || c.consumed {
				t.Fatal("GET synthesized/overwrote original POST or create permission")
			}
			index := 0
			if phase == "settle" {
				index = 1
			}
			if phase == "foreign" {
				if c.recoveries[0] != nil || c.recoveries[1] != nil {
					t.Fatal("unknown recovery attempt installed")
				}
			} else {
				x := c.recoveries[index]
				if x == nil || x.cause == nil || x.transportReturn.OriginalState != "" || len(x.raw) != 0 {
					t.Fatal("retry reset identity or invented HTTP GoReturn")
				}
			}
		})
	}
}

// Source assembly input: native_ordinary_settle_source_test_fragment.go
// These projections are Source identity discriminants, never QEMU/SQL proof.
func TestOriginalOrdinaryFreshProcessLifetimeKeepsDynamicStat(t *testing.T) {
	original := originalOrdinaryQEMUProcess{PID: 42, PPID: 7, StartTicks: 123, StatSHA256: digest([]byte("original stat counters"))}
	for _, tc := range []struct {
		name   string
		change func(*originalOrdinaryQEMUProcess)
		accept bool
	}{
		{"different_stat_same_lifetime", func(p *originalOrdinaryQEMUProcess) { p.StatSHA256 = digest([]byte("later original stat counters")) }, true},
		{"different_pid", func(p *originalOrdinaryQEMUProcess) { p.PID++ }, false},
		{"different_parent", func(p *originalOrdinaryQEMUProcess) { p.PPID++ }, false},
		{"different_start_ticks", func(p *originalOrdinaryQEMUProcess) { p.StartTicks++ }, false},
		{"unknown_start", func(p *originalOrdinaryQEMUProcess) { p.StartTicks = 0 }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fresh := original
			tc.change(&fresh)
			before, _ := json.Marshal(fresh)
			if originalOrdinarySameLifetime(fresh, original) != tc.accept {
				t.Fatal("fresh lifetime identity joined mutable stat or foreign process")
			}
			after, _ := json.Marshal(fresh)
			if string(before) != string(after) {
				t.Fatal("original stat projection rewritten")
			}
		})
	}
}

// Source assembly input: native_ordinary_stdio_source_test_fragment.go
// Small actual pipe/file fixtures for remote CI only. They provide no process,
// Start, Wait, Native receipt, compiled installation, SDK or SQL permission.
func TestOriginalOrdinaryQEMUStdioOwnedClosure(t *testing.T) {
	ctx, l := ordinaryQMPTestLedger(t)
	q := &originalOrdinaryQEMULifetime{audit: l, cleanup: ctx, joinDone: make(chan struct{})}
	stdio, e := ordinaryOriginalQEMUStdio(ctx, q)
	if e != nil || stdio == nil || q.stdio != stdio || len(q.stdioHandles) != 5 {
		t.Fatal("actual stdio owners missing")
	}
	before := make(map[*callHandle]uint64)
	for _, h := range q.stdioHandles {
		if h == nil || h.ledger != l || h.file == nil || h.fd < 0 {
			t.Fatal("unregistered stdio endpoint")
		}
		l.mu.Lock()
		registered := l.handles[h.id] == h
		l.mu.Unlock()
		if !registered {
			t.Fatal("endpoint absent from Source acquisition order")
		}
		before[h] = h.next
	}
	for n := 0; n < 2; n++ {
		if e = q.closeAndJoin(ctx); e != nil {
			t.Fatal("unstarted actual Source closure refused")
		}
	}
	for _, h := range q.stdioHandles {
		count := 0
		for _, r := range h.unclassified {
			if r.operation == "source_audit_private_close" {
				count++
				if r.cause != nil || r.returnedAt.IsZero() || r.calledAt.IsZero() || r.callID == "" {
					t.Fatal("actual Close absent")
				}
			}
		}
		if !h.closed || h.closeAt.IsZero() || count != 1 || h.next != before[h]+1 {
			t.Fatal("Close lost/replayed or Native counter fabricated")
		}
	}
}

func TestOriginalOrdinaryQEMUStdioPrivateRead(t *testing.T) {
	for _, name := range []string{"literal_zero_eof", "binary_partial_then_literal_eof", "actual65537_private_refusal", "cancel_before_read_keeps_close"} {
		t.Run(name, func(t *testing.T) {
			parent, l := ordinaryQMPTestLedger(t)
			ctx, stop := context.WithCancel(parent)
			defer stop()
			l, _ = newLedger(ctx, l.ownerID, l.ownerRole, l.primitiveSHA, l.bindingSchema, l.bindingSHA)
			q := &originalOrdinaryQEMULifetime{audit: l, cleanup: ctx, joinDone: make(chan struct{})}
			_, e := ordinaryOriginalQEMUStdio(ctx, q)
			if e != nil {
				t.Fatal(e)
			}
			defer q.closeAndJoin(parent)
			payload := []byte{}
			switch name {
			case "binary_partial_then_literal_eof":
				payload = []byte{0, 0xff, 1, 2, 3, 0}
			case "actual65537_private_refusal":
				payload = bytes.Repeat([]byte{0xff}, bodyLimit+1)
			case "cancel_before_read_keeps_close":
				stop()
			}
			done := make(chan error, 1)
			go ordinaryOriginalQEMURead(ctx, q.stdout, done)
			if name != "cancel_before_read_keeps_close" && len(payload) > 0 {
				if n, e := q.stdoutWriter.file.Write(payload); e != nil || n != len(payload) {
					t.Fatal("fixture pipe input failed")
				}
			}
			if e := ordinaryOriginalQEMUClose(q.stdoutWriter); e != nil && name != "cancel_before_read_keeps_close" {
				t.Fatal(e)
			}
			var cause error
			select {
			case cause = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("actual Source reader did not join")
			}
			ok := name == "literal_zero_eof" || name == "binary_partial_then_literal_eof"
			if (cause == nil) != ok || !q.stdout.closed {
				t.Fatal("partial/cancelled/oversized read became complete")
			}
			var raw []byte
			eof := false
			reads := 0
			for _, r := range q.stdout.unclassified {
				if r.operation == "source_audit_private_read" {
					reads++
					if r.returnedAt.IsZero() || r.scalar != int64(len(r.raw)) || !r.private || r.rawOmitted {
						t.Fatal("private actual return lost")
					}
					raw = append(raw, r.raw...)
					eof = eof || r.cause == io.EOF
				}
			}
			if name == "cancel_before_read_keeps_close" {
				if reads != 0 || len(raw) != 0 {
					t.Fatal("cancelled Source manufactured Read")
				}
			} else {
				if !bytes.Equal(raw, payload) || ok && !eof {
					t.Fatal("partial raw or literal EOF changed")
				}
			}
		})
	}
}

func TestOriginalOrdinaryQEMUCloseCensusDiagnostic(t *testing.T) {
	for _, name := range []string{"owned_close", "census_exhausted_unknown_identity", "cancelled_original_bound"} {
		t.Run(name, func(t *testing.T) {
			parent, l := ordinaryQMPTestLedger(t)
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			l, _ = newLedger(ctx, l.ownerID, l.ownerRole, l.primitiveSHA, l.bindingSchema, l.bindingSHA)
			file, e := os.CreateTemp(t.TempDir(), "source-close-")
			if e != nil {
				t.Fatal(e)
			}
			defer file.Close()
			h, _ := l.handle()
			h.file = file
			h.fd, e = originalFileNumber(file)
			if e != nil {
				t.Fatal(e)
			}
			if name == "census_exhausted_unknown_identity" {
				h.next = callLimit
			}
			if name == "cancelled_original_bound" {
				cancel()
			}
			before := h.next
			e = ordinaryOriginalQEMUClose(h)
			if (e == nil) != (name == "owned_close") || !h.closed || h.closeAt.IsZero() || len(h.unclassified) != 1 {
				t.Fatal("original cleanup lost or refusal hid ownership")
			}
			r := h.unclassified[0]
			if r.cause != nil || r.operation != "source_audit_private_close" || r.returnedAt.IsZero() {
				t.Fatal("policy error replaced actual Close cause")
			}
			if name == "census_exhausted_unknown_identity" {
				if r.callID != "" || r.ordinal != 0 || h.next != before {
					t.Fatal("fallback invented CallID/counter")
				}
			} else if r.callID == "" || r.ordinal != before+1 {
				t.Fatal("owning Close identity absent")
			}
			_ = ordinaryOriginalQEMUClose(h)
			if len(h.unclassified) != 1 {
				t.Fatal("Close replayed")
			}
		})
	}
}

// The following fixtures own only in-memory completion channels. They execute
// the production join/timeout paths without a process, signal, Wait, file, pipe,
// installed Source, Native receipt, public caller or SQL success.
type ordinaryQEMUJoinMemory struct {
	q                                *originalOrdinaryQEMULifetime
	waitOnce, stdoutOnce, stderrOnce sync.Once
}

func newOrdinaryQEMUJoinMemory(cleanup context.Context) *ordinaryQEMUJoinMemory {
	return &ordinaryQEMUJoinMemory{q: &originalOrdinaryQEMULifetime{
		cleanup: cleanup, waitStarted: true, readersStarted: true,
		waitDone: make(chan struct{}), stdoutDone: make(chan error, 1),
		stderrDone: make(chan error, 1), joinDone: make(chan struct{}),
	}}
}
func (m *ordinaryQEMUJoinMemory) wait(cause error) {
	m.waitOnce.Do(func() { m.q.waitCause = cause; close(m.q.waitDone) })
}
func (m *ordinaryQEMUJoinMemory) stdout(cause error) {
	m.stdoutOnce.Do(func() { m.q.stdoutDone <- cause })
}
func (m *ordinaryQEMUJoinMemory) stderr(cause error) {
	m.stderrOnce.Do(func() { m.q.stderrDone <- cause })
}
func (m *ordinaryQEMUJoinMemory) finish() { m.wait(nil); m.stdout(nil); m.stderr(nil) }
func ordinaryQEMUJoinMemoryContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	t.Cleanup(cancel)
	return ctx
}
func ordinaryQEMUJoinMemoryDone(t *testing.T, q *originalOrdinaryQEMULifetime) {
	t.Helper()
	select {
	case <-q.joinDone:
	case <-time.After(time.Second):
		t.Fatal("memory completion owner did not retain original returns")
	}
}

// An intentionally lagging Done channel exercises the absolute-bound check;
// this fixture context is never an installed Source capability.
type ordinaryQEMUJoinDeadlineOnly struct {
	context.Context
	bound time.Time
}

func (c ordinaryQEMUJoinDeadlineOnly) Deadline() (time.Time, bool) { return c.bound, true }

type ordinaryQEMUJoinObservedContext struct {
	context.Context
	seen chan struct{}
	once sync.Once
}

func (c *ordinaryQEMUJoinObservedContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.seen) })
	return c.Context.Done()
}

func TestOriginalOrdinaryQEMUBoundedJoinOriginalBounds(t *testing.T) {
	for _, name := range []string{"caller_cancelled", "cleanup_cancelled", "caller_expired_without_done", "cleanup_expired_without_done", "caller_missing_deadline", "cleanup_missing_deadline", "caller_nil", "cleanup_nil"} {
		t.Run(name, func(t *testing.T) {
			original := ordinaryQEMUJoinMemoryContext(t)
			cleanup, caller := original, original
			cancelled, cancel := context.WithCancel(original)
			cancel()
			expired := ordinaryQEMUJoinDeadlineOnly{Context: context.Background(), bound: time.Now().Add(-time.Second)}
			switch name {
			case "caller_cancelled":
				caller = cancelled
			case "cleanup_cancelled":
				cleanup = cancelled
			case "caller_expired_without_done":
				caller = expired
			case "cleanup_expired_without_done":
				cleanup = expired
			case "caller_missing_deadline":
				caller = context.Background()
			case "cleanup_missing_deadline":
				cleanup = context.Background()
			case "caller_nil":
				caller = nil
			case "cleanup_nil":
				cleanup = nil
			}
			m := newOrdinaryQEMUJoinMemory(cleanup)
			if m.q.closeAndJoin(caller) == nil {
				t.Fatal("unknown/expired context joined pending owners")
			}
			select {
			case <-m.q.waitDone:
				t.Fatal("timeout manufactured original Wait return")
			default:
			}
			select {
			case <-m.q.joinDone:
				t.Fatal("once-init manufactured completion")
			default:
			}
			late := errors.New("literal late memory Wait cause")
			m.wait(late)
			m.stdout(io.EOF)
			m.stderr(nil)
			if m.q.joinOwnerStarted {
				ordinaryQEMUJoinMemoryDone(t, m.q)
				if m.q.closeAndJoin(original) == nil || !errors.Is(m.q.joinedCause(), late) || !errors.Is(m.q.joinedCause(), io.EOF) {
					t.Fatal("late original causes lost or prior HOLD erased")
				}
			}
		})
	}
}

func TestOriginalOrdinaryQEMUBoundedJoinKnownCompletion(t *testing.T) {
	for _, name := range []string{"all_known_nil_memory_only", "wait_error", "stdout_error", "stderr_error", "literal_eof_error_retained", "partial_reader_error"} {
		t.Run(name, func(t *testing.T) {
			ctx := ordinaryQEMUJoinMemoryContext(t)
			m := newOrdinaryQEMUJoinMemory(ctx)
			var waitCause, stdoutCause, stderrCause error
			literal := errors.New("same original memory return")
			switch name {
			case "wait_error":
				waitCause = literal
			case "stdout_error", "partial_reader_error":
				stdoutCause = literal
			case "stderr_error":
				stderrCause = literal
			case "literal_eof_error_retained":
				stdoutCause = io.EOF
				literal = io.EOF
			}
			m.wait(waitCause)
			m.stdout(stdoutCause)
			m.stderr(stderrCause)
			done := m.q.joinDone
			for n := 0; n < 2; n++ {
				cause := m.q.closeAndJoin(ctx)
				if (cause == nil) != (name == "all_known_nil_memory_only") || cause != nil && !errors.Is(cause, literal) {
					t.Fatal("known memory causes replaced or completion replay consumed channels again")
				}
			}
			if m.q.joinDone != done || m.q.joinCompletedAt.IsZero() || !m.q.waitJoined || !m.q.stdoutJoined || !m.q.stderrJoined || len(m.q.stdoutDone) != 0 || len(m.q.stderrDone) != 0 {
				t.Fatal("same completion owner/channels not retained")
			}
			if m.q.cmd != nil || m.q.audit != nil || m.q.stdio != nil || len(m.q.fallbackReturns) != 0 {
				t.Fatal("memory join acquired a process/Source return")
			}
		})
	}
}

func TestOriginalOrdinaryQEMUBoundedJoinPendingOwner(t *testing.T) {
	for _, name := range []string{"wait_pending_not_signal_success", "stdout_pending", "stderr_pending", "all_pending"} {
		t.Run(name, func(t *testing.T) {
			cleanup := ordinaryQEMUJoinMemoryContext(t)
			caller, cancel := context.WithCancel(cleanup)
			defer cancel()
			observed := &ordinaryQEMUJoinObservedContext{Context: caller, seen: make(chan struct{})}
			m := newOrdinaryQEMUJoinMemory(cleanup)
			defer m.finish()
			literal := errors.New("literal already returned reader")
			if name != "wait_pending_not_signal_success" && name != "all_pending" {
				m.wait(nil)
			}
			if name != "stdout_pending" && name != "all_pending" {
				m.stdout(literal)
			}
			if name != "stderr_pending" && name != "all_pending" {
				m.stderr(literal)
			}
			returned := make(chan error, 1)
			go func() { returned <- m.q.closeAndJoin(observed) }()
			select {
			case <-observed.seen:
			case <-time.After(time.Second):
				t.Fatal("production join did not observe original caller")
			}
			cancel()
			select {
			case cause := <-returned:
				if cause == nil {
					t.Fatal("pending owner became nil join")
				}
			case <-time.After(time.Second):
				t.Fatal("join blocked beyond caller cancellation")
			}
			select {
			case <-m.q.joinDone:
				t.Fatal("pending owner marked complete")
			default:
			}
			m.finish()
			ordinaryQEMUJoinMemoryDone(t, m.q)
			if m.q.closeAndJoin(cleanup) == nil {
				t.Fatal("later original returns renewed failed join")
			}
			if name != "all_pending" && !errors.Is(m.q.joinedCause(), literal) {
				t.Fatal("already returned reader cause dropped")
			}
		})
	}
}

func TestOriginalOrdinaryQEMUBoundedJoinConcurrentNarrowerCaller(t *testing.T) {
	cleanup := ordinaryQEMUJoinMemoryContext(t)
	first, stop := context.WithCancel(cleanup)
	defer stop()
	observed := &ordinaryQEMUJoinObservedContext{Context: first, seen: make(chan struct{})}
	m := newOrdinaryQEMUJoinMemory(cleanup)
	defer m.finish()
	firstReturn := make(chan error, 1)
	go func() { firstReturn <- m.q.closeAndJoin(observed) }()
	select {
	case <-observed.seen:
	case <-time.After(time.Second):
		t.Fatal("first owner not installed")
	}
	narrow, cancel := context.WithCancel(cleanup)
	cancel()
	secondReturn := make(chan error, 1)
	go func() { secondReturn <- m.q.closeAndJoin(narrow) }()
	select {
	case cause := <-secondReturn:
		if cause == nil {
			t.Fatal("narrow caller ignored cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("second caller blocked behind closeOnce pending owner")
	}
	stop()
	select {
	case cause := <-firstReturn:
		if cause == nil {
			t.Fatal("pending first caller succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("first join stuck")
	}
	// Replay while the original channels remain pending must return the
	// retained HOLD, not start another wait under a later caller bound.
	repeated := make(chan error, 1)
	go func() { repeated <- m.q.closeAndJoin(cleanup) }()
	select {
	case cause := <-repeated:
		if cause == nil {
			t.Fatal("pending replay erased original refusal")
		}
	case <-time.After(time.Second):
		t.Fatal("replay renewed pending join horizon")
	}
	select {
	case <-m.q.joinDone:
		t.Fatal("replay manufactured completion")
	default:
	}
	m.finish()
	ordinaryQEMUJoinMemoryDone(t, m.q)
	done, completed := m.q.joinDone, m.q.joinCompletedAt
	if m.q.closeAndJoin(cleanup) == nil || m.q.joinDone != done || !m.q.joinCompletedAt.Equal(completed) {
		t.Fatal("repeat reset owner or sticky refusal")
	}
}

func TestOriginalOrdinaryQEMUBoundedJoinClosedChannel(t *testing.T) {
	for _, name := range []string{"buffered_return_then_close", "empty_reader_close_unknown", "missing_wait_channel_unknown", "missing_join_channel_unknown"} {
		t.Run(name, func(t *testing.T) {
			ctx := ordinaryQEMUJoinMemoryContext(t)
			m := newOrdinaryQEMUJoinMemory(ctx)
			if name == "missing_wait_channel_unknown" || name == "missing_join_channel_unknown" {
				if name == "missing_wait_channel_unknown" {
					m.q.waitDone = nil
				} else {
					m.q.joinDone = nil
				}
				if m.q.closeAndJoin(ctx) == nil || m.q.joinOwnerStarted {
					t.Fatal("missing owned channel installed completion")
				}
				select {
				case <-m.q.joinDone:
					t.Fatal("unknown channel closed join")
				default:
				}
				return
			}
			m.wait(nil)
			m.stderr(nil)
			if name == "buffered_return_then_close" {
				m.stdout(nil)
			}
			close(m.q.stdoutDone)
			// Direct production owner call keeps this invalid-channel case
			// deterministic without a process or a test-only production hook.
			m.q.joinOriginalReturns(ctx)
			if name == "buffered_return_then_close" {
				select {
				case <-m.q.joinDone:
				default:
					t.Fatal("known buffered return lost")
				}
				if m.q.joinedCause() != nil || !m.q.stdoutJoined {
					t.Fatal("closed channel erased known return")
				}
			} else {
				select {
				case <-m.q.joinDone:
					t.Fatal("empty closed reader manufactured return")
				default:
				}
				if m.q.joinedCause() == nil || m.q.stdoutJoined || !m.q.joinCompletedAt.IsZero() {
					t.Fatal("unknown completion promoted")
				}
			}
		})
	}
}

func TestOriginalOrdinaryQEMUBoundedJoinDeadlineTimerLag(t *testing.T) {
	for _, name := range []string{"caller_deadline", "cleanup_deadline"} {
		t.Run(name, func(t *testing.T) {
			original := ordinaryQEMUJoinMemoryContext(t)
			bound := time.Now().Add(10 * time.Millisecond)
			lagging := ordinaryQEMUJoinDeadlineOnly{Context: context.Background(), bound: bound}
			cleanup, caller := original, context.Context(lagging)
			if name == "cleanup_deadline" {
				cleanup, caller = lagging, original
			}
			m := newOrdinaryQEMUJoinMemory(cleanup)
			defer m.finish()
			returned := make(chan error, 1)
			go func() { returned <- m.q.closeAndJoin(caller) }()
			select {
			case cause := <-returned:
				if cause == nil || time.Now().Before(bound) {
					t.Fatal("pending owner joined before real original bound")
				}
			case <-time.After(time.Second):
				t.Fatal("lagging Done hid original absolute bound")
			}
			select {
			case <-m.q.joinDone:
				t.Fatal("deadline was treated as completion")
			default:
			}
			m.finish()
			ordinaryQEMUJoinMemoryDone(t, m.q)
			if m.q.closeAndJoin(original) == nil || m.q.joinCompletedAt.Before(bound) {
				t.Fatal("late return renewed deadline")
			}
		})
	}
}

func TestOriginalOrdinaryQEMUBoundedJoinReadyAndBoundary(t *testing.T) {
	for _, name := range []string{"ready_returns_expired_caller", "equal_caller_bound", "equal_cleanup_bound"} {
		t.Run(name, func(t *testing.T) {
			ctx := ordinaryQEMUJoinMemoryContext(t)
			if name == "ready_returns_expired_caller" {
				m := newOrdinaryQEMUJoinMemory(ctx)
				m.finish()
				expired := ordinaryQEMUJoinDeadlineOnly{Context: context.Background(), bound: time.Now().Add(-time.Second)}
				if m.q.closeAndJoin(expired) == nil {
					t.Fatal("ready channels bypassed expired original caller")
				}
				ordinaryQEMUJoinMemoryDone(t, m.q)
				if m.q.closeAndJoin(ctx) == nil {
					t.Fatal("ready late join erased HOLD")
				}
				return
			}
			bound := time.Now().Add(time.Second)
			exact := ordinaryQEMUJoinDeadlineOnly{Context: context.Background(), bound: bound}
			cleanup, caller := ctx, context.Context(exact)
			if name == "equal_cleanup_bound" {
				cleanup, caller = exact, ctx
			}
			if _, e := ordinaryOriginalQEMUJoinDeadline(cleanup, caller, bound); e == nil {
				t.Fatal("deadline equality accepted")
			}
		})
	}
}

// Source assembly input: native_parent_current_reader_capture_source_test_fragment.go
// These are Source custody/chronology cases. Struct fixtures do not establish
// native observations, actual installation, SQL-FIRST or admission permission.
func TestOriginalParentCurrentAnchorDescriptorJoin(t *testing.T) {
	fixture := func() (model.HostFactoryPrimitiveIOReturn, model.HostFactoryPrimitiveIOReturn, model.HostFactoryBootstrapDescriptorSource) {
		expected := model.HostFactoryBootstrapDescriptorSource{Device: 8, Inode: 19, Type: "directory", Mode: unix.S_IFDIR | 0700, LinkCount: 2, UID: 1000, GID: 1001}
		open := model.HostFactoryPrimitiveIOReturn{OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "unix_openat", RequestedFlags: ptr(uint32(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC)), RequestedMode: ptr(uint32(0)), OriginalScalar: ptr(int64(71)), ReturnedDescriptors: []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: "original-held", OriginalDescriptorNumber: 71}}}}
		stat := model.HostFactoryPrimitiveIOReturn{OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "unix_fstat", InputDescriptorNumber: ptr(71), OriginalStat: &model.HostFactoryNativeStatReturn{Device: 8, Inode: 19, Mode: unix.S_IFDIR | 0700, LinkCount: 2, UID: 1000, GID: 1001, Size: 4096}}}
		return open, stat, expected
	}
	open, stat, expected := fixture()
	if err := parentCurrentCaptureOpenStat(open, stat, "original-held", "unix_openat", expected); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*model.HostFactoryPrimitiveIOReturn, *model.HostFactoryPrimitiveIOReturn, *model.HostFactoryBootstrapDescriptorSource)
	}{
		{"open_missing", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			o.OriginalNativeReturn = nil
		}},
		{"stat_missing", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			s.OriginalNativeReturn = nil
		}},
		{"open_kind", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			o.OriginalNativeReturn.Kind = "unix_open"
		}},
		{"flags_missing", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			o.OriginalNativeReturn.RequestedFlags = nil
		}},
		{"nofollow_missing", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			*o.OriginalNativeReturn.RequestedFlags &^= unix.O_NOFOLLOW
		}},
		{"mode_unknown", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			o.OriginalNativeReturn.RequestedMode = nil
		}},
		{"mode_changed", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			*o.OriginalNativeReturn.RequestedMode = 0700
		}},
		{"extra_descriptor", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			o.OriginalNativeReturn.ReturnedDescriptors = append(o.OriginalNativeReturn.ReturnedDescriptors, o.OriginalNativeReturn.ReturnedDescriptors[0])
		}},
		{"other_handle", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			o.OriginalNativeReturn.ReturnedDescriptors[0].OriginalHandleID = "earlier-closed-root"
		}},
		{"negative_descriptor", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			o.OriginalNativeReturn.ReturnedDescriptors[0].OriginalDescriptorNumber = -1
		}},
		{"scalar_missing", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			o.OriginalNativeReturn.OriginalScalar = nil
		}},
		{"scalar_other_descriptor", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			*o.OriginalNativeReturn.OriginalScalar = 72
		}},
		{"stat_wrong_descriptor", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			*s.OriginalNativeReturn.InputDescriptorNumber = 72
		}},
		{"stat_unknown", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			s.OriginalNativeReturn.OriginalStat = nil
		}},
		{"device", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			s.OriginalNativeReturn.OriginalStat.Device++
		}},
		{"inode", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			s.OriginalNativeReturn.OriginalStat.Inode++
		}},
		{"mode", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			s.OriginalNativeReturn.OriginalStat.Mode |= 0004
		}},
		{"type", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			s.OriginalNativeReturn.OriginalStat.Mode = unix.S_IFREG | 0700
			e.Mode = s.OriginalNativeReturn.OriginalStat.Mode
		}},
		{"link_count", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			s.OriginalNativeReturn.OriginalStat.LinkCount++
		}},
		{"uid", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			s.OriginalNativeReturn.OriginalStat.UID++
		}},
		{"gid", func(o, s *model.HostFactoryPrimitiveIOReturn, e *model.HostFactoryBootstrapDescriptorSource) {
			s.OriginalNativeReturn.OriginalStat.GID++
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, s, e := fixture()
			tc.mutate(&o, &s, &e)
			if parentCurrentCaptureOpenStat(o, s, "original-held", "unix_openat", e) == nil {
				t.Fatal("accepted changed original descriptor/stat join")
			}
		})
	}
	// Directory size can change as the genuine owners publish their files.
	// It is not the immutable physical identity comparator in this contract.
	stat.OriginalNativeReturn.OriginalStat.Size = 8192
	if err := parentCurrentCaptureOpenStat(open, stat, "original-held", "unix_openat", expected); err != nil {
		t.Fatal(err)
	}
	open.OriginalNativeReturn.Kind = "unix_open"
	if err := parentCurrentCaptureOpenStat(open, stat, "original-held", "unix_open", expected); err != nil {
		t.Fatal(err)
	}
}

func TestOriginalParentCurrentOwningReturnChronology(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	defer cancel()
	d, _ := ctx.Deadline()
	now := time.Now().UTC()
	x := &controlCurrentAdmission{ctx: ctx, publisher: &originalNativePublisher{ledger: &originalLedger{ctx: ctx, deadline: d}}, journal: currentOriginalFactoryOwnerJournal{OriginalEffectivePhaseDeadline: d}}
	previous := now.Add(-6 * time.Second)
	value := controlCurrentSourceReturn{"control_retain_original_factory_prepared", "owner", "host_exterior", now.Add(-5 * time.Second), now.Add(-4 * time.Second), d, "returned", false}
	if err := parentCurrentCaptureReturned(value, value.Operation, "owner", x, previous); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*controlCurrentSourceReturn)
	}{
		{"internal_marker_operation", func(v *controlCurrentSourceReturn) { v.Operation = "read_original_parent_worker_frame" }},
		{"other_owner", func(v *controlCurrentSourceReturn) { v.OriginalOwnerID = "registrar" }},
		{"other_role", func(v *controlCurrentSourceReturn) { v.OriginalOwnerRole = "host_registrar" }},
		{"pending", func(v *controlCurrentSourceReturn) { v.OriginalState = "called_pending" }},
		{"literal_error", func(v *controlCurrentSourceReturn) { v.OriginalErrorPresent = true }},
		{"unknown_return", func(v *controlCurrentSourceReturn) { v.OriginalReturnedAt = time.Time{} }},
		{"unknown_called", func(v *controlCurrentSourceReturn) { v.OriginalCalledAt = time.Time{} }},
		{"return_before_call", func(v *controlCurrentSourceReturn) { v.OriginalReturnedAt = v.OriginalCalledAt.Add(-time.Nanosecond) }},
		{"call_before_previous_owner_return", func(v *controlCurrentSourceReturn) { v.OriginalCalledAt = previous.Add(-time.Nanosecond) }},
		{"different_bound", func(v *controlCurrentSourceReturn) { v.OriginalContextDeadline = d.Add(time.Second) }},
		{"return_at_bound", func(v *controlCurrentSourceReturn) { v.OriginalReturnedAt = d }},
		{"return_after_bound", func(v *controlCurrentSourceReturn) { v.OriginalReturnedAt = d.Add(time.Nanosecond) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := value
			tc.mutate(&v)
			if parentCurrentCaptureReturned(v, value.Operation, "owner", x, previous) == nil {
				t.Fatal("accepted invalid owning GoReturn")
			}
		})
	}
	if parentCurrentCaptureReturned(value, value.Operation, "owner", x, time.Time{}) == nil {
		t.Fatal("accepted unknown predecessor")
	}
	cancel()
	if parentCurrentCaptureReturned(value, value.Operation, "owner", x, previous) == nil {
		t.Fatal("accepted canceled original context")
	}
}

func TestOriginalParentCurrentReaderAttemptStaysConsumed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	x := &controlCurrentAdmission{ctx: ctx}
	r := &OriginalFactoryRealm{control: &originalControl{currentAdmission: x}}
	cancel()
	first := controlCaptureOriginalCurrentLedgerReaderReport(ctx, r)
	if first == nil || !x.readerReportAttempted || x.readerReportCause == nil || len(x.postStartCustodyRaw) != 0 || x.readerReportAudit != nil || x.readerReportHandle != nil {
		t.Fatal("failed attempt lost reservation or installed custody")
	}
	cause := x.readerReportCause
	second := controlCaptureOriginalCurrentLedgerReaderReport(context.Background(), r)
	if second == nil || !errors.Is(x.readerReportCause, cause) || !reflect.DeepEqual(x.postStartCustodyRaw, []byte(nil)) {
		t.Fatal("new context replaced failed attempt")
	}
}

func TestOriginalParentCurrentHeldFlagsUseOriginalOperationKind(t *testing.T) {
	for _, original := range []struct {
		operation string
		command   int
		expected  uint32
	}{{"fcntl_getfl", unix.F_GETFL, uint32(unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NONBLOCK)}, {"fcntl_getfd", unix.F_GETFD, unix.FD_CLOEXEC}} {
		fixture := func() model.HostFactoryPrimitiveIOReturn {
			return model.HostFactoryPrimitiveIOReturn{Operation: original.operation, OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: original.operation, InputDescriptorNumber: ptr(71), RequestedFcntlCommand: ptr(original.command), RequestedArgument: ptr(int64(0)), OriginalScalar: ptr(int64(original.expected))}}
		}
		t.Run(original.operation+"_actual_producer_kind", func(t *testing.T) {
			if err := parentCurrentCaptureFlag(fixture(), 71, original.operation, original.command, original.expected); err != nil {
				t.Fatal(err)
			}
		})
		for _, tc := range []struct {
			name   string
			mutate func(*model.HostFactoryPrimitiveIOReturn)
		}{
			{"generic_unix_fcntl_is_not_original", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalNativeReturn.Kind = "unix_fcntl" }},
			{"other_get_kind", func(f *model.HostFactoryPrimitiveIOReturn) {
				if original.operation == "fcntl_getfl" {
					f.OriginalNativeReturn.Kind = "fcntl_getfd"
				} else {
					f.OriginalNativeReturn.Kind = "fcntl_getfl"
				}
			}},
			{"other_operation", func(f *model.HostFactoryPrimitiveIOReturn) { f.Operation = "fcntl_other" }},
			{"unknown_native_return", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalNativeReturn = nil }},
			{"descriptor_missing", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalNativeReturn.InputDescriptorNumber = nil }},
			{"descriptor_changed", func(f *model.HostFactoryPrimitiveIOReturn) { *f.OriginalNativeReturn.InputDescriptorNumber = 72 }},
			{"command_missing", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalNativeReturn.RequestedFcntlCommand = nil }},
			{"command_changed", func(f *model.HostFactoryPrimitiveIOReturn) { *f.OriginalNativeReturn.RequestedFcntlCommand = -1 }},
			{"argument_missing", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalNativeReturn.RequestedArgument = nil }},
			{"argument_changed", func(f *model.HostFactoryPrimitiveIOReturn) { *f.OriginalNativeReturn.RequestedArgument = 1 }},
			{"scalar_missing", func(f *model.HostFactoryPrimitiveIOReturn) { f.OriginalNativeReturn.OriginalScalar = nil }},
			{"scalar_changed", func(f *model.HostFactoryPrimitiveIOReturn) { *f.OriginalNativeReturn.OriginalScalar++ }},
		} {
			t.Run(original.operation+"_"+tc.name, func(t *testing.T) {
				f := fixture()
				tc.mutate(&f)
				if parentCurrentCaptureFlag(f, 71, original.operation, original.command, original.expected) == nil {
					t.Fatal("changed original flags accepted")
				}
			})
		}
	}
}

// Source assembly input: native_parent_current_reader_report_auth_source_test_fragment.go
// All fixtures below are synthetic Source codec/selection inputs. They do not
// install compiledInstallations, execute IO, create native facts or prove FIRST.
func parentCurrentReportTestFixture(t *testing.T) (originalCurrentLedgerReaderReport, *originalNativePhaseReservation, model.HostFactoryBasalOwnerObservation, model.HostFactoryOriginalEmptyRealmRead, [2]int, string) {
	t.Helper()
	origin := time.Date(2100, 1, 2, 3, 4, 5, 0, time.UTC)
	bound := origin.Add(time.Hour)
	ctx, cancel := context.WithDeadline(context.Background(), bound)
	t.Cleanup(cancel)
	root := "00000000-0000-4000-8000-000000000001"
	request := "00000000-0000-4000-8000-000000000002"
	owner := "00000000-0000-4000-8000-000000000003"
	sha := strings.Repeat("1", 64)
	approval := strings.Repeat("2", 64)
	r := originalCurrentLedgerReaderReport{Schema: "source_private_original_current_ledger_reader_report_v2", FactoryRootID: root, RequestID: request, RegistrarOwnerID: owner, RegistrarBasalSHA256: sha, ScopeBodySHA256: strings.Repeat("3", 64), CurrentJournalSHA256: strings.Repeat("4", 64), AggregateBodySHA256: strings.Repeat("5", 64), AggregateEnvelopeSHA256: strings.Repeat("6", 64), OriginalSourceAuditProjections: []originalSourceAuditProjection{}}
	phase := &originalNativePhaseReservation{ctx: ctx, requestID: request, factoryRoot: root, calledAt: origin}
	basal := model.HostFactoryBasalOwnerObservation{FactoryRootID: root, OriginalOwnerID: owner, Role: "host_registrar", OriginalContextStartedAt: origin.Add(-time.Hour), OriginalContextDeadline: bound.Add(time.Hour)}
	anchor := "00000000-0000-4000-8000-000000000010"
	native := "00000000-0000-4000-8000-000000000011"
	r.OriginalActorNativeRootAnchor = originalCurrentNativeRootAnchor{OriginalHandleID: native, OriginalInventoryBodySHA256: sha, OriginalInventoryEnvelopeSHA256: approval, OriginalAcquisitionCallID: native + ":1", OriginalFstatCallID: native + ":2"}
	makeBlock := func(handle string, n int, start time.Time) (postStartSourceSelection, []originalSourceAuditProjection) {
		prefix := n < 0
		ops := []string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_read", "source_file_fstat", "source_file_close"}
		if prefix {
			ops = []string{"source_directory_open", "source_directory_fstat"}
		}
		s := postStartSourceSelection{OriginalSourceOwnerID: owner, OriginalSourceOwnerRole: "host_registrar", OriginalSourceBindingSchema: "original_host_factory_pre_authority_scope_v4", OriginalSourceBindingSHA256: r.ScopeBodySHA256, OriginalHandleID: handle, OriginalAnchorHandleID: ptr(anchor), OriginalCallReferences: []string{}, OriginalCloseCallID: ptr(handle + ":6"), OriginalStreamState: "closed_file"}
		d := bound
		if prefix {
			s.OriginalStreamState, s.OriginalAnchorHandleID, s.OriginalCloseCallID = "open_directory_prefix", nil, nil
			s.OriginalSourceBindingSchema, s.OriginalSourceBindingSHA256 = "original_host_factory_source_approval_v4", approval
			d = basal.OriginalContextDeadline
		}
		rows := []originalSourceAuditProjection{}
		for k, op := range ops {
			id := handle + ":" + string(rune('1'+k))
			called := start.Add(time.Duration(k*2) * time.Millisecond)
			returned := called.Add(time.Millisecond)
			f := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: root, OriginalAuditHandleID: handle, OriginalCallID: ptr(id), Operation: op, OriginalState: "returned", OriginalCalledAt: ptr(called), OriginalReturnedAt: ptr(returned), OriginalOperationDeadline: d, OriginalErrorPresent: ptr(false), OriginalHashState: "not_byte_operation"}
			if op == "source_file_read" {
				f.OriginalHashState, f.OriginalEOF, f.OriginalCount = "private_withheld", ptr(k == 3), ptr(int64(n))
				if k == 3 {
					f.OriginalCount, f.OriginalErrorPresent = ptr(int64(0)), ptr(true)
				}
			}
			rows = append(rows, originalSourceAuditProjection{Family: "source_audit", SubjectIdentity: originalSourceAuditSubject{SubjectKind: "source_file"}, Fact: f, OriginalCloseReference: mergeOriginalSourceAuditPointer(s.OriginalCloseCallID)})
			s.OriginalCallReferences = append(s.OriginalCallReferences, id)
		}
		return s, rows
	}
	var rows []originalSourceAuditProjection
	r.OriginalDirectoryPrefix, rows = makeBlock(anchor, -1, origin.Add(-time.Minute))
	r.OriginalSourceAuditProjections = append(r.OriginalSourceAuditProjections, rows...)
	expected := [2]int{13, 17}
	for k, handle := range []string{"00000000-0000-4000-8000-000000000020", "00000000-0000-4000-8000-000000000021", "00000000-0000-4000-8000-000000000022", "00000000-0000-4000-8000-000000000023"} {
		s, block := makeBlock(handle, expected[k%2], origin.Add(time.Duration(10+k*20)*time.Millisecond))
		if k < 2 {
			r.OriginalExpectedReaders[k] = s
		} else {
			r.OriginalFinalReaders[k-2] = s
		}
		r.OriginalSourceAuditProjections = append(r.OriginalSourceAuditProjections, block...)
	}
	last := r.OriginalSourceAuditProjections[len(r.OriginalSourceAuditProjections)-6:]
	aggregate := model.HostFactoryOriginalEmptyRealmRead{OriginalReadStartedAt: origin, OriginalReadReturnedAt: *last[3].Fact.OriginalReturnedAt, OriginalReadCloseReturnedAt: *last[5].Fact.OriginalReturnedAt, ObservedAt: *last[5].Fact.OriginalReturnedAt}
	return r, phase, basal, aggregate, expected, approval
}

func parentCurrentReportTestClone(t *testing.T, r originalCurrentLedgerReaderReport) originalCurrentLedgerReaderReport {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var clone originalCurrentLedgerReaderReport
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func parentCurrentReportTestEnvelope(t *testing.T, r originalCurrentLedgerReaderReport) (fixedInstallation, []byte, ed25519.PrivateKey) {
	t.Helper()
	// Synthetic cryptography is executed ONLY by owning remote Source CI.
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	i := fixedInstallation{keys: []approvedKey{{id: "synthetic-registrar", role: "host_registrar", public: key.Public().(ed25519.PublicKey)}}}
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	env := originalCurrentLedgerReaderEnvelope{Schema: "source_private_original_current_ledger_reader_envelope_v2", KeyID: "synthetic-registrar", Role: "host_registrar", ReportDomain: originalCurrentReaderDomain, ReportBodyBase64: base64.StdEncoding.EncodeToString(body), SignatureBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(key, originalCurrentReaderMessage(r, body)))}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return i, raw, key
}

func TestOriginalParentCurrentReaderReportSourceEnvelope(t *testing.T) {
	r, _, _, _, _, _ := parentCurrentReportTestFixture(t)
	i, raw, _ := parentCurrentReportTestEnvelope(t, r)
	t.Run("canonical-source-envelope-not-native-proof", func(t *testing.T) {
		got, body, err := parentCurrentReportDecode(i, raw)
		want, _ := json.Marshal(r)
		if err != nil || !reflect.DeepEqual(got, r) || !bytes.Equal(body, want) {
			t.Fatalf("synthetic Source codec refused: %v", err)
		}
		body[0] = '!'
		_, again, err := parentCurrentReportDecode(i, raw)
		if err != nil || !bytes.Equal(again, want) {
			t.Fatal("decoded original aliases returned buffer")
		}
	})
	mutations := []struct {
		name string
		edit func(*originalCurrentLedgerReaderEnvelope)
	}{
		{"wrong-schema", func(e *originalCurrentLedgerReaderEnvelope) { e.Schema += "x" }},
		{"wrong-domain", func(e *originalCurrentLedgerReaderEnvelope) { e.ReportDomain += "x" }},
		{"wrong-role", func(e *originalCurrentLedgerReaderEnvelope) { e.Role = "host_exterior" }},
		{"envelope-cannot-select-other-key", func(e *originalCurrentLedgerReaderEnvelope) { e.KeyID = "caller-key" }},
		{"invalid-signature", func(e *originalCurrentLedgerReaderEnvelope) {
			e.SignatureBase64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		}},
		{"signature-short", func(e *originalCurrentLedgerReaderEnvelope) { e.SignatureBase64 = "AA==" }},
		{"signature-base64-newline", func(e *originalCurrentLedgerReaderEnvelope) { e.SignatureBase64 += "\n" }},
		{"body-base64-newline", func(e *originalCurrentLedgerReaderEnvelope) { e.ReportBodyBase64 += "\n" }},
		{"body-empty", func(e *originalCurrentLedgerReaderEnvelope) { e.ReportBodyBase64 = "" }},
		{"body-unknown-field", func(e *originalCurrentLedgerReaderEnvelope) {
			b, _ := base64.StdEncoding.DecodeString(e.ReportBodyBase64)
			b = append([]byte(`{"unknown":0,`), b[1:]...)
			e.ReportBodyBase64 = base64.StdEncoding.EncodeToString(b)
		}},
		{"body-duplicate-field", func(e *originalCurrentLedgerReaderEnvelope) {
			b, _ := base64.StdEncoding.DecodeString(e.ReportBodyBase64)
			b = append([]byte(`{"schema":"duplicate",`), b[1:]...)
			e.ReportBodyBase64 = base64.StdEncoding.EncodeToString(b)
		}},
		{"body-noncanonical-whitespace", func(e *originalCurrentLedgerReaderEnvelope) {
			b, _ := base64.StdEncoding.DecodeString(e.ReportBodyBase64)
			e.ReportBodyBase64 = base64.StdEncoding.EncodeToString(append([]byte(" "), b...))
		}},
		{"signed-message-domain-not-reusable", func(e *originalCurrentLedgerReaderEnvelope) {
			b, _ := base64.StdEncoding.DecodeString(e.ReportBodyBase64)
			b = bytes.Replace(b, []byte(r.RequestID), []byte("00000000-0000-4000-8000-000000000099"), 1)
			e.ReportBodyBase64 = base64.StdEncoding.EncodeToString(b)
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			var env originalCurrentLedgerReaderEnvelope
			if err := json.Unmarshal(raw, &env); err != nil {
				t.Fatal(err)
			}
			test.edit(&env)
			bad, _ := json.Marshal(env)
			if _, body, err := parentCurrentReportDecode(i, bad); err == nil || body != nil {
				t.Fatal("unsafe Source envelope accepted")
			}
		})
	}
	t.Run("default-empty-installation-unavailable", func(t *testing.T) {
		if _, _, err := parentCurrentReportDecode(fixedInstallation{}, raw); err == nil {
			t.Fatal("empty catalog became trusted")
		}
	})
	t.Run("cross-role-key-alias-refused", func(t *testing.T) {
		bad := i
		bad.keys = append(append([]approvedKey{}, i.keys...), approvedKey{id: "alias", role: "host_exterior", public: bytes.Clone(i.keys[0].public)})
		if _, _, err := parentCurrentReportDecode(bad, raw); err == nil {
			t.Fatal("role key alias accepted")
		}
	})
	t.Run("outer-envelope-unknown-duplicate-and-noncanonical-refused", func(t *testing.T) {
		for _, bad := range [][]byte{append([]byte(`{"public_key":"caller",`), raw[1:]...), append([]byte(`{"role":"host_registrar",`), raw[1:]...), append([]byte(" "), raw...)} {
			if _, _, err := parentCurrentReportDecode(i, bad); err == nil {
				t.Fatal("outer shape accepted")
			}
		}
	})
	t.Run("empty-and-cap-plus-one-refused-before-decode", func(t *testing.T) {
		for _, bad := range [][]byte{nil, bytes.Repeat([]byte{' '}, bodyLimit+1)} {
			if _, _, err := parentCurrentReportDecode(i, bad); err == nil {
				t.Fatal("invalid bounded wire accepted")
			}
		}
	})
	for _, test := range []struct {
		name string
		edit func(*originalCurrentLedgerReaderReport)
	}{
		{"signed-wrong-report-schema", func(r *originalCurrentLedgerReaderReport) { r.Schema += "x" }},
		{"signed-empty-factory-root", func(r *originalCurrentLedgerReaderReport) { r.FactoryRootID = "" }},
		{"signed-request-not-uuid", func(r *originalCurrentLedgerReaderReport) { r.RequestID = "caller-label" }},
		{"signed-owner-not-uuid", func(r *originalCurrentLedgerReaderReport) { r.RegistrarOwnerID = "caller-label" }},
		{"signed-invalid-original-body-digest", func(r *originalCurrentLedgerReaderReport) { r.AggregateBodySHA256 = "unknown" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			bad := parentCurrentReportTestClone(t, r)
			test.edit(&bad)
			installation, wire, _ := parentCurrentReportTestEnvelope(t, bad)
			if _, _, err := parentCurrentReportDecode(installation, wire); err == nil {
				t.Fatal("valid signature bypassed closed report identity")
			}
		})
	}
}

func TestOriginalParentCurrentReaderReportSourceSelections(t *testing.T) {
	base, phase, basal, aggregate, expected, approval := parentCurrentReportTestFixture(t)
	t.Run("whole-private-eof-error-and-earlier-directory-deadline", func(t *testing.T) {
		if err := parentCurrentReportSelections(base, phase, basal, aggregate, expected, approval); err != nil {
			t.Fatalf("lawful synthetic Source sequence refused: %v", err)
		}
	})
	t.Run("actual-final-read-can-return-bytes-with-eof", func(t *testing.T) {
		r := parentCurrentReportTestClone(t, base)
		selection := &r.OriginalExpectedReaders[0]
		// Preserve the actual timestamps while replacing this synthetic reader
		// with a five-call source: its sole Read returns bytes AND literal EOF.
		rows := append([]originalSourceAuditProjection{}, r.OriginalSourceAuditProjections[2:4]...)
		rows = append(rows, r.OriginalSourceAuditProjections[5:8]...)
		selection.OriginalCallReferences = []string{}
		selection.OriginalCloseCallID = ptr(selection.OriginalHandleID + ":5")
		for n := range rows {
			id := selection.OriginalHandleID + ":" + string(rune('1'+n))
			selection.OriginalCallReferences = append(selection.OriginalCallReferences, id)
			rows[n].Fact.OriginalCallID = ptr(id)
			rows[n].OriginalCloseReference = ptr(*selection.OriginalCloseCallID)
		}
		rows[2].Fact.OriginalCount = ptr(int64(expected[0]))
		r.OriginalSourceAuditProjections = append(append(append([]originalSourceAuditProjection{}, r.OriginalSourceAuditProjections[:2]...), rows...), r.OriginalSourceAuditProjections[8:]...)
		if err := parentCurrentReportSelections(r, phase, basal, aggregate, expected, approval); err != nil {
			t.Fatalf("actual bytes+EOF incorrectly normalized/refused: %v", err)
		}
	})
	mutations := []struct {
		name string
		edit func(*originalCurrentLedgerReaderReport)
	}{
		{"nil-roster", func(r *originalCurrentLedgerReaderReport) { r.OriginalSourceAuditProjections = nil }},
		{"orphan-row", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections = append(r.OriginalSourceAuditProjections, r.OriginalSourceAuditProjections[0])
		}},
		{"duplicate-handle", func(r *originalCurrentLedgerReaderReport) { r.OriginalFinalReaders[0] = r.OriginalExpectedReaders[0] }},
		{"native-source-directory-alias", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalActorNativeRootAnchor.OriginalHandleID = r.OriginalDirectoryPrefix.OriginalHandleID
			r.OriginalActorNativeRootAnchor.OriginalAcquisitionCallID = r.OriginalDirectoryPrefix.OriginalHandleID + ":1"
			r.OriginalActorNativeRootAnchor.OriginalFstatCallID = r.OriginalDirectoryPrefix.OriginalHandleID + ":2"
		}},
		{"expected-final-order", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalExpectedReaders[0], r.OriginalExpectedReaders[1] = r.OriginalExpectedReaders[1], r.OriginalExpectedReaders[0]
		}},
		{"wrong-owner", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalFinalReaders[1].OriginalSourceOwnerID = r.RequestID
		}},
		{"wrong-role", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalFinalReaders[1].OriginalSourceOwnerRole = "host_exterior"
		}},
		{"wrong-scope-binding", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalFinalReaders[1].OriginalSourceBindingSHA256 = approval
		}},
		{"directory-rebound-to-scope", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalDirectoryPrefix.OriginalSourceBindingSchema = "original_host_factory_pre_authority_scope_v4"
		}},
		{"directory-foreign-approval", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalDirectoryPrefix.OriginalSourceBindingSHA256 = r.ScopeBodySHA256
		}},
		{"directory-future-close-backfilled", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalDirectoryPrefix.OriginalCloseCallID = ptr(r.OriginalDirectoryPrefix.OriginalHandleID + ":3")
		}},
		{"directory-anchor-not-null", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalDirectoryPrefix.OriginalAnchorHandleID = ptr(r.RequestID)
		}},
		{"directory-prefix-not-two", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalDirectoryPrefix.OriginalCallReferences = r.OriginalDirectoryPrefix.OriginalCallReferences[:1]
		}},
		{"file-wrong-anchor", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalExpectedReaders[0].OriginalAnchorHandleID = ptr(r.RequestID)
		}},
		{"file-close-null", func(r *originalCurrentLedgerReaderReport) { r.OriginalExpectedReaders[0].OriginalCloseCallID = nil }},
		{"file-pending-stream", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalExpectedReaders[0].OriginalStreamState = "pending"
		}},
		{"call-gap", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalExpectedReaders[0].OriginalCallReferences[2] = r.OriginalExpectedReaders[0].OriginalHandleID + ":9"
		}},
		{"wrong-factory-root", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[2].Fact.FactoryRootID = r.RequestID
		}},
		{"pending-original", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[2].Fact.OriginalState = "pending"
		}},
		{"missing-original-call", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[2].Fact.OriginalCallID = nil
		}},
		{"missing-original-return", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[2].Fact.OriginalReturnedAt = nil
		}},
		{"public-request-selector", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[2].SubjectIdentity.RequestIdentity = ptr("caller")
		}},
		{"private-read-hash-leak", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.OriginalSHA256 = ptr(r.ScopeBodySHA256)
		}},
		{"private-prefix-hash-leak", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.RetainedPrefixSHA256 = ptr(r.ScopeBodySHA256)
		}},
		{"private-prefix-count-leak", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.RetainedPrefixBytes = ptr(int64(1))
		}},
		{"private-read-scope-not-null", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.OriginalReadScope = ptr("complete_original_body_read")
		}},
		{"http-status-not-null", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.OriginalStatusCode = ptr(200)
		}},
		{"failure-code-not-null", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.FailureCode = ptr("storage_unknown")
		}},
		{"no-eof", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[5].Fact.OriginalEOF = ptr(false)
		}},
		{"eof-error-was-normalized", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[5].Fact.OriginalErrorPresent = ptr(false)
		}},
		{"partial-non-eof-error", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.OriginalErrorPresent = ptr(true)
		}},
		{"zero-progress-without-eof", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.OriginalCount = ptr(int64(0))
		}},
		{"count-short", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.OriginalCount = ptr(int64(expected[0] - 1))
		}},
		{"count-excess", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.OriginalCount = ptr(int64(expected[0] + 1))
		}},
		{"original-open-failed", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[2].Fact.OriginalErrorPresent = ptr(true)
		}},
		{"post-fstat-is-real", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[6].Fact.Operation = "source_file_sync"
		}},
		{"close-error", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[7].Fact.OriginalErrorPresent = ptr(true)
		}},
		{"close-reference-other-stream", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[7].OriginalCloseReference = ptr(r.OriginalFinalReaders[1].OriginalHandleID + ":6")
		}},
		{"phase-deadline-extended", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[4].Fact.OriginalOperationDeadline = r.OriginalSourceAuditProjections[4].Fact.OriginalOperationDeadline.Add(time.Nanosecond)
		}},
		{"late-original-return", func(r *originalCurrentLedgerReaderReport) {
			d, _ := phase.ctx.Deadline()
			r.OriginalSourceAuditProjections[4].Fact.OriginalReturnedAt = ptr(d)
		}},
		{"before-phase-original-call", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[2].Fact.OriginalCalledAt = ptr(phase.calledAt.Add(-time.Nanosecond))
		}},
		{"intra-stream-overlap", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[3].Fact.OriginalCalledAt = r.OriginalSourceAuditProjections[2].Fact.OriginalCalledAt
		}},
		{"cross-stream-overlap", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalSourceAuditProjections[8].Fact.OriginalCalledAt = r.OriginalSourceAuditProjections[6].Fact.OriginalReturnedAt
		}},
		{"native-anchor-call-is-not-uuid", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalActorNativeRootAnchor.OriginalAcquisitionCallID = r.OriginalActorNativeRootAnchor.OriginalHandleID
		}},
		{"native-anchor-fstat-not-second", func(r *originalCurrentLedgerReaderReport) {
			r.OriginalActorNativeRootAnchor.OriginalFstatCallID = r.OriginalActorNativeRootAnchor.OriginalHandleID + ":3"
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			r := parentCurrentReportTestClone(t, base)
			test.edit(&r)
			if err := parentCurrentReportSelections(r, phase, basal, aggregate, expected, approval); err == nil {
				t.Fatal("unsafe synthetic Source selection accepted")
			}
		})
	}
	t.Run("final-aggregate-endpoint-is-actual-control-close", func(t *testing.T) {
		bad := aggregate
		bad.OriginalReadCloseReturnedAt = bad.OriginalReadCloseReturnedAt.Add(time.Nanosecond)
		bad.ObservedAt = bad.OriginalReadCloseReturnedAt
		if err := parentCurrentReportSelections(base, phase, basal, bad, expected, approval); err == nil {
			t.Fatal("invented final close accepted")
		}
	})
	t.Run("final-aggregate-eof-is-original-last-read", func(t *testing.T) {
		bad := aggregate
		bad.OriginalReadReturnedAt = bad.OriginalReadReturnedAt.Add(time.Nanosecond)
		if err := parentCurrentReportSelections(base, phase, basal, bad, expected, approval); err == nil {
			t.Fatal("invented EOF time accepted")
		}
	})
	t.Run("nil-phase-refused", func(t *testing.T) {
		if err := parentCurrentReportSelections(base, nil, basal, aggregate, expected, approval); err == nil {
			t.Fatal("missing source phase accepted")
		}
	})
}

func TestOriginalParentCurrentReaderReportMissingSourceRefuses(t *testing.T) {
	t.Run("missing-source-does-not-authenticate-signed-json", func(t *testing.T) {
		r, _, _, _, _, _ := parentCurrentReportTestFixture(t)
		_, raw, _ := parentCurrentReportTestEnvelope(t, r)
		if _, body, err := authenticateOriginalParentCurrentReaderReport(context.Background(), nil, nil, raw); err == nil || body != nil {
			t.Fatal("JSON installed Source authority")
		}
	})
	t.Run("nil-context-does-not-renew-deadline", func(t *testing.T) {
		if _, body, err := authenticateOriginalParentCurrentReaderReport(nil, &originalNativePublisher{}, &controlCurrentAdmission{}, []byte(`{}`)); err == nil || body != nil {
			t.Fatal("missing original context accepted")
		}
	})
	t.Run("unbounded-context-does-not-mint-phase", func(t *testing.T) {
		p := &originalNativePublisher{}
		x := &controlCurrentAdmission{ctx: context.Background(), publisher: p}
		if _, body, err := authenticateOriginalParentCurrentReaderReport(x.ctx, p, x, []byte(`{}`)); err == nil || body != nil {
			t.Fatal("missing original phase accepted")
		}
	})
}

// Source assembly input: native_parent_worker_frame_kernel_source_test_fragment.go
// Synthetic memory fixture, not an authenticated family or native proof.
func parentWorkerFrameSourceFixture(t *testing.T) (*originalParentWorkerFrameRead, originalParentWorkerPublicFrameBasis) {
	t.Helper()
	deadline := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)
	profile := capacity.ProposedHostFactorySourceProfileV1()
	id := "11111111-1111-4111-8111-111111111111"
	l := &originalLedger{ctx: ctx, deadline: deadline, ownerRole: "host_exterior", bindingSchema: "original_host_factory_pre_authority_scope_v4", bindingSHA: strings.Repeat("a", 64), sourceProfile: profile, subjects: map[string]string{"host_worker": id}, handles: map[string]*callHandle{}, calls: map[string][]*retainedCall{}, collection: &OriginalIOCollection{sourceProfile: profile, bodies: map[string][]byte{}}}
	h := &callHandle{id: id, ledger: l}
	l.handles[id] = h
	started := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	phase := &originalNativePhaseReservation{ctx: ctx, name: "worker", calledAt: started}
	body := []byte(`{"synthetic":"public"}`)
	purposes, err := json.Marshal(capacity.HostFactorySourcePurposeSet{Schema: "source_host_factory_original_call_purposes_v1", OriginalBodySHA256: digest(body), OriginalCallPurposes: []capacity.HostFactorySourceCallPurpose{}})
	if err != nil {
		t.Fatal(err)
	}
	// A structurally valid all-zero signature is deliberately NOT authenticated.
	// This fixture exercises a Source-private projection after a synthetic basis.
	envelope, err := json.Marshal(capacity.HostFactorySourceSignedEnvelope{Schema: "source_host_factory_signed_envelope_v1", Purpose: "prepared-create-plan", KeyID: id, Role: "host_worker", PreAuthorityScopeSHA256: l.bindingSHA, SourceProfileSHA256: originalNativeSourceProfileManifestSHA, OriginalPurposeBase64: base64.StdEncoding.EncodeToString(purposes), BodyBase64: base64.StdEncoding.EncodeToString(body), SignatureBase64: base64.StdEncoding.EncodeToString(make([]byte, 64))})
	if err != nil {
		t.Fatal(err)
	}
	frame := originalWorkerSignedFrame{Schema: "source_private_original_worker_signed_frame_v1", Selector: "prepared-create-plan", EnvelopeRaw: envelope}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(raw)))
	read := &originalParentWorkerFrameRead{handle: h, ctx: ctx, phase: phase, prefix: prefix, raw: raw, calledAt: started.Add(time.Second), returnedAt: started.Add(9 * time.Second)}
	for n, data := range [][]byte{prefix, raw[:7], raw[7:]} {
		ordinal := uint64(n + 1)
		called := started.Add(time.Duration(2+n*2) * time.Second)
		returned := called.Add(time.Second)
		row := &retainedCall{subjectRole: "host_worker", stage: "worker_exterior_join", originalRaw: bytes.Clone(data), originalRawKnown: true, fact: model.HostFactoryPrimitiveIOReturn{Operation: "stdout_read", OriginalHandleID: id, OriginalCallID: ptr(id + ":" + strconv.Itoa(n+1)), OriginalCallOrdinal: &ordinal, SubjectOwnerID: id, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalCount: ptr(int64(len(data))), OriginalHashState: "unknown_original_bytes", OriginalReturnClass: "success", OriginalEOF: ptr(false), OriginalOperationDeadline: deadline}}
		read.rows = append(read.rows, row)
		l.calls[id+"\x00stdout_read"] = append(l.calls[id+"\x00stdout_read"], row)
	}
	h.parentWorkerFrameReads = []*originalParentWorkerFrameRead{read}
	return read, originalParentWorkerPublicFrameBasis{read: read, profile: profile, phase: phase, canonicalFrame: bytes.Clone(raw), selector: frame.Selector, body: body, envelope: envelope, effectiveContext: ctx, effectiveDeadline: deadline}
}

func parentWorkerFactsSource(t *testing.T, read *originalParentWorkerFrameRead) ([]byte, [][]byte) {
	t.Helper()
	facts := make([]model.HostFactoryPrimitiveIOReturn, len(read.rows))
	raw := make([][]byte, len(read.rows))
	for n, row := range read.rows {
		facts[n], raw[n] = row.fact, bytes.Clone(row.originalRaw)
	}
	b, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	return b, raw
}

func TestHostParentWorkerFrameProjectionSource(t *testing.T) {
	for _, name := range []string{"whole_atomic_projection", "nil_collection", "foreign_read", "foreign_phase", "wrong_phase_name", "foreign_context", "wrong_deadline", "missing_profile", "wrong_owner_role", "root_binding", "unknown_family", "changed_envelope", "changed_body", "noncanonical_frame", "duplicate_key", "omitted_key", "unknown_key", "prefix_mismatch", "failed_reader", "unknown_raw", "partial_count", "EOF_row", "real_cause", "wrong_operation", "wrong_stage", "foreign_subject", "foreign_row_pointer", "duplicate_membership", "duplicate_collector", "foreign_handle", "pending_row", "preexisting_hash", "first_published", "final_published", "pending_published", "collection_exposed", "return_after_helper", "return_before_call", "call_before_phase", "reordered_rows", "IO_chunk_frame_private", "IO_manifest_frame_private", "IO_inventory_frame_private"} {
		t.Run(name, func(t *testing.T) {
			read, basis := parentWorkerFrameSourceFixture(t)
			h, l, row := read.handle, read.handle.ledger, read.rows[1]
			switch name {
			case "nil_collection":
				l.collection = nil
			case "foreign_read":
				basis.read = &originalParentWorkerFrameRead{}
			case "foreign_phase":
				basis.phase = &originalNativePhaseReservation{}
			case "wrong_phase_name":
				read.phase.name = "registrar"
			case "foreign_context":
				basis.effectiveContext = context.Background()
			case "wrong_deadline":
				basis.effectiveDeadline = basis.effectiveDeadline.Add(-time.Second)
			case "missing_profile":
				basis.profile = nil
			case "wrong_owner_role":
				l.ownerRole = "host_worker"
			case "root_binding":
				l.bindingSchema = "original_host_factory_root_v4"
			case "unknown_family":
				basis.selector = "ordinary-prepared-create-plan"
			case "IO_chunk_frame_private", "IO_manifest_frame_private", "IO_inventory_frame_private":
				// Canonical whole frame and original raw rows stay internally
				// consistent. Only its IO family makes the synthetic basis
				// ineligible for public projection; no crypto is executed.
				kind := strings.TrimSuffix(strings.TrimPrefix(name, "IO_"), "_frame_private")
				basis.selector = "io-calls/11111111-1111-4111-8111-111111111111/" + kind + "/" + digest(basis.body)
				raw, err := json.Marshal(originalWorkerSignedFrame{Schema: "source_private_original_worker_signed_frame_v1", Selector: basis.selector, EnvelopeRaw: basis.envelope})
				if err != nil {
					t.Fatal(err)
				}
				read.raw, basis.canonicalFrame = raw, bytes.Clone(raw)
				binary.BigEndian.PutUint32(read.prefix, uint32(len(raw)))
				for n, data := range [][]byte{read.prefix, raw[:7], raw[7:]} {
					read.rows[n].originalRaw = bytes.Clone(data)
					read.rows[n].fact.OriginalCount = ptr(int64(len(data)))
				}
			case "changed_envelope":
				basis.envelope = []byte("synthetic-private")
			case "changed_body":
				basis.body = []byte("synthetic-private")
			case "noncanonical_frame":
				basis.canonicalFrame = append(basis.canonicalFrame, '\n')
			case "duplicate_key", "omitted_key", "unknown_key":
				if name == "duplicate_key" {
					read.raw = append([]byte(`{"schema":"other",`), read.raw[1:]...)
				}
				if name == "omitted_key" {
					read.raw = []byte(`{"schema":"source_private_original_worker_signed_frame_v1","selector":"prepared-create-plan"}`)
				}
				if name == "unknown_key" {
					read.raw = append([]byte(`{"private":true,`), read.raw[1:]...)
				}
				basis.canonicalFrame = bytes.Clone(read.raw)
				binary.BigEndian.PutUint32(read.prefix, uint32(len(read.raw)))
			case "prefix_mismatch":
				binary.BigEndian.PutUint32(read.prefix, uint32(len(read.raw)+1))
			case "failed_reader":
				read.cause = errors.New("synthetic partial")
			case "unknown_raw":
				row.originalRawKnown = false
			case "partial_count":
				row.fact.OriginalCount = ptr(int64(0))
			case "EOF_row":
				row.fact.OriginalEOF = ptr(true)
			case "real_cause":
				row.cause = io.EOF
			case "wrong_operation":
				row.fact.Operation = "control_frame_read"
			case "wrong_stage":
				row.stage = "prepared_create"
			case "foreign_subject":
				row.fact.SubjectOwnerID = "22222222-2222-4222-8222-222222222222"
			case "foreign_row_pointer":
				copy := *row
				l.calls[h.id+"\x00stdout_read"][1] = &copy
			case "duplicate_membership":
				l.calls[h.id+"\x00stdout_read"] = append(l.calls[h.id+"\x00stdout_read"], row)
			case "duplicate_collector":
				h.parentWorkerFrameReads = append(h.parentWorkerFrameReads, read)
			case "foreign_handle":
				l.handles[h.id] = &callHandle{}
			case "pending_row":
				row.fact.OriginalState = "called_pending"
			case "preexisting_hash":
				row.fact.OriginalSHA256 = ptr(strings.Repeat("b", 64))
			case "first_published":
				row.firstSHA = strings.Repeat("b", 64)
			case "final_published":
				row.finalSHA = strings.Repeat("b", 64)
			case "pending_published":
				row.pendingPublished = true
			case "collection_exposed":
				b, _ := json.Marshal(model.HostFactoryCallVectorChunk{OriginalCalls: []model.HostFactoryPrimitiveIOReturn{row.fact}})
				l.collection.bodies["synthetic"] = b
			case "return_after_helper":
				row.fact.OriginalReturnedAt = ptr(read.returnedAt.Add(time.Second))
			case "return_before_call":
				row.fact.OriginalReturnedAt = ptr(row.fact.OriginalCalledAt.Add(-time.Second))
			case "call_before_phase":
				row.fact.OriginalCalledAt = ptr(read.phase.calledAt.Add(-time.Second))
			case "reordered_rows":
				read.rows[1], read.rows[2] = read.rows[2], read.rows[1]
			}
			before, originals := parentWorkerFactsSource(t, read)
			err := projectOriginalParentWorkerFrame(read, basis)
			if (err == nil) != (name == "whole_atomic_projection") {
				t.Fatal("unexpected projection admission")
			}
			if err != nil {
				after, actual := parentWorkerFactsSource(t, read)
				if !bytes.Equal(before, after) || !reflect.DeepEqual(originals, actual) || read.classified {
					t.Fatal("refused projection mutated original custody")
				}
			} else {
				for n, r := range read.rows {
					if r.fact.OriginalSHA256 == nil || *r.fact.OriginalSHA256 != digest(originals[n]) || r.fact.OriginalHashState != "actual_public_bytes" || r.firstSHA != "" || r.finalSHA != "" || r.pendingPublished {
						t.Fatal("whole projection or publication boundary changed")
					}
				}
				if projectOriginalParentWorkerFrame(read, basis) == nil {
					t.Fatal("completed projection repeated")
				}
			}
		})
	}
}

// Real anonymous pipes only when CI executes these cases; no signature/native
// acceptance. The queued second frame must remain byte-exact for its own read.
func TestHostParentWorkerExactPipeSource(t *testing.T) {
	for _, name := range []string{"two_adjacent_frames", "empty_literal_EOF", "partial_prefix", "zero_length", "over_limit_length", "partial_payload", "exact_limit_payload", "closed_descriptor_error"} {
		t.Run(name, func(t *testing.T) {
			fixture, _ := parentWorkerFrameSourceFixture(t)
			h, phase := fixture.handle, fixture.phase
			phase.calledAt = time.Now().UTC()
			h.parentWorkerFrameReads = nil
			h.ledger.calls[h.id+"\x00stdout_read"] = nil
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			h.file, h.fd = r, int(r.Fd())
			var wire []byte
			add := func(raw []byte) {
				prefix := make([]byte, 4)
				binary.BigEndian.PutUint32(prefix, uint32(len(raw)))
				wire = append(wire, prefix...)
				wire = append(wire, raw...)
			}
			switch name {
			case "two_adjacent_frames":
				add([]byte("first"))
				add([]byte("second"))
			case "partial_prefix":
				wire = []byte{0, 0}
			case "zero_length":
				wire = make([]byte, 4)
			case "over_limit_length":
				wire = make([]byte, 4)
				binary.BigEndian.PutUint32(wire, bodyLimit+1)
			case "partial_payload":
				add([]byte("three"))
				wire = wire[:len(wire)-2]
			case "exact_limit_payload":
				add(bytes.Repeat([]byte{'x'}, bodyLimit))
			case "closed_descriptor_error":
				if err := r.Close(); err != nil {
					t.Fatal(err)
				}
			}
			writerDone := make(chan error, 1)
			go func() { _, e := w.Write(wire); writerDone <- errors.Join(e, w.Close()) }()
			read, readErr := readOriginalParentWorkerFrame(phase.ctx, h, phase)
			if name == "two_adjacent_frames" || name == "exact_limit_payload" {
				if readErr != nil {
					t.Fatal(readErr)
				}
				if name == "two_adjacent_frames" {
					second, e := readOriginalParentWorkerFrame(phase.ctx, h, phase)
					if e != nil || !bytes.Equal(read.raw, []byte("first")) || !bytes.Equal(second.raw, []byte("second")) {
						t.Fatal("read consumed adjacent frame bytes")
					}
				} else if len(read.raw) != bodyLimit {
					t.Fatal("exact cap refused or truncated")
				}
			} else if readErr == nil {
				t.Fatal("failed framing admitted")
			}
			if name == "empty_literal_EOF" {
				if readErr != io.EOF || len(read.rows) != 1 || !read.rows[0].originalRawKnown || len(read.rows[0].originalRaw) != 0 || read.rows[0].cause != io.EOF || read.rows[0].fact.OriginalEOF == nil || !*read.rows[0].fact.OriginalEOF {
					t.Fatal("literal EOF confused with unknown bytes")
				}
			}
			if name != "closed_descriptor_error" {
				if err := <-writerDone; err != nil {
					t.Fatal(err)
				}
			} else {
				<-writerDone
			}
			if read == nil || read.returnedAt.IsZero() || read.cause != readErr {
				t.Fatal("owning helper return missing")
			}
			for _, row := range read.rows {
				if row.fact.OriginalSHA256 != nil || row.fact.OriginalHashState != "unknown_original_bytes" || row.firstSHA != "" || row.finalSHA != "" || row.pendingPublished {
					t.Fatal("unauthenticated raw exposed")
				}
				if row.originalRawKnown && (row.fact.OriginalCount == nil || *row.fact.OriginalCount != int64(len(row.originalRaw))) {
					t.Fatal("actual partial count/raw lost")
				}
			}
		})
	}
}

func TestHostParentWorkerProjectionWaitSource(t *testing.T) {
	for _, name := range []string{"cancel_waiting_ledger", "expire_waiting_ledger", "cancel_waiting_collection", "expire_waiting_collection"} {
		t.Run(name, func(t *testing.T) {
			read, basis := parentWorkerFrameSourceFixture(t)
			h, l := read.handle, read.handle.ledger
			var ctx context.Context
			var cancel context.CancelFunc
			if strings.HasPrefix(name, "expire") {
				ctx, cancel = context.WithDeadline(read.ctx, time.Now().Add(2*time.Second))
			} else {
				ctx, cancel = context.WithCancel(read.ctx)
			}
			defer cancel()
			read.ctx, read.phase.ctx, basis.effectiveContext = ctx, ctx, ctx
			basis.effectiveDeadline, _ = ctx.Deadline()
			before, originals := parentWorkerFactsSource(t, read)
			unlock := l.mu.Unlock
			if strings.HasSuffix(name, "collection") {
				l.collection.mu.Lock()
				unlock = l.collection.mu.Unlock
			} else {
				l.mu.Lock()
			}
			locked := true
			defer func() {
				if locked {
					unlock()
				}
			}()
			done := make(chan error, 1)
			go func() { done <- projectOriginalParentWorkerFrame(read, basis) }()
			limit := time.Now().Add(5 * time.Second)
			for h.mu.TryLock() {
				h.mu.Unlock()
				if time.Now().After(limit) {
					t.Fatal("projector failed to reach held later lock")
				}
				runtime.Gosched()
			}
			if strings.HasPrefix(name, "expire") {
				<-ctx.Done()
			} else {
				cancel()
			}
			unlock()
			locked = false
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("waited cancellation/cutoff admitted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("projection stuck after unlock")
			}
			after, actual := parentWorkerFactsSource(t, read)
			if !bytes.Equal(before, after) || !reflect.DeepEqual(originals, actual) || read.classified {
				t.Fatal("refused lock barrier changed custody")
			}
		})
	}
}

// Observe the original real context's second Deadline read (the phase guard,
// after its Err check). It only records arrival; cancellation remains genuine.
type parentWorkerDeadlineArrivalSource struct {
	context.Context
	reads   atomic.Int32
	arrived chan struct{}
}

func (c *parentWorkerDeadlineArrivalSource) Deadline() (time.Time, bool) {
	d, ok := c.Context.Deadline()
	if c.reads.Add(1) == 2 {
		close(c.arrived)
	}
	return d, ok
}

func TestHostParentWorkerHandleWaitSource(t *testing.T) {
	for _, name := range []string{"cancel_with_handle_held", "expire_with_handle_held"} {
		t.Run(name, func(t *testing.T) {
			read, basis := parentWorkerFrameSourceFixture(t)
			var ctx context.Context
			var cancel context.CancelFunc
			if name == "expire_with_handle_held" {
				ctx, cancel = context.WithDeadline(read.ctx, time.Now().Add(2*time.Second))
			} else {
				ctx, cancel = context.WithCancel(read.ctx)
			}
			defer cancel()
			observed := &parentWorkerDeadlineArrivalSource{Context: ctx, arrived: make(chan struct{})}
			read.ctx, read.phase.ctx, basis.effectiveContext = observed, observed, observed
			basis.effectiveDeadline, _ = ctx.Deadline()
			before, originals := parentWorkerFactsSource(t, read)
			read.handle.mu.Lock()
			locked := true
			defer func() {
				if locked {
					read.handle.mu.Unlock()
				}
			}()
			done := make(chan error, 1)
			go func() { done <- projectOriginalParentWorkerFrame(read, basis) }()
			select {
			case <-observed.arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("initial phase guard never reached held handle barrier")
			}
			if name == "expire_with_handle_held" {
				<-ctx.Done()
			} else {
				cancel()
			}
			select {
			case <-done:
				t.Fatal("projector returned through held handle lock")
			default:
			}
			read.handle.mu.Unlock()
			locked = false
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("handle barrier cancellation admitted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("handle barrier stuck")
			}
			after, actual := parentWorkerFactsSource(t, read)
			if !bytes.Equal(before, after) || !reflect.DeepEqual(originals, actual) || read.classified {
				t.Fatal("handle wait changed original custody")
			}
		})
	}
}

// The fixed guard calls the ledger Err three times before begin's ledger-only
// admission reads it a fourth time. Observe that actual admission boundary;
// never supply cancellation or outputs through a production callback.
type parentWorkerBeginArrivalSource struct {
	context.Context
	reads   atomic.Int32
	arrived chan struct{}
}

func (c *parentWorkerBeginArrivalSource) Err() error {
	err := c.Context.Err()
	if c.reads.Add(1) == 4 {
		close(c.arrived)
	}
	return err
}

func TestHostParentWorkerBeginWaitDispatchSource(t *testing.T) {
	for _, name := range []string{"cancel_phase_during_begin_handle_wait", "expire_phase_during_begin_handle_wait"} {
		t.Run(name, func(t *testing.T) {
			read, _ := parentWorkerFrameSourceFixture(t)
			h, l := read.handle, read.handle.ledger
			read.rows = nil
			l.calls[h.id+"\x00stdout_read"] = nil
			var phaseCtx context.Context
			var cancel context.CancelFunc
			if strings.HasPrefix(name, "expire") {
				phaseCtx, cancel = context.WithDeadline(read.ctx, time.Now().Add(2*time.Second))
			} else {
				phaseCtx, cancel = context.WithCancel(read.ctx)
			}
			defer cancel()
			read.ctx, read.phase.ctx = phaseCtx, phaseCtx
			observed := &parentWorkerBeginArrivalSource{Context: l.ctx, arrived: make(chan struct{})}
			l.ctx = observed // original broad ledger remains live
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			h.file, h.fd = r, int(r.Fd())
			queued := []byte{0, 0, 0, 7}
			if n, err := w.Write(queued); err != nil || n != len(queued) {
				t.Fatal("pipe input not queued")
			}
			h.mu.Lock()
			locked := true
			defer func() {
				if locked {
					h.mu.Unlock()
				}
			}()
			done := make(chan error, 1)
			go func() { _, err := readOriginalParentWorkerExact(read, 4); done <- err }()
			select {
			case <-observed.arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("begin admission boundary never reached")
			}
			if strings.HasPrefix(name, "expire") {
				<-phaseCtx.Done()
			} else {
				cancel()
			}
			h.mu.Unlock()
			locked = false
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("late dispatch admitted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("late dispatch stuck")
			}
			if len(read.rows) != 1 {
				t.Fatal("same pending reservation not retained")
			}
			row := read.rows[0]
			if row.fact.OriginalState != "called_pending" || row.fact.OriginalReturnedAt != nil || row.fact.OriginalCount != nil || row.fact.OriginalEOF != nil || row.originalRawKnown || row.fact.OriginalSHA256 != nil || row.fact.OriginalHashState != "unknown_original_bytes" || !h.pending || h.active != row {
				t.Fatal("undispatched original fabricated a completion")
			}
			if l.ctx.Err() != nil {
				t.Fatal("fixture expired ledger instead of narrower phase")
			}
			// Read the queued bytes directly only as the CI fixture teardown
			// oracle. The refused kernel must have consumed none of them.
			if err := r.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			actual := make([]byte, 4)
			if _, err := io.ReadFull(r, actual); err != nil || !bytes.Equal(actual, queued) {
				t.Fatal("late kernel read consumed queued original bytes")
			}
		})
	}
}

func TestHostParentWorkerClosedFamilySource(t *testing.T) {
	body := []byte("synthetic public")
	for _, selector := range []string{"basal-owner-worker", "bootstrap-return-worker", "prepared-create-plan", "choice-return", "io-calls/11111111-1111-4111-8111-111111111111/chunk/" + digest(body), "io-calls/11111111-1111-4111-8111-111111111111/manifest/" + digest(body), "io-calls/11111111-1111-4111-8111-111111111111/inventory/" + digest(body), "ordinary-prepared-create-plan", "root-preparation", "io-calls/not-uuid/chunk/" + digest(body), "io-calls/11111111-1111-4111-8111-111111111111/private/" + digest(body), "io-calls/11111111-1111-4111-8111-111111111111/chunk/" + strings.Repeat("b", 64)} {
		t.Run(selector, func(t *testing.T) {
			want := selector == "basal-owner-worker" || selector == "bootstrap-return-worker" || selector == "prepared-create-plan" || selector == "choice-return"
			if originalParentWorkerPublicFamily(selector, body) != want {
				t.Fatal("closed family grammar changed")
			}
		})
	}
}

// Source assembly input: native_parent_worker_source_audit_projector_source_test_fragment.go
// Synthetic Source-only custody fixture. The all-zero signature is deliberately
// not authenticated; no native authority, secret, SQL or supplier is installed.
func parentWorkerSourceAuditFixture(t *testing.T) (*originalParentWorkerFrameRead, originalParentWorkerSourceAuditFrameBasis) {
	t.Helper()
	read, stage := parentWorkerFrameSourceFixture(t)
	root := "22222222-2222-4222-8222-222222222222"
	handle := "33333333-3333-4333-8333-333333333333"
	owner := read.handle.ledger.subjects["host_worker"]
	read.phase.factoryRoot = root
	start := read.phase.calledAt
	projections := make([]originalSourceAuditProjection, 0, 2)
	closeID := handle + ":2"
	for i, op := range []string{"source_directory_open", "source_directory_close"} {
		called, returned := start.Add(time.Duration(2+i*2)*time.Second), start.Add(time.Duration(3+i*2)*time.Second)
		projections = append(projections, originalSourceAuditProjection{Family: "source_audit", SubjectIdentity: originalSourceAuditSubject{SubjectKind: "source_file"}, Fact: model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: root, OriginalAuditHandleID: handle, OriginalCallID: ptr(handle + ":" + strconv.Itoa(i+1)), Operation: op, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: stage.effectiveDeadline, OriginalErrorPresent: ptr(false), OriginalHashState: "not_byte_operation"}, OriginalCloseReference: &closeID})
	}
	carrier := originalFinalSourceAuditCarrier{Schema: "source_private_original_final_source_audit_carrier_v1", FactoryRootID: root, SourceApprovalSHA256: strings.Repeat("a", 64), RootPreparationSHA256: strings.Repeat("b", 64), OriginalOwnerID: owner, OriginalOwnerRole: "host_worker", OriginalBasalSHA256: strings.Repeat("c", 64), BindingSchema: read.handle.ledger.bindingSchema, BindingSHA256: read.handle.ledger.bindingSHA, SnapshotID: "44444444-4444-4444-8444-444444444444", OriginalStreamCount: 1, OriginalArtifactReferences: []originalFinalSourceAuditArtifactReference{}, OriginalRemainingStreams: []originalFinalSourceAuditStream{{OriginalAcquisitionOrdinal: 1, OriginalSourceOwnerID: owner, OriginalSourceOwnerRole: "host_worker", OriginalSourceBindingSchema: read.handle.ledger.bindingSchema, OriginalSourceBindingSHA256: read.handle.ledger.bindingSHA, OriginalHandleID: handle, OriginalSourceAuditProjections: projections}}, OriginalHelperReturn: controlCurrentSourceReturn{"receive_original_sealed_worker", owner, "host_worker", start, start.Add(7 * time.Second), stage.effectiveDeadline, "returned", false}}
	basis := originalParentWorkerSourceAuditFrameBasis{read: read, profile: stage.profile, phase: read.phase, selector: "final-source-audit-worker", carrier: carrier, envelope: originalFinalSourceAuditEnvelope{Schema: "source_private_original_final_source_audit_envelope_v1", KeyID: owner, Role: "host_worker", ReportDomain: "source_private_original_final_source_audit_carrier_domain_v1", SignatureBase64: base64.StdEncoding.EncodeToString(make([]byte, 64))}, effectiveContext: read.ctx, effectiveDeadline: stage.effectiveDeadline}
	parentWorkerSourceAuditEncode(t, read, &basis)
	return read, basis
}

func parentWorkerSourceAuditEncode(t *testing.T, read *originalParentWorkerFrameRead, basis *originalParentWorkerSourceAuditFrameBasis) {
	t.Helper()
	var err error
	basis.carrierBody, err = json.Marshal(basis.carrier)
	if err != nil {
		t.Fatal(err)
	}
	basis.envelope.BodyBase64 = base64.StdEncoding.EncodeToString(basis.carrierBody)
	basis.carrierEnvelope, err = json.Marshal(basis.envelope)
	if err != nil {
		t.Fatal(err)
	}
	read.raw, err = json.Marshal(originalWorkerSignedFrame{Schema: "source_private_original_final_source_audit_signed_frame_v1", Selector: basis.selector, EnvelopeRaw: basis.carrierEnvelope})
	if err != nil {
		t.Fatal(err)
	}
	basis.canonicalFrame = bytes.Clone(read.raw)
	binary.BigEndian.PutUint32(read.prefix, uint32(len(read.raw)))
	for n, raw := range [][]byte{read.prefix, read.raw[:7], read.raw[7:]} {
		read.rows[n].originalRaw = bytes.Clone(raw)
		read.rows[n].fact.OriginalCount = ptr(int64(len(raw)))
	}
}

func TestHostParentWorkerSourceAuditProjectionSource(t *testing.T) {
	for _, name := range []string{"whole_projection", "safe_failed_open", "safe_private_read", "ordered_artifact_ref", "wrong_selector", "foreign_root", "foreign_owner", "wrong_role", "wrong_scope", "unknown_source", "empty_snapshot", "wrong_carrier_schema", "wrong_envelope_schema", "wrong_domain", "wrong_key_role", "empty_key", "noncanonical_signature", "wrong_helper", "helper_failed", "helper_error_pending", "helper_error_unknown_return", "helper_error_late", "helper_future", "helper_deadline", "helper_nonUTC", "NULL_refs", "NULL_streams", "missing_ordinal", "overlap_ref", "unsafe_basename", "ref_invalid_digest", "ref_overcap", "wrong_stream_owner", "unknown_stream_binding", "duplicate_stream_handle", "NULL_projections", "wrong_subject", "HTTP_metadata", "private_hash", "private_prefix", "private_scope", "unknown_failure_code", "foreign_fact_root", "wrong_call_ordinal", "missing_close", "future_source_return", "foreign_basis_read", "foreign_basis_context", "wrong_basis_deadline", "preexisting_row_hash", "unknown_row_raw", "raw_count_mismatch", "stage_family_refuses"} {
		t.Run(name, func(t *testing.T) {
			read, basis := parentWorkerSourceAuditFixture(t)
			c := &basis.carrier
			s := &c.OriginalRemainingStreams[0]
			p := &s.OriginalSourceAuditProjections[0]
			switch name {
			case "safe_failed_open":
				s.OriginalSourceAuditProjections = s.OriginalSourceAuditProjections[:1]
				p.OriginalCloseReference = nil
				p.Fact.OriginalErrorPresent = ptr(true)
				p.Fact.FailureCode = ptr("storage_unknown")
			case "safe_private_read":
				first := s.OriginalSourceAuditProjections[0]
				first.Fact.Operation = "source_file_open"
				first.OriginalCloseReference = ptr(s.OriginalHandleID + ":3")
				readRow := first
				readRow.Fact.Operation = "source_file_read"
				readRow.Fact.OriginalCallID = ptr(s.OriginalHandleID + ":2")
				readRow.Fact.OriginalCalledAt = ptr(read.phase.calledAt.Add(4 * time.Second))
				readRow.Fact.OriginalReturnedAt = ptr(read.phase.calledAt.Add(5 * time.Second))
				readRow.Fact.OriginalErrorPresent = ptr(true) // literal EOF cause retained
				readRow.Fact.OriginalEOF = ptr(true)
				readRow.Fact.OriginalCount = ptr(int64(0))
				readRow.Fact.OriginalHashState = "private_withheld"
				closeRow := first
				closeRow.Fact.Operation = "source_file_close"
				closeRow.Fact.OriginalCallID = ptr(s.OriginalHandleID + ":3")
				closeRow.Fact.OriginalCalledAt = ptr(read.phase.calledAt.Add(6 * time.Second))
				closeRow.Fact.OriginalReturnedAt = ptr(read.phase.calledAt.Add(7 * time.Second))
				s.OriginalSourceAuditProjections = []originalSourceAuditProjection{first, readRow, closeRow}
			case "wrong_selector":
				basis.selector = "choice-return"
			case "foreign_root":
				c.FactoryRootID = "55555555-5555-4555-8555-555555555555"
			case "foreign_owner":
				c.OriginalOwnerID = "55555555-5555-4555-8555-555555555555"
			case "wrong_role":
				c.OriginalOwnerRole = "host_registrar"
			case "wrong_scope":
				c.BindingSHA256 = strings.Repeat("d", 64)
			case "unknown_source":
				c.SourceApprovalSHA256 = ""
			case "empty_snapshot":
				c.SnapshotID = ""
			case "wrong_carrier_schema":
				c.Schema = "private_unknown"
			case "wrong_envelope_schema":
				basis.envelope.Schema = "private_unknown"
			case "wrong_domain":
				basis.envelope.ReportDomain = "private_unknown"
			case "wrong_key_role":
				basis.envelope.Role = "host_registrar"
			case "empty_key":
				basis.envelope.KeyID = ""
			case "noncanonical_signature":
				basis.envelope.SignatureBase64 += "\n"
			case "wrong_helper":
				c.OriginalHelperReturn.Operation = "publish_original_final_source_audit_snapshot"
			case "helper_failed":
				c.OriginalHelperReturn.OriginalErrorPresent = true
			case "helper_error_pending":
				c.OriginalHelperReturn.OriginalErrorPresent = true
				c.OriginalHelperReturn.OriginalState = "called_pending"
			case "helper_error_unknown_return":
				c.OriginalHelperReturn.OriginalErrorPresent = true
				c.OriginalHelperReturn.OriginalReturnedAt = time.Time{}
			case "helper_error_late":
				c.OriginalHelperReturn.OriginalErrorPresent = true
				c.OriginalHelperReturn.OriginalContextDeadline = c.OriginalHelperReturn.OriginalReturnedAt
			case "helper_future":
				c.OriginalHelperReturn.OriginalReturnedAt = read.returnedAt.Add(time.Second)
			case "helper_deadline":
				c.OriginalHelperReturn.OriginalContextDeadline = c.OriginalHelperReturn.OriginalReturnedAt
			case "helper_nonUTC":
				c.OriginalHelperReturn.OriginalReturnedAt = c.OriginalHelperReturn.OriginalReturnedAt.In(time.FixedZone("offset", 3600))
			case "NULL_refs":
				c.OriginalArtifactReferences = nil
			case "NULL_streams":
				c.OriginalRemainingStreams = nil
			case "missing_ordinal":
				c.OriginalStreamCount = 2
			case "ordered_artifact_ref", "overlap_ref", "unsafe_basename", "ref_invalid_digest", "ref_overcap":
				c.OriginalStreamCount = 2
				s.OriginalAcquisitionOrdinal = 2
				ref := originalFinalSourceAuditArtifactReference{Basename: c.SnapshotID + "-source-audit-1-1.json", OriginalBytes: 10, OriginalSHA256: strings.Repeat("f", 64), FirstAcquisitionOrdinal: 1, LastAcquisitionOrdinal: 1, OriginalStreamCount: 1}
				switch name {
				case "overlap_ref":
					s.OriginalAcquisitionOrdinal = 1
				case "unsafe_basename":
					ref.Basename = "../private"
				case "ref_invalid_digest":
					ref.OriginalSHA256 = "unknown-private"
				case "ref_overcap":
					ref.OriginalBytes = bodyLimit + 1
				}
				c.OriginalArtifactReferences = []originalFinalSourceAuditArtifactReference{ref}
			case "wrong_stream_owner":
				s.OriginalSourceOwnerID = "55555555-5555-4555-8555-555555555555"
			case "unknown_stream_binding":
				s.OriginalSourceBindingSchema = "private_unknown"
			case "duplicate_stream_handle":
				c.OriginalStreamCount = 2
				copyStream := *s
				copyStream.OriginalAcquisitionOrdinal = 2
				c.OriginalRemainingStreams = append(c.OriginalRemainingStreams, copyStream)
			case "NULL_projections":
				s.OriginalSourceAuditProjections = nil
			case "wrong_subject":
				p.SubjectIdentity.SubjectKind = "source_directory"
			case "HTTP_metadata":
				p.SubjectIdentity.Method = ptr("private")
			case "private_hash":
				p.Fact.OriginalSHA256 = ptr(strings.Repeat("e", 64))
			case "private_prefix":
				p.Fact.RetainedPrefixBytes = ptr(int64(1))
			case "private_scope":
				p.Fact.OriginalReadScope = ptr("complete_original_body_read")
			case "unknown_failure_code":
				p.Fact.FailureCode = ptr("private cause text")
			case "foreign_fact_root":
				p.Fact.FactoryRootID = "55555555-5555-4555-8555-555555555555"
			case "wrong_call_ordinal":
				p.Fact.OriginalCallID = ptr(s.OriginalHandleID + ":2")
			case "missing_close":
				p.OriginalCloseReference = nil
			case "future_source_return":
				p.Fact.OriginalReturnedAt = ptr(c.OriginalHelperReturn.OriginalReturnedAt.Add(time.Second))
			}
			parentWorkerSourceAuditEncode(t, read, &basis)
			switch name {
			case "foreign_basis_read":
				basis.read = &originalParentWorkerFrameRead{}
			case "foreign_basis_context":
				basis.effectiveContext = context.Background()
			case "wrong_basis_deadline":
				basis.effectiveDeadline = basis.effectiveDeadline.Add(-time.Second)
			case "preexisting_row_hash":
				read.rows[0].fact.OriginalSHA256 = ptr(strings.Repeat("a", 64))
			case "unknown_row_raw":
				read.rows[0].originalRawKnown = false
			case "raw_count_mismatch":
				read.rows[0].fact.OriginalCount = ptr(int64(1))
			}
			before, raw := parentWorkerFactsSource(t, read)
			if name == "stage_family_refuses" {
				if originalParentWorkerPublicFamily(basis.selector, basis.carrierBody) {
					t.Fatal("Source-only carrier acquired Host-stage family")
				}
				stage := originalParentWorkerPublicFrameBasis{read: read, phase: read.phase, profile: basis.profile, canonicalFrame: read.raw, selector: basis.selector, body: basis.carrierBody, envelope: basis.carrierEnvelope, effectiveContext: read.ctx, effectiveDeadline: basis.effectiveDeadline}
				if projectOriginalParentWorkerFrame(read, stage) == nil {
					t.Fatal("Source carrier acquired Host-stage projection")
				}
			} else if err := projectOriginalParentWorkerSourceAuditFrame(read, basis); name == "whole_projection" || name == "safe_failed_open" || name == "safe_private_read" || name == "ordered_artifact_ref" || name == "helper_failed" {
				if err != nil || !read.classified {
					t.Fatalf("whole synthetic Source projection refused: %v", err)
				}
				for _, row := range read.rows {
					if row.fact.OriginalSHA256 == nil || *row.fact.OriginalSHA256 != digest(row.originalRaw) || row.fact.OriginalHashState != "actual_public_bytes" {
						t.Fatal("whole original ranges not projected")
					}
				}
				if projectOriginalParentWorkerSourceAuditFrame(read, basis) == nil {
					t.Fatal("completed projection replayed")
				}
				if name == "helper_failed" && !basis.carrier.OriginalHelperReturn.OriginalErrorPresent {
					t.Fatal("real Source diagnostic error rewritten")
				}
				return
			} else if err == nil {
				t.Fatal("unsafe/foreign Source frame projected")
			}
			after, actual := parentWorkerFactsSource(t, read)
			if !bytes.Equal(before, after) || !reflect.DeepEqual(raw, actual) || read.classified {
				t.Fatal("refusal changed immutable original custody")
			}
		})
	}
}

func TestHostParentWorkerSourceAuditWaitSource(t *testing.T) {
	for _, name := range []string{"cancel_handle", "expire_handle", "cancel_ledger", "expire_ledger", "cancel_collection", "expire_collection"} {
		t.Run(name, func(t *testing.T) {
			read, basis := parentWorkerSourceAuditFixture(t)
			var ctx context.Context
			var cancel context.CancelFunc
			if strings.HasPrefix(name, "expire") {
				ctx, cancel = context.WithDeadline(read.ctx, time.Now().Add(2*time.Second))
			} else {
				ctx, cancel = context.WithCancel(read.ctx)
			}
			defer cancel()
			observed := &parentWorkerDeadlineArrivalSource{Context: ctx, arrived: make(chan struct{})}
			read.ctx, read.phase.ctx, basis.effectiveContext = observed, observed, observed
			basis.effectiveDeadline, _ = ctx.Deadline()
			h, l := read.handle, read.handle.ledger
			unlock := h.mu.Unlock
			switch {
			case strings.HasSuffix(name, "handle"):
				h.mu.Lock()
			case strings.HasSuffix(name, "ledger"):
				l.mu.Lock()
				unlock = l.mu.Unlock
			default:
				l.collection.mu.Lock()
				unlock = l.collection.mu.Unlock
			}
			locked := true
			defer func() {
				if locked {
					unlock()
				}
			}()
			before, raw := parentWorkerFactsSource(t, read)
			done := make(chan error, 1)
			go func() { done <- projectOriginalParentWorkerSourceAuditFrame(read, basis) }()
			select {
			case <-observed.arrived:
			case <-time.After(5 * time.Second):
				t.Fatal("real initial context guard not reached")
			}
			if !strings.HasSuffix(name, "handle") {
				limit := time.Now().Add(5 * time.Second)
				for h.mu.TryLock() {
					h.mu.Unlock()
					if time.Now().After(limit) {
						t.Fatal("projector did not reach held later lock")
					}
					runtime.Gosched()
				}
			}
			if strings.HasPrefix(name, "expire") {
				<-ctx.Done()
			} else {
				cancel()
			}
			unlock()
			locked = false
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("late lock wait projected")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("projector stuck")
			}
			after, actual := parentWorkerFactsSource(t, read)
			if !bytes.Equal(before, after) || !reflect.DeepEqual(raw, actual) || read.classified {
				t.Fatal("wait refusal changed custody")
			}
		})
	}
}

// Observe a real attempted hash commit while publication locks are held, then
// cancel the genuine context. The observer never invents an Err/deadline/result.
type parentWorkerSourceAuditCommitObserver struct {
	context.Context
	cancel context.CancelFunc
	read   *originalParentWorkerFrameRead
}

func (c *parentWorkerSourceAuditCommitObserver) Err() error {
	if c.read.rows[0].fact.OriginalSHA256 != nil {
		c.cancel()
	}
	return c.Context.Err()
}

func TestHostParentWorkerSourceAuditAtomicRollbackSource(t *testing.T) {
	read, basis := parentWorkerSourceAuditFixture(t)
	ctx, cancel := context.WithCancel(read.ctx)
	defer cancel()
	observed := &parentWorkerSourceAuditCommitObserver{Context: ctx, cancel: cancel, read: read}
	read.ctx, read.phase.ctx, basis.effectiveContext = observed, observed, observed
	before, raw := parentWorkerFactsSource(t, read)
	if projectOriginalParentWorkerSourceAuditFrame(read, basis) == nil || ctx.Err() != context.Canceled {
		t.Fatal("real cancellation at unpublished commit not retained")
	}
	after, actual := parentWorkerFactsSource(t, read)
	if !bytes.Equal(before, after) || !reflect.DeepEqual(raw, actual) || read.classified {
		t.Fatal("atomic rollback changed facts/raw or exposed partial hashes")
	}
}

// Source assembly input: native_poststart_composer_source_test_fragment.go
// CI ONLY: synthetic readonly custody/grammar kernels. No helper below reads a
// file, starts a process, installs Source, proves SQL-FIRST or native absence.
const postStartTestRoot = "01010101-0101-4101-8101-010101010101"
const postStartTestHandle = "02020202-0202-4202-8202-020202020202"

func postStartTestLedgerRead(t *testing.T) (*originalPostStartLedgerRead, *originalNativePhaseReservation, []byte) {
	base := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	deadline := base.Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)
	phase := &originalNativePhaseReservation{ctx: ctx, calledAt: base}
	x := &originalPostStartLedgerRead{raw: []byte("logical-source-only"), handle: &callHandle{id: postStartTestHandle}}
	ops := []string{"source_file_open", "source_file_fstat", "source_file_read", "source_file_read", "source_file_fstat", "source_file_close"}
	for n, op := range ops {
		called, returned := base.Add(time.Duration(2*n+1)*time.Nanosecond), base.Add(time.Duration(2*n+2)*time.Nanosecond)
		f := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: postStartTestRoot, OriginalAuditHandleID: postStartTestHandle, OriginalCallID: ptr(fmt.Sprintf("%s:%d", postStartTestHandle, n+1)), Operation: op, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalOperationDeadline: deadline, OriginalErrorPresent: ptr(false), OriginalHashState: "not_byte_operation"}
		if n == 2 {
			f.OriginalCount, f.OriginalEOF, f.OriginalHashState = ptr(int64(len(x.raw))), ptr(false), "private_withheld"
		}
		if n == 3 {
			f.OriginalCount, f.OriginalEOF, f.OriginalErrorPresent, f.OriginalHashState = ptr(int64(0)), ptr(true), ptr(true), "private_withheld"
		}
		x.calls = append(x.calls, f)
	}
	x.firstRead, x.finalRead, x.closeReturn = x.calls[2], x.calls[3], x.calls[5]
	return x, phase, append([]byte{}, x.raw...)
}

func TestPostStartOriginalLedgerSourceCustody(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*originalPostStartLedgerRead, *originalNativePhaseReservation, *[]byte)
		accepted bool
	}{
		{"literal_EOF_error_preserved_private_hashes_NULL", nil, true},
		{"aggregate_error_retained", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.cause = errors.New("synthetic-original-reader-error")
		}, false},
		{"foreign_root", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].FactoryRootID = postStartTestHandle
		}, false},
		{"foreign_handle", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalAuditHandleID = postStartTestRoot
		}, false},
		{"CallID_noncanonical_ordinal", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalCallID = ptr(postStartTestHandle + ":03")
		}, false},
		{"CallID_gap", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalCallID = ptr(postStartTestHandle + ":4")
		}, false},
		{"duplicate_CallID", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalCallID = x.calls[1].OriginalCallID
		}, false},
		{"missing_pre_Fstat", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[1].Operation = "source_file_open"
		}, false},
		{"missing_post_Fstat", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[4].Operation = "source_file_open"
		}, false},
		{"repeated_pre_Fstat", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].Operation = "source_file_fstat"
		}, false},
		{"returned_before_call", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalReturnedAt = x.calls[1].OriginalCalledAt
		}, false},
		{"current_phase_start_after_original_read", func(x *originalPostStartLedgerRead, p *originalNativePhaseReservation, _ *[]byte) {
			p.calledAt = *x.calls[2].OriginalReturnedAt
		}, false},
		{"original_return_at_phase_deadline", func(x *originalPostStartLedgerRead, p *originalNativePhaseReservation, _ *[]byte) {
			d, _ := p.ctx.Deadline()
			x.calls[5].OriginalReturnedAt = &d
		}, false},
		{"original_own_deadline_before_return", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalOperationDeadline = *x.calls[2].OriginalCalledAt
		}, false},
		{"EOF_is_not_nil_error", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[3].OriginalErrorPresent = ptr(false)
		}, false},
		{"missing_literal_EOF", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[3].OriginalEOF = ptr(false)
			x.calls[3].OriginalErrorPresent = ptr(false)
		}, false},
		{"read_failure_not_EOF", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalErrorPresent = ptr(true)
		}, false},
		{"pending_read_not_returned", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalState = "called_pending"
		}, false},
		{"unknown_count", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalCount = nil
		}, false},
		{"wrong_whole_count", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalCount = ptr(int64(1))
		}, false},
		{"private_original_hash_not_exported", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalSHA256 = ptr(strings.Repeat("a", 64))
		}, false},
		{"private_prefix_hash_not_exported", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].RetainedPrefixSHA256 = ptr(strings.Repeat("a", 64))
		}, false},
		{"no_HTTP_read_scope_for_FileRead", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[2].OriginalReadScope = ptr("complete_original_body_read")
		}, false},
		{"no_read_after_EOF", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[4].Operation = "source_file_read"
			x.calls[4].OriginalCount = ptr(int64(1))
			x.calls[4].OriginalEOF = ptr(false)
			x.calls[4].OriginalHashState = "private_withheld"
		}, false},
		{"Close_error_refuses_complete", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls[5].OriginalErrorPresent = ptr(true)
		}, false},
		{"foreign_final_Close_projection", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.closeReturn = x.calls[4]
		}, false},
		{"foreign_first_read_projection", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.firstRead = x.calls[3]
		}, false},
		{"foreign_final_read_projection", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.finalRead = x.calls[2]
		}, false},
		{"same_length_foreign_raw", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) { x.raw[0] = 'X' }, false},
		{"empty_expected_is_unknown", func(_ *originalPostStartLedgerRead, _ *originalNativePhaseReservation, b *[]byte) { *b = nil }, false},
		{"cap_plus_one_never_trimmed", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, b *[]byte) {
			*b = []byte(strings.Repeat("x", 65537))
			x.raw = *b
		}, false},
		{"failed_Open_no_fake_Close", func(x *originalPostStartLedgerRead, _ *originalNativePhaseReservation, _ *[]byte) {
			x.calls = x.calls[:1]
			x.calls[0].OriginalErrorPresent = ptr(true)
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x, p, b := postStartTestLedgerRead(t)
			if tc.mutate != nil {
				tc.mutate(x, p, &b)
			}
			before := append([]model.HostFactorySourceAuditReturn{}, x.calls...)
			err := postStartOriginalLedgerRead(x, b, p, postStartTestRoot)
			if (err == nil) != tc.accepted {
				t.Fatalf("Source-only custody expectation=%v error=%v", tc.accepted, err)
			}
			if !reflect.DeepEqual(before, x.calls) {
				t.Fatal("readonly guard rewrote original facts")
			}
		})
	}
}

func TestPostStartOriginalSelectedRecipe(t *testing.T) {
	p := capacity.ProposedHostFactorySourceProfileV1()
	manifestRaw, err := p.Manifest()
	var manifest capacity.HostFactorySourceProfileManifest
	if err != nil || p.Decode(manifestRaw, &manifest) != nil {
		t.Fatal("fixed source profile unavailable")
	}
	workerCleanupDeclared := false
	for _, tuple := range manifest.ExactTuples {
		if tuple.Operation == "proc_owner_directory_close" && tuple.OwnerRole == "host_registrar" && tuple.SubjectRole == "host_worker" && tuple.Stage == "cleanup" && tuple.BindingSchema == "original_host_factory_pre_authority_scope_v4" && tuple.EnvelopeType == "HostFactorySignedEnvelope" && tuple.NativeKind != nil && *tuple.NativeKind == "original_file_close" {
			workerCleanupDeclared = true
		}
	}
	rows := postStartOriginalTuples()
	if len(rows) != 49 {
		t.Fatal("whole selected native observer recipe changed")
	}
	for n, row := range rows {
		t.Run(fmt.Sprintf("tuple_%02d_%s_%s_%s", n, row.Operation, row.SubjectRole, row.Stage), func(t *testing.T) {
			err := p.ValidateOperation(row.Operation, row.OwnerRole, row.SubjectRole, row.Stage, row.BindingSchema, row.EnvelopeType, row.NativeKind)
			missing := row.Operation == "proc_owner_directory_close" && row.SubjectRole == "host_worker" && row.Stage == "cleanup"
			if (err != nil) != (missing && !workerCleanupDeclared) {
				t.Fatal("exact selected manifest outcomes changed")
			}
		})
	}
	t.Run("whole_cleanup_preflight_matches_exact_source_manifest", func(t *testing.T) {
		l := &originalLedger{ownerRole: "host_registrar", bindingSchema: "original_host_factory_pre_authority_scope_v4", sourceProfile: p}
		if (postStartOriginalPurpose(l) == nil) != workerCleanupDeclared {
			t.Fatal("whole selected cleanup differs from exact declared source manifest")
		}
	})
	t.Run("empty_installed_profile_cannot_be_source", func(t *testing.T) {
		if postStartOriginalPurpose(&originalLedger{}) == nil {
			t.Fatal("missing genuine profile accepted")
		}
	})
}

func TestPostStartOriginalUnavailableBeforeNativeIO(t *testing.T) {
	cases := []struct {
		name  string
		p     *originalNativePublisher
		phase *originalNativePhaseReservation
	}{
		{"missing_publisher", nil, nil},
		{"missing_ledger", &originalNativePublisher{}, nil},
		{"missing_actual_phase", &originalNativePublisher{ledger: &originalLedger{}}, nil},
		{"unapproved_structural_token_only", &originalNativePublisher{sourceProfile: capacity.ProposedHostFactorySourceProfileV1(), ledger: &originalLedger{}}, &originalNativePhaseReservation{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, body, env, err := composeOriginalPostStartEmpty(context.Background(), tc.p, tc.phase, nil, nil, nil, nil)
			if err == nil || body != nil || env != nil {
				t.Fatal("missing original source basis promoted before native IO")
			}
		})
	}
}

func TestPostStartOriginalPublicationReturn(t *testing.T) {
	t.Run("actual_original_buffers_preserved_on_cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		body, env := []byte("already-retained-source-body"), []byte("already-retained-source-envelope")
		b, e, err := postStartOriginalPublicationReturn(ctx, &originalLedger{ctx: ctx}, body, env, nil)
		if err == nil || &b[0] != &body[0] || &e[0] != &env[0] {
			t.Fatal("cancel lost actual publication buffers")
		}
	})
	t.Run("original_publication_error_not_replaced", func(t *testing.T) {
		cause := errors.New("original-source-publication-refusal")
		body, env := []byte("retained"), []byte("retained-envelope")
		b, e, err := postStartOriginalPublicationReturn(nil, nil, body, env, cause)
		if err != cause || &b[0] != &body[0] || &e[0] != &env[0] {
			t.Fatal("original error/buffers reconstructed")
		}
	})
	t.Run("unbounded_original_context_refused", func(t *testing.T) {
		ctx := context.Background()
		_, _, err := postStartOriginalPublicationReturn(ctx, &originalLedger{ctx: ctx}, []byte("retained"), nil, nil)
		if err == nil {
			t.Fatal("unbounded original context passed return gate")
		}
	})
	t.Run("lagged_Err_does_not_extend_original_deadline", func(t *testing.T) {
		past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
		ctx := postStartTestLaggedContext{Context: context.Background(), deadline: past}
		_, _, err := postStartOriginalPublicationReturn(ctx, &originalLedger{ctx: ctx, deadline: past}, []byte("retained"), nil, nil)
		if err == nil {
			t.Fatal("nil Err disguised expired original deadline")
		}
	})
}

type postStartTestLaggedContext struct {
	context.Context
	deadline time.Time
}

func (c postStartTestLaggedContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c postStartTestLaggedContext) Err() error                  { return nil }

func TestPostStartOriginalOnceReservation(t *testing.T) {
	makeLocal := func() (*originalNativePublisher, *originalNativePhaseReservation) {
		phase := &originalNativePhaseReservation{requestID: "source-local-once", factoryRoot: postStartTestRoot, ownerID: postStartTestHandle, primitiveSHA: strings.Repeat("a", 64)}
		p := &originalNativePublisher{root: postStartTestRoot, ledger: &originalLedger{ownerID: postStartTestHandle}, basal: &basalOwner{sha: strings.Repeat("a", 64)}, activePhase: phase, phaseReservations: map[string]*originalNativePhaseReservation{phase.requestID: phase}}
		return p, phase
	}
	t.Run("first_local_once_and_sticky_replay_refusal", func(t *testing.T) {
		p, phase := makeLocal()
		if postStartOriginalTryOnce(p, phase) != nil || !phase.postStartEmptyAttempted {
			t.Fatal("local once not consumed")
		}
		if postStartOriginalTryOnce(p, phase) == nil || phase.completed {
			t.Fatal("local once reset or wholephase promoted")
		}
	})
	cases := []struct {
		name   string
		mutate func(*originalNativePublisher, *originalNativePhaseReservation)
	}{
		{"foreign_phase_pointer", func(p *originalNativePublisher, q *originalNativePhaseReservation) {
			copy := *q
			p.phaseReservations[q.requestID] = &copy
		}},
		{"foreign_root", func(_ *originalNativePublisher, q *originalNativePhaseReservation) {
			q.factoryRoot = postStartTestHandle
		}},
		{"foreign_owner", func(_ *originalNativePublisher, q *originalNativePhaseReservation) { q.ownerID = postStartTestRoot }},
		{"foreign_primitive", func(_ *originalNativePublisher, q *originalNativePhaseReservation) {
			q.primitiveSHA = strings.Repeat("b", 64)
		}},
		{"publication_sealed", func(p *originalNativePublisher, _ *originalNativePhaseReservation) { p.sealed = true }},
		{"source_import_failed", func(p *originalNativePublisher, _ *originalNativePhaseReservation) {
			p.importFailure = errors.New("original-source-import-refusal")
		}},
		{"wholephase_closed", func(_ *originalNativePublisher, q *originalNativePhaseReservation) { q.completed = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, q := makeLocal()
			tc.mutate(p, q)
			if postStartOriginalTryOnce(p, q) == nil || q.postStartEmptyAttempted {
				t.Fatal("foreign or sealed local phase admitted")
			}
		})
	}
}

func TestPostStartOriginalWholeThreadRoster(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func([]*originalNativePublication)
		accepted bool
	}{
		{"whole_roster_two_original_core_children", nil, true},
		{"missing_worker_child", func(x []*originalNativePublication) { x[0].thread.ChildPIDs = []int{11} }, false},
		{"duplicate_original_child", func(x []*originalNativePublication) { x[0].thread.ChildPIDs = []int{11, 12, 12} }, false},
		{"foreign_child", func(x []*originalNativePublication) { x[0].thread.ChildPIDs = []int{11, 99} }, false},
		{"child_owned_by_worker_thread", func(x []*originalNativePublication) {
			x[0].thread.ChildPIDs = []int{11}
			x[2].thread.ChildPIDs = []int{12}
		}, false},
		{"duplicate_thread_identity", func(x []*originalNativePublication) { x[2].thread.PID = 11; x[2].thread.TID = 11 }, false},
		{"missing_thread_return", func(x []*originalNativePublication) { x[2] = nil }, false},
		{"foreign_thread_roster", func(x []*originalNativePublication) { x[2].thread.TID = 99 }, false},
		{"thread_read_before_original_task_window", func(x []*originalNativePublication) {
			x[2].thread.OriginalThreadStatBeforeRead.OriginalCalledAt = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
		}, false},
		{"thread_Close_after_original_task_window", func(x []*originalNativePublication) {
			x[2].thread.OriginalThreadStatAfterRead.OriginalCloseReturnedAt = time.Date(2030, 1, 1, 0, 0, 0, 11, time.UTC)
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Explicit Source-only interval/roster synthetics: no observed PID,
			// returned native syscall, kernel read or absence proof is supplied.
			base := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
			threads := []*originalNativePublication{}
			roster := map[string]bool{}
			windows := map[int][2]time.Time{}
			for _, pid := range []int{10, 11, 12} {
				fact := &model.HostFactoryNativeThreadChildRead{PID: pid, TID: pid}
				fact.OriginalThreadStatBeforeRead.OriginalCalledAt = base.Add(2 * time.Nanosecond)
				fact.OriginalThreadStatAfterRead.OriginalCloseReturnedAt = base.Add(3 * time.Nanosecond)
				threads = append(threads, &originalNativePublication{thread: fact})
				roster[fmt.Sprintf("%d:%d", pid, pid)] = true
				windows[pid] = [2]time.Time{base.Add(time.Nanosecond), base.Add(10 * time.Nanosecond)}
			}
			threads[0].thread.ChildPIDs = []int{11, 12}
			if tc.mutate != nil {
				tc.mutate(threads)
			}
			if (postStartOriginalThreadRoster(10, 11, 12, threads, roster, windows) == nil) != tc.accepted {
				t.Fatal("complete original Source roster/window/child join differed")
			}
		})
	}
}

// Source assembly input: native_prepared_source_root_source_test_fragment.go
// Source-memory origins only; no FD is acquired or used and no native/SQL
// approval is installed. The invalid file value is never read/closed.
func preparedSourceRootFixture(t *testing.T) (context.Context, *originalLedger, *callHandle) {
	t.Helper()
	root, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	d, _ := root.Deadline()
	ctx, stop := context.WithDeadline(root, d.Add(-time.Minute))
	t.Cleanup(stop)
	owner := "11111111-1111-4111-8111-111111111111"
	primitive, binding := digest([]byte("original basal")), digest([]byte("original ordinary binding"))
	native, e := newLedger(ctx, owner, "factory_ordinary_worker", primitive, "factory_ordinary_source_binding_v4", binding)
	if e != nil {
		t.Fatal(e)
	}
	source, e := newLedger(root, owner, native.ownerRole, primitive, native.bindingSchema, binding)
	if e != nil {
		t.Fatal(e)
	}
	h, e := source.handle()
	if e != nil {
		t.Fatal(e)
	}
	h.file, h.fd = &os.File{}, 7
	now := time.Now().UTC()
	stat := unix.Stat_t{Dev: 1, Ino: 2, Mode: unix.S_IFDIR | 0700, Nlink: 3, Uid: 1000, Gid: 1000}
	h.unclassified = []unclassifiedNativeReturn{
		{operation: "source_directory_open", handleID: h.id, callID: h.id + ":1", ordinal: 1, scalarObserved: true, scalar: 7, calledAt: now.Add(-4 * time.Second), returnedAt: now.Add(-3 * time.Second), deadline: d},
		{operation: "source_directory_fstat", handleID: h.id, callID: h.id + ":2", ordinal: 2, stat: &stat, calledAt: now.Add(-2 * time.Second), returnedAt: now.Add(-time.Second), deadline: d},
	}
	return ctx, native, h
}
func TestOriginalPreparedRootReusesActualSourceStat(t *testing.T) {
	for _, name := range []string{"same_actual_original", "foreign_descriptor", "foreign_owner", "foreign_namespace", "missing_original_stat", "unknown_original_return", "foreign_stat_CallID", "closed_parent", "cannot_substitute_new_stat"} {
		t.Run(name, func(t *testing.T) {
			ctx, l, h := preparedSourceRootFixture(t)
			fd := 7
			switch name {
			case "foreign_descriptor":
				fd = 8
			case "foreign_owner":
				h.ledger.ownerID = "22222222-2222-4222-8222-222222222222"
			case "foreign_namespace":
				h.ledger.bindingSHA = digest([]byte("foreign binding"))
			case "missing_original_stat":
				h.unclassified = h.unclassified[:1]
			case "unknown_original_return":
				h.unclassified[1].returnedAt = time.Time{}
			case "foreign_stat_CallID":
				h.unclassified[1].callID = h.id + ":3"
			case "closed_parent":
				h.closed = true
			case "cannot_substitute_new_stat":
				h.unclassified = append(h.unclassified, h.unclassified[1])
			}
			actual, origin, e := originalPreparedRootStat(ctx, l, fd, h)
			if (e == nil) != (name == "same_actual_original") {
				t.Fatalf("original Source stat %s: %v", name, e)
			}
			if e == nil && (actual.Ino != 2 || origin.callID != h.id+":2" || origin.stat == h.unclassified[1].stat) {
				t.Fatal("original stat copied from another return or pointer alias")
			}
		})
	}
}
func TestOriginalOrdinaryCreateLedgerDoesNotRebindPrepared(t *testing.T) {
	for _, name := range []string{"fresh_actual_owner", "missing_old_member", "duplicate_old_member", "foreign_choice", "repeat_attempt", "foreign_source_root", "old_deadline_kept", "old_handles_kept"} {
		t.Run(name, func(t *testing.T) {
			parent, old, h := preparedSourceRootFixture(t)
			d, _ := parent.Deadline()
			ctx, cancel := context.WithDeadline(parent, d.Add(-time.Minute))
			defer cancel()
			prior := &originalChoice{rootFD: h.fd, rootIdentity: *h.unclassified[1].stat, ledger: old, sourceRoot: h, sourceRootCall: h.unclassified[1]}
			publisher := &originalNativePublisher{ledger: old, originalLedgers: []*originalLedger{old}}
			w := &originalOrdinaryWorker{publisher: publisher, artifactDirectory: h}
			p := &preparedOriginal{ordinaryWorker: w, choice: prior}
			w.prepared = p
			before, _ := old.ctx.Deadline()
			oldHandle, e := old.handle()
			if e != nil {
				t.Fatal(e)
			}
			switch name {
			case "missing_old_member":
				publisher.originalLedgers = nil
			case "duplicate_old_member":
				publisher.originalLedgers = append(publisher.originalLedgers, old)
			case "foreign_choice":
				p.choice = &originalChoice{ledger: nil}
			case "repeat_attempt":
				w.createLedgerAttempted = true
			case "foreign_source_root":
				prior.sourceRoot = nil
			}
			ledger, e := originalOrdinaryCreateLedger(ctx, p, old)
			accept := name == "fresh_actual_owner" || name == "old_deadline_kept" || name == "old_handles_kept"
			if (e == nil) != accept {
				t.Fatalf("create owner %s: %v", name, e)
			}
			if e == nil {
				after, _ := old.ctx.Deadline()
				current, _ := ctx.Deadline()
				if ledger == old || publisher.ledger != old || p.choice.ledger != ledger || p.choice == prior || w.preparedChoice != prior || ledger.ctx != ctx || !ledger.deadline.Equal(current) || !after.Equal(before) || old.handles[oldHandle.id] != oldHandle || len(publisher.originalLedgers) != 2 {
					t.Fatal("original owner/context/handle was rebound or orphaned")
				}
				if _, e = originalOrdinaryCreateLedger(ctx, p, old); e == nil {
					t.Fatal("same original create owner renewed")
				}
			}
		})
	}
}

// Source assembly input: native_registrar_closing_import_source_test_fragment.go
// Pure Source grammar only: no key, actual IO, installation, SQL FIRST or
// native permission. A recognized malformed chunk cannot vanish as another type.
func TestOriginalClosingHistoryRefusesRecognizedInvalidProfileChunk(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"recognized-missing-required-fields", []byte(`{"schema":"original_host_factory_call_vector_chunk_v2"}`)},
		{"recognized-null-calls", []byte(`{"schema":"original_host_factory_call_vector_chunk_v2","original_calls":null}`)},
		{"recognized-unknown-field", []byte(`{"schema":"original_host_factory_call_vector_chunk_v2","caller_native_ready":true}`)},
		{"malformed-header", []byte(`{"schema":`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph := &originalNativeSourceGraph{sourceProfile: capacity.ProposedHostFactorySourceProfileV1(), io: map[string]originalNativeSignedIO{"retained": {body: tc.raw}}}
			if graph.pendingHistory() == nil {
				t.Fatal("recognized chunk decode error disappeared from original history")
			}
		})
	}
}

// Source assembly input: native_start_finalizer_source_test_fragment.go
// Synthetic private pointer/request grammar. No Cmd.Start, syscall, signer,
// Realm approval, native process or SQL-FIRST is supplied by this fixture.
func startFinalSourceCallFixture(t *testing.T) (*originalNativePublisher, *originalNativePhaseReservation, *callHandle, *retainedCall) {
	t.Helper()
	origin := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithDeadline(context.Background(), origin.Add(30*time.Second))
	t.Cleanup(cancel)
	owner, subject, id := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	profile := capacity.ProposedHostFactorySourceProfileV1()
	l := &originalLedger{ctx: ctx, sourceProfile: profile, ownerID: owner, ownerRole: "host_exterior", primitiveSHA: strings.Repeat("a", 64), bindingSchema: "original_host_factory_pre_authority_scope_v4", bindingSHA: strings.Repeat("b", 64), deadline: origin.Add(30 * time.Second), subjects: map[string]string{"host_worker": subject}, handles: map[string]*callHandle{}, calls: map[string][]*retainedCall{}}
	h := &callHandle{ledger: l, id: id}
	l.handles[id] = h
	called, returned := origin, origin.Add(time.Nanosecond)
	ordinal := uint64(1)
	row := &retainedCall{subjectRole: "host_worker", stage: "worker_start", fact: model.HostFactoryPrimitiveIOReturn{Operation: "worker_start", OriginalHandleID: id, SubjectOwnerID: subject, OriginalState: "returned", OriginalReturnClass: "success", OriginalHashState: "not_byte_operation", OriginalOperationDeadline: l.deadline, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalCallOrdinal: &ordinal, OriginalCallID: ptr(id + ":1"), OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "original_cmd_start", ReturnedPID: ptr(17), OriginalErrorPresent: ptr(false), OriginalErrno: ptr(uint32(0))}}}
	l.calls[id+"\x00worker_start"] = []*retainedCall{row}
	p := &originalNativePublisher{ledger: l, sourceProfile: profile}
	phase := &originalNativePhaseReservation{ctx: ctx, calledAt: origin}
	return p, phase, h, row
}

func TestHostStartFinalizerOwnedCallSource(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*originalNativePublisher, *originalNativePhaseReservation, *callHandle, *retainedCall)
	}{
		{"same_exact_registered_call_source_only", func(*originalNativePublisher, *originalNativePhaseReservation, *callHandle, *retainedCall) {}},
		{"copied_call_is_not_original_pointer", func(p *originalNativePublisher, _ *originalNativePhaseReservation, h *callHandle, r *retainedCall) {
			copy := *r
			p.ledger.calls[h.id+"\x00worker_start"] = []*retainedCall{&copy}
		}},
		{"foreign_handle_registration", func(p *originalNativePublisher, _ *originalNativePhaseReservation, h *callHandle, _ *retainedCall) {
			copy := *h
			p.ledger.handles[h.id] = &copy
		}},
		{"duplicate_original_call_pointer", func(p *originalNativePublisher, _ *originalNativePhaseReservation, h *callHandle, r *retainedCall) {
			p.ledger.calls[h.id+"\x00worker_start"] = []*retainedCall{r, r}
		}},
		{"foreign_subject_role", func(_ *originalNativePublisher, _ *originalNativePhaseReservation, _ *callHandle, r *retainedCall) {
			r.subjectRole = "host_exterior"
		}},
		{"wrong_original_call_stage", func(_ *originalNativePublisher, _ *originalNativePhaseReservation, _ *callHandle, r *retainedCall) {
			r.stage = "worker_exterior_join"
		}},
		{"unknown_original_return", func(_ *originalNativePublisher, _ *originalNativePhaseReservation, _ *callHandle, r *retainedCall) {
			r.fact.OriginalState = "called_pending"
			r.fact.OriginalReturnedAt = nil
		}},
		{"actual_start_error_preserved", func(_ *originalNativePublisher, _ *originalNativePhaseReservation, _ *callHandle, r *retainedCall) {
			r.fact.OriginalNativeReturn.OriginalErrorPresent = ptr(true)
			r.fact.OriginalNativeReturn.OriginalErrno = ptr(uint32(1))
		}},
		{"foreign_primitive", func(_ *originalNativePublisher, _ *originalNativePhaseReservation, _ *callHandle, r *retainedCall) {
			r.fact.OwnerPrimitiveRawSHA256 = ptr(strings.Repeat("f", 64))
		}},
		{"source_before_original_phase", func(_ *originalNativePublisher, phase *originalNativePhaseReservation, _ *callHandle, _ *retainedCall) {
			phase.calledAt = phase.calledAt.Add(time.Second)
		}},
		{"late_original_return", func(p *originalNativePublisher, _ *originalNativePhaseReservation, _ *callHandle, r *retainedCall) {
			r.fact.OriginalReturnedAt = ptr(p.ledger.deadline)
		}},
		{"wrong_native_method_not_start", func(_ *originalNativePublisher, _ *originalNativePhaseReservation, _ *callHandle, r *retainedCall) {
			r.fact.OriginalNativeReturn.Kind = "original_cmd_wait"
		}},
		{"unknown_phase_context", func(_ *originalNativePublisher, phase *originalNativePhaseReservation, _ *callHandle, _ *retainedCall) {
			phase.ctx = nil
		}},
		{"profile_not_same_original_ledger", func(p *originalNativePublisher, _ *originalNativePhaseReservation, _ *callHandle, _ *retainedCall) {
			p.ledger.sourceProfile = nil
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p, phase, h, row := startFinalSourceCallFixture(t)
			tt.mutate(p, phase, h, row)
			_, e := startFinalOwnedCall(p, phase, h, row, "worker_start", "original_cmd_start")
			if (e == nil) != (tt.name == "same_exact_registered_call_source_only") {
				t.Fatal("original call identity/return/stage boundary changed")
			}
		})
	}
}

func TestHostStartFinalizerExtraFilesSource(t *testing.T) {
	for _, name := range []string{"same_original_three_pointers_two_inputs", "swapped_fd3_fd4", "copied_gate_pointer", "fourth_inherited_descriptor", "root_gate_in_redundant_inputs", "wrong_redundant_close_family", "nil_actual_root_anchor", "aliased_fd3_fd4_file", "root_gate_is_pipe_file"} {
		t.Run(name, func(t *testing.T) {
			// Memory identities only: no file or process is opened in this Source case.
			bootstrap, control, gate := &callHandle{file: &os.File{}}, &callHandle{file: &os.File{}}, &callHandle{file: &os.File{}}
			s := &originalChildStartSources{bootstrapHandle: bootstrap, controlHandle: control}
			w := &originalChild{inputs: []originalChildInput{{bootstrap, "bootstrap_reader_close"}, {control, "control_reader_close"}}}
			w.cmd = &exec.Cmd{ExtraFiles: []*os.File{bootstrap.file, control.file, gate.file}}
			p := &originalNativePublisher{realm: &OriginalFactoryRealm{control: &originalControl{fresh: &controlFreshRootIO{anchor: gate}}}}
			switch name {
			case "swapped_fd3_fd4":
				w.cmd.ExtraFiles[0], w.cmd.ExtraFiles[1] = w.cmd.ExtraFiles[1], w.cmd.ExtraFiles[0]
			case "copied_gate_pointer":
				w.cmd.ExtraFiles[2] = &os.File{}
			case "fourth_inherited_descriptor":
				w.cmd.ExtraFiles = append(w.cmd.ExtraFiles, &os.File{})
			case "root_gate_in_redundant_inputs":
				w.inputs = append(w.inputs, originalChildInput{gate, "root_directory_close"})
			case "wrong_redundant_close_family":
				w.inputs[0].closeOperation = "control_reader_close"
			case "nil_actual_root_anchor":
				p.realm.control.fresh.anchor = nil
			case "aliased_fd3_fd4_file":
				control.file = bootstrap.file
				w.cmd.ExtraFiles[1] = bootstrap.file
			case "root_gate_is_pipe_file":
				gate.file = bootstrap.file
				w.cmd.ExtraFiles[2] = bootstrap.file
			}
			if (startFinalExtraFiles(p, w, s) == nil) != (name == "same_original_three_pointers_two_inputs") {
				t.Fatal("original ExtraFiles ownership mapping changed")
			}
		})
	}
	t.Run("unavailable_full_source_never_publishes_start", func(t *testing.T) {
		out, raw, env, e := composeOriginalStartReturn(context.Background(), nil, nil, nil, nil)
		if e == nil || len(raw) != 0 || len(env) != 0 || out.Schema != "" {
			t.Fatal("missing source supplier published Start")
		}
	})
}

func TestHostStartFinalizerUnavailableDescriptorSource(t *testing.T) {
	for _, name := range []string{"unavailable_publisher", "unavailable_ledger", "unavailable_profile", "unavailable_phase", "unavailable_original_handle"} {
		t.Run(name, func(t *testing.T) {
			p, phase, h, _ := startFinalSourceCallFixture(t)
			switch name {
			case "unavailable_publisher":
				p = nil
			case "unavailable_ledger":
				p.ledger = nil
			case "unavailable_profile":
				p.sourceProfile = nil
			case "unavailable_phase":
				phase = nil
			case "unavailable_original_handle":
				h = nil
			}
			got, err := startFinalDescriptor(p, phase, h, model.HostFactoryDescriptorSource{}, "control_reader", "control_pipe_create", strings.Repeat("a", 64), true, time.Time{})
			if err == nil || got.OriginalHandleID != "" {
				t.Fatal("unavailable original descriptor became a returned source fact")
			}
		})
	}
}

func TestHostStartFinalizerCloseSource(t *testing.T) {
	for _, name := range []string{"same_original_close_after_start_source_only", "wrong_original_close_fd", "close_before_actual_start_return", "actual_close_error", "wrong_close_family", "copied_return_pointer", "unknown_start_return"} {
		t.Run(name, func(t *testing.T) {
			p, phase, h, row := startFinalSourceCallFixture(t)
			delete(p.ledger.calls, h.id+"\x00worker_start")
			h.fd = 11
			row.fact.Operation = "control_reader_close"
			row.fact.OriginalNativeReturn = &model.HostFactoryNativeCallReturn{Kind: "original_file_close", InputDescriptorNumber: ptr(h.fd), OriginalErrorPresent: ptr(false), OriginalErrno: ptr(uint32(0))}
			p.ledger.calls[h.id+"\x00control_reader_close"] = []*retainedCall{row}
			startReturned := phase.calledAt
			switch name {
			case "wrong_original_close_fd":
				row.fact.OriginalNativeReturn.InputDescriptorNumber = ptr(12)
			case "close_before_actual_start_return":
				startReturned = row.fact.OriginalReturnedAt.Add(time.Nanosecond)
			case "actual_close_error":
				row.fact.OriginalNativeReturn.OriginalErrorPresent = ptr(true)
			case "wrong_close_family":
				row.fact.Operation = "bootstrap_reader_close"
			case "copied_return_pointer":
				copy := *row
				p.ledger.calls[h.id+"\x00control_reader_close"] = []*retainedCall{&copy}
			case "unknown_start_return":
				startReturned = time.Time{}
			}
			at, err := startFinalCloseReturn(p, phase, h, row, "control_reader_close", startReturned)
			if (err == nil) != (name == "same_original_close_after_start_source_only") || err != nil && !at.IsZero() || err == nil && !at.Equal(*row.fact.OriginalReturnedAt) {
				t.Fatal("Close substituted an FD, family, call or proof time")
			}
		})
	}
}

// Exact selected values are synthetic inputs to a read-only stat/flags
// relationship kernel. Passing this kernel proves no actual native return.
func startFinalDescriptorSourceFixture() (model.HostFactoryDescriptorSource, [3]model.HostFactoryPrimitiveIOReturn, time.Time) {
	base := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	handle := "33333333-3333-4333-8333-333333333333"
	s := model.HostFactoryDescriptorSource{OriginalHandleID: handle, OriginalDescriptorNumber: 11, Device: 1, Inode: 2, Mode: 0010600, LinkCount: 1, UID: 1000, GID: 1000, Flags: 0x800, DescriptorFlags: 1, OriginalFstatReturnedAt: base.Add(2 * time.Nanosecond), OriginalFstatCallID: handle + ":2", OriginalGetflCallID: handle + ":3", OriginalGetfdCallID: handle + ":4"}
	var facts [3]model.HostFactoryPrimitiveIOReturn
	for i, operation := range []string{"descriptor_fstat", "fcntl_getfl", "fcntl_getfd"} {
		id := fmt.Sprintf("%s:%d", handle, i+2)
		called, returned := base.Add(time.Duration(i*2+1)*time.Nanosecond), base.Add(time.Duration(i*2+2)*time.Nanosecond)
		kind := []string{"unix_fstat", "fcntl_getfl", "fcntl_getfd"}[i]
		facts[i] = model.HostFactoryPrimitiveIOReturn{OriginalHandleID: handle, Operation: operation, OriginalCallID: &id, OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalReturnClass: "success", OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: kind, InputDescriptorNumber: ptr(11), OriginalErrorPresent: ptr(false), OriginalErrno: ptr(uint32(0))}}
	}
	facts[0].OriginalNativeReturn.OriginalStat = &model.HostFactoryNativeStatReturn{Device: s.Device, Inode: s.Inode, Mode: s.Mode, LinkCount: s.LinkCount, UID: s.UID, GID: s.GID}
	facts[1].OriginalNativeReturn.RequestedFcntlCommand, facts[1].OriginalNativeReturn.RequestedArgument, facts[1].OriginalNativeReturn.OriginalScalar = ptr(3), ptr(int64(0)), ptr(int64(s.Flags))
	facts[2].OriginalNativeReturn.RequestedFcntlCommand, facts[2].OriginalNativeReturn.RequestedArgument, facts[2].OriginalNativeReturn.OriginalScalar = ptr(1), ptr(int64(0)), ptr(int64(s.DescriptorFlags))
	return s, facts, base
}

func TestHostStartFinalizerSelectedDescriptorSource(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*model.HostFactoryDescriptorSource, *[3]model.HostFactoryPrimitiveIOReturn, *time.Time)
	}{
		{"same_exact_selected_values_source_only", func(*model.HostFactoryDescriptorSource, *[3]model.HostFactoryPrimitiveIOReturn, *time.Time) {}},
		{"unavailable_acquisition_return", func(_ *model.HostFactoryDescriptorSource, _ *[3]model.HostFactoryPrimitiveIOReturn, at *time.Time) {
			*at = time.Time{}
		}},
		{"selected_stat_before_acquisition_return", func(_ *model.HostFactoryDescriptorSource, _ *[3]model.HostFactoryPrimitiveIOReturn, at *time.Time) {
			*at = at.Add(time.Second)
		}},
		{"foreign_selected_stat_id", func(s *model.HostFactoryDescriptorSource, _ *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			s.OriginalFstatCallID = s.OriginalHandleID + ":9"
		}},
		{"foreign_selected_handle", func(_ *model.HostFactoryDescriptorSource, f *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			f[0].OriginalHandleID = "44444444-4444-4444-8444-444444444444"
		}},
		{"wrong_selected_method", func(_ *model.HostFactoryDescriptorSource, f *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			f[0].OriginalNativeReturn.Kind = "original_file_sync"
		}},
		{"missing_selected_stat", func(_ *model.HostFactoryDescriptorSource, f *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			f[0].OriginalNativeReturn.OriginalStat = nil
		}},
		{"observed_stat_inode_differs", func(s *model.HostFactoryDescriptorSource, _ *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			s.Inode++
		}},
		{"observed_stat_owner_differs", func(s *model.HostFactoryDescriptorSource, _ *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			s.UID++
		}},
		{"stat_return_time_is_not_selected_return", func(s *model.HostFactoryDescriptorSource, _ *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			s.OriginalFstatReturnedAt = s.OriginalFstatReturnedAt.Add(time.Nanosecond)
		}},
		{"getter_fd_differs", func(_ *model.HostFactoryDescriptorSource, f *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			f[1].OriginalNativeReturn.InputDescriptorNumber = ptr(12)
		}},
		{"getfl_command_alias_refused", func(_ *model.HostFactoryDescriptorSource, f *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			f[1].OriginalNativeReturn.RequestedFcntlCommand = ptr(1)
		}},
		{"getfd_argument_differs", func(_ *model.HostFactoryDescriptorSource, f *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			f[2].OriginalNativeReturn.RequestedArgument = ptr(int64(1))
		}},
		{"observed_flags_are_not_requested_or_expected_bits", func(s *model.HostFactoryDescriptorSource, _ *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			s.Flags = 0
		}},
		{"unknown_descriptor_flags", func(_ *model.HostFactoryDescriptorSource, f *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			f[2].OriginalNativeReturn.OriginalScalar = nil
		}},
		{"getfl_precedes_selected_stat_return", func(_ *model.HostFactoryDescriptorSource, f *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			f[1].OriginalCalledAt = f[0].OriginalCalledAt
		}},
		{"getfd_precedes_selected_getfl_return", func(_ *model.HostFactoryDescriptorSource, f *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			f[2].OriginalCalledAt = f[1].OriginalCalledAt
		}},
		{"actual_getter_error", func(_ *model.HostFactoryDescriptorSource, f *[3]model.HostFactoryPrimitiveIOReturn, _ *time.Time) {
			f[2].OriginalNativeReturn.OriginalErrorPresent = ptr(true)
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			s, facts, acquired := startFinalDescriptorSourceFixture()
			tt.mutate(&s, &facts, &acquired)
			if (startFinalDescriptorReturns(s, facts, acquired) == nil) != (tt.name == "same_exact_selected_values_source_only") {
				t.Fatal("selected original stat/getter relation changed")
			}
		})
	}
}

// The original cache graph here is constructed Source-only: no real pipe,
// signature, observed process, approved Realm or SQL-FIRST is supplied.
func startFinalPipeSourceFixture(t *testing.T) (*originalNativePublisher, *originalNativePhaseReservation, *callHandle, *callHandle, model.HostFactoryDescriptorSource) {
	t.Helper()
	p, phase, read, row := startFinalSourceCallFixture(t)
	l := p.ledger
	delete(l.calls, read.id+"\x00worker_start")
	read.fd = 11
	writer := &callHandle{id: "44444444-4444-4444-8444-444444444444", fd: 12, ledger: l}
	l.handles[writer.id] = writer
	row.fact.Operation = "stdout_pipe_create"
	row.fact.OriginalNativeReturn = &model.HostFactoryNativeCallReturn{Kind: "original_os_pipe", OriginalErrorPresent: ptr(false), OriginalErrno: ptr(uint32(0)), ReturnedDescriptors: []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: read.id, OriginalDescriptorNumber: read.fd}, {OriginalHandleID: writer.id, OriginalDescriptorNumber: writer.fd}}}
	l.calls[read.id+"\x00stdout_pipe_create"] = []*retainedCall{row}
	c := &OriginalIOCollection{sourceProfile: p.sourceProfile, bodies: map[string][]byte{}, purposes: map[string][]capacity.HostFactorySourceCallPurpose{}, predecessors: map[string]string{}, first: map[string]bool{}}
	l.collection = c
	chunk := model.HostFactoryCallVectorChunk{Schema: "original_host_factory_call_vector_chunk_v2", Purpose: "original_host_factory_call_vector_chunk_v2", BindingSchema: l.bindingSchema, BindingSHA256: l.bindingSHA, OwnerRole: l.ownerRole, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: l.primitiveSHA, Operation: row.fact.Operation, OriginalHandleID: read.id, FirstOrdinal: 1, LastOrdinal: 1, OriginalCalls: []model.HostFactoryPrimitiveIOReturn{row.fact}, RecordedAt: phase.calledAt.Add(time.Second)}
	raw, err := c.canonical(chunk)
	if err != nil {
		t.Fatal(err)
	}
	sha := digest(raw)
	c.bodies[sha], c.purposes[sha] = raw, []capacity.HostFactorySourceCallPurpose{{*row.fact.OriginalCallID, "host_worker", "worker_start"}}
	row.firstSHA, row.finalSHA = sha, sha
	manifest := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: l.bindingSchema, BindingSHA256: l.bindingSHA, OwnerRole: l.ownerRole, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: l.primitiveSHA, Operation: row.fact.Operation, OriginalHandleID: read.id, Level: 0, FirstOrdinal: 1, LastOrdinal: 1, OriginalCallCount: 1, ChildBodySHAs: []string{sha}, CollectionState: "complete_original_calls"}
	raw, err = c.canonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sha = digest(raw)
	c.bodies[sha], c.purposes[sha] = raw, []capacity.HostFactorySourceCallPurpose{}
	ref := model.HostFactoryCallVectorReference{Operation: row.fact.Operation, OriginalHandleID: read.id, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), SubjectOwnerID: l.subjects["host_worker"], FirstOrdinal: 1, LastOrdinal: 1, OriginalCallCount: 1, ManifestRootSHA256: ptr(sha), CollectionState: "complete_original_calls"}
	return p, phase, read, writer, model.HostFactoryDescriptorSource{Role: "stdout_reader", OriginalHandleID: read.id, OriginalDescriptorNumber: read.fd, OriginalAcquisitionCallVector: &ref}
}

func TestHostStartFinalizerOppositePipeSource(t *testing.T) {
	for _, name := range []string{"same_returned_pipe_opposite_pointer_source_only", "writer_registry_missing", "writer_actual_fd_differs", "copied_reader_pointer", "wrong_pipe_family", "unknown_phase_context", "wrong_original_read_descriptor", "foreign_source_profile", "changed_same_original_row"} {
		t.Run(name, func(t *testing.T) {
			p, phase, reader, writer, source := startFinalPipeSourceFixture(t)
			switch name {
			case "writer_registry_missing":
				delete(p.ledger.handles, writer.id)
			case "writer_actual_fd_differs":
				writer.fd++
			case "copied_reader_pointer":
				copy := *reader
				reader = &copy
			case "wrong_pipe_family":
				source.Role = "stderr_reader"
			case "unknown_phase_context":
				phase.ctx = nil
			case "wrong_original_read_descriptor":
				source.OriginalDescriptorNumber++
			case "foreign_source_profile":
				p.ledger.sourceProfile = nil
			case "changed_same_original_row":
				p.ledger.calls[reader.id+"\x00stdout_pipe_create"][0].fact.OriginalNativeReturn.ReturnedDescriptors[1].OriginalDescriptorNumber++
			}
			got, err := startFinalOppositePipe(p, phase, reader, source)
			if (err == nil) != (name == "same_returned_pipe_opposite_pointer_source_only") || err == nil && got != writer || err != nil && got != nil {
				t.Fatal("opposite writer was guessed or its original pipe relation lost")
			}
		})
	}
}

// Source-only deadline delivery model: Err may lag an expired deadline. This
// is no actor, native observation, publisher callback or replacement context.
type startFinalLaggedDeadlineSourceContext struct {
	context.Context
	deadline time.Time
}

func (c startFinalLaggedDeadlineSourceContext) Deadline() (time.Time, bool) { return c.deadline, true }
func (c startFinalLaggedDeadlineSourceContext) Err() error                  { return nil }

func TestHostStartFinalizerPublicationReturnSource(t *testing.T) {
	for _, name := range []string{"same_original_publication_buffer_passthrough", "cancel_after_original_buffers_retained", "deadline_expired_even_if_Err_delivery_lags", "original_publication_error_not_replaced", "unknown_original_deadline", "wider_replacement_deadline_refused", "unknown_original_ledger"} {
		t.Run(name, func(t *testing.T) {
			p, phase, _, _ := startFinalSourceCallFixture(t)
			ctx := phase.ctx
			// Already retained synthetic buffers; no actual aggregate/signature
			// or Source authority is supplied by these bytes.
			body, envelope := []byte("original-body"), []byte("original-envelope")
			var originalErr error
			switch name {
			case "cancel_after_original_buffers_retained":
				owned, cancel := context.WithCancel(ctx)
				ctx, p.ledger.ctx = owned, owned
				cancel()
			case "deadline_expired_even_if_Err_delivery_lags":
				ctx = startFinalLaggedDeadlineSourceContext{Context: context.Background(), deadline: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
				p.ledger.ctx = ctx
			case "original_publication_error_not_replaced":
				originalErr = errors.New("synthetic original publication refusal")
				owned, cancel := context.WithCancel(ctx)
				ctx, p.ledger.ctx = owned, owned
				cancel()
			case "unknown_original_deadline":
				ctx = context.Background()
			case "wider_replacement_deadline_refused":
				owned, cancel := context.WithDeadline(context.Background(), p.ledger.deadline.Add(time.Second))
				t.Cleanup(cancel)
				ctx = owned
			case "unknown_original_ledger":
				p.ledger = nil
			}
			gotBody, gotEnvelope, err := startFinalPublicationReturn(ctx, p.ledger, body, envelope, originalErr)
			if !bytes.Equal(gotBody, body) || !bytes.Equal(gotEnvelope, envelope) || &gotBody[0] != &body[0] || &gotEnvelope[0] != &envelope[0] || (err == nil) != (name == "same_original_publication_buffer_passthrough") || originalErr != nil && err != originalErr {
				t.Fatal("publication return lost original buffers/error or accepted a cancelled/late return")
			}
		})
	}
}

// Source assembly input: native_start_owned_vector_source_test_fragment.go
// Private synthetic cache fixture only. No call/signature/Source approval or
// SQL FIRST is executed or represented. It deliberately leaves c.first empty.
func startOwnedVectorSourceFixture(t *testing.T) (*originalLedger, *callHandle, model.HostFactoryCallVectorReference, []string) {
	t.Helper()
	origin := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	owner, subject, handle := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"
	profile := capacity.ProposedHostFactorySourceProfileV1()
	ctx, cancel := context.WithDeadline(context.Background(), origin.Add(600*time.Second))
	t.Cleanup(cancel)
	c := &OriginalIOCollection{sourceProfile: profile, bodies: map[string][]byte{}, purposes: map[string][]capacity.HostFactorySourceCallPurpose{}, predecessors: map[string]string{}, first: map[string]bool{}}
	l := &originalLedger{ctx: ctx, sourceProfile: profile, ownerID: owner, ownerRole: "host_exterior", primitiveSHA: strings.Repeat("a", 64), bindingSchema: "original_host_factory_pre_authority_scope_v4", bindingSHA: strings.Repeat("b", 64), deadline: origin.Add(600 * time.Second), collection: c, subjects: map[string]string{"host_exterior": owner, "host_worker": subject}, calls: map[string][]*retainedCall{}, handles: map[string]*callHandle{}}
	h := &callHandle{id: handle, ledger: l, fd: 11}
	l.handles[handle] = h
	var hashes []string
	for _, ordinal := range []uint64{1, 3} {
		called, returned := origin.Add(time.Duration(ordinal)*2*time.Nanosecond), origin.Add(time.Duration(ordinal)*2*time.Nanosecond+time.Nanosecond)
		fact := model.HostFactoryPrimitiveIOReturn{Operation: "descriptor_fstat", OriginalHandleID: handle, SubjectOwnerID: subject, OriginalState: "returned", OriginalReturnClass: "success", OriginalHashState: "not_byte_operation", OriginalOperationDeadline: l.deadline, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), OriginalCallID: ptr(fmt.Sprintf("%s:%d", handle, ordinal)), OriginalCallOrdinal: ptr(ordinal), OriginalCalledAt: ptr(called), OriginalReturnedAt: ptr(returned), OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "unix_fstat", InputDescriptorNumber: ptr(11), OriginalErrorPresent: ptr(false), OriginalErrno: ptr(uint32(0)), OriginalStat: &model.HostFactoryNativeStatReturn{Device: 1, Inode: 1, Mode: 0100600, LinkCount: 1}}}
		chunk := model.HostFactoryCallVectorChunk{Schema: "original_host_factory_call_vector_chunk_v2", Purpose: "original_host_factory_call_vector_chunk_v2", BindingSchema: l.bindingSchema, BindingSHA256: l.bindingSHA, OwnerRole: l.ownerRole, OriginalOwnerID: owner, OwnerPrimitiveRawSHA256: l.primitiveSHA, Operation: fact.Operation, OriginalHandleID: handle, FirstOrdinal: ordinal, LastOrdinal: ordinal, OriginalCalls: []model.HostFactoryPrimitiveIOReturn{fact}, RecordedAt: origin.Add(time.Second)}
		raw, err := profile.Canonical(chunk)
		if err != nil {
			t.Fatal(err)
		}
		sha := digest(raw)
		c.bodies[sha], c.purposes[sha] = raw, []capacity.HostFactorySourceCallPurpose{{*fact.OriginalCallID, "host_worker", "worker_start"}}
		l.calls[handle+"\x00descriptor_fstat"] = append(l.calls[handle+"\x00descriptor_fstat"], &retainedCall{fact: fact, subjectRole: "host_worker", stage: "worker_start", firstSHA: sha, finalSHA: sha})
		hashes = append(hashes, sha)
	}
	manifest := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: l.bindingSchema, BindingSHA256: l.bindingSHA, OwnerRole: l.ownerRole, OriginalOwnerID: owner, OwnerPrimitiveRawSHA256: l.primitiveSHA, Operation: "descriptor_fstat", OriginalHandleID: handle, Level: 0, FirstOrdinal: 1, LastOrdinal: 3, OriginalCallCount: 2, ChildBodySHAs: hashes, CollectionState: "complete_original_calls"}
	raw, err := profile.Canonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sha := digest(raw)
	c.bodies[sha], c.purposes[sha] = raw, []capacity.HostFactorySourceCallPurpose{}
	ref := model.HostFactoryCallVectorReference{Operation: "descriptor_fstat", OriginalHandleID: handle, OriginalOwnerID: owner, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), SubjectOwnerID: subject, FirstOrdinal: 1, LastOrdinal: 3, OriginalCallCount: 2, ManifestRootSHA256: ptr(sha), CollectionState: "complete_original_calls"}
	return l, h, ref, hashes
}

func TestHostStartOwnedVectorSourceCustody(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*originalLedger, *callHandle, *model.HostFactoryCallVectorReference, []string)
	}{
		{"sparse_original_operation_without_SQL_FIRST", func(*originalLedger, *callHandle, *model.HostFactoryCallVectorReference, []string) {}},
		{"foreign_owner", func(_ *originalLedger, _ *callHandle, r *model.HostFactoryCallVectorReference, _ []string) {
			r.OriginalOwnerID = "44444444-4444-4444-8444-444444444444"
		}},
		{"foreign_subject", func(_ *originalLedger, _ *callHandle, r *model.HostFactoryCallVectorReference, _ []string) {
			r.SubjectOwnerID = "44444444-4444-4444-8444-444444444444"
		}},
		{"foreign_handle_pointer", func(l *originalLedger, h *callHandle, _ *model.HostFactoryCallVectorReference, _ []string) {
			copy := *h
			l.handles[h.id] = &copy
		}},
		{"unknown_profile", func(l *originalLedger, _ *callHandle, _ *model.HostFactoryCallVectorReference, _ []string) {
			l.sourceProfile = nil
		}},
		{"pending_row", func(l *originalLedger, h *callHandle, _ *model.HostFactoryCallVectorReference, _ []string) {
			l.calls[h.id+"\x00descriptor_fstat"][0].fact.OriginalState = "called_pending"
		}},
		{"nil_original_row", func(l *originalLedger, h *callHandle, _ *model.HostFactoryCallVectorReference, _ []string) {
			l.calls[h.id+"\x00descriptor_fstat"][0] = nil
		}},
		{"foreign_final_SHA", func(l *originalLedger, h *callHandle, _ *model.HostFactoryCallVectorReference, _ []string) {
			l.calls[h.id+"\x00descriptor_fstat"][0].finalSHA = strings.Repeat("f", 64)
		}},
		{"stale_prefix", func(l *originalLedger, h *callHandle, _ *model.HostFactoryCallVectorReference, _ []string) {
			l.calls[h.id+"\x00descriptor_fstat"] = l.calls[h.id+"\x00descriptor_fstat"][:1]
		}},
		{"wrong_cached_body_SHA", func(l *originalLedger, _ *callHandle, _ *model.HostFactoryCallVectorReference, hashes []string) {
			l.collection.bodies[hashes[0]] = []byte("{}")
		}},
		{"empty_original_body", func(l *originalLedger, _ *callHandle, _ *model.HostFactoryCallVectorReference, hashes []string) {
			l.collection.bodies[hashes[0]] = []byte{}
		}},
		{"oversize_original_body", func(l *originalLedger, _ *callHandle, _ *model.HostFactoryCallVectorReference, hashes []string) {
			l.collection.bodies[hashes[0]] = []byte(strings.Repeat("x", bodyLimit+1))
		}},
		{"foreign_original_purpose", func(l *originalLedger, _ *callHandle, _ *model.HostFactoryCallVectorReference, hashes []string) {
			l.collection.purposes[hashes[0]][0].SubjectRole = "host_registrar"
		}},
		{"changed_actual_return", func(l *originalLedger, h *callHandle, _ *model.HostFactoryCallVectorReference, _ []string) {
			l.calls[h.id+"\x00descriptor_fstat"][0].fact.OriginalNativeReturn = &model.HostFactoryNativeCallReturn{Kind: "unix_fstat", InputDescriptorNumber: ptr(12), OriginalErrorPresent: ptr(false), OriginalErrno: ptr(uint32(0)), OriginalStat: &model.HostFactoryNativeStatReturn{Device: 1, Inode: 1, Mode: 0100600, LinkCount: 1}}
		}},
		{"orphan_successor", func(l *originalLedger, _ *callHandle, _ *model.HostFactoryCallVectorReference, hashes []string) {
			l.collection.predecessors[hashes[0]] = strings.Repeat("f", 64)
		}},
		{"missing_child", func(l *originalLedger, _ *callHandle, _ *model.HostFactoryCallVectorReference, hashes []string) {
			delete(l.collection.bodies, hashes[1])
		}},
		{"unknown_empty_vector", func(_ *originalLedger, _ *callHandle, r *model.HostFactoryCallVectorReference, _ []string) {
			r.OriginalCallCount = 0
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			l, h, ref, hashes := startOwnedVectorSourceFixture(t)
			tt.mutate(l, h, &ref, hashes)
			got, err := startOriginalOwnedVector(l, h, ref, "host_worker")
			if (err == nil) != (tt.name == "sparse_original_operation_without_SQL_FIRST") {
				t.Fatal("Source original custody disposition changed")
			}
			if err == nil && (len(got) != 2 || *got[0].OriginalCallOrdinal != 1 || *got[1].OriginalCallOrdinal != 3 || len(l.collection.first) != 0) {
				t.Fatal("sparse originals or Source-only boundary lost")
			}
		})
	}
	t.Run("returned_copies_never_alias_cache", func(t *testing.T) {
		l, h, ref, _ := startOwnedVectorSourceFixture(t)
		got, err := startOriginalOwnedVector(l, h, ref, "host_worker")
		if err != nil {
			t.Fatal(err)
		}
		*got[0].OriginalCallID = "changed"
		*got[0].OriginalNativeReturn.InputDescriptorNumber = 99
		row := l.calls[h.id+"\x00descriptor_fstat"][0]
		if *row.fact.OriginalCallID == "changed" || *row.fact.OriginalNativeReturn.InputDescriptorNumber != 11 {
			t.Fatal("readonly result aliases original cache")
		}
	})
}

func TestHostStartOwnedVectorManifestAndSuccessorSource(t *testing.T) {
	for _, name := range []string{"duplicate_child", "wrong_child_order", "wrong_manifest_count", "wrong_manifest_range", "foreign_namespace", "branch_level_with_leaf_children", "unknown_nested_header", "case_alias_header", "known_pending_successor_without_SQL_FIRST", "missing_pending_original", "changed_pending_request", "pending_publication_after_returned_publication"} {
		t.Run(name, func(t *testing.T) {
			l, h, ref, hashes := startOwnedVectorSourceFixture(t)
			c := l.collection
			if name == "known_pending_successor_without_SQL_FIRST" || name == "missing_pending_original" || name == "changed_pending_request" || name == "pending_publication_after_returned_publication" {
				var current model.HostFactoryCallVectorChunk
				if c.decode(c.bodies[hashes[0]], &current) != nil {
					t.Fatal("synthetic current body")
				}
				pending := current
				fact := current.OriginalCalls[0]
				fact.OriginalState, fact.OriginalReturnClass, fact.OriginalHashState = "called_pending", "unavailable", "unknown_original_bytes"
				fact.OriginalReturnedAt = nil
				fact.OriginalNativeReturn = &model.HostFactoryNativeCallReturn{Kind: "unix_fstat", InputDescriptorNumber: ptr(11)}
				if name == "changed_pending_request" {
					fact.OriginalNativeReturn.InputDescriptorNumber = ptr(12)
				}
				pending.OriginalCalls = []model.HostFactoryPrimitiveIOReturn{fact}
				pending.RecordedAt = *fact.OriginalCalledAt
				if name == "pending_publication_after_returned_publication" {
					// Both bodies remain individually shaped; the original
					// pending publication may not be later than its successor.
					pending.RecordedAt = current.RecordedAt.Add(time.Nanosecond)
				}
				raw, e := c.canonical(pending)
				if e != nil {
					t.Fatal(e)
				}
				sha := digest(raw)
				c.bodies[sha] = raw
				c.purposes[sha] = append([]capacity.HostFactorySourceCallPurpose{}, c.purposes[hashes[0]]...)
				row := l.calls[h.id+"\x00descriptor_fstat"][0]
				row.pendingPublished = true
				row.firstSHA = sha
				c.predecessors[hashes[0]] = sha
				if name == "missing_pending_original" {
					delete(c.bodies, sha)
				}
			} else {
				var manifest model.HostFactoryCallVectorManifest
				if c.decode(c.bodies[*ref.ManifestRootSHA256], &manifest) != nil {
					t.Fatal("synthetic manifest")
				}
				switch name {
				case "duplicate_child":
					manifest.ChildBodySHAs = []string{hashes[0], hashes[0]}
				case "wrong_child_order":
					manifest.ChildBodySHAs = []string{hashes[1], hashes[0]}
				case "wrong_manifest_count":
					manifest.OriginalCallCount = 3
				case "wrong_manifest_range":
					manifest.LastOrdinal = 4
				case "foreign_namespace":
					manifest.BindingSHA256 = strings.Repeat("f", 64)
				case "branch_level_with_leaf_children":
					manifest.Level = 1
				}
				raw, e := json.Marshal(manifest)
				if e != nil {
					t.Fatal(e)
				}
				if name == "unknown_nested_header" {
					raw = append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"unapproved":true}`)...)
				}
				if name == "case_alias_header" {
					raw = bytes.Replace(raw, []byte(`"owner_role":`), []byte(`"Owner_Role":`), 1)
				}
				sha := digest(raw)
				c.bodies[sha], c.purposes[sha] = raw, []capacity.HostFactorySourceCallPurpose{}
				ref.ManifestRootSHA256 = ptr(sha)
			}
			got, e := startOriginalOwnedVector(l, h, ref, "host_worker")
			if (e == nil) != (name == "known_pending_successor_without_SQL_FIRST") {
				t.Fatal("manifest/original pending custody disposition changed")
			}
			if e == nil && (len(got) != 2 || len(c.first) != 0) {
				t.Fatal("Source-only relationship promoted to FIRST or original rows lost")
			}
		})
	}
}

// Source assembly input: native_start_precapture_source_test_fragment.go
// Source chronology/once kernels only. These written cases create no trusted
// installation, native IO, signature, SQL-FIRST relation or actual Start.
func TestHostStartComposerExteriorBeforeActualStartSource(t *testing.T) {
	o := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithDeadline(context.Background(), o.Add(30*time.Second))
	defer cancel()
	for _, tc := range []struct {
		name   string
		mutate func(*originalNativePhaseReservation, *model.HostFactoryNativeProcess, *time.Time, *time.Time)
	}{
		{"fresh_outer_return_before_actual_start", func(*originalNativePhaseReservation, *model.HostFactoryNativeProcess, *time.Time, *time.Time) {}},
		{"fresh_reader_started_before_source_phase", func(p *originalNativePhaseReservation, f *model.HostFactoryNativeProcess, _, _ *time.Time) {
			f.OriginalNativeReadStartedAt = p.calledAt.Add(-time.Nanosecond)
		}},
		{"post_start_capture_cannot_supply_pre_start_proof", func(_ *originalNativePhaseReservation, _ *model.HostFactoryNativeProcess, returned, called *time.Time) {
			*called = returned.Add(-time.Nanosecond)
		}},
		{"final_poll_is_not_later_reader_go_return", func(_ *originalNativePhaseReservation, f *model.HostFactoryNativeProcess, returned, _ *time.Time) {
			*returned = f.OriginalSubjectNativePin.OriginalObservedAt.Add(-time.Nanosecond)
		}},
		{"unknown_reader_go_return", func(_ *originalNativePhaseReservation, _ *model.HostFactoryNativeProcess, returned, _ *time.Time) {
			*returned = time.Time{}
		}},
		{"missing_executable_close", func(_ *originalNativePhaseReservation, f *model.HostFactoryNativeProcess, _, _ *time.Time) {
			f.Execution.OriginalExecutableCloseReturnedAt = time.Time{}
		}},
		{"start_at_original_deadline", func(p *originalNativePhaseReservation, _ *model.HostFactoryNativeProcess, _, called *time.Time) {
			*called, _ = p.ctx.Deadline()
		}},
		{"unbounded_replacement_context", func(p *originalNativePhaseReservation, _ *model.HostFactoryNativeProcess, _, _ *time.Time) {
			p.ctx = context.Background()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			phase := &originalNativePhaseReservation{ctx: ctx, calledAt: o}
			fresh := model.HostFactoryNativeProcess{OriginalNativeReadStartedAt: o.Add(time.Second), OriginalNativeReadReturnedAt: o.Add(8 * time.Second), OriginalNativeCloseReturnedAt: o.Add(9 * time.Second)}
			fresh.Execution.OriginalExecutableReadStartedAt = o.Add(2 * time.Second)
			fresh.Execution.OriginalExecutableReadReturnedAt = o.Add(3 * time.Second)
			fresh.Execution.OriginalExecutableCloseReturnedAt = o.Add(4 * time.Second)
			fresh.Execution.OriginalCmdlineReadReturnedAt = o.Add(5 * time.Second)
			fresh.Execution.OriginalCmdlineCloseReturnedAt = o.Add(6 * time.Second)
			fresh.OriginalSubjectNativePin.OriginalObservedAt = o.Add(10 * time.Second)
			returned, called := o.Add(11*time.Second), o.Add(12*time.Second)
			tc.mutate(phase, &fresh, &returned, &called)
			if (startOriginalExteriorWindow(phase, fresh, returned, called) == nil) != (tc.name == "fresh_outer_return_before_actual_start") {
				t.Fatal("original exterior-before-Start disposition")
			}
		})
	}
}

func TestHostStartComposerOriginalAttemptsSource(t *testing.T) {
	newState := func() (*originalNativePublisher, *originalNativePhaseReservation) {
		phase := &originalNativePhaseReservation{requestID: "synthetic-original-slot", aggregateAttempts: map[string]*originalNativeAggregateAttempt{}}
		p := &originalNativePublisher{activePhase: phase, phaseReservations: map[string]*originalNativePhaseReservation{phase.requestID: phase}}
		return p, phase
	}
	t.Run("failed_capture_consumes_once_without_fabricating_reference", func(t *testing.T) {
		p, phase := newState()
		if startOriginalReserve(p, phase, false) != nil || startOriginalReserve(p, phase, false) == nil || phase.startExteriorRef != nil {
			t.Fatal("failed original capture was repeatable or gained a reference")
		}
	})
	t.Run("missing_capture_finalization_is_sticky", func(t *testing.T) {
		p, phase := newState()
		if startOriginalReserve(p, phase, true) == nil || !phase.startReturnAttempted || startOriginalReserve(p, phase, true) == nil {
			t.Fatal("missing original capture allowed finalization retry")
		}
	})
	t.Run("premature_final_attempt_cannot_start_a_later_observation", func(t *testing.T) {
		p, phase := newState()
		if startOriginalReserve(p, phase, true) == nil || startOriginalReserve(p, phase, false) == nil || phase.startExteriorAttempted {
			t.Fatal("premature finalization enabled a later fresh observation")
		}
	})
	t.Run("capture_reference_permits_only_one_distinct_final_attempt", func(t *testing.T) {
		p, phase := newState()
		if startOriginalReserve(p, phase, false) != nil {
			t.Fatal("first source attempt")
		}
		phase.startExteriorRef = &model.HostFactoryNativeObservationReference{ObservationID: "synthetic-reference-only"}
		if startOriginalReserve(p, phase, true) != nil || startOriginalReserve(p, phase, true) == nil || phase.completed || len(phase.aggregateAttempts) != 0 {
			t.Fatal("source attempt fabricated publication or became repeatable")
		}
	})
	t.Run("same_slot_foreign_phase_pointer_cannot_capture", func(t *testing.T) {
		p, phase := newState()
		foreign := &originalNativePhaseReservation{requestID: phase.requestID}
		if startOriginalReserve(p, foreign, false) == nil || phase.startExteriorAttempted || foreign.startExteriorAttempted {
			t.Fatal("foreign phase consumed original source slot")
		}
	})
	t.Run("completed_phase_cannot_capture", func(t *testing.T) {
		p, phase := newState()
		phase.completed = true
		if startOriginalReserve(p, phase, false) == nil || phase.startExteriorAttempted {
			t.Fatal("completed original phase reopened")
		}
	})
}

func TestHostStartComposerUnavailableSource(t *testing.T) {
	t.Run("nil_supplier_cannot_observe_exterior", func(t *testing.T) {
		ref, err := captureOriginalStartExterior(context.Background(), nil, nil, nil)
		if err == nil || ref != (model.HostFactoryNativeObservationReference{}) {
			t.Fatal("missing source gained a native reference")
		}
	})
	t.Run("missing_original_pin_does_not_reacquire", func(t *testing.T) {
		if startOriginalScopedPin(nil, nil, nil) == nil {
			t.Fatal("missing acquisition accepted")
		}
	})
}

// Source assembly input: native_terminal_composer_source_test_fragment.go
// UNEXECUTED Source memory kernels. No actual IO, installation, signature,
// SQL/FIRST, native admission or owning producer is supplied by these cases.
func TestHostTerminalComposerAttemptSource(t *testing.T) {
	for _, name := range []string{"first", "repeat_after_failure", "foreign_phase", "inactive_phase", "completed", "sealed", "import_failure", "missing_owner"} {
		t.Run(name, func(t *testing.T) {
			phase := &originalNativePhaseReservation{requestID: "fixed-slot"}
			p := &originalNativePublisher{phaseReservations: map[string]*originalNativePhaseReservation{phase.requestID: phase}, activePhase: phase}
			switch name {
			case "repeat_after_failure":
				if terminalOriginalReserve(p, phase) != nil {
					t.Fatal("first reservation")
				}
			case "foreign_phase":
				p.phaseReservations[phase.requestID] = &originalNativePhaseReservation{}
			case "inactive_phase":
				p.activePhase = &originalNativePhaseReservation{}
			case "completed":
				phase.completed = true
			case "sealed":
				p.sealed = true
			case "import_failure":
				p.importFailure = errors.New("synthetic retained refusal")
			case "missing_owner":
				p = nil
			}
			err := terminalOriginalReserve(p, phase)
			if (err == nil) != (name == "first") {
				t.Fatalf("once-only %s: %v", name, err)
			}
			if name == "first" && !phase.terminalReadAttempted {
				t.Fatal("attempt not retained before cache/IO")
			}
		})
	}
}

func terminalChoiceSourceFixture(t *testing.T, issued bool) ([]byte, terminalOriginalSources) {
	t.Helper()
	b := terminalOriginalSources{scopeSHA: strings.Repeat("1", 64), registrationSHA: strings.Repeat("2", 64), issuedAttachmentSHA: strings.Repeat("4", 64)}
	reservation := strings.Repeat("3", 64)
	var value any
	if issued {
		value = model.HostFactoryIssuedChoiceBody{Schema: "original_host_factory_issued_choice_body_v4", Purpose: "original_host_factory_issued_choice_body_v4", PreAuthorityScopeSHA256: b.scopeSHA, AliveRegistrationSHA256: b.registrationSHA, IssuedAttachmentSHA256: b.issuedAttachmentSHA, ChoiceReservationSHA256: reservation, Choice: "sealed_before_possible_create"}
		b.choice.ChoiceBodySchema = "original_host_factory_issued_choice_body_v4"
	} else {
		value = model.HostFactoryUnissuedChoiceBody{Schema: "original_host_factory_unissued_choice_body_v4", Purpose: "original_host_factory_unissued_choice_body_v4", PreAuthorityScopeSHA256: b.scopeSHA, AliveRegistrationSHA256: b.registrationSHA, ChoiceReservationSHA256: reservation, Choice: "sealed_before_possible_create"}
		b.choice.ChoiceBodySchema = "original_host_factory_unissued_choice_body_v4"
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	b.choice.OriginalWrittenBytes, b.choice.ChoiceBodySHA256, b.choice.ChoiceReservationSHA256 = len(raw), digest(raw), reservation
	return raw, b
}

func TestHostTerminalComposerChoiceBytesSource(t *testing.T) {
	for _, name := range []string{"unissued_exact", "issued_exact", "changed_bytes", "wrong_byte_count", "wrong_digest", "wrong_scope", "wrong_registration", "wrong_reservation", "wrong_attachment", "unknown_schema", "newline", "unknown_key", "case_alias", "empty"} {
		t.Run(name, func(t *testing.T) {
			raw, b := terminalChoiceSourceFixture(t, name == "issued_exact" || name == "wrong_attachment")
			updateRecordedBytes := false
			switch name {
			case "changed_bytes":
				raw = bytes.Replace(raw, []byte("sealed_before_possible_create"), []byte("unknown_choice"), 1)
			case "wrong_byte_count":
				b.choice.OriginalWrittenBytes++
			case "wrong_digest":
				b.choice.ChoiceBodySHA256 = strings.Repeat("5", 64)
			case "wrong_scope":
				b.scopeSHA = strings.Repeat("5", 64)
			case "wrong_registration":
				b.registrationSHA = strings.Repeat("5", 64)
			case "wrong_reservation":
				b.choice.ChoiceReservationSHA256 = strings.Repeat("5", 64)
			case "wrong_attachment":
				b.issuedAttachmentSHA = strings.Repeat("5", 64)
			case "unknown_schema":
				b.choice.ChoiceBodySchema = "future_terminal_choice_v1"
			case "newline":
				raw, updateRecordedBytes = append(raw, '\n'), true
			case "unknown_key":
				raw, updateRecordedBytes = append(append([]byte{}, raw[:len(raw)-1]...), []byte(`,"extra":true}`)...), true
			case "case_alias":
				raw, updateRecordedBytes = bytes.Replace(raw, []byte(`"pre_authority_scope_sha256"`), []byte(`"Pre_Authority_Scope_SHA256"`), 1), true
			case "empty":
				raw = nil
			}
			if updateRecordedBytes {
				b.choice.OriginalWrittenBytes, b.choice.ChoiceBodySHA256 = len(raw), digest(raw)
			}
			err := terminalOriginalChoiceBytes(raw, b)
			accept := name == "unissued_exact" || name == "issued_exact"
			if (err == nil) != accept {
				t.Fatalf("literal immutable choice %s: %v", name, err)
			}
		})
	}
}

func TestHostTerminalComposerDescriptorIdentitySource(t *testing.T) {
	for _, name := range []string{"same", "foreign_device", "foreign_inode", "changed_mode", "changed_uid", "changed_gid", "changed_links", "not_directory"} {
		t.Run(name, func(t *testing.T) {
			original := model.HostFactoryBootstrapDescriptorSource{Device: 1, Inode: 2, Type: "directory", Mode: 0040700, UID: 1000, GID: 1000, LinkCount: 2}
			actual := model.HostFactoryDescriptorSource{Device: 1, Inode: 2, Type: "directory", Mode: 0040700, UID: 1000, GID: 1000, LinkCount: 2}
			switch name {
			case "foreign_device":
				actual.Device++
			case "foreign_inode":
				actual.Inode++
			case "changed_mode":
				actual.Mode = 0040755
			case "changed_uid":
				actual.UID++
			case "changed_gid":
				actual.GID++
			case "changed_links":
				actual.LinkCount++
			case "not_directory":
				actual.Type = "regular"
			}
			if terminalOriginalDirectoryIdentity(actual, original) != (name == "same") {
				t.Fatal("new duplicate cannot select another Root directory")
			}
			stat := unix.Stat_t{Dev: 1, Ino: 2, Mode: 0040700, Uid: 1000, Gid: 1000, Nlink: 2}
			switch name {
			case "foreign_device":
				stat.Dev++
			case "foreign_inode":
				stat.Ino++
			case "changed_mode":
				stat.Mode = 0040755
			case "changed_uid":
				stat.Uid++
			case "changed_gid":
				stat.Gid++
			case "changed_links":
				stat.Nlink++
			case "not_directory":
				stat.Mode = 0100600
			}
			if terminalOriginalDirectoryStatIdentity(stat, original) != (name == "same") {
				t.Fatal("post-read actual directory identity drift")
			}
		})
	}
}

func terminalWindowSourceFixture(t *testing.T) (*originalNativePhaseReservation, model.HostFactoryTerminalRead, model.HostFactoryNativeProcess, model.HostFactoryNativeProcess, time.Time, time.Time, time.Time) {
	t.Helper()
	at := time.Now().UTC()
	ctx, cancel := context.WithDeadline(context.Background(), at.Add(time.Minute))
	t.Cleanup(cancel)
	phase := &originalNativePhaseReservation{ctx: ctx, calledAt: at}
	makeProcess := func(start time.Time) model.HostFactoryNativeProcess {
		return model.HostFactoryNativeProcess{HostBootID: "synthetic-same-boot", PID: 101, PPID: 100, StartTicks: 9, ProcessNonceSHA256: strings.Repeat("1", 64), BootstrapReturnSHA256: strings.Repeat("2", 64), UID: 1000, GID: 1000, OriginalNativeReadStartedAt: start, Execution: model.HostFactoryBinaryExecution{ExecutableSHA256: strings.Repeat("3", 64), OriginalExecutableReadStartedAt: start.Add(time.Millisecond), OriginalExecutableReadReturnedAt: start.Add(2 * time.Millisecond), OriginalExecutableCloseReturnedAt: start.Add(3 * time.Millisecond), OriginalCmdlineReadReturnedAt: start.Add(4 * time.Millisecond), OriginalCmdlineCloseReturnedAt: start.Add(5 * time.Millisecond)}, OriginalNativeReadReturnedAt: start.Add(6 * time.Millisecond), OriginalNativeCloseReturnedAt: start.Add(7 * time.Millisecond), OriginalSubjectNativePin: model.HostFactoryNativeSubjectPin{OriginalObservedAt: start.Add(8 * time.Millisecond)}}
	}
	before := makeProcess(at.Add(time.Millisecond))
	b := model.HostFactoryTerminalRead{OriginalReadStartedAt: at.Add(20 * time.Millisecond), OriginalReadReturnedAt: at.Add(21 * time.Millisecond), OriginalFileCloseReturnedAt: at.Add(22 * time.Millisecond), OriginalDirectoryCloseReturnedAt: at.Add(23 * time.Millisecond)}
	after := makeProcess(at.Add(24 * time.Millisecond))
	return phase, b, before, after, at.Add(10 * time.Millisecond), at.Add(33 * time.Millisecond), at.Add(34 * time.Millisecond)
}

func TestHostTerminalComposerFreshWindowSource(t *testing.T) {
	for _, name := range []string{"same_different_read_clocks", "before_actual_GoReturn_after_gate_read", "before_GoReturn_before_final_poll", "after_actual_GoReturn_after_last_close", "after_GoReturn_before_final_poll", "after_reads_before_directory_close", "wrong_pid", "wrong_ppid", "wrong_ticks", "wrong_boot", "wrong_nonce", "wrong_bootstrap", "wrong_uid", "wrong_gid", "wrong_executable", "reversed_native_window", "reversed_file_close", "directory_close_at_deadline", "last_close_at_deadline", "before_phase_start", "missing_GoReturn", "canceled", "pre_exit_window"} {
		t.Run(name, func(t *testing.T) {
			phase, b, before, after, br, ar, last := terminalWindowSourceFixture(t)
			switch name {
			case "before_actual_GoReturn_after_gate_read":
				br = b.OriginalReadStartedAt.Add(time.Nanosecond)
			case "before_GoReturn_before_final_poll":
				br = before.OriginalSubjectNativePin.OriginalObservedAt.Add(-time.Nanosecond)
			case "after_actual_GoReturn_after_last_close":
				ar = last.Add(time.Nanosecond)
			case "after_GoReturn_before_final_poll":
				ar = after.OriginalSubjectNativePin.OriginalObservedAt.Add(-time.Nanosecond)
			case "after_reads_before_directory_close":
				after.OriginalNativeReadStartedAt = b.OriginalDirectoryCloseReturnedAt.Add(-time.Nanosecond)
			case "wrong_pid":
				after.PID++
			case "wrong_ppid":
				after.PPID++
			case "wrong_ticks":
				after.StartTicks++
			case "wrong_boot":
				after.HostBootID = "other-boot"
			case "wrong_nonce":
				after.ProcessNonceSHA256 = strings.Repeat("5", 64)
			case "wrong_bootstrap":
				after.BootstrapReturnSHA256 = strings.Repeat("5", 64)
			case "wrong_uid":
				after.UID++
			case "wrong_gid":
				after.GID++
			case "wrong_executable":
				after.Execution.ExecutableSHA256 = strings.Repeat("5", 64)
			case "reversed_native_window":
				after.Execution.OriginalExecutableCloseReturnedAt = after.Execution.OriginalExecutableReadReturnedAt.Add(-time.Nanosecond)
			case "reversed_file_close":
				b.OriginalFileCloseReturnedAt = b.OriginalReadReturnedAt.Add(-time.Nanosecond)
			case "directory_close_at_deadline":
				d, _ := phase.ctx.Deadline()
				b.OriginalDirectoryCloseReturnedAt = d
			case "last_close_at_deadline":
				last, _ = phase.ctx.Deadline()
			case "before_phase_start":
				before.OriginalNativeReadStartedAt = phase.calledAt.Add(-time.Nanosecond)
			case "missing_GoReturn":
				br = time.Time{}
			case "canceled":
				ctx, cancel := context.WithCancel(phase.ctx)
				cancel()
				phase.ctx = ctx
			case "pre_exit_window":
				last = time.Time{}
			}
			accept := name == "same_different_read_clocks" || name == "pre_exit_window"
			if (terminalOriginalReadWindow(phase, b, before, after, br, ar, last) == nil) != accept {
				t.Fatalf("same reader timing %s", name)
			}
		})
	}
}

// Synthetic already-returned data for the private completion kernel only.
// No File.Read, approval, collector export, SQL or native proof is supplied.
func TestHostTerminalComposerGateRawRetentionSource(t *testing.T) {
	for _, name := range []string{"partial_prefix", "different_actual_bytes", "known_empty_EOF", "empty_nonEOF", "io_error_with_bytes", "cancel_after_return", "late_actual_return", "cap_plus_one_two_original_returns", "original_buffer_copy_not_alias", "pending_not_known_empty"} {
		t.Run(name, func(t *testing.T) {
			at := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
			ctx, cancel := context.WithDeadline(context.Background(), at.Add(time.Minute))
			t.Cleanup(cancel)
			l := &originalLedger{ctx: ctx, deadline: at.Add(time.Minute), ownerID: "source-owner", ownerRole: "host_registrar"}
			h := &callHandle{id: "source-handle", ledger: l}
			id := h.id + ":1"
			row := &retainedCall{subjectRole: "host_worker", stage: "terminal_read", fact: model.HostFactoryPrimitiveIOReturn{Operation: "gate_read", OriginalHandleID: h.id, OriginalCallID: &id, OriginalCalledAt: &at, OriginalState: "called_pending"}}
			expected := []byte("expected-choice-body")
			raw := []byte("actual-partial-prefix")
			cause := error(nil)
			returned := at.Add(time.Second)
			switch name {
			case "different_actual_bytes":
				raw = []byte("different-returned-data")
			case "known_empty_EOF":
				raw, cause = []byte{}, io.EOF
			case "empty_nonEOF":
				raw = []byte{}
			case "io_error_with_bytes":
				cause = io.ErrUnexpectedEOF
			case "cancel_after_return":
				cancel()
			case "late_actual_return":
				returned = l.deadline.Add(time.Nanosecond)
			case "cap_plus_one_two_original_returns":
				raw = bytes.Repeat([]byte("a"), bodyLimit)
			case "pending_not_known_empty":
				if row.originalRawKnown || row.originalRaw != nil || row.fact.OriginalReturnedAt != nil {
					t.Fatal("pending became an actual empty return")
				}
				return
			}
			original := bytes.Clone(raw)
			terminalOriginalFinishGateRead(h, row, returned, raw, cause)
			if !row.originalRawKnown || row.originalRaw == nil || !bytes.Equal(row.originalRaw, original) || row.fact.OriginalCount == nil || *row.fact.OriginalCount != int64(len(original)) || row.fact.OriginalSHA256 == nil || *row.fact.OriginalSHA256 != digest(original) || row.cause != cause || row.fact.OriginalCallID != &id || row.fact.OriginalHandleID != h.id || row.subjectRole != "host_worker" || row.stage != "terminal_read" || row.fact.OriginalReturnedAt == nil || !row.fact.OriginalReturnedAt.Equal(returned) {
				t.Fatal("lost actual private buffer or original identity/return")
			}
			if bytes.Equal(row.originalRaw, expected) {
				t.Fatal("expected choice repaired a refused actual prefix")
			}
			if row.fact.OriginalEOF == nil || *row.fact.OriginalEOF != (cause == io.EOF) {
				t.Fatal("empty count inferred EOF")
			}
			if name == "original_buffer_copy_not_alias" {
				raw[0] ^= 1
				if !bytes.Equal(row.originalRaw, original) {
					t.Fatal("retained actual buffer aliases caller scratch")
				}
			}
			if name == "cap_plus_one_two_original_returns" {
				id2 := h.id + ":2"
				row2 := &retainedCall{subjectRole: "host_worker", stage: "terminal_read", fact: model.HostFactoryPrimitiveIOReturn{Operation: "gate_read", OriginalHandleID: h.id, OriginalCallID: &id2, OriginalCalledAt: &returned, OriginalState: "called_pending"}}
				terminalOriginalFinishGateRead(h, row2, returned.Add(time.Nanosecond), []byte("b"), nil)
				if !row2.originalRawKnown || !bytes.Equal(row2.originalRaw, []byte("b")) || len(row.originalRaw)+len(row2.originalRaw) != bodyLimit+1 || len(row.originalRaw) != bodyLimit {
					t.Fatal("cap refusal trimmed/split original owning returns")
				}
			}
			public, err := json.Marshal(row.fact)
			if err != nil || len(original) > 0 && bytes.Contains(public, original) {
				t.Fatal("raw private bytes leaked into public wire fact")
			}
		})
	}
}

// Source assembly input: native_worker_composer_source_test_fragment.go
// Synthetic Source byte/identity/window kernels only. No original process,
// syscall, signature trust, compiled Source approval or SQL-FIRST is supplied.
func TestHostWorkerComposerBootstrapPairSource(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*model.HostFactoryBootstrapReturn, *model.HostFactoryBootstrapWriteReturn)
	}{
		{"same_original_public_segments", func(*model.HostFactoryBootstrapReturn, *model.HostFactoryBootstrapWriteReturn) {}},
		{"foreign_recipient", func(_ *model.HostFactoryBootstrapReturn, w *model.HostFactoryBootstrapWriteReturn) {
			w.RecipientOwnerID = "foreign"
		}},
		{"foreign_worker_primitive", func(b *model.HostFactoryBootstrapReturn, _ *model.HostFactoryBootstrapWriteReturn) {
			b.OwnerPrimitiveRawSHA256 = strings.Repeat("f", 64)
		}},
		{"foreign_binding", func(_ *model.HostFactoryBootstrapReturn, w *model.HostFactoryBootstrapWriteReturn) {
			w.BindingSHA256 = strings.Repeat("f", 64)
		}},
		{"nonce_is_first_challenge_not_binding", func(b *model.HostFactoryBootstrapReturn, _ *model.HostFactoryBootstrapWriteReturn) {
			b.ProcessNonceSHA256 = *b.SegmentReturns[2].OriginalSegmentSHA256
		}},
		{"changed_challenge_write", func(_ *model.HostFactoryBootstrapReturn, w *model.HostFactoryBootstrapWriteReturn) {
			w.SegmentReturns[0].OriginalSegmentSHA256 = ptr(strings.Repeat("f", 64))
		}},
		{"private_key_digest_refused", func(b *model.HostFactoryBootstrapReturn, w *model.HostFactoryBootstrapWriteReturn) {
			b.SegmentReturns[1].OriginalSegmentSHA256 = ptr(strings.Repeat("f", 64))
			w.SegmentReturns[1].OriginalSegmentSHA256 = ptr(strings.Repeat("f", 64))
		}},
		{"private_state_refused", func(b *model.HostFactoryBootstrapReturn, w *model.HostFactoryBootstrapWriteReturn) {
			b.SegmentReturns[1].OriginalSegmentHashState = "actual_public_bytes"
			w.SegmentReturns[1].OriginalSegmentHashState = "actual_public_bytes"
		}},
		{"partial_key_read", func(b *model.HostFactoryBootstrapReturn, _ *model.HostFactoryBootstrapWriteReturn) {
			b.SegmentReturns[1].OriginalTotalBytes--
		}},
		{"same_wrong_segment_sizes", func(b *model.HostFactoryBootstrapReturn, w *model.HostFactoryBootstrapWriteReturn) {
			b.SegmentReturns[0].ExpectedBytes = 31
			w.SegmentReturns[0].ExpectedBytes = 31
		}},
		{"missing_public_hash", func(b *model.HostFactoryBootstrapReturn, w *model.HostFactoryBootstrapWriteReturn) {
			b.SegmentReturns[2].OriginalSegmentSHA256 = nil
			w.SegmentReturns[2].OriginalSegmentSHA256 = nil
		}},
		{"wrong_binding_bytes_both", func(b *model.HostFactoryBootstrapReturn, w *model.HostFactoryBootstrapWriteReturn) {
			b.SegmentReturns[2].OriginalSegmentSHA256 = ptr(strings.Repeat("f", 64))
			w.SegmentReturns[2].OriginalSegmentSHA256 = ptr(strings.Repeat("f", 64))
		}},
		{"segment_foreign_subject", func(_ *model.HostFactoryBootstrapReturn, w *model.HostFactoryBootstrapWriteReturn) {
			w.SegmentReturns[1].OriginalCallVector.SubjectOwnerID = "foreign"
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			owner, primitive := "synthetic-source-owner", strings.Repeat("a", 64)
			binding := strings.Repeat("b", 64)
			bindingBytes, _ := hex.DecodeString(binding)
			challenge, bindingDigest := strings.Repeat("c", 64), digest(bindingBytes)
			b := model.HostFactoryBootstrapReturn{OwnerPrimitiveRawSHA256: primitive, BootstrapBindingSchema: "original_host_factory_pre_authority_scope_v4", BootstrapBindingSHA256: binding, ProcessNonceSHA256: challenge}
			w := model.HostFactoryBootstrapWriteReturn{RecipientOwnerID: owner, BindingSchema: b.BootstrapBindingSchema, BindingSHA256: binding}
			for i, n := range []int{32, 64, 32} {
				h := challenge
				if i == 2 {
					h = bindingDigest
				}
				state := "actual_public_bytes"
				sha := ptr(h)
				if i == 1 {
					state, sha = "private_withheld", nil
				}
				b.SegmentReturns[i] = model.HostFactoryBootstrapSegmentReturn{ExpectedBytes: n, OriginalTotalBytes: n, OriginalSegmentHashState: state, OriginalSegmentSHA256: sha}
				w.SegmentReturns[i] = b.SegmentReturns[i]
				w.SegmentReturns[i].OriginalCallVector.SubjectOwnerID = owner
			}
			tt.mutate(&b, &w)
			if (workerOriginalBootstrapPair(owner, primitive, b, w) == nil) != (tt.name == "same_original_public_segments") {
				t.Fatal("bootstrap pair disposition differs")
			}
		})
	}
}

func TestHostWorkerComposerAliveWindowSource(t *testing.T) {
	origin := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithDeadline(context.Background(), origin.Add(30*time.Second))
	defer cancel()
	tests := []struct {
		name   string
		mutate func(*originalNativePhaseReservation, *model.HostFactoryNativeProcess, *model.HostFactoryNativeProcess, *model.HostFactoryNativeProcess, *model.HostFactoryTaskDirectoryRead)
	}{
		{"final_task_close_after_all_polls", func(*originalNativePhaseReservation, *model.HostFactoryNativeProcess, *model.HostFactoryNativeProcess, *model.HostFactoryNativeProcess, *model.HostFactoryTaskDirectoryRead) {
		}},
		{"worker_foreign_parent", func(_ *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, _ *model.HostFactoryTaskDirectoryRead) {
			w.PPID++
		}},
		{"registrar_foreign_parent", func(_ *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, _ *model.HostFactoryTaskDirectoryRead) {
			r.PPID++
		}},
		{"worker_equals_registrar", func(_ *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, _ *model.HostFactoryTaskDirectoryRead) {
			w.PID = r.PID
		}},
		{"foreign_boot", func(_ *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, _ *model.HostFactoryTaskDirectoryRead) {
			w.HostBootID = "foreign"
		}},
		{"foreign_final_task_lifetime", func(_ *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, task *model.HostFactoryTaskDirectoryRead) {
			task.SubjectStartTicks++
		}},
		{"read_before_source_phase", func(p *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, _ *model.HostFactoryTaskDirectoryRead) {
			w.OriginalNativeReadStartedAt = p.calledAt.Add(-time.Nanosecond)
		}},
		{"pin_poll_after_last_task_started", func(_ *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, task *model.HostFactoryTaskDirectoryRead) {
			r.OriginalSubjectNativePin.OriginalObservedAt = task.OriginalSubjectStatBeforeRead.OriginalCalledAt.Add(time.Nanosecond)
		}},
		{"native_stat_close_not_final_poll_join", func(_ *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, task *model.HostFactoryTaskDirectoryRead) {
			task.OriginalSubjectStatAfterRead.OriginalCloseReturnedAt = r.OriginalNativeCloseReturnedAt
		}},
		{"close_before_return", func(_ *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, task *model.HostFactoryTaskDirectoryRead) {
			task.OriginalSubjectStatAfterRead.OriginalCloseReturnedAt = task.OriginalSubjectStatAfterRead.OriginalReturnedAt.Add(-time.Nanosecond)
		}},
		{"return_at_original_deadline", func(p *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, task *model.HostFactoryTaskDirectoryRead) {
			task.OriginalSubjectStatAfterRead.OriginalCloseReturnedAt, _ = p.ctx.Deadline()
		}},
		{"missing_poll_return", func(_ *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, _ *model.HostFactoryTaskDirectoryRead) {
			c.OriginalSubjectNativePin.OriginalObservedAt = time.Time{}
		}},
		{"unbounded_replacement_context", func(p *originalNativePhaseReservation, w, c, r *model.HostFactoryNativeProcess, _ *model.HostFactoryTaskDirectoryRead) {
			p.ctx = context.Background()
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &originalNativePhaseReservation{ctx: ctx, calledAt: origin}
			mk := func(pid, ppid int) model.HostFactoryNativeProcess {
				return model.HostFactoryNativeProcess{PID: pid, PPID: ppid, StartTicks: 7, HostBootID: "synthetic-boot", OriginalNativeReadStartedAt: origin.Add(time.Second), OriginalNativeCloseReturnedAt: origin.Add(3 * time.Second), OriginalSubjectNativePin: model.HostFactoryNativeSubjectPin{OriginalObservedAt: origin.Add(4 * time.Second)}}
			}
			w, c, r := mk(43, 42), mk(42, 41), mk(44, 42)
			task := model.HostFactoryTaskDirectoryRead{SubjectPID: r.PID, SubjectBootID: r.HostBootID, SubjectStartTicks: r.StartTicks, OriginalSubjectStatBeforeRead: model.HostFactoryOriginalIOFact{OriginalCalledAt: origin.Add(5 * time.Second)}, OriginalSubjectStatAfterRead: model.HostFactoryOriginalIOFact{OriginalCalledAt: origin.Add(7 * time.Second), OriginalReturnedAt: origin.Add(8 * time.Second), OriginalCloseReturnedAt: origin.Add(9 * time.Second)}}
			tt.mutate(p, &w, &c, &r, &task)
			if (workerOriginalAliveWindow(p, w, c, r, task) == nil) != (tt.name == "final_task_close_after_all_polls") {
				t.Fatal("source window disposition differs")
			}
		})
	}
}

func TestHostWorkerComposerDescriptorCustodySource(t *testing.T) {
	t.Run("all_22_fields_preserved", func(t *testing.T) {
		vec := model.HostFactoryCallVectorReference{Operation: "synthetic", OriginalHandleID: "handle", OriginalOwnerID: "owner", OwnerPrimitiveRawSHA256: ptr("primitive"), SubjectOwnerID: "subject", FirstOrdinal: 2, LastOrdinal: 4, OriginalCallCount: 2, ManifestRootSHA256: ptr("manifest"), CollectionState: "complete_original_calls"}
		s := model.HostFactoryBootstrapDescriptorSource{Role: "registrar_worker_pidfd", OwnerPrimitiveRawSHA256: "primitive", Device: 1, Inode: 2, Type: "pidfd", Mode: 3, LinkCount: 4, UID: 5, GID: 6, Flags: 7, OriginalDescriptorNumber: 8, DescriptorFlags: 1, OriginalFstatReturnedAt: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), OriginalHandleID: "handle", OriginalAcquisitionCallVector: &vec, OriginalInheritedFromHandleID: ptr("parent"), OriginalFstatCallVector: vec, OriginalFstatCallID: "stat:2", OriginalGetflCallVector: vec, OriginalGetflCallID: "fl:3", OriginalGetfdCallVector: vec, OriginalGetfdCallID: "fd:4"}
		basis := workerOriginalSources{registrar: model.HostFactoryBasalOwnerObservation{Role: "host_registrar"}, registrarPrimitiveSHA: strings.Repeat("a", 64), registrarNativeSHA: strings.Repeat("b", 64)}
		s.OwnerPrimitiveRawSHA256 = basis.registrarPrimitiveSHA
		converted, e := workerOriginalLegacyDescriptor(s, basis)
		if e != nil {
			t.Fatal(e)
		}
		got := reflect.ValueOf(converted)
		want := reflect.ValueOf(s)
		if got.NumField() != 22 || want.NumField() != 22 {
			t.Fatal("descriptor field census changed")
		}
		for i := 0; i < want.NumField(); i++ {
			name := want.Type().Field(i).Name
			if name == "OwnerPrimitiveRawSHA256" {
				if got.FieldByName("OwnerNativeReceiptSHA256").String() != basis.registrarNativeSHA {
					t.Fatal("native owner receipt replaced by Basal primitive")
				}
				continue
			}
			selected := got.FieldByName(name)
			if !selected.IsValid() || !reflect.DeepEqual(selected.Interface(), want.Field(i).Interface()) {
				t.Fatalf("field %s lost", name)
			}
		}
	})
	t.Run("copied_vector_pointers_do_not_alias", func(t *testing.T) {
		v := model.HostFactoryCallVectorReference{OwnerPrimitiveRawSHA256: ptr("old"), ManifestRootSHA256: ptr("root")}
		s := model.HostFactoryBootstrapDescriptorSource{OriginalAcquisitionCallVector: &v, OriginalInheritedFromHandleID: ptr("parent"), OriginalFstatCallVector: v, OriginalGetflCallVector: v, OriginalGetfdCallVector: v}
		basis := workerOriginalSources{registrar: model.HostFactoryBasalOwnerObservation{Role: "host_registrar"}, registrarPrimitiveSHA: strings.Repeat("a", 64), registrarNativeSHA: strings.Repeat("b", 64)}
		s.OwnerPrimitiveRawSHA256 = basis.registrarPrimitiveSHA
		got, e := workerOriginalLegacyDescriptor(s, basis)
		if e != nil {
			t.Fatal(e)
		}
		*s.OriginalAcquisitionCallVector.OwnerPrimitiveRawSHA256 = "changed"
		*s.OriginalAcquisitionCallVector.ManifestRootSHA256 = "changed"
		*s.OriginalInheritedFromHandleID = "changed"
		if *got.OriginalAcquisitionCallVector.OwnerPrimitiveRawSHA256 != "old" || *got.OriginalFstatCallVector.OwnerPrimitiveRawSHA256 != "old" || *got.OriginalGetflCallVector.ManifestRootSHA256 != "root" || *got.OriginalGetfdCallVector.ManifestRootSHA256 != "root" || *got.OriginalInheritedFromHandleID != "parent" {
			t.Fatal("immutable descriptor custody aliased")
		}
	})
	t.Run("unavailable_source_and_empty_owner", func(t *testing.T) {
		for _, p := range []*originalNativePublisher{nil, {}} {
			if out, e := composeOriginalWorkerNative(context.Background(), p, nil, nil, nil, nil); e == nil || len(out) != 0 {
				t.Fatal("empty supplier produced native outputs")
			}
		}
	})
	t.Run("missing_original_acquisition", func(t *testing.T) {
		if _, _, e := workerOriginalPinAcquisition(&originalPin{}, &originalNativePhaseReservation{}); e == nil {
			t.Fatal("missing original acquisition accepted")
		}
	})
	t.Run("missing_selected_descriptor_return", func(t *testing.T) {
		if e := workerOriginalDescriptorReturns(nil, model.HostFactoryBootstrapDescriptorSource{}, nil); e == nil {
			t.Fatal("missing actual return accepted")
		}
	})
}

func TestHostWorkerComposerPurposeGateSource(t *testing.T) {
	// Operation grammar checks ONLY. An admitted tuple is not native evidence.
	tests := []struct {
		name, subject, stage string
		valid                bool
	}{
		{"worker_native_alive_tuple", "host_worker", "native_alive", true},
		{"core_native_alive_missing", "host_exterior", "native_alive", false},
		{"registrar_native_alive_missing", "host_registrar", "native_alive", false},
		{"core_poststart_tuple_not_alive_authority", "host_exterior", "poststart_empty", true},
		{"registrar_poststart_tuple_not_alive_authority", "host_registrar", "poststart_empty", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := capacity.ValidateHostFactoryOperation("native_subject_pidfd_fstat", "host_registrar", tt.subject, tt.stage, "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope")
			if (e == nil) != tt.valid {
				t.Fatal("exact purpose tuple differs")
			}
		})
	}
	t.Run("current141_complete_alive_hold_before_IO", func(t *testing.T) {
		l := &originalLedger{ownerRole: "host_registrar", bindingSchema: "original_host_factory_pre_authority_scope_v4"}
		if workerOriginalAlivePurpose(l) == nil {
			t.Fatal("missing purpose silently substituted")
		}
	})
}

func TestHostWorkerComposerPinAcquisitionSource(t *testing.T) {
	// Synthetic retained membership/grammar only; no PIDFD/syscall is executed.
	origin := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithDeadline(context.Background(), origin.Add(30*time.Second))
	defer cancel()
	cases := []struct {
		name   string
		mutate func(*originalPin, *retainedCall, *originalLedger)
	}{
		{"exact_original_acquisition_pointer", func(*originalPin, *retainedCall, *originalLedger) {}},
		{"copied_handle_pointer_refused", func(p *originalPin, _ *retainedCall, _ *originalLedger) {
			p.handle = &callHandle{id: p.handle.id, ledger: p.handle.ledger, fd: p.handle.fd}
		}},
		{"acquisition_wrong_source_purpose", func(_ *originalPin, r *retainedCall, _ *originalLedger) { r.stage = "poststart_empty" }},
		{"call_uuid_is_not_handle_ordinal", func(_ *originalPin, r *retainedCall, _ *originalLedger) {
			r.fact.OriginalCallID = ptr(r.fact.OriginalHandleID)
		}},
		{"foreign_acquired_handle", func(p *originalPin, _ *retainedCall, _ *originalLedger) {
			p.source.OriginalAcquisitionCallVector.OriginalHandleID = "foreign"
		}},
		{"counter_mismatch", func(_ *originalPin, r *retainedCall, _ *originalLedger) {
			r.fact.OriginalCallID = ptr(r.fact.OriginalHandleID + ":2")
		}},
		{"unknown_pending_return", func(_ *originalPin, r *retainedCall, _ *originalLedger) { r.fact.OriginalState = "called_pending" }},
		{"wrong_original_requested_pid", func(_ *originalPin, r *retainedCall, _ *originalLedger) {
			r.fact.OriginalNativeReturn.RequestedPID = ptr(99)
		}},
		{"wrong_actual_descriptor", func(_ *originalPin, r *retainedCall, _ *originalLedger) {
			r.fact.OriginalNativeReturn.OriginalScalar = ptr(int64(6))
		}},
		{"unreturned_original_error_flag", func(_ *originalPin, r *retainedCall, _ *originalLedger) {
			r.fact.OriginalNativeReturn.OriginalErrorPresent = nil
		}},
		{"wrong_original_returned_handle", func(_ *originalPin, r *retainedCall, _ *originalLedger) {
			r.fact.OriginalNativeReturn.ReturnedDescriptors[0].OriginalHandleID = "foreign"
		}},
		{"returned_before_called", func(_ *originalPin, r *retainedCall, _ *originalLedger) { r.fact.OriginalReturnedAt = ptr(origin) }},
		{"duplicate_original_acquisition_row", func(p *originalPin, r *retainedCall, l *originalLedger) {
			l.calls[p.handle.id+"\x00native_subject_pidfd_open"] = append(l.calls[p.handle.id+"\x00native_subject_pidfd_open"], r)
		}},
		{"foreign_subject_ledger", func(_ *originalPin, _ *retainedCall, l *originalLedger) { l.subjects["host_worker"] = "foreign" }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			id := "00000000-0000-4000-8000-000000000001"
			primitive := strings.Repeat("a", 64)
			l := &originalLedger{ctx: ctx, deadline: origin.Add(30 * time.Second), ownerID: "registrar", primitiveSHA: primitive, subjects: map[string]string{"host_worker": "worker"}, calls: map[string][]*retainedCall{}}
			h := &callHandle{id: id, ledger: l, fd: 5}
			l.handles = map[string]*callHandle{id: h}
			ref := model.HostFactoryCallVectorReference{Operation: "native_subject_pidfd_open", OriginalHandleID: id, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: &primitive, SubjectOwnerID: "worker", FirstOrdinal: 1, LastOrdinal: 1, OriginalCallCount: 1, CollectionState: "complete_original_calls"}
			pin := &originalPin{handle: h, pid: 43, source: model.HostFactoryBootstrapDescriptorSource{OriginalHandleID: id, OriginalDescriptorNumber: 5, OriginalAcquisitionCallVector: &ref}}
			row := &retainedCall{subjectRole: "host_worker", stage: "native_alive", fact: model.HostFactoryPrimitiveIOReturn{Operation: ref.Operation, OriginalHandleID: id, OwnerPrimitiveRawSHA256: &primitive, SubjectOwnerID: "worker", OriginalCallOrdinal: ptr(uint64(1)), OriginalCallID: ptr(id + ":1"), OriginalState: "returned", OriginalCalledAt: ptr(origin.Add(time.Second)), OriginalReturnedAt: ptr(origin.Add(2 * time.Second)), OriginalReturnClass: "success", OriginalOperationDeadline: l.deadline, OriginalNativeReturn: &model.HostFactoryNativeCallReturn{Kind: "unix_pidfd_open", RequestedFlags: ptr(uint32(0)), RequestedPID: ptr(43), OriginalScalar: ptr(int64(5)), OriginalErrno: ptr(uint32(0)), OriginalErrorPresent: ptr(false), ReturnedDescriptors: []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: id, OriginalDescriptorNumber: 5}}}}}
			l.calls[id+"\x00native_subject_pidfd_open"] = []*retainedCall{row}
			tt.mutate(pin, row, l)
			called, returned, e := workerOriginalPinAcquisition(pin, &originalNativePhaseReservation{ctx: ctx, calledAt: origin})
			if (e == nil) != (tt.name == "exact_original_acquisition_pointer") {
				t.Fatal("exact acquisition disposition differs")
			}
			if e == nil && (!called.Equal(*row.fact.OriginalCalledAt) || !returned.Equal(*row.fact.OriginalReturnedAt)) {
				t.Fatal("original call times replaced")
			}
		})
	}
}

func TestHostWorkerComposerExactPurposeCensusSource(t *testing.T) {
	// List/grammar discrimination only; not Source/native approval or execution.
	t.Run("Core_process13_without_Task", func(t *testing.T) {
		ops := workerOriginalAliveOperationList("host_exterior")
		if len(ops) != 13 {
			t.Fatal("Core process operation count")
		}
		for _, op := range ops {
			if op == "task_inventory_getdents" {
				t.Fatal("Core has no final Task reader")
			}
		}
	})
	t.Run("registrar_process13_and_final_Task1", func(t *testing.T) {
		ops := workerOriginalAliveOperationList("host_registrar")
		n := 0
		for _, op := range ops {
			if op == "task_inventory_getdents" {
				n++
			}
		}
		if len(ops) != 14 || n != 1 {
			t.Fatal("registrar final Task operation count")
		}
	})
	t.Run("ALL3_proc_owner_calls_required_for_both", func(t *testing.T) {
		for _, subject := range []string{"host_exterior", "host_registrar"} {
			ops := workerOriginalAliveOperationList(subject)
			for _, needed := range []string{"proc_owner_directory_open", "proc_owner_directory_fstat", "proc_owner_directory_close"} {
				found := 0
				for _, op := range ops {
					if op == needed {
						found++
					}
				}
				if found != 1 {
					t.Fatal("missing or duplicate original proc owner", subject, needed)
				}
			}
		}
	})
	t.Run("no_duplicate_original_operation", func(t *testing.T) {
		for _, subject := range []string{"host_exterior", "host_registrar"} {
			seen := map[string]bool{}
			for _, op := range workerOriginalAliveOperationList(subject) {
				if seen[op] {
					t.Fatal("duplicate operation")
				}
				seen[op] = true
			}
		}
	})
	t.Run("unknown_subject_has_no_recipe", func(t *testing.T) {
		if workerOriginalAliveOperationList("host_worker") != nil {
			t.Fatal("worker handled in its distinct leaf recipe")
		}
	})
	t.Run("returned_recipe_does_not_mutate_next_capture", func(t *testing.T) {
		ops := workerOriginalAliveOperationList("host_exterior")
		ops[0] = "changed"
		if workerOriginalAliveOperationList("host_exterior")[0] == "changed" {
			t.Fatal("recipe mutable alias")
		}
	})
}

func TestHostWorkerComposerNilOriginalRowsSource(t *testing.T) {
	// Corrupt/missing private retained custody must refuse before dereference.
	// No original syscall or native/SQL Source basis exists in these inputs.
	t.Run("nil_acquisition_row_HOLD", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
		defer cancel()
		l := &originalLedger{ownerID: "owner", primitiveSHA: "primitive", calls: map[string][]*retainedCall{"handle\x00native_subject_pidfd_open": {nil}}}
		h := &callHandle{id: "handle", ledger: l, fd: 4}
		p := &originalPin{handle: h, source: model.HostFactoryBootstrapDescriptorSource{OriginalHandleID: h.id, OriginalDescriptorNumber: h.fd, OriginalAcquisitionCallVector: &model.HostFactoryCallVectorReference{Operation: "native_subject_pidfd_open", OriginalHandleID: h.id, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: &l.primitiveSHA, CollectionState: "complete_original_calls", FirstOrdinal: 1, LastOrdinal: 1, OriginalCallCount: 1}}}
		if _, _, e := workerOriginalPinAcquisition(p, &originalNativePhaseReservation{ctx: ctx}); e == nil {
			t.Fatal("nil row accepted")
		}
	})
	t.Run("nil_selected_descriptor_row_HOLD", func(t *testing.T) {
		l := &originalLedger{calls: map[string][]*retainedCall{"handle\x00descriptor_fstat": {nil}}}
		h := &callHandle{id: "handle", ledger: l, fd: 4}
		source := model.HostFactoryBootstrapDescriptorSource{OriginalHandleID: h.id, OriginalDescriptorNumber: h.fd, OriginalFstatCallID: "handle:1"}
		if e := workerOriginalDescriptorReturns(h, source, &originalNativePhaseReservation{ctx: context.Background()}); e == nil {
			t.Fatal("nil selected row accepted")
		}
	})
}

func TestHostWorkerComposerSeparateStartCommandSource(t *testing.T) {
	// These are synthetic Source identity inputs. No command is started, and
	// neither record is an actual native owner or a supplied approval.
	origin := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		mutate func(*model.HostFactoryOriginalStartReturn)
	}{
		{"distinct_parent_worker_and_prepared_create_handles", func(*model.HostFactoryOriginalStartReturn) {}},
		{"foreign_scope", func(x *model.HostFactoryOriginalStartReturn) { x.PreAuthorityScopeSHA256 = strings.Repeat("f", 64) }},
		{"foreign_worker_primitive", func(x *model.HostFactoryOriginalStartReturn) { x.WorkerPrimitiveRawSHA256 = strings.Repeat("f", 64) }},
		{"foreign_bootstrap_write", func(x *model.HostFactoryOriginalStartReturn) {
			x.OriginalBootstrapWriteReturnSHA256 = strings.Repeat("f", 64)
		}},
		{"foreign_worker_pid", func(x *model.HostFactoryOriginalStartReturn) { x.OriginalWorkerPID++ }},
		{"start_called_after_child_basal", func(x *model.HostFactoryOriginalStartReturn) {
			x.OriginalWorkerStartCalledAt = origin.Add(time.Nanosecond)
		}},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			worker := model.HostFactoryBasalOwnerObservation{}
			worker.Calls[0].OriginalScalar = 23
			worker.Calls[0].OriginalCalledAt = origin
			scope, workerSHA, writeSHA := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
			start := model.HostFactoryOriginalStartReturn{PreAuthorityScopeSHA256: scope, WorkerPrimitiveRawSHA256: workerSHA, OriginalBootstrapWriteReturnSHA256: writeSHA, OriginalWorkerPID: 23, OriginalWorkerStartCalledAt: origin.Add(-time.Nanosecond), OriginalCommandHandleID: "00000000-0000-4000-8000-000000000001"}
			plan := model.HostFactoryPreparedCreatePlan{OriginalCreateCommandHandleID: "00000000-0000-4000-8000-000000000002"}
			if start.OriginalCommandHandleID == plan.OriginalCreateCommandHandleID {
				t.Fatal("synthetic distinct owning objects accidentally equal")
			}
			tt.mutate(&start)
			if (workerOriginalStartPair(start, worker, scope, workerSHA, writeSHA) == nil) != (tt.name == "distinct_parent_worker_and_prepared_create_handles") {
				t.Fatal("original Start identity or chronology join changed")
			}
		})
	}
}

func TestHostWorkerComposerExplicitSourceProfileSource(t *testing.T) {
	// Proposed profile validates structure only. No compiled Source registry,
	// Realm, key, actual native IO, SQL-FIRST or admission is supplied here.
	t.Run("nil_profile_default_hold", func(t *testing.T) {
		if workerOriginalAlivePurpose(&originalLedger{ownerRole: "host_registrar", bindingSchema: "original_host_factory_pre_authority_scope_v4"}) == nil {
			t.Fatal("default implicitly selected Source extension")
		}
	})
	t.Run("zero_profile_hold", func(t *testing.T) {
		if workerOriginalAlivePurpose(&originalLedger{ownerRole: "host_registrar", bindingSchema: "original_host_factory_pre_authority_scope_v4", sourceProfile: &capacity.HostFactorySourceProfile{}}) == nil {
			t.Fatal("zero profile accepted")
		}
	})
	t.Run("explicit_proposed_profile_structure_only", func(t *testing.T) {
		if workerOriginalAlivePurpose(&originalLedger{ownerRole: "host_registrar", bindingSchema: "original_host_factory_pre_authority_scope_v4", sourceProfile: capacity.ProposedHostFactorySourceProfileV1()}) != nil {
			t.Fatal("fixed declared tuple structure refused")
		}
	})
	t.Run("foreign_owner_hold", func(t *testing.T) {
		if workerOriginalAlivePurpose(&originalLedger{ownerRole: "host_exterior", bindingSchema: "original_host_factory_pre_authority_scope_v4", sourceProfile: capacity.ProposedHostFactorySourceProfileV1()}) == nil {
			t.Fatal("owner relabeled")
		}
	})
	t.Run("ordinary_binding_not_scope", func(t *testing.T) {
		if workerOriginalAlivePurpose(&originalLedger{ownerRole: "host_registrar", bindingSchema: "factory_ordinary_source_binding_v4", sourceProfile: capacity.ProposedHostFactorySourceProfileV1()}) == nil {
			t.Fatal("ordinary binding relabeled")
		}
	})
	t.Run("native_kind_null_cannot_alias_fstat", func(t *testing.T) {
		profile := capacity.ProposedHostFactorySourceProfileV1()
		if profile.ValidateOperation("native_subject_pidfd_fstat", "host_registrar", "host_exterior", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", nil) == nil {
			t.Fatal("missing actual native kind accepted")
		}
	})
	t.Run("kind_mutation_cannot_alias_poll", func(t *testing.T) {
		kind := "unix_fstat"
		if capacity.ProposedHostFactorySourceProfileV1().ValidateOperation("native_subject_alive_poll", "host_registrar", "host_exterior", "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", &kind) == nil {
			t.Fatal("poll kind relabeled")
		}
	})
	t.Run("all_operation_kinds_match_fixed_reader", func(t *testing.T) {
		for _, subject := range []string{"host_exterior", "host_registrar"} {
			for _, op := range workerOriginalAliveOperationList(subject) {
				if capacity.ProposedHostFactorySourceProfileV1().ValidateOperation(op, "host_registrar", subject, "native_alive", "original_host_factory_pre_authority_scope_v4", "HostFactorySignedEnvelope", workerOriginalAliveNativeKind(op)) != nil {
					t.Fatalf("declared Source tuple %s/%s has wrong kind", subject, op)
				}
			}
		}
	})
}

func TestHostWorkerComposerNativeOwnerReceiptSource(t *testing.T) {
	// Private Source pair only. A synthetic receipt string never authenticates
	// a native leaf; production basis must come from the exact cached original.
	cases := []struct {
		name   string
		mutate func(*workerOriginalSources)
	}{
		{"distinct_original_native_leaf_receipt", func(*workerOriginalSources) {}},
		{"basal_hash_is_not_native_leaf_receipt", func(b *workerOriginalSources) { b.registrarNativeSHA = b.registrarPrimitiveSHA }},
		{"foreign_leaf_primitive", func(b *workerOriginalSources) { b.registrarPrimitiveSHA = strings.Repeat("f", 64) }},
		{"foreign_leaf_owner_role", func(b *workerOriginalSources) { b.registrar.Role = "host_exterior" }},
		{"unknown_original_native_receipt", func(b *workerOriginalSources) { b.registrarNativeSHA = "" }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			basis := workerOriginalSources{registrar: model.HostFactoryBasalOwnerObservation{Role: "host_registrar"}, registrarPrimitiveSHA: strings.Repeat("a", 64), registrarNativeSHA: strings.Repeat("b", 64)}
			s := model.HostFactoryBootstrapDescriptorSource{OwnerPrimitiveRawSHA256: basis.registrarPrimitiveSHA}
			tt.mutate(&basis)
			got, e := workerOriginalLegacyDescriptor(s, basis)
			if (e == nil) != (tt.name == "distinct_original_native_leaf_receipt") {
				t.Fatal("native receipt ownership join changed")
			}
			if e == nil && got.OwnerNativeReceiptSHA256 != basis.registrarNativeSHA {
				t.Fatal("actual selected native receipt lost")
			}
		})
	}
}

// Source assembly input: native_worker_frame_privacy_source_test_fragment.go
// Private memory projection fixture only. No syscall, actual original,
// signature/Source installation, classifier authentication or native proof.
func workerFramePrivacySourceFixture(t *testing.T) (*originalWorkerReadCustody, originalWorkerPublicFrameBasis) {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
	t.Cleanup(cancel)
	profile := capacity.ProposedHostFactorySourceProfileV1()
	id := "11111111-1111-4111-8111-111111111111"
	l := &originalLedger{ctx: ctx, deadline: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), ownerRole: "host_worker", sourceProfile: profile, subjects: map[string]string{"host_worker": id}, handles: map[string]*callHandle{}, calls: map[string][]*retainedCall{}, collection: &OriginalIOCollection{sourceProfile: profile, bodies: map[string][]byte{}}}
	h := &callHandle{id: id, ledger: l}
	l.handles[id] = h
	frame := originalWorkerEarlyFrame{Schema: "source_private_original_worker_early_frame_v1", RootPreparationEnvelopeRaw: []byte("synthetic-public-root"), ScopeEnvelopeRaw: []byte("synthetic-public-scope"), PhaseOwnerEnvelopeRaw: []byte("synthetic-public-phase"), OriginalEffectiveContextDeadline: l.deadline.UTC().Format(time.RFC3339Nano)}
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(raw)))
	read := &originalWorkerReadCustody{handle: h, ctx: ctx, stage: "prepared_create", prefix: prefix, raw: raw}
	for n, data := range [][]byte{prefix, raw[:7], raw[7:]} {
		ordinal := uint64(n + 1)
		called := time.Date(2020, 1, 1, 0, 0, n*2, 0, time.UTC)
		returned := called.Add(time.Second)
		row := &retainedCall{subjectRole: "host_worker", stage: "prepared_create", originalRaw: bytes.Clone(data), originalRawKnown: true, fact: model.HostFactoryPrimitiveIOReturn{Operation: "control_frame_read", OriginalHandleID: id, OriginalCallID: ptr(id + ":" + []string{"1", "2", "3"}[n]), OriginalCallOrdinal: &ordinal, SubjectOwnerID: id, OriginalState: "returned", OriginalCalledAt: &called, OriginalReturnedAt: &returned, OriginalCount: ptr(int64(len(data))), OriginalHashState: "unknown_original_bytes", OriginalReturnClass: "success", OriginalEOF: ptr(false), OriginalOperationDeadline: l.deadline}}
		read.rows = append(read.rows, row)
		l.calls[id+"\x00control_frame_read"] = append(l.calls[id+"\x00control_frame_read"], row)
	}
	h.workerFrameReads = []*originalWorkerReadCustody{read}
	return read, originalWorkerPublicFrameBasis{read: read, profile: profile, canonicalFrame: bytes.Clone(raw), schema: frame.Schema, effectiveContext: ctx, effectiveDeadline: l.deadline}
}

func TestHostWorkerFramePrivateReadProjectionSource(t *testing.T) {
	for _, name := range []string{"same_private_original_projection_only", "no_authenticated_lexical_basis", "foreign_basis_reader", "unapproved_profile_missing", "noncanonical_classified_frame", "unknown_family", "private_or_partial_read_error", "pending_original_return", "unknown_actual_raw", "changed_raw_vs_count", "body_does_not_equal_original_segments", "foreign_actual_row_pointer", "duplicate_original_row_pointer", "wrong_handle_registration", "already_first_published", "already_final_published", "pending_original_published", "collection_exposed_without_row_flags", "unsafe_public_hash_preexists", "unknown_original_time", "foreign_subject", "wrong_actual_stage", "actual_EOF_before_frame_end", "unknown_call_identity", "expired_or_canceled_reader"} {
		t.Run(name, func(t *testing.T) {
			read, basis := workerFramePrivacySourceFixture(t)
			h, l, row := read.handle, read.handle.ledger, read.rows[1]
			switch name {
			case "no_authenticated_lexical_basis":
				basis = originalWorkerPublicFrameBasis{}
			case "foreign_basis_reader":
				basis.read = &originalWorkerReadCustody{}
			case "unapproved_profile_missing":
				basis.profile = nil
			case "noncanonical_classified_frame":
				basis.canonicalFrame = append(basis.canonicalFrame, '\n')
			case "unknown_family":
				basis.schema = "private-credential-frame"
			case "private_or_partial_read_error":
				read.cause = errors.New("synthetic partial")
			case "pending_original_return":
				row.fact.OriginalState = "called_pending"
			case "unknown_actual_raw":
				row.originalRawKnown = false
			case "changed_raw_vs_count":
				row.fact.OriginalCount = ptr(int64(999))
			case "body_does_not_equal_original_segments":
				row.originalRaw = bytes.Repeat([]byte{'x'}, len(row.originalRaw))
			case "foreign_actual_row_pointer":
				copy := *row
				l.calls[h.id+"\x00control_frame_read"][1] = &copy
			case "duplicate_original_row_pointer":
				l.calls[h.id+"\x00control_frame_read"] = append(l.calls[h.id+"\x00control_frame_read"], row)
			case "wrong_handle_registration":
				copy := *h
				l.handles[h.id] = &copy
			case "already_first_published":
				row.firstSHA = strings.Repeat("a", 64)
			case "already_final_published":
				row.finalSHA = strings.Repeat("a", 64)
			case "pending_original_published":
				row.pendingPublished = true
			case "collection_exposed_without_row_flags":
				raw, _ := json.Marshal(model.HostFactoryCallVectorChunk{OriginalCalls: []model.HostFactoryPrimitiveIOReturn{row.fact}})
				l.collection.bodies["synthetic-exposed-original"] = raw
			case "unsafe_public_hash_preexists":
				row.fact.OriginalSHA256 = ptr(strings.Repeat("a", 64))
			case "unknown_original_time":
				row.fact.OriginalReturnedAt = ptr(time.Time{})
			case "foreign_subject":
				row.fact.SubjectOwnerID = "22222222-2222-4222-8222-222222222222"
			case "wrong_actual_stage":
				row.stage = "choice_control"
			case "actual_EOF_before_frame_end":
				row.fact.OriginalEOF = ptr(true)
				row.fact.OriginalReturnClass = "eof"
			case "unknown_call_identity":
				row.fact.OriginalCallID = ptr(h.id + ":99")
			case "expired_or_canceled_reader":
				owned, cancel := context.WithCancel(read.ctx)
				cancel()
				read.ctx = owned
			}
			before := make([]model.HostFactoryPrimitiveIOReturn, len(read.rows))
			for n, r := range read.rows {
				before[n] = r.fact
			}
			err := classifyOriginalWorkerFrame(read, basis)
			if (err == nil) != (name == "same_private_original_projection_only") {
				t.Fatal("unknown/private/publication custody changed")
			}
			if err != nil {
				for n, r := range read.rows {
					if r.fact.OriginalHashState != before[n].OriginalHashState || r.fact.OriginalSHA256 != before[n].OriginalSHA256 {
						t.Fatal("failed classification mutated original hash")
					}
				}
			} else {
				for n, r := range read.rows {
					if r.fact.OriginalSHA256 == nil || *r.fact.OriginalSHA256 != digest(r.originalRaw) || r.fact.OriginalHashState != "actual_public_bytes" || !r.fact.OriginalReturnedAt.Equal(*before[n].OriginalReturnedAt) || r.fact.OriginalReturnClass != before[n].OriginalReturnClass || *r.fact.OriginalEOF != *before[n].OriginalEOF {
						t.Fatal("classification replaced an actual completion")
					}
				}
				if classifyOriginalWorkerFrame(read, basis) == nil {
					t.Fatal("projection can repeat after original completion")
				}
			}
		})
	}
}

// These cases exercise only the private projection publication barrier. They
// use synthetic contexts/memory and run remotely; no Source crypto/native/IO.
func workerFramePrivacyOriginals(t *testing.T, read *originalWorkerReadCustody) ([]byte, [][]byte) {
	t.Helper()
	facts := make([]model.HostFactoryPrimitiveIOReturn, len(read.rows))
	raw := make([][]byte, len(read.rows))
	for n, row := range read.rows {
		facts[n] = row.fact
		raw[n] = bytes.Clone(row.originalRaw)
	}
	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	return encoded, raw
}
func workerFramePrivacyUnchanged(t *testing.T, read *originalWorkerReadCustody, before []byte, originalRaw [][]byte) {
	t.Helper()
	facts := make([]model.HostFactoryPrimitiveIOReturn, len(read.rows))
	for n, row := range read.rows {
		facts[n] = row.fact
		if row.fact.OriginalSHA256 != nil || row.fact.OriginalHashState != "unknown_original_bytes" || !bytes.Equal(row.originalRaw, originalRaw[n]) {
			t.Fatal("refused barrier exposed or replaced original completion")
		}
	}
	after, err := json.Marshal(facts)
	if err != nil || !bytes.Equal(before, after) || read.classified {
		t.Fatal("refused barrier mutated original facts")
	}
}
func TestHostWorkerFrameAuthenticatedCutoffSource(t *testing.T) {
	for _, name := range []string{"missing_effective_context", "mismatched_authenticated_deadline", "effective_deadline_extends_original", "actual_return_after_authenticated_cutoff", "expired_early_cutoff_original_live", "expired_choice_cutoff_original_live"} {
		t.Run(name, func(t *testing.T) {
			read, basis := workerFramePrivacySourceFixture(t)
			switch name {
			case "missing_effective_context":
				basis.effectiveContext = nil
			case "mismatched_authenticated_deadline":
				basis.effectiveDeadline = basis.effectiveDeadline.Add(-time.Second)
			case "effective_deadline_extends_original":
				ctx, cancel := context.WithDeadline(context.Background(), basis.effectiveDeadline.Add(time.Hour))
				defer cancel()
				basis.effectiveContext = ctx
				basis.effectiveDeadline, _ = ctx.Deadline()
			case "actual_return_after_authenticated_cutoff":
				ctx, cancel := context.WithDeadline(read.ctx, time.Now().Add(time.Hour))
				defer cancel()
				basis.effectiveContext = ctx
				basis.effectiveDeadline, _ = ctx.Deadline()
				read.rows[2].fact.OriginalReturnedAt = ptr(basis.effectiveDeadline.Add(time.Second))
			case "expired_early_cutoff_original_live", "expired_choice_cutoff_original_live":
				ctx, cancel := context.WithDeadline(read.ctx, time.Now().Add(-time.Second))
				defer cancel()
				basis.effectiveContext = ctx
				basis.effectiveDeadline, _ = ctx.Deadline()
				if name == "expired_choice_cutoff_original_live" {
					read.stage = "choice_control"
					basis.schema = "source_private_original_worker_late_frame_v1"
					for _, row := range read.rows {
						row.stage = read.stage
					}
				}
			}
			before, raw := workerFramePrivacyOriginals(t, read)
			if classifyOriginalWorkerFrame(read, basis) == nil {
				t.Fatal("foreign/late authenticated cutoff admitted")
			}
			workerFramePrivacyUnchanged(t, read, before, raw)
			if read.ctx.Err() != nil {
				t.Fatal("test did not preserve live original reader context")
			}
		})
	}
}
func TestHostWorkerFrameProjectionWaitSource(t *testing.T) {
	for _, name := range []string{"cancel_original_waiting_ledger", "expire_original_waiting_ledger", "expire_early_cutoff_waiting_collection", "expire_choice_cutoff_waiting_collection"} {
		t.Run(name, func(t *testing.T) {
			read, basis := workerFramePrivacySourceFixture(t)
			h, l := read.handle, read.handle.ledger
			var cancel context.CancelFunc
			var original context.Context
			if name == "cancel_original_waiting_ledger" {
				original, cancel = context.WithCancel(read.ctx)
				read.ctx = original
				basis.effectiveContext = original
			} else if name == "expire_original_waiting_ledger" {
				original, cancel = context.WithDeadline(read.ctx, time.Now().Add(2*time.Second))
				read.ctx = original
				basis.effectiveContext = original
				basis.effectiveDeadline, _ = original.Deadline()
			} else {
				original, cancel = context.WithDeadline(read.ctx, time.Now().Add(2*time.Second))
				basis.effectiveContext = original
				basis.effectiveDeadline, _ = original.Deadline()
				if name == "expire_choice_cutoff_waiting_collection" {
					read.stage = "choice_control"
					basis.schema = "source_private_original_worker_late_frame_v1"
					for _, row := range read.rows {
						row.stage = read.stage
					}
				}
			}
			defer cancel()
			before, raw := workerFramePrivacyOriginals(t, read)
			collection := name == "expire_early_cutoff_waiting_collection" || name == "expire_choice_cutoff_waiting_collection"
			if collection {
				l.collection.mu.Lock()
			} else {
				l.mu.Lock()
			}
			var unlock func()
			if collection {
				unlock = l.collection.mu.Unlock
			} else {
				unlock = l.mu.Unlock
			}
			locked := true
			defer func() {
				if locked {
					unlock()
				}
			}()
			done := make(chan error, 1)
			go func() { done <- classifyOriginalWorkerFrame(read, basis) }()
			// Owning h.mu while our later publication lock is held establishes
			// that the projector passed its initial guard and is blocked inside
			// the publication barrier, rather than cancelled before entry.
			limit := time.Now().Add(5 * time.Second)
			for h.mu.TryLock() {
				h.mu.Unlock()
				if time.Now().After(limit) {
					t.Fatal("projector never reached held publication lock")
				}
				runtime.Gosched()
			}
			if name == "cancel_original_waiting_ledger" {
				cancel()
			} else {
				<-original.Done()
			}
			unlock()
			locked = false
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("cancelled/expired publication barrier admitted")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("projector did not return after actual lock release")
			}
			workerFramePrivacyUnchanged(t, read, before, raw)
			if collection && read.ctx.Err() != nil {
				t.Fatal("narrow cutoff replaced original live context")
			}
			// Same original rows remain unknown, and the identical cancelled
			// Source basis cannot be used to repair/retry this projection.
			if classifyOriginalWorkerFrame(read, basis) == nil {
				t.Fatal("expired attempt can be repaired")
			}
			workerFramePrivacyUnchanged(t, read, before, raw)
			if !reflect.DeepEqual(read.rows[0].originalRaw, raw[0]) {
				t.Fatal("original binary prefix changed")
			}
		})
	}
}

// Source assembly input: native_worker_io_index_codec_source_test_fragment.go
// CI ONLY: unsigned opaque synthetic byte/metadata kernels, not Source-auth,
// native syscall facts, actual file custody, signatures, SQL FIRST or permission.
func workerIOTestIdentity() originalWorkerIOIndexIdentity {
	return originalWorkerIOIndexIdentity{Phase: "prepared", FactoryRootID: "11111111-1111-4111-8111-111111111111", RootPreparationSHA256: strings.Repeat("a", 64), SourceApprovalSHA256: strings.Repeat("b", 64), CreatorOwnerID: "22222222-2222-4222-8222-222222222222", WorkerOwnerID: "22222222-2222-4222-8222-222222222222", WorkerBasalSHA256: strings.Repeat("c", 64), BindingSchema: "original_host_factory_pre_authority_scope_v4", BindingSHA256: strings.Repeat("d", 64), OriginalEffectiveContextDeadline: "2030-01-01T00:00:00Z"}
}
func workerIOTestOriginals(n int) []originalNativeSignedIO {
	out := []originalNativeSignedIO{}
	for i := 0; i < n; i++ {
		body := []byte(fmt.Sprintf("unsigned-source-only-body-%d", i))
		envelope := []byte(fmt.Sprintf("unsigned-source-only-envelope-%d", i))
		out = append(out, originalNativeSignedIO{selector: "io-calls/33333333-3333-4333-8333-333333333333/chunk/" + digest(body), body: body, envelope: envelope, purposes: []capacity.HostFactorySourceCallPurpose{}})
	}
	return out
}
func workerIOTestFiles(files []originalNativeTransferFile) map[string][]byte {
	out := map[string][]byte{}
	for _, f := range files {
		out[f.basename] = bytes.Clone(f.raw)
	}
	return out
}
func TestWorkerIOIndexIdentitySource(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*originalWorkerIOIndexIdentity)
		accept bool
	}{
		{"Creator_is_exact_worker", nil, true},
		{"distinct_creator_not_fabricated", func(x *originalWorkerIOIndexIdentity) { x.CreatorOwnerID = x.FactoryRootID }, false},
		{"Root_cannot_equal_worker", func(x *originalWorkerIOIndexIdentity) { x.FactoryRootID = x.WorkerOwnerID }, false},
		{"unknown_phase", func(x *originalWorkerIOIndexIdentity) { x.Phase = "rpc" }, false},
		{"choice_exact_phase", func(x *originalWorkerIOIndexIdentity) { x.Phase = "choice" }, true},
		{"closing_is_bookkeeping_only", func(x *originalWorkerIOIndexIdentity) { x.Phase = "closing" }, true},
		{"noncanonical_UUID", func(x *originalWorkerIOIndexIdentity) {
			x.WorkerOwnerID = "22222222-2222-4222-8222-22222222222A"
			x.CreatorOwnerID = x.WorkerOwnerID
		}, false},
		{"zero_UUID", func(x *originalWorkerIOIndexIdentity) { x.FactoryRootID = "00000000-0000-0000-0000-000000000000" }, false},
		{"ordinary_is_not_Scope", func(x *originalWorkerIOIndexIdentity) { x.BindingSchema = "factory_ordinary_source_binding_v4" }, false},
		{"unknown_digest", func(x *originalWorkerIOIndexIdentity) { x.SourceApprovalSHA256 = "" }, false},
		{"UTC_offset_is_not_canonical", func(x *originalWorkerIOIndexIdentity) {
			x.OriginalEffectiveContextDeadline = "2030-01-01T00:00:00+00:00"
		}, false},
		{"redundant_fraction_is_not_canonical", func(x *originalWorkerIOIndexIdentity) {
			x.OriginalEffectiveContextDeadline = "2030-01-01T00:00:00.000Z"
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := workerIOTestIdentity()
			if tc.mutate != nil {
				tc.mutate(&x)
			}
			if (originalWorkerIOIdentityValid(x) == nil) != tc.accept {
				t.Fatal("Source-only identity expectation differed")
			}
		})
	}
}
func TestWorkerIOIndexWholeMetadataTreeSource(t *testing.T) {
	for _, n := range []int{1, 17, 257} {
		t.Run(fmt.Sprintf("whole_reference_tree_%d", n), func(t *testing.T) {
			id := workerIOTestIdentity()
			originals := workerIOTestOriginals(n)
			before := append([]originalNativeSignedIO{}, originals...)
			raw, files, want, err := buildOriginalWorkerIOIndex(id, originals)
			if err != nil {
				t.Fatal(err)
			}
			data := workerIOTestFiles(files)
			calls := map[string]int{}
			got, err := resolveOriginalWorkerIOIndex(id, raw, func(name string, count int, sha string) ([]byte, error) {
				calls[name]++
				b, ok := data[name]
				if !ok || len(b) != count || digest(b) != sha {
					return nil, errors.New("synthetic-basis-unknown")
				}
				return bytes.Clone(b), nil
			})
			if err != nil || !reflect.DeepEqual(got, want) || len(calls) != len(files) || !reflect.DeepEqual(before, originals) {
				t.Fatalf("whole readonly metadata %v", err)
			}
			for _, count := range calls {
				if count != 1 {
					t.Fatal("original node reread")
				}
			}
			for _, f := range files {
				if f.getdents {
					t.Fatal("metadata became native raw bytes")
				}
			}
		})
	}
	cases := []struct {
		name   string
		mutate func([]originalNativeSignedIO) []originalNativeSignedIO
	}{
		{"identical_snapshot_duplicate_refused", func(x []originalNativeSignedIO) []originalNativeSignedIO { return append(x, x[0]) }},
		{"same_selector_different_original_refused", func(x []originalNativeSignedIO) []originalNativeSignedIO {
			y := x[0]
			y.envelope = []byte("foreign-source-only-envelope")
			return append(x, y)
		}},
		{"unknown_purposes_refused", func(x []originalNativeSignedIO) []originalNativeSignedIO { x[0].purposes = nil; return x }},
		{"whole_body_cap_plus_one_no_trim", func(x []originalNativeSignedIO) []originalNativeSignedIO {
			x[0].body = bytes.Repeat([]byte{'x'}, 65537)
			return x
		}},
		{"whole_envelope_cap_plus_one_no_trim", func(x []originalNativeSignedIO) []originalNativeSignedIO {
			x[0].envelope = bytes.Repeat([]byte{'x'}, 65537)
			return x
		}},
		{"unknown_selector_family_refused", func(x []originalNativeSignedIO) []originalNativeSignedIO {
			x[0].selector = strings.Replace(x[0].selector, "/chunk/", "/failure/", 1)
			return x
		}},
		{"empty_snapshot_is_not_absence", func(_ []originalNativeSignedIO) []originalNativeSignedIO { return []originalNativeSignedIO{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := buildOriginalWorkerIOIndex(workerIOTestIdentity(), tc.mutate(workerIOTestOriginals(1)))
			if err == nil {
				t.Fatal("unknown/duplicate/oversized whole originals accepted")
			}
		})
	}
	t.Run("flat_complete_roster_cap_holds_without_trimming", func(t *testing.T) {
		raw, files, descriptors, err := buildOriginalWorkerIOIndex(workerIOTestIdentity(), workerIOTestOriginals(4097))
		if err == nil || raw != nil || files != nil || descriptors != nil {
			t.Fatal("oversized flat roster disguised as complete")
		}
	})
}
func TestWorkerIOIndexClosedRootSource(t *testing.T) {
	id := workerIOTestIdentity()
	raw, files, _, err := buildOriginalWorkerIOIndex(id, workerIOTestOriginals(17))
	if err != nil {
		t.Fatal(err)
	}
	var valid originalWorkerIOIndex
	if json.Unmarshal(raw, &valid) != nil {
		t.Fatal("synthetic root")
	}
	data := workerIOTestFiles(files)
	cases := []struct {
		name   string
		mutate func(originalWorkerIOIndex) originalWorkerIOIndex
	}{
		{"foreign_identity", func(x originalWorkerIOIndex) originalWorkerIOIndex { x.Identity.Phase = "choice"; return x }},
		{"unknown_schema", func(x originalWorkerIOIndex) originalWorkerIOIndex { x.Schema = "unknown"; return x }},
		{"NULL_flat_roster", func(x originalWorkerIOIndex) originalWorkerIOIndex { x.MetadataFiles = nil; return x }},
		{"missing_reachable_node", func(x originalWorkerIOIndex) originalWorkerIOIndex { x.MetadataFiles = x.MetadataFiles[:1]; return x }},
		{"duplicate_roster_node", func(x originalWorkerIOIndex) originalWorkerIOIndex {
			x.MetadataFiles = append(x.MetadataFiles, x.MetadataFiles[0])
			return x
		}},
		{"unknown_reference_count", func(x originalWorkerIOIndex) originalWorkerIOIndex {
			x.OriginalIO.OriginalDescriptorCount = 0
			return x
		}},
		{"wrong_category_no_Registrar_alias", func(x originalWorkerIOIndex) originalWorkerIOIndex { x.OriginalIO.Category = "io_artifacts"; return x }},
		{"wrong_worker_path", func(x originalWorkerIOIndex) originalWorkerIOIndex {
			s := "../foreign.meta"
			x.OriginalIO.NodeBasename = &s
			return x
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := valid
			x.MetadataFiles = append([]originalWorkerIOMetadataFileReference{}, valid.MetadataFiles...)
			bad := tc.mutate(x)
			b, _ := json.Marshal(bad)
			_, err := resolveOriginalWorkerIOIndex(id, b, func(name string, _ int, _ string) ([]byte, error) { return bytes.Clone(data[name]), nil })
			if err == nil {
				t.Fatal("incomplete root accepted")
			}
		})
	}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"unknown_key", bytes.Replace(raw, []byte(`"schema":`), []byte(`"unknown":1,"schema":`), 1)},
		{"case_alias", bytes.Replace(raw, []byte(`"schema":`), []byte(`"Schema":`), 1)},
		{"duplicate_key", bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"shadow","schema":`), 1)},
		{"noncanonical_whitespace", append([]byte{' '}, raw...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveOriginalWorkerIOIndex(id, tc.raw, func(name string, _ int, _ string) ([]byte, error) { return data[name], nil })
			if err == nil {
				t.Fatal("closed canonical root widened")
			}
		})
	}
	t.Run("callback_error_is_original_no_repair", func(t *testing.T) {
		cause := errors.New("synthetic-original-read-error")
		count := 0
		_, err := resolveOriginalWorkerIOIndex(id, raw, func(string, int, string) ([]byte, error) { count++; return nil, cause })
		if err != cause || count != 1 {
			t.Fatal("error replaced or reader retried")
		}
	})
	t.Run("callback_raw_hash_mismatch", func(t *testing.T) {
		_, err := resolveOriginalWorkerIOIndex(id, raw, func(string, int, string) ([]byte, error) { return []byte("foreign-original"), nil })
		if err == nil {
			t.Fatal("unknown original accepted")
		}
	})
	t.Run("missing_callback", func(t *testing.T) {
		_, err := resolveOriginalWorkerIOIndex(id, raw, nil)
		if err == nil {
			t.Fatal("missing reader became known")
		}
	})
}
func TestWorkerIOIndexNodeShapeSource(t *testing.T) {
	id := workerIOTestIdentity()
	_, files, ds, err := buildOriginalWorkerIOIndex(id, workerIOTestOriginals(1))
	if err != nil {
		t.Fatal(err)
	}
	var leaf originalWorkerIOMetadataNode
	if json.Unmarshal(files[0].raw, &leaf) != nil {
		t.Fatal("synthetic node")
	}
	cases := []struct {
		name   string
		mutate func(*originalWorkerIOMetadataNode)
		accept bool
	}{
		{"whole_leaf", nil, true},
		{"missing_children_array", func(x *originalWorkerIOMetadataNode) { x.Children = nil }, false},
		{"missing_descriptor_array", func(x *originalWorkerIOMetadataNode) { x.OriginalIO = nil }, false},
		{"unknown_level", func(x *originalWorkerIOMetadataNode) { x.Level = 4 }, false},
		{"gap_in_range", func(x *originalWorkerIOMetadataNode) { x.FirstOrdinal = 2 }, false},
		{"count_mismatch", func(x *originalWorkerIOMetadataNode) { x.OriginalDescriptorCount = 2 }, false},
		{"foreign_phase", func(x *originalWorkerIOMetadataNode) { x.Identity.Phase = "choice" }, false},
		{"fanout17_refused", func(x *originalWorkerIOMetadataNode) {
			x.OriginalIO = []originalNativeExportStage{}
			for i := 0; i < 17; i++ {
				x.OriginalIO = append(x.OriginalIO, ds[0])
			}
			x.LastOrdinal = 17
			x.OriginalDescriptorCount = 17
		}, false},
		{"leaf_cannot_borrow_branch", func(x *originalWorkerIOMetadataNode) {
			x.Children = []originalNativeExportMetadataReference{{Category: "original_io"}}
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			x := leaf
			if tc.mutate != nil {
				tc.mutate(&x)
			}
			if (originalWorkerIONodeValid(id, x) == nil) != tc.accept {
				t.Fatal("closed metadata node expectation differed")
			}
		})
	}
}

func TestWorkerIOIndexCompleteRosterBranchesSource(t *testing.T) {
	id := workerIOTestIdentity()
	raw, files, _, err := buildOriginalWorkerIOIndex(id, workerIOTestOriginals(17))
	if err != nil {
		t.Fatal(err)
	}
	var branch originalWorkerIOMetadataNode
	branchRaw := files[len(files)-1].raw
	if json.Unmarshal(branchRaw, &branch) != nil || branch.Level != 1 {
		t.Fatal("synthetic branch")
	}
	cases := []struct {
		name   string
		mutate func(*originalWorkerIOMetadataNode)
		accept bool
	}{
		{"whole_contiguous_children", nil, true},
		{"branch_descriptor_array_must_known_empty", func(x *originalWorkerIOMetadataNode) { x.OriginalIO = nil }, false},
		{"duplicate_child_cycle_reference_refused", func(x *originalWorkerIOMetadataNode) { x.Children[1] = x.Children[0] }, false},
		{"child_gap_refused", func(x *originalWorkerIOMetadataNode) { v := uint32(18); x.Children[1].FirstOrdinal = &v }, false},
		{"child_level_must_decrease", func(x *originalWorkerIOMetadataNode) { v := uint32(1); x.Children[0].Level = &v }, false},
		{"unknown_child_NULL", func(x *originalWorkerIOMetadataNode) { x.Children[0].NodeSHA256 = nil }, false},
		{"Level3_structural_limit_only", func(x *originalWorkerIOMetadataNode) {
			x.Level = 3
			for i := range x.Children {
				v := uint32(2)
				x.Children[i].Level = &v
			}
		}, true},
		{"Level4_never_extension", func(x *originalWorkerIOMetadataNode) { x.Level = 4 }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var x originalWorkerIOMetadataNode
			if json.Unmarshal(branchRaw, &x) != nil {
				t.Fatal("synthetic branch copy")
			}
			if tc.mutate != nil {
				tc.mutate(&x)
			}
			if (originalWorkerIONodeValid(id, x) == nil) != tc.accept {
				t.Fatal("branch range/level/known-list expectation differed")
			}
		})
	}
	t.Run("unreachable_orphan_roster_not_read_or_repaired", func(t *testing.T) {
		var root originalWorkerIOIndex
		if json.Unmarshal(raw, &root) != nil {
			t.Fatal("synthetic root")
		}
		unknownRaw := []byte("unsigned-unused-metadata")
		sha := digest(unknownRaw)
		name, _ := originalWorkerIOArtifactBasename(id, sha, "meta")
		root.MetadataFiles = append(root.MetadataFiles, originalWorkerIOMetadataFileReference{name, len(unknownRaw), sha})
		sort.Slice(root.MetadataFiles, func(i, j int) bool { return root.MetadataFiles[i].Basename < root.MetadataFiles[j].Basename })
		bad, _ := json.Marshal(root)
		data := workerIOTestFiles(files)
		count := 0
		orphanReads := 0
		_, err := resolveOriginalWorkerIOIndex(id, bad, func(n string, _ int, _ string) ([]byte, error) {
			count++
			if n == name {
				orphanReads++
			}
			return bytes.Clone(data[n]), nil
		})
		if err == nil || orphanReads != 0 || count != len(files) {
			t.Fatal("unknown roster promoted or repair IO requested")
		}
	})
	t.Run("NULL_target_is_closed_refusal", func(t *testing.T) {
		var target *originalWorkerIOIndex
		if originalWorkerIODecode(raw, target) == nil {
			t.Fatal("NULL decoder target accepted")
		}
	})
}

// This is a private metadata namespace fixture. An ordinary identity never
// becomes Scope, and neither accepted branch authenticates Source or native IO.
func workerIOOrdinaryTestIdentity() originalWorkerIOIndexIdentity {
	x := workerIOTestIdentity()
	x.BindingSchema = "factory_ordinary_source_binding_v4"
	return x
}

func TestWorkerIOIndexClosedTransferPairSource(t *testing.T) {
	for _, tc := range []struct {
		name, schema, phase, role string
	}{
		{"Scope_prepared", "original_host_factory_pre_authority_scope_v4", "prepared", "host_worker"},
		{"Scope_choice", "original_host_factory_pre_authority_scope_v4", "choice", "host_worker"},
		{"Scope_closing", "original_host_factory_pre_authority_scope_v4", "closing", "host_worker"},
		{"Scope_created_refused", "original_host_factory_pre_authority_scope_v4", "created", ""},
		{"ordinary_prepared", "factory_ordinary_source_binding_v4", "prepared", "factory_ordinary_worker"},
		{"ordinary_created", "factory_ordinary_source_binding_v4", "created", "factory_ordinary_worker"},
		{"ordinary_closing", "factory_ordinary_source_binding_v4", "closing", "factory_ordinary_worker"},
		{"ordinary_choice_refused", "factory_ordinary_source_binding_v4", "choice", ""},
		{"ordinary_unknown_phase", "factory_ordinary_source_binding_v4", "rpc", ""},
		{"RootPreparation_is_not_transfer", "original_host_factory_root_preparation_v4", "prepared", ""},
		{"unknown_binding_refused", "factory_ordinary_source_binding_v5", "prepared", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := workerIOTestIdentity()
			x.BindingSchema, x.Phase = tc.schema, tc.phase
			before := x
			role, err := originalWorkerIOTransferOwnerRole(x)
			if role != tc.role || (err == nil) != (tc.role != "") || (originalWorkerIOTransferIdentityValid(x) == nil) != (tc.role != "") || x != before {
				t.Fatal("closed namespace/phase role selection changed or rewrote identity")
			}
			// The old predicate remains Scope-only even for a valid ordinary
			// transfer. No schema substitution makes an ordinary fact Scope.
			if (originalWorkerIOIdentityValid(x) == nil) != (tc.role == "host_worker") {
				t.Fatal("Scope-only predicate widened")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(*originalWorkerIOIndexIdentity)
	}{
		{"ordinary_creator_mismatch", func(x *originalWorkerIOIndexIdentity) { x.CreatorOwnerID = x.FactoryRootID }},
		{"ordinary_Root_equals_worker", func(x *originalWorkerIOIndexIdentity) { x.FactoryRootID = x.WorkerOwnerID }},
		{"ordinary_noncanonical_worker", func(x *originalWorkerIOIndexIdentity) {
			x.WorkerOwnerID = strings.ToUpper("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
			x.CreatorOwnerID = x.WorkerOwnerID
		}},
		{"ordinary_zero_Root", func(x *originalWorkerIOIndexIdentity) { x.FactoryRootID = "00000000-0000-0000-0000-000000000000" }},
		{"ordinary_missing_RootPreparation", func(x *originalWorkerIOIndexIdentity) { x.RootPreparationSHA256 = "" }},
		{"ordinary_missing_SourceApproval", func(x *originalWorkerIOIndexIdentity) { x.SourceApprovalSHA256 = "" }},
		{"ordinary_missing_Basal", func(x *originalWorkerIOIndexIdentity) { x.WorkerBasalSHA256 = "" }},
		{"ordinary_missing_binding", func(x *originalWorkerIOIndexIdentity) { x.BindingSHA256 = "" }},
		{"ordinary_missing_deadline", func(x *originalWorkerIOIndexIdentity) { x.OriginalEffectiveContextDeadline = "" }},
		{"ordinary_noncanonical_deadline", func(x *originalWorkerIOIndexIdentity) {
			x.OriginalEffectiveContextDeadline = "2030-01-01T00:00:00+00:00"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := workerIOOrdinaryTestIdentity()
			tc.mutate(&x)
			role, err := originalWorkerIOTransferOwnerRole(x)
			if err == nil || role != "" || originalWorkerIOTransferIdentityValid(x) == nil {
				t.Fatal("invalid ordinary transfer obtained a publication role")
			}
			if _, err := originalWorkerIORootBasename(x); err == nil {
				t.Fatal("invalid ordinary identity obtained a root path")
			}
			if _, err := originalWorkerIOArtifactBasename(x, strings.Repeat("a", 64), "body"); err == nil {
				t.Fatal("invalid ordinary identity obtained an original artifact path")
			}
		})
	}
}

func TestWorkerIOIndexOrdinaryWholeTreeSource(t *testing.T) {
	for _, phase := range []string{"prepared", "created", "closing"} {
		t.Run(phase, func(t *testing.T) {
			id := workerIOOrdinaryTestIdentity()
			id.Phase = phase
			originals := workerIOTestOriginals(257) // leaf + branch + root
			before := append([]originalNativeSignedIO{}, originals...)
			raw, files, want, err := buildOriginalWorkerIOIndex(id, originals)
			if err != nil {
				t.Fatal(err)
			}
			data := workerIOTestFiles(files)
			calls := map[string]int{}
			got, err := resolveOriginalWorkerIOIndex(id, raw, func(name string, count int, sha string) ([]byte, error) {
				calls[name]++
				b, ok := data[name]
				if !ok || len(b) != count || digest(b) != sha {
					return nil, errors.New("unknown-original-metadata")
				}
				return bytes.Clone(b), nil
			})
			if err != nil || !reflect.DeepEqual(got, want) || !reflect.DeepEqual(originals, before) || len(calls) != len(files) {
				t.Fatalf("ordinary complete tree %v", err)
			}
			for _, count := range calls {
				if count != 1 {
					t.Fatal("ordinary metadata reread")
				}
			}
			var root originalWorkerIOIndex
			if originalWorkerIODecode(raw, &root) != nil || root.Identity != id {
				t.Fatal("ordinary original identity rewritten")
			}
			name, err := originalWorkerIORootBasename(id)
			if err != nil || name != id.CreatorOwnerID+"-worker-io-"+phase+".json" {
				t.Fatal("fixed filename changed")
			}
		})
	}
	for _, name := range []string{"Scope_cannot_read_ordinary_same_names", "ordinary_cannot_read_Scope_same_names", "ordinary_phase_substitution_before_callback", "ordinary_cap_plus_one_not_trimmed", "ordinary_unknown_purposes_not_installed"} {
		t.Run(name, func(t *testing.T) {
			id := workerIOOrdinaryTestIdentity()
			if name == "ordinary_cannot_read_Scope_same_names" {
				id = workerIOTestIdentity()
			}
			originals := workerIOTestOriginals(1)
			if name == "ordinary_cap_plus_one_not_trimmed" {
				originals[0].envelope = bytes.Repeat([]byte{'x'}, bodyLimit+1)
			}
			if name == "ordinary_unknown_purposes_not_installed" {
				originals[0].purposes = nil
			}
			raw, files, _, err := buildOriginalWorkerIOIndex(id, originals)
			if name == "ordinary_cap_plus_one_not_trimmed" || name == "ordinary_unknown_purposes_not_installed" {
				if err == nil || raw != nil || files != nil {
					t.Fatal("unknown/oversized original became complete")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			expected := id
			switch name {
			case "Scope_cannot_read_ordinary_same_names":
				expected.BindingSchema = "original_host_factory_pre_authority_scope_v4"
			case "ordinary_cannot_read_Scope_same_names":
				expected.BindingSchema = "factory_ordinary_source_binding_v4"
			case "ordinary_phase_substitution_before_callback":
				expected.Phase = "created"
			}
			calls := 0
			_, err = resolveOriginalWorkerIOIndex(expected, raw, func(string, int, string) ([]byte, error) {
				calls++
				return nil, errors.New("must not read foreign tree")
			})
			if err == nil || calls != 0 {
				t.Fatal("foreign namespace/phase reached a metadata read")
			}
		})
	}
}

// Source assembly input: native_worker_io_index_physical_source_test_fragment.go
// These real-file fixtures run in remote CI only. Proposed profile/private
// memory pointers are synthetic and establish no compiled Source/native trust.
func workerIOPhysicalSourceOwner(t *testing.T, ctx context.Context, role string, identity originalWorkerIOIndexIdentity, dir string) *originalWorkerIOTransferOwner {
	t.Helper()
	ownerID, primitive := identity.WorkerOwnerID, identity.WorkerBasalSHA256
	if role == "host_exterior" {
		ownerID, primitive = "22222222-2222-4222-8222-222222222222", strings.Repeat("b", 64)
	}
	l, err := newLedger(ctx, ownerID, role, primitive, identity.BindingSchema, identity.BindingSHA256)
	if err != nil {
		t.Fatal(err)
	}
	profile := capacity.ProposedHostFactorySourceProfileV1()
	l.sourceProfile, l.collection.sourceProfile = profile, profile
	p := &originalNativePublisher{root: identity.FactoryRootID, ledger: l, sourceProfile: profile}
	f, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return &originalWorkerIOTransferOwner{publisher: p, audit: l, anchor: &callHandle{file: f, fd: int(f.Fd()), id: "33333333-3333-4333-8333-333333333333"}, uid: uint32(os.Getuid()), gid: uint32(os.Getgid()), cache: &originalWorkerIOTransferCache{publisher: p, factoryRootID: identity.FactoryRootID, creatorOwnerID: identity.CreatorOwnerID, bindingSHA: identity.BindingSHA256, published: map[string]*originalWorkerIOTransferFileReturn{}, slots: map[string]*originalWorkerIOTransfer{}}}
}

func workerIOPhysicalSourceFixture(t *testing.T) (context.Context, originalWorkerIOIndexIdentity, []originalNativeSignedIO, string) {
	t.Helper()
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute))
	t.Cleanup(cancel)
	d, _ := ctx.Deadline()
	identity := originalWorkerIOIndexIdentity{Phase: "prepared", FactoryRootID: "44444444-4444-4444-8444-444444444444", RootPreparationSHA256: strings.Repeat("c", 64), SourceApprovalSHA256: strings.Repeat("d", 64), CreatorOwnerID: "11111111-1111-4111-8111-111111111111", WorkerOwnerID: "11111111-1111-4111-8111-111111111111", WorkerBasalSHA256: strings.Repeat("e", 64), BindingSchema: "original_host_factory_pre_authority_scope_v4", BindingSHA256: strings.Repeat("a", 64), OriginalEffectiveContextDeadline: d.UTC().Format(time.RFC3339Nano)}
	body, envelope := []byte(`{"fixture":"whole_source_original"}`), []byte(`{"fixture":"unauthenticated_envelope"}`)
	originals := []originalNativeSignedIO{{selector: "io-calls/55555555-5555-4555-8555-555555555555/chunk/" + digest(body), body: body, envelope: envelope, purposes: []capacity.HostFactorySourceCallPurpose{}}}
	return ctx, identity, originals, t.TempDir()
}

func TestWorkerIOPhysicalFilesSource(t *testing.T) {
	for _, name := range []string{"whole_file_roundtrip_separate_parent_deadline", "phase_reentry_refuses", "choice_reuses_same_old_writer_and_method", "unknown_open_never_replays", "noreplace_does_not_overwrite_original", "source_file_EOF_literal_cause_retained", "reader_changed_mode_refuses", "reader_symlink_refuses"} {
		t.Run(name, func(t *testing.T) {
			ctx, identity, originals, dir := workerIOPhysicalSourceFixture(t)
			cancelOld := func() {}
			if name == "choice_reuses_same_old_writer_and_method" {
				ctx, cancelOld = context.WithCancel(ctx)
				t.Cleanup(cancelOld)
			}
			worker := workerIOPhysicalSourceOwner(t, ctx, "host_worker", identity, dir)
			bodyName, err := originalWorkerIOArtifactBasename(identity, digest(originals[0].body), "body")
			if err != nil {
				t.Fatal(err)
			}
			if name == "unknown_open_never_replays" {
				if err := os.WriteFile(filepath.Join(dir, bodyName+".tmp"), []byte("unowned existing temporary"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if name == "noreplace_does_not_overwrite_original" {
				if err := os.WriteFile(filepath.Join(dir, bodyName), []byte("unowned existing final"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			published, publishErr := publishOriginalWorkerIOIndex(ctx, worker, identity, originals)
			if name == "unknown_open_never_replays" || name == "noreplace_does_not_overwrite_original" {
				if publishErr == nil || published == nil || published.cause == nil {
					t.Fatal("uncertain original admitted")
				}
				attempt := worker.cache.published[bodyName]
				if attempt == nil || attempt.writer == nil || attempt.cause == nil {
					t.Fatal("failed original owner missing")
				}
				if name == "unknown_open_never_replays" && attempt.writer.file != nil {
					t.Fatal("failed Open fabricated acquired descriptor")
				}
				choiceCtx, cancel := context.WithDeadline(ctx, time.Now().Add(30*time.Second))
				defer cancel()
				choice := identity
				choice.Phase = "choice"
				d, _ := choiceCtx.Deadline()
				choice.OriginalEffectiveContextDeadline = d.UTC().Format(time.RFC3339Nano)
				audit, e := newLedger(choiceCtx, identity.WorkerOwnerID, "host_worker", identity.WorkerBasalSHA256, identity.BindingSchema, identity.BindingSHA256)
				if e != nil {
					t.Fatal(e)
				}
				audit.sourceProfile, audit.collection.sourceProfile = worker.publisher.sourceProfile, worker.publisher.sourceProfile
				owner := &originalWorkerIOTransferOwner{publisher: worker.publisher, audit: audit, anchor: worker.anchor, uid: worker.uid, gid: worker.gid, cache: worker.cache}
				if _, e := publishOriginalWorkerIOIndex(choiceCtx, owner, choice, originals); e == nil || worker.cache.published[bodyName] != attempt {
					t.Fatal("failed physical publication replayed or taken over")
				}
				if name == "noreplace_does_not_overwrite_original" {
					actual, e := os.ReadFile(filepath.Join(dir, bodyName))
					if e != nil || !bytes.Equal(actual, []byte("unowned existing final")) {
						t.Fatal("original final replaced")
					}
				}
				return
			}
			if publishErr != nil {
				t.Fatal(publishErr)
			}
			if name == "phase_reentry_refuses" {
				again, err := publishOriginalWorkerIOIndex(ctx, worker, identity, originals)
				if err == nil || again != published {
					t.Fatal("original transfer reservation reset")
				}
				return
			}
			if name == "choice_reuses_same_old_writer_and_method" {
				cancelOld() // completed originals remain immutable after phase end
				choiceCtx, cancel := context.WithDeadline(context.Background(), time.Now().Add(30*time.Second))
				defer cancel()
				choice := identity
				choice.Phase = "choice"
				d, _ := choiceCtx.Deadline()
				choice.OriginalEffectiveContextDeadline = d.UTC().Format(time.RFC3339Nano)
				audit, e := newLedger(choiceCtx, identity.WorkerOwnerID, "host_worker", identity.WorkerBasalSHA256, identity.BindingSchema, identity.BindingSHA256)
				if e != nil {
					t.Fatal(e)
				}
				audit.sourceProfile, audit.collection.sourceProfile = worker.publisher.sourceProfile, worker.publisher.sourceProfile
				owner := &originalWorkerIOTransferOwner{publisher: worker.publisher, audit: audit, anchor: worker.anchor, uid: worker.uid, gid: worker.gid, cache: worker.cache}
				later, e := publishOriginalWorkerIOIndex(choiceCtx, owner, choice, originals)
				if e != nil {
					t.Fatal(e)
				}
				a, b := published.files[bodyName], later.files[bodyName]
				if ctx.Err() == nil || a != b || a.writer != b.writer || a.method != b.method || a.writer.ledger.ctx != ctx || owner.audit.ctx != choiceCtx || a.writer.ledger.deadline.UTC().Format(time.RFC3339Nano) != identity.OriginalEffectiveContextDeadline {
					t.Fatal("cached original owners/deadlines rebound")
				}
				return
			}
			if name == "reader_changed_mode_refuses" {
				if err := os.Chmod(filepath.Join(dir, bodyName), 0644); err != nil {
					t.Fatal(err)
				}
			}
			if name == "reader_symlink_refuses" {
				if err := os.Remove(filepath.Join(dir, bodyName)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(dir, "unowned-target"), filepath.Join(dir, bodyName)); err != nil {
					t.Fatal(err)
				}
			}
			// An independent earlier parent caller bound never replaces the
			// expected actual worker publication identity/date.
			parentCtx, cancel := context.WithDeadline(ctx, time.Now().Add(30*time.Second))
			defer cancel()
			parent := workerIOPhysicalSourceOwner(t, parentCtx, "host_exterior", identity, dir)
			read, readErr := readOriginalWorkerIOIndex(parentCtx, parent, identity)
			if name == "reader_changed_mode_refuses" || name == "reader_symlink_refuses" {
				if readErr == nil || read == nil || read.files[bodyName] == nil || read.files[bodyName].reader == nil {
					t.Fatal("unsafe original file admitted or discarded")
				}
				return
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			got := read.originals[originals[0].selector]
			if !bytes.Equal(got.body, originals[0].body) || !bytes.Equal(got.envelope, originals[0].envelope) || !reflect.DeepEqual(read.descriptors, published.descriptors) || !bytes.Equal(read.rootRaw, published.rootRaw) {
				t.Fatal("whole original transfer changed")
			}
			if name == "source_file_EOF_literal_cause_retained" {
				for _, file := range read.files {
					h := file.reader
					h.mu.Lock()
					rows := append([]unclassifiedNativeReturn(nil), h.unclassified...)
					closed := h.closed
					h.mu.Unlock()
					if !closed || len(rows) < 6 || rows[len(rows)-1].operation != "source_file_close" || rows[len(rows)-2].operation != "source_file_fstat" {
						t.Fatal("actual postFstat/soleClose missing")
					}
					EOFs := 0
					for _, row := range rows {
						if row.operation == "source_file_read" && row.cause == io.EOF {
							EOFs++
							if !row.scalarObserved || row.scalar != 0 || len(row.raw) != 0 || row.returnedAt.IsZero() || !row.private {
								t.Fatal("literal EOF confused with unknown")
							}
						}
					}
					if EOFs != 1 {
						t.Fatal("real EOF normalized or invented")
					}
				}
			}
		})
	}
}

// Remote-only observer of actual recorder state. It neither replaces Err nor
// supplies syscall results. Its hook performs genuine context cancellation or
// an external untrusted file mutation after the original return is retained.
type workerIOPhysicalAfterEffectContext struct {
	context.Context
	observe func() bool
	after   func()
	fired   atomic.Bool
}

func (c *workerIOPhysicalAfterEffectContext) Err() error {
	if !c.fired.Load() && c.observe != nil && c.observe() && c.fired.CompareAndSwap(false, true) {
		c.after()
	}
	return c.Context.Err()
}

func TestWorkerIOPhysicalAfterEffectCustodySource(t *testing.T) {
	for _, name := range []string{"publisher_cancel_after_actual_Open_retains_Close", "reader_cancel_after_actual_Read_retains_raw", "reader_actual_growth_retains_cap_plus_one"} {
		t.Run(name, func(t *testing.T) {
			base, identity, originals, dir := workerIOPhysicalSourceFixture(t)
			rootName, err := originalWorkerIORootBasename(identity)
			if err != nil {
				t.Fatal(err)
			}
			if name == "publisher_cancel_after_actual_Open_retains_Close" {
				actual, cancel := context.WithCancel(base)
				defer cancel()
				ctx := &workerIOPhysicalAfterEffectContext{Context: actual, after: cancel}
				var worker *originalWorkerIOTransferOwner
				bodyName, err := originalWorkerIOArtifactBasename(identity, digest(originals[0].body), "body")
				if err != nil {
					t.Fatal(err)
				}
				ctx.observe = func() bool {
					if worker == nil {
						return false
					}
					f := worker.cache.published[bodyName]
					return f != nil && f.writer != nil && f.writer.file != nil
				}
				worker = workerIOPhysicalSourceOwner(t, ctx, "host_worker", identity, dir)
				out, err := publishOriginalWorkerIOIndex(ctx, worker, identity, originals)
				if err == nil || out == nil || out.cause == nil || !ctx.fired.Load() {
					t.Fatal("late acquired Open admitted or lost")
				}
				f := out.files[bodyName]
				if f == nil || f.writer == nil || !f.writer.closed || f.cause == nil {
					t.Fatal("late acquired original not actually closed/retained")
				}
				rows := f.writer.unclassified
				if len(rows) != 2 || rows[0].operation != "source_file_open" || !rows[0].scalarObserved || rows[0].cause != nil || rows[0].returnedAt.IsZero() || rows[1].operation != "source_file_close" || rows[1].cause != nil || rows[1].returnedAt.IsZero() {
					t.Fatal("actual Open/Close return replaced or future Fstat invented")
				}
				return
			}
			worker := workerIOPhysicalSourceOwner(t, base, "host_worker", identity, dir)
			if _, err := publishOriginalWorkerIOIndex(base, worker, identity, originals); err != nil {
				t.Fatal(err)
			}
			actual, cancel := context.WithCancel(base)
			defer cancel()
			ctx := &workerIOPhysicalAfterEffectContext{Context: actual}
			parent := workerIOPhysicalSourceOwner(t, ctx, "host_exterior", identity, dir)
			var selected *originalWorkerIOTransfer
			var fixtureErr error
			ctx.observe = func() bool {
				if selected == nil {
					selected = parent.cache.slots["read\x00"+identity.Phase]
				}
				if selected == nil || selected.files[rootName] == nil || selected.files[rootName].reader == nil {
					return false
				}
				rows := selected.files[rootName].reader.unclassified
				if len(rows) == 0 {
					return false
				}
				last := rows[len(rows)-1]
				if name == "reader_actual_growth_retains_cap_plus_one" {
					return last.operation == "source_file_fstat" && last.stat != nil && !last.returnedAt.IsZero()
				}
				return last.operation == "source_file_read" && len(last.raw) > 0 && !last.returnedAt.IsZero()
			}
			ctx.after = cancel
			if name == "reader_actual_growth_retains_cap_plus_one" {
				ctx.after = func() {
					f, err := os.OpenFile(filepath.Join(dir, rootName), os.O_WRONLY|os.O_APPEND, 0600)
					if err != nil {
						fixtureErr = err
						return
					}
					_, writeErr := f.Write(bytes.Repeat([]byte{'x'}, bodyLimit+1))
					fixtureErr = errors.Join(writeErr, f.Close())
				}
			}
			out, err := readOriginalWorkerIOIndex(ctx, parent, identity)
			if fixtureErr != nil {
				t.Fatal(fixtureErr)
			}
			if err == nil || out == nil || out.cause == nil || out != selected || !ctx.fired.Load() {
				t.Fatal("post-acquisition refusal lost original transfer")
			}
			f := out.files[rootName]
			if f == nil || f.reader == nil || !f.reader.closed || f.cause == nil || len(f.raw) < 1 || !bytes.Equal(out.rootRaw, f.raw) {
				t.Fatal("partial actual reader raw/Close not retained")
			}
			if name == "reader_actual_growth_retains_cap_plus_one" && len(f.raw) != bodyLimit+1 {
				t.Fatal("actual cap+1 raw trimmed")
			}
			var raw []byte
			reads, closes, fstats := 0, 0, 0
			for _, row := range f.reader.unclassified {
				if !row.private || row.returnedAt.IsZero() || row.cause != nil {
					t.Fatal("actual successful primitive cause/time replaced by policy error")
				}
				switch row.operation {
				case "source_file_read":
					reads++
					if !row.scalarObserved || row.scalar != int64(len(row.raw)) {
						t.Fatal("actual read count/raw changed")
					}
					raw = append(raw, row.raw...)
				case "source_file_close":
					closes++
				case "source_file_fstat":
					fstats++
				}
			}
			if reads < 1 || closes != 1 || fstats != 1 || !bytes.Equal(raw, f.raw) {
				t.Fatal("actual partial raw/soleClose lost or postFstat fabricated")
			}
		})
	}
}

func TestWorkerIOPhysicalGuardsSource(t *testing.T) {
	for _, name := range []string{"publisher_deadline_mismatch", "reader_independent_deadline_allowed", "foreign_cache_publisher", "foreign_cache_binding", "nil_cache_inventory", "source_profile_pointer_missing", "rebound_audit_context", "foreign_writer_owner", "reader_wrong_role", "cancelled_owner_no_IO", "cap_plus_one_no_file_attempt"} {
		t.Run(name, func(t *testing.T) {
			ctx, identity, originals, dir := workerIOPhysicalSourceFixture(t)
			role, direction := "host_worker", "publish"
			if name == "reader_independent_deadline_allowed" || name == "reader_wrong_role" {
				role, direction = "host_exterior", "read"
			}
			owner := workerIOPhysicalSourceOwner(t, ctx, role, identity, dir)
			switch name {
			case "publisher_deadline_mismatch":
				identity.OriginalEffectiveContextDeadline = time.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano)
			case "reader_independent_deadline_allowed":
				identity.OriginalEffectiveContextDeadline = time.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano)
			case "foreign_cache_publisher":
				owner.cache.publisher = &originalNativePublisher{}
			case "foreign_cache_binding":
				owner.cache.bindingSHA = strings.Repeat("f", 64)
			case "nil_cache_inventory":
				owner.cache.published = nil
			case "source_profile_pointer_missing":
				owner.audit.collection.sourceProfile = nil
			case "rebound_audit_context":
				owner.audit.ctx = context.Background()
			case "foreign_writer_owner":
				owner.audit.ownerID = "66666666-6666-4666-8666-666666666666"
			case "reader_wrong_role":
				owner.audit.ownerRole = "host_worker"
			case "cancelled_owner_no_IO":
				cancelCtx, cancel := context.WithCancel(ctx)
				ctx = cancelCtx
				owner.audit.ctx = ctx
				cancel()
			case "cap_plus_one_no_file_attempt":
				originals[0].body = bytes.Repeat([]byte{'x'}, bodyLimit+1)
				originals[0].selector = "io-calls/55555555-5555-4555-8555-555555555555/chunk/" + digest(originals[0].body)
			}
			if name == "reader_independent_deadline_allowed" {
				if workerIOPhysicalGuard(ctx, owner, identity, direction) != nil {
					t.Fatal("reader bound substituted for worker original")
				}
				return
			}
			out, err := publishOriginalWorkerIOIndex(ctx, owner, identity, originals)
			if direction == "read" {
				out, err = readOriginalWorkerIOIndex(ctx, owner, identity)
			}
			if err == nil {
				t.Fatal("invalid original Source owner admitted")
			}
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) != 0 {
				t.Fatal("invalid owner performed physical IO")
			}
			if name == "cap_plus_one_no_file_attempt" && (out == nil || len(out.files) != 0 || out.cause == nil) {
				t.Fatal("oversize original trimmed or reservation lost")
			}
		})
	}
}

func TestWorkerIOPhysicalStatSource(t *testing.T) {
	base := unix.Stat_t{Mode: unix.S_IFREG | 0600, Nlink: 1, Uid: 12, Gid: 13, Dev: 4, Ino: 5, Size: 7}
	for _, name := range []string{"exact_regular_identity", "wrong_mode", "directory", "hard_link", "wrong_uid", "wrong_gid", "different_inode", "different_device", "changed_size"} {
		t.Run(name, func(t *testing.T) {
			actual := base
			switch name {
			case "wrong_mode":
				actual.Mode = unix.S_IFREG | 0644
			case "directory":
				actual.Mode = unix.S_IFDIR | 0600
			case "hard_link":
				actual.Nlink = 2
			case "wrong_uid":
				actual.Uid = 14
			case "wrong_gid":
				actual.Gid = 14
			case "different_inode":
				actual.Ino = 6
			case "different_device":
				actual.Dev = 6
			case "changed_size":
				actual.Size = 8
			}
			accepted := workerIORegularStat(&actual, 12, 13) && workerIOStatEqual(base, actual)
			if accepted != (name == "exact_regular_identity") {
				t.Fatal("original file identity guard changed")
			}
		})
	}
	if workerIORegularStat(nil, 12, 13) {
		t.Fatal("missing original stat fabricated")
	}
}

// Observe the recorder's three genuine entry Err reads without replacing any
// result. SAME context remains on the ledger and recorder. The third read is
// the last Err access in its entry guard, before the held handle-lock wait.
type workerIOPhysicalEntryContext struct {
	context.Context
	reads   atomic.Int32
	arrived chan struct{}
}

func (c *workerIOPhysicalEntryContext) Err() error {
	err := c.Context.Err()
	if c.reads.Add(1) == 3 {
		close(c.arrived)
	}
	return err
}

// The real context is cancelled/expires after its entry guard's Err reads
// while the handle lock is held. Its reserved row must stay pending, and the
// actual callback must never run after the lock wait.
func TestWorkerIOPhysicalPendingDispatchSource(t *testing.T) {
	for _, name := range []string{"cancelled_while_handle_lock_held", "expired_while_handle_lock_held"} {
		t.Run(name, func(t *testing.T) {
			duration := time.Minute
			if name == "expired_while_handle_lock_held" {
				duration = 5 * time.Second
			}
			base, cancel := context.WithDeadline(context.Background(), time.Now().Add(duration))
			defer cancel()
			ctx := &workerIOPhysicalEntryContext{Context: base, arrived: make(chan struct{})}
			l, err := newLedger(ctx, "11111111-1111-4111-8111-111111111111", "host_worker", strings.Repeat("a", 64), "original_host_factory_pre_authority_scope_v4", strings.Repeat("b", 64))
			if err != nil {
				t.Fatal(err)
			}
			h, err := l.handle()
			if err != nil {
				t.Fatal(err)
			}
			ctx.reads.Store(0)
			h.mu.Lock()
			locked := true
			defer func() {
				if locked {
					h.mu.Unlock()
				}
			}()
			done := make(chan error, 1)
			effected := make(chan struct{}, 1)
			go func() {
				_, e := currentOriginalAuditCall(ctx, h, "source_file_open", func() unclassifiedNativeReturn {
					effected <- struct{}{}
					return unclassifiedNativeReturn{cause: errors.New("fixture must not dispatch")}
				})
				done <- e
			}()
			select {
			case <-ctx.arrived:
			case <-time.After(time.Second):
				t.Fatal("recorder did not reach genuine entry Err reads")
			}
			if name == "cancelled_while_handle_lock_held" {
				cancel()
			} else {
				<-base.Done()
			}
			h.mu.Unlock()
			locked = false
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("late original dispatched")
				}
			case <-time.After(time.Second):
				t.Fatal("late recorder stuck")
			}
			select {
			case <-effected:
				t.Fatal("late original effect executed")
			default:
			}
			h.mu.Lock()
			defer h.mu.Unlock()
			if len(h.unclassified) != 1 {
				t.Fatalf("actual reservation count = %d, want 1", len(h.unclassified))
			}
			row := h.unclassified[0]
			if row.calledAt.IsZero() || row.ordinal != 1 || row.callID != h.id+":1" || !row.returnedAt.IsZero() || row.scalarObserved || row.cause != nil || row.raw != nil {
				t.Fatal("undispatched original reservation fabricated completion")
			}
		})
	}
}

func TestWorkerIOPhysicalOrdinaryFilesSource(t *testing.T) {
	for _, phase := range []string{"prepared", "created", "closing"} {
		t.Run(phase, func(t *testing.T) {
			ctx, id, originals, dir := workerIOPhysicalSourceFixture(t)
			id.BindingSchema, id.Phase = "factory_ordinary_source_binding_v4", phase
			worker := workerIOPhysicalSourceOwner(t, ctx, "factory_ordinary_worker", id, dir)
			// The existing original native ledger remains legacy/unprofiled.
			// Only the new immutable Source audit owner has the genuine
			// publisher profile pointer in production. These are synthetic
			// pointers for real-file custody coverage, never Source approval.
			legacy, err := newLedger(ctx, id.WorkerOwnerID, "factory_ordinary_worker", id.WorkerBasalSHA256, id.BindingSchema, id.BindingSHA256)
			if err != nil {
				t.Fatal(err)
			}
			worker.publisher.ledger = legacy
			published, err := publishOriginalWorkerIOIndex(ctx, worker, id, originals)
			if err != nil {
				t.Fatal(err)
			}
			if legacy.sourceProfile != nil || worker.audit == legacy || worker.audit.ctx != ctx {
				t.Fatal("legacy original ledger rebound or profile installed")
			}
			for _, f := range published.files {
				if workerIOPublicationComplete(f, id) != nil || f.writer.ledger.ownerRole != "factory_ordinary_worker" || f.method.ledger != f.writer.ledger || f.writer.ledger.bindingSchema != id.BindingSchema {
					t.Fatal("ordinary original writer/method custody missing")
				}
				foreign := id
				foreign.BindingSchema, foreign.Phase = "original_host_factory_pre_authority_scope_v4", "prepared"
				if workerIOPublicationComplete(f, foreign) == nil {
					t.Fatal("ordinary streams were accepted as host_worker Scope")
				}
			}
			parentCtx, cancel := context.WithDeadline(ctx, time.Now().Add(30*time.Second))
			defer cancel()
			parent := workerIOPhysicalSourceOwner(t, parentCtx, "host_exterior", id, dir)
			read, err := readOriginalWorkerIOIndex(parentCtx, parent, id)
			if err != nil || !bytes.Equal(read.rootRaw, published.rootRaw) || !reflect.DeepEqual(read.descriptors, published.descriptors) {
				t.Fatalf("whole ordinary transfer %v", err)
			}
			got := read.originals[originals[0].selector]
			if !bytes.Equal(got.body, originals[0].body) || !bytes.Equal(got.envelope, originals[0].envelope) || got.purposes != nil {
				t.Fatal("opaque original changed or unverified purposes installed")
			}
			for _, file := range read.files {
				h := file.reader
				if h == nil || !h.closed || h.ledger.ownerRole != "host_exterior" || h.ledger.bindingSchema != id.BindingSchema {
					t.Fatal("independent parent reader ownership missing")
				}
				EOFs, closes := 0, 0
				var raw []byte
				for _, row := range h.unclassified {
					if row.operation == "source_file_read" {
						if row.scalar != int64(len(row.raw)) || !row.scalarObserved || !row.private {
							t.Fatal("actual read raw/count altered")
						}
						raw = append(raw, row.raw...)
						if row.cause == io.EOF {
							EOFs++
							if row.scalar != 0 {
								t.Fatal("terminal EOF fabricated")
							}
						}
					}
					if row.operation == "source_file_close" {
						closes++
						if row.cause != nil {
							t.Fatal("actual reader Close failed")
						}
					}
				}
				if EOFs != 1 || closes != 1 || !bytes.Equal(raw, file.raw) {
					t.Fatal("literal EOF/sole Close/whole raw lost")
				}
			}
		})
	}
}

func TestWorkerIOPhysicalOrdinaryClosedPairGuardsSource(t *testing.T) {
	for _, name := range []string{"host_worker_cannot_publish_ordinary", "ordinary_cannot_publish_Scope", "ordinary_choice_refused_before_IO", "Scope_created_refused_before_IO", "ordinary_missing_audit_profile", "ordinary_publisher_deadline_mismatch", "ordinary_reader_worker_role_refused", "ordinary_created_same_attempt_unknown_stays_reserved"} {
		t.Run(name, func(t *testing.T) {
			ctx, id, originals, dir := workerIOPhysicalSourceFixture(t)
			id.BindingSchema = "factory_ordinary_source_binding_v4"
			role, direction := "factory_ordinary_worker", "publish"
			if name == "host_worker_cannot_publish_ordinary" {
				role = "host_worker"
			}
			if name == "ordinary_cannot_publish_Scope" || name == "Scope_created_refused_before_IO" {
				id.BindingSchema = "original_host_factory_pre_authority_scope_v4"
			}
			if name == "ordinary_choice_refused_before_IO" {
				id.Phase = "choice"
			}
			if name == "Scope_created_refused_before_IO" || name == "ordinary_created_same_attempt_unknown_stays_reserved" {
				id.Phase = "created"
			}
			if name == "Scope_created_refused_before_IO" {
				role = "host_worker" // isolate the invalid phase, not a role mismatch
			}
			if name == "ordinary_reader_worker_role_refused" {
				direction = "read"
			}
			owner := workerIOPhysicalSourceOwner(t, ctx, role, id, dir)
			if name == "ordinary_missing_audit_profile" {
				owner.audit.collection.sourceProfile = nil
			}
			if name == "ordinary_publisher_deadline_mismatch" {
				id.OriginalEffectiveContextDeadline = time.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano)
			}
			if name == "ordinary_created_same_attempt_unknown_stays_reserved" {
				originals[0].purposes = nil
			}
			var out *originalWorkerIOTransfer
			var err error
			if direction == "read" {
				out, err = readOriginalWorkerIOIndex(ctx, owner, id)
			} else {
				out, err = publishOriginalWorkerIOIndex(ctx, owner, id, originals)
			}
			if err == nil {
				t.Fatal("foreign/unknown closed pair performed transfer")
			}
			entries, e := os.ReadDir(dir)
			if e != nil || len(entries) != 0 || len(owner.audit.handleOrder) != 0 {
				t.Fatal("invalid pair acquired Source file owners or physical files")
			}
			if name == "ordinary_created_same_attempt_unknown_stays_reserved" {
				if out == nil || out.cause == nil || len(out.files) != 0 {
					t.Fatal("unknown original reservation lost")
				}
				originals[0].purposes = []capacity.HostFactorySourceCallPurpose{}
				again, e := publishOriginalWorkerIOIndex(ctx, owner, id, originals)
				if e == nil || again != out || len(again.files) != 0 || len(owner.audit.handleOrder) != 0 {
					t.Fatal("unknown original phase supplier retried after failure")
				}
			}
		})
	}
}

func TestWorkerIOPhysicalOrdinaryCrossPhaseOriginalSource(t *testing.T) {
	for _, laterPhase := range []string{"created", "closing"} {
		t.Run(laterPhase, func(t *testing.T) {
			base, id, originals, dir := workerIOPhysicalSourceFixture(t)
			id.BindingSchema = "factory_ordinary_source_binding_v4"
			ctx, cancelOld := context.WithCancel(base)
			defer cancelOld()
			worker := workerIOPhysicalSourceOwner(t, ctx, "factory_ordinary_worker", id, dir)
			first, err := publishOriginalWorkerIOIndex(ctx, worker, id, originals)
			if err != nil {
				t.Fatal(err)
			}
			name, err := originalWorkerIOArtifactBasename(id, digest(originals[0].body), "body")
			if err != nil {
				t.Fatal(err)
			}
			original := first.files[name]
			before := append([]unclassifiedNativeReturn{}, original.writer.unclassified...)
			for n := range before {
				before[n].raw = bytes.Clone(before[n].raw)
				if before[n].stat != nil {
					stat := *before[n].stat
					before[n].stat = &stat
				}
			}
			oldDeadline := original.writer.ledger.deadline
			cancelOld()
			laterCtx, cancel := context.WithDeadline(base, time.Now().Add(20*time.Second))
			defer cancel()
			later := id
			later.Phase = laterPhase
			d, _ := laterCtx.Deadline()
			later.OriginalEffectiveContextDeadline = d.UTC().Format(time.RFC3339Nano)
			audit, e := newLedger(laterCtx, id.WorkerOwnerID, "factory_ordinary_worker", id.WorkerBasalSHA256, id.BindingSchema, id.BindingSHA256)
			if e != nil {
				t.Fatal(e)
			}
			audit.sourceProfile, audit.collection.sourceProfile = worker.publisher.sourceProfile, worker.publisher.sourceProfile
			owner := &originalWorkerIOTransferOwner{publisher: worker.publisher, audit: audit, anchor: worker.anchor, uid: worker.uid, gid: worker.gid, cache: worker.cache}
			published, e := publishOriginalWorkerIOIndex(laterCtx, owner, later, originals)
			if e != nil {
				t.Fatal(e)
			}
			if ctx.Err() == nil || published.files[name] != original || published.files[name].writer != original.writer || published.files[name].method != original.method || original.writer.ledger.ctx != ctx || !original.writer.ledger.deadline.Equal(oldDeadline) || !reflect.DeepEqual(original.writer.unclassified, before) {
				t.Fatal("ordinary completed writer rebound, renewed, rewritten or republished")
			}
			if _, e := publishOriginalWorkerIOIndex(laterCtx, owner, later, originals); e == nil {
				t.Fatal("same original phase reentered")
			}
		})
	}
	for _, name := range []string{"ordinary_unknown_Open_not_replayed_created", "ordinary_completed_cannot_change_binding"} {
		t.Run(name, func(t *testing.T) {
			ctx, id, originals, dir := workerIOPhysicalSourceFixture(t)
			id.BindingSchema = "factory_ordinary_source_binding_v4"
			worker := workerIOPhysicalSourceOwner(t, ctx, "factory_ordinary_worker", id, dir)
			bodyName, err := originalWorkerIOArtifactBasename(id, digest(originals[0].body), "body")
			if err != nil {
				t.Fatal(err)
			}
			if name == "ordinary_unknown_Open_not_replayed_created" {
				if e := os.WriteFile(filepath.Join(dir, bodyName+".tmp"), []byte("unowned temporary"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			first, err := publishOriginalWorkerIOIndex(ctx, worker, id, originals)
			if name == "ordinary_unknown_Open_not_replayed_created" {
				if err == nil || first == nil || first.files[bodyName] == nil || first.files[bodyName].writer == nil || first.files[bodyName].writer.file != nil {
					t.Fatal("failed Open became acquisition")
				}
				attempt := first.files[bodyName]
				laterCtx, cancel := context.WithDeadline(ctx, time.Now().Add(20*time.Second))
				defer cancel()
				later := id
				later.Phase = "created"
				d, _ := laterCtx.Deadline()
				later.OriginalEffectiveContextDeadline = d.UTC().Format(time.RFC3339Nano)
				audit, e := newLedger(laterCtx, id.WorkerOwnerID, "factory_ordinary_worker", id.WorkerBasalSHA256, id.BindingSchema, id.BindingSHA256)
				if e != nil {
					t.Fatal(e)
				}
				audit.sourceProfile, audit.collection.sourceProfile = worker.publisher.sourceProfile, worker.publisher.sourceProfile
				owner := &originalWorkerIOTransferOwner{publisher: worker.publisher, audit: audit, anchor: worker.anchor, uid: worker.uid, gid: worker.gid, cache: worker.cache}
				if _, e := publishOriginalWorkerIOIndex(laterCtx, owner, later, originals); e == nil || worker.cache.published[bodyName] != attempt || len(audit.handleOrder) != 0 {
					t.Fatal("unknown original Open retried or taken over")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			foreign := id
			foreign.BindingSHA256 = strings.Repeat("f", 64)
			if workerIOPublicationComplete(first.files[bodyName], foreign) == nil {
				t.Fatal("returned ordinary streams rebound to foreign binding")
			}
		})
	}
}

// Source assembly input: native_writer_audit_source_test_fragment.go
// Synthetic Source-kernel byte projections only. These records never attest
// kernel methods, compiled source/native approval or actual SQL-FIRST.
func TestHostGetdentsWriterAuditProjectionSource(t *testing.T) {
	origin := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	handle := "00000000-0000-4000-8000-000000000001"
	root := "00000000-0000-4000-8000-000000000002"
	cases := []struct {
		name, operation           string
		scalar                    bool
		raw                       []byte
		count                     int64
		cause                     error
		byteOp, eof, errorPresent bool
	}{
		{"actual_private_write_count", "source_file_write", true, []byte("x"), 1, nil, true, false, false},
		{"actual_empty_file_eof", "source_file_read", true, []byte{}, 0, io.EOF, true, true, true},
		{"actual_partial_read_error", "source_file_read", true, []byte("x"), 1, errors.New("synthetic private refusal"), true, false, true},
		{"nonbyte_fstat_count_unavailable", "source_file_fstat", false, nil, 0, nil, false, false, false},
		{"nonbyte_close_count_unavailable", "source_file_close", false, nil, 0, nil, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := unclassifiedNativeReturn{operation: c.operation, handleID: handle, callID: handle + ":1", ordinal: 1, calledAt: origin, returnedAt: origin.Add(time.Second), deadline: origin.Add(30 * time.Second), private: true, scalarObserved: c.scalar, scalar: c.count, raw: c.raw, cause: c.cause}
			projections, refs, e := writerAuditProject(root, nil, []unclassifiedNativeReturn{x}, nil)
			if e != nil || len(projections) != 1 || len(refs) != 1 || refs[0] != x.callID {
				t.Fatal("Source projection refused")
			}
			f := projections[0].Fact
			if f.OriginalErrorPresent == nil || *f.OriginalErrorPresent != c.errorPresent || f.OriginalSHA256 != nil || f.RetainedPrefixSHA256 != nil || f.RetainedPrefixBytes != nil || f.OriginalReadScope != nil {
				t.Fatal("private facts changed")
			}
			if c.byteOp {
				if f.OriginalCount == nil || *f.OriginalCount != c.count || f.OriginalHashState != "private_withheld" {
					t.Fatal("actual byte count lost")
				}
			} else if f.OriginalCount != nil || f.OriginalHashState != "not_byte_operation" {
				t.Fatal("synthetic scalar")
			}
			if c.operation == "source_file_read" {
				if f.OriginalEOF == nil || *f.OriginalEOF != c.eof {
					t.Fatal("literal EOF lost")
				}
			} else if f.OriginalEOF != nil {
				t.Fatal("invented EOF")
			}
		})
	}
}

func TestHostGetdentsWriterAuditIdentitySource(t *testing.T) {
	h := "00000000-0000-4000-8000-000000000001"
	cases := []struct {
		name, id string
		known    bool
	}{
		{"same_handle_ordinal", h + ":1", true},
		{"last_native_ordinal", h + ":65536", true},
		{"observation_uuid_not_call", h, false},
		{"leading_zero_alias", h + ":01", false},
		{"above_actual_counter_cap", h + ":65537", false},
		{"missing_counter", h + ":", false},
		{"unknown_handle", "unknown:1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, ok := writerAuditCallIdentity(c.id)
			if ok != c.known {
				t.Fatal("call identity changed")
			}
		})
	}
}

func TestHostGetdentsWriterAuditClosedRefusalSource(t *testing.T) {
	cases := []struct {
		name string
		run  func() bool
	}{
		{"no_actual_handle_supplier", func() bool {
			_, _, e := buildOriginalGetdentsWriterAudit(controlRegistrarRequest{}, originalNativeExportGetdents{}, nil, nil, nil)
			return e != nil
		}},
		{"no_original_artifact", func() bool {
			return validateOriginalGetdentsWriterAudit(controlRegistrarRequest{}, originalNativeExportGetdents{}, originalNativeExportGetdentsWriterAudit{}, nil) != nil
		}},
		{"body_cap_plus_one", func() bool {
			return validateOriginalGetdentsWriterAudit(controlRegistrarRequest{}, originalNativeExportGetdents{}, originalNativeExportGetdentsWriterAudit{}, []byte(strings.Repeat("x", bodyLimit+1))) != nil
		}},
		{"nonnull_reference_arrays", func() bool { return !equalWriterAuditRefs(nil, []string{}) }},
		{"foreign_exact_call_ref", func() bool { return !equalWriterAuditRefs([]string{"a:1"}, []string{"a:2"}) }},
		{"missing_writer_original", func() bool { _, e := writerAuditSnapshot(nil, nil); return e != nil }},
		{"private_count_unobserved", func() bool {
			_, _, e := writerAuditProject("00000000-0000-4000-8000-000000000002", nil, []unclassifiedNativeReturn{{operation: "source_file_write", handleID: "00000000-0000-4000-8000-000000000001", callID: "00000000-0000-4000-8000-000000000001:1", calledAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), returnedAt: time.Date(2030, 1, 1, 0, 0, 1, 0, time.UTC), deadline: time.Date(2030, 1, 1, 0, 0, 30, 0, time.UTC), raw: []byte("x"), scalar: 1}}, nil)
			return e != nil
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !c.run() {
				t.Fatal("Source custody refusal lost")
			}
		})
	}
}

// Complete codec-only synthetic vector. No actual ledger/handle/kernel/Source
// approval is supplied: a successful byte decode cannot be native permission.
func writerAuditSyntheticCodecVector(t *testing.T) (controlRegistrarRequest, originalNativeExportGetdents, originalNativeExportGetdentsWriterAudit, originalNativeGetdentsWriterAuditArtifact) {
	t.Helper()
	origin := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	w := "00000000-0000-4000-8000-000000000001"
	m := "00000000-0000-4000-8000-000000000002"
	root := "00000000-0000-4000-8000-000000000003"
	owner := "00000000-0000-4000-8000-000000000004"
	rq := "00000000-0000-4000-8000-000000000005"
	request := controlRegistrarRequest{Schema: "original_private_registrar_request_v1", RequestID: rq, FactoryRootID: root, Phase: "initial", OriginalEffectivePhaseDeadline: origin.Add(30 * time.Second).Format(time.RFC3339Nano), OriginalPhaseCalledAt: ptr(origin.Format(time.RFC3339Nano))}
	native := originalNativeExportGetdents{OriginalCallID: w + ":7", Basename: "original-native-buffer", OriginalBytes: 0, OriginalSHA256: digest(nil), OriginalChunkBodySHA256: strings.Repeat("a", 64), OriginalChunkEnvelopeSHA256: strings.Repeat("b", 64), OriginalOwnerID: owner, BindingSchema: "original_host_factory_root_preparation_v4", BindingSHA256: strings.Repeat("c", 64)}
	ops := []string{"source_file_open", "source_file_fstat", "source_file_sync", "source_file_close", "source_file_rename_noreplace", "source_directory_sync"}
	rows := make([]unclassifiedNativeReturn, 6)
	for i, op := range ops {
		h, n := w, uint64(i+1)
		if i >= 4 {
			h, n = m, uint64(i-3)
		}
		rows[i] = unclassifiedNativeReturn{operation: op, handleID: h, callID: h + ":" + strconv.FormatUint(n, 10), ordinal: n, calledAt: origin.Add(time.Duration(2*i+1) * time.Second), returnedAt: origin.Add(time.Duration(2*i+2) * time.Second), deadline: origin.Add(30 * time.Second)}
	}
	closeID := rows[3].callID
	wp, wr, e := writerAuditProject(root, nil, rows[:4], &closeID)
	if e != nil {
		t.Fatal(e)
	}
	mp, mr, e := writerAuditProject(root, nil, rows[4:], nil)
	if e != nil {
		t.Fatal(e)
	}
	x := originalNativeGetdentsWriterAuditArtifact{Schema: "source_private_original_getdents_writer_audit_v1", FactoryRootID: root, RequestID: rq, Phase: "initial", OriginalCallID: native.OriginalCallID, OriginalChunkBodySHA256: native.OriginalChunkBodySHA256, OriginalChunkEnvelopeSHA256: native.OriginalChunkEnvelopeSHA256, OriginalOwnerID: owner, BindingSchema: native.BindingSchema, BindingSHA256: native.BindingSHA256, OriginalRawSHA256: native.OriginalSHA256, SourceAuditOwnerID: owner, SourceAuditOwnerRole: "host_registrar", SourceAuditBindingSchema: "source_private_original_audit_v1", SourceAuditBindingSHA256: strings.Repeat("d", 64), OriginalWriterHandleID: w, OriginalWriterCloseCallID: closeID, OriginalPublicationMethodHandleID: m, OriginalWriterCallReferences: wr, OriginalPublicationCallReferences: mr, OriginalSourceAuditProjections: append(wp, mp...)}
	ref := originalNativeExportGetdentsWriterAudit{Basename: rq + "-" + digest([]byte(native.OriginalCallID)) + ".writer-audit", RequestID: rq, OriginalCallID: native.OriginalCallID, OriginalChunkBodySHA256: native.OriginalChunkBodySHA256, OriginalChunkEnvelopeSHA256: native.OriginalChunkEnvelopeSHA256, OriginalOwnerID: owner, BindingSchema: native.BindingSchema, BindingSHA256: native.BindingSHA256, OriginalWriterHandleID: w, OriginalWriterCloseCallID: closeID, OriginalPublicationMethodHandleID: m, OriginalWriterCallReferences: wr, OriginalPublicationCallReferences: mr}
	return request, native, ref, x
}
func TestHostGetdentsWriterAuditClosedCodecSource(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*originalNativeGetdentsWriterAuditArtifact)
	}{
		{"known_empty_codec_only", func(*originalNativeGetdentsWriterAuditArtifact) {}},
		{"no_source_call_refs", func(x *originalNativeGetdentsWriterAuditArtifact) { x.OriginalWriterCallReferences = nil }},
		{"method_cannot_borrow_file_close", func(x *originalNativeGetdentsWriterAuditArtifact) {
			x.OriginalSourceAuditProjections[4].OriginalCloseReference = ptr(x.OriginalWriterCloseCallID)
		}},
		{"close_is_same_actual_id", func(x *originalNativeGetdentsWriterAuditArtifact) {
			x.OriginalWriterCloseCallID = x.OriginalWriterCallReferences[2]
		}},
		{"nonbyte_count_must_be_unknown", func(x *originalNativeGetdentsWriterAuditArtifact) {
			x.OriginalSourceAuditProjections[1].Fact.OriginalCount = ptr(int64(0))
		}},
		{"no_private_prefix_digest", func(x *originalNativeGetdentsWriterAuditArtifact) {
			x.OriginalSourceAuditProjections[1].Fact.RetainedPrefixSHA256 = ptr(digest(nil))
		}},
		{"late_actual_method_return", func(x *originalNativeGetdentsWriterAuditArtifact) {
			f := &x.OriginalSourceAuditProjections[5].Fact
			f.OriginalReturnedAt = ptr(f.OriginalOperationDeadline)
		}},
		{"original_error_not_complete", func(x *originalNativeGetdentsWriterAuditArtifact) {
			x.OriginalSourceAuditProjections[2].Fact.OriginalErrorPresent = ptr(true)
		}},
		{"native_observation_id_not_call", func(x *originalNativeGetdentsWriterAuditArtifact) { x.OriginalCallID = x.OriginalOwnerID }},
		{"unknown_source_role", func(x *originalNativeGetdentsWriterAuditArtifact) { x.SourceAuditOwnerRole = "host_worker" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, n, ref, x := writerAuditSyntheticCodecVector(t)
			c.mutate(&x)
			raw, e := json.Marshal(x)
			if e != nil {
				t.Fatal(e)
			}
			ref.OriginalBytes, ref.OriginalSHA256 = len(raw), digest(raw)
			err := validateOriginalGetdentsWriterAudit(r, n, ref, raw)
			if (err == nil) != (c.name == "known_empty_codec_only") {
				t.Fatal("closed codec disposition differs")
			}
		})
	}
}

func TestHostGetdentsWriterAuditClosedShapeSource(t *testing.T) {
	_, _, _, x := writerAuditSyntheticCodecVector(t)
	raw, e := json.Marshal(x)
	if e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"case_fold_alias", []byte(strings.Replace(string(raw), `"schema":`, `"Schema":`, 1))},
		{"duplicate_exact_key", []byte(strings.Replace(string(raw), `"schema":`, `"schema":"extra","schema":`, 1))},
		{"omitted_known_field", []byte(strings.Replace(string(raw), `"schema":"source_private_original_getdents_writer_audit_v1",`, "", 1))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var target originalNativeGetdentsWriterAuditArtifact
			if decodePrivateOriginalJSON(c.raw, &target) == nil {
				t.Fatal("closed Source shape widened")
			}
		})
	}
}
