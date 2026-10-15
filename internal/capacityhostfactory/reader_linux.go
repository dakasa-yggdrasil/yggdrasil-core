//go:build linux

// Package capacityhostfactory owns original Linux handles. Its records are
// observations of calls, not credentials or a replacement for the Core joins.
package capacityhostfactory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const bodyLimit = 65536
const callLimit = 65536

type sourceError struct {
	code  string
	cause error
}

func (e *sourceError) Error() string              { return "host original factory source refused" }
func (e *sourceError) GoString() string           { return e.Error() }
func (e *sourceError) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, e.Error()) }
func refused(code string, cause error) error      { return &sourceError{code: code, cause: cause} }

// RefusalCode never projects an error string, private body, token or key.
func RefusalCode(err error) string {
	var e *sourceError
	if errors.As(err, &e) {
		return e.code
	}
	return "source_registry_refused"
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func newID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", refused("storage_unknown", err)
	}
	return id.String(), nil
}
func ptr[T any](v T) *T { return &v }

// File.Fd switches an os.Pipe reader to blocking mode in Go 1.25. Obtain the
// number through the same live File instead; this leaves its deadline owner
// intact and never opens, duplicates or transfers ownership of the descriptor.
func originalFileNumber(f *os.File) (int, error) {
	if f == nil {
		return -1, refused("original_pipe_refused", nil)
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return -1, refused("original_pipe_refused", err)
	}
	number := -1
	err = raw.Control(func(fd uintptr) { number = int(fd) })
	if err != nil || number < 0 {
		return -1, refused("original_pipe_refused", err)
	}
	return number, nil
}

// Private nonHost transport/bootstrap inputs retain their actual owning calls.
// These are deliberately not encoded as signed native facts in the frozen
// Host grammar. The source audit codec must admit them separately before any
// qualification can be claimed.
func readOriginalPrivateAuditFile(ctx context.Context, rootFD int, l *originalLedger, name string, private bool) (_ []byte, runErr error) {
	if ctx == nil || ctx.Err() != nil || !fixedBasename(name) || l == nil || rootFD < 0 {
		return nil, refused("source_registry_refused", nil)
	}
	h, err := l.handle()
	if err != nil {
		return nil, err
	}
	fd, _, err := h.unclassifiedCall("source_audit_private_open", l.ownerRole, "source_audit", private, func() (int64, []byte, error) {
		n, e := unix.Openat(rootFD, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		return int64(n), nil, e
	})
	if err != nil {
		return nil, refused("source_registry_refused", err)
	}
	h.fd = int(fd)
	h.file = os.NewFile(uintptr(h.fd), "original-private-source-audit-reader")
	defer func() {
		e := h.unclassifiedErrorCall("source_audit_private_close", l.ownerRole, "source_audit", private, h.file.Close)
		h.mu.Lock()
		h.closed = true
		h.mu.Unlock()
		runErr = errors.Join(runErr, e)
	}()
	var before, after unix.Stat_t
	stat := func(target *unix.Stat_t) error {
		value, e := h.unclassifiedFstat("source_audit_private_fstat", l.ownerRole, "source_audit", private)
		*target = value
		return e
	}
	if err = stat(&before); err != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Mode&0077 != 0 || before.Size < 1 || before.Size > bodyLimit {
		return nil, refused("source_registry_refused", err)
	}
	var data []byte
	for len(data) <= bodyLimit {
		if ctx.Err() != nil {
			return data, refused("original_context_refused", ctx.Err())
		}
		buffer := make([]byte, bodyLimit+1-len(data))
		n, actual, e := h.unclassifiedCall("source_audit_private_read", l.ownerRole, "source_audit", private, func() (int64, []byte, error) {
			n, e := h.file.Read(buffer)
			return int64(n), bytes.Clone(buffer[:n]), e
		})
		data = append(data, actual...)
		if e == io.EOF {
			if err = stat(&after); err != nil || !sameOriginalFileStat(before, after) || len(data) > bodyLimit || len(data) == 0 || ctx.Err() != nil {
				return data, refused("source_registry_refused", errors.Join(err, ctx.Err()))
			}
			return data, nil
		}
		if e != nil || n == 0 || len(data) > bodyLimit {
			return data, refused("original_pipe_refused", e)
		}
	}
	return data, refused("original_pipe_refused", nil)
}

// Private existing Core records are not one of the Host wire schemas. Decode
// their exact declared JSON keys without rewriting the retained original bytes.
// This also prevents encoding/json's case-insensitive key aliases and duplicate
// key last-value behavior from changing a projection's meaning.
func decodePrivateOriginalJSON(raw []byte, target any) error {
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() || len(raw) == 0 || len(raw) > bodyLimit || !utf8.Valid(raw) {
		return refused("original_issue_refused", nil)
	}
	if err := privateOriginalJSONShape(raw, v.Elem().Type(), 0); err != nil {
		return err
	}
	fresh := reflect.New(v.Elem().Type())
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(fresh.Interface()); err != nil {
		return refused("original_issue_refused", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return refused("original_issue_refused", err)
	}
	v.Elem().Set(fresh.Elem())
	return nil
}

func privateOriginalJSONShape(raw []byte, typ reflect.Type, depth int) error {
	if depth > 48 || !json.Valid(raw) {
		return refused("original_issue_refused", nil)
	}
	if typ.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		return privateOriginalJSONShape(raw, typ.Elem(), depth+1)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) && typ.Kind() == reflect.Slice {
		// Existing private Core records retain nil slices as null. This is a
		// decoded unavailable value, never converted into an EMPTY census.
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return refused("original_issue_refused", nil)
	}
	if typ == reflect.TypeOf(time.Time{}) {
		var actual time.Time
		if err := json.Unmarshal(raw, &actual); err != nil {
			return refused("original_issue_refused", err)
		}
		return nil
	}
	if typ == reflect.TypeOf(uuid.UUID{}) {
		var actual uuid.UUID
		var text string
		if json.Unmarshal(raw, &text) != nil || json.Unmarshal(raw, &actual) != nil || actual == uuid.Nil || actual.String() != text {
			return refused("original_issue_refused", nil)
		}
		return nil
	}
	if typ == reflect.TypeOf([]byte{}) {
		// encoding/json represents the built-in byte slice as a base64 string.
		// Preserve that exact private representation, including known empty
		// bytes. Named slices and RawMessage keep their existing shape rules.
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return refused("original_issue_refused", err)
		}
		actual, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(actual) > bodyLimit || base64.StdEncoding.EncodeToString(actual) != encoded {
			return refused("original_issue_refused", err)
		}
		canonical, err := json.Marshal(encoded)
		if err != nil || !bytes.Equal(raw, canonical) {
			return refused("original_issue_refused", err)
		}
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		fields := map[string]reflect.StructField{}
		required := map[string]bool{}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			if f.PkgPath != "" || tag[0] == "" || tag[0] == "-" {
				return refused("original_issue_refused", nil)
			}
			fields[tag[0]] = f
			required[tag[0]] = !strings.Contains(f.Tag.Get("json"), ",omitempty")
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		opening, err := d.Token()
		if err != nil || opening != json.Delim('{') {
			return refused("original_issue_refused", err)
		}
		seen := map[string]bool{}
		for d.More() {
			token, err := d.Token()
			name, ok := token.(string)
			field, declared := fields[name]
			if err != nil || !ok || !declared || seen[name] {
				return refused("original_issue_refused", err)
			}
			seen[name] = true
			var child json.RawMessage
			if err = d.Decode(&child); err != nil {
				return refused("original_issue_refused", err)
			}
			if err = privateOriginalJSONShape(child, field.Type, depth+1); err != nil {
				return err
			}
		}
		if _, err = d.Token(); err != nil {
			return refused("original_issue_refused", err)
		}
		for name, mandatory := range required {
			if mandatory && !seen[name] {
				return refused("original_issue_refused", nil)
			}
		}
	case reflect.Slice, reflect.Array:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil || typ.Kind() == reflect.Array && len(items) != typ.Len() {
			return refused("original_issue_refused", err)
		}
		for _, item := range items {
			if err := privateOriginalJSONShape(item, typ.Elem(), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// A handle ID is reserved by the acquiring owner. It does not claim that an
// Open returned, or that a descriptor has been acquired.
type callHandle struct {
	id                      string
	mu                      sync.Mutex
	next                    uint64
	pending                 bool
	closed                  bool
	active                  *retainedCall
	closeOnce               sync.Once
	closeAt                 time.Time
	closeCall               *retainedCall // actual sole admitted Close reservation; NULL on diagnostic fallback
	closeErr                error
	ledger                  *originalLedger
	file                    *os.File
	fd                      int
	unclassified            []unclassifiedNativeReturn
	workerFrameReads        []*originalWorkerReadCustody     // actual private reader owners, registered before IO
	parentWorkerFrameReads  []*originalParentWorkerFrameRead // sealed parent sole stdout collectors, beforeIO
	ordinaryAuthorityReturn *originalOrdinaryAuthorityReturn // private actual request/response; no wire encoder
}

type retainedCall struct {
	subjectRole, stage string // lexical call purpose retained before publication; no wire authority
	cause              error  // exact original cause PRIVATE; never an error string/hash in a BODY
	originalRaw        []byte // private SAME returned kernel bytes; never parsed/re-rendered data
	originalRawKnown   bool   // an actual empty buffer is distinct from unknown/pending
	fact               model.HostFactoryPrimitiveIOReturn
	firstSHA           string
	pendingPublished   bool
	finalSHA           string
}

// These actual syscall returns deliberately have NO admitted wire encoder.
// They preserve evidence when the frozen operation grammar lacks a tuple.
// A source consumer must retain INCOMPLETE/HOLD, never silently omit them or
// relabel fcntl/getdents as File.Read/fstat.
type unclassifiedNativeReturn struct {
	scalarObserved                                                                      bool
	stat                                                                                *unix.Stat_t
	operation, ownerID, subjectRole, stage, bindingSchema, bindingSHA, handleID, callID string
	ordinal                                                                             uint64
	calledAt, returnedAt, deadline                                                      time.Time
	scalar                                                                              int64
	raw                                                                                 []byte
	rawOmitted                                                                          bool // lexical streaming scope; never integral RAW or Native
	statfs                                                                              *unix.Statfs_t
	ucred                                                                               *unix.Ucred
	private                                                                             bool
	cause                                                                               error
}

func (h *callHandle) unclassifiedCall(operation, subject, stage string, private bool, action func() (int64, []byte, error)) (int64, []byte, error) {
	h.mu.Lock()
	if h.next >= callLimit-1 || h.closed {
		h.mu.Unlock()
		return 0, nil, refused("storage_unknown", nil)
	}
	h.next++
	ordinal := h.next
	at := time.Now().UTC()
	index := len(h.unclassified)
	h.unclassified = append(h.unclassified, unclassifiedNativeReturn{operation: operation, ownerID: h.ledger.ownerID, subjectRole: subject, stage: stage, bindingSchema: h.ledger.bindingSchema, bindingSHA: h.ledger.bindingSHA, handleID: h.id, callID: h.id + ":" + strconv.FormatUint(ordinal, 10), ordinal: ordinal, calledAt: at, deadline: h.ledger.deadline, private: private})
	h.mu.Unlock()
	value, raw, err := action()
	returned := time.Now().UTC()
	h.mu.Lock()
	actual := &h.unclassified[index]
	actual.returnedAt, actual.scalar, actual.scalarObserved, actual.raw, actual.cause = returned, value, true, bytes.Clone(raw), err
	h.mu.Unlock()
	return value, raw, err
}

func (h *callHandle) unclassifiedErrorCall(operation, subject, stage string, private bool, action func() error) error {
	_, err := h.unclassifiedErrorReturn(operation, subject, stage, private, func() (*unix.Stat_t, error) { return nil, action() })
	return err
}

func (h *callHandle) unclassifiedFstat(operation, subject, stage string, private bool) (unix.Stat_t, error) {
	value, err := h.unclassifiedErrorReturn(operation, subject, stage, private, func() (*unix.Stat_t, error) {
		var value unix.Stat_t
		err := unix.Fstat(h.fd, &value)
		if err != nil {
			return nil, err
		}
		return &value, nil
	})
	if value == nil {
		return unix.Stat_t{}, err
	}
	return *value, err
}

// Fstat/File.Close expose an actual error return, not a native scalar. Retain
// scalarObserved=false and a stat only when the actual Fstat returned it.
func (h *callHandle) unclassifiedErrorReturn(operation, subject, stage string, private bool, action func() (*unix.Stat_t, error)) (*unix.Stat_t, error) {
	h.mu.Lock()
	if h.next >= callLimit-1 || h.closed {
		h.mu.Unlock()
		return nil, refused("storage_unknown", nil)
	}
	h.next++
	ordinal := h.next
	at := time.Now().UTC()
	index := len(h.unclassified)
	h.unclassified = append(h.unclassified, unclassifiedNativeReturn{operation: operation, ownerID: h.ledger.ownerID, subjectRole: subject, stage: stage, bindingSchema: h.ledger.bindingSchema, bindingSHA: h.ledger.bindingSHA, handleID: h.id, callID: h.id + ":" + strconv.FormatUint(ordinal, 10), ordinal: ordinal, calledAt: at, deadline: h.ledger.deadline, private: private})
	h.mu.Unlock()
	value, err := action()
	returned := time.Now().UTC()
	var retained *unix.Stat_t
	if value != nil {
		copy := *value
		retained = &copy
	}
	h.mu.Lock()
	actual := &h.unclassified[index]
	actual.returnedAt, actual.stat, actual.cause = returned, retained, err
	h.mu.Unlock()
	return value, err
}

func (h *callHandle) lastOriginalNativeReturn(operation string) (unclassifiedNativeReturn, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for index := len(h.unclassified) - 1; index >= 0; index-- {
		value := h.unclassified[index]
		if value.operation == operation {
			value.raw = bytes.Clone(value.raw)
			if value.statfs != nil {
				c := *value.statfs
				value.statfs = &c
			}
			if value.ucred != nil {
				c := *value.ucred
				value.ucred = &c
			}
			if value.stat != nil {
				copy := *value.stat
				value.stat = &copy
			}
			return value, true
		}
	}
	return unclassifiedNativeReturn{}, false
}

// OriginalIOCollection exposes copies of immutable original BODYs. SQL13 and
// signature/native authentication belong to the separately scoped receiver.
type OriginalIOCollection struct {
	sourceProfile *capacity.HostFactorySourceProfile // immutable genuine Source-scoped constructor only
	purposes      map[string][]capacity.HostFactorySourceCallPurpose
	mu            sync.Mutex
	bodies        map[string][]byte
	predecessors  map[string]string
	first         map[string]bool
}

// This compares only the immutable request reserved before the original call.
// Returned native outputs are deliberately excluded: they did not exist in the
// published pending singleton and cannot change its original request identity.
func originalSourcePendingRequestEqual(pending, returned model.HostFactoryPrimitiveIOReturn) bool {
	if pending.Operation != returned.Operation || pending.OriginalHandleID != returned.OriginalHandleID || pending.SubjectOwnerID != returned.SubjectOwnerID || !reflect.DeepEqual(pending.OwnerPrimitiveRawSHA256, returned.OwnerPrimitiveRawSHA256) || !reflect.DeepEqual(pending.OriginalCallID, returned.OriginalCallID) || !reflect.DeepEqual(pending.OriginalCallOrdinal, returned.OriginalCallOrdinal) || pending.OriginalCalledAt == nil || returned.OriginalCalledAt == nil || !pending.OriginalCalledAt.Equal(*returned.OriginalCalledAt) || !pending.OriginalOperationDeadline.Equal(returned.OriginalOperationDeadline) {
		return false
	}
	if pending.OriginalNativeReturn == nil || returned.OriginalNativeReturn == nil {
		return pending.OriginalNativeReturn == nil && returned.OriginalNativeReturn == nil
	}
	request := func(n model.HostFactoryNativeCallReturn) model.HostFactoryNativeCallReturn {
		n.OriginalScalar, n.OriginalErrno, n.OriginalErrorPresent = nil, nil, nil
		n.OriginalStat, n.ReturnedDescriptors = nil, nil
		n.OriginalPollRevents, n.ReturnedPID, n.OriginalExitCode = nil, nil, nil
		return n
	}
	return reflect.DeepEqual(request(*pending.OriginalNativeReturn), request(*returned.OriginalNativeReturn))
}

// Source custody ONLY, before SQL exists. This checks the original retained
// Source association and selected whole handle graph; it deliberately does not
// invoke a Pure predecessor callback or certify immutable SQL FIRST.
func checkOriginalSourceCallVector(ref model.HostFactoryCallVectorReference, c *OriginalIOCollection) ([]model.HostFactoryPrimitiveIOReturn, error) {
	if c == nil || c.validate(ref) != nil {
		return nil, refused("storage_unknown", nil)
	}
	if ref.OriginalCallCount == 0 {
		return nil, nil
	} // syntax only; never absence/admission
	if ref.ManifestRootSHA256 == nil || ref.CollectionState != "complete_original_calls" {
		return nil, refused("storage_unknown", nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]bool{}
	namespaceSchema, namespaceSHA, namespaceRole := "", "", ""
	join := func(schema, sha, role string) error {
		if namespaceSchema == "" {
			namespaceSchema, namespaceSHA, namespaceRole = schema, sha, role
			return nil
		}
		if schema != namespaceSchema || sha != namespaceSHA || role != namespaceRole {
			return refused("storage_unknown", nil)
		}
		return nil
	}
	var walk func(string) ([]model.HostFactoryPrimitiveIOReturn, error)
	walk = func(sha string) ([]model.HostFactoryPrimitiveIOReturn, error) {
		if seen[sha] {
			return nil, refused("storage_unknown", nil)
		}
		seen[sha] = true
		raw, known := c.bodies[sha]
		if !known || digest(raw) != sha {
			return nil, refused("storage_unknown", nil)
		}
		var chunk model.HostFactoryCallVectorChunk
		if c.decode(raw, &chunk) == nil {
			if join(chunk.BindingSchema, chunk.BindingSHA256, chunk.OwnerRole) != nil || chunk.Operation != ref.Operation || chunk.OriginalHandleID != ref.OriginalHandleID || chunk.OriginalOwnerID != ref.OriginalOwnerID || ref.OwnerPrimitiveRawSHA256 == nil || chunk.OwnerPrimitiveRawSHA256 != *ref.OwnerPrimitiveRawSHA256 {
				return nil, refused("storage_unknown", nil)
			}
			for index, f := range chunk.OriginalCalls {
				if f.OriginalState != "returned" || f.SubjectOwnerID != ref.SubjectOwnerID {
					return nil, refused("storage_unknown", nil)
				}
				if previous, exists := c.predecessors[sha]; exists {
					var pending model.HostFactoryCallVectorChunk
					if index != 0 || len(chunk.OriginalCalls) != 1 || c.decode(c.bodies[previous], &pending) != nil || len(pending.OriginalCalls) != 1 || pending.OriginalCalls[0].OriginalState != "called_pending" {
						return nil, refused("storage_unknown", nil)
					}
					p := pending.OriginalCalls[0]
					if !originalSourcePendingRequestEqual(p, f) || !c.first[previous+":0"] || c.first[sha+":0"] || pending.OriginalOwnerID != chunk.OriginalOwnerID || pending.OriginalHandleID != chunk.OriginalHandleID || pending.OwnerPrimitiveRawSHA256 != chunk.OwnerPrimitiveRawSHA256 || pending.OwnerRole != chunk.OwnerRole || pending.BindingSchema != chunk.BindingSchema || pending.BindingSHA256 != chunk.BindingSHA256 || pending.Operation != chunk.Operation || !reflect.DeepEqual(c.purposes[previous], c.purposes[sha]) {
						return nil, refused("storage_unknown", nil)
					}
				} else if !c.first[sha+":"+strconv.FormatUint(uint64(index), 10)] {
					return nil, refused("storage_unknown", nil)
				}
			}
			return append([]model.HostFactoryPrimitiveIOReturn(nil), chunk.OriginalCalls...), nil
		}
		var m model.HostFactoryCallVectorManifest
		if c.decode(raw, &m) != nil || join(m.BindingSchema, m.BindingSHA256, m.OwnerRole) != nil || m.Operation != ref.Operation || m.OriginalHandleID != ref.OriginalHandleID || m.OriginalOwnerID != ref.OriginalOwnerID || ref.OwnerPrimitiveRawSHA256 == nil || m.OwnerPrimitiveRawSHA256 != *ref.OwnerPrimitiveRawSHA256 || m.CollectionState != "complete_original_calls" {
			return nil, refused("storage_unknown", nil)
		}
		var all []model.HostFactoryPrimitiveIOReturn
		for _, child := range m.ChildBodySHAs {
			childRaw, ok := c.bodies[child]
			if !ok {
				return nil, refused("storage_unknown", nil)
			}
			if m.Level == 0 {
				var leaf model.HostFactoryCallVectorChunk
				if c.decode(childRaw, &leaf) != nil {
					return nil, refused("storage_unknown", nil)
				}
			} else {
				var branch model.HostFactoryCallVectorManifest
				if c.decode(childRaw, &branch) != nil || branch.Level+1 != m.Level {
					return nil, refused("storage_unknown", nil)
				}
			}
			rows, e := walk(child)
			if e != nil {
				return nil, e
			}
			all = append(all, rows...)
		}
		if len(all) == 0 || uint64(len(all)) != m.OriginalCallCount || all[0].OriginalCallOrdinal == nil || all[len(all)-1].OriginalCallOrdinal == nil || *all[0].OriginalCallOrdinal != m.FirstOrdinal || *all[len(all)-1].OriginalCallOrdinal != m.LastOrdinal {
			return nil, refused("storage_unknown", nil)
		}
		return all, nil
	}
	rows, e := walk(*ref.ManifestRootSHA256)
	if e != nil || uint64(len(rows)) != ref.OriginalCallCount || len(rows) == 0 || *rows[0].OriginalCallOrdinal != ref.FirstOrdinal || *rows[len(rows)-1].OriginalCallOrdinal != ref.LastOrdinal {
		return nil, refused("storage_unknown", e)
	}
	for n := 1; n < len(rows); n++ {
		if *rows[n].OriginalCallOrdinal <= *rows[n-1].OriginalCallOrdinal || rows[n-1].OriginalReturnedAt == nil || rows[n].OriginalCalledAt == nil || rows[n].OriginalCalledAt.Before(*rows[n-1].OriginalReturnedAt) {
			return nil, refused("storage_unknown", nil)
		}
	}
	return rows, nil
}

func checkOriginalSourceHandleInventory(inv model.HostFactoryHandleCallInventory, c *OriginalIOCollection) error {
	if c == nil || c.validate(inv) != nil || inv.CollectionState != "complete_original_calls" {
		return refused("storage_unknown", nil)
	}
	union := map[uint64]model.HostFactoryPrimitiveIOReturn{}
	for _, ref := range inv.OperationVectors {
		if ref.OriginalHandleID != inv.OriginalHandleID || ref.OriginalOwnerID != inv.OriginalOwnerID {
			return refused("storage_unknown", nil)
		}
		calls, e := checkOriginalSourceCallVector(ref, c)
		if e != nil {
			return e
		}
		if ref.ManifestRootSHA256 != nil {
			raw, e := c.Resolve(*ref.ManifestRootSHA256)
			var m model.HostFactoryCallVectorManifest
			if e != nil || c.decode(raw, &m) != nil || m.BindingSchema != inv.BindingSchema || m.BindingSHA256 != inv.BindingSHA256 || m.OwnerRole != inv.OwnerRole {
				return refused("storage_unknown", e)
			}
		}
		for _, f := range calls {
			if f.OriginalCallOrdinal == nil {
				return refused("storage_unknown", nil)
			}
			ordinal := *f.OriginalCallOrdinal
			if _, exists := union[ordinal]; exists {
				return refused("storage_unknown", nil)
			}
			union[ordinal] = f
		}
	}
	if uint64(len(union)) != inv.OriginalCallCount || inv.LastOrdinal != inv.OriginalCallCount {
		return refused("storage_unknown", nil)
	}
	var previous *time.Time
	for ordinal := uint64(1); ordinal <= inv.LastOrdinal; ordinal++ {
		f, found := union[ordinal]
		if !found || f.OriginalCalledAt == nil || f.OriginalReturnedAt == nil || previous != nil && f.OriginalCalledAt.Before(*previous) || f.OriginalReturnedAt.After(inv.OriginalOperationDeadline) {
			return refused("storage_unknown", nil)
		}
		previous = f.OriginalReturnedAt
	}
	return nil
}

func (c *OriginalIOCollection) Resolve(sha string) ([]byte, error) {
	if c == nil {
		return nil, refused("storage_unknown", nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.bodies[sha]
	if !ok {
		return nil, refused("storage_unknown", nil)
	}
	return bytes.Clone(b), nil
}
func (c *OriginalIOCollection) Predecessor(sha string, index uint32) ([]byte, uint32, error) {
	if c == nil {
		return nil, 0, refused("storage_unknown", nil)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.predecessors[sha]
	if !ok {
		if c.first[sha+":"+strconv.FormatUint(uint64(index), 10)] {
			return nil, 0, nil
		}
		return nil, 0, refused("storage_unknown", nil)
	}
	if index != 0 {
		return nil, 0, refused("storage_unknown", nil)
	}
	b, ok := c.bodies[p]
	if !ok {
		return nil, 0, refused("storage_unknown", nil)
	}
	return bytes.Clone(b), 0, nil
}
func (c *OriginalIOCollection) OriginalBodies() map[string][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	x := make(map[string][]byte, len(c.bodies))
	for k, v := range c.bodies {
		x[k] = bytes.Clone(v)
	}
	return x
}
func (c *OriginalIOCollection) put(value any, previous string) (string, error) {
	return c.putOriginal(value, previous, []capacity.HostFactorySourceCallPurpose{})
}

func (c *OriginalIOCollection) putOriginal(value any, previous string, purposes []capacity.HostFactorySourceCallPurpose) (string, error) {
	b, err := c.canonical(value)
	if err != nil || len(b) > bodyLimit {
		return "", refused("storage_unknown", err)
	}
	if err := c.checkOriginalPurposes(value, purposes); err != nil {
		return "", err
	}
	s := digest(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	if prior, ok := c.bodies[s]; ok && (!bytes.Equal(prior, b) || !reflect.DeepEqual(c.purposes[s], purposes)) {
		return "", refused("storage_unknown", nil)
	}
	if previous != "" {
		if prior, ok := c.predecessors[s]; ok && prior != previous {
			return "", refused("storage_unknown", nil)
		}
		var pending, returned model.HostFactoryCallVectorChunk
		if previous == s || c.decode(c.bodies[previous], &pending) != nil || c.decode(b, &returned) != nil || len(pending.OriginalCalls) != 1 || len(returned.OriginalCalls) != 1 || pending.OriginalCalls[0].OriginalState != "called_pending" || returned.OriginalCalls[0].OriginalState != "returned" || !originalSourcePendingRequestEqual(pending.OriginalCalls[0], returned.OriginalCalls[0]) || !c.first[previous+":0"] || c.first[s+":0"] || pending.BindingSchema != returned.BindingSchema || pending.BindingSHA256 != returned.BindingSHA256 || pending.OriginalOwnerID != returned.OriginalOwnerID || pending.OwnerRole != returned.OwnerRole || pending.OwnerPrimitiveRawSHA256 != returned.OwnerPrimitiveRawSHA256 || !reflect.DeepEqual(c.purposes[previous], purposes) {
			return "", refused("storage_unknown", nil)
		}
	}
	if c.purposes == nil {
		c.purposes = map[string][]capacity.HostFactorySourceCallPurpose{}
	}
	c.purposes[s] = append([]capacity.HostFactorySourceCallPurpose{}, purposes...)
	c.bodies[s] = bytes.Clone(b)
	if chunk, ok := value.(model.HostFactoryCallVectorChunk); ok && previous == "" {
		if c.first == nil {
			c.first = map[string]bool{}
		}
		for index := range chunk.OriginalCalls {
			c.first[s+":"+strconv.Itoa(index)] = true
		}
	}
	if previous != "" {
		c.predecessors[s] = previous
	}
	return s, nil
}

type originalLedger struct {
	sourceProfile                                               *capacity.HostFactorySourceProfile // SAME pointer as scoped collection/publisher
	mu                                                          sync.Mutex
	ctx                                                         context.Context
	ownerID, ownerRole, primitiveSHA, bindingSchema, bindingSHA string
	deadline                                                    time.Time
	calls                                                       map[string][]*retainedCall
	handles                                                     map[string]*callHandle
	handleOrder                                                 []*callHandle // reserved before each handle's first IO
	subjects                                                    map[string]string
	collection                                                  *OriginalIOCollection
}

func newLedger(ctx context.Context, ownerID, role, primitiveSHA, schema, sha string) (*originalLedger, error) {
	d, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil || !capacity.ValidDigest(primitiveSHA) || !capacity.ValidDigest(sha) {
		return nil, refused("original_context_refused", nil)
	}
	return &originalLedger{ctx: ctx, ownerID: ownerID, ownerRole: role, primitiveSHA: primitiveSHA, bindingSchema: schema, bindingSHA: sha, deadline: d.UTC(), calls: map[string][]*retainedCall{}, handles: map[string]*callHandle{}, subjects: map[string]string{role: ownerID}, collection: &OriginalIOCollection{bodies: map[string][]byte{}, predecessors: map[string]string{}}}, nil
}
func (l *originalLedger) handle() (*callHandle, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	h := &callHandle{id: id, ledger: l, fd: -1}
	l.mu.Lock()
	l.handles[id] = h
	l.handleOrder = append(l.handleOrder, h)
	l.mu.Unlock()
	return h, nil
}

// Acquisition/method order belongs to the original ledger, including failed
// Opens and non-FD publication methods. No later caller-selected list or UUID
// ordering can silently remove a key/RPC diagnostic from the final handoff.
func (l *originalLedger) originalHandles() ([]*callHandle, error) {
	if l == nil {
		return nil, refused("storage_unknown", nil)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	seen := make(map[string]bool, len(l.handleOrder))
	for _, h := range l.handleOrder {
		if h == nil || h.id == "" || h.ledger != l || seen[h.id] || l.handles[h.id] != h {
			return append([]*callHandle(nil), l.handleOrder...), refused("storage_unknown", nil)
		}
		seen[h.id] = true
	}
	if len(seen) != len(l.handles) {
		return append([]*callHandle(nil), l.handleOrder...), refused("storage_unknown", nil)
	}
	return append([]*callHandle(nil), l.handleOrder...), nil
}

func (h *callHandle) begin(operation, subject, stage string, cleanup bool) (*retainedCall, error) {
	return h.beginWithNative(operation, subject, stage, cleanup, nil)
}

func (h *callHandle) beginWithNative(operation, subject, stage string, cleanup bool, native *model.HostFactoryNativeCallReturn) (*retainedCall, error) {
	l := h.ledger
	envelope := "HostFactoryRootSignedEnvelope"
	if l.bindingSchema == "original_host_factory_pre_authority_scope_v4" {
		envelope = "HostFactorySignedEnvelope"
	}
	if l.bindingSchema == "original_host_factory_pre_authority_scope_v4" {
		if l.sourceProfile == nil || l.collection.sourceProfile != l.sourceProfile {
			return nil, refused("source_registry_refused", nil)
		}
		var kind *string
		if native != nil {
			kind = ptr(native.Kind)
		}
		if err := l.sourceProfile.ValidateOperation(operation, l.ownerRole, subject, stage, l.bindingSchema, envelope, kind); err != nil {
			return nil, refused("source_registry_refused", err)
		}
	} else if err := capacity.ValidateHostFactoryOperation(operation, l.ownerRole, subject, stage, l.bindingSchema, envelope); err != nil {
		return nil, refused("source_registry_refused", err)
	}
	if !cleanup && (l.ctx.Err() != nil || !time.Now().Before(l.deadline)) {
		return nil, refused("original_context_refused", l.ctx.Err())
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// The final ordinal is reserved for the SAME original Close, including
	// after a stream exhausted its bounded call inventory.
	ceiling := uint64(callLimit - 1)
	if cleanup && len(operation) >= 6 && operation[len(operation)-6:] == "_close" {
		ceiling = callLimit
	}
	// A cleanup Close may cancel this SAME endpoint, but it cannot acquire a
	// new admitted ordinal while its original Read/syscall remains pending.
	// The caller retains such a real Close as unclassified/incomplete.
	if h.pending || h.closed || h.next >= ceiling {
		return nil, refused("storage_unknown", nil)
	}
	l.mu.Lock()
	subjectID := l.subjects[subject]
	l.mu.Unlock()
	if subjectID == "" {
		return nil, refused("native_join_refused", nil)
	}
	h.next++
	ordinal := h.next
	id := h.id + ":" + strconv.FormatUint(ordinal, 10)
	at := time.Now().UTC()
	r := &retainedCall{subjectRole: subject, stage: stage, fact: model.HostFactoryPrimitiveIOReturn{Operation: operation, OriginalHandleID: h.id, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), OriginalState: "called_pending", OriginalCalledAt: &at, OriginalReturnClass: "unavailable", SubjectOwnerID: subjectID, OriginalOperationDeadline: l.deadline, OriginalHashState: "unknown_original_bytes", OriginalCallOrdinal: &ordinal, OriginalCallID: &id}}
	r.fact.OriginalNativeReturn = native
	if !cleanup {
		h.pending = true
		h.active = r
	}
	l.mu.Lock()
	l.calls[h.id+"\x00"+operation] = append(l.calls[h.id+"\x00"+operation], r)
	l.mu.Unlock()
	return r, nil
}
func (h *callHandle) finish(r *retainedCall, returnedAt time.Time, n *int64, sha *string, hashState, class string, eof *bool) {
	h.finishNative(r, returnedAt, n, sha, hashState, class, eof, nil)
}

// The returned native sidecar and its original call state are published under
// the same locks. A vector cannot observe a terminal call with pending outputs.
func (h *callHandle) finishNative(r *retainedCall, returnedAt time.Time, n *int64, sha *string, hashState, class string, eof *bool, native *model.HostFactoryNativeCallReturn) {
	h.finishOriginal(r, returnedAt, n, sha, hashState, class, eof, native, nil)
}
func (h *callHandle) finishOriginal(r *retainedCall, returnedAt time.Time, n *int64, sha *string, hashState, class string, eof *bool, native *model.HostFactoryNativeCallReturn, cause error) {
	h.finishOriginalRaw(r, returnedAt, n, sha, hashState, class, eof, native, cause, nil, false)
}

func (h *callHandle) finishOriginalRaw(r *retainedCall, returnedAt time.Time, n *int64, sha *string, hashState, class string, eof *bool, native *model.HostFactoryNativeCallReturn, cause error, raw []byte, rawKnown bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	r.fact.OriginalState = "returned"
	r.fact.OriginalReturnedAt = ptr(returnedAt.UTC())
	r.fact.OriginalCount = n
	r.fact.OriginalSHA256 = sha
	r.fact.OriginalHashState = hashState
	r.fact.OriginalReturnClass = class
	r.fact.OriginalEOF = eof
	r.fact.OriginalNativeReturn = native
	r.cause = cause
	r.originalRawKnown = rawKnown
	if rawKnown {
		r.originalRaw = append(make([]byte, 0, len(raw)), raw...)
	}
	if h.active == r {
		h.pending = false
		h.active = nil
	}
}

// Native results describe the original API's actual returned values. Error-only
// methods have no scalar; a failed Fstat has no stat; no requested flag is an
// observed flag. Callers are private lexical owners of the actual syscall.
type originalNativeResult struct {
	call                 *retainedCall
	calledAt, returnedAt time.Time
	raw                  []byte
	scalar               *int64
	stat                 *model.HostFactoryNativeStatReturn
	descriptors          []model.HostFactoryNativeAcquiredDescriptor
	revents              *uint32
	pid                  *int
	exitCode             *int
	cause                error
}

func nativeStat(st unix.Stat_t) model.HostFactoryNativeStatReturn {
	return model.HostFactoryNativeStatReturn{Device: uint64(st.Dev), Inode: st.Ino, Mode: st.Mode, LinkCount: uint64(st.Nlink), UID: st.Uid, GID: st.Gid, Size: st.Size}
}

func (h *callHandle) nativeCall(operation, subject, stage string, cleanup bool, request model.HostFactoryNativeCallReturn, action func() originalNativeResult) (originalNativeResult, error) {
	// Clear every output before the syscall. Its known request is retained even
	// if the original owner never returns; it cannot become a returned fact.
	request.OriginalScalar, request.OriginalErrno, request.OriginalErrorPresent = nil, nil, nil
	request.OriginalStat, request.ReturnedDescriptors = nil, nil
	request.OriginalPollRevents, request.ReturnedPID, request.OriginalExitCode = nil, nil, nil
	// Reserve the pending CallID and attach all known request values under
	// the SAME publication lock. No pending snapshot can omit this request.
	call, err := h.beginWithNative(operation, subject, stage, cleanup, ptr(request))
	if err != nil {
		return originalNativeResult{}, err
	}
	value := action()
	returnedAt := time.Now().UTC()
	// Only this actual owning boundary supplies times; the lexical syscall
	// action cannot substitute a requested/after-join sample as its return.
	value.call, value.calledAt, value.returnedAt = call, *call.fact.OriginalCalledAt, returnedAt
	value.raw = bytes.Clone(value.raw)
	request.OriginalScalar = value.scalar
	request.OriginalStat = value.stat
	request.ReturnedDescriptors = append([]model.HostFactoryNativeAcquiredDescriptor(nil), value.descriptors...)
	request.OriginalPollRevents, request.ReturnedPID, request.OriginalExitCode = value.revents, value.pid, value.exitCode
	request.OriginalErrorPresent = ptr(value.cause != nil)
	class := "success"
	if value.cause == nil {
		request.OriginalErrno = ptr(uint32(0))
	} else {
		class = "io_refused"
		var errno syscall.Errno
		if errors.As(value.cause, &errno) {
			request.OriginalErrno = ptr(uint32(errno))
		}
	}
	var count *int64
	var hash *string
	var eof *bool
	hashState := "not_byte_operation"
	if request.Kind == "unix_getdents64" {
		// Getdents is a kernel byte return with an exposed scalar. Its
		// n=0,nil terminal is NOT File.Read/io.EOF. Preserve actual bytes
		// and count independently; a disagreement is an incomplete fact.
		hashState = "unknown_original_bytes"
		eof = ptr(false)
		if value.scalar != nil && *value.scalar >= 0 {
			count = ptr(*value.scalar)
			if int64(len(value.raw)) == *value.scalar && len(value.raw) <= bodyLimit {
				hash, hashState = ptr(digest(value.raw)), "actual_public_bytes"
			}
			if *value.scalar == 0 && value.cause == nil {
				class = "native_zero_return"
			}
		}
	}
	rawKnown := request.Kind == "unix_getdents64" && value.scalar != nil && *value.scalar >= 0 && *value.scalar == int64(len(value.raw)) && len(value.raw) <= bodyLimit
	h.finishOriginalRaw(call, returnedAt, count, hash, hashState, class, eof, &request, value.cause, value.raw, rawKnown)
	return value, value.cause
}

func fstatNative(h *callHandle, operation, subject, stage string) (unix.Stat_t, error) {
	var stat unix.Stat_t
	_, err := h.nativeCall(operation, subject, stage, false, model.HostFactoryNativeCallReturn{Kind: "unix_fstat", InputDescriptorNumber: ptr(h.fd)}, func() originalNativeResult {
		err := unix.Fstat(h.fd, &stat)
		value := originalNativeResult{cause: err}
		if err == nil {
			value.stat = ptr(nativeStat(stat))
		}
		return value
	})
	return stat, err
}

func fcntlNative(h *callHandle, operation, subject, stage string, command int, argument int) (int, error) {
	value, err := h.nativeCall(operation, subject, stage, false, model.HostFactoryNativeCallReturn{Kind: operation, InputDescriptorNumber: ptr(h.fd), RequestedFcntlCommand: ptr(command), RequestedArgument: ptr(int64(argument))}, func() originalNativeResult {
		scalar, err := unix.FcntlInt(uintptr(h.fd), command, argument)
		return originalNativeResult{scalar: ptr(int64(scalar)), cause: err}
	})
	if value.scalar == nil {
		return -1, err
	}
	return int(*value.scalar), err
}

type vectorNode struct {
	sha                string
	first, last, count uint64
	state              string
}

func (l *originalLedger) vector(h *callHandle, operation, subject string) (model.HostFactoryCallVectorReference, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rows := l.calls[h.id+"\x00"+operation]
	reference := model.HostFactoryCallVectorReference{Operation: operation, OriginalHandleID: h.id, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), SubjectOwnerID: l.subjects[subject], CollectionState: "incomplete_retention"}
	if len(rows) == 0 {
		return reference, nil
	}
	reference.FirstOrdinal = *rows[0].fact.OriginalCallOrdinal
	reference.LastOrdinal = *rows[len(rows)-1].fact.OriginalCallOrdinal
	reference.OriginalCallCount = uint64(len(rows))
	// First publication of a returned prefix never republishes terminal
	// facts. A pending publication and its actual successor are singletons.
	flush := func(batch []*retainedCall) (int, error) {
		// Contiguous original facts stay whole. Choose a bounded prefix whose
		// exact BODY plus signed-purpose/envelope encoding fits BOTH caps.
		// No recorded call is dropped or split; a singleton oversize is HOLD.
		recordedAt := time.Now().UTC()
		var cause error
		for take := len(batch); take >= 1; take-- {
			facts := make([]model.HostFactoryPrimitiveIOReturn, take)
			for i, r := range batch[:take] {
				facts[i] = r.fact
			}
			chunk := model.HostFactoryCallVectorChunk{Schema: "original_host_factory_call_vector_chunk_v2", Purpose: "original_host_factory_call_vector_chunk_v2", BindingSchema: l.bindingSchema, BindingSHA256: l.bindingSHA, OwnerRole: l.ownerRole, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: l.primitiveSHA, Operation: operation, OriginalHandleID: h.id, FirstOrdinal: *facts[0].OriginalCallOrdinal, LastOrdinal: *facts[len(facts)-1].OriginalCallOrdinal, OriginalCalls: facts, RecordedAt: recordedAt}
			sha, err := l.putOriginalCollectionLocked(chunk, "")
			if err != nil {
				cause = err
				continue
			}
			for _, r := range batch[:take] {
				r.firstSHA = sha
				if r.fact.OriginalState == "called_pending" {
					r.pendingPublished = true
				} else {
					r.finalSHA = sha
				}
			}
			return take, nil
		}
		return 0, refused("storage_unknown", cause)
	}
	for i := 0; i < len(rows); {
		r := rows[i]
		if r.firstSHA != "" {
			if r.pendingPublished && r.fact.OriginalState == "returned" && r.finalSHA == "" {
				previousRaw, err := l.collection.Resolve(r.firstSHA)
				if err != nil {
					return reference, err
				}
				var previous model.HostFactoryCallVectorChunk
				if err = l.collection.decode(previousRaw, &previous); err != nil {
					return reference, refused("storage_unknown", err)
				}
				current := previous
				current.OriginalCalls = []model.HostFactoryPrimitiveIOReturn{r.fact}
				current.RecordedAt = time.Now().UTC()
				if err = l.checkOriginalPendingSuccessorLocked(previous, current); err != nil {
					return reference, refused("storage_unknown", err)
				}
				sha, err := l.putOriginalCollectionLocked(current, r.firstSHA)
				if err != nil {
					return reference, err
				}
				r.finalSHA = sha
			}
			i++
			continue
		}
		if r.fact.OriginalState == "called_pending" {
			if _, err := flush(rows[i : i+1]); err != nil {
				return reference, err
			}
			i++
			continue
		}
		end := i
		for end < len(rows) && end-i < 16 && rows[end].firstSHA == "" && rows[end].fact.OriginalState == "returned" {
			if end > i && *rows[end].fact.OriginalCallOrdinal != *rows[end-1].fact.OriginalCallOrdinal+1 {
				// Only contiguous actual ordinal runs can share a chunk. A
				// sparse operation vector uses separate original chunks and the
				// full handle inventory must account for the intervening calls.
				break
			}
			end++
		}
		if end == i {
			return reference, refused("storage_unknown", nil)
		}
		take, err := flush(rows[i:end])
		if err != nil {
			return reference, err
		}
		i += take
	}
	var nodes []vectorNode
	state := "complete_original_calls"
	for _, r := range rows {
		sha := r.finalSHA
		s := "complete_original_calls"
		if sha == "" {
			sha = r.firstSHA
			s = "same_original_call_pending"
			state = s
		}
		ordinal := *r.fact.OriginalCallOrdinal
		if len(nodes) > 0 && nodes[len(nodes)-1].sha == sha {
			nodes[len(nodes)-1].last = ordinal
			nodes[len(nodes)-1].count++
		} else {
			nodes = append(nodes, vectorNode{sha, ordinal, ordinal, 1, s})
		}
	}
	for level := uint32(0); ; level++ {
		if level > 3 {
			return reference, refused("storage_unknown", nil)
		}
		var parents []vectorNode
		for i := 0; i < len(nodes); i += 16 {
			end := i + 16
			if end > len(nodes) {
				end = len(nodes)
			}
			group := nodes[i:end]
			hashes := make([]string, len(group))
			var count uint64
			groupState := "complete_original_calls"
			for j, n := range group {
				hashes[j] = n.sha
				count += n.count
				if n.state != "complete_original_calls" {
					groupState = n.state
				}
			}
			m := model.HostFactoryCallVectorManifest{Schema: "original_host_factory_call_vector_manifest_v2", Purpose: "original_host_factory_call_vector_manifest_v2", BindingSchema: l.bindingSchema, BindingSHA256: l.bindingSHA, OwnerRole: l.ownerRole, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: l.primitiveSHA, Operation: operation, OriginalHandleID: h.id, Level: level, FirstOrdinal: group[0].first, LastOrdinal: group[len(group)-1].last, OriginalCallCount: count, ChildBodySHAs: hashes, CollectionState: groupState}
			sha, err := l.putOriginalCollectionLocked(m, "")
			if err != nil {
				return reference, err
			}
			parents = append(parents, vectorNode{sha, m.FirstOrdinal, m.LastOrdinal, count, groupState})
		}
		if len(parents) == 1 {
			reference.ManifestRootSHA256 = ptr(parents[0].sha)
			reference.CollectionState = state
			return reference, nil
		}
		nodes = parents
	}
}

type byteReturn struct {
	started, returned time.Time
	count             int64
	sha               string
	eof               bool
	err               error
}

func readOwned(h *callHandle, operation, subject, stage string, limit int64, private bool, exact int64) ([]byte, byteReturn) {
	return readOwnedStreaming(h, operation, subject, stage, limit, private, exact, nil)
}

func readOwnedStreaming(h *callHandle, operation, subject, stage string, limit int64, private bool, exact int64, onBytes func([]byte) error) ([]byte, byteReturn) {
	r := byteReturn{}
	var data []byte
	hash := sha256.New()
	buf := make([]byte, 65536)
	for {
		remaining := limit + 1 - r.count
		if exact >= 0 {
			remaining = exact - r.count
			if remaining == 0 {
				break
			}
		}
		if remaining <= 0 {
			r.err = refused("original_pipe_refused", nil)
			break
		}
		if remaining < int64(len(buf)) {
			buf = buf[:remaining]
		}
		call, err := h.begin(operation, subject, stage, false)
		if err != nil {
			r.err = err
			break
		}
		if r.started.IsZero() {
			r.started = *call.fact.OriginalCalledAt
		}
		n, callErr := h.file.Read(buf)
		returned := time.Now().UTC()
		r.returned = returned
		r.eof = callErr == io.EOF // actual return retained before admission/consumer/cap refusal
		class := "success"
		if callErr == io.EOF {
			class = "eof"
		} else if callErr != nil {
			class = "io_refused"
		} else if n == 0 {
			class = "partial"
		}
		sha := ptr(digest(buf[:n]))
		hashState := "actual_public_bytes"
		if private {
			sha = nil
			hashState = "private_withheld"
		}
		h.finishOriginal(call, returned, ptr(int64(n)), sha, hashState, class, ptr(callErr == io.EOF), nil, callErr)
		if n > 0 {
			_, _ = hash.Write(buf[:n])
			r.count += int64(n)
			if limit <= bodyLimit {
				data = append(data, buf[:n]...)
			}
		}
		if r.count > limit {
			r.err = refused("original_pipe_refused", nil)
			break
		}
		if n > 0 && onBytes != nil {
			if e := onBytes(bytes.Clone(buf[:n])); e != nil {
				r.err = e
				break
			}
		}
		if callErr != nil {
			if !r.eof {
				r.err = refused("original_pipe_refused", callErr)
			}
			break
		}
		if n == 0 {
			r.err = refused("original_pipe_refused", io.ErrNoProgress)
			break
		}
		if r.count > limit {
			r.err = refused("original_pipe_refused", nil)
			break
		}
	}
	if !private && !r.returned.IsZero() {
		r.sha = hex.EncodeToString(hash.Sum(nil))
	}
	if exact >= 0 && r.count != exact {
		r.err = refused("original_pipe_refused", io.ErrUnexpectedEOF)
	}
	if h.ledger.ctx.Err() != nil {
		r.err = refused("original_context_refused", h.ledger.ctx.Err())
	}
	return data, r
}

func writeOwned(h *callHandle, operation, subject, stage string, data []byte, private bool) (byteReturn, error) {
	r := byteReturn{}
	if !private {
		r.sha = digest(data)
	}
	remaining := data
	for len(remaining) > 0 {
		call, err := h.begin(operation, subject, stage, false)
		if err != nil {
			return r, err
		}
		if r.started.IsZero() {
			r.started = *call.fact.OriginalCalledAt
		}
		n, writeErr := h.file.Write(remaining)
		at := time.Now().UTC()
		r.returned = at
		if n < 0 || n > len(remaining) {
			h.finishOriginal(call, at, nil, nil, "unknown_original_bytes", "io_refused", nil, nil, writeErr)
			r.err = refused("original_write_refused", writeErr)
			return r, r.err
		}
		r.count += int64(n)
		class := "full_write"
		if writeErr != nil {
			class = "io_refused"
		} else if n != len(remaining) {
			class = "short_write"
		}
		sha := ptr(digest(remaining[:n]))
		state := "actual_public_bytes"
		if private {
			sha = nil
			state = "private_withheld"
		}
		h.finishOriginal(call, at, ptr(int64(n)), sha, state, class, nil, nil, writeErr)
		if writeErr != nil || n == 0 {
			r.err = refused("original_write_refused", writeErr)
			return r, r.err
		}
		remaining = remaining[n:]
	}
	if h.ledger.ctx.Err() != nil {
		r.err = refused("original_context_refused", h.ledger.ctx.Err())
		return r, r.err
	}
	return r, nil
}

func nonbyte(h *callHandle, operation, subject, stage string, cleanup bool, action func() error) (time.Time, error) {
	// Sync has an actual error-only File.Sync return, retained separately from
	// context/class admission; no zero scalar or nil error is synthesized.
	if strings.HasSuffix(operation, "_sync") {
		v, err := h.nativeCall(operation, subject, stage, cleanup, model.HostFactoryNativeCallReturn{Kind: "original_file_sync", InputDescriptorNumber: ptr(h.fd)}, func() originalNativeResult {
			return originalNativeResult{cause: action()}
		})
		return v.returnedAt, err
	}
	r, err := h.begin(operation, subject, stage, cleanup)
	if err != nil {
		return time.Time{}, err
	}
	err = action()
	at := time.Now().UTC()
	class := "success"
	if err != nil {
		class = "io_refused"
	}
	h.finishOriginal(r, at, nil, nil, "not_byte_operation", class, nil, nil, err)
	if err != nil {
		return at, refused("original_close_refused", err)
	}
	return at, nil
}
func closeOwned(h *callHandle, operation, subject, stage string) (time.Time, error) {
	if h == nil || h.file == nil {
		return time.Time{}, refused("original_close_refused", nil)
	}
	h.closeOnce.Do(func() {
		value, err := h.nativeCall(operation, subject, stage, true, model.HostFactoryNativeCallReturn{Kind: "original_file_close", InputDescriptorNumber: ptr(h.fd)}, func() originalNativeResult {
			err := h.file.Close()
			return originalNativeResult{cause: err}
		})
		h.closeAt, h.closeErr, h.closeCall = value.returnedAt, err, value.call
		if h.closeAt.IsZero() {
			// A grammar/counter refusal cannot leak an acquired original FD.
			// Keep this real unclassified return private/incomplete; it is not
			// a fabricated accepted call vector or a repaired ordinal.
			// There was no admitted reservation. This actual error-only Close
			// has no replacement CallID/ordinal/scalar, including cancellation
			// of the SAME original still-pending Read.
			calledAt := time.Now().UTC()
			actualErr := h.file.Close()
			h.closeAt = time.Now().UTC()
			h.mu.Lock()
			h.unclassified = append(h.unclassified, unclassifiedNativeReturn{operation: operation, ownerID: h.ledger.ownerID, subjectRole: subject, stage: stage, bindingSchema: h.ledger.bindingSchema, bindingSHA: h.ledger.bindingSHA, handleID: h.id, calledAt: calledAt, returnedAt: h.closeAt, deadline: h.ledger.deadline, cause: actualErr})
			h.mu.Unlock()
			h.closeErr = refused("original_close_refused", errors.Join(h.closeErr, actualErr))
		}
		h.mu.Lock()
		h.closed = true
		h.mu.Unlock()
	})
	return h.closeAt, h.closeErr
}

func acquireFile(l *originalLedger, path, subject, stage, openOperation, fstatOperation string, flags int) (*callHandle, *unix.Stat_t, error) {
	h, e := l.handle()
	if e != nil {
		return nil, nil, e
	}
	flags |= unix.O_CLOEXEC | unix.O_NONBLOCK
	value, e := h.nativeCall(openOperation, subject, stage, false, model.HostFactoryNativeCallReturn{Kind: "unix_open", RequestedFlags: ptr(uint32(flags)), RequestedMode: ptr(uint32(0))}, func() originalNativeResult {
		fd, err := unix.Open(path, flags, 0)
		v := originalNativeResult{scalar: ptr(int64(fd)), cause: err}
		if err == nil && fd >= 0 {
			h.fd, h.file = fd, os.NewFile(uintptr(fd), "original-source")
			v.descriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: h.id, OriginalDescriptorNumber: fd}}
		}
		return v
	})
	_ = value
	if e != nil {
		return h, nil, e
	}
	st, e := fstatNative(h, fstatOperation, subject, stage)
	if e != nil {
		return h, nil, e
	}
	return h, &st, nil
}

func descriptor(h *callHandle, role, primitiveSHA, subject, stage, acquisitionOperation string) (model.HostFactoryBootstrapDescriptorSource, error) {
	return descriptorFromAcquisition(h, h, role, primitiveSHA, subject, stage, acquisitionOperation)
}
func descriptorFromAcquisition(h, acquiredOn *callHandle, role, primitiveSHA, subject, stage, acquisitionOperation string) (model.HostFactoryBootstrapDescriptorSource, error) {
	return descriptorFromOriginalOwnership(h, acquiredOn, role, primitiveSHA, subject, stage, acquisitionOperation, nil)
}

// Inheritance expectations are retained before descriptor validation. Actual
// parent Pipe/ExtraFiles/Start/child-FD custody remains an independent join;
// an inherited Fstat is never relabeled as a descriptor-acquiring syscall.
func descriptorFromInherited(h *callHandle, role, primitiveSHA, subject, stage, parentID string) (model.HostFactoryBootstrapDescriptorSource, error) {
	if h == nil || uuidMust(parentID) == "" || parentID == h.id {
		return model.HostFactoryBootstrapDescriptorSource{}, refused("native_join_refused", nil)
	}
	return descriptorFromOriginalOwnership(h, nil, role, primitiveSHA, subject, stage, "", ptr(parentID))
}

func descriptorFromOriginalOwnership(h, acquiredOn *callHandle, role, primitiveSHA, subject, stage, acquisitionOperation string, inherited *string) (model.HostFactoryBootstrapDescriptorSource, error) {
	var out model.HostFactoryBootstrapDescriptorSource
	if h == nil || h.file == nil || h.ledger == nil || primitiveSHA != h.ledger.primitiveSHA || (inherited == nil && (acquiredOn == nil || acquiredOn.ledger != h.ledger)) || (inherited != nil && (acquiredOn != nil || acquisitionOperation != "")) {
		return out, refused("native_join_refused", nil)
	}
	var st unix.Stat_t
	statValue, err := h.nativeCall("descriptor_fstat", subject, stage, false, model.HostFactoryNativeCallReturn{Kind: "unix_fstat", InputDescriptorNumber: ptr(h.fd)}, func() originalNativeResult {
		e := unix.Fstat(h.fd, &st)
		v := originalNativeResult{cause: e}
		if e == nil {
			v.stat = ptr(nativeStat(st))
		}
		return v
	})
	if err != nil || statValue.call == nil {
		return out, refused("native_join_refused", err)
	}
	get := func(op string, command int) (originalNativeResult, error) {
		return h.nativeCall(op, subject, stage, false, model.HostFactoryNativeCallReturn{Kind: op, InputDescriptorNumber: ptr(h.fd), RequestedFcntlCommand: ptr(command), RequestedArgument: ptr(int64(0))}, func() originalNativeResult {
			n, e := unix.FcntlInt(uintptr(h.fd), command, 0)
			return originalNativeResult{scalar: ptr(int64(n)), cause: e}
		})
	}
	fl, e1 := get("fcntl_getfl", unix.F_GETFL)
	df, e2 := get("fcntl_getfd", unix.F_GETFD)
	if e1 != nil || e2 != nil || fl.call == nil || df.call == nil || fl.scalar == nil || df.scalar == nil {
		return out, refused("native_join_refused", errors.Join(e1, e2))
	}
	typ := ""
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		typ = "regular"
	case unix.S_IFDIR:
		typ = "directory"
	case unix.S_IFIFO:
		typ = "pipe"
	}
	if role == "basal_self_pidfd" || role == "exterior_worker_pidfd" || role == "registrar_worker_pidfd" {
		typ = "pidfd"
	}
	var acquire *model.HostFactoryCallVectorReference
	var a error
	if inherited == nil {
		v, cause := h.ledger.vector(acquiredOn, acquisitionOperation, subject)
		acquire, a = &v, cause
	}
	stat, b := h.ledger.vector(h, "descriptor_fstat", subject)
	getfl, c := h.ledger.vector(h, "fcntl_getfl", subject)
	getfd, d := h.ledger.vector(h, "fcntl_getfd", subject)
	if e := errors.Join(a, b, c, d); e != nil {
		return out, e
	}
	out = model.HostFactoryBootstrapDescriptorSource{Role: role, Device: uint64(st.Dev), Inode: st.Ino, Type: typ, Mode: st.Mode, LinkCount: uint64(st.Nlink), UID: st.Uid, GID: st.Gid, Flags: uint32(*fl.scalar), OriginalDescriptorNumber: h.fd, DescriptorFlags: uint32(*df.scalar), OriginalFstatReturnedAt: statValue.returnedAt, OwnerPrimitiveRawSHA256: primitiveSHA, OriginalHandleID: h.id, OriginalAcquisitionCallVector: acquire, OriginalInheritedFromHandleID: inherited, OriginalFstatCallVector: stat, OriginalFstatCallID: *statValue.call.fact.OriginalCallID, OriginalGetflCallVector: getfl, OriginalGetflCallID: *fl.call.fact.OriginalCallID, OriginalGetfdCallVector: getfd, OriginalGetfdCallID: *df.call.fact.OriginalCallID}
	if err = capacity.ValidateHostFactory(out); err != nil {
		return out, refused("native_join_refused", err)
	}
	return out, nil
}

func readFrame(h *callHandle, family, subject, stage string, private bool) ([]byte, error) {
	prefix, r := readOwned(h, family+"_prefix_read", subject, stage, 4, false, 4)
	if r.err != nil {
		return nil, r.err
	}
	n := binary.BigEndian.Uint32(prefix)
	if n == 0 || n > bodyLimit {
		return nil, refused("original_pipe_refused", nil)
	}
	body, r := readOwned(h, family+"_read", subject, stage, int64(n), private, int64(n))
	return body, r.err
}
func frameEOF(h *callHandle, operation, subject, stage string) error {
	_, err := frameEOFOriginal(h, operation, subject, stage)
	return err
}

func frameEOFOriginal(h *callHandle, operation, subject, stage string) (*retainedCall, error) {
	call, err := h.begin(operation, subject, stage, false)
	if err != nil {
		return nil, err
	}
	var probe [1]byte
	n, readErr := h.file.Read(probe[:])
	at := time.Now().UTC()
	class := "success"
	if readErr == io.EOF {
		class = "eof"
	} else if readErr != nil {
		class = "io_refused"
	}
	sha, hashState := ptr(digest(probe[:n])), "actual_public_bytes"
	if operation == "issuer_signing_key_eof_read" {
		sha, hashState = nil, "private_withheld"
	}
	h.finishOriginal(call, at, ptr(int64(n)), sha, hashState, class, ptr(readErr == io.EOF), nil, readErr)
	if n != 0 || readErr != io.EOF || h.ledger.ctx.Err() != nil {
		return call, refused("original_pipe_refused", readErr)
	}
	return call, nil
}
func writeFrame(h *callHandle, family, subject, stage string, body []byte, private bool) error {
	if len(body) == 0 || len(body) > bodyLimit {
		return refused("original_write_refused", nil)
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
	if _, err := writeOwned(h, family+"_prefix_write", subject, stage, prefix[:], false); err != nil {
		return err
	}
	_, err := writeOwned(h, family+"_write", subject, stage, body, private)
	return err
}

func fixedBasename(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\\\x00")
}
