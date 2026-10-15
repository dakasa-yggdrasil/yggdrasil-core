//go:build linux

package capacityhostfactory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/manifest"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"golang.org/x/sys/unix"
)

// Patch-only slice for control_linux.go. This owns physical calls, not the
// admission BODY builder, signer, native census or initial assessment.
type controlFreshRootIO struct {
	parent, create, directory, anchor, ledger *callHandle
	directorySource                           model.HostFactoryBootstrapDescriptorSource
	anchorSource                              model.HostFactoryBootstrapDescriptorSource // SAME distinct actual held anchor, never directorySource alias
	originalLedgerInput                       []byte
	originalNativeCalls                       []controlOriginalNativeCall
	ledgerWrite                               byteReturn
	ledgerSyncAt, ledgerCloseAt               time.Time
	directorySyncAt, directoryCloseAt         time.Time
	cause                                     error
}

type controlOriginalNativeCall struct {
	call  *retainedCall
	cause error // private actual method error, never public text or error hash
}

// The caller owns the actual initial admission mutex and canonical nonsecret
// ledger builder. Passing bytes here grants no admission/native authority.
// An error preserves the result and its original IO instead of retrying a root.
func controlCreateFreshRoot(ctx context.Context, r *OriginalFactoryRealm, originalLedgerInput []byte) (_ *controlFreshRootIO, runErr error) {
	out := &controlFreshRootIO{originalLedgerInput: bytes.Clone(originalLedgerInput)}
	if ctx == nil || r == nil || r.basal == nil || r.root == nil || r.preparedRootHandle == nil || ctx.Err() != nil || len(originalLedgerInput) == 0 || len(originalLedgerInput) > bodyLimit || !json.Valid(originalLedgerInput) {
		return out, refused("source_registry_refused", nil)
	}
	r.mu.Lock()
	trusted := r.trustedInstallationLocked()
	r.mu.Unlock()
	parent := r.preparedRootHandle
	out.parent = parent
	if trusted != nil || parent.file != r.root || parent.fd != r.rootFD || parent.ledger != r.basal.ledger || parent.closed || parent.pending || parent.ledger.bindingSchema != "original_host_factory_source_approval_v4" {
		return out, refused("source_registry_refused", trusted)
	}
	// The directory sync/Close endpoint and long-lived control endpoint are
	// distinct acquired owners. Neither borrows the prepared parent handle.
	defer func() {
		if out.ledger != nil && out.ledger.file != nil {
			at, e := controlCloseNative(ctx, out, out.ledger, "initial_ledger_close")
			out.ledgerCloseAt = at
			runErr = errors.Join(runErr, e)
		}
		if out.directory != nil && out.directory.file != nil {
			at, e := controlCloseNative(ctx, out, out.directory, "root_directory_close")
			out.directoryCloseAt = at
			runErr = errors.Join(runErr, e)
		}
		if runErr != nil && out.anchor != nil && out.anchor.file != nil {
			_, e := controlCloseNative(ctx, out, out.anchor, "root_directory_close")
			runErr = errors.Join(runErr, e)
		}
		out.cause = runErr
	}()
	var err error
	out.create, err = parent.ledger.handle()
	if err != nil {
		return out, err
	}
	request := model.HostFactoryNativeCallReturn{Kind: "unix_mkdirat", InputDescriptorNumber: ptr(parent.fd), ParentHandleID: ptr(parent.id), RequestedMode: ptr(uint32(0700))}
	_, err = controlRunNative(ctx, out, out.create, "root_directory_create", request, false, func() originalNativeResult {
		// A fixed component and O_EXCL ledger survive failure. EEXIST never
		// adopts, deletes or replaces an earlier original root.
		return originalNativeResult{cause: unix.Mkdirat(parent.fd, "original-control-root", 0700)}
	})
	if err != nil {
		return out, refused("original_write_refused", err)
	}
	if ctx.Err() != nil {
		return out, refused("original_context_refused", ctx.Err())
	}
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	out.directory, err = controlOpenNative(ctx, out, parent, "original-control-root", "root_directory_open", flags, 0)
	if err != nil {
		return out, err
	}
	out.directorySource, err = controlDescribeNative(ctx, out, out.directory, "gate_directory", "root_directory_open")
	if err != nil {
		return out, err
	}
	if out.directorySource.Type != "directory" || out.directorySource.Mode&07777 != 0700 || out.directorySource.UID != r.rootStat.Uid || out.directorySource.GID != r.rootStat.Gid {
		return out, refused("native_join_refused", nil)
	}
	out.anchor, err = controlOpenNative(ctx, out, parent, "original-control-root", "root_directory_open", flags, 0)
	if err != nil {
		return out, err
	}
	anchorSource, err := controlDescribeNative(ctx, out, out.anchor, "gate_directory", "root_directory_open")
	out.anchorSource = anchorSource // preserve actual returned descriptor even on refusal
	if err != nil || anchorSource.Device != out.directorySource.Device || anchorSource.Inode != out.directorySource.Inode || anchorSource.Type != "directory" || anchorSource.Mode != out.directorySource.Mode || anchorSource.UID != out.directorySource.UID || anchorSource.GID != out.directorySource.GID {
		return out, refused("native_join_refused", err)
	}
	flags = unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	out.ledger, err = controlOpenNative(ctx, out, out.directory, "initial-control-ledger.json", "initial_ledger_open_exclusive", flags, 0600)
	if err != nil {
		return out, err
	}
	ledgerSource, err := controlDescribeNative(ctx, out, out.ledger, "gate_file", "initial_ledger_open_exclusive")
	if err != nil || ledgerSource.Type != "regular" || ledgerSource.Mode&07777 != 0600 || ledgerSource.LinkCount != 1 || ledgerSource.UID != out.directorySource.UID || ledgerSource.GID != out.directorySource.GID {
		return out, refused("native_join_refused", err)
	}
	out.ledgerWrite, err = writeOwned(out.ledger, "initial_ledger_write", "host_exterior", "root_prepare", originalLedgerInput, false)
	if err != nil || out.ledgerWrite.count != int64(len(originalLedgerInput)) {
		return out, refused("original_write_refused", err)
	}
	out.ledgerSyncAt, err = controlSyncNative(ctx, out, out.ledger, "initial_ledger_sync")
	if err != nil {
		return out, err
	}
	out.ledgerCloseAt, err = controlCloseNative(ctx, out, out.ledger, "initial_ledger_close")
	if err != nil {
		return out, err
	}
	out.directorySyncAt, err = controlSyncNative(ctx, out, out.directory, "root_directory_sync")
	if err != nil {
		return out, err
	}
	out.directoryCloseAt, err = controlCloseNative(ctx, out, out.directory, "root_directory_close")
	if err != nil || ctx.Err() != nil {
		return out, refused("original_close_refused", errors.Join(err, ctx.Err()))
	}
	return out, nil
}

// Reuse the single original recorder. Its result owns the actual reserved
// call and return sample; callbacks cannot provide those identities or times.
func controlRunNative(ctx context.Context, out *controlFreshRootIO, h *callHandle, operation string, request model.HostFactoryNativeCallReturn, cleanup bool, action func() originalNativeResult) (originalNativeResult, error) {
	if ctx == nil || h == nil || h.ledger == nil || (!cleanup && ctx.Err() != nil) {
		return originalNativeResult{}, refused("original_context_refused", nil)
	}
	value, err := h.nativeCall(operation, "host_exterior", "root_prepare", cleanup, request, action)
	if value.call != nil {
		out.originalNativeCalls = append(out.originalNativeCalls, controlOriginalNativeCall{call: value.call, cause: value.cause})
	}
	return value, err
}

func controlOpenNative(ctx context.Context, out *controlFreshRootIO, parent *callHandle, name, operation string, flags int, mode uint32) (*callHandle, error) {
	h, err := parent.ledger.handle()
	if err != nil {
		return nil, err
	}
	request := model.HostFactoryNativeCallReturn{Kind: "unix_openat", InputDescriptorNumber: ptr(parent.fd), ParentHandleID: ptr(parent.id), RequestedFlags: ptr(uint32(flags)), RequestedMode: ptr(mode)}
	_, err = controlRunNative(ctx, out, h, operation, request, false, func() originalNativeResult {
		fd, actualErr := unix.Openat(parent.fd, name, flags, mode)
		value := originalNativeResult{scalar: ptr(int64(fd)), cause: actualErr}
		if actualErr == nil && fd >= 0 {
			// Register the acquired owner before validation/cancellation.
			h.fd, h.file = fd, os.NewFile(uintptr(fd), "original-control-root-owner")
			value.descriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: h.id, OriginalDescriptorNumber: fd}}
		}
		return value
	})
	if err != nil || h.file == nil || ctx.Err() != nil {
		return h, refused("native_join_refused", errors.Join(err, ctx.Err()))
	}
	return h, nil
}

func controlDescribeNative(ctx context.Context, out *controlFreshRootIO, h *callHandle, role, acquisitionOperation string) (model.HostFactoryBootstrapDescriptorSource, error) {
	request := model.HostFactoryNativeCallReturn{Kind: "unix_fstat", InputDescriptorNumber: ptr(h.fd)}
	var stat unix.Stat_t
	statValue, err := controlRunNative(ctx, out, h, "descriptor_fstat", request, false, func() originalNativeResult {
		actualErr := unix.Fstat(h.fd, &stat)
		value := originalNativeResult{cause: actualErr}
		if actualErr == nil {
			value.stat = ptr(nativeStat(stat))
		}
		return value
	})
	if err != nil || statValue.call == nil {
		return model.HostFactoryBootstrapDescriptorSource{}, refused("native_join_refused", err)
	}
	statCall, statReturnedAt := statValue.call, statValue.returnedAt
	flags, getflCall, err := controlGetFlagsNative(ctx, out, h, "fcntl_getfl", unix.F_GETFL)
	if err != nil {
		return model.HostFactoryBootstrapDescriptorSource{}, err
	}
	fdFlags, getfdCall, err := controlGetFlagsNative(ctx, out, h, "fcntl_getfd", unix.F_GETFD)
	if err != nil {
		return model.HostFactoryBootstrapDescriptorSource{}, err
	}
	if flags < 0 || fdFlags != unix.FD_CLOEXEC || flags&unix.O_NONBLOCK == 0 {
		return model.HostFactoryBootstrapDescriptorSource{}, refused("native_join_refused", nil)
	}
	typ := ""
	switch stat.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		typ = "directory"
	case unix.S_IFREG:
		typ = "regular"
	}
	acquire, e1 := h.ledger.vector(h, acquisitionOperation, "host_exterior")
	fstat, e2 := h.ledger.vector(h, "descriptor_fstat", "host_exterior")
	getfl, e3 := h.ledger.vector(h, "fcntl_getfl", "host_exterior")
	getfd, e4 := h.ledger.vector(h, "fcntl_getfd", "host_exterior")
	if err := errors.Join(e1, e2, e3, e4); err != nil {
		return model.HostFactoryBootstrapDescriptorSource{}, err
	}
	return model.HostFactoryBootstrapDescriptorSource{Role: role, Device: uint64(stat.Dev), Inode: stat.Ino, Type: typ, Mode: stat.Mode, LinkCount: uint64(stat.Nlink), UID: stat.Uid, GID: stat.Gid, Flags: uint32(flags), OriginalDescriptorNumber: h.fd, DescriptorFlags: uint32(fdFlags), OriginalFstatReturnedAt: statReturnedAt, OwnerPrimitiveRawSHA256: h.ledger.primitiveSHA, OriginalHandleID: h.id, OriginalAcquisitionCallVector: &acquire, OriginalFstatCallVector: fstat, OriginalFstatCallID: *statCall.fact.OriginalCallID, OriginalGetflCallVector: getfl, OriginalGetflCallID: *getflCall.fact.OriginalCallID, OriginalGetfdCallVector: getfd, OriginalGetfdCallID: *getfdCall.fact.OriginalCallID}, nil
}

func controlGetFlagsNative(ctx context.Context, out *controlFreshRootIO, h *callHandle, operation string, command int) (int, *retainedCall, error) {
	request := model.HostFactoryNativeCallReturn{Kind: operation, InputDescriptorNumber: ptr(h.fd), RequestedFcntlCommand: ptr(command), RequestedArgument: ptr(int64(0))}
	value, err := controlRunNative(ctx, out, h, operation, request, false, func() originalNativeResult {
		scalar, actualErr := unix.FcntlInt(uintptr(h.fd), command, 0)
		return originalNativeResult{scalar: ptr(int64(scalar)), cause: actualErr}
	})
	if err != nil || value.call == nil || value.scalar == nil || ctx.Err() != nil {
		return 0, value.call, refused("native_join_refused", errors.Join(err, ctx.Err()))
	}
	return int(*value.scalar), value.call, nil
}

func controlSyncNative(ctx context.Context, out *controlFreshRootIO, h *callHandle, operation string) (time.Time, error) {
	request := model.HostFactoryNativeCallReturn{Kind: "original_file_sync", InputDescriptorNumber: ptr(h.fd)}
	value, err := controlRunNative(ctx, out, h, operation, request, false, func() originalNativeResult {
		return originalNativeResult{cause: h.file.Sync()}
	})
	if err != nil || ctx.Err() != nil {
		return value.returnedAt, refused("original_write_refused", errors.Join(err, ctx.Err()))
	}
	return value.returnedAt, nil
}

func controlCloseNative(ctx context.Context, out *controlFreshRootIO, h *callHandle, operation string) (time.Time, error) {
	h.closeOnce.Do(func() {
		request := model.HostFactoryNativeCallReturn{Kind: "original_file_close", InputDescriptorNumber: ptr(h.fd)}
		value, err := controlRunNative(ctx, out, h, operation, request, true, func() originalNativeResult {
			return originalNativeResult{cause: h.file.Close()}
		})
		if value.call == nil {
			// Reservation failure cannot leak a real acquired FD. This close
			// remains unencoded/incomplete, without a replacement ordinal.
			calledAt := time.Now().UTC()
			actualErr := h.file.Close()
			h.closeAt = time.Now().UTC()
			h.mu.Lock()
			h.unclassified = append(h.unclassified, unclassifiedNativeReturn{operation: operation, ownerID: h.ledger.ownerID, subjectRole: "host_exterior", stage: "root_prepare", bindingSchema: h.ledger.bindingSchema, bindingSHA: h.ledger.bindingSHA, handleID: h.id, calledAt: calledAt, returnedAt: h.closeAt, deadline: h.ledger.deadline, cause: actualErr})
			h.mu.Unlock()
			h.closeErr = refused("original_close_refused", errors.Join(err, actualErr))
		} else {
			h.closeAt = value.returnedAt
			if err != nil {
				h.closeErr = refused("original_close_refused", err)
			}
		}
		h.mu.Lock()
		h.closed = true
		h.mu.Unlock()
	})
	return h.closeAt, h.closeErr
}

// Snapshot the actual complete per-handle union at this original boundary.
// A held anchor is explicitly held, not declared closed or safe to create.
// This is retention only; native/source authentication remains the caller's
// separately owned original producer/consumer obligation.
func controlRootHandleInventories(out *controlFreshRootIO) ([]string, error) {
	if out == nil {
		return nil, refused("storage_unknown", nil)
	}
	var hashes []string
	for _, h := range []*callHandle{out.parent, out.create, out.directory, out.anchor, out.ledger} {
		if h == nil {
			return hashes, refused("storage_unknown", nil)
		}
		h.mu.Lock()
		boundary, pending, closed := h.next, h.pending, h.closed
		if boundary == 0 || boundary > callLimit || len(h.unclassified) != 0 {
			h.mu.Unlock()
			return hashes, refused("storage_unknown", nil)
		}
		l := h.ledger
		l.mu.Lock()
		var operations []string
		ordinals := make(map[uint64]string)
		firstByOperation := make(map[string]uint64)
		for key, rows := range l.calls {
			if !strings.HasPrefix(key, h.id+"\x00") {
				continue
			}
			operation := strings.TrimPrefix(key, h.id+"\x00")
			for _, row := range rows {
				fact := row.fact
				if fact.OriginalCallOrdinal == nil || fact.OriginalCallID == nil || *fact.OriginalCallOrdinal > boundary || *fact.OriginalCallOrdinal == 0 || fact.OriginalHandleID != h.id || fact.Operation != operation {
					l.mu.Unlock()
					h.mu.Unlock()
					return hashes, refused("storage_unknown", nil)
				}
				ordinal := *fact.OriginalCallOrdinal
				if _, duplicate := ordinals[ordinal]; duplicate || *fact.OriginalCallID != h.id+":"+strconv.FormatUint(ordinal, 10) {
					l.mu.Unlock()
					h.mu.Unlock()
					return hashes, refused("storage_unknown", nil)
				}
				ordinals[ordinal] = *fact.OriginalCallID
				if first, ok := firstByOperation[operation]; !ok || ordinal < first {
					firstByOperation[operation] = ordinal
				}
			}
			operations = append(operations, operation)
		}
		l.mu.Unlock()
		// Keep the same handle reservation lock through graph publication.
		// No later call may enter the captured boundary between vectors and
		// the inventory's actual RecordedAt sample.
		if uint64(len(ordinals)) != boundary || len(operations) == 0 || len(operations) > 32 {
			h.mu.Unlock()
			return hashes, refused("storage_unknown", nil)
		}
		sort.Slice(operations, func(i, j int) bool { return firstByOperation[operations[i]] < firstByOperation[operations[j]] })
		vectors := make([]model.HostFactoryCallVectorReference, 0, len(operations))
		state := "complete_original_calls"
		for _, operation := range operations {
			vector, err := l.vector(h, operation, "host_exterior")
			if err != nil {
				h.mu.Unlock()
				return hashes, err
			}
			if vector.CollectionState != "complete_original_calls" {
				state = vector.CollectionState
			}
			vectors = append(vectors, vector)
		}
		if h.next != boundary || h.pending != pending || h.closed != closed || len(h.unclassified) != 0 {
			h.mu.Unlock()
			return hashes, refused("storage_unknown", nil)
		}
		acquisition := "not_acquired"
		if h.file != nil {
			acquisition = "acquired_held"
			if closed {
				acquisition = "original_close_returned"
			}
		}
		inventory := model.HostFactoryHandleCallInventory{Schema: "original_host_factory_handle_call_inventory_v1", Purpose: "original_host_factory_handle_call_inventory_v1", BindingSchema: l.bindingSchema, BindingSHA256: l.bindingSHA, OwnerRole: l.ownerRole, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), OriginalHandleID: h.id, OriginalAcquisitionState: acquisition, FirstOrdinal: 1, LastOrdinal: boundary, OriginalCallCount: boundary, OperationVectors: vectors, CollectionState: state, OriginalOperationDeadline: l.deadline, RecordedAt: time.Now().UTC()}
		if err := checkOriginalSourceHandleInventory(inventory, l.collection); err != nil {
			h.mu.Unlock()
			return hashes, refused("storage_unknown", err)
		}
		sha, err := l.collection.put(inventory, "")
		h.mu.Unlock()
		if err != nil {
			return hashes, err
		}
		hashes = append(hashes, sha)
	}
	return hashes, nil
}

// Patch-only retention helper for control_linux.go. Successful graph checks
// prove byte/ordinal consistency at each captured boundary. The caller still
// owns the real quiescence gate, native acquisition/lifetime authentication,
// actual Source approval and all required original-return phase joins.
type originalLedgerInventorySnapshot struct {
	handles         []originalHandleInventorySnapshot
	graphConsistent bool
}

type originalHandleInventorySnapshot struct {
	handleID        string
	lastOrdinal     uint64
	pending         bool
	closed          bool
	unclassified    int
	vectors         []model.HostFactoryCallVectorReference
	inventorySHA256 string
	cause           error // retention error; never presented as an OS-call error
}

// No effect or signer is invoked here. Partial original chunks already stored
// by vector remain available on failure. An incomplete handle has no success
// inventory hash; it cannot be silently dropped from the observed handle set.
func publishOriginalLedgerInventories(ctx context.Context, l *originalLedger) (*originalLedgerInventorySnapshot, error) {
	out := &originalLedgerInventorySnapshot{}
	if ctx == nil || l == nil || l.collection == nil || ctx.Err() != nil {
		return out, refused("original_context_refused", nil)
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return out, refused("original_context_refused", nil)
	}
	// Index once, rather than walking every operation key for every handle.
	// Do not take a handle lock under this ledger lock.
	l.mu.Lock()
	handles := make(map[string]*callHandle, len(l.handles))
	operations := make(map[string][]string, len(l.handles))
	subjects := make(map[string]string, len(l.subjects))
	valid := len(l.handles) <= callLimit
	for id, h := range l.handles {
		if h == nil || h.id != id || h.ledger != l {
			valid = false
		}
		handles[id] = h
	}
	for role, id := range l.subjects {
		subjects[role] = id
	}
	for key, rows := range l.calls {
		id, operation, ok := strings.Cut(key, "\x00")
		if !ok || operation == "" || strings.Contains(operation, "\x00") || handles[id] == nil || len(rows) == 0 {
			valid = false
			continue
		}
		operations[id] = append(operations[id], operation)
	}
	l.mu.Unlock()
	if !valid {
		return out, refused("storage_unknown", nil)
	}
	ids := make([]string, 0, len(handles))
	for id := range handles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var firstError error
	for _, id := range ids {
		if ctx.Err() != nil {
			return out, refused("original_context_refused", ctx.Err())
		}
		captured := publishOriginalHandleInventory(ctx, handles[id], operations[id], subjects)
		out.handles = append(out.handles, captured)
		if captured.cause != nil && firstError == nil {
			firstError = captured.cause
		}
	}
	// Detect observed growth or rebinding. This check is not a global lifetime
	// seal: the Source-owned caller must have joined/stopped the actual owners
	// and keep its original publication gate closed against later work.
	l.mu.Lock()
	unchanged := len(l.handles) == len(handles) && len(l.subjects) == len(subjects)
	for id, h := range handles {
		unchanged = unchanged && l.handles[id] == h
	}
	for role, id := range subjects {
		unchanged = unchanged && l.subjects[role] == id
	}
	l.mu.Unlock()
	for _, captured := range out.handles {
		h := handles[captured.handleID]
		h.mu.Lock()
		unchanged = unchanged && h.next == captured.lastOrdinal && h.pending == captured.pending && h.closed == captured.closed && len(h.unclassified) == captured.unclassified
		h.mu.Unlock()
	}
	if ctx.Err() != nil {
		return out, refused("original_context_refused", ctx.Err())
	}
	if !unchanged || firstError != nil {
		return out, refused("storage_unknown", firstError)
	}
	out.graphConsistent = true
	return out, nil
}

func publishOriginalHandleInventory(ctx context.Context, h *callHandle, operations []string, subjects map[string]string) (out originalHandleInventorySnapshot) {
	out.handleID = h.id
	h.mu.Lock()
	defer h.mu.Unlock()
	out.lastOrdinal, out.pending, out.closed, out.unclassified = h.next, h.pending, h.closed, len(h.unclassified)
	if h.next > callLimit || len(operations) > 32 {
		out.cause = refused("storage_unknown", nil)
		return out
	}
	l := h.ledger
	ordinals := make(map[uint64]string)
	firstByOperation := make(map[string]uint64)
	roleByOperation := make(map[string]string)
	ownerByOperation := make(map[string]string)
	validatedTuples := make(map[string]bool)
	envelope := "HostFactoryRootSignedEnvelope"
	if l.bindingSchema == "original_host_factory_pre_authority_scope_v4" {
		envelope = "HostFactorySignedEnvelope"
	}
	invalid := false
	l.mu.Lock()
	for _, operation := range operations {
		rows := l.calls[h.id+"\x00"+operation]
		if len(rows) == 0 {
			invalid = true
			continue
		}
		for _, row := range rows {
			if ctx.Err() != nil {
				l.mu.Unlock()
				out.cause = refused("original_context_refused", ctx.Err())
				return out
			}
			if row == nil {
				invalid = true
				continue
			}
			fact := row.fact
			if fact.OriginalCallOrdinal == nil || fact.OriginalCallID == nil || *fact.OriginalCallOrdinal == 0 || *fact.OriginalCallOrdinal > h.next || fact.OriginalHandleID != h.id || fact.Operation != operation {
				invalid = true
				continue
			}
			ordinal := *fact.OriginalCallOrdinal
			if _, duplicate := ordinals[ordinal]; duplicate || *fact.OriginalCallID != h.id+":"+strconv.FormatUint(ordinal, 10) {
				invalid = true
			}
			ordinals[ordinal] = *fact.OriginalCallID
			if first, ok := firstByOperation[operation]; !ok || ordinal < first {
				firstByOperation[operation] = ordinal
			}
			if prior, ok := ownerByOperation[operation]; ok && prior != fact.SubjectOwnerID {
				invalid = true
			}
			ownerByOperation[operation] = fact.SubjectOwnerID
			// The same actual process may own distinct source purposes. Its
			// UUID does not choose a role: retain the lexical role and stage
			// originally passed by the native owner at reservation time.
			if row.subjectRole == "" || row.stage == "" || subjects[row.subjectRole] != fact.SubjectOwnerID || l.subjects[row.subjectRole] != fact.SubjectOwnerID {
				invalid = true
				continue
			}
			tuple := operation + "\x00" + row.subjectRole + "\x00" + row.stage
			if !validatedTuples[tuple] {
				if capacity.ValidateHostFactoryOperation(operation, l.ownerRole, row.subjectRole, row.stage, l.bindingSchema, envelope) != nil {
					invalid = true
					continue
				}
				validatedTuples[tuple] = true
			}
			if roleByOperation[operation] == "" {
				// vector encodes the actual SubjectOwnerID, not a new role.
				// Every row above independently retains its admitted tuple.
				roleByOperation[operation] = row.subjectRole
			}
		}
		if roleByOperation[operation] == "" {
			invalid = true
		}
	}
	l.mu.Unlock()
	if invalid {
		out.cause = refused("storage_unknown", nil)
		return out
	}
	sort.Slice(operations, func(i, j int) bool { return firstByOperation[operations[i]] < firstByOperation[operations[j]] })
	out.vectors = make([]model.HostFactoryCallVectorReference, 0, len(operations))
	terminal := !h.pending && len(h.unclassified) == 0 && uint64(len(ordinals)) == h.next
	for _, operation := range operations {
		if ctx.Err() != nil {
			out.cause = refused("original_context_refused", ctx.Err())
			return out
		}
		vector, err := l.vector(h, operation, roleByOperation[operation])
		if err != nil || vector.SubjectOwnerID != ownerByOperation[operation] {
			out.cause = refused("storage_unknown", err)
			return out
		}
		out.vectors = append(out.vectors, vector)
		terminal = terminal && vector.CollectionState == "complete_original_calls"
	}
	// Pending/unclassified acquisition cannot be replaced with an invented
	// descriptor state. Keep its original vector/private diagnostics instead.
	if !terminal {
		out.cause = refused("storage_unknown", nil)
		return out
	}
	acquisition := "not_acquired"
	if h.file != nil {
		acquisition = "acquired_held"
		if h.closed {
			acquisition = "original_close_returned"
		}
	}
	first := uint64(0)
	if h.next != 0 {
		first = 1
	}
	inventory := model.HostFactoryHandleCallInventory{Schema: "original_host_factory_handle_call_inventory_v1", Purpose: "original_host_factory_handle_call_inventory_v1", BindingSchema: l.bindingSchema, BindingSHA256: l.bindingSHA, OwnerRole: l.ownerRole, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), OriginalHandleID: h.id, OriginalAcquisitionState: acquisition, FirstOrdinal: first, LastOrdinal: h.next, OriginalCallCount: h.next, OperationVectors: out.vectors, CollectionState: "complete_original_calls", OriginalOperationDeadline: l.deadline, RecordedAt: time.Now().UTC()}
	if err := checkOriginalSourceHandleInventory(inventory, l.collection); err != nil {
		out.cause = refused("storage_unknown", err)
		return out
	}
	sha, err := l.collection.put(inventory, "")
	if err != nil {
		out.cause = err
		return out
	}
	out.inventorySHA256 = sha
	return out
}

// PATCH_ONLY, intended to be composed into control_linux.go by its sole Source
// integrator. Logical Source metadata and private admission state supply no
// native absence, Units, VM tuple, billing, grant or future-Start proof.
type originalControl struct {
	workerControlWriter     *callHandle // actual FD4 opposite writer, owned through late-frame EOF
	sealAttempted           bool
	sealCause               error
	sourceAuditOwnerLedgers []*originalLedger // Source-owned actual registration order, before first effect

	workerIOCache                 *originalWorkerIOTransferCache
	workerIOOwners                map[string]*originalWorkerIOTransferOwner
	workerIOTransfers             map[string]*originalWorkerIOTransfer
	workerIOReadAttempts          map[string]bool
	workerBootstrapReady          chan struct{}
	workerBootstrapAttempted      bool
	workerBootstrapRelease        sync.Once
	workerBootstrapReturn         controlCurrentSourceReturn
	workerBootstrapCause          error
	scopePreparationAttempted     bool // Source-only once BEFORE actual Scope/preparation effects
	parentChoiceReady             chan struct{}
	parentChoiceRelease           sync.Once
	parentChoicePhase             *originalNativePhaseReservation
	parentChoiceWriteReturn       controlCurrentSourceReturn
	parentChoiceCause             error
	parentHeldRootAnchor          *originalCurrentNativeRootAnchor
	parentHeldRootAnchorRaw       []byte
	parentHeldRootAnchorAttempted bool
	currentAdmission              *controlCurrentAdmission // SAME admission mutex owns real post-start history
	nativePublisher               *originalNativePublisher
	nativePublishers              []*originalNativePublisher          // every original independent ledger/pin owner through cleanup
	phasePublishers               map[string]*originalNativePublisher // Source creates once before phase IO; getter never constructs
	parentInputExports            map[string]*originalNativeParentInputExport
	registrarRPC                  *controlRegistrarRPC
	admissionMu                   sync.Mutex
	admission                     controlAdmissionState
	exteriorKey                   ed25519.PrivateKey // actual approved-role bootstrap copy; cleared by finalizer
	bootstrapChallenge            []byte             // actual original challenge32 Read, retained privately before registrar Start
	registrarStartOnce            sync.Once
	registrarStartErr             error
	registrarExpectedOwnerID      string             // Source-reserved logical identity BEFORE actual registrar Cmd.Start
	registrarKey                  ed25519.PrivateKey // actual approved-role private Read; never artifact/debug output
	registrarLedger               *originalLedger
	policyInputs                  *controlPolicyInputs
	fresh                         *controlFreshRootIO
	sourceApprovalEnvelope        []byte
	originalInitialLedger         []byte
	originalInitialAdmission      []byte
	bootstrapHandle, issuerHandle *callHandle
	bootstrapSource, issuerSource model.HostFactoryBootstrapDescriptorSource
	sourceApprovalHandle          *callHandle
	sourceApprovalRead            byteReturn
	bootstrapSegments             [3]byteReturn
	registrarReturnsRaw           []byte
	registrarReturnsSHA           string
	basalCloseReturns             []model.HostFactoryDiagnosticIOFact
	handleInventories             []string
	ownerReturns                  []realmOwnerReturn
	closureCause                  error
	closureMu                     sync.Mutex
	closureOnce                   sync.Once
	closureReturned               bool
	publicationMu                 sync.Mutex
	publicationSealed             bool
	observationOwners             []*controlObservationOwner
	ledgerSnapshots               []*originalLedgerInventorySnapshot
	closingIO                     map[string][]byte
	policyAuditLedger             *originalLedger
	policyAuditHandles            []*callHandle
	policyAuditFacts              []model.HostFactorySourceAuditReturn
	policyAuditUnencoded          []unclassifiedNativeReturn
}

type controlAdmissionState struct {
	state                        string
	rootID, attemptID, creatorID string
	// All reservations enter through the SAME source-owned admission lock BEFORE
	// Prepare/Start. Unknown or missing owner state cannot be read as empty.
	reservations         map[string]controlOwnerReservation
	sourceFactoryEntries []string
}

type controlOwnerReservation struct {
	FactoryAttemptID string `json:"factory_attempt_id"`
	CreatorOwnerID   string `json:"creator_owner_id"`
	State            string `json:"state"`
}

type controlInitialAdmissionBody struct {
	Schema                     string                    `json:"schema"`
	FactoryRootID              string                    `json:"factory_root_id"`
	SourceApprovalSHA256       string                    `json:"source_approval_sha256"`
	CoreBasalOwnerRawSHA256    string                    `json:"core_basal_owner_raw_sha256"`
	FactoryRegistrySHA256      string                    `json:"factory_registry_sha256"`
	FactorySourceClosureSHA256 string                    `json:"factory_source_closure_sha256"`
	OriginalContextStartedAt   time.Time                 `json:"original_context_started_at"`
	OriginalContextDeadline    time.Time                 `json:"original_context_deadline"`
	FactoryAttemptID           string                    `json:"factory_attempt_id"`
	CreatorOwnerID             string                    `json:"creator_owner_id"`
	FactoryEntryClasses        []string                  `json:"factory_entry_classes"`
	FactoryOwnerReservations   []controlOwnerReservation `json:"factory_owner_reservations"`
}

type controlInitialLedgerBody struct {
	Schema                          string                    `json:"schema"`
	FactoryRootID                   string                    `json:"factory_root_id"`
	SourceApprovalSHA256            string                    `json:"source_approval_sha256"`
	CoreBasalOwnerRawSHA256         string                    `json:"core_basal_owner_raw_sha256"`
	FactoryRegistrySHA256           string                    `json:"factory_registry_sha256"`
	FactorySourceClosureSHA256      string                    `json:"factory_source_closure_sha256"`
	OriginalContextStartedAt        time.Time                 `json:"original_context_started_at"`
	OriginalContextDeadline         time.Time                 `json:"original_context_deadline"`
	FactoryAttemptID                string                    `json:"factory_attempt_id"`
	CreatorOwnerID                  string                    `json:"creator_owner_id"`
	InitialProtectedAdmissionSHA256 string                    `json:"initial_protected_admission_sha256"`
	FactoryOwnerReservations        []controlOwnerReservation `json:"factory_owner_reservations"`
}

// This factory list must come from the complete SOURCE-owned compiled entry
// inventory, not SourceApprovalJSON, caller flags or an initialized empty map.
// The current compiled inventory remains EMPTY, so no constructor IO is enabled.
func controlInitializeAdmission(r *OriginalFactoryRealm) error {
	if r == nil || r.control == nil || r.basal == nil {
		return capacity.ErrHostFactorySourceUnavailable
	}
	r.mu.Lock()
	trusted := r.trustedInstallationLocked()
	r.mu.Unlock()
	if trusted != nil {
		return trusted
	}
	entries := r.installation.controlFactoryEntries
	if len(entries) != 3 || entries[0] != "sealed_a0" || entries[1] != "sealed_a1" || entries[2] != "ordinary_original_create" {
		return capacity.ErrHostFactorySourceUnavailable
	}
	c := r.control
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	if c.admission.state != "" || c.admission.reservations != nil || r.worker != nil || r.registrar != nil || r.factoryAttemptID == "" || r.creatorOwnerID == "" {
		return refused("owner_registration_refused", nil)
	}
	c.admission = controlAdmissionState{state: "initial_admission_closed_before_any_factory_owner", rootID: r.rootID, attemptID: r.factoryAttemptID, creatorID: r.creatorOwnerID, reservations: make(map[string]controlOwnerReservation), sourceFactoryEntries: append([]string(nil), entries...)}
	return nil
}

func controlCacheOriginalBootstrapReturn(r *OriginalFactoryRealm, h *callHandle, source model.HostFactoryBootstrapDescriptorSource, segments [3]byteReturn, eofCall, closeCall *retainedCall, key ed25519.PrivateKey) error {
	if r == nil || r.control == nil || r.basal == nil || h == nil || h.ledger != r.basal.ledger || h != r.control.bootstrapHandle || h.closeCall != closeCall || eofCall == nil || closeCall == nil || eofCall.fact.OriginalHandleID != h.id || closeCall.fact.OriginalHandleID != h.id || len(key) != ed25519.PrivateKeySize {
		return refused("storage_unknown", nil)
	}
	l := h.ledger
	body := model.HostFactoryBootstrapReturn{Schema: "original_host_factory_bootstrap_return_v4", Purpose: "original_host_factory_bootstrap_return_v4", BootstrapBindingSchema: l.bindingSchema, BootstrapBindingSHA256: l.bindingSHA, Role: l.ownerRole, OwnerPrimitiveRawSHA256: l.primitiveSHA, OriginalBootstrapSource: source, ProcessNonceSHA256: digest(r.control.bootstrapChallenge), DerivedApprovedPublicKeySHA256: digest(key.Public().(ed25519.PublicKey)), OriginalPrivateConsumerReturnedAt: time.Now().UTC()}
	operations := [3]string{"bootstrap_challenge32_read", "bootstrap_key64_read", "bootstrap_binding_digest32_read"}
	sizes := [3]int{32, 64, 32}
	for n, original := range segments {
		vector, err := l.vector(h, operations[n], l.ownerRole)
		if err != nil || original.err != nil || original.count != int64(sizes[n]) || vector.CollectionState != "complete_original_calls" {
			return refused("storage_unknown", err)
		}
		hashState, sha := "actual_public_bytes", ptr(original.sha)
		if n == 1 {
			hashState, sha = "private_withheld", nil
		}
		body.SegmentReturns[n] = model.HostFactoryBootstrapSegmentReturn{Operation: operations[n], OwnerPrimitiveRawSHA256: l.primitiveSHA, OriginalHandleID: h.id, ExpectedBytes: sizes[n], OriginalCallVector: vector, OriginalTotalBytes: sizes[n], OriginalSegmentHashState: hashState, OriginalSegmentSHA256: sha, OriginalReturnedAt: original.returned}
	}
	var err error
	body.OriginalEOFReturn, err = controlDiagnosticFromOriginal(l, eofCall)
	if err != nil {
		return err
	}
	body.OriginalBootstrapCloseReturn, err = controlDiagnosticFromOriginal(l, closeCall)
	if err != nil {
		return err
	}
	raw, err := capacity.CanonicalHostFactory(body)
	if err != nil {
		return err
	}
	envelope, err := capacity.SignHostFactoryEnvelope(body, l.ownerRole, keyIDFor(r.installation, l.ownerRole), l.bindingSchema, l.bindingSHA, key)
	if err != nil || len(raw) > bodyLimit || len(envelope) > bodyLimit {
		return refused("storage_unknown", err)
	}
	basalEnvelope, err := capacity.SignHostFactoryEnvelope(r.basal.body, l.ownerRole, keyIDFor(r.installation, l.ownerRole), l.bindingSchema, l.bindingSHA, key)
	if err != nil || len(basalEnvelope) > bodyLimit {
		return refused("storage_unknown", err)
	}
	if len(r.records["basal-owner-core"]) != 0 || len(r.records["bootstrap-return-core"]) != 0 {
		return refused("storage_unknown", nil)
	}
	r.originalBodies["basal-owner-core"], r.records["basal-owner-core"] = bytes.Clone(r.basal.raw), bytes.Clone(basalEnvelope)
	r.originalBodies["bootstrap-return-core"], r.records["bootstrap-return-core"] = bytes.Clone(raw), bytes.Clone(envelope)
	return nil
}

// This returns Source-retained originals for ONE known operation. It never
// chooses a latest row or treats a syscall that did not return as completed.
func controlOriginalOperationDiagnostic(l *originalLedger, h *callHandle, operation, subject string) (model.HostFactoryDiagnosticIOFact, error) {
	var empty model.HostFactoryDiagnosticIOFact
	if l == nil || h == nil || h.ledger != l {
		return empty, refused("storage_unknown", nil)
	}
	vector, err := l.vector(h, operation, subject)
	if err != nil {
		return empty, err
	}
	rows, err := checkOriginalSourceCallVector(vector, l.collection)
	if err != nil || len(rows) == 0 {
		return empty, refused("storage_unknown", err)
	}
	first, last := rows[0], rows[len(rows)-1]
	if first.OriginalCalledAt == nil || last.OriginalReturnedAt == nil {
		return empty, refused("storage_unknown", nil)
	}
	count := int64(0)
	byteOperation := first.OriginalCount != nil
	for _, row := range rows {
		if row.OriginalState != "returned" || row.OriginalReturnClass == "io_refused" || row.OriginalCount != nil != byteOperation {
			return empty, refused("storage_unknown", nil)
		}
		if byteOperation {
			count += *row.OriginalCount
		}
	}
	fact := model.HostFactoryDiagnosticIOFact{Operation: operation, OriginalHandleID: h.id, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), OriginalState: "returned", OriginalCalledAt: first.OriginalCalledAt, OriginalReturnedAt: last.OriginalReturnedAt, OriginalReturnClass: last.OriginalReturnClass, OriginalCloseState: "not_called", OriginalCloseClass: "unavailable", SubjectOwnerID: first.SubjectOwnerID, OriginalOperationDeadline: first.OriginalOperationDeadline, OriginalHashState: first.OriginalHashState, OriginalEOF: last.OriginalEOF, OriginalCallVector: vector, OriginalCloseCallVector: model.HostFactoryCallVectorReference{Operation: operation, OriginalHandleID: h.id, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), SubjectOwnerID: first.SubjectOwnerID, CollectionState: "complete_original_calls"}}
	if byteOperation {
		fact.OriginalCount = ptr(count)
		// Issuer material remains withheld. This helper does not re-read bytes
		// or concatenate primitive hashes into a manufactured raw digest.
		if first.OriginalHashState != "private_withheld" {
			return empty, refused("storage_unknown", nil)
		}
	}
	if capacity.ValidateHostFactory(fact) != nil {
		return empty, refused("storage_unknown", nil)
	}
	return fact, nil
}

func controlPrepareOriginalRoot(ctx context.Context, r *OriginalFactoryRealm) error {
	if r == nil || ctx == nil || ctx != r.ctx || r.control == nil || r.control.issuerHandle == nil || r.control.issuerHandle.closeCall == nil || ctx.Err() != nil {
		return capacity.ErrHostFactorySourceUnavailable
	}
	if err := controlInitializeAdmission(r); err != nil {
		return err
	}
	ledger, admission, err := controlBuildInitialLedger(r)
	if err != nil {
		return err
	}
	r.control.fresh, err = controlCreateFreshRoot(ctx, r, ledger)
	if err != nil {
		return err
	}
	if _, err = controlReadApprovedPolicyInputs(ctx, r); err != nil {
		return err
	}
	l := r.basal.ledger
	ops := []model.HostFactoryDiagnosticIOFact{}
	for _, returned := range r.control.fresh.originalNativeCalls {
		if returned.call == nil || returned.cause != nil {
			return refused("storage_unknown", returned.cause)
		}
		fact, err := controlDiagnosticFromOriginal(l, returned.call)
		if err != nil {
			return err
		}
		ops = append(ops, fact)
	}
	write := r.control.fresh.ledgerWrite
	writeVector, err := l.vector(r.control.fresh.ledger, "initial_ledger_write", "host_exterior")
	if err != nil || write.err != nil || write.count != int64(len(ledger)) {
		return refused("storage_unknown", err)
	}
	ops = append(ops, model.HostFactoryDiagnosticIOFact{Operation: "initial_ledger_write", OriginalHandleID: r.control.fresh.ledger.id, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), OriginalState: "returned", OriginalCalledAt: ptr(write.started), OriginalReturnedAt: ptr(write.returned), OriginalCount: ptr(write.count), OriginalSHA256: ptr(write.sha), OriginalReturnClass: "full_write", OriginalCloseState: "not_called", OriginalCloseClass: "unavailable", SubjectOwnerID: l.ownerID, OriginalOperationDeadline: l.deadline, OriginalHashState: "actual_public_bytes", OriginalCallVector: writeVector, OriginalCloseCallVector: model.HostFactoryCallVectorReference{Operation: "initial_ledger_close", OriginalHandleID: r.control.fresh.ledger.id, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), SubjectOwnerID: l.ownerID, CollectionState: "complete_original_calls"}})
	issuerReturns := [3]model.HostFactoryDiagnosticIOFact{}
	for n, operation := range [3]string{"issuer_signing_key64_read", "issuer_signing_key_eof_read", "issuer_signing_key_close"} {
		issuerReturns[n], err = controlOriginalOperationDiagnostic(l, r.control.issuerHandle, operation, "host_core_issuer")
		if err != nil {
			return err
		}
	}
	inventories, err := controlRootHandleInventories(r.control.fresh)
	if err != nil {
		return err
	}
	approval, err := capacity.CanonicalHostFactory(r.installation.approval)
	if err != nil {
		return err
	}
	body := model.HostFactoryRootPreparation{Schema: "original_host_factory_root_preparation_v4", Purpose: "original_host_factory_root_preparation_v4", FactoryRootID: r.rootID, SourceApprovalSHA256: digest(approval), CoreBasalOwnerRawSHA256: r.basal.sha, FactoryRegistrySHA256: r.installation.approval.FactoryRegistrySHA256, FactorySourceClosureSHA256: r.installation.approval.FactorySourceClosureSHA256, RootDirectorySource: r.control.fresh.directorySource, InitialControlLedgerSHA256: digest(ledger), InitialControlLedgerBytes: len(ledger), OriginalRootOperations: ops, OriginalContextStartedAt: r.started.UTC(), OriginalContextDeadline: r.deadline.UTC(), FactoryEntryClass: r.installation.entry, InitialProtectedAdmissionSHA256: digest(admission), OriginalIssuerSigningKeySource: r.control.issuerSource, OriginalIssuerSigningKeyReadReturns: issuerReturns, IssuerApprovedPublicKeySHA256: digest(r.issuerKey.Public().(ed25519.PublicKey)), OriginalHandleInventorySHAs: inventories}
	raw, err := capacity.CanonicalHostFactory(body)
	if err != nil {
		return err
	}
	envelope, err := capacity.SignHostFactoryEnvelope(body, "host_exterior", keyIDFor(r.installation, "host_exterior"), r.installation.approval.Schema, digest(approval), r.control.exteriorKey)
	if err != nil || len(raw) > bodyLimit || len(envelope) > bodyLimit || ctx.Err() != nil {
		return refused("storage_unknown", err)
	}
	r.rootPreparation, r.rootPreparationRaw = body, bytes.Clone(raw)
	r.originalBodies["root-preparation"], r.records["root-preparation"] = bytes.Clone(raw), bytes.Clone(envelope)
	return nil
}

// Build BOTH source-private nonsecret originals under the admission lock. No
// filesystem/process IO is performed while holding it. This is an exclusion
// state within this source factory only; native all-thread/registry/ledger
// observations remain mandatory before an InitialEMPTY or capacity projection.
func controlBuildInitialLedger(r *OriginalFactoryRealm) ([]byte, []byte, error) {
	if r == nil || r.control == nil || r.basal == nil || r.ctx == nil || r.ctx.Err() != nil {
		return nil, nil, refused("original_context_refused", nil)
	}
	c := r.control
	c.admissionMu.Lock()
	defer c.admissionMu.Unlock()
	a := c.admission
	if a.state != "initial_admission_closed_before_any_factory_owner" || a.rootID != r.rootID || a.attemptID != r.factoryAttemptID || a.creatorID != r.creatorOwnerID || a.reservations == nil || len(a.reservations) != 0 || len(a.sourceFactoryEntries) != 3 || r.worker != nil {
		return nil, nil, refused("owner_registration_refused", nil)
	}
	approval, err := capacity.CanonicalHostFactory(r.installation.approval)
	if err != nil {
		return nil, nil, err
	}
	admission := controlInitialAdmissionBody{Schema: "original_host_factory_initial_admission_body_v1", FactoryRootID: r.rootID, SourceApprovalSHA256: digest(approval), CoreBasalOwnerRawSHA256: r.basal.sha, FactoryRegistrySHA256: r.installation.approval.FactoryRegistrySHA256, FactorySourceClosureSHA256: r.installation.approval.FactorySourceClosureSHA256, OriginalContextStartedAt: r.started.UTC(), OriginalContextDeadline: r.deadline.UTC(), FactoryAttemptID: a.attemptID, CreatorOwnerID: a.creatorID, FactoryEntryClasses: append([]string(nil), a.sourceFactoryEntries...), FactoryOwnerReservations: []controlOwnerReservation{}}
	admissionRaw, err := json.Marshal(admission)
	if err != nil || len(admissionRaw) == 0 || len(admissionRaw) > bodyLimit {
		return nil, nil, refused("storage_unknown", err)
	}
	ledger := controlInitialLedgerBody{Schema: "original_host_factory_initial_control_ledger_v1", FactoryRootID: r.rootID, SourceApprovalSHA256: admission.SourceApprovalSHA256, CoreBasalOwnerRawSHA256: r.basal.sha, FactoryRegistrySHA256: admission.FactoryRegistrySHA256, FactorySourceClosureSHA256: admission.FactorySourceClosureSHA256, OriginalContextStartedAt: admission.OriginalContextStartedAt, OriginalContextDeadline: admission.OriginalContextDeadline, FactoryAttemptID: a.attemptID, CreatorOwnerID: a.creatorID, InitialProtectedAdmissionSHA256: digest(admissionRaw), FactoryOwnerReservations: []controlOwnerReservation{}}
	raw, err := json.Marshal(ledger)
	if err != nil || len(raw) == 0 || len(raw) > bodyLimit {
		return nil, nil, refused("storage_unknown", err)
	}
	if len(c.originalInitialLedger) != 0 || len(c.originalInitialAdmission) != 0 {
		return nil, nil, refused("choice_conflict", nil)
	}
	c.originalInitialLedger, c.originalInitialAdmission = bytes.Clone(raw), bytes.Clone(admissionRaw)
	return bytes.Clone(raw), bytes.Clone(admissionRaw), nil
}

type controlPolicyMap struct {
	Schema           string `json:"schema"`
	Namespace        string `json:"namespace"`
	PolicyID         string `json:"policy_id"`
	PolicyChecksum   string `json:"policy_checksum"`
	WorkflowID       string `json:"workflow_id"`
	WorkflowChecksum string `json:"workflow_checksum"`
	AssessStepID     string `json:"assess_step_id"`
	ClaimStepID      string `json:"claim_step_id"`
	ProvisionStepID  string `json:"provision_step_id"`
	Profile          string `json:"profile"`
}

type controlApprovedArtifactRead struct {
	handle                        *callHandle
	before, after                 unix.Stat_t
	raw                           []byte
	calledAt, returnedAt, closeAt time.Time
	eof                           bool
	cause                         error
}

type controlPolicyInputs struct {
	mapping                                                controlPolicyMap
	policy, workflow                                       model.Manifest
	policySpec                                             model.CapacityPolicySpec
	workflowSpec                                           model.WorkflowManifestSpec
	assessStep, claimStep, provisionStep                   model.WorkflowStepSpec
	originalPolicyRaw, originalWorkflowRaw, originalMapRaw []byte
	canonicalPolicySpec, canonicalWorkflowSpec             []byte
	originalAuditHandles                                   [3]*callHandle
	originalReads                                          [3]controlApprovedArtifactRead
	// Set only by the complete source-private original classifier. Partial
	// acquisition caches remain diagnostic and cannot satisfy the comparer.
	qualifiedMetadata bool
}

// Every leaf/container is a PRIOR compiled nonsecret logical declaration,
// finalized before metadata artifact hashes. No runtime/DTO/key can populate
// this inventory; empty means unavailable. It never approves native stock.
type controlPublicScalar struct {
	path          string // exact RFC6901 path prefixed /policy, /workflow or /map
	canonicalJSON string // exact public string/number/bool/null token
}
type controlPublicContainer struct {
	path   string
	kind   string // object or array
	length int
}
type controlPolicyPublicInventory struct {
	scalars    []controlPublicScalar
	containers []controlPublicContainer
}

// Source-audit acquisition/read/Close, NOT a signed Host native row. The raw
// original stays private until the complete exact nonsecret value/subtree gate
// passes. Every method error and actual return sample is retained independently
// of later policy validation, cancellation or public-byte classification.
func controlReadPolicyArtifact(ctx context.Context, r *OriginalFactoryRealm, expected approvedArtifact) (out controlApprovedArtifactRead, runErr error) {
	return controlReadPolicyArtifactCaptured(ctx, r, expected)
}

func controlReadApprovedPolicyInputs(ctx context.Context, r *OriginalFactoryRealm) (*controlPolicyInputs, error) {
	if r == nil || r.control == nil || ctx == nil || ctx.Err() != nil {
		return nil, capacity.ErrHostFactorySourceUnavailable
	}
	in := &controlPolicyInputs{}
	if r.control.policyAuditLedger != nil {
		return nil, refused("choice_conflict", nil)
	}
	approvalRaw, err := capacity.CanonicalHostFactory(r.installation.approval)
	if err != nil {
		return nil, err
	}
	r.control.policyAuditLedger, err = newLedger(ctx, r.basal.body.OriginalOwnerID, "host_exterior", r.basal.sha, r.installation.approval.Schema, digest(approvalRaw))
	if err != nil {
		return nil, err
	}
	r.control.sourceAuditOwnerLedgers = append(r.control.sourceAuditOwnerLedgers, r.control.policyAuditLedger)
	names := [3]string{"source-policy-manifest.json", "source-workflow-manifest.json", "source-factory-policy-map.json"}
	for n, name := range names {
		expected := r.installation.controlPolicyArtifacts[n]
		if expected.name != name || expected.bytes < 1 || expected.sha == "" {
			return nil, capacity.ErrHostFactorySourceUnavailable
		}
		read, err := controlReadPolicyArtifact(ctx, r, expected)
		in.originalReads[n] = read
		in.originalAuditHandles[n] = read.handle
		// Preserve failure originals privately before refusing, without installing
		// a metadata cache or exporting any original or digest.
		r.control.policyInputs = in
		if err != nil || !read.eof || read.closeAt.IsZero() || read.cause != nil {
			return nil, refused("source_registry_refused", err)
		}
	}
	in.originalPolicyRaw = bytes.Clone(in.originalReads[0].raw)
	in.originalWorkflowRaw = bytes.Clone(in.originalReads[1].raw)
	in.originalMapRaw = bytes.Clone(in.originalReads[2].raw)
	if err := controlClassifyPublicTree(r.installation.controlPolicyPublic, "/map", in.originalMapRaw); err != nil {
		return nil, err
	}
	if err := decodePrivateOriginalJSON(in.originalMapRaw, &in.mapping); err != nil {
		return nil, err
	}
	if in.mapping.Schema != "original_host_factory_policy_source_map_v2" || in.mapping.Namespace != r.installation.approval.AllowedNamespace || in.mapping.PolicyID != r.installation.approval.AllowedPolicyID || in.mapping.WorkflowID != r.installation.approval.AllowedWorkflowID || in.mapping.AssessStepID != r.installation.approval.AllowedAssessStepID || in.mapping.ClaimStepID != r.installation.approval.AllowedClaimStepID || in.mapping.ProvisionStepID != r.installation.approval.AllowedOriginalStepID {
		return nil, refused("source_registry_refused", nil)
	}
	if err := controlDecodeApprovedManifest(r.installation, in.originalPolicyRaw, "capacity_policy", &in.policy); err != nil {
		return nil, err
	}
	if err := controlDecodeApprovedManifest(r.installation, in.originalWorkflowRaw, "workflow", &in.workflow); err != nil {
		return nil, err
	}
	if in.policy.ID.String() != in.mapping.PolicyID || in.workflow.ID.String() != in.mapping.WorkflowID || in.policy.Checksum != in.mapping.PolicyChecksum || in.workflow.Checksum != in.mapping.WorkflowChecksum {
		return nil, refused("source_registry_refused", nil)
	}
	p, err := manifest.ParseCapacityPolicySpec(in.policy.Spec)
	if err != nil || capacity.ValidatePolicy(p) != nil {
		return nil, refused("source_registry_refused", err)
	}
	in.policySpec = p
	w, err := manifest.ParseWorkflowSpec(in.workflow.Spec)
	if err != nil || manifest.ValidateWorkflowSpec(w) != nil {
		return nil, refused("source_registry_refused", err)
	}
	in.workflowSpec = w
	if len(w.Steps) != 3 {
		return nil, refused("source_registry_refused", nil)
	}
	for _, s := range w.Steps {
		switch s.ID {
		case in.mapping.AssessStepID:
			in.assessStep = s
		case in.mapping.ClaimStepID:
			in.claimStep = s
		case in.mapping.ProvisionStepID:
			in.provisionStep = s
		default:
			return nil, refused("source_registry_refused", nil)
		}
	}
	if err := controlApprovedThreeSteps(r.installation, in); err != nil {
		return nil, err
	}
	profile := false
	for _, p := range p.Profiles {
		if p.Name == in.mapping.Profile {
			profile = true
		}
	}
	if !profile {
		return nil, refused("source_registry_refused", nil)
	}
	in.canonicalPolicySpec, err = controlCanonicalFullJSON(in.policy.Spec)
	if err != nil {
		return nil, err
	}
	in.canonicalWorkflowSpec, err = controlCanonicalFullJSON(in.workflow.Spec)
	if err != nil {
		return nil, err
	}
	// Public hashes are computed ONLY after the source-specific metadata/spec
	// classifier succeeds, and are compared to compiled leaf provenance.
	for n, read := range in.originalReads {
		if digest(read.raw) != r.installation.controlPolicyArtifacts[n].sha {
			return nil, refused("source_registry_refused", nil)
		}
	}
	in.qualifiedMetadata = true
	return in, nil
}

// This comparer is entirely private/full-record, not a public redaction or
// projection. It refuses unknown/changed specs and all original step inputs.
func controlVerifyOriginalPolicyInput(ctx context.Context, r *OriginalFactoryRealm, policy, workflow model.Manifest, assessStep, claimStep, provisionStep model.WorkflowStepSpec) error {
	if ctx == nil || r == nil || ctx.Err() != nil || r.control == nil || r.control.policyInputs == nil {
		return capacity.ErrHostFactorySourceUnavailable
	}
	in := r.control.policyInputs
	if !in.qualifiedMetadata || len(in.originalPolicyRaw) == 0 || len(in.originalWorkflowRaw) == 0 || !controlSameManifestMetadata(policy, in.policy) || !controlSameManifestMetadata(workflow, in.workflow) {
		return refused("source_registry_refused", nil)
	}
	for _, read := range in.originalReads {
		if read.cause != nil || !read.eof || read.calledAt.IsZero() || read.returnedAt.IsZero() || read.closeAt.IsZero() || len(read.raw) == 0 {
			return refused("source_registry_refused", nil)
		}
	}
	for n, read := range in.originalReads {
		if !bytes.Equal(read.raw, r.installation.controlPolicyRaw[n]) {
			return refused("source_registry_refused", nil)
		}
	}
	return controlCompareApprovedPolicyInput(r.installation, policy, workflow, assessStep, claimStep, provisionStep)
}

func controlSameManifestMetadata(a, b model.Manifest) bool {
	return a.ID == b.ID && a.APIVersion == b.APIVersion && a.Kind == b.Kind && a.Version == b.Version && a.Checksum == b.Checksum && reflect.DeepEqual(a.Metadata, b.Metadata) && a.CreatedAt.Equal(b.CreatedAt) && a.UpdatedAt.Equal(b.UpdatedAt)
}

func controlSameOriginalStep(a, b model.WorkflowStepSpec) bool { return reflect.DeepEqual(a, b) }

// UseNumber preserves exact integers; object order/whitespace only are
// normalized. No unknown fields, private values, nulls or fractional numeric
// syntax are discarded to make the original DB comparison pass.
func controlCanonicalFullJSON(raw []byte) ([]byte, error) {
	if len(raw) == 0 || len(raw) > bodyLimit || !json.Valid(raw) {
		return nil, refused("source_registry_refused", nil)
	}
	v, err := controlFullJSONValue(raw)
	if err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// This decoder is used for FULL private source/DB equality. It keeps every
// unknown key/value and exact numeric token, and refuses duplicate keys rather
// than letting json.Unmarshal overwrite an original observation.
func controlFullJSONValue(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > bodyLimit || !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, refused("source_registry_refused", nil)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := controlReadJSONValue(d, 0)
	if err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, refused("source_registry_refused", err)
	}
	return v, nil
}
func controlReadJSONValue(d *json.Decoder, depth int) (any, error) {
	if depth > 48 {
		return nil, refused("source_registry_refused", nil)
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	mark, composite := t.(json.Delim)
	if !composite {
		return t, nil
	}
	switch mark {
	case '{':
		out := map[string]any{}
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return nil, refused("source_registry_refused", err)
			}
			if _, duplicate := out[name]; duplicate {
				return nil, refused("source_registry_refused", nil)
			}
			v, err := controlReadJSONValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			out[name] = v
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, refused("source_registry_refused", err)
		}
		return out, nil
	case '[':
		out := []any{}
		for d.More() {
			v, err := controlReadJSONValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, refused("source_registry_refused", err)
		}
		return out, nil
	}
	return nil, refused("source_registry_refused", nil)
}
func controlObject(v any, allowed ...string) (map[string]any, error) {
	object, ok := v.(map[string]any)
	if !ok {
		return nil, refused("source_registry_refused", nil)
	}
	for key := range object {
		present := false
		for _, name := range allowed {
			if key == name {
				present = true
				break
			}
		}
		if !present {
			return nil, refused("source_registry_refused", nil)
		}
	}
	return object, nil
}

// Exact leaf values and container cardinalities are separately compiled
// PUBLIC declarations. No raw artifact hash is calculated by this classifier.
// It rejects both unmatched observed paths and unmatched compiled paths.
func controlClassifyPublicTree(inventory controlPolicyPublicInventory, prefix string, raw []byte) error {
	value, err := controlFullJSONValue(raw)
	if err != nil {
		return err
	}
	if len(inventory.scalars) == 0 || len(inventory.containers) == 0 {
		return capacity.ErrHostFactorySourceUnavailable
	}
	scalars := map[string]string{}
	containers := map[string]controlPublicContainer{}
	for _, expected := range inventory.scalars {
		if !strings.HasPrefix(expected.path, prefix+"/") {
			continue
		}
		if _, seen := scalars[expected.path]; seen {
			return refused("source_registry_refused", nil)
		}
		token, e := controlFullJSONValue([]byte(expected.canonicalJSON))
		if e != nil {
			return refused("source_registry_refused", e)
		}
		switch token.(type) {
		case map[string]any, []any:
			return refused("source_registry_refused", nil)
		}
		canonical, e := json.Marshal(token)
		if e != nil || string(canonical) != expected.canonicalJSON {
			return refused("source_registry_refused", e)
		}
		scalars[expected.path] = expected.canonicalJSON
	}
	for _, expected := range inventory.containers {
		if expected.path != prefix && !strings.HasPrefix(expected.path, prefix+"/") {
			continue
		}
		if expected.length < 0 || expected.length > bodyLimit || (expected.kind != "array" && expected.kind != "object") {
			return refused("source_registry_refused", nil)
		}
		if _, seen := containers[expected.path]; seen {
			return refused("source_registry_refused", nil)
		}
		if _, seen := scalars[expected.path]; seen {
			return refused("source_registry_refused", nil)
		}
		containers[expected.path] = expected
	}
	var walk func(any, string) error
	walk = func(v any, path string) error {
		switch object := v.(type) {
		case map[string]any:
			expected, found := containers[path]
			if !found || expected.kind != "object" || expected.length != len(object) {
				return refused("source_registry_refused", nil)
			}
			delete(containers, path)
			for key, child := range object {
				escaped := strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
				if err := walk(child, path+"/"+escaped); err != nil {
					return err
				}
			}
		case []any:
			expected, found := containers[path]
			if !found || expected.kind != "array" || expected.length != len(object) {
				return refused("source_registry_refused", nil)
			}
			delete(containers, path)
			for n, child := range object {
				if err := walk(child, path+"/"+strconv.Itoa(n)); err != nil {
					return err
				}
			}
		default:
			actual, e := json.Marshal(v)
			expected, found := scalars[path]
			if e != nil || !found || string(actual) != expected {
				return refused("source_registry_refused", e)
			}
			delete(scalars, path)
		}
		return nil
	}
	if err := walk(value, prefix); err != nil {
		return err
	}
	if len(scalars) != 0 || len(containers) != 0 {
		return refused("source_registry_refused", nil)
	}
	return nil
}

// Reflection supplies ONLY declared JSON keys for concrete typed spec groups.
// Dynamic With/labels groups are checked explicitly below. It supplies neither
// source approval nor public value classification.
func controlDeclaredShape(value any, typ reflect.Type, depth int) error {
	if depth > 48 {
		return refused("source_registry_refused", nil)
	}
	if typ.Kind() == reflect.Pointer {
		if value == nil {
			return nil
		}
		return controlDeclaredShape(value, typ.Elem(), depth+1)
	}
	if typ == reflect.TypeOf(time.Time{}) || (typ.PkgPath() == "github.com/google/uuid" && typ.Name() == "UUID") || typ == reflect.TypeOf([]byte{}) {
		if _, ok := value.(string); !ok {
			return refused("source_registry_refused", nil)
		}
		return nil
	}
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	} // ONLY Manifest.spec, separately closed below
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return refused("source_registry_refused", nil)
		}
		fields := map[string]reflect.StructField{}
		mandatory := map[string]bool{}
		for n := 0; n < typ.NumField(); n++ {
			f := typ.Field(n)
			parts := strings.Split(f.Tag.Get("json"), ",")
			if f.PkgPath != "" || parts[0] == "" || parts[0] == "-" {
				return refused("source_registry_refused", nil)
			}
			fields[parts[0]] = f
			mandatory[parts[0]] = !strings.Contains(f.Tag.Get("json"), ",omitempty")
		}
		for key, child := range object {
			field, declared := fields[key]
			if !declared {
				return refused("source_registry_refused", nil)
			}
			if err := controlDeclaredShape(child, field.Type, depth+1); err != nil {
				return err
			}
			delete(mandatory, key)
		}
		for _, required := range mandatory {
			if required {
				return refused("source_registry_refused", nil)
			}
		}
	case reflect.Slice, reflect.Array:
		if value == nil && typ.Kind() == reflect.Slice {
			return nil
		}
		array, ok := value.([]any)
		if !ok || typ.Kind() == reflect.Array && len(array) != typ.Len() {
			return refused("source_registry_refused", nil)
		}
		for _, child := range array {
			if err := controlDeclaredShape(child, typ.Elem(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		if value == nil {
			return nil
		}
		object, ok := value.(map[string]any)
		if !ok || typ.Key().Kind() != reflect.String {
			return refused("source_registry_refused", nil)
		}
		if typ.Elem().Kind() == reflect.Interface {
			return nil
		} // ONLY WorkflowStep.With, exact source grammar below
		for _, child := range object {
			if err := controlDeclaredShape(child, typ.Elem(), depth+1); err != nil {
				return err
			}
		}
	case reflect.String:
		if _, ok := value.(string); !ok {
			return refused("source_registry_refused", nil)
		}
	case reflect.Bool:
		if _, ok := value.(bool); !ok {
			return refused("source_registry_refused", nil)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		if _, ok := value.(json.Number); !ok {
			return refused("source_registry_refused", nil)
		}
	default:
		return refused("source_registry_refused", nil)
	}
	return nil
}
func controlDecodeApprovedManifest(i fixedInstallation, raw []byte, kind string, out *model.Manifest) error {
	if out == nil {
		return capacity.ErrHostFactorySourceUnavailable
	}
	value, err := controlFullJSONValue(raw)
	if err != nil {
		return err
	}
	object, err := controlObject(value, "id", "apiVersion", "kind", "metadata", "version", "checksum", "spec", "created_at", "updated_at")
	if err != nil {
		return err
	}
	if err = controlDeclaredShape(value, reflect.TypeOf(model.Manifest{}), 0); err != nil {
		return err
	}
	meta, err := controlObject(object["metadata"], "name", "namespace", "description", "labels", "active")
	if err != nil {
		return err
	}
	if meta["active"] != true || meta["namespace"] != i.approval.AllowedNamespace {
		return refused("source_registry_refused", nil)
	}
	if description, present := meta["description"]; present && description != "" {
		return refused("source_registry_refused", nil)
	}
	if labels, present := meta["labels"]; present && labels != nil {
		m, ok := labels.(map[string]any)
		if !ok || len(m) != 0 {
			return refused("source_registry_refused", nil)
		}
	}
	if object["kind"] != kind {
		return refused("source_registry_refused", nil)
	}
	if kind == "capacity_policy" {
		if _, err = controlObject(object["spec"], "environment", "domain", "dimension", "target_identity", "owner", "workflow", "currency", "floor", "ceiling", "step", "max_evidence_age_seconds", "min_samples", "max_sample_gap_seconds", "up_hold_seconds", "down_hold_seconds", "cooldown_seconds", "lease_seconds", "execution_enabled", "signals", "profiles", "mutation_bindings", "guest_bootstrap_binding", "guest_retirement_binding"); err != nil {
			return err
		}
		if err = controlDeclaredShape(object["spec"], reflect.TypeOf(model.CapacityPolicySpec{}), 0); err != nil {
			return err
		}
	} else if kind == "workflow" {
		if _, err = controlObject(object["spec"], "trigger", "dispatch_mode", "authorization", "steps"); err != nil {
			return err
		}
		if err = controlDeclaredShape(object["spec"], reflect.TypeOf(model.WorkflowManifestSpec{}), 0); err != nil {
			return err
		}
	} else {
		return refused("source_registry_refused", nil)
	}
	// Unknown/case/duplicate/null shape is refused BEFORE decoding. Decode into
	// a fresh typed record so partial parser state cannot become the cache.
	var fresh model.Manifest
	if err = json.Unmarshal(raw, &fresh); err != nil {
		return refused("source_registry_refused", err)
	}
	if fresh.ID.String() == "00000000-0000-0000-0000-000000000000" || fresh.Version < 1 || fresh.CreatedAt.IsZero() || fresh.UpdatedAt.IsZero() || fresh.UpdatedAt.Before(fresh.CreatedAt) || fresh.Metadata.Name == "" || fresh.Checksum == "" {
		return refused("source_registry_refused", nil)
	}
	if err = controlClassifyPublicTree(i.controlPolicyPublic, "/"+strings.TrimPrefix(kind, "capacity_"), raw); err != nil {
		return err
	}
	if kind == "capacity_policy" {
		p, err := manifest.ParseCapacityPolicySpec(fresh.Spec)
		if err != nil || capacity.ValidatePolicy(p) != nil {
			return refused("source_registry_refused", err)
		}
		for _, profile := range p.Profiles {
			if !controlNonsecretReference(profile.ValidationRef) {
				return refused("source_registry_refused", nil)
			}
		}
	}
	*out = fresh
	return nil
}
func controlNonsecretReference(value string) bool {
	if value == "" || strings.ContainsAny(value, "\r\n\t%") {
		return false
	}
	if !strings.Contains(value, "://") {
		return !strings.ContainsAny(value, "?&#@")
	}
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && u.ForceQuery == false && u.Fragment == "" && u.RawFragment == "" && u.RawPath == ""
}
func controlApprovedThreeSteps(i fixedInstallation, in *controlPolicyInputs) error {
	if in == nil {
		return capacity.ErrHostFactorySourceUnavailable
	}
	w := in.workflowSpec
	if (w.Trigger.Mode != "" && w.Trigger.Mode != "manual") || w.Trigger.Schedule != nil || w.Trigger.Event != nil || (w.DispatchMode != "sync" && w.DispatchMode != "async") || len(w.Steps) != 3 {
		return refused("source_registry_refused", nil)
	}
	steps := [3]model.WorkflowStepSpec{in.assessStep, in.claimStep, in.provisionStep}
	operations := [3]string{"capacity.assess", "capacity.claim", "capacity.provision_original_guest"}
	ids := [3]string{in.mapping.AssessStepID, in.mapping.ClaimStepID, in.mapping.ProvisionStepID}
	var originalPolicySelector []byte
	for n, s := range steps {
		if s.ID != ids[n] || s.ID == "" || s.Use.Kind != "yggdrasil" || s.Use.Operation != operations[n] || s.Use.InstanceRef != nil || s.Use.ProviderRef != nil || s.Use.Family != "" || s.Use.Capability != "" || s.Description != "" || s.Condition != "" || s.ForEach != nil || s.Retry.MaxAttempts > 1 || s.Retry.MaxAttempts < 0 || s.TimeoutSeconds <= 0 {
			return refused("source_registry_refused", nil)
		}
		raw, e := json.Marshal(s.With["policy"])
		if e != nil {
			return refused("source_registry_refused", e)
		}
		selectorValue, e := controlFullJSONValue(raw)
		if e != nil {
			return e
		}
		if e = controlDeclaredShape(selectorValue, reflect.TypeOf(model.ManifestSelector{}), 0); e != nil {
			return e
		}
		var selector model.ManifestSelector
		if json.Unmarshal(raw, &selector) != nil {
			return refused("source_registry_refused", nil)
		}
		if selector.ManifestID != "" {
			if selector.ManifestID != in.mapping.PolicyID || selector.Namespace != "" || selector.Name != "" || selector.Version != nil {
				return refused("source_registry_refused", nil)
			}
		} else if selector.Namespace != in.policy.Metadata.Namespace || selector.Name != in.policy.Metadata.Name || selector.Version == nil || *selector.Version != in.policy.Version {
			return refused("source_registry_refused", nil)
		}
		canonical, e := controlCanonicalFullJSON(raw)
		if e != nil {
			return e
		}
		if n == 0 {
			originalPolicySelector = canonical
		} else if !bytes.Equal(canonical, originalPolicySelector) {
			return refused("source_registry_refused", nil)
		}
		allowed := []string{"policy", "assessment"}
		if n == 1 {
			allowed = []string{"policy", "generation"}
		}
		if n == 2 {
			allowed = []string{"policy", "binding_name", "slot", "generation", "fencing_token", "lease_owner"}
		}
		if len(s.With) != len(allowed) {
			return refused("source_registry_refused", nil)
		}
		for key := range s.With {
			found := false
			for _, expected := range allowed {
				found = found || key == expected
			}
			if !found {
				return refused("source_registry_refused", nil)
			}
		}
		if n == 0 && s.With["assessment"] != "{{ inputs.assessment }}" {
			return refused("source_registry_refused", nil)
		}
		if n > 0 && s.With["generation"] != fmt.Sprintf("{{ steps.%s.metadata.generation }}", ids[0]) {
			return refused("source_registry_refused", nil)
		}
		if n == 2 {
			if s.With["binding_name"] != i.approval.AllowedMutationBindingName || s.With["fencing_token"] != fmt.Sprintf("{{ steps.%s.metadata.fencing_token }}", ids[1]) || s.With["lease_owner"] != fmt.Sprintf("{{ steps.%s.metadata.lease_owner }}", ids[1]) {
				return refused("source_registry_refused", nil)
			}
			actual, e := json.Marshal(s.With["slot"])
			expected, _ := json.Marshal(i.approval.AllowedSlot)
			if e != nil || !bytes.Equal(actual, expected) {
				return refused("source_registry_refused", e)
			}
		}
	}
	if ids[0] == ids[1] || ids[0] == ids[2] || ids[1] == ids[2] {
		return refused("source_registry_refused", nil)
	}
	return nil
}

// Capture the actual private policy methods after their sole source reader
// returned. Original per-File.Read EOF/error are independent facts; they are
// NOT a manufactured ReadAll or complete/incomplete body-read scope.
func controlRetainPolicyAuditFacts(r *OriginalFactoryRealm) error {
	if r == nil || r.control == nil || r.control.policyAuditLedger == nil {
		return capacity.ErrHostFactorySourceUnavailable
	}
	l := r.control.policyAuditLedger
	handles, cause := l.originalHandles()
	for _, h := range handles {
		if h == nil {
			cause = errors.Join(cause, refused("storage_unknown", nil))
			continue
		}
		h.mu.Lock()
		originals := append([]unclassifiedNativeReturn(nil), h.unclassified...)
		h.mu.Unlock()
		for _, original := range originals {
			if original.callID == "" || original.calledAt.IsZero() {
				r.control.policyAuditUnencoded = append(r.control.policyAuditUnencoded, original)
				cause = errors.Join(cause, refused("storage_unknown", nil))
				continue
			}
			fact := model.HostFactorySourceAuditReturn{Schema: "original_host_factory_source_audit_return_v1", Purpose: "source_audit_only_no_host_native_authority", FactoryRootID: r.rootID, OriginalAuditHandleID: original.handleID, OriginalCallID: ptr(original.callID), Operation: original.operation, OriginalState: "called_pending", OriginalCalledAt: ptr(original.calledAt), OriginalOperationDeadline: original.deadline, OriginalHashState: "unknown_original_bytes"}
			if !original.returnedAt.IsZero() {
				fact.OriginalState = "returned"
				fact.OriginalReturnedAt = ptr(original.returnedAt)
				fact.OriginalErrorPresent = ptr(original.cause != nil)
				fact.OriginalHashState = "not_byte_operation"
				if original.operation == "source_file_read" || original.operation == "source_file_write" {
					if !original.scalarObserved || original.scalar < 0 || original.scalar != int64(len(original.raw)) || original.scalar > bodyLimit+1 {
						r.control.policyAuditUnencoded = append(r.control.policyAuditUnencoded, original)
						cause = errors.Join(cause, refused("storage_unknown", nil))
						continue
					}
					fact.OriginalCount = ptr(original.scalar)
					fact.OriginalHashState = "private_withheld"
					if original.operation == "source_file_read" {
						fact.OriginalEOF = ptr(original.cause == io.EOF)
					}
					// ALL byte digests/raw/prefix stay private/NULL here, even after
					// a separately approved whole logical artifact is classified.
				}
			}
			if _, err := capacity.CanonicalHostFactory(fact); err != nil {
				r.control.policyAuditUnencoded = append(r.control.policyAuditUnencoded, original)
				cause = errors.Join(cause, err)
				continue
			}
			r.control.policyAuditFacts = append(r.control.policyAuditFacts, fact)
		}
	}
	return cause
}

// Cache-only private handoff to the paired Source9 final corpus producer.
// Unencoded original methods remain retained privately and force INCOMPLETE;
// they are never assigned a replacement UUID/ordinal/empty hash.
func controlOriginalSourceAudits(r *OriginalFactoryRealm) ([]model.HostFactorySourceAuditReturn, error) {
	if r == nil || r.control == nil {
		return nil, capacity.ErrHostFactorySourceUnavailable
	}
	c := r.control
	c.closureMu.Lock()
	defer c.closureMu.Unlock()
	if !c.closureReturned {
		return nil, refused("original_close_refused", nil)
	}
	raw, err := json.Marshal(c.policyAuditFacts)
	if err != nil {
		return nil, err
	}
	var facts []model.HostFactorySourceAuditReturn
	if err = json.Unmarshal(raw, &facts); err != nil {
		return nil, err
	}
	if len(c.policyAuditUnencoded) != 0 {
		return facts, refused("storage_unknown", nil)
	}
	return facts, nil
}

// Private implementation of the paired exported Owner wrapper. It compares
// complete logical DB inputs to prior compiled nonsecret declarations. It
// performs NO Realm construction/IO/key use/native approval/counter/clock.
// Native/source/SQL closure is a SEPARATE Source13 historical obligation.
func controlVerifyOriginalHistoricalPolicyInput(ctx context.Context, policy, workflow model.Manifest, assessStep, claimStep, provisionStep model.WorkflowStepSpec) error {
	if ctx == nil || ctx.Err() != nil {
		return refused("original_context_refused", nil)
	}
	approval, err := capacity.ApprovedHostFactorySource()
	if err != nil || approval.ActualBuildSourceCommit != capacity.CurrentGuestCoreSource() {
		return capacity.ErrHostFactorySourceUnavailable
	}
	actualApproval, err := capacity.CanonicalHostFactory(approval)
	if err != nil {
		return err
	}
	var matching *controlPolicyInputs
	for _, i := range compiledInstallations {
		compiledApproval, e := capacity.CanonicalHostFactory(i.approval)
		if e != nil || !bytes.Equal(actualApproval, compiledApproval) || policy.ID.String() != i.approval.AllowedPolicyID || workflow.ID.String() != i.approval.AllowedWorkflowID {
			continue
		}
		in, e := controlCompiledLogicalPolicyInputs(i)
		if e != nil {
			return e
		}
		if matching != nil {
			return refused("source_registry_refused", nil)
		}
		matching = in
	}
	if matching == nil {
		return capacity.ErrHostFactorySourceUnavailable
	}
	return controlCompareLogicalCache(matching, policy, workflow, assessStep, claimStep, provisionStep)
}

func controlCompareApprovedPolicyInput(i fixedInstallation, policy, workflow model.Manifest, assessStep, claimStep, provisionStep model.WorkflowStepSpec) error {
	in, err := controlCompiledLogicalPolicyInputs(i)
	if err != nil {
		return err
	}
	return controlCompareLogicalCache(in, policy, workflow, assessStep, claimStep, provisionStep)
}
func controlCompareLogicalCache(in *controlPolicyInputs, policy, workflow model.Manifest, assessStep, claimStep, provisionStep model.WorkflowStepSpec) error {
	if in == nil {
		return capacity.ErrHostFactorySourceUnavailable
	}
	if !controlSameManifestMetadata(policy, in.policy) || !controlSameManifestMetadata(workflow, in.workflow) {
		return refused("source_registry_refused", nil)
	}
	p, e1 := controlCanonicalFullJSON(policy.Spec)
	w, e2 := controlCanonicalFullJSON(workflow.Spec)
	if e1 != nil || e2 != nil || !bytes.Equal(p, in.canonicalPolicySpec) || !bytes.Equal(w, in.canonicalWorkflowSpec) || !controlSameOriginalStep(assessStep, in.assessStep) || !controlSameOriginalStep(claimStep, in.claimStep) || !controlSameOriginalStep(provisionStep, in.provisionStep) {
		return refused("source_registry_refused", errors.Join(e1, e2))
	}
	return nil
}
func controlCompiledLogicalPolicyInputs(i fixedInstallation) (*controlPolicyInputs, error) {
	// These independent finalized PUBLIC leaves precede SourceInputs/registry/
	// closure/approval. Zero inventory is never synthesized from DB/caller data.
	in := &controlPolicyInputs{originalPolicyRaw: bytes.Clone(i.controlPolicyRaw[0]), originalWorkflowRaw: bytes.Clone(i.controlPolicyRaw[1]), originalMapRaw: bytes.Clone(i.controlPolicyRaw[2])}
	names := [3]string{"source-policy-manifest.json", "source-workflow-manifest.json", "source-factory-policy-map.json"}
	for n, raw := range i.controlPolicyRaw {
		if i.controlPolicyArtifacts[n].name != names[n] || len(raw) == 0 || len(raw) > bodyLimit || int64(len(raw)) != i.controlPolicyArtifacts[n].bytes {
			return nil, capacity.ErrHostFactorySourceUnavailable
		}
	}
	if err := controlClassifyPublicTree(i.controlPolicyPublic, "/map", in.originalMapRaw); err != nil {
		return nil, err
	}
	if err := decodePrivateOriginalJSON(in.originalMapRaw, &in.mapping); err != nil {
		return nil, err
	}
	m := in.mapping
	a := i.approval
	if m.Schema != "original_host_factory_policy_source_map_v2" || m.Namespace != a.AllowedNamespace || m.PolicyID != a.AllowedPolicyID || m.WorkflowID != a.AllowedWorkflowID || m.AssessStepID != a.AllowedAssessStepID || m.ClaimStepID != a.AllowedClaimStepID || m.ProvisionStepID != a.AllowedOriginalStepID {
		return nil, refused("source_registry_refused", nil)
	}
	if err := controlDecodeApprovedManifest(i, in.originalPolicyRaw, "capacity_policy", &in.policy); err != nil {
		return nil, err
	}
	if err := controlDecodeApprovedManifest(i, in.originalWorkflowRaw, "workflow", &in.workflow); err != nil {
		return nil, err
	}
	if in.policy.ID.String() != m.PolicyID || in.workflow.ID.String() != m.WorkflowID || in.policy.Checksum != m.PolicyChecksum || in.workflow.Checksum != m.WorkflowChecksum {
		return nil, refused("source_registry_refused", nil)
	}
	p, err := manifest.ParseCapacityPolicySpec(in.policy.Spec)
	if err != nil || capacity.ValidatePolicy(p) != nil {
		return nil, refused("source_registry_refused", err)
	}
	in.policySpec = p
	w, err := manifest.ParseWorkflowSpec(in.workflow.Spec)
	if err != nil || manifest.ValidateWorkflowSpec(w) != nil || len(w.Steps) != 3 {
		return nil, refused("source_registry_refused", err)
	}
	in.workflowSpec = w
	for _, s := range w.Steps {
		switch s.ID {
		case m.AssessStepID:
			in.assessStep = s
		case m.ClaimStepID:
			in.claimStep = s
		case m.ProvisionStepID:
			in.provisionStep = s
		default:
			return nil, refused("source_registry_refused", nil)
		}
	}
	if err = controlApprovedThreeSteps(i, in); err != nil {
		return nil, err
	}
	profileFound := false
	for _, profile := range p.Profiles {
		profileFound = profileFound || profile.Name == m.Profile
	}
	if !profileFound {
		return nil, refused("source_registry_refused", nil)
	}
	in.canonicalPolicySpec, err = controlCanonicalFullJSON(in.policy.Spec)
	if err != nil {
		return nil, err
	}
	in.canonicalWorkflowSpec, err = controlCanonicalFullJSON(in.workflow.Spec)
	if err != nil {
		return nil, err
	}
	for n, raw := range i.controlPolicyRaw {
		if digest(raw) != i.controlPolicyArtifacts[n].sha {
			return nil, refused("source_registry_refused", nil)
		}
	}
	// qualifiedMetadata is deliberately NOT set: no original runtime file
	// Read/EOF/Close has occurred in this historical-only pure comparison.
	return in, nil
}

// PATCH_ONLY. This owns the SAME registered close/join once and caches original
// returns. It never marks a pending owner returned or signs another owner's IO.
// The private policy-audit ledger remains separate/non-native and is retained
// independently; it cannot disappear from the final historical corpus.
func controlCloseAndJoin(ctx context.Context, r *OriginalFactoryRealm) error {
	if ctx == nil || r == nil || r.control == nil || r.basal == nil {
		return refused("original_close_refused", nil)
	}
	c := r.control
	c.closureMu.Lock()
	defer c.closureMu.Unlock()
	c.closureOnce.Do(func() {
		// The first effective close attempt permanently stops new effects even
		// if its cleanup-context/Source guard refuses. A consumed closeOnce or
		// closed closeDone must never leave live admission/publication behind.
		r.mu.Lock()
		r.closing = true
		r.mu.Unlock()
		c.admissionMu.Lock()
		if c.admission.reservations == nil {
			c.closureCause = errors.Join(c.closureCause, refused("owner_registration_refused", nil))
		}
		c.admission.state = "permanently_closed_for_completion"
		c.admissionMu.Unlock()
		// Seal before the cleanup guard and actual owner joins. These Source
		// stop bits do not assert an actual Close/Wait/EOF or native completion.
		c.publicationMu.Lock()
		c.publicationSealed = true
		c.publicationMu.Unlock()
		if err := controlCaptureOriginalClosingContext(ctx, r); err != nil {
			c.closureCause = errors.Join(c.closureCause, err)
			return
		}
		c.publicationMu.Lock()
		originalObservers := append([]*controlObservationOwner(nil), c.observationOwners...)
		originalChildren := []*originalChild{r.worker, r.registrar}
		originalLedgers := []*originalLedger{r.basal.ledger}
		if c.registrarLedger != nil && c.registrarLedger != r.basal.ledger {
			originalLedgers = append(originalLedgers, c.registrarLedger)
		}
		publishers := append([]*originalNativePublisher{}, c.nativePublishers...)
		c.publicationMu.Unlock()
		if writer := c.workerControlWriter; writer != nil && writer.file != nil && !writer.closed {
			operation, subject := "control_writer_close", "host_worker"
			if r.installation.entry == "ordinary_original_create" {
				operation, subject = "ordinary_grant_writer_close", "factory_ordinary_worker"
			}
			_, cause := closeOwned(writer, operation, subject, "cleanup")
			c.closureCause = errors.Join(c.closureCause, cause)
		}

		// The preowned closing RPC returns signed original child IO custody
		// before cancellation or signal. This is not a new Native phase/token.
		if r.registrar != nil {
			c.closureCause = errors.Join(c.closureCause, controlRegistrarCloseOriginal(ctx, r))
		}
		for _, child := range originalChildren {
			if child == nil {
				continue
			}
			gracefulErr := child.join(ctx) // real sole Wait + literal stdout/stderr EOF/Close first
			c.closureCause = errors.Join(c.closureCause, gracefulErr, child.CloseAndJoin(ctx))
			select {
			case <-child.resultDone:
			default:
				// Keep SAME root/parent/basal pins held while the original Wait or
				// pipe reader remains pending. Timeout is NOT an owner join.
				c.closureCause = errors.Join(c.closureCause, refused("original_wait_refused", nil))
				return
			}
		}
		if r.worker != nil && r.installation.entry == "ordinary_original_create" {
			c.closureCause = errors.Join(c.closureCause, controlReadOriginalOrdinaryWorkerIO(ctx, r, r.worker, "closing"))
		}
		if r.worker != nil && (r.installation.entry == "sealed_a0" || r.installation.entry == "sealed_a1") {
			c.closureCause = errors.Join(c.closureCause, controlReadOriginalWorkerIO(ctx, r, r.worker, "closing"))
		}

		// No private observation loop may outlive these dependencies. Such loops
		// register original done channels before launch; only their actual return
		// permits closing. Missing supplier never becomes an empty native census.
		for _, owner := range originalObservers {
			if owner == nil || owner.done == nil || owner.cancel == nil {
				c.closureCause = errors.Join(c.closureCause, refused("native_join_refused", nil))
				return
			}
			owner.cancel()
			select {
			case <-owner.done:
				c.closureCause = errors.Join(c.closureCause, owner.cause)
			case <-ctx.Done():
				c.closureCause = errors.Join(c.closureCause, refused("native_join_refused", ctx.Err()))
				return
			}
		}
		// Independent Source observers retain each genuine namespace/handle.
		// Their native pins close only after child/observation owners returned.
		seenLedgers := map[*originalLedger]bool{}
		for _, l := range originalLedgers {
			seenLedgers[l] = true
		}
		seenPins := map[*callHandle]bool{}
		for _, publisher := range publishers {
			if publisher == nil {
				c.closureCause = errors.Join(c.closureCause, refused("storage_unknown", nil))
				continue
			}
			for _, pin := range append(append([]*originalPin{}, publisher.ownedNativePins...), publisher.scopedExteriorPins...) {
				if pin == nil || pin.handle == nil || seenPins[pin.handle] {
					continue
				}
				seenPins[pin.handle] = true
				subject := "host_exterior"
				if pin.acquisition != nil {
					subject = pin.acquisition.subjectRole
				}
				_, e := closeOwned(pin.handle, "native_subject_pidfd_close", subject, "cleanup")
				c.closureCause = errors.Join(c.closureCause, e)
			}
			for _, l := range publisher.originalLedgers {
				if l == nil || seenLedgers[l] {
					continue
				}
				seenLedgers[l] = true
				originalLedgers = append(originalLedgers, l)
			}
		}
		if r.cancel != nil {
			r.cancel()
		} // AFTER real child and independent observer joins
		if c.fresh != nil && c.fresh.anchor != nil && c.fresh.anchor.file != nil {
			_, err := closeOwned(c.fresh.anchor, "root_directory_close", "host_exterior", "root_completion")
			c.closureCause = errors.Join(c.closureCause, err)
		}
		if r.preparedRootHandle != nil && r.root != nil {
			if r.preparedRootHandle.file != r.root {
				c.closureCause = errors.Join(c.closureCause, refused("native_join_refused", nil))
				return
			}
			_, err := closeOwned(r.preparedRootHandle, "source_directory_close", "host_exterior", "root_completion")
			c.closureCause = errors.Join(c.closureCause, err)
			r.root = nil
		}
		c.closureCause = errors.Join(c.closureCause, r.basal.close())
		if c.policyAuditLedger != nil {
			c.closureCause = errors.Join(c.closureCause, controlRetainPolicyAuditFacts(r))
		}
		// All actual native calls are retained even when an earlier result was
		// late/error. Complete graph consistency is a separate requirement; the
		// callback cannot replace unknown/unclassified calls with zero facts.
		for _, l := range originalLedgers {
			snapshot, err := publishOriginalLedgerInventories(ctx, l)
			c.closureCause = errors.Join(c.closureCause, err)
			c.ledgerSnapshots = append(c.ledgerSnapshots, snapshot)
			if snapshot != nil {
				for _, h := range snapshot.handles {
					if h.inventorySHA256 != "" {
						c.handleInventories = append(c.handleInventories, h.inventorySHA256)
					}
				}
			}
			c.closureCause = errors.Join(c.closureCause, controlCaptureExteriorOriginalReturns(r, l, snapshot))
		}
		// Registrar returns are selected from the actual parent-side same-child
		// command/reader/pin handles. Child-owned basal Close comes ONLY from the
		// independently authenticated original child publication (not parent IO).
		if r.registrar != nil {
			registrar := []realmOwnerReturn{}
			for _, row := range c.ownerReturns {
				if row.SubjectRole == "host_registrar" && row.OwnerRole == "host_exterior" {
					registrar = append(registrar, row)
				}
			}
			raw, e := json.Marshal(registrar)
			if e != nil || len(registrar) == 0 || len(raw) > bodyLimit {
				c.closureCause = errors.Join(c.closureCause, refused("storage_unknown", e))
			} else {
				c.registrarReturnsRaw = bytes.Clone(raw)
				c.registrarReturnsSHA = digest(raw)
			}
		}
		for _, l := range originalLedgers {
			c.closureCause = errors.Join(c.closureCause, controlCacheOriginalClosingIO(r, l))
		}
		// Child signatures remain original. Copy only previously Source-verified
		// IO; never select another role on the exterior key or re-sign it.
		for _, publisher := range publishers {
			if publisher == nil {
				continue
			}
			publisher.mu.Lock()
			for _, original := range publisher.importedIO {
				if old, known := c.closingIO[original.selector]; known && !bytes.Equal(old, original.envelope) {
					c.closureCause = errors.Join(c.closureCause, refused("storage_unknown", nil))
					continue
				}
				c.closingIO[original.selector] = bytes.Clone(original.envelope)
			}
			publisher.mu.Unlock()
		}
		c.closureCause = errors.Join(c.closureCause, controlCaptureOriginalRegistrarBasalClose(r))

		c.closureReturned = true // Actual closure function returned; NOT complete/native authority.
	})
	if c.closureCause != nil || !c.closureReturned {
		return refused("original_close_refused", c.closureCause)
	}
	return nil
}

type controlObservationOwner struct {
	cancel context.CancelFunc
	done   chan struct{}
	cause  error // set by sole original loop BEFORE close(done)
}

func controlCaptureExteriorOriginalReturns(r *OriginalFactoryRealm, l *originalLedger, snapshot *originalLedgerInventorySnapshot) error {
	if snapshot == nil || r == nil || r.control == nil || r.basal == nil || l == nil || l.ownerRole != "host_exterior" || l.ownerID != r.basal.body.OriginalOwnerID || l.primitiveSHA != r.basal.sha {
		return refused("storage_unknown", nil)
	}
	inventoryByHandle := map[string]string{}
	for _, h := range snapshot.handles {
		inventoryByHandle[h.handleID] = h.inventorySHA256
	}
	l.mu.Lock()
	handles := make(map[string]*callHandle, len(l.handles))
	for id, h := range l.handles {
		handles[id] = h
	}
	l.mu.Unlock()
	ids := []string{}
	for id := range handles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var cause error
	for _, id := range ids {
		h := handles[id]
		if h == nil {
			cause = errors.Join(cause, refused("storage_unknown", nil))
			continue
		}
		h.mu.Lock()
		l.mu.Lock()
		rows := []*retainedCall{}
		for _, calls := range l.calls {
			for _, row := range calls {
				if row != nil && row.fact.OriginalHandleID == id {
					copy := *row
					rows = append(rows, &copy)
				}
			}
		}
		l.mu.Unlock()
		h.mu.Unlock()
		sort.Slice(rows, func(a, b int) bool {
			aa, bb := rows[a].fact.OriginalCallOrdinal, rows[b].fact.OriginalCallOrdinal
			if aa == nil {
				return bb != nil
			}
			if bb == nil {
				return false
			}
			return *aa < *bb
		})
		for _, row := range rows {
			if !controlCompletionOperation(row.fact.Operation) {
				continue
			}
			record, err := controlOriginalOwnerReturn(l, row, inventoryByHandle[id])
			r.control.ownerReturns = append(r.control.ownerReturns, record)
			cause = errors.Join(cause, err)
			if row.fact.Operation == "basal_self_pidfd_close" {
				fact, err := controlDiagnosticFromOriginal(l, row)
				if err != nil {
					cause = errors.Join(cause, err)
				} else {
					r.control.basalCloseReturns = append(r.control.basalCloseReturns, fact)
				}
			}
		}
	}
	return cause
}
func controlCompletionOperation(operation string) bool {
	switch operation {
	case "worker_wait", "registrar_wait", "stdout_read", "stderr_read", "stdout_close", "stderr_close", "worker_pidfd_close", "registrar_pidfd_close", "root_directory_close", "source_directory_close", "basal_self_pidfd_close":
		return true
	}
	return false
}
func controlOriginalOwnerReturn(l *originalLedger, row *retainedCall, inventorySHA string) (realmOwnerReturn, error) {
	out := realmOwnerReturn{Schema: "source_owned_host_factory_realm_owner_return_v1", OwnerRole: l.ownerRole, SubjectRole: row.subjectRole, OriginalOwnerID: l.ownerID, SubjectOwnerID: row.fact.SubjectOwnerID, OriginalHandleID: row.fact.OriginalHandleID, Operation: row.fact.Operation, OriginalState: row.fact.OriginalState}
	factRaw, err := json.Marshal(row.fact)
	if err != nil {
		return out, err
	}
	var fact model.HostFactoryPrimitiveIOReturn
	if err = json.Unmarshal(factRaw, &fact); err != nil {
		return out, err
	}
	out.OriginalFact = &fact
	if row.finalSHA == "" || inventorySHA == "" || row.fact.OriginalState != "returned" || row.fact.OriginalReturnedAt == nil || row.fact.OriginalCallOrdinal == nil {
		return out, refused("storage_unknown", nil)
	}
	raw, err := l.collection.Resolve(row.finalSHA)
	if err != nil {
		return out, err
	}
	var chunk model.HostFactoryCallVectorChunk
	if l.bindingSchema == "original_host_factory_pre_authority_scope_v4" {
		if l.sourceProfile == nil {
			return out, refused("source_registry_refused", nil)
		}
		err = l.sourceProfile.Decode(raw, &chunk)
	} else {
		err = capacity.DecodeHostFactory(raw, &chunk)
	}
	if err != nil {
		return out, err
	}
	index := -1
	for n, selected := range chunk.OriginalCalls {
		if reflect.DeepEqual(selected, fact) {
			if index != -1 {
				return out, refused("storage_unknown", nil)
			}
			index = n
		}
	}
	if index < 0 || chunk.OriginalOwnerID != l.ownerID || chunk.OriginalHandleID != fact.OriginalHandleID {
		return out, refused("storage_unknown", nil)
	}
	h := l.handles[fact.OriginalHandleID]
	if h == nil {
		return out, refused("storage_unknown", nil)
	}
	vector, err := l.vector(h, fact.Operation, row.subjectRole)
	if err != nil {
		return out, err
	}
	out.OriginalFactReference = &realmFactReference{BindingSchema: l.bindingSchema, BindingSHA256: l.bindingSHA, ChunkBodySHA256: row.finalSHA, FactIndex: uint32(index), OriginalCallVector: vector, OriginalHandleInventoryBodySHA256: ptr(inventorySHA)}
	return out, nil
}

// Aggregate classification follows actual primitive outputs. It does not
// rewrite native errors or completion timestamps to satisfy a positive guard.
func controlDiagnosticFromOriginal(l *originalLedger, row *retainedCall) (model.HostFactoryDiagnosticIOFact, error) {
	x := row.fact
	h := l.handles[x.OriginalHandleID]
	if h == nil {
		return model.HostFactoryDiagnosticIOFact{}, refused("storage_unknown", nil)
	}
	v, err := l.vector(h, x.Operation, row.subjectRole)
	if err != nil {
		return model.HostFactoryDiagnosticIOFact{}, err
	}
	return model.HostFactoryDiagnosticIOFact{Operation: x.Operation, OriginalHandleID: x.OriginalHandleID, OwnerPrimitiveRawSHA256: x.OwnerPrimitiveRawSHA256, OriginalState: x.OriginalState, OriginalCalledAt: x.OriginalCalledAt, OriginalReturnedAt: x.OriginalReturnedAt, OriginalCount: x.OriginalCount, OriginalSHA256: x.OriginalSHA256, OriginalReturnClass: x.OriginalReturnClass, OriginalCloseState: "not_called", OriginalCloseClass: "unavailable", SubjectOwnerID: x.SubjectOwnerID, OriginalOperationDeadline: x.OriginalOperationDeadline, OriginalHashState: x.OriginalHashState, OriginalEOF: x.OriginalEOF, OriginalCallVector: v, OriginalCloseCallVector: model.HostFactoryCallVectorReference{Operation: x.Operation, OriginalHandleID: x.OriginalHandleID, OriginalOwnerID: l.ownerID, OwnerPrimitiveRawSHA256: ptr(l.primitiveSHA), SubjectOwnerID: x.SubjectOwnerID, CollectionState: "complete_original_calls"}}, nil
}

// Only THIS original exterior signs its own retained IO while its key is still
// held. Child-owned bodies require the original child's authenticated sender;
// these are never signed by changing role on an exterior key.
func controlCacheOriginalClosingIO(r *OriginalFactoryRealm, l *originalLedger) error {
	if r == nil || r.control == nil || l == nil || l.collection == nil || l.ownerRole != "host_exterior" || len(r.control.exteriorKey) != ed25519.PrivateKeySize || !r.installation.approvedPublic(l.ownerRole, r.control.exteriorKey.Public().(ed25519.PublicKey)) {
		return refused("role_or_signature_refused", nil)
	}
	for sha, raw := range l.collection.OriginalBodies() {
		var schema struct {
			Schema string `json:"schema"`
		}
		if json.Unmarshal(raw, &schema) != nil {
			return refused("storage_unknown", nil)
		}
		var body any
		kind := ""
		switch schema.Schema {
		case "original_host_factory_call_vector_chunk_v2":
			body = &model.HostFactoryCallVectorChunk{}
			kind = "chunk"
		case "original_host_factory_call_vector_manifest_v2":
			body = &model.HostFactoryCallVectorManifest{}
			kind = "manifest"
		case "original_host_factory_handle_call_inventory_v1":
			body = &model.HostFactoryHandleCallInventory{}
			kind = "inventory"
		default:
			return refused("storage_unknown", nil)
		}
		decodeErr := capacity.DecodeHostFactory(raw, body)
		if l.bindingSchema == "original_host_factory_pre_authority_scope_v4" {
			if l.sourceProfile == nil || l.collection.sourceProfile != l.sourceProfile {
				return capacity.ErrHostFactorySourceUnavailable
			}
			decodeErr = l.sourceProfile.Decode(raw, body)
		}
		if decodeErr != nil {
			return refused("storage_unknown", nil)
		}
		var envelope []byte
		for _, publisher := range r.control.nativePublishers {
			if publisher == nil {
				continue
			}
			publisher.mu.Lock()
			original, known := publisher.ioPublications[sha]
			publisher.mu.Unlock()
			if !known {
				continue
			}
			if !bytes.Equal(original.body, raw) || envelope != nil && !bytes.Equal(envelope, original.envelope) {
				return refused("storage_unknown", nil)
			}
			envelope = bytes.Clone(original.envelope)
		}
		if envelope == nil {
			var err error
			if l.bindingSchema == "original_host_factory_pre_authority_scope_v4" {
				purposes := []capacity.HostFactorySourceCallPurpose{}
				if chunk, ok := body.(*model.HostFactoryCallVectorChunk); ok {
					purposes, err = l.originalSourceChunkPurposes(*chunk)
					if err != nil {
						return err
					}
				}
				envelope, err = l.sourceProfile.SignEnvelope(reflect.ValueOf(body).Elem().Interface(), purposes, l.ownerRole, keyIDFor(r.installation, l.ownerRole), l.bindingSchema, l.bindingSHA, r.control.exteriorKey)
			} else {
				envelope, err = capacity.SignHostFactoryEnvelope(reflect.ValueOf(body).Elem().Interface(), l.ownerRole, keyIDFor(r.installation, l.ownerRole), l.bindingSchema, l.bindingSHA, r.control.exteriorKey)
			}
			if err != nil {
				return err
			}
		}
		handle := ""
		switch x := body.(type) {
		case *model.HostFactoryCallVectorChunk:
			handle = x.OriginalHandleID
		case *model.HostFactoryCallVectorManifest:
			handle = x.OriginalHandleID
		case *model.HostFactoryHandleCallInventory:
			handle = x.OriginalHandleID
		}
		selector := "io-calls/" + handle + "/" + kind + "/" + sha
		if r.control.closingIO == nil {
			r.control.closingIO = map[string][]byte{}
		}
		if prior, seen := r.control.closingIO[selector]; seen && !bytes.Equal(prior, envelope) {
			return refused("storage_unknown", nil)
		}
		r.control.closingIO[selector] = bytes.Clone(envelope)
	}
	return nil
}

// Pure cache getter after the actual owning Close. Missing mandatory registrar
// basal publication/joins/RootPreparation remains HOLD, including partial
// constructors; no empty hash, timestamp or absent-VM inference is emitted.
func controlOriginalRootCompletion(r *OriginalFactoryRealm) (model.HostFactoryRootCompletion, []realmOwnerReturn, error) {
	if r == nil || r.control == nil {
		return model.HostFactoryRootCompletion{}, nil, capacity.ErrHostFactorySourceUnavailable
	}
	c := r.control
	c.closureMu.Lock()
	defer c.closureMu.Unlock()
	if !c.closureReturned || c.closureCause != nil || len(r.rootPreparationRaw) == 0 || c.registrarReturnsSHA == "" || len(c.basalCloseReturns) < 2 || len(c.handleInventories) == 0 || len(c.ownerReturns) == 0 {
		return model.HostFactoryRootCompletion{}, nil, refused("original_close_refused", c.closureCause)
	}
	body := model.HostFactoryRootCompletion{Schema: "original_host_factory_root_completion_v4", Purpose: "original_host_factory_root_completion_v4", RootPreparationSHA256: digest(r.rootPreparationRaw), RegistrarExteriorReturnsSHA256: c.registrarReturnsSHA, OriginalBasalPinCloseReturns: append([]model.HostFactoryDiagnosticIOFact(nil), c.basalCloseReturns...), DiagnosticStageRawSHAs: []string{}, OriginalHandleInventorySHAs: append([]string(nil), c.handleInventories...)}
	if len(r.initialRaw) != 0 {
		body.InitialEmptyRealmReadSHA256 = ptr(digest(r.initialRaw))
	}
	if len(r.leaseRaw) != 0 {
		body.OriginalLeaseProvenanceSHA256 = ptr(digest(r.leaseRaw))
	}
	// The Owner finalizer alone adds its actual sampled CompletedAt and signs
	// once AFTER real Main dependency closure. No IO/sign/clock happens here.
	encoded, err := json.Marshal(struct {
		Body   model.HostFactoryRootCompletion
		Owners []realmOwnerReturn
	}{body, c.ownerReturns})
	if err != nil {
		return model.HostFactoryRootCompletion{}, nil, err
	}
	var copy struct {
		Body   model.HostFactoryRootCompletion
		Owners []realmOwnerReturn
	}
	if json.Unmarshal(encoded, &copy) != nil {
		return model.HostFactoryRootCompletion{}, nil, refused("storage_unknown", nil)
	}
	return copy.Body, copy.Owners, nil
}

// PATCH_ONLY: the Source9 owner composes this private slice into control_linux.go.
// A successful launch is an actual Start return, never native qualification.
// The compiled installation is still empty; this supplies no runtime approval.
func controlLaunchOriginalRegistrar(ctx context.Context, r *OriginalFactoryRealm) (*originalChild, error) {
	if ctx == nil || r == nil || r.control == nil || ctx != r.ctx || r.basal == nil || ctx.Err() != nil {
		return nil, capacity.ErrHostFactorySourceUnavailable
	}
	c := r.control
	c.registrarStartOnce.Do(func() {
		c.registrarStartErr = controlRegistrarLaunchOnce(ctx, r)
	})
	c.publicationMu.Lock()
	child := r.registrar
	c.publicationMu.Unlock()
	if c.registrarStartErr != nil || child == nil {
		return child, refused("source_registry_refused", c.registrarStartErr)
	}
	return child, nil
}

func controlRegistrarLaunchOnce(ctx context.Context, r *OriginalFactoryRealm) (runErr error) {
	c := r.control
	i := r.installation
	launchContext, cancelLaunch := context.WithCancel(ctx)
	launchOwner := &controlObservationOwner{cancel: cancelLaunch, done: make(chan struct{})}
	c.publicationMu.Lock()
	r.mu.Lock()
	closed := c.publicationSealed || r.closing || ctx.Err() != nil
	if !closed {
		c.observationOwners = append(c.observationOwners, launchOwner)
	}
	r.mu.Unlock()
	c.publicationMu.Unlock()
	if closed {
		cancelLaunch()
		return refused("owner_registration_refused", nil)
	}
	// The original function is registered before any key/pipe/Start IO. Close
	// joins its actual return before closing the source/root/ledger dependencies.
	defer func() {
		cancelLaunch()
		launchOwner.cause = runErr
		close(launchOwner.done)
	}()
	ctx = launchContext
	r.mu.Lock()
	trusted := r.trustedInstallationLocked()
	preparationRaw := bytes.Clone(r.rootPreparationRaw)
	preparationEnvelope := bytes.Clone(r.records["root-preparation"])
	preparation := r.rootPreparation
	r.mu.Unlock()
	if trusted != nil || c.fresh == nil || c.fresh.anchor == nil || len(preparationRaw) == 0 || len(preparationEnvelope) == 0 || len(c.bootstrapChallenge) != 32 || len(c.exteriorKey) != ed25519.PrivateKeySize || c.policyAuditLedger == nil {
		return refused("source_registry_refused", trusted)
	}
	canonical, err := capacity.CanonicalHostFactory(preparation)
	if err != nil || !bytes.Equal(canonical, preparationRaw) || preparation.FactoryRootID != r.rootID || preparation.Schema != "original_host_factory_root_preparation_v4" {
		return refused("source_registry_refused", err)
	}
	r.mu.Lock()
	err = r.verifyOriginalStageLocked("root-preparation", preparationEnvelope)
	r.mu.Unlock()
	if err != nil {
		return err
	}
	cmd, err := controlRegistrarCommand(i)
	if err != nil {
		return err
	}
	key, err := controlRegistrarReadKey(ctx, r)
	if err != nil {
		return err
	}
	defer clear(key)
	ownerID, err := newID()
	if err != nil {
		return err
	}
	bindingSHA := digest(preparationRaw)
	l, err := newLedger(r.ctx, r.basal.body.OriginalOwnerID, "host_exterior", r.basal.sha, preparation.Schema, bindingSHA)
	if err != nil {
		return err
	}
	l.subjects["host_registrar"] = ownerID
	// Reserve this one original launch owner before any pipe acquisition. The
	// same gate protects Close's ledger/child snapshot. No join runs under it.
	c.publicationMu.Lock()
	r.mu.Lock()
	refusedLaunch := c.publicationSealed || r.closing || r.registrar != nil || c.registrarLedger != nil || c.registrarExpectedOwnerID != "" || ctx.Err() != nil
	if !refusedLaunch {
		c.registrarLedger = l
		c.registrarExpectedOwnerID = ownerID
		c.registrarKey = append(ed25519.PrivateKey(nil), key...)
	}
	r.mu.Unlock()
	c.publicationMu.Unlock()
	if refusedLaunch {
		return refused("owner_registration_refused", nil)
	}
	if err = controlRegistrarReserveRPC(r.ctx, r); err != nil {
		return err
	}
	read, write, readerSource, err := controlRegistrarBootstrapPipe(ctx, l)
	if err != nil {
		return err
	}
	// The retained original launch owner covers all the following writes/Close.
	defer func() {
		_, closeErr := closeOwned(write, "bootstrap_writer_close", "host_registrar", "cleanup")
		runErr = errors.Join(runErr, closeErr)
		if runErr != nil {
			_, closeErr = closeOwned(read, "bootstrap_reader_close", "host_registrar", "cleanup")
			runErr = errors.Join(runErr, closeErr)
		}
	}()
	hints := launchHints{rootID: r.rootID, ownerID: ownerID, role: "host_registrar", approvalSHA: i.approvalRawSHA, buildSHA: i.registrar.buildSHA, started: r.started, deadline: r.deadline}
	cmd.Env = append(fixedChildEnvironment(hints, i.privateDirectory, bindingSHA, bindingSHA, ""), "HOST_ORIGINAL_FD3_PARENT_HANDLE_ID="+readerSource.OriginalHandleID)
	cmd.ExtraFiles = []*os.File{read.file}
	register := func(child *originalChild) (func(), error) {
		c.publicationMu.Lock()
		r.mu.Lock()
		closed := c.publicationSealed || r.closing || r.registrar != nil || child == nil || child.command == nil || child.command.ledger != l || c.registrarLedger != l || ctx.Err() != nil
		if !closed {
			r.registrar = child      // actual allocated owner, before any child effect
			child.registrarRealm = r // Source-owned LF reader before its goroutine/Start
		}
		r.mu.Unlock()
		if closed {
			c.publicationMu.Unlock()
			return nil, refused("owner_registration_refused", nil)
		}
		var releaseOnce sync.Once
		return func() { releaseOnce.Do(c.publicationMu.Unlock) }, nil
	}
	child, err := startOriginalChildRegistered(ctx, cmd, l, "host_registrar", "registrar_start", "registrar_start", "registrar_wait", []originalChildInput{{handle: read, closeOperation: "bootstrap_reader_close"}}, register)
	if err != nil {
		return err
	}
	if child == nil || child.cmd != cmd || child.pin == nil {
		return refused("source_registry_refused", nil)
	}
	writerSource, err := descriptorFromAcquisition(write, read, "bootstrap_writer", l.primitiveSHA, "host_registrar", "registrar_bootstrap", "bootstrap_pipe_create")
	if err != nil {
		return err
	}
	// The writer owns exactly the original challenge, distinct approved-role
	// private key and RootPreparation BODY digest. There is no frame or fourth FD.
	digestBytes, err := hex.DecodeString(bindingSHA)
	if err != nil || len(digestBytes) != 32 {
		return refused("source_registry_refused", err)
	}
	var originalSegments [3]byteReturn
	for index, segment := range []struct {
		operation string
		raw       []byte
		private   bool
	}{{"bootstrap_challenge32_write", c.bootstrapChallenge, false}, {"bootstrap_key64_write", key, true}, {"bootstrap_binding_digest32_write", digestBytes, false}} {
		originalSegments[index], err = writeOwned(write, segment.operation, "host_registrar", "registrar_bootstrap", segment.raw, segment.private)
		if err != nil {
			return err
		}
	}
	_, err = closeOwned(write, "bootstrap_writer_close", "host_registrar", "registrar_bootstrap")
	if err != nil {
		return err
	}
	return controlRegistrarCacheBootstrapWrite(r, l, write, writerSource, originalSegments)
}

func controlRegistrarCacheBootstrapWrite(r *OriginalFactoryRealm, l *originalLedger, writer *callHandle, source model.HostFactoryBootstrapDescriptorSource, segments [3]byteReturn) error {
	body := model.HostFactoryBootstrapWriteReturn{Schema: "original_host_factory_bootstrap_write_return_v4", Purpose: "original_host_factory_bootstrap_write_return_v4", BindingSchema: l.bindingSchema, BindingSHA256: l.bindingSHA, RecipientOwnerID: l.subjects["host_registrar"], WriterPrimitiveRawSHA256: l.primitiveSHA, OriginalWriterSource: source}
	operations := [3]string{"bootstrap_challenge32_write", "bootstrap_key64_write", "bootstrap_binding_digest32_write"}
	expected := [3]int{32, 64, 32}
	for index, operation := range operations {
		actual := segments[index]
		if actual.err != nil || actual.count != int64(expected[index]) || actual.returned.IsZero() {
			return refused("original_write_refused", actual.err)
		}
		vector, err := l.vector(writer, operation, "host_registrar")
		if err != nil {
			return err
		}
		segment := model.HostFactoryBootstrapSegmentReturn{Operation: operation, OwnerPrimitiveRawSHA256: l.primitiveSHA, OriginalHandleID: writer.id, ExpectedBytes: expected[index], OriginalCallVector: vector, OriginalTotalBytes: int(actual.count), OriginalSegmentHashState: "actual_public_bytes", OriginalReturnedAt: actual.returned}
		if index == 1 {
			segment.OriginalSegmentHashState = "private_withheld"
		} else {
			if !capacity.ValidDigest(actual.sha) {
				return refused("original_write_refused", nil)
			}
			segment.OriginalSegmentSHA256 = ptr(actual.sha)
		}
		body.SegmentReturns[index] = segment
	}
	l.mu.Lock()
	rows := append([]*retainedCall(nil), l.calls[writer.id+"\x00bootstrap_writer_close"]...)
	l.mu.Unlock()
	if len(rows) != 1 {
		return refused("original_close_refused", nil)
	}
	closeReturn, err := controlDiagnosticFromOriginal(l, rows[0])
	if err != nil {
		return err
	}
	body.OriginalWriterCloseReturn = closeReturn
	raw, err := capacity.CanonicalHostFactory(body)
	if err != nil || len(raw) > bodyLimit {
		return refused("storage_unknown", err)
	}
	envelope, err := capacity.SignHostFactoryEnvelope(body, "host_exterior", keyIDFor(r.installation, "host_exterior"), l.bindingSchema, l.bindingSHA, r.control.exteriorKey)
	if err != nil || len(envelope) > bodyLimit {
		return refused("role_or_signature_refused", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.records["bootstrap-write-registrar"]) != 0 || len(r.originalBodies["bootstrap-write-registrar"]) != 0 {
		return refused("choice_conflict", nil)
	}
	// Cache this actual producer's one original return. Source9's immutable
	// collection exporter retains the referenced same-ledger chunks unchanged.
	r.records["bootstrap-write-registrar"] = bytes.Clone(envelope)
	r.originalBodies["bootstrap-write-registrar"] = bytes.Clone(raw)
	return nil
}

func controlRegistrarReadKey(ctx context.Context, r *OriginalFactoryRealm) (ed25519.PrivateKey, error) {
	i := r.installation
	expected := i.controlRegistrarKey
	if !fixedBasename(expected.name) || expected.sha != "" || expected.bytes != ed25519.PrivateKeySize || expected.mode != uint32(unix.S_IFREG|0600) || expected.uid != uint32(r.basal.body.Calls[2].OriginalScalar) || expected.gid != uint32(r.basal.body.Calls[3].OriginalScalar) {
		return nil, capacity.ErrHostFactorySourceUnavailable
	}
	read, err := controlReadPolicyArtifact(ctx, r, expected)
	defer clear(read.raw)
	if err != nil || !read.eof || len(read.raw) != ed25519.PrivateKeySize {
		return nil, refused("role_or_signature_refused", err)
	}
	derived := ed25519.NewKeyFromSeed(read.raw[:ed25519.SeedSize])
	defer clear(derived)
	public := derived.Public().(ed25519.PublicKey)
	selected, selectedErr := i.key("host_registrar", keyIDFor(i, "host_registrar"))
	if !bytes.Equal(derived, read.raw) || selectedErr != nil || !bytes.Equal(selected, public) {
		return nil, refused("role_or_signature_refused", selectedErr)
	}
	for _, approved := range i.keys {
		if approved.role != "host_registrar" && bytes.Equal(approved.public, public) {
			// A malformed future catalog cannot relabel the original exterior,
			// issuer or worker key as the independently owned registrar key.
			return nil, refused("role_or_signature_refused", nil)
		}
	}
	return append(ed25519.PrivateKey(nil), read.raw...), nil
}

func controlRegistrarCommand(i fixedInstallation) (*exec.Cmd, error) {
	if !fixedBasename(i.registrarName) || !filepath.IsAbs(i.privateDirectory) || filepath.Clean(i.privateDirectory) != i.privateDirectory || i.registrar.commit != capacity.CurrentGuestCoreSource() || !capacity.ValidDigest(i.registrar.sha) || !capacity.ValidDigest(i.registrar.buildSHA) || i.registrar.bytes < 1 || i.registrar.device == 0 || i.registrar.inode == 0 || len(i.registrar.cmdline) == 0 || i.registrar.cmdline[len(i.registrar.cmdline)-1] != 0 {
		return nil, capacity.ErrHostFactorySourceUnavailable
	}
	parts := bytes.Split(i.registrar.cmdline[:len(i.registrar.cmdline)-1], []byte{0})
	path := filepath.Join(i.privateDirectory, i.registrarName)
	if len(parts) != 2 || string(parts[0]) != path || string(parts[1]) != "--original-host-factory-registrar" {
		return nil, refused("source_registry_refused", nil)
	}
	// No shell, PATH lookup, inherited environment or caller-built arguments.
	// The independent native observation must still join the actual executable
	// device/inode/full bytes/source/build/cmdline before any positive authority.
	return &exec.Cmd{Path: path, Args: []string{string(parts[0]), string(parts[1])}}, nil
}

func controlRegistrarBootstrapPipe(ctx context.Context, l *originalLedger) (read, write *callHandle, source model.HostFactoryBootstrapDescriptorSource, runErr error) {
	if ctx == nil || l == nil || ctx.Err() != nil || l.ownerRole != "host_exterior" || l.bindingSchema != "original_host_factory_root_preparation_v4" {
		return nil, nil, source, refused("source_registry_refused", nil)
	}
	var err error
	read, err = l.handle()
	if err != nil {
		return nil, nil, source, err
	}
	write, err = l.handle()
	if err != nil {
		return read, nil, source, err
	}
	defer func() {
		if runErr != nil {
			for _, endpoint := range []struct {
				handle *callHandle
				op     string
			}{{read, "bootstrap_reader_close"}, {write, "bootstrap_writer_close"}} {
				if endpoint.handle != nil && endpoint.handle.file != nil {
					_, err := closeOwned(endpoint.handle, endpoint.op, "host_registrar", "cleanup")
					runErr = errors.Join(runErr, err)
				}
			}
		}
	}()
	var descriptorErr error
	_, err = read.nativeCall("bootstrap_pipe_create", "host_registrar", "registrar_start", false, model.HostFactoryNativeCallReturn{Kind: "original_os_pipe"}, func() originalNativeResult {
		r, w, err := os.Pipe()
		if err != nil {
			return originalNativeResult{cause: err}
		}
		read.file, write.file = r, w
		var readErr, writeErr error
		read.fd, readErr = originalFileNumber(r)
		write.fd, writeErr = originalFileNumber(w)
		descriptorErr = errors.Join(readErr, writeErr)
		if descriptorErr != nil {
			// os.Pipe itself returned nil. A later descriptor-query failure is
			// separate Source refusal, never rewritten as the Pipe method error.
			return originalNativeResult{}
		}
		return originalNativeResult{descriptors: []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: read.id, OriginalDescriptorNumber: read.fd}, {OriginalHandleID: write.id, OriginalDescriptorNumber: write.fd}}}
	})
	if err != nil || descriptorErr != nil {
		return read, write, source, refused("original_pipe_refused", errors.Join(err, descriptorErr))
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return read, write, source, refused("original_context_refused", nil)
	}
	if err = write.file.SetWriteDeadline(deadline); err != nil {
		return read, write, source, err
	}
	source, err = descriptor(read, "bootstrap_reader", l.primitiveSHA, "host_registrar", "registrar_start", "bootstrap_pipe_create")
	if err != nil || source.Type != "pipe" {
		return read, write, source, refused("native_join_refused", err)
	}
	return read, write, source, nil
}

// PATCH_ONLY. These are SourceAudit calls, never Host native aliases. The
// original request owner and typed protocol gate belong to the caller. No
// helper retries an uncertain publication or gives returned bytes authority.
// Fixed Source-private wrappers. Empty custody is used ONLY after Source9 has
// selected an exact actual known raw getdents CallID under the frozen manifest.
// Empty Source file EOF never becomes native zero/absence or a Host observation.
// Captured Source file read/publication wrappers are assembled exactly once
// from the owning Source-private reader/publisher suppliers.
func controlRegistrarCloseAuditFile(h *callHandle) error {
	if h == nil || h.file == nil || h.ledger == nil {
		return nil
	}
	h.closeOnce.Do(func() {
		h.mu.Lock()
		index := len(h.unclassified)
		h.mu.Unlock()
		err := h.unclassifiedErrorCall("source_file_close", h.ledger.ownerRole, "source_audit", true, h.file.Close)
		h.mu.Lock()
		returned := time.Time{}
		if index < len(h.unclassified) && h.unclassified[index].operation == "source_file_close" {
			returned = h.unclassified[index].returnedAt
		}
		h.mu.Unlock()
		if returned.IsZero() {
			called := time.Now().UTC()
			cause := h.file.Close()
			returned = time.Now().UTC()
			err = errors.Join(err, cause)
			h.mu.Lock()
			h.unclassified = append(h.unclassified, unclassifiedNativeReturn{operation: "source_file_close", ownerID: h.ledger.ownerID, subjectRole: h.ledger.ownerRole, stage: "source_audit", bindingSchema: h.ledger.bindingSchema, bindingSHA: h.ledger.bindingSHA, handleID: h.id, calledAt: called, returnedAt: returned, deadline: h.ledger.deadline, private: true, cause: cause})
			h.mu.Unlock()
		}
		h.mu.Lock()
		h.closeAt, h.closeErr, h.closed = returned, err, true
		h.mu.Unlock()
	})
	return h.closeErr
}

// Readonly Source-private selector. Caller ctx is only a copy/cancellation guard;
// it never chooses an effect bound or installs Source/lease/native authority.
func controlOriginalRegistrarPhaseContext(ctx context.Context, r *OriginalFactoryRealm, phase string) (context.Context, error) {
	if ctx == nil || ctx.Err() != nil || r == nil {
		return nil, capacity.ErrHostFactorySourceUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trustedInstallationLocked() != nil || r.ctx == nil || r.basal == nil {
		return nil, capacity.ErrHostFactorySourceUnavailable
	}
	if phase == "initial" {
		if r.closing || r.ctx.Err() != nil {
			return nil, refused("original_context_refused", nil)
		}
		return r.ctx, nil
	}
	actual := r.nativePhaseContexts[phase]
	if actual == nil || actual.Err() != nil {
		return nil, refused("original_context_refused", nil)
	}
	if phase == "closing" {
		if !r.closing {
			return nil, refused("original_close_refused", nil)
		}
		return actual, nil
	}
	if r.closing || r.awaitingState != "original_committed_return" {
		return nil, refused("original_context_refused", nil)
	}
	bound, ok := actual.Deadline()
	if !ok || bound.After(r.awaitingDeadline) || bound.After(r.lease.OriginalLeaseExpiresAt) {
		return nil, refused("original_context_refused", nil)
	}
	return actual, nil
}

// Lexical Source terminal owner calls this exactly once BEFORE any terminal
// native IO. Source cached effective context/grant/pre bounds only: no caller
// deadline, renewal, observed-at reconstruction or replacement epoch.
func controlCaptureOriginalTerminalContext(r *OriginalFactoryRealm) (context.Context, error) {
	if r == nil {
		return nil, capacity.ErrHostFactorySourceUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trustedInstallationLocked() != nil || r.closing || r.awaitingState != "original_committed_return" || r.nativePhaseContexts["worker"] == nil {
		return nil, capacity.ErrHostFactorySourceUnavailable
	}
	if original := r.nativePhaseContexts["terminal"]; original != nil {
		return nil, refused("storage_unknown", nil)
	}
	parent := r.nativePhaseContexts["worker"]
	if r.installation.entry == "sealed_a0" || r.installation.entry == "sealed_a1" {
		parent = r.nativePhaseContexts["choice"]
	}
	if parent == nil {
		return nil, refused("original_context_refused", nil)
	}
	bound, ok := parent.Deadline()
	if !ok || parent.Err() != nil {
		return nil, refused("original_context_refused", nil)
	}
	for _, cap := range []time.Time{r.awaitingDeadline, r.lease.OriginalLeaseExpiresAt} {
		if cap.IsZero() {
			return nil, refused("original_context_refused", nil)
		}
		if cap.Before(bound) {
			bound = cap
		}
	}
	if r.installation.entry != "sealed_a0" {
		for _, cap := range []time.Time{r.grant.ExpiresAt, r.pre.OriginalDeadline} {
			if cap.IsZero() {
				return nil, refused("original_context_refused", nil)
			}
			if cap.Before(bound) {
				bound = cap
			}
		}
	}
	actual, cancel := context.WithDeadline(parent, bound)
	d, ok := actual.Deadline()
	if !ok || !d.Equal(bound) || actual.Err() != nil {
		cancel()
		return nil, refused("original_context_refused", nil)
	}
	r.nativePhaseContexts["terminal"], r.nativePhaseCancels["terminal"] = actual, cancel
	return actual, nil
}

// Capture the SAME Source-owning cleanup context at the lexical closer entry.
// It never produces positive native records or changes the declared600 origin.
func controlCaptureOriginalClosingContext(ctx context.Context, r *OriginalFactoryRealm) error {
	if r == nil || ctx == nil || ctx.Err() != nil {
		return refused("original_close_refused", nil)
	}
	d, ok := ctx.Deadline()
	if !ok {
		return refused("original_close_refused", nil)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.trustedInstallationLocked() != nil || r.basal == nil || d.After(r.basal.body.OriginalContextDeadline.Add(150*time.Second)) {
		return refused("original_close_refused", nil)
	}
	if r.nativePhaseContexts == nil {
		r.nativePhaseContexts = map[string]context.Context{}
		r.nativePhaseCancels = map[string]context.CancelFunc{}
	}
	if r.nativePhaseContexts["closing"] != nil {
		return refused("storage_unknown", nil)
	}
	r.nativePhaseContexts["closing"] = ctx
	return nil
}
