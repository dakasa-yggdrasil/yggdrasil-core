//go:build linux

package capacityhostfactory

import (
	"errors"
	"os"
	"sync"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"golang.org/x/sys/unix"
)

// A choice is never removed, repaired, replaced or reopened for write. The
// source mutex serializes the prepared handle; O_EXCL arbitrates processes.
type originalChoice struct {
	mu                sync.Mutex
	rootFD            int
	rootIdentity      unix.Stat_t
	attempted         bool
	ledger            *originalLedger
	rootHandle        *callHandle // SAME inherited FD5 original, never reopened/rebound
	sourceRoot        *callHandle
	sourceRootCall    unclassifiedNativeReturn
	ordinaryRootAudit *originalLedger
	sourceReceiptSHA  string // authentic prior worker-leaf BODY, Source-only constructor
}

func (c *originalChoice) validateRoot() error {
	var st unix.Stat_t
	if c == nil || c.rootFD < 0 || c.ledger == nil {
		return refused("source_registry_refused", nil)
	}
	if c.rootHandle != nil {
		if c.rootHandle.fd != c.rootFD || c.rootHandle.file == nil || c.rootHandle.closed || nativeProcessPhase(c.ledger.ctx, c.rootHandle.ledger) != nil {
			return refused("source_registry_refused", nil)
		}
		value, err := c.rootHandle.nativeCall("gate_fstat", "host_worker", "choice_write", false, model.HostFactoryNativeCallReturn{Kind: "unix_fstat", InputDescriptorNumber: ptr(c.rootFD)}, func() originalNativeResult {
			e := unix.Fstat(c.rootFD, &st)
			v := originalNativeResult{cause: e}
			if e == nil {
				v.stat = ptr(nativeStat(st))
			}
			return v
		})
		if err != nil || nativeProcessPhase(c.ledger.ctx, c.rootHandle.ledger, value.calledAt, value.returnedAt) != nil {
			return refused("source_registry_refused", err)
		}
	} else if c.ledger.ownerRole == "factory_ordinary_worker" {
		if c.sourceRoot == nil || c.sourceRoot.file == nil || c.sourceRoot.fd != c.rootFD || c.ordinaryRootAudit == nil || c.ordinaryRootAudit.ctx != c.ledger.ctx {
			return refused("source_registry_refused", nil)
		}
		h, err := c.ordinaryRootAudit.handle()
		if err != nil {
			return err
		}
		h.fd = c.rootFD // borrowed Source method; this handle NEVER owns a Close
		actual, err := ordinaryQMPSourceReturn(c.ordinaryRootAudit.ctx, h, "source_audit_private_fstat", false, false, func() (unclassifiedNativeReturn, error) {
			cause := unix.Fstat(c.rootFD, &st)
			value := unclassifiedNativeReturn{}
			if cause == nil {
				copied := st
				value.stat = &copied
			}
			return value, cause
		})
		if err != nil || nativeProcessPhase(c.ledger.ctx, c.ledger, actual.calledAt, actual.returnedAt) != nil {
			return refused("source_registry_refused", err)
		}
	} else {
		return refused("source_registry_refused", nil)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0777 != 0700 || st.Ino != c.rootIdentity.Ino || st.Dev != c.rootIdentity.Dev || st.Uid != c.rootIdentity.Uid || st.Gid != c.rootIdentity.Gid || st.Nlink != c.rootIdentity.Nlink {
		return refused("source_registry_refused", nil)
	}
	return nil
}

func (c *originalChoice) writeOnce(value any, subject, stage string, ordinary bool) (out model.HostFactoryChoiceReturn, runErr error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var acquired []*callHandle
	defer func() {
		if runErr == nil {
			return
		}
		for index := len(acquired) - 1; index >= 0; index-- {
			h := acquired[index]
			if h != nil && h.file != nil && !h.closed {
				op := choiceOp("gate_file_close", "ordinary_dispatch_close", ordinary)
				if index == 0 {
					op = choiceOp("gate_directory_close", "ordinary_directory_close", ordinary)
				}
				_, cause := closeOwned(h, op, subject, stage)
				runErr = errors.Join(runErr, cause)
			}
		}
	}()
	if c.attempted || c.validateRoot() != nil || !ordinary && (c.ledger.sourceProfile == nil || !capacity.ValidDigest(c.sourceReceiptSHA)) {
		return out, refused("choice_conflict", nil)
	}
	body, err := capacity.CanonicalHostFactory(value)
	if err != nil {
		return out, refused("role_or_signature_refused", err)
	}
	// There is no lawful possible-create Host body. Only the independently
	// credentialed ordinary capsule can call the ordinary branch below.
	switch x := value.(type) {
	case model.HostFactoryUnissuedChoiceBody:
		if ordinary || x.Choice != "sealed_before_possible_create" {
			return out, refused("choice_conflict", nil)
		}
	case model.HostFactoryIssuedChoiceBody:
		if ordinary || x.Choice != "sealed_before_possible_create" {
			return out, refused("choice_conflict", nil)
		}
	case model.FactoryOrdinaryDispatchBody:
		if !ordinary {
			return out, refused("choice_conflict", nil)
		}
	default:
		return out, refused("choice_conflict", nil)
	}
	c.attempted = true // sticky before the first possible O_EXCL effect
	dir, err := c.ledger.handle()
	if err != nil {
		return out, err
	}
	acquired = append(acquired, dir)
	request := model.HostFactoryNativeCallReturn{Kind: "fcntl_dupfd_cloexec", InputDescriptorNumber: ptr(c.rootFD), RequestedFcntlCommand: ptr(unix.F_DUPFD_CLOEXEC), RequestedArgument: ptr(int64(0))}
	if c.rootHandle != nil {
		request.ParentHandleID = ptr(c.rootHandle.id)
	}
	dupReturn, err := dir.nativeCall("gate_directory_duplicate", subject, stage, false, request, func() originalNativeResult {
		fd, cause := unix.FcntlInt(uintptr(c.rootFD), unix.F_DUPFD_CLOEXEC, 0)
		v := originalNativeResult{scalar: ptr(int64(fd)), cause: cause}
		if cause == nil && fd >= 0 {
			dir.fd, dir.file = fd, os.NewFile(uintptr(fd), "original-choice-directory")
			v.descriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: dir.id, OriginalDescriptorNumber: fd}}
		}
		return v
	})
	if err == nil {
		err = nativeProcessPhase(c.ledger.ctx, c.ledger, dupReturn.calledAt, dupReturn.returnedAt)
	}
	if err != nil {
		return out, err
	}
	dirSource, err := descriptor(dir, "gate_directory", c.ledger.primitiveSHA, subject, stage, "gate_directory_duplicate")
	if err != nil {
		_, _ = closeOwned(dir, choiceOp("gate_directory_close", "ordinary_directory_close", ordinary), subject, stage)
		return out, err
	}
	file, err := c.ledger.handle()
	if err != nil {
		_, _ = closeOwned(dir, choiceOp("gate_directory_close", "ordinary_directory_close", ordinary), subject, stage)
		return out, err
	}
	acquired = append(acquired, file)
	flags := unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	opened, err := file.nativeCall(choiceOp("gate_open_exclusive", "ordinary_dispatch_open_exclusive", ordinary), subject, stage, false, model.HostFactoryNativeCallReturn{Kind: "unix_openat", InputDescriptorNumber: ptr(dir.fd), ParentHandleID: ptr(dir.id), RequestedFlags: ptr(uint32(flags)), RequestedMode: ptr(uint32(0600))}, func() originalNativeResult {
		fd, cause := unix.Openat(dir.fd, "creator.choice", flags, 0600)
		v := originalNativeResult{scalar: ptr(int64(fd)), cause: cause}
		if cause == nil && fd >= 0 {
			file.fd, file.file = fd, os.NewFile(uintptr(fd), "original-creator-choice")
			v.descriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: file.id, OriginalDescriptorNumber: fd}}
		}
		return v
	})
	if err == nil {
		err = nativeProcessPhase(c.ledger.ctx, c.ledger, opened.calledAt, opened.returnedAt)
	}
	if err != nil {
		_, ce := closeOwned(dir, choiceOp("gate_directory_close", "ordinary_directory_close", ordinary), subject, stage)
		return out, refused("choice_conflict", errors.Join(err, ce))
	}
	fileSource, err := descriptor(file, "gate_file", c.ledger.primitiveSHA, subject, stage, choiceOp("gate_open_exclusive", "ordinary_dispatch_open_exclusive", ordinary))
	if err != nil {
		_, e1 := closeOwned(file, choiceOp("gate_file_close", "ordinary_dispatch_close", ordinary), subject, stage)
		_, e2 := closeOwned(dir, choiceOp("gate_directory_close", "ordinary_directory_close", ordinary), subject, stage)
		return out, refused("choice_partial", errors.Join(err, e1, e2))
	}
	if fileSource.Type != "regular" || fileSource.Mode&0777 != 0600 || fileSource.LinkCount != 1 {
		_, _ = closeOwned(file, choiceOp("gate_file_close", "ordinary_dispatch_close", ordinary), subject, stage)
		_, _ = closeOwned(dir, choiceOp("gate_directory_close", "ordinary_directory_close", ordinary), subject, stage)
		return out, refused("choice_partial", nil)
	}
	write, writeErr := writeOwned(file, choiceOp("choice_body_write", "ordinary_dispatch_write", ordinary), subject, stage, body, false)
	var syncAt time.Time
	var syncErr error
	if writeErr == nil {
		syncAt, syncErr = nonbyte(file, choiceOp("gate_file_sync", "ordinary_dispatch_sync", ordinary), subject, stage, false, file.file.Sync)
	}
	closeAt, closeErr := closeOwned(file, choiceOp("gate_file_close", "ordinary_dispatch_close", ordinary), subject, stage)
	var dirSyncAt time.Time
	var dirSyncErr error
	if writeErr == nil && syncErr == nil && closeErr == nil {
		dirSyncAt, dirSyncErr = nonbyte(dir, choiceOp("gate_directory_sync", "ordinary_directory_sync", ordinary), subject, stage, false, dir.file.Sync)
	}
	dirCloseAt, dirCloseErr := closeOwned(dir, choiceOp("gate_directory_close", "ordinary_directory_close", ordinary), subject, stage)
	if writeErr != nil || syncErr != nil || closeErr != nil || dirSyncErr != nil || dirCloseErr != nil || write.count != int64(len(body)) || nativeProcessPhase(c.ledger.ctx, c.ledger, write.started, write.returned, syncAt, closeAt, dirSyncAt, dirCloseAt) != nil {
		return out, refused("choice_partial", errors.Join(writeErr, syncErr, closeErr, dirSyncErr, dirCloseErr))
	}
	// Ordinary dispatch is a private non-Host gate record. It deliberately
	// cannot be returned as a signed Host ChoiceReturn/disposition.
	if ordinary {
		return out, nil
	}
	var schema, reservation string
	switch x := value.(type) {
	case model.HostFactoryUnissuedChoiceBody:
		schema = x.Schema
		reservation = x.ChoiceReservationSHA256
	case model.HostFactoryIssuedChoiceBody:
		schema = x.Schema
		reservation = x.ChoiceReservationSHA256
	}
	return model.HostFactoryChoiceReturn{Schema: "original_host_factory_choice_return_v4", Purpose: "original_host_factory_choice_return_v4", ChoiceBodySchema: schema, ChoiceBodySHA256: digest(body), ChoiceReservationSHA256: reservation, ReturnSignerNativeReceiptSHA256: c.sourceReceiptSHA, OriginalGateSource: finalDescriptor(fileSource, c.sourceReceiptSHA), OriginalDirectorySource: finalDescriptor(dirSource, c.sourceReceiptSHA), OriginalWriteStartedAt: write.started, OriginalWriteReturnedAt: write.returned, OriginalWrittenBytes: int(write.count), OriginalWrittenSHA256: write.sha, OriginalFileSyncReturnedAt: syncAt, OriginalFileCloseReturnedAt: closeAt, OriginalDirectorySyncReturnedAt: dirSyncAt, OriginalDirectoryCloseReturnedAt: dirCloseAt}, nil
}
func choiceOp(sealed, ordinary string, yes bool) string {
	if yes {
		return ordinary
	}
	return sealed
}
func finalDescriptor(s model.HostFactoryBootstrapDescriptorSource, nativeSHA string) model.HostFactoryDescriptorSource {
	var acquisition *model.HostFactoryCallVectorReference
	var inherited *string
	if s.OriginalAcquisitionCallVector != nil {
		copy := workerOriginalCloneVector(*s.OriginalAcquisitionCallVector)
		acquisition = &copy
	}
	if s.OriginalInheritedFromHandleID != nil {
		copy := *s.OriginalInheritedFromHandleID
		inherited = &copy
	}
	return model.HostFactoryDescriptorSource{Role: s.Role, OwnerNativeReceiptSHA256: nativeSHA, Device: s.Device, Inode: s.Inode, Type: s.Type, Mode: s.Mode, LinkCount: s.LinkCount, UID: s.UID, GID: s.GID, Flags: s.Flags, OriginalDescriptorNumber: s.OriginalDescriptorNumber, DescriptorFlags: s.DescriptorFlags, OriginalFstatReturnedAt: s.OriginalFstatReturnedAt, OriginalHandleID: s.OriginalHandleID, OriginalAcquisitionCallVector: acquisition, OriginalInheritedFromHandleID: inherited, OriginalFstatCallVector: workerOriginalCloneVector(s.OriginalFstatCallVector), OriginalFstatCallID: s.OriginalFstatCallID, OriginalGetflCallVector: workerOriginalCloneVector(s.OriginalGetflCallVector), OriginalGetflCallID: s.OriginalGetflCallID, OriginalGetfdCallVector: workerOriginalCloneVector(s.OriginalGetfdCallVector), OriginalGetfdCallID: s.OriginalGetfdCallID}
}
