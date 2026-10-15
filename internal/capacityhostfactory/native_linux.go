//go:build linux

package capacityhostfactory

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"golang.org/x/sys/unix"
)

// Existing QEMU qualification ABI projections are kept private here to avoid
// importing capacitynativeqemu (which imports repository). Their facts come
// from this original observer; neither these types nor supplied JSON install a
// factory, a Host role, Guest admission or provider/physical authority.
type ordinaryQMPIO struct {
	Direction  string    `json:"direction"`
	SHA256     string    `json:"sha256"`
	Bytes      int       `json:"bytes"`
	ReturnedAt time.Time `json:"returned_at"`
}
type ordinaryQMPUUID struct {
	UUID string `json:"UUID"`
}
type ordinaryQMPStatus struct {
	Running    bool   `json:"running"`
	SingleStep bool   `json:"singlestep"`
	Status     string `json:"status"`
}
type originalOrdinaryQMP struct {
	ctx                                  context.Context
	connection                           *net.UnixConn
	handle                               *callHandle
	reader                               *bufio.Reader
	peer                                 unix.Ucred
	source                               unix.Stat_t
	rootFD                               int
	started, readReturned, closeReturned time.Time
	io                                   []ordinaryQMPIO
	closeOnce                            sync.Once
	closeErr                             error
	cancelStop                           func() bool
	cancelReturned                       chan struct{}
}

// One owned Source connection. Connect is NEVER retried; ENOENT socket
// appearance observations use this same actual context and original owner.
func openOriginalOrdinaryQMP(ctx context.Context, rootFD, pid int, l *originalLedger) (_ *originalOrdinaryQMP, runErr error) {
	if ordinaryQMPWindow(ctx, l) != nil || rootFD < 0 || pid < 2 {
		return nil, refused("native_join_refused", nil)
	}
	deadline, _ := ctx.Deadline()
	h, e := l.handle()
	if e != nil {
		return nil, e
	}
	q := &originalOrdinaryQMP{ctx: ctx, handle: h, rootFD: rootFD, io: []ordinaryQMPIO{}, cancelReturned: make(chan struct{})}
	defer func() {
		if runErr != nil {
			runErr = errors.Join(runErr, q.closeAndJoin())
		}
	}()
	for {
		actual, se := ordinaryQMPSourceReturn(ctx, h, "source_audit_qmp_source_stat", false, false, func() (unclassifiedNativeReturn, error) {
			var st unix.Stat_t
			e := unix.Fstatat(rootFD, "original-qmp.sock", &st, unix.AT_SYMLINK_NOFOLLOW)
			if e == nil {
				q.source = st
				return unclassifiedNativeReturn{stat: &st}, nil
			}
			return unclassifiedNativeReturn{}, e
		})
		if q.started.IsZero() {
			q.started = actual.calledAt
		}
		if ordinaryQMPWindow(ctx, l, actual.calledAt, actual.returnedAt) != nil {
			return nil, refused("original_context_refused", se)
		}
		if se == nil {
			break
		}
		if !errors.Is(actual.cause, unix.ENOENT) {
			return nil, refused("native_join_refused", se)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, refused("original_context_refused", ctx.Err())
		case <-timer.C:
		}
	}
	if q.source.Mode&unix.S_IFMT != unix.S_IFSOCK || q.source.Ino == 0 {
		return nil, refused("native_join_refused", nil)
	}
	var connection net.Conn
	_, e = ordinaryQMPSourceError(ctx, h, "source_audit_qmp_connect", false, func() error {
		var cause error
		connection, cause = (&net.Dialer{}).DialContext(ctx, "unix", "/proc/self/fd/"+strconv.Itoa(rootFD)+"/original-qmp.sock")
		return cause
	})
	if connection != nil {
		var ok bool
		q.connection, ok = connection.(*net.UnixConn)
		if !ok {
			_, ce := ordinaryQMPSourceError(ctx, h, "source_audit_qmp_close", true, connection.Close)
			return nil, refused("native_join_refused", errors.Join(e, ce))
		}
	}
	if e != nil || q.connection == nil {
		return nil, refused("native_join_refused", e)
	}
	q.cancelStop = context.AfterFunc(ctx, func() { q.closeOriginal(); close(q.cancelReturned) })
	var raw syscall.RawConn
	_, e = ordinaryQMPSourceError(ctx, h, "source_audit_qmp_syscall_conn", false, func() error { var ce error; raw, ce = q.connection.SyscallConn(); return ce })
	if e != nil {
		return nil, refused("native_join_refused", e)
	}
	var nativeErr error
	_, e = ordinaryQMPSourceError(ctx, h, "source_audit_qmp_raw_control", false, func() error {
		return raw.Control(func(fd uintptr) {
			h.fd = int(fd)
			_, nativeErr = ordinaryQMPSourceReturn(ctx, h, "source_audit_qmp_peer", false, false, func() (unclassifiedNativeReturn, error) {
				v, ce := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
				out := unclassifiedNativeReturn{}
				if v != nil {
					copied := *v
					out.ucred = &copied
					if ce == nil {
						q.peer = *v
					}
				}
				return out, ce
			})
		})
	})
	if e != nil || nativeErr != nil || int(q.peer.Pid) != pid {
		return nil, refused("native_join_refused", errors.Join(e, nativeErr))
	}
	_, e = ordinaryQMPSourceError(ctx, h, "source_audit_qmp_deadline", false, func() error { return q.connection.SetDeadline(deadline) })
	if e != nil {
		return nil, e
	}
	q.reader = bufio.NewReaderSize(ordinaryQMPReader{q}, bodyLimit+1)
	return q, nil
}

type ordinaryQMPReader struct{ q *originalOrdinaryQMP }

func (reader ordinaryQMPReader) Read(buffer []byte) (int, error) {
	q := reader.q
	if len(buffer) > bodyLimit+1 {
		buffer = buffer[:bodyLimit+1]
	}
	actual, e := ordinaryQMPSourceReturn(q.ctx, q.handle, "source_audit_qmp_read", false, false, func() (unclassifiedNativeReturn, error) {
		n, ce := q.connection.Read(buffer)
		return unclassifiedNativeReturn{scalarObserved: true, scalar: int64(n), raw: buffer[:n]}, ce
	})
	if !actual.returnedAt.IsZero() {
		q.readReturned = actual.returnedAt
	}
	return int(actual.scalar), e
}
func privateQMPObject(raw []byte) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > bodyLimit || !utf8.Valid(raw) {
		return nil, refused("native_join_refused", nil)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, refused("native_join_refused", err)
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		name, ok := t.(string)
		if err != nil || !ok || out[name] != nil {
			return nil, refused("native_join_refused", err)
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return nil, refused("native_join_refused", err)
		}
		out[name] = bytes.Clone(value)
	}
	if _, err = d.Token(); err != nil {
		return nil, refused("native_join_refused", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, refused("native_join_refused", nil)
	}
	return out, nil
}

func (q *originalOrdinaryQMP) readRow() (map[string]json.RawMessage, error) {
	if len(q.io) >= 64 || ordinaryQMPWindow(q.ctx, q.handle.ledger) != nil {
		return nil, refused("native_join_refused", nil)
	}
	raw, e := q.reader.ReadSlice('\n')
	// A frame projection of the SAME actual source subreads, not another Read.
	if len(raw) > 0 {
		q.io = append(q.io, ordinaryQMPIO{Direction: "read", SHA256: digest(raw), Bytes: len(raw), ReturnedAt: q.readReturned})
	}
	if e != nil || len(raw) > bodyLimit || ordinaryQMPWindow(q.ctx, q.handle.ledger, q.readReturned) != nil {
		return nil, refused("native_join_refused", e)
	}
	return privateQMPObject(raw)
}
func (q *originalOrdinaryQMP) command(operation, id string, target any) error {
	if (operation != "qmp_capabilities" && operation != "query-uuid" && operation != "query-status") || len(q.io) >= 64 {
		return refused("native_join_refused", nil)
	}
	body, e := json.Marshal(struct {
		Execute string `json:"execute"`
		ID      string `json:"id"`
	}{operation, id})
	if e != nil {
		return e
	}
	body = append(body, '\r', '\n')
	actual, e := ordinaryQMPSourceReturn(q.ctx, q.handle, "source_audit_qmp_write", false, false, func() (unclassifiedNativeReturn, error) {
		n, ce := q.connection.Write(body)
		return unclassifiedNativeReturn{scalarObserved: true, scalar: int64(n), raw: body[:n]}, ce
	})
	if actual.scalarObserved {
		q.io = append(q.io, ordinaryQMPIO{Direction: "write", SHA256: digest(actual.raw), Bytes: int(actual.scalar), ReturnedAt: actual.returnedAt})
	}
	if e != nil || actual.scalar != int64(len(body)) {
		return refused("native_join_refused", e)
	}
	for remaining := 32; remaining > 0; remaining-- {
		row, re := q.readRow()
		if re != nil {
			return re
		}
		if row["event"] != nil {
			continue
		}
		var got string
		if len(row) != 2 || row["return"] == nil || json.Unmarshal(row["id"], &got) != nil || got != id {
			return refused("native_join_refused", nil)
		}
		return decodePrivateOriginalJSON(row["return"], target)
	}
	return refused("native_join_refused", nil)
}
func (q *originalOrdinaryQMP) readIdentity() (ordinaryQMPUUID, ordinaryQMPStatus, error) {
	var id ordinaryQMPUUID
	var status ordinaryQMPStatus
	greeting, e := q.readRow()
	if e != nil || len(greeting) != 1 || greeting["QMP"] == nil {
		return id, status, refused("native_join_refused", e)
	}
	var capabilities struct{}
	if e = q.command("qmp_capabilities", "factory-original-capabilities", &capabilities); e == nil {
		e = q.command("query-uuid", "factory-original-uuid", &id)
	}
	if e == nil {
		e = q.command("query-status", "factory-original-status", &status)
	}
	if e != nil || uuidMust(id.UUID) == "" || !status.Running || status.SingleStep || status.Status != "running" {
		return id, status, refused("native_join_refused", e)
	}
	return id, status, nil
}
func (q *originalOrdinaryQMP) closeOriginal() {
	q.closeOnce.Do(func() {
		if q.connection == nil {
			return
		}
		actual, e := ordinaryQMPSourceError(q.ctx, q.handle, "source_audit_qmp_close", true, q.connection.Close)
		q.closeReturned, q.closeErr = actual.returnedAt, e
		q.handle.mu.Lock()
		q.handle.closed = true
		q.handle.mu.Unlock()
	})
}
func (q *originalOrdinaryQMP) closeAndJoin() error {
	if q == nil {
		return nil
	}
	q.closeOriginal()
	if q.cancelStop != nil && !q.cancelStop() {
		<-q.cancelReturned
	}
	return q.closeErr
}

type launchHints struct {
	rootID, ownerID, role, approvalSHA, buildSHA string
	started, deadline                            time.Time
}
type basalOwner struct {
	body   model.HostFactoryBasalOwnerObservation
	raw    []byte
	sha    string
	pin    *os.File
	pinFD  int
	ledger *originalLedger
	self   *callHandle
}

// This is the first actual native producer. No Read, key, bootstrap, NativeLeaf
// or self-digest is used to manufacture the basal observation.
func captureBasalOriginalOwner(h launchHints) (*basalOwner, error) {
	if capacity.CurrentGuestCoreSource() == "" || h.started.IsZero() || h.deadline.Sub(h.started) != 600*time.Second || !h.deadline.After(time.Now()) {
		return nil, refused("source_registry_refused", nil)
	}
	selfID, err := newID()
	if err != nil {
		return nil, err
	}
	b := model.HostFactoryBasalOwnerObservation{Schema: "original_host_factory_basal_owner_observation_v3", Purpose: "original_host_factory_basal_owner_observation_v3", FactoryRootID: h.rootID, OriginalOwnerID: h.ownerID, Role: h.role, SourceApprovalSHA256: h.approvalSHA, ActualBinarySourceCommit: capacity.CurrentGuestCoreSource(), BuildReceiptSHA256: h.buildSHA, OriginalContextStartedAt: h.started.UTC(), OriginalContextDeadline: h.deadline.UTC(), OriginalSelfPIDFDHandleID: selfID}
	var fd int = -1
	var stat unix.Stat_t
	call := func(index int, op string, fn func() (int64, error)) error {
		at := time.Now().UTC()
		v, e := fn()
		ret := time.Now().UTC()
		class := "success"
		if e != nil {
			class = "io_refused"
		}
		b.Calls[index] = model.HostFactoryBasalCallReturn{Operation: op, OriginalCalledAt: at, OriginalReturnedAt: ret, OriginalScalar: v, OriginalReturnClass: class}
		return e
	}
	_ = call(0, "getpid", func() (int64, error) { return int64(unix.Getpid()), nil })
	_ = call(1, "getppid", func() (int64, error) { return int64(unix.Getppid()), nil })
	_ = call(2, "getuid", func() (int64, error) { return int64(unix.Getuid()), nil })
	_ = call(3, "getgid", func() (int64, error) { return int64(unix.Getgid()), nil })
	if err = call(4, "pidfd_open_self", func() (int64, error) {
		var e error
		fd, e = unix.PidfdOpen(int(b.Calls[0].OriginalScalar), 0)
		return int64(fd), e
	}); err != nil {
		return nil, refused("original_pin_refused", err)
	}
	// Close is owned immediately, including a partial first-root refusal. Such
	// a failure is not a positive basal body and has no invented owner hash.
	failure := func(e error) (*basalOwner, error) {
		closeErr := unix.Close(fd)
		return nil, refused("original_pin_refused", errors.Join(e, closeErr))
	}
	if err = call(5, "fstat_self_pidfd", func() (int64, error) {
		e := unix.Fstat(fd, &stat)
		if e != nil {
			return -1, e
		}
		return 0, nil
	}); err != nil {
		return failure(err)
	}
	if err = call(6, "fcntl_getfl_self_pidfd", func() (int64, error) { n, e := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); return int64(n), e }); err != nil {
		return failure(err)
	}
	if err = call(7, "fcntl_getfd_self_pidfd", func() (int64, error) { n, e := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); return int64(n), e }); err != nil {
		return failure(err)
	}
	b.OriginalSelfPIDFDSource = model.HostFactoryBasalDescriptorSource{Role: "basal_self_pidfd", Device: uint64(stat.Dev), Inode: stat.Ino, Type: "pidfd", Mode: stat.Mode, LinkCount: uint64(stat.Nlink), UID: stat.Uid, GID: stat.Gid, Flags: uint32(b.Calls[6].OriginalScalar), OriginalDescriptorNumber: fd, DescriptorFlags: uint32(b.Calls[7].OriginalScalar), OriginalFstatReturnedAt: b.Calls[5].OriginalReturnedAt}
	raw, err := capacity.CanonicalHostFactory(b)
	if err != nil {
		return failure(err)
	}
	return &basalOwner{body: b, raw: raw, sha: digest(raw), pin: os.NewFile(uintptr(fd), "original-self-pidfd"), pinFD: fd}, nil
}

func (b *basalOwner) bind(ctx context.Context, schema, sha string) error {
	if b == nil || b.pin == nil || b.ledger != nil {
		return refused("native_join_refused", nil)
	}
	l, err := newLedger(ctx, b.body.OriginalOwnerID, b.body.Role, b.sha, schema, sha)
	if err != nil {
		return err
	}
	b.ledger = l
	b.self = &callHandle{id: b.body.OriginalSelfPIDFDHandleID, file: b.pin, fd: b.pinFD, ledger: l}
	// The basal-eight owner already reserved and acquired this exact PIDFD.
	// Register that SAME handle before later native calls/Close; its ID, FD,
	// basal ordinal history and ownership are never recaptured or replaced.
	l.mu.Lock()
	if prior := l.handles[b.self.id]; prior != nil {
		l.mu.Unlock()
		return refused("native_join_refused", nil)
	}
	l.handles[b.self.id] = b.self
	l.handleOrder = append(l.handleOrder, b.self)
	l.mu.Unlock()
	return nil
}
func (b *basalOwner) close() error {
	if b == nil || b.pin == nil {
		return nil
	}
	if b.self == nil {
		err := b.pin.Close()
		b.pin = nil
		if err != nil {
			return refused("original_close_refused", err)
		}
		return nil
	}
	_, err := closeOwned(b.self, "basal_self_pidfd_close", b.body.Role, "cleanup")
	b.pin = nil
	return err
}

type originalPin struct {
	handle      *callHandle
	pid         int
	startTicks  uint64
	source      model.HostFactoryBootstrapDescriptorSource
	exitPoll    *retainedCall // SAME sole child-join Poll reservation; no latest-call lookup
	acquisition *retainedCall // actual original pidfd_open reservation, never newest lookup
}

func pinOriginalSubject(l *originalLedger, pid int, role, stage, operation string) (*originalPin, error) {
	if pid < 1 {
		return nil, refused("original_pin_refused", nil)
	}
	h, err := l.handle()
	if err != nil {
		return nil, err
	}
	pin := &originalPin{handle: h, pid: pid}
	value, err := h.nativeCall(operation, role, stage, false, model.HostFactoryNativeCallReturn{Kind: "unix_pidfd_open", RequestedFlags: ptr(uint32(0)), RequestedPID: ptr(pid)}, func() originalNativeResult {
		fd, e := unix.PidfdOpen(pid, 0)
		v := originalNativeResult{scalar: ptr(int64(fd)), cause: e}
		if e == nil && fd >= 0 {
			h.fd, h.file = fd, os.NewFile(uintptr(fd), "original-subject-pidfd")
			v.descriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: h.id, OriginalDescriptorNumber: fd}}
		}
		return v
	})
	pin.acquisition = value.call
	if err != nil {
		if h.file != nil {
			_, closeErr := closeOwned(h, choiceOp("worker_pidfd_close", "registrar_pidfd_close", role == "host_registrar"), role, "cleanup")
			err = errors.Join(err, closeErr)
		}
		return pin, err
	}
	pin.source, err = descriptor(h, "exterior_worker_pidfd", l.primitiveSHA, role, stage, operation)
	if err != nil {
		_, e := closeOwned(h, choiceOp("worker_pidfd_close", "registrar_pidfd_close", role == "host_registrar"), role, "cleanup")
		return pin, errors.Join(err, e)
	}
	return pin, nil
}

func (p *originalPin) alive() error {
	if p == nil || p.handle == nil || p.handle.closed {
		return refused("alive_owner_refused", nil)
	}
	// Requested POLLIN is not the returned mask. Readiness here is refusal:
	// the expected original subject must still be alive.
	fds := []unix.PollFd{{Fd: int32(p.handle.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil || n != 0 || fds[0].Revents != 0 {
		return refused("alive_owner_refused", err)
	}
	return nil
}

func (p *originalPin) pollAndClose(operation, closeOperation, subject, stage string) (int, time.Time, time.Time, error) {
	if p == nil || p.handle == nil {
		return 0, time.Time{}, time.Time{}, refused("original_pin_refused", nil)
	}
	value, err := p.handle.nativeCall(operation, subject, stage, true, model.HostFactoryNativeCallReturn{Kind: "unix_poll", InputDescriptorNumber: ptr(p.handle.fd), RequestedFlags: ptr(uint32(unix.POLLIN)), RequestedArgument: ptr(int64(0))}, func() originalNativeResult {
		fds := []unix.PollFd{{Fd: int32(p.handle.fd), Events: unix.POLLIN}}
		n, e := unix.Poll(fds, 0)
		return originalNativeResult{scalar: ptr(int64(n)), revents: ptr(uint32(uint16(fds[0].Revents))), cause: e}
	})
	p.exitPoll = value.call
	revents := 0
	if value.revents != nil {
		revents = int(*value.revents)
	}
	var policyErr error
	if value.scalar == nil || *value.scalar != 1 || (revents != int(unix.POLLIN) && revents != int(unix.POLLIN|unix.POLLHUP)) {
		policyErr = refused("original_pin_refused", nil)
	}
	closed, closeErr := closeOwned(p.handle, closeOperation, subject, stage)
	return revents, value.returnedAt, closed, errors.Join(err, policyErr, closeErr)
}

func readNativeFile(l *originalLedger, path, operation, subject, stage string, limit int64, magic bool) ([]byte, model.HostFactoryOriginalIOFact, error) {
	data, fact, _, err := readNativeFileWithSource(l, path, operation, subject, stage, limit, magic)
	return data, fact, err
}

func readNativeFileWithSource(l *originalLedger, path, operation, subject, stage string, limit int64, magic bool) ([]byte, model.HostFactoryOriginalIOFact, unix.Stat_t, error) {
	flags := unix.O_RDONLY
	if !magic {
		flags |= unix.O_NOFOLLOW
	}
	h, stat, err := acquireFile(l, path, subject, stage, "native_reader_open", "native_reader_fstat", flags)
	if err != nil {
		var closed error
		if h != nil && h.file != nil {
			_, closed = closeOwned(h, "native_reader_close", subject, "cleanup")
		}
		return nil, model.HostFactoryOriginalIOFact{}, unix.Stat_t{}, errors.Join(err, closed)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_, closed := closeOwned(h, "native_reader_close", subject, "cleanup")
		return nil, model.HostFactoryOriginalIOFact{}, *stat, refused("native_join_refused", closed)
	}
	data, r := readOwned(h, operation, subject, stage, limit, false, -1)
	// The executable/source identity belongs to this acquired original FD.
	// No fresh pathname Stat after Close substitutes a different file's facts.
	after, statErr := fstatNative(h, "native_reader_fstat", subject, stage)
	unchanged := sameOriginalFileStat(*stat, after)
	closeAt, closeErr := closeOwned(h, "native_reader_close", subject, stage)
	reads, e := l.vector(h, operation, subject)
	closes, e2 := l.vector(h, "native_reader_close", subject)
	fact := model.HostFactoryOriginalIOFact{Operation: operation, OriginalHandleID: h.id, OwnerPrimitiveRawSHA256: l.primitiveSHA, OriginalCalledAt: r.started, OriginalReturnedAt: r.returned, OriginalCount: r.count, OriginalSHA256: r.sha, OriginalReturnClass: "eof", OriginalCloseReturnedAt: closeAt, SubjectOwnerID: l.subjects[subject], OriginalOperationDeadline: l.deadline, OriginalEOF: r.eof, OriginalCallVector: reads, OriginalCloseCallVector: closes}
	if r.err != nil || !r.eof || r.count > limit || statErr != nil || !unchanged || closeErr != nil || e != nil || e2 != nil {
		return data, fact, *stat, refused("native_join_refused", errors.Join(r.err, statErr, closeErr, e, e2))
	}
	return data, fact, *stat, nil
}

func sameOriginalFileStat(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode && before.Nlink == after.Nlink && before.Uid == after.Uid && before.Gid == after.Gid && before.Size == after.Size && before.Mtim == after.Mtim && before.Ctim == after.Ctim
}

type procStat struct {
	pid, ppid int
	ticks     uint64
}

func parseProcStat(raw []byte) (procStat, error) {
	end := bytes.LastIndexByte(raw, ')')
	begin := bytes.IndexByte(raw, '(')
	if begin < 2 || end < begin || len(raw) > bodyLimit {
		return procStat{}, refused("native_join_refused", nil)
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(raw[:begin])))
	f := strings.Fields(string(raw[end+1:]))
	if e != nil || pid < 1 || len(f) < 20 {
		return procStat{}, refused("native_join_refused", e)
	}
	ppid, e := strconv.Atoi(f[1])
	if e != nil || ppid < 1 {
		return procStat{}, refused("native_join_refused", e)
	}
	ticks, e := strconv.ParseUint(f[19], 10, 64)
	if e != nil || ticks == 0 {
		return procStat{}, refused("native_join_refused", e)
	}
	return procStat{pid, ppid, ticks}, nil
}

func nativeProcessPhase(ctx context.Context, l *originalLedger, actual ...time.Time) error {
	if ctx == nil || l == nil || l.ctx == nil || ctx.Err() != nil || l.ctx.Err() != nil {
		return refused("original_context_refused", nil)
	}
	d, ok := ctx.Deadline()
	if !ok || d.After(l.deadline) || !time.Now().Before(d) || !time.Now().Before(l.deadline) {
		return refused("original_context_refused", nil)
	}
	for _, at := range actual {
		if at.IsZero() || at.After(d) || at.After(l.deadline) {
			return refused("original_context_refused", nil)
		}
	}
	return nil
}

// Checks the pointer returned by THIS reserved native call. It never chooses a
// latest row, supplies native facts or reconstructs a successful return.
func nativeProcessOriginalCall(h *callHandle, actual *retainedCall, operation string) error {
	if h == nil || h.ledger == nil || actual == nil {
		return refused("storage_unknown", nil)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	l := h.ledger
	l.mu.Lock()
	defer l.mu.Unlock()
	if actual.fact.Operation != operation || actual.fact.OriginalHandleID != h.id || actual.fact.OriginalState != "returned" || actual.fact.OriginalCallID == nil || actual.fact.OriginalCalledAt == nil || actual.fact.OriginalReturnedAt == nil || actual.fact.OriginalCalledAt.IsZero() || actual.fact.OriginalReturnedAt.IsZero() || actual.fact.OriginalReturnedAt.Before(*actual.fact.OriginalCalledAt) {
		return refused("storage_unknown", nil)
	}
	for _, row := range l.calls[h.id+"\x00"+operation] {
		if row == actual {
			return nil
		}
	}
	return refused("storage_unknown", nil)
}

// Inline original File.Read owner; each actual read is guarded before and
// after return. Regular/proc reads are not claimed cancelable. A late pending
// method must actually return and stays HOLD, with every original subreturn.
func nativeProcessReadBytes(ctx context.Context, h *callHandle, operation, subject, stage string, limit int64) (data []byte, r byteReturn) {
	hash := sha256.New()
	buffer := make([]byte, 65536)
	for {
		if e := nativeProcessPhase(ctx, h.ledger); e != nil {
			r.err = e
			break
		}
		remaining := limit + 1 - r.count
		if remaining <= 0 {
			r.err = refused("original_pipe_refused", nil)
			break
		}
		if remaining < int64(len(buffer)) {
			buffer = buffer[:remaining]
		}
		call, e := h.begin(operation, subject, stage, false)
		if e != nil {
			r.err = e
			break
		}
		if r.started.IsZero() {
			r.started = *call.fact.OriginalCalledAt
		}
		n, cause := h.file.Read(buffer)
		returned := time.Now().UTC()
		r.returned = returned
		r.eof = cause == io.EOF // literal owning return, independent of later admission guard
		class := "success"
		if cause == io.EOF {
			class = "eof"
		} else if cause != nil {
			class = "io_refused"
		} else if n == 0 {
			class = "partial"
		}
		h.finishOriginal(call, returned, ptr(int64(n)), ptr(digest(buffer[:n])), "actual_public_bytes", class, ptr(cause == io.EOF), nil, cause)
		if n > 0 {
			_, _ = hash.Write(buffer[:n])
			r.count += int64(n)
			if limit <= bodyLimit {
				data = append(data, buffer[:n]...)
			}
		}
		if e = nativeProcessPhase(ctx, h.ledger, *call.fact.OriginalCalledAt, returned); e != nil {
			r.err = e
			break
		}
		if r.count > limit {
			r.err = refused("original_pipe_refused", nil)
			break
		}
		if cause != nil {
			r.eof = cause == io.EOF
			if !r.eof {
				r.err = refused("original_pipe_refused", cause)
			}
			break
		}
		if n == 0 {
			r.err = refused("original_pipe_refused", io.ErrNoProgress)
			break
		}
	}
	if !r.started.IsZero() {
		r.sha = hex.EncodeToString(hash.Sum(nil))
	}
	return data, r
}

// Each original Open/Fstat is separately guarded; a preceding successful
// Open is not permission to issue Fstat after the phase has expired.
func nativeProcessAcquire(ctx context.Context, l *originalLedger, path, subject, stage, openOperation, fstatOperation string, flags int) (h *callHandle, stat *unix.Stat_t, opened, fstated *retainedCall, runErr error) {
	if e := nativeProcessPhase(ctx, l); e != nil {
		return nil, nil, nil, nil, e
	}
	h, e := l.handle()
	if e != nil {
		return nil, nil, nil, nil, e
	}
	flags |= unix.O_CLOEXEC | unix.O_NONBLOCK
	value, e := h.nativeCall(openOperation, subject, stage, false, model.HostFactoryNativeCallReturn{Kind: "unix_open", RequestedFlags: ptr(uint32(flags)), RequestedMode: ptr(uint32(0))}, func() originalNativeResult {
		fd, cause := unix.Open(path, flags, 0)
		result := originalNativeResult{scalar: ptr(int64(fd)), cause: cause}
		if cause == nil && fd >= 0 {
			h.fd, h.file = fd, os.NewFile(uintptr(fd), "original-native-source")
			result.descriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: h.id, OriginalDescriptorNumber: fd}}
		}
		return result
	})
	if e != nil || nativeProcessPhase(ctx, l, value.calledAt, value.returnedAt) != nil {
		return h, nil, value.call, nil, refused("native_join_refused", e)
	}
	st, actualStat, e := nativeProcessFstat(ctx, h, fstatOperation, subject, stage)
	if e != nil {
		return h, nil, value.call, actualStat.call, e
	}
	return h, &st, value.call, actualStat.call, nil
}
func nativeProcessFstat(ctx context.Context, h *callHandle, operation, subject, stage string) (stat unix.Stat_t, value originalNativeResult, runErr error) {
	if h == nil || nativeProcessPhase(ctx, h.ledger) != nil {
		return stat, value, refused("original_context_refused", nil)
	}
	value, e := h.nativeCall(operation, subject, stage, false, model.HostFactoryNativeCallReturn{Kind: "unix_fstat", InputDescriptorNumber: ptr(h.fd)}, func() originalNativeResult {
		cause := unix.Fstat(h.fd, &stat)
		result := originalNativeResult{cause: cause}
		if cause == nil {
			result.stat = ptr(nativeStat(stat))
		}
		return result
	})
	if e != nil || nativeProcessPhase(ctx, h.ledger, value.calledAt, value.returnedAt) != nil {
		return stat, value, refused("native_join_refused", e)
	}
	return stat, value, nil
}

func nativeProcessReadFile(ctx context.Context, l *originalLedger, path, operation, subject, stage string, limit int64, magic bool) (data []byte, fact model.HostFactoryOriginalIOFact, held model.HostFactoryHeldExecutableRead, runErr error) {
	if e := nativeProcessPhase(ctx, l); e != nil {
		return nil, fact, held, e
	}
	flags := unix.O_RDONLY
	if !magic {
		flags |= unix.O_NOFOLLOW
	}
	h, stat, _, before, e := nativeProcessAcquire(ctx, l, path, subject, stage, "native_reader_open", "native_reader_fstat", flags)
	if h != nil && h.file != nil {
		defer func() {
			if !h.closed {
				_, cause := closeOwned(h, "native_reader_close", subject, "cleanup")
				runErr = errors.Join(runErr, cause)
			}
		}()
	}
	if e != nil || stat == nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fact, held, refused("native_join_refused", e)
	}
	if nativeProcessOriginalCall(h, before, "native_reader_fstat") != nil || nativeProcessPhase(ctx, l, *before.fact.OriginalCalledAt, *before.fact.OriginalReturnedAt) != nil {
		return nil, fact, held, refused("native_join_refused", e)
	}
	data, r := nativeProcessReadBytes(ctx, h, operation, subject, stage, limit)
	// Close this same original FD even when the original Read was partial/late.
	var afterStat unix.Stat_t
	var after *retainedCall
	if r.err == nil && nativeProcessPhase(ctx, l) == nil {
		var actualStat originalNativeResult
		afterStat, actualStat, e = nativeProcessFstat(ctx, h, "native_reader_fstat", subject, stage)
		after = actualStat.call
	}
	closeAt, closeErr := closeOwned(h, "native_reader_close", subject, stage)
	reads, e1 := l.vector(h, operation, subject)
	closes, e2 := l.vector(h, "native_reader_close", subject)
	returnClass := "partial"
	if r.eof {
		returnClass = "eof"
	}
	fact = model.HostFactoryOriginalIOFact{Operation: operation, OriginalHandleID: h.id, OwnerPrimitiveRawSHA256: l.primitiveSHA, OriginalCalledAt: r.started, OriginalReturnedAt: r.returned, OriginalCount: r.count, OriginalSHA256: r.sha, OriginalReturnClass: returnClass, OriginalCloseReturnedAt: closeAt, SubjectOwnerID: l.subjects[subject], OriginalOperationDeadline: l.deadline, OriginalEOF: r.eof, OriginalCallVector: reads, OriginalCloseCallVector: closes}
	if r.err != nil || !r.eof || r.count > limit || e != nil || nativeProcessOriginalCall(h, after, "native_reader_fstat") != nil || !sameOriginalFileStat(*stat, afterStat) || closeErr != nil || errors.Join(e1, e2) != nil || nativeProcessPhase(ctx, l, r.started, r.returned, closeAt) != nil {
		return data, fact, held, refused("native_join_refused", errors.Join(r.err, e, closeErr, e1, e2))
	}
	if magic {
		open, e3 := l.vector(h, "native_reader_open", subject)
		stats, e4 := l.vector(h, "native_reader_fstat", subject)
		if errors.Join(e3, e4) != nil {
			return data, fact, held, refused("storage_unknown", errors.Join(e3, e4))
		}
		held = model.HostFactoryHeldExecutableRead{OriginalHandleID: h.id, OwnerPrimitiveRawSHA256: l.primitiveSHA, SubjectOwnerID: l.subjects[subject], OriginalDescriptorNumber: h.fd, OriginalBeforeStat: nativeStat(*stat), OriginalAfterStat: nativeStat(afterStat), OriginalOpenCallVector: open, OriginalFstatCallVector: stats, OriginalBeforeFstatCallID: *before.fact.OriginalCallID, OriginalAfterFstatCallID: *after.fact.OriginalCallID, OriginalRead: fact}
	}
	return data, fact, held, nil
}

func nativeProcessOwnerRead(ctx context.Context, l *originalLedger, path, subject, stage, boot string, pid int, ticks uint64) (out model.HostFactoryProcessOwnerRead, runErr error) {
	if e := nativeProcessPhase(ctx, l); e != nil {
		return out, e
	}
	h, stat, opened, fstated, e := nativeProcessAcquire(ctx, l, path, subject, stage, "proc_owner_directory_open", "proc_owner_directory_fstat", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW)
	if h != nil && h.file != nil {
		defer func() {
			if !h.closed {
				_, cause := closeOwned(h, "proc_owner_directory_close", subject, "cleanup")
				runErr = errors.Join(runErr, cause)
			}
		}()
	}
	if e != nil || stat == nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return out, refused("native_join_refused", e)
	}
	var e1, e2 error
	if nativeProcessOriginalCall(h, opened, "proc_owner_directory_open") != nil {
		e1 = refused("storage_unknown", nil)
	}
	if nativeProcessOriginalCall(h, fstated, "proc_owner_directory_fstat") != nil {
		e2 = refused("storage_unknown", nil)
	}
	closeAt, closeErr := closeOwned(h, "proc_owner_directory_close", subject, stage)
	opens, e3 := l.vector(h, "proc_owner_directory_open", subject)
	stats, e4 := l.vector(h, "proc_owner_directory_fstat", subject)
	closes, e5 := l.vector(h, "proc_owner_directory_close", subject)
	if errors.Join(e1, e2, e3, e4, e5, closeErr) != nil {
		return out, refused("native_join_refused", errors.Join(e1, e2, e3, e4, e5, closeErr))
	}
	out = model.HostFactoryProcessOwnerRead{SubjectOwnerID: l.subjects[subject], SubjectBootID: boot, SubjectPID: pid, SubjectStartTicks: ticks, OriginalHandleID: h.id, OwnerPrimitiveRawSHA256: l.primitiveSHA, OriginalDescriptorNumber: h.fd, OriginalStat: nativeStat(*stat), OriginalOpenCallVector: opens, OriginalFstatCallVector: stats, OriginalCloseCallVector: closes, OriginalCalledAt: *opened.fact.OriginalCalledAt, OriginalReturnedAt: *fstated.fact.OriginalReturnedAt, OriginalCloseReturnedAt: closeAt}
	return out, nativeProcessPhase(ctx, l, out.OriginalCalledAt, out.OriginalReturnedAt, out.OriginalCloseReturnedAt)
}

func nativeProcessPinPoll(ctx context.Context, l *originalLedger, pin *originalPin, subject, stage string) (originalNativeResult, error) {
	if pin == nil || pin.handle == nil || pin.handle.ledger != l || pin.handle.closed || nativeProcessPhase(ctx, l) != nil {
		return originalNativeResult{}, refused("native_join_refused", nil)
	}
	value, e := pin.handle.nativeCall("native_subject_alive_poll", subject, stage, false, model.HostFactoryNativeCallReturn{Kind: "unix_poll", InputDescriptorNumber: ptr(pin.handle.fd), RequestedFlags: ptr(uint32(unix.POLLIN)), RequestedArgument: ptr(int64(0))}, func() originalNativeResult {
		descriptors := []unix.PollFd{{Fd: int32(pin.handle.fd), Events: unix.POLLIN}}
		n, cause := unix.Poll(descriptors, 0)
		return originalNativeResult{scalar: ptr(int64(n)), revents: ptr(uint32(uint16(descriptors[0].Revents))), cause: cause}
	})
	if e != nil || value.call == nil || value.scalar == nil || *value.scalar != 0 || value.revents == nil || *value.revents != 0 || nativeProcessPhase(ctx, l, value.calledAt, value.returnedAt) != nil {
		return value, refused("alive_owner_refused", e)
	}
	return value, nil
}

// Kept as a lexical legacy entry point. Native phase producers must call the
// Context variant with their actual captured phase context, never a date label.
func readOriginalNativeSubject(l *originalLedger, pin *originalPin, subject string, subjectBasal model.HostFactoryBasalOwnerObservation, bootstrapSHA, processNonceSHA string, expected executableApproval, stage string) (model.HostFactoryNativeProcess, error) {
	if l == nil {
		return model.HostFactoryNativeProcess{}, refused("native_join_refused", nil)
	}
	return readOriginalNativeSubjectContext(l.ctx, l, pin, subject, subjectBasal, bootstrapSHA, processNonceSHA, expected, stage)
}

func readOriginalNativeSubjectContext(ctx context.Context, l *originalLedger, pin *originalPin, subject string, subjectBasal model.HostFactoryBasalOwnerObservation, bootstrapSHA, processNonceSHA string, expected executableApproval, stage string) (out model.HostFactoryNativeProcess, runErr error) {
	if l == nil || pin == nil || pin.handle == nil || pin.handle.ledger != l || subjectBasal.OriginalOwnerID != l.subjects[subject] || subjectBasal.Calls[0].OriginalScalar != int64(pin.pid) || !capacity.ValidDigest(bootstrapSHA) || !capacity.ValidDigest(processNonceSHA) || nativeProcessPhase(ctx, l) != nil {
		return out, refused("native_join_refused", nil)
	}
	beforePoll, e := nativeProcessPinPoll(ctx, l, pin, subject, stage)
	if e != nil {
		return out, e
	}
	pinStat, _, e := nativeProcessFstat(ctx, pin.handle, "native_subject_pidfd_fstat", subject, stage)
	if e != nil || nativeProcessPhase(ctx, l) != nil {
		return out, refused("native_join_refused", e)
	}
	base := "/proc/" + strconv.Itoa(pin.pid)
	boot, f0, _, e := nativeProcessReadFile(ctx, l, "/proc/sys/kernel/random/boot_id", "boot_id_read", subject, stage, bodyLimit, false)
	if e != nil {
		return out, e
	}
	before, f1, _, e := nativeProcessReadFile(ctx, l, base+"/stat", "stat_before_read", subject, stage, bodyLimit, false)
	if e != nil {
		return out, e
	}
	statBefore, e := parseProcStat(before)
	if e != nil || statBefore.pid != pin.pid {
		return out, refused("native_join_refused", e)
	}
	_, f2, held, e := nativeProcessReadFile(ctx, l, base+"/exe", "executable_read", subject, stage, 134217728, true)
	if e != nil {
		return out, e
	}
	cmdline, f3, _, e := nativeProcessReadFile(ctx, l, base+"/cmdline", "cmdline_read", subject, stage, bodyLimit, false)
	if e != nil {
		return out, e
	}
	bootID := strings.TrimSpace(string(boot))
	if _, e = uuidParseExact(bootID); e != nil {
		return out, e
	}
	owner, e := nativeProcessOwnerRead(ctx, l, base, subject, stage, bootID, pin.pid, statBefore.ticks)
	if e != nil {
		return out, e
	}
	after, f4, _, e := nativeProcessReadFile(ctx, l, base+"/stat", "stat_after_read", subject, stage, bodyLimit, false)
	if e != nil {
		return out, e
	}
	statAfter, e := parseProcStat(after)
	if e != nil || statBefore != statAfter || pin.startTicks != 0 && pin.startTicks != statBefore.ticks {
		return out, refused("native_join_refused", e)
	}
	afterPoll, e := nativeProcessPinPoll(ctx, l, pin, subject, stage)
	if e != nil {
		return out, e
	}
	if f2.OriginalSHA256 != expected.sha || f2.OriginalCount != expected.bytes || !bytes.Equal(cmdline, expected.cmdline) || held.OriginalBeforeStat.Inode != expected.inode || held.OriginalBeforeStat.Device != expected.device {
		return out, refused("source_registry_refused", nil)
	}
	polls, e1 := l.vector(pin.handle, "native_subject_alive_poll", subject)
	fstats, e2 := l.vector(pin.handle, "native_subject_pidfd_fstat", subject)
	if errors.Join(e1, e2) != nil {
		return out, refused("storage_unknown", errors.Join(e1, e2))
	}
	pinProof := model.HostFactoryNativeSubjectPin{OriginalHandleID: pin.handle.id, ObserverOwnerID: l.ownerID, ObserverPrimitiveRawSHA256: l.primitiveSHA, SubjectOwnerID: subjectBasal.OriginalOwnerID, SubjectBootID: bootID, SubjectPID: pin.pid, SubjectStartTicks: statBefore.ticks, OriginalDescriptorNumber: pin.handle.fd, OriginalStat: nativeStat(pinStat), OriginalFstatCallVector: fstats, OriginalAlivePollCallVector: polls, OriginalBeforePollCallID: *beforePoll.call.fact.OriginalCallID, OriginalAfterPollCallID: *afterPoll.call.fact.OriginalCallID, OriginalObservedAt: afterPoll.returnedAt}
	if l.ownerID == subjectBasal.OriginalOwnerID && pin.handle.id == subjectBasal.OriginalSelfPIDFDHandleID {
		pinProof.OriginalBasalSelfPIDFDSourceSHA256 = ptr(l.primitiveSHA)
	} else {
		if pin.source.OriginalAcquisitionCallVector == nil || pin.source.OriginalHandleID != pin.handle.id || pin.source.OriginalDescriptorNumber != pin.handle.fd {
			return out, refused("storage_unknown", nil)
		}
		actual := *pin.source.OriginalAcquisitionCallVector
		pinProof.OriginalOpenCallVector = &actual
	}
	snapshot, e := publishOriginalLedgerInventories(ctx, l)
	if e != nil || snapshot == nil || !snapshot.graphConsistent {
		return out, refused("storage_unknown", e)
	}
	inventories := []string{}
	byHandle := map[string]string{}
	for _, h := range snapshot.handles {
		if h.inventorySHA256 != "" {
			byHandle[h.handleID] = h.inventorySHA256
			inventories = append(inventories, h.inventorySHA256)
		}
	}
	held.OriginalHandleInventorySHA256 = byHandle[held.OriginalHandleID]
	owner.OriginalHandleInventorySHA256 = byHandle[owner.OriginalHandleID]
	pinProof.OriginalHandleInventorySHA256 = byHandle[pinProof.OriginalHandleID]
	execution := model.HostFactoryBinaryExecution{ExecutionClass: "linux_owned_binary_subprocess_v1", ScriptMode: "none_compiled_binary", BuildReceiptSHA256: expected.buildSHA, ActualBinarySourceCommit: expected.commit, ExecutableSHA256: f2.OriginalSHA256, ExecutableDevice: held.OriginalBeforeStat.Device, ExecutableInode: held.OriginalBeforeStat.Inode, ExecutableLinkCount: held.OriginalBeforeStat.LinkCount, ExecutableUID: held.OriginalBeforeStat.UID, ExecutableGID: held.OriginalBeforeStat.GID, ExecutableMode: held.OriginalBeforeStat.Mode, FixedArgvSHA256: digest(expected.cmdline), OriginalCmdlineReadSHA256: f3.OriginalSHA256, OriginalExecutableReadStartedAt: f2.OriginalCalledAt, OriginalExecutableReadBytes: int(f2.OriginalCount), OriginalExecutableReadReturnedAt: f2.OriginalReturnedAt, OriginalExecutableCloseReturnedAt: f2.OriginalCloseReturnedAt, OriginalCmdlineReadBytes: int(f3.OriginalCount), OriginalCmdlineReadReturnedAt: f3.OriginalReturnedAt, OriginalCmdlineCloseReturnedAt: f3.OriginalCloseReturnedAt}
	out = model.HostFactoryNativeProcess{HostBootID: bootID, PID: pin.pid, PPID: statBefore.ppid, StartTicks: statBefore.ticks, ProcessNonceSHA256: processNonceSHA, BootstrapReturnSHA256: bootstrapSHA, UID: owner.OriginalStat.UID, GID: owner.OriginalStat.GID, Execution: execution, OriginalStatBeforeSHA256: f1.OriginalSHA256, OriginalStatAfterSHA256: f4.OriginalSHA256, OriginalNativeReadStartedAt: f0.OriginalCalledAt, OriginalNativeReadReturnedAt: f4.OriginalReturnedAt, OriginalNativeCloseReturnedAt: f4.OriginalCloseReturnedAt, NativeReadOperations: [5]model.HostFactoryOriginalIOFact{f0, f1, f2, f3, f4}, OriginalHeldExecutableRead: held, OriginalProcessOwnerRead: owner, OriginalSubjectNativePin: pinProof, NativeHandleInventorySHAs: inventories}
	if e = capacity.ValidateHostFactory(out); e != nil || nativeProcessPhase(ctx, l, afterPoll.calledAt, afterPoll.returnedAt) != nil {
		return out, refused("native_join_refused", e)
	}
	pin.startTicks = statBefore.ticks
	return out, nil
}

func uuidParseExact(s string) (string, error) {
	// Parsing here is separate from source expectations. Noncanonical kernel
	// identity strings are unsupported rather than normalized into a proof.
	if len(s) != 36 || strings.ToLower(s) != s || s == "00000000-0000-0000-0000-000000000000" {
		return "", refused("native_join_refused", nil)
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "", refused("native_join_refused", nil)
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return "", refused("native_join_refused", nil)
		}
	}
	return s, nil
}

func exactIntent(raw []byte, next model.CapacityIntent) bool {
	encoded, err := json.Marshal(next)
	return err == nil && bytes.Equal(raw, encoded)
}

type threadDirectoryReturn struct {
	handle       *callHandle
	tids         []int
	terminalZero bool
	closeAt      time.Time
	err          error
}

// Native getdents returns raw kernel bytes. Its actual terminal is 0,nil,
// distinct from File.Read/io.EOF. The frozen wire grammar cannot admit this
// as an EOF-based task_inventory_read proof, so it remains private/HOLD.
func readOriginalTaskDirectory(l *originalLedger, pid int, subject, stage string) threadDirectoryReturn {
	result := threadDirectoryReturn{}
	if pid < 1 {
		result.err = refused("native_join_refused", nil)
		return result
	}
	h, err := l.handle()
	if err != nil {
		result.err = err
		return result
	}
	result.handle = h
	fdRaw, _, err := h.unclassifiedCall("open_task_directory", subject, stage, false, func() (int64, []byte, error) {
		fd, e := unix.Open("/proc/"+strconv.Itoa(pid)+"/task", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		return int64(fd), nil, e
	})
	if err != nil {
		result.err = refused("native_join_refused", err)
		return result
	}
	fd := int(fdRaw)
	h.fd = fd
	h.file = os.NewFile(uintptr(fd), "original-native-task-directory")
	var names []string
	total := 0
	for {
		if l.ctx.Err() != nil || total > bodyLimit {
			result.err = refused("original_context_refused", l.ctx.Err())
			break
		}
		buf := make([]byte, bodyLimit+1-total)
		nRaw, raw, e := h.unclassifiedCall("task_inventory_getdents", subject, stage, false, func() (int64, []byte, error) {
			n, e := unix.ReadDirent(fd, buf)
			if n < 0 {
				return int64(n), nil, e
			}
			return int64(n), bytes.Clone(buf[:n]), e
		})
		if e != nil || nRaw < 0 {
			result.err = refused("native_join_refused", e)
			break
		}
		if nRaw == 0 {
			result.terminalZero = true
			break
		}
		total += int(nRaw)
		_, _, batch := unix.ParseDirent(raw, -1, nil)
		names = append(names, batch...)
		if len(names) > 4096 {
			result.err = refused("native_join_refused", nil)
			break
		}
	}
	_, _, closeErr := h.unclassifiedCall("close_task_directory", subject, stage, false, func() (int64, []byte, error) {
		e := h.file.Close()
		if e != nil {
			return -1, nil, e
		}
		return 0, nil, nil
	})
	result.closeAt = time.Now().UTC()
	seen := map[int]bool{}
	for _, name := range names {
		tid, e := strconv.Atoi(name)
		if e != nil || tid < 1 || strconv.Itoa(tid) != name || seen[tid] {
			result.err = refused("native_join_refused", e)
			continue
		}
		seen[tid] = true
		result.tids = append(result.tids, tid)
	}
	sort.Ints(result.tids)
	if result.err == nil && closeErr == nil && result.terminalZero && len(result.tids) > 0 {
		// The actual returns are retained, but an unsupported wire/terminal
		// convention cannot be upgraded into a complete native EMPTY.
		result.err = capacity.ErrHostFactorySourceUnavailable
	} else {
		result.err = refused("native_join_refused", errors.Join(result.err, closeErr))
	}
	return result
}
