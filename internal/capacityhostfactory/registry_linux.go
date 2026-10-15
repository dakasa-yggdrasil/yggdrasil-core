//go:build linux

package capacityhostfactory

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"golang.org/x/sys/unix"
)

type executableApproval struct {
	sha              string
	bytes            int64
	device, inode    uint64
	commit, buildSHA string
	cmdline          []byte
}
type approvedArtifact struct {
	name, sha string
	bytes     int64
	uid, gid  uint32
	mode      uint32
}
type approvedKey struct {
	id, role string
	public   ed25519.PublicKey
}
type fixedInstallation struct {
	sourceProfileManifest                 []byte // externally compiled approved canonical50 manifest; current catalogs EMPTY
	privateDirectory                      string
	approval                              model.HostFactorySourceApproval
	approvalRawSHA                        string
	keys                                  []approvedKey
	artifacts                             [4]approvedArtifact
	core, worker, registrar               executableApproval
	workerName, registrarName             string
	qemuUUID                              string
	ordinaryCA, ordinaryClientCertificate approvedArtifact
	ordinaryMutationPrincipal             string
	slot                                  int
	entry                                 string
	initialAssessment                     model.CapacityAssessment
	controlPolicyArtifacts                [3]approvedArtifact
	controlPolicyRaw                      [3][]byte
	controlPolicyPublic                   controlPolicyPublicInventory
	controlFactoryEntries                 []string
	ordinaryCredentialSource              approvedArtifact // private metadata only; EMPTY default/no secret digest
	controlWorkerKey                      approvedArtifact // compiled private metadata only; EMPTY by default
	controlRegistrarKey                   approvedArtifact
}

// No environment, DTO, command flag, signature-provided public key or context
// can populate this compiled catalog. Approval/build/source inputs are NULL.
var compiledInstallations = [...]fixedInstallation{}

func selectInstallation(directory string) (fixedInstallation, error) {
	a, err := capacity.ApprovedHostFactorySource()
	if err != nil {
		return fixedInstallation{}, err
	}
	if a.ActualBuildSourceCommit != capacity.CurrentGuestCoreSource() || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return fixedInstallation{}, capacity.ErrHostFactorySourceUnavailable
	}
	for _, i := range compiledInstallations {
		b1, e1 := capacity.CanonicalHostFactory(a)
		b2, e2 := capacity.CanonicalHostFactory(i.approval)
		if e1 == nil && e2 == nil && bytes.Equal(b1, b2) && directory == i.privateDirectory {
			return i, nil
		}
	}
	return fixedInstallation{}, capacity.ErrHostFactorySourceUnavailable
}
func (i fixedInstallation) key(role, id string) (ed25519.PublicKey, error) {
	var selected ed25519.PublicKey
	for _, k := range i.keys {
		if k.role == role && k.id == id && len(k.public) == ed25519.PublicKeySize {
			if selected != nil && !bytes.Equal(selected, k.public) {
				return nil, refused("role_or_signature_refused", nil)
			}
			selected = k.public
		}
	}
	if selected == nil {
		return nil, refused("role_or_signature_refused", nil)
	}
	for _, k := range i.keys {
		if k.role != role && bytes.Equal(selected, k.public) {
			// A fixed signature namespace is not separation of key custody.
			// Malformed future compiled role aliases remain unavailable.
			return nil, refused("role_or_signature_refused", nil)
		}
	}
	return bytes.Clone(selected), nil
}
func (i fixedInstallation) approvedPublic(role string, public ed25519.PublicKey) bool {
	for _, k := range i.keys {
		if k.role == role && bytes.Equal(k.public, public) {
			key, err := i.key(role, k.id)
			return err == nil && bytes.Equal(key, public)
		}
	}
	return false
}

// Exact source paths are pinned component by component before use. The final
// FD is retained; /proc/self/fd numbers are never re-opened after that owner
// closed or reused the original descriptor.
func openPrivateDirectory(path string) (*os.File, unix.Stat_t, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, unix.Stat_t{}, refused("source_registry_refused", nil)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, unix.Stat_t{}, refused("source_registry_refused", err)
	}
	for _, name := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if name == "" || name == "." || name == ".." {
			_ = unix.Close(fd)
			return nil, unix.Stat_t{}, refused("source_registry_refused", nil)
		}
		next, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		closeErr := unix.Close(fd)
		if e != nil || closeErr != nil {
			if next >= 0 {
				_ = unix.Close(next)
			}
			return nil, unix.Stat_t{}, refused("source_registry_refused", errors.Join(e, closeErr))
		}
		fd = next
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0777 != 0700 || st.Uid != uint32(unix.Getuid()) {
		_ = unix.Close(fd)
		return nil, st, refused("source_registry_refused", err)
	}
	return os.NewFile(uintptr(fd), "original-private-source-directory"), st, nil
}

// The prepared directory is acquired by the original basal owner, not supplied
// as a caller FD. Every component reserves its handle BEFORE Open, records its
// actual native return/Fstat/getters, and closes the preceding parent separately.
// The returned handle remains the sole live anchor for all future Openat calls.
func openOriginalPrivateDirectory(ctx context.Context, path string, ledger *originalLedger, stage string, ownerUID uint32) (_ *callHandle, finalStat unix.Stat_t, runErr error) {
	if ctx == nil || ctx.Err() != nil || ledger == nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, finalStat, refused("source_registry_refused", nil)
	}
	var live []*callHandle
	defer func() {
		if runErr != nil {
			// Each successfully acquired endpoint is registered immediately;
			// validation/refusal cannot lose a child or parent original Close.
			for _, h := range live {
				if h.file != nil {
					_, err := closeOwned(h, "source_directory_close", ledger.ownerRole, stage)
					runErr = errors.Join(runErr, err)
				}
			}
		}
	}()
	flags := uint32(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC)
	acquire := func(parent *callHandle, name string) (*callHandle, unix.Stat_t, error) {
		h, err := ledger.handle()
		if err != nil {
			return nil, unix.Stat_t{}, err
		}
		live = append(live, h)
		operation, kind := "source_directory_open", "unix_open"
		request := model.HostFactoryNativeCallReturn{Kind: kind, RequestedFlags: &flags, RequestedMode: ptr(uint32(0))}
		if parent != nil {
			operation, kind = "source_directory_openat", "unix_openat"
			request.Kind = kind
			request.InputDescriptorNumber, request.ParentHandleID = ptr(parent.fd), ptr(parent.id)
		}
		value, err := h.nativeCall(operation, ledger.ownerRole, stage, false, request, func() originalNativeResult {
			var fd int
			var err error
			if parent == nil {
				fd, err = unix.Open("/", int(flags), 0)
			} else {
				fd, err = unix.Openat(parent.fd, name, int(flags), 0)
			}
			result := originalNativeResult{scalar: ptr(int64(fd)), cause: err}
			if err == nil {
				// Original ownership exists now, before any Fstat/validation.
				h.fd, h.file = fd, os.NewFile(uintptr(fd), "original-source-directory-component")
				result.descriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: h.id, OriginalDescriptorNumber: fd}}
			}
			return result
		})
		if err != nil || value.scalar == nil || *value.scalar < 0 || h.file == nil {
			return h, unix.Stat_t{}, refused("source_registry_refused", err)
		}
		stat, err := fstatNative(h, "source_directory_fstat", ledger.ownerRole, stage)
		if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Ino == 0 {
			return h, stat, refused("source_registry_refused", err)
		}
		observedFlags, err := fcntlNative(h, "fcntl_getfl", ledger.ownerRole, stage, unix.F_GETFL, 0)
		if err != nil || observedFlags < 0 || observedFlags&unix.O_ACCMODE != unix.O_RDONLY || observedFlags&unix.O_DIRECTORY == 0 || observedFlags&unix.O_NONBLOCK == 0 {
			return h, stat, refused("source_registry_refused", err)
		}
		observedDescriptorFlags, err := fcntlNative(h, "fcntl_getfd", ledger.ownerRole, stage, unix.F_GETFD, 0)
		if err != nil || observedDescriptorFlags != unix.FD_CLOEXEC {
			return h, stat, refused("source_registry_refused", err)
		}
		if ctx.Err() != nil {
			return h, stat, refused("original_context_refused", ctx.Err())
		}
		return h, stat, nil
	}
	current, stat, err := acquire(nil, "")
	if err != nil {
		return nil, stat, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			return nil, stat, refused("source_registry_refused", nil)
		}
		next, nextStat, err := acquire(current, component)
		if err != nil {
			return nil, nextStat, err
		}
		_, closeErr := closeOwned(current, "source_directory_close", ledger.ownerRole, stage)
		if closeErr != nil {
			return nil, nextStat, closeErr
		}
		current, stat = next, nextStat
	}
	if stat.Mode&0777 != 0700 || stat.Uid != ownerUID || ctx.Err() != nil {
		return nil, stat, refused("source_registry_refused", ctx.Err())
	}
	return current, stat, nil
}

type preparedOriginal struct {
	ordinaryWorker *originalOrdinaryWorker
	command        *callHandle
	cmd            *exec.Cmd
	handleID       string
	plan           model.HostFactoryPreparedCreatePlan
	anchor         *os.File
	anchorHandle   *callHandle
	choice         *originalChoice
	started        bool
	owner          *originalChild
	stdio          *privatePreparedIO
}

type privatePreparedIO struct {
	stdoutR, stdoutW, stderrR, stderrW, stdin *os.File
	stdout, stderr                            chan privateStreamReturn
	closed                                    bool
}
type privateStreamReturn struct {
	readStartedAt, readReturnedAt, closeReturnedAt time.Time
	count                                          int64
	sha                                            string
	eof                                            bool
	err                                            error
}

func preparePrivateStdio(ctx context.Context) (_ *privatePreparedIO, runErr error) {
	p := &privatePreparedIO{stdout: make(chan privateStreamReturn, 1), stderr: make(chan privateStreamReturn, 1)}
	defer func() {
		if runErr != nil {
			runErr = errors.Join(runErr, p.closeUnstarted())
		}
	}()
	var err error
	p.stdoutR, p.stdoutW, err = os.Pipe()
	if err != nil {
		return nil, err
	}
	p.stderrR, p.stderrW, err = os.Pipe()
	if err != nil {
		return nil, err
	}
	p.stdin, err = os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	d, ok := ctx.Deadline()
	if !ok {
		return nil, refused("original_context_refused", nil)
	}
	if err = p.stdoutR.SetReadDeadline(d); err != nil {
		return nil, err
	}
	if err = p.stderrR.SetReadDeadline(d); err != nil {
		return nil, err
	}
	return p, nil
}
func (p *privatePreparedIO) closeUnstarted() error {
	if p == nil || p.closed {
		return nil
	}
	p.closed = true
	var joined error
	for _, f := range []*os.File{p.stdoutR, p.stdoutW, p.stderrR, p.stderrW, p.stdin} {
		if f != nil {
			joined = errors.Join(joined, f.Close())
		}
	}
	return joined
}

// The real compiled create body is prepared in the worker process. The same
// pointer and executable anchor survive registration/Issue/late grant/Redeem.
func prepareFixedOriginalCreate(ctx context.Context, rootFD int, rootPath string, i fixedInstallation, l *originalLedger, bindingSchema, bindingSHA, targetSHA, preparationSHA string, originalRoot ...*callHandle) (_ *preparedOriginal, runErr error) {
	if ctx.Err() != nil || i.slot < 1 || i.slot > 2 || uuidMust(i.qemuUUID) == "" || i.entry == "" {
		return nil, refused("source_registry_refused", nil)
	}
	commandID, err := newID()
	if err != nil {
		return nil, err
	}
	p := &preparedOriginal{handleID: commandID}
	defer func() {
		if runErr != nil && p.anchorHandle != nil {
			_, e := closeOwned(p.anchorHandle, "executable_anchor_close", l.ownerRole, "cleanup")
			runErr = errors.Join(runErr, e)
		}
	}()
	roles := [4]string{"qemu_executable", "original_disk", "seed_image", "source_iso"}
	for n, a := range i.artifacts {
		path := filepath.Join(rootPath, a.name)
		if n == 0 {
			path = "/usr/bin/qemu-system-x86_64"
		}
		h, st, e := acquireFile(l, path, l.ownerRole, "prepared_create", "artifact_reader_open", "artifact_reader_fstat", unix.O_RDONLY|unix.O_NOFOLLOW)
		if e != nil {
			if h != nil && h.file != nil {
				_, _ = closeOwned(h, "artifact_reader_close", l.ownerRole, "cleanup")
			}
			return nil, e
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Ino == 0 || st.Nlink != 1 || st.Uid != a.uid || st.Gid != a.gid || st.Mode != a.mode {
			_, _ = closeOwned(h, "artifact_reader_close", l.ownerRole, "cleanup")
			return nil, refused("source_registry_refused", nil)
		}
		limit := int64(536870912)
		if n == 0 {
			limit = 134217728
		}
		_, r := readOwned(h, roles[n]+"_read", l.ownerRole, "prepared_create", limit, false, -1)
		if n == 0 && r.err == nil && r.eof && r.count == a.bytes && r.sha == a.sha {
			anchor, e := l.handle()
			if e != nil {
				_, _ = closeOwned(h, "artifact_reader_close", l.ownerRole, "cleanup")
				return nil, e
			}
			value, e := anchor.nativeCall("executable_anchor_duplicate", l.ownerRole, "prepared_create", false, model.HostFactoryNativeCallReturn{Kind: "fcntl_dupfd_cloexec", InputDescriptorNumber: ptr(h.fd), ParentHandleID: ptr(h.id), RequestedFcntlCommand: ptr(unix.F_DUPFD_CLOEXEC), RequestedArgument: ptr(int64(0))}, func() originalNativeResult {
				fd, callErr := unix.FcntlInt(uintptr(h.fd), unix.F_DUPFD_CLOEXEC, 0)
				v := originalNativeResult{scalar: ptr(int64(fd)), cause: callErr}
				if callErr == nil && fd >= 0 {
					anchor.fd, anchor.file = fd, os.NewFile(uintptr(fd), "original-qemu-start-anchor")
					v.descriptors = []model.HostFactoryNativeAcquiredDescriptor{{OriginalHandleID: anchor.id, OriginalDescriptorNumber: fd}}
				}
				return v
			})
			if e == nil {
				e = nativeProcessPhase(ctx, l, value.calledAt, value.returnedAt)
			}
			if e != nil {
				_, _ = closeOwned(h, "artifact_reader_close", l.ownerRole, "cleanup")
				return nil, e
			}
			p.anchor = anchor.file
			p.anchorHandle = anchor
		}
		closeAt, ce := closeOwned(h, "artifact_reader_close", l.ownerRole, "prepared_create")
		if r.err != nil || ce != nil || !r.eof || r.count != a.bytes || r.sha != a.sha {
			return nil, refused("source_registry_refused", errors.Join(r.err, ce))
		}
		p.plan.OriginalArtifacts[n] = model.HostFactoryArtifactSource{Role: roles[n], SourceDevice: uint64(st.Dev), SourceInode: st.Ino, SourceUID: st.Uid, SourceGID: st.Gid, SourceMode: st.Mode, SourceLinkCount: uint64(st.Nlink), OriginalSourceBytes: uint64(r.count), OriginalSourceSHA256: r.sha, OriginalSourceReadStartedAt: r.started, OriginalSourceReadReturnedAt: r.returned, OriginalSourceCloseReturnedAt: closeAt}
	}
	if p.anchor == nil {
		return nil, refused("source_registry_refused", nil)
	}
	args := fixedQEMUArguments(rootPath, i)
	p.cmd = &exec.Cmd{Path: "/proc/self/fd/3", Args: args, Env: []string{"PATH=/usr/bin:/bin", "LANG=C"}, ExtraFiles: []*os.File{p.anchor}}
	// This fd3 is in the QEMU CHILD namespace. Worker fd3/4/5 are its own
	// bootstrap/late grant/credential handles, not this executable anchor.
	anchorSource, e := descriptor(p.anchorHandle, "qemu_start_executable_anchor", l.primitiveSHA, l.ownerRole, "prepared_create", "executable_anchor_duplicate")
	if e != nil {
		return nil, e
	}
	if len(originalRoot) != 1 {
		return nil, refused("source_registry_refused", nil)
	}
	rootStat, rootCall, err := originalPreparedRootStat(ctx, l, rootFD, originalRoot[0])
	if err != nil {
		return nil, err
	}
	p.choice = &originalChoice{rootFD: rootFD, rootIdentity: rootStat, ledger: l, sourceRoot: originalRoot[0], sourceRootCall: rootCall}
	argv, _ := json.Marshal(args)
	p.plan.Schema = "original_host_factory_prepared_create_plan_v4"
	p.plan.Purpose = p.plan.Schema
	p.plan.BindingSchema = bindingSchema
	p.plan.BindingSHA256 = bindingSHA
	p.plan.OriginalCreateCommandHandleID = commandID
	p.plan.FactoryRegistrySHA256 = i.approval.FactoryRegistrySHA256
	p.plan.FixedArgvSHA256 = digest(argv)
	p.plan.SourcePreparationSHA256 = preparationSHA
	p.plan.PreparedAt = time.Now().UTC()
	p.plan.OwnerPrimitiveRawSHA256 = l.primitiveSHA
	p.plan.StableOriginalTargetSHA256 = targetSHA
	p.plan.ExecutableStartAnchorSource = anchorSource
	if err = capacity.ValidateHostFactory(p.plan); err != nil {
		return nil, refused("source_registry_refused", err)
	}
	return p, nil
}
func uuidMust(s string) string {
	x, e := uuidParseExact(s)
	if e != nil {
		return ""
	}
	return x
}
func fixedQEMUArguments(root string, i fixedInstallation) []string {
	port := "19447"
	if i.slot == 2 {
		port = "20447"
	}
	return []string{"/usr/bin/qemu-system-x86_64", "-machine", "accel=kvm", "-cpu", "max", "-m", "1536", "-smp", "2", "-display", "none", "-no-reboot", "-uuid", i.qemuUUID, "-qmp", "unix:" + filepath.Join(root, "original-qmp.sock") + ",server=on,wait=off", "-serial", "file:" + filepath.Join(root, "original-serial.log"), "-drive", "file=" + filepath.Join(root, i.artifacts[1].name) + ",format=qcow2", "-drive", "file=" + filepath.Join(root, i.artifacts[2].name) + ",format=raw,media=cdrom,readonly=on", "-drive", "file=" + filepath.Join(root, i.artifacts[3].name) + ",format=raw,media=cdrom,readonly=on", "-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:" + port + "-:9447", "-device", "virtio-net-pci,netdev=net0"}
}
