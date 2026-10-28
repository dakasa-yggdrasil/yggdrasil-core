//go:build linux && nativequalification

package capacitynativeqemu

import (
	"context"
	"encoding/json"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"golang.org/x/sys/unix"
	"path/filepath"
	"time"
)

type OriginalPIDFD struct {
	fd     int
	fact   repository.GuestNativeQEMUPIDFDReturn
	closed bool
}

func nativeProjection(p Process) repository.GuestNativeQEMUProcess {
	return repository.GuestNativeQEMUProcess{PID: p.PID, PPID: p.PPID, StartTicks: p.StartTicks, StatSHA256: p.StatSHA256}
}

// Pin the original lifetime while it is live, BEFORE the retirement intent
// and any possible POST. No PID lookup after exit substitutes for this handle.
func (r *Realm) PinOriginalRetirement(ctx context.Context, slot int) error {
	if slot != 2 || !RetirementCase(r.Request.NativeCase) {
		return ErrOriginalUnknown
	}
	r.mu.Lock()
	native, ok := r.originals[slot]
	if r.retirementPins == nil {
		r.retirementPins = map[int]*OriginalPIDFD{}
	}
	if !ok || r.retirementPins[slot] != nil {
		r.mu.Unlock()
		return ErrOriginalUnknown
	}
	r.mu.Unlock()
	fact := repository.GuestNativeQEMUPIDFDReturn{Schema: "core_original_same_qemu_pidfd_join_v1", ResourceID: native.Original.ResourceID, CreatorOriginalSHA256: native.OriginalCreatorSHA256, OriginalPinStartedAt: time.Now().UTC()}
	before, err := nativeProcess(ctx, native.After.PID)
	if err != nil || !sameProcess(before, native.After) {
		return ErrOriginalUnknown
	}
	fd, err := unix.PidfdOpen(before.PID, 0)
	if err != nil {
		return ErrOriginalUnknown
	}
	after, err := nativeProcess(ctx, before.PID)
	if err != nil || !sameProcess(before, after) || ctx.Err() != nil {
		_ = unix.Close(fd)
		return ErrOriginalUnknown
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	if err != nil || n != 0 || poll[0].Revents != 0 {
		_ = unix.Close(fd)
		return ErrOriginalUnknown
	}
	fact.Before, fact.After, fact.OriginalPinReturnedAt = nativeProjection(before), nativeProjection(after), time.Now().UTC()
	r.mu.Lock()
	r.retirementPins[slot] = &OriginalPIDFD{fd: fd, fact: fact}
	r.mu.Unlock()
	return nil
}

func (r *Realm) OriginalNativeOff(ctx context.Context) ([]byte, []byte, error) {
	r.mu.Lock()
	pin := r.retirementPins[2]
	r.mu.Unlock()
	if pin == nil || pin.closed {
		return nil, nil, ErrOriginalUnknown
	}
	var off repository.GuestNativeQEMUOffReturn
	wire, err := Await(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, 2), "native-off-original.json"), &off)
	if err != nil {
		return nil, nil, err
	}
	if off.QEMU.PID != pin.fact.Before.PID || off.QEMU.PPID != pin.fact.Before.PPID || off.QEMU.StartTicks != pin.fact.Before.StartTicks || off.CreatorOriginalSHA256 != pin.fact.CreatorOriginalSHA256 {
		return nil, nil, ErrOriginalUnknown
	}
	poll := []unix.PollFd{{Fd: int32(pin.fd), Events: unix.POLLIN}}
	for {
		if ctx.Err() != nil {
			return nil, nil, ErrOriginalUnknown
		}
		n, e := unix.Poll(poll, 20)
		if e == unix.EINTR {
			continue
		}
		if e != nil {
			return nil, nil, ErrOriginalUnknown
		}
		if n == 1 && repository.GuestNativeQEMUPIDFDExited(poll[0].Revents) {
			break
		}
		if n != 0 || poll[0].Revents != 0 {
			return nil, nil, ErrOriginalUnknown
		}
	}
	pin.fact.OriginalPollReturnedAt = time.Now().UTC()
	pin.fact.OriginalPollRevents = poll[0].Revents
	err = unix.Close(pin.fd)
	pin.closed = true
	pin.fact.OriginalCloseReturnedAt = time.Now().UTC()
	if err != nil || ctx.Err() != nil {
		return nil, nil, ErrOriginalUnknown
	}
	joinWire, err := json.Marshal(pin.fact)
	if err != nil {
		return nil, nil, err
	}
	if _, err = PublishBytes(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, 2), "core-original-pidfd-join.json"), joinWire); err != nil {
		return nil, nil, err
	}
	return wire, joinWire, nil
}

func (r *Realm) CloseOriginalPins() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pin := range r.retirementPins {
		if !pin.closed {
			if unix.Close(pin.fd) != nil {
				return ErrOriginalUnknown
			}
			pin.closed = true
		}
	}
	return nil
}

func (r *Realm) OriginalNativeResource(slot int) (Process, string, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	native, ok := r.originals[slot]
	if !ok {
		return Process{}, "", "", ErrOriginalUnknown
	}
	return native.After, native.Original.ResourceID, native.OriginalCreatorSHA256, nil
}
