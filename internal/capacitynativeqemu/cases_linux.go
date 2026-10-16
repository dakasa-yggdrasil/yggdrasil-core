//go:build linux && nativequalification

package capacitynativeqemu

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
)

func AllowedCase(value string) bool {
	switch value {
	case "positive_original_lifecycle", "held_hello_original_deadline", "held_ack_after_owned_original_deadline", "held_probe_body_original_deadline", "cancelled_probe_original_join", "actor_startup_delay_positive", "admission_bind_cancelled_original":
		return true
	}
	return false
}
func PositiveCase(value string) bool {
	return value == "positive_original_lifecycle" || value == "actor_startup_delay_positive"
}

// Exact unit bytes come from the actual clean Guest source. The only native
// source case insertion is fixed before ISO/precreate; arbitrary env/commands
// or later bootstrap/profile mutation never enters the source approved realm.
func (r *Realm) verifySourceUnits(ctx context.Context, slot int) error {
	selected := r.Request.NativeCase
	if slot == 1 {
		selected = "positive_original_lifecycle"
	}
	if !AllowedCase(selected) {
		return ErrOriginalUnknown
	}
	for _, unit := range []string{"yggdrasil-guest-retirement.service", "yggdrasil-guest-protected-runtime-owner.service"} {
		original, err := readOpened(ctx, filepath.Join(os.Getenv("GUEST_NATIVE_SOURCE_ROOT"), "docs", "systemd", unit), 65536, false, false)
		if err != nil {
			return err
		}
		if bytes.Count(original, []byte("[Service]\n")) != 1 || bytes.Contains(original, []byte("GUEST_ORIGINAL_NATIVE_CASE")) {
			return ErrOriginalUnknown
		}
		approved := bytes.Replace(original, []byte("[Service]\n"), []byte("[Service]\nEnvironment=GUEST_ORIGINAL_NATIVE_CASE="+selected+"\n"), 1)
		actual, err := readOpened(ctx, filepath.Join(SlotDirectory(r.PrivateDirectory, slot), "source-bundle", unit), 65536, false, false)
		if err != nil || !bytes.Equal(actual, approved) {
			return ErrOriginalUnknown
		}
	}
	return nil
}

func RetirementCase(value string) bool {
	return PositiveCase(value) || value == "held_ack_after_owned_original_deadline"
}
