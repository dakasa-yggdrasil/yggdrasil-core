//go:build linux && nativequalification

package capacity

// GuestPostlossQualificationSlot selects the actual failed QEMU slot for the
// two source-owned post-loss cases. Zero rejects every other case; callers must
// retain the selected slot when joining the owning return, independent read,
// enrollment, cleanup and child grant.
func GuestPostlossQualificationSlot(name string) int {
	switch name {
	case "canonical_postloss_unprotected_failed_create_reissue":
		return 2
	case "canonical_postloss_protected_failed_create_reissue":
		return 1
	default:
		return 0
	}
}
