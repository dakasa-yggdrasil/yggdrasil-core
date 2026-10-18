//go:build linux && nativequalification
package capacitynativeqemu
// Separate fixed qualification cases. Existing lost-empty negatives retain their ABI.
func PostlossSourceCase(c string)bool{return c=="canonical_postloss_unprotected_failed_create_reissue" || c=="canonical_postloss_protected_failed_create_reissue"}
