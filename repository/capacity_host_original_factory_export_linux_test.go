//go:build linux && nativequalification

package repository

// Test-only access preserves the same closed full-wrapper decoder and 64MiB
// bound for the external native ABI corpus without importing the native
// producer into the repository test package. No production API is added.
func DecodeOriginalHostFinalCorpusForNativeTest(raw []byte) (hostOriginalFinalCorpus, error) {
	var wrapper hostOriginalFinalCorpus
	err := hostOriginalStrictJSON(raw, &wrapper, 64*1024*1024)
	return wrapper, err
}
