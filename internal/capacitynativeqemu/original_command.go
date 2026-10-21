package capacitynativeqemu

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
)

// exactOriginalCommand checks the complete original command bytes and every
// argument. Executable identity is independently verified by the native reader.
func exactOriginalCommand(raw []byte, expected []string, originalSHA256 string) bool {
	arguments := bytes.Split(bytes.TrimSuffix(raw, []byte{0}), []byte{0})
	sum := sha256.Sum256(raw)
	if len(arguments) < 2 || len(arguments) != len(expected)+1 || hex.EncodeToString(sum[:]) != originalSHA256 {
		return false
	}
	for n, value := range expected {
		if string(arguments[n+1]) != value {
			return false
		}
	}
	return true
}
