//go:build labqualification && nativequalification

package capacity

// The LAB registry and native-QEMU qualification are separate authorities.
// Fail compilation explicitly if both execution classes are selected.
var _ = labqualification_and_nativequalification_must_not_be_combined
