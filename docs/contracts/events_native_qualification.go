package contracts

// IsNativeQualificationMutationEvent recognizes only the two fixed native QEMU
// server events in a nativequalification build. It grants no native authority.
// Production builds keep this set empty and retain the generic event grammar.
func IsNativeQualificationMutationEvent(eventType string) bool {
	return nativeQualificationMutationSchemaPath(eventType) != ""
}
