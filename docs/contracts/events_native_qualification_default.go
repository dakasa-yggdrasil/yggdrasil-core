//go:build !nativequalification

package contracts

func nativeQualificationMutationSchemaPath(string) string { return "" }

func readEventSchemaFile(schemaPath string) ([]byte, error) {
	return eventSchemaFS.ReadFile(schemaPath)
}
