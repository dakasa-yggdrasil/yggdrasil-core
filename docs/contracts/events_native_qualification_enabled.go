//go:build nativequalification

package contracts

import "embed"

// These schemas are absent from default builds. Keep their vocabulary separate
// from the generic provider/resource schemas and their snake_case grammar.
//
//go:embed events/v1/native_qualification/server_ensured.json events/v1/native_qualification/server_destroyed.json
var nativeQualificationEventSchemaFS embed.FS

func nativeQualificationMutationSchemaPath(eventType string) string {
	switch eventType {
	case "native-qemu.server.ensured":
		return "events/v1/native_qualification/server_ensured.json"
	case "native-qemu.server.destroyed":
		return "events/v1/native_qualification/server_destroyed.json"
	default:
		return ""
	}
}

func readEventSchemaFile(schemaPath string) ([]byte, error) {
	switch schemaPath {
	case "events/v1/native_qualification/server_ensured.json", "events/v1/native_qualification/server_destroyed.json":
		return nativeQualificationEventSchemaFS.ReadFile(schemaPath)
	default:
		return eventSchemaFS.ReadFile(schemaPath)
	}
}
