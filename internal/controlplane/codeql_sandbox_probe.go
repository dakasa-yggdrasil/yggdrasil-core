// Diagnostic branch only: synthetic values, no production call sites.
package controlplane

import (
    "crypto/sha256"
    "encoding/json"

    "github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

type codeqlSandboxValues struct {
    Password string
    PasswordRef string
}

func codeqlSandboxShared(v string) [32]byte { return sha256.Sum256([]byte(v)) } // PROBE_SHARED
func codeqlSandboxDirect(v codeqlSandboxValues) [32]byte { return sha256.Sum256([]byte(v.Password)) } // PROBE_DIRECT_PASSWORD
func codeqlSandboxRawRef(v codeqlSandboxValues) [32]byte { return sha256.Sum256([]byte(v.PasswordRef)) } // PROBE_RAW_REFERENCE
func codeqlSandboxOtherCall(v codeqlSandboxValues) [32]byte { return sha256.Sum256([]byte(secretRefName(v.Password))) } // PROBE_OTHER_CALL
func codeqlSandboxName(v codeqlSandboxValues) [32]byte {
    public := envFromExternalPostgresSecret(&model.ControlPlanePostgresExternalSpec{PasswordRef: v.PasswordRef})
    raw, _ := json.Marshal(public)
    return sha256.Sum256(raw) // PROBE_REFERENCE_NAME
}
func codeqlSandboxCallShared(v codeqlSandboxValues) {
    _ = codeqlSandboxShared(v.Password)
    public := envFromExternalPostgresSecret(&model.ControlPlanePostgresExternalSpec{PasswordRef: v.PasswordRef})
    raw, _ := json.Marshal(public)
    _ = codeqlSandboxShared(string(raw))
}
