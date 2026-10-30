// Diagnostic branch only: synthetic values, no production call sites.
package controlplane

import "crypto/sha256"

type codeqlSandboxValues struct {
    Password string
    PasswordRef string
}

func codeqlSandboxShared(v string) [32]byte { return sha256.Sum256([]byte(v)) } // PROBE_SHARED
func codeqlSandboxDirect(v codeqlSandboxValues) [32]byte { return sha256.Sum256([]byte(v.Password)) } // PROBE_DIRECT_PASSWORD
func codeqlSandboxRawRef(v codeqlSandboxValues) [32]byte { return sha256.Sum256([]byte(v.PasswordRef)) } // PROBE_RAW_REFERENCE
func codeqlSandboxName(v codeqlSandboxValues) [32]byte { return sha256.Sum256([]byte(secretRefName(v.PasswordRef))) } // PROBE_REFERENCE_NAME
func codeqlSandboxCallShared(v codeqlSandboxValues) {
    _ = codeqlSandboxShared(v.Password)
    _ = codeqlSandboxShared(secretRefName(v.PasswordRef))
}
