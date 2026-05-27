package httpapi

import (
	"os"
	"strings"
)

// Validator phases for the universal capability-naming convention
// (INTEGRATION_CONTRACT §5 + the 2026-05-27 rollout).  Two phases live
// in this codebase:
//
//   - "warn-only" (DEFAULT): non-conformant integration_type capability
//     names produce a warnings:[...] array on the 201 Created response
//     and persist to manifests.metadata.  Registration ALWAYS succeeds;
//     the validator never blocks.  This is the Phase 1 behaviour that
//     shipped 2026-05-27 alongside the SDK v0.5.0 convention codification.
//
//   - "hard-fail": non-conformant names cause the registration to be
//     rejected with HTTP 422 Unprocessable Entity carrying the same
//     warnings:[...] body.  No DB row is written.  Conformant manifests
//     and the rest of the registration pipeline are unaffected.  This
//     is Phase 2, gated chronologically on 14 days of observation after
//     warn-only landed (earliest cut-over: 2026-06-10).
//
// The phase is read once at boot from YGGDRASIL_VALIDATOR_PHASE.  Any
// other value (including blank, "phase-1", "phase-2", typos, …) is
// treated as warn-only — the SAFE default — so an operator who
// fat-fingers the env-var does not accidentally start rejecting writes.
//
// The flip itself is reversible at any time by toggling the env-var and
// restarting the pod (no DB migration, no schema change).  See
// reference_phase2_validator_flip_runbook.md for the full procedure.
const (
	ValidatorPhaseWarnOnly = "warn-only"
	ValidatorPhaseHardFail = "hard-fail"
)

// resolveValidatorPhase returns the canonical phase string read from
// YGGDRASIL_VALIDATOR_PHASE.  Unknown values silently fall back to
// warn-only.  Exported (lower-case) for use by handleManifestCreate
// and the metrics-emission path; package-private because the only
// caller is this package.
func resolveValidatorPhase() string {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("YGGDRASIL_VALIDATOR_PHASE")))
	switch raw {
	case ValidatorPhaseHardFail:
		return ValidatorPhaseHardFail
	default:
		return ValidatorPhaseWarnOnly
	}
}
