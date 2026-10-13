# ADR-0045: Join original Guest bootstrap under fixed VM membership

- **Status:** Proposed
- **Date:** 2026-10-11
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / protected original Guest observations
- **Supersedes:** —
- **Superseded by:** —

## Context

Provider action completion and Kubernetes Node Ready do not observe the original
bootstrap invocation. A Guest observer has a separate public protocol for its
original payload Start/Wait and the enclosing systemd/cloud-init invocation.
Its read-only SSH credential and signed enrollment are operator-owned. Generic
integration hydration embeds resolved credentials in a typed instance spec,
while the Guest contract binds the original public spec and requires resolved
SSH Auth separately. Decoding into an untyped output also loses duplicate JSON
member information before the consumer can enforce the native protocol.

## Decision

Extend the existing protected VM-to-Node collector with an optional Guest binding.
An absent binding preserves the ordinary collector. A declared binding additionally
requires explicit process opt-in, the current protected workflow and catalogs,
the original intent executor/epoch/lease and independently resolved managed-secret
ID/version/status/expiry. Copy the original lease deadline once and fence all
owning returns and the final observation against it; do not renew it for a read.

Keep approved slot ceiling, registered selected members and actual enrollment
roster distinct. Enrollment covers only current selected members, never presumed
future slots. Every selected registered VM requires exactly one enrolled read;
empty, duplicate, missing or extra rosters refuse the whole Guest observation.
Read provider and Node before and after all Guest calls, preserving their existing
registered tuple and immutable lifetime checks. Join exact provider/catalog/scope/
profile/slot/resource/creation/BootID/source and signed issuer bindings.

Keep Guest HTTP bearer header-only under a narrow package-private policy with
fixed verified HTTPS origin, routes and no redirects. The existing private SDK
Auth envelope carries only the independently resolved read-only SSH key. It is
never capability input, a public spec, a log or an output. Send original raw public
instance/type specs separately. Original connectivity, fresh Describe and Execute
consume actual bounded Do/Read/Close and original context results. Decode the closed
typed Guest reply directly from original HTTP bytes before envelope or output
remarshal. All other integration authentication, hydration, cache and transport
branches retain their existing behavior.

Recompute the per-member original payload and enclosing unit joins from required
native fields, including explicitly present false/zero values. A final record is
preparation evidence; it does not prove original SDK/owner caller return. QEMU
enrollment belongs to its owned fixture and cannot certify a provider VM or a
physical Node. Keep aggregate bootstrap, warmth, useful capacity, routing, full
business drain, provider quiescence and physical release authority false. Construct
no CapacityTransitionProof and write no new grant, resource, lease or phase.

## Consequences

- Production activation requires a real provider-to-host-key/BootID/source issuer,
  approved bindings/catalogs, current read authority, secrets, endpoint TLS identity
  and installed original binaries. Source or CI completion alone provides none.
- Existing resolver health/Describe runtime-state writes remain. Capacity ledger
  and provider-resource state remain unchanged by this observer.
- Protocol PostgreSQL/TLS fixtures exercise the real consumer and refusal paths.
  The separate original QEMU bridge must execute the exact current Core collector
  cases while its original native guest is alive. Adapter test passes and copied
  BootIDs never substitute for those consumer results or physical provenance.
- The ordinary public Go suite explicitly skips the unrequested external native
  job. The owning private Guest job requires its native opt-in before effects;
  missing input, PostgreSQL, rendezvous or literal census fails without skip or
  protocol fallback. Its original fixture owns a twenty-minute context and a
  five-minute preparation bound; the binary's twenty-one-minute limit fits the
  existing Guest step budget. No intent or ninety-second execution lease is
  created while the original QEMU guest boots.
- Useful canary, warmup, admission/withdrawal of routes, full drain, writer retirement
  and release remain separately observed lifecycle cuts.

## Related

- ADR-0042 (independent native VM-to-Node membership)
- ADR-0043 (original business creation observations)
- ADR-0044 (durable protected pre-start dispatch)
- Canonical integration contract (provider-neutral capability composition)
