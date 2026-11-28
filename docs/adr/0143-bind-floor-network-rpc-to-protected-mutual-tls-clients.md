# ADR-0143: Bind floor network RPC to protected mutual TLS clients

- **Status:** Proposed
- **Date:** 2026-11-27
- **Deciders:** Giomaster
- **Scope:** Core / dedicated System floor network transport
- **Supersedes:** —
- **Superseded by:** —

## Context

The floor network owner exposes separate reader and writer processes, with its
own three-member request envelope and typed replies. It is not a provider
integration and does not advertise provider Describe or diagnostic-health
endpoints. Reusing a fabricated provider adapter would lose those authority
boundaries. A successful HTTP call alone is not a host-effect or admission proof.

## Decision

Construct a dedicated opaque Core floor RPC handle from protected Go
configuration. Bind its role, AdapterID, compiled System Source, whole reviewed
binding-file SHA256, floor identity and exact network template. Compute the only
destination from the canonical private floor IPv4: HTTPS9444 for the reader or
HTTPS9443 for the writer, with fixed `/rpc/execute`. No input selects a URL,
trust file, header, proxy, redirect, credential or capability group.

Use the existing protected file, CA-chain, exact server-leaf, client-purpose,
deadline and shared-Close invariants. A reader accepts only the five-field
observe selector; a writer accepts only binding name and permit UUID for the
two declared operations. Each call sends once and requires bounded original
Read and actual Close, a live context, the exact compiled Source header, the
real five-member reply envelope and two explicit false metadata claims. Missing,
null, aliased, duplicated or extra fields are refused at every typed depth.

Check reader Source, scope, exact selectors, floor/template, freshness and
complete kernel inventories. Preserve the real five-field writer disposition,
including unknown or GET-only recovery. Do not add an invented writer scope
echo or transform `original_return_custodied` into a network receipt. The System
writer independently checks the actual loaded scope against Core's permission
before redemption; effect receiving remains a separate Core responsibility.

## Consequences

The source adds transport handles, not their runtime installation, controller,
permission issuance, provider action, guest evidence, network qualification or
scheduling admission. A configured reader can truthfully report an absent
interface only with complete typed inventory. A writer response cannot settle
absence or release quota. Nil or closed handles remain unavailable.

CI exercises actual mutual TLS against isolated loopback sockets while retaining
the protected floor Host, IP SAN and role port. The dialer seam is unexported;
the public constructor exposes no endpoint override or test switch. CI covers
role separation, identity/scope drift, TLS trust, framing, field presence,
original Read/Close/cancellation and consumed dispositions. It performs no real
provider, floor or production mutation.

## Related

- ADR-0138: protected provider RPC transport invariants
- ADR-0140: floor permissions and independent original receiving
