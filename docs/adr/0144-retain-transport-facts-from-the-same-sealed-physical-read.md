# ADR-0144: Retain transport facts from the same sealed physical read

- **Status:** Proposed
- **Date:** 2026-11-27
- **Scope:** Core / protected Native provider transport observation

## Context

The independent physical adapters already return a public transport IPv4 and
fresh Source, scope, evidence and observation time. ReobserveACK intentionally
returns only the same sealed physical tuple. The floor network preparation
cannot replace those omitted facts with expected values or a private address,
or claim that a second unqualified response was the first validated read.

## Decision

Add a Go-only ReobserveTransportACK port to the existing ACK qualifier. Use a
local qualifier copy with a per-call reader wrapper: obtain exactly one actual
independent response, copy its full typed provider-specific carrier, and pass
that same copy through the original sealed reobservation checks. Preserve all
original custody, immutable launch, provider/account/project, reader Source and
scope, lifetime, freshness and sealed physical identity guards.

Return only the same sealed physical tuple and the actual read time, safe
evidence digest, compiled adapter Source, scope and canonical public IPv4 from
that response. The endpoint is mandatory for this port; unavailable transport
stays unavailable. The existing physical-only ReobserveACK API and absent
optional AWS transport wire remain unchanged. No lifecycle state, original
acceptance, birth, original HTTP ID or mutation permission is created or changed.

HCloud's internal carrier has json:"-" on the AWS DTO. Copy it independently so
a generic AWS JSON roundtrip cannot erase its complete typed observation. The
wrapper is local to one call and does not replace the original qualifier's
reader or retain mutable producer-owned arrays.

## Consequences

This is a read port, not a network runtime, controller, guest witness or
admission proof. Actual protected provider clients and independent floor/guest
receiving remain required before installation. CI covers the two literal
providers, one-read identity/freshness provenance, original-guard refusals,
absent transport compatibility, copied carrier ownership and both public
observation/witness privacy surfaces. No local tests or cloud calls run here.
