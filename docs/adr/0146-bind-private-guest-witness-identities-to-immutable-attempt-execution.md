# ADR-0146: Bind private guest witness identities to immutable Attempt Execution

- Status: Proposed; activation gated
- Date: 2026-11-27
- Scope: Core private factory, authenticated guest report and readiness port

## Context

The real factory recreates its WireGuard identity from protected generation
material and immutable Attempt context. Private user-data is not a durable
database archive. The existing System witness needs its fixed public template
and an authenticated read channel. Neither that local report nor its hash is
independent network/path MTU or workload startup evidence.

## Decision

Add an optional final `guest_identity_policy_sha256` field to ExecutionProfile.
Its absence is omitted and preserves legacy wire bytes. The existing immutable
Attempt and private command context retain it without a new table or migration.
Paired provider mirrors must accept this optional canonical lowercase SHA256;
it is not a bearer, permission or caller-selected identity.

The protected factory configuration loads a new 32-byte master, separate from
the WireGuard master, and a pinned Ed25519 issuer CA/private key. The public
policy hash is SHA256 of canonical JSON in this declaration order:
version, master_version, master_public_key, issuer_ca_sha256,
network_template_sha256, certificate_validity_seconds, max_read_age_seconds.
The master public proof is a purpose-separated Ed25519 public key, not a hash
of private bootstrap material. Paths and private values are excluded. A loaded
configuration must exactly match the persisted Execution pin. Missing config
and absent pin go together; a replaced generation or template fails closed.

Server and client seeds and serials use different HMAC purpose domains and
the same immutable Attempt/Launch frame. Their EKUs differ. The pinned CA must authorize both TLS roles before private
rendering; a CA restricted to one role fails closed. Ed25519 signing,
explicit serials and validity from CreatedAt make their DER deterministic
without a clock, random seed, provider fact or capability URL in derivation.
The allocated overlay IP and Attempt/Launch URI bind both certificates. Only
the unique client public DER pin and CA reach the guest. Neither private key
is shared with another Attempt; the client key stays in Core RAM.

Validity has no default and must fit inside the pinned CA. Retain the original
protected generation for every live Attempt. Expiry is HOLD. There is no
renewal endpoint, retry remint, secret write or implicit CA rotation.

Public Launch/schema1 and private material/schema1 stay unchanged. Opt-in
private renderer v2 receives closed input containing the exact template and
guest TLS material on stdin FD0, then returns private cloud-init on FD3. The
held executable is still checked against actual published Source, digest and size.

The authenticated read performs one zero-body GET at the fixed overlay
IPv4:9445/native-worker/network-witness. Protected chain, IP SAN, exact derived
server leaf/URI and compiled Source checks precede decoding. Actual bounded
Read, Close and context completion are required. There is no proxy, redirect,
replay, public URL override or machine/workflow configuration port.

The existing PhaseReader readiness callback consumes this typed local report
only after matching the fresh complete Attempt and immutable stored Launch
from the database. A protected Go callback must supply actual independent
network/path and startup evidence. The database context is checked again after
receiving. Nil or incomplete evidence cannot admit or release quarantine; the
existing full phase-proof joins remain mandatory. No WAN occurs under SQL locks.

## Consequences

All new behavior is default-off. Local witness flags remain false for path MTU,
independent network, admission and useful capacity. A small Source-pinned
Pod/Service path probe and representative startup receiving are separate work;
a report hash cannot replace them. No cloud, production change, provision or
Hetzner load is authorized by this Source publication. Tests/builds run in CI.
