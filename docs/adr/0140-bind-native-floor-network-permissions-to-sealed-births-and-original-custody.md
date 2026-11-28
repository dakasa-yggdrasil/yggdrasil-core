# ADR-0140: Bind Native floor network permissions to sealed births and original custody

**Status:** Proposed

**Date:** 2026-11-27

## Context

A provider create ACK and a quarantined Node do not establish the floor return
route, WireGuard peer or provider transport ACL. Installing those effects through
an unbound host command would bypass the lifecycle's original one-send authority.
The System floor reader/writer is separately Source pinned and defaults off.

## Decision

An optional `native_worker_floor_network_v1` policy binds separate System writer
and reader instances, protected floor identity and one exact public network
template. Its omission preserves the previous policy wire. Launch/schema1 stays
unchanged. The guest Source, private geometry, pinned floor key and MTU1380 must
match; the overlay floor address is excluded from allocation in every profile.

Migration117 retains immutable private network grants, original host batch bytes
and append-only revision history. A grant selects one attempt, sealed birth and
stored launch, writer scope, pool epoch, parent generation/fence, expiry and full
configuration preimage. Begin and redeem share the existing attempt arbiter;
network I/O occurs outside locks. Install requires a fresh independently read
provider target and actual public transport IPv4. Remove uses the sealed target,
current complete floor observation and only the endpoint retained in an original
install grant. A real provider not_found must not require a fabricated live GET.
Current draining/abort recovery authority is still required inside the transaction.

The exact protected machine principal and System Source are authenticated before
any private request body. GET read/reconcile and POST redeem/receive are fixed
callbacks. Only one successful redeem exposes mutation permission. Full original
Read, Close and context completion precede a state change. Late private custody
remains possible after process gates close and never reopens a permission.

The source-owned private batch can prove original producer closure independently
of capture completeness or execution success. Missing/ambiguous process facts
cannot prove closure. An unknown batch cannot authorize replay. Abort waits for
any exposed install producer; overlay release also waits for exposed cleanup
producers and an independently observed compensating removal. An issued unsent
install may be closed atomically under the same attempt lock.

Independent GET-only floor receiving checks the stored launch and template,
actual host/interface/CA-origin facts, complete public WG/route/nft inventories,
exact worker ownership and stable configuration preimage. Return routes use the
floor's actual native source IP. A matching host configuration grants no guest
path, DNS, end-to-end MTU, useful capacity or Node admission credit.

## Consequences

All new ports and process gates default off. No provider, floor network, data,
Flannel, business deployment or allocator is changed by this Source. Dedicated
mutual TLS client/runtime composition, protected guest template delivery and
remote original witness custody must be qualified before activation. A source
bound local CA file is not evidence of the actual current Kubernetes realm.

Tests run only in GitHub Actions, using actual PostgreSQL migrations and the
shared attempt/permit arbiter. Unit and PostgreSQL roots remain in the complete
market census. Rollback refuses retained permission/history rows; no old schema
or original uncertain history is rewritten to obtain a green result.
