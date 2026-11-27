# ADR-0138: Bind Native provider RPC to protected mutual TLS clients

**Status:** Proposed

**Date:** 2026-11-27

## Context

An outbound private create or observation request carries resolved provider
credentials. Core callback authentication alone does not authenticate who may
invoke the provider adapter. SDK envelope headers are input data, and ordinary
integration metadata must not select a TLS key or a different trusted origin.
The original resolver performs health and Describe before execution, so a
certificate installed only on the final execution would leave that path broken.

## Decision

Protected Go composition constructs a separate opaque Native RPC client for an
exact adapter instance/version/checksum, type/checksum, profile, binding, SDK
Source, scope and allowed role. Read-only and mutation clients use separate
certificates and inventories. No Execution DTO, bearer or payload identity field
is introduced. File ownership, private-key mode, bounded reads and canonical CA
and leaf material are checked before constructing the client.

The client validates the server CA chain and hostname, a pinned server leaf,
explicit serverAuth and the exact compiled Source response header before decoding
any SDK reply. Client material requires explicit clientAuth. Its fixed HTTPS
origin accepts only Describe and the configured Native operations. Redirects,
environment proxies, broker fallback and replayable original requests are
refused. Each call retains its actual bounded Read and Close; a Close failure
cannot qualify a complete reply.

A private context separate from generic call policies carries the selected
client through the original resolver and final execution. Original instance/type
pins and public origin are checked before credential hydration and again before
Describe or execution. Protected Describe never uses the generic cached result.
The separate fixed public health endpoint receives no client certificate or
private header; that observation remains diagnostic and grants no readiness or
mutation authority. Closing any copy fences all copies of the private handle.

## Consequences

Ordinary calls with no protected context retain their existing behavior. Native
installation must provision the matching server listener, actual compiled Source
header, separate client/server certificates and fixed public health route. TLS
identity never replaces the separate one-use Core command/abort permit or the
independent physical and network observations. This contract installs no process,
controller, provider resource or production policy by itself.

GitHub CI owns real mutual-TLS, original transport, negative scope and secret
hydration ordering cases. Tests and compilation are not run on the owner's
machine. Source qualification is separate from operational receiving.
