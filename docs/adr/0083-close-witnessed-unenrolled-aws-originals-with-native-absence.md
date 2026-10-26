# ADR-0083: Close witnessed unenrolled AWS originals with native absence

- **Status:** Proposed
- **Date:** 2026-10-26
- **Deciders:** Core maintainers
- **Scope:** Core administrative failed original accounting
- **Supersedes:** None
- **Superseded by:** None

## Context

An owning AWS create can return an accepted settlement and an immutable create
witness, then finish its workflow failed without enrollment or installation.
The dispatch can retain an unknown original ACK. The original AWS settlement
does not assert complete auxiliary inventory. Existing witnessed failed-original
accounting covers the historical Hetzner creator; the earlier AWS disposition
requires no witness, and enrolled-failed accounting requires enrollment.

## Decision

Extend the existing failed-original terminal flow for the exact independently
published AWS creator with a witnessed, settled, unenrolled original and unknown
ACK. Preserve every original scope, policy/workflow pin, create-return, witness,
generation/fence, expired deadline, failed-run and no-competing-work join. An
authenticated administrator supplies only the original grant and dispatch IDs.
Native deletion remains a separate administrative action, never a Guest
retirement or a never-started claim.

Reuse the existing independently published accepted-failed AWS read-only
observer. Its closed request and response contain native create/action/resource
and auxiliary absence evidence; they contain no enrollment assertion. Authenticate
the exact observer source, description, normal creator bindings and catalogs
before and after the read. Validate all six original native reads, their closed
intervals and retained bodies, sanitized CloudTrail event/request identity,
instance lifetime, original root-snapshot descendants and primary ENI absence.
Join the observed AMI and account to the immutable create witness. Retain the
owning settlement's omitted false/empty auxiliary fields without upgrading them.

Add a new migration extending only future insert admission. Do not rewrite
historical migrations or existing records. The existing atomic terminal foreign
keys and immutable pointers remain in force. Preserve the accepted create,
witness, failed run and unknown ACK; append a separate `failed_disposed` terminal
with writer start state `unknown` and no serving, quiescence or savings authority.
A successor still requires a fresh generation, assessment and single-use grant.

## Consequences

No new AWS adapter, Guest image, callback replay, lease renewal or deadline
change is needed for this accounting path. Other AWS creators, enrolled or
installed originals, incomplete/non-absent native evidence and conflicting work
remain refused. The legacy Hetzner branch retains its original guards. Downgrade
refuses while modern AWS terminal records exist, preserving their supported
history.
