# ADR-0033: Preserve current declarations during conditional contact writes

- **Status:** Accepted
- **Date:** 2026-10-07
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / operator contact declaration
- **Supersedes:** none
- **Superseded by:** none

## Context

An authorized operator may declare an existing person's contact during a reviewed
cutover. A person can complete their own declaration before that write. A blind
upsert would overwrite a legitimate current declaration; granting sensitive
contact-read access just to inspect absence would disclose unnecessary data.

## Decision

Extend only operator phone PUT with optional `expected_version`, an integer at
least zero. Zero requires no typed declaration; a positive version must match the
current record. Null and malformed versions are invalid. Lock the canonical
collaborator first, matching every supported contact writer, then compare version
before encryption, mutation, completion or successful declaration audit.

A mismatch returns409 `contact.version_conflict`, preserves the current value,
version, provenance and binding, and never discloses its value. This conditional
write needs the existing operator edit authority, not a contact-read grant.
Existing interactive writes without the optional field keep their semantics.
Self-profile PUT rejects the operator-only field and keeps ADR0030's owner-bound
completion, recovery and independent MFA boundary.

## Consequences

Reviewed absence-only backfills cannot overwrite a racing self declaration. An
unknown acknowledgement followed by the same expected version fails closed after
a successful original write; no automatic retry or inference of an old contact
is introduced. Declared provenance remains separate from verification/consent.
Actual backfill and secret provisioning remain separately authorized operations.

## Related

- ADR0030 (declared contact authority refined without retrospective enrollment)
