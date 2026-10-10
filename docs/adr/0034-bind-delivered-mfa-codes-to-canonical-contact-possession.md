# ADR-0034: Bind delivered MFA codes to canonical contact possession

- **Status:** Proposed
- **Date:** 2026-10-08
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / collaborator authentication

## Context

Collaborators already have email and phone in their profile. These contacts
must be available for OTP MFA at password login without another registration,
activation or optional factor record. Contact declaration remains distinct from
an actual authentication proof.

## Decision

Offer email/SMS automatically from the canonical profile whenever that contact
and provider delivery are usable. Never require a per-user contact factor row.
Verify the password before sending; bind every code to owner, channel, current
contact, exact credential epoch and login purpose. Consume the valid OTP and
create its session atomically. Only that real proof updates internal MFA posture.
Track TOTP confirmation independently of this shared posture. An unfinished
authenticator setup cannot become confirmed through a contact proof.

Keep delivery provider-neutral and preserve challenge, resend and attempt budgets.
Bind recent contact-authenticated session proof to owner, current contact and
credential epoch for one password change within five minutes; the proof is
server-issued, never caller metadata, and consumed in the password-update transaction.

Keep email-link password reset dependent on an independent authenticator/recovery
code. Existing federated provider authentication remains a separate contract.

## Consequences

A changed profile contact is usable for new codes immediately; old pending codes
and recent session proofs become invalid. Directory assurance remains declared.
There is no user-controlled registration, enable/disable or deletion for contact
methods. Provider acceptance is separate from code receipt. Setup routes to password
login when automatic contacts are usable and still never creates a session alone.

## Related

- ADR-0030: canonical declared contacts and profile completion.
- [Automatic contact OTP API and operation](../mfa-contact-otp.md).
