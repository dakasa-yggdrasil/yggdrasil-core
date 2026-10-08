# ADR-0034: Bind delivered MFA codes to canonical contact possession

- **Status:** Proposed
- **Date:** 2026-10-08
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / collaborator authentication

## Context

Collaborators need email and SMS OTPs alongside passkeys and authenticators.
Directory contacts are declarations, which prove neither possession nor
authentication authority. Providers must stay outside Core; password reset
already sends an email link.

## Decision

Keep contact MFA possession in separate state and bind every proof to the
canonical collaborator, current contact, purpose and enrollment authority
or exact password hash. Activate only after atomic consumption of a delivered
OTP. Bind email to the normalized primary email and SMS to its typed contact
declaration version/time. Use configured `send_email`/`send_sms` integrations.

Persist hashed random challenge tokens and HMAC code digests, serialize
attempt/send budgets in PostgreSQL, and commit login proof with its session.
Administrative recovery invalidates factors/challenges with old credentials.
Email-link password reset keeps requiring an independent authenticator or
recovery code instead of another proof of the same mailbox.

## Consequences

Contact changes require new possession proof. Directory assurance remains
declared. Provider acceptance and human receipt remain separate. Missing
delivery configuration prevents offering a channel for login. Contact-only
accounts need saved recovery codes or admin recovery after password loss.

## Related

- ADR-0030: canonical declared contacts and profile completion.
- [Contact OTP API and operation](../mfa-contact-otp.md).
