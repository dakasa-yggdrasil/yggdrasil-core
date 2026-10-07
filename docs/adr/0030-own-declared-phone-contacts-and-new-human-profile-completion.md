# ADR-0030: Own declared phone contacts and new human profile completion

- **Status:** Accepted
- **Date:** 2026-10-06
- **Deciders:** DaKasa Platform
- **Scope:** yggdrasil-core / collaborator contact and human enrollment
- **Supersedes:** none
- **Superseded by:** none

## Context

Collaborator personal data is an extensible object consumed by directory and console readers. A phone entered in that object has no typed declaration, verification or disclosure contract. New human identities can originate in the administrative console, machine-managed person creation, bootstrap or a third-party identity provider. A form-only requirement would leave the other creation paths open, while a retroactive login requirement could lock existing people out during credential recovery.

## Decision

Own a typed, envelope-encrypted phone contact keyed by canonical collaborator UUID. E.164 validity proves formatting only. Record declaration time, actor and source on the server and expose its assurance as declared; do not imply OTP verification, provider reachability, messaging consent or channel engagement.

Use an explicit generic enrollment policy for newly created human collaborators. Manual creation must provide the phone when this policy is enabled. Automatically provisioned identities remain provisional until a self-profile completion step supplies it. Do not apply the new requirement retrospectively to existing people or block their credential recovery. Completion must be enforced by the Core before ordinary protected access and relying-party token issuance, independently of surface navigation.

Keep new typed phone values out of ordinary collaborator projections, identity events and logs. Separate self-contact access, privileged operator declarations and restricted machine contact disclosure. Operator phone reads require an exact contact-read grant: existing wildcard powers, administrative traits and observation mode are not an implicit grant to this new sensitive projection. Existing route authorization semantics remain unchanged. Existing generic personal data is not silently imported or labelled verified.

## Consequences

Deployment requires encryption readiness and a coordinated policy switch. Existing phone presence and provenance require a private, separately authorized backfill. Authentication, MFA, recovery and profile completion stay distinct. A declared phone never activates a messaging provider or proves opt-in.

## Related

- ADR-0019: restricted directory machine credentials
- ADR-0022: explicit credential configuration and fail-closed startup
