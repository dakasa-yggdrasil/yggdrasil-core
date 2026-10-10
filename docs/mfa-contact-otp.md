# Automatic email and SMS verification codes

Email and SMS are always offered for password-login MFA using the contacts
already saved in the collaborator profile, when those contacts and delivery
are usable. No MFA contact enrollment, activation, verification setup or
per-user toggle is required. Passkeys and authenticator apps remain available.

## Delivery configuration

`AUTH_EMAIL_INTEGRATION=<namespace>/<name>` selects an instance with
`send_email`; `AUTH_EMAIL_FROM` optionally selects its sender. This reuses
password-reset delivery but OTP messages contain no link and need no console origin.

`AUTH_SMS_INTEGRATION=<namespace>/<name>` selects an instance with `send_sms`.
Core supplies the typed canonical phone, message and `sms_type=Transactional`.
Credentials, region and sender policy belong to that operator-owned instance.
SMS also requires the existing auth envelope key to decrypt the saved phone.
Provider `status=sent` proves acceptance, not inbox/handset arrival. Uncertain
or failed sends issue no usable challenge.

## Login

1. Submit `identifier` and `password` to `POST /api/v1/auth/login`.
2. HTTP `202 auth.mfa_required` lists `email` and/or `sms` from the current
   profile. This works even with no manual factors and no earlier MFA timestamp.
   Password verification alone never creates a session or marks MFA proof.
3. `POST /api/v1/auth/mfa/contact/login/begin` with `identifier`, `password`
   and `channel` sends to the saved canonical contact. Callers cannot select
   or override a destination. Response: opaque `challenge_token`, `channel`,
   RFC3339 `expires_at`, `retry_after:60`.
4. Complete `POST /api/v1/auth/login` with `identifier`, `password`,
   `otp_channel`, `otp_challenge_token`, `otp_code`.
5. Only a valid OTP commits its consumption, internal MFA proof timestamp,
   recent-session proof and session creation together. Response HTTP200 has
   `mfa_enrollment_required:false`. No contact-factor record is inserted.

The profile's current email/phone is authoritative on each new send. Changing
it does not require registration again: new codes use the new destination
immediately, while old pending codes and recent session proofs cannot transfer.
Restoring an earlier email or password cannot resurrect an old proof.

## Read-only account information

`GET /api/v1/auth/mfa/factors` includes `email` and `sms` objects:

```json
{"email":{"available":true,"automatic":true},"sms":{"available":true,"automatic":true}}
```

`GET /api/v1/auth/mfa/contact/options` returns the same channel metadata plus
`password_login_available`. It requires an own live session or existing
first-access link (`?token=...`). The extra flag says whether a local password
exists, so the existing optional-factor wizard never routes an SSO-only user
to a password flow. This read does not grant login authority. Federated provider
login keeps its existing separate contract.

Full contacts, code digests and bindings never appear in these responses.
Contact begin/finish enrollment and delete routes do not exist. The Console
shows automatic methods as read-only; saved contacts are managed in the profile.

## First access and password changes

Password setup returns `password_set`, `next:login`, no session or cookies when
automatic profile channels are usable. It does not force contact registration.
Protected routes still require actual MFA proof. Provisional old sessions can
be closed to reach password login without an enrollment redirect loop.

`GET /auth/session` exposes `password_change_required` and
`recent_contact_mfa_verified` from current database state. A successful OTP login
issues a recent-session proof valid for five minutes. The proof is not user
metadata: it binds the live session, active owner, current contact and credential
version, and is consumed once inside the password-update transaction.

`POST /auth/passwords/change` may send `use_recent_contact_mfa:true` with current
and new password, the own live session and `X-CSRF-Token`. Expired, consumed,
changed-contact/credential and revoked-session proofs fail closed. Traditional
inline authenticator/recovery proofs remain supported. The Console asks for a
fresh login when a contact-only user's recent proof expired.

## Limits and recovery

Six-digit codes expire after five minutes and allow five atomic attempts.
Each collaborator/channel allows one send per minute and five per rolling hour,
including failed sends. Resending supersedes older codes for that purpose/channel.
Codes cannot cross owner, channel, purpose, contact or credential epoch.

Storage contains SHA-256 challenge-token digests and HMAC code digests keyed
by the unpersisted random 256-bit challenge token. OTPs and provider message
bodies do not enter workflow/event/audit records. Errors omit provider output.
Old challenge rows are pruned on the owner's next issuance; recent proof rows
cascade with their authentication sessions.

Directory phone assurance stays `declared`; this does not claim general identity
verification or consent. Full administrative MFA recovery preserves saved
contacts, clears the old password/proofs and sessions, then setup/login uses
those contacts again automatically. Email-link password reset still requires
an independent authenticator or saved recovery code; contact-only users without
those proofs use administrative recovery.

GitHub CI executes required migrated PostgreSQL/HTTP regressions for automatic
first login, contact changes, challenge budgets, races, proof freshness and
password changes. No local tests or production activation are implied.
