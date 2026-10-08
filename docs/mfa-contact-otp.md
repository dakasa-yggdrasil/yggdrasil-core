# Email and SMS verification codes

Collaborators can enroll email and SMS as MFA factors alongside passkeys and
authenticator apps. A channel becomes a factor only after the collaborator
proves possession with a delivered six-digit code.

## Delivery configuration

`AUTH_EMAIL_INTEGRATION=<namespace>/<name>` selects an instance with
`send_email`; `AUTH_EMAIL_FROM` optionally selects its sender. This reuses
the password-reset email integration, but OTPs do not require a console
origin because messages contain no links.

`AUTH_SMS_INTEGRATION=<namespace>/<name>` selects an instance with
`send_sms`, such as the AWS adapter. Core supplies `phone_number`, `message`
and `sms_type=Transactional`. Provider credentials, region and sender policy
belong to the instance. SMS requires the existing envelope key to decrypt
the typed phone contact.

A channel is offered only when configured and its canonical contact is
available. Adapter `status=sent` proves provider acceptance, not mailbox or
handset delivery. Uncertain/failed sends issue no usable challenge.

## Enrollment and management

`GET /api/v1/auth/mfa/contact/options?token=<enroll token>` returns:

```json
{"email":{"available":true,"enrolled":false},"sms":{"available":true,"enrolled":false}}
```

Omit `token` for a live session. `GET /api/v1/auth/mfa/factors` includes the
same objects alongside existing factors. Neither full contacts nor binding
digests are exposed.

1. `POST /api/v1/auth/mfa/factors/contact/begin` with `channel` (`email` or
   `sms`) and optional enrollment `token` sends to the canonical contact.
2. Response: `challenge_token`, `channel`, RFC3339 `expires_at`, and
   `retry_after:60`.
3. `POST /api/v1/auth/mfa/factors/contact/finish` with the same optional
   `token`, `channel`, `challenge_token` and six-digit `code` proves possession.
4. Success: `mfa_enrolled:true`, ten recovery `codes`, `displayed_once:true`.
   Save these codes: successful enrollment replaces the recovery-code set.

Session-mode mutations enforce `X-CSRF-Token` against the live session.
Link mode is bound to the exact unconsumed enrollment link and is allowed
only before first MFA enrollment. Successful first enrollment consumes all
outstanding links. Proof, authority consumption, factor and recovery vault
commit together. Session mode permits adding more factors.

`DELETE /api/v1/auth/mfa/factors/contact/{email|sms}` requires the owner
session and CSRF proof, invalidates outstanding codes for that channel and
refuses removal of the last current primary factor. Passkey removal uses
the same transaction locks and counts current contact factors.

## Password login

Password login keeps the intermediate HTTP `202 auth.mfa_required` result.
Its `factors` include `email`/`sms` only after possession enrollment while
the contact binding still matches and delivery is configured.

Request a code with `POST /api/v1/auth/mfa/contact/login/begin`, supplying
`identifier`, `password`, `channel`. Core verifies the password before
sending. Complete `POST /api/v1/auth/login` using `identifier`, `password`,
`otp_channel`, `otp_challenge_token`, `otp_code`.

Proof consumption and session creation commit together, bound to the exact
verified password hash. Credential replacement or administrative MFA reset
cannot reopen an old proof after revocation. Only HTTP `200` establishes a
session.

## Security and recovery

Codes expire after five minutes and allow five attempts, reserved atomically
before comparison. Each collaborator/channel allows one send per minute
and five per rolling hour across enrollment/login, including failed sends.
Resending supersedes earlier codes for the same purpose/channel. Codes
cannot cross owner, channel, purpose, enrollment authority, password version
or contact binding.

Storage contains a SHA-256 token digest and HMAC code digest keyed by the
unpersisted random 256-bit challenge token. OTPs, tokens and delivery bodies
are absent from workflow/event/audit storage. Delivery errors omit provider
bodies. Rows older than 24 hours are pruned on the owner's next issuance.

Changing the email or redeclaring the typed phone invalidates its old factor;
the new destination needs enrollment. SMS possession does not change
directory `assurance:declared` into a general verification or consent claim.

Email-link password reset still accepts only an independent authenticator
or recovery code. Email OTP cannot serve as independent proof of the same
mailbox. Contact-only users recover with saved recovery codes or an admin's
full recovery. Full MFA reset clears contact factors/challenges alongside
the existing factors and password.

Regression tests run against migrated PostgreSQL in GitHub Actions. Provider
activation and actual inbox/handset receipt remain deployment checks.
