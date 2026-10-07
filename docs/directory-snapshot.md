# Restricted directory snapshots and declared phone profiles

Core owns canonical collaborator identity, lifecycle, formal leadership and
declared contact provenance. A consumer owns its own participation, message
consent, delivery and report policy. A declared phone is not OTP verification,
WhatsApp consent, provider identity or proof of ownership.

## Human enrollment

`YGGDRASIL_REQUIRE_NEW_COLLABORATOR_PHONE` defaults to `false` for coordinated
cutover. When enabled, server-side collaborator creation requires canonical
`phone_e164` (`+` followed by ASCII digits, first digit nonzero, at most 15 digits).
There is no national-number guessing or country allocation validation.
Encryption requires the existing 32-byte `YGGDRASIL_AUTH_KEK_BASE64` key.

First bootstrap and newly provisioned OIDC identities instead persist
`phone_profile_required=true`. Their login/MFA/setup/recovery and own profile
completion routes remain available; ordinary API access and native code/token
issuance remain blocked until completion. Existing people are not backfilled or
required to supply a phone to reset/recover their credentials. Turning enrollment
policy off does not clear an already persisted completion requirement.

`GET/PUT /api/v1/me/contact/phone` operates only on the current human identity.
PUT accepts `{phone_e164:string}` and records `self_profile` provenance.
`PUT /api/v1/console/collaborators/{id}/contact/phone` uses the existing edit
permission and records `operator_assertion` with the authenticated actor. It
returns the newly declared value, never the previous value.
Operator GET on that route requires the exact `yggdrasil:view_contact_phones`
grant through a current active team/membership and active Yggdrasil-self instance.
Wildcard/admin authority and RBAC warn mode do not imply this sensitive grant;
no existing grant is automatically added. Grant and contact read share a
repeatable-read snapshot, and a successful audit write precedes disclosure.
Contact reads and declaration responses use `Cache-Control:no-store`.

The typed registry is encrypted and separate from legacy generic
`personal_data`, which may already contain older contact information. This
feature does not import, inspect, publish or reclassify those generic values.

## Machine snapshot

`GET /api/v1/directory/snapshot?limit=100[&include_phone=true][&cursor=opaque]`
uses only directory-machine authentication. `directory.snapshot` is required;
phone projection additionally requires `directory.contacts.phone`. Only exact
UUIDs in `allowed_external_identity_instances` disclose external links. Old
lookup/read/action capabilities retain their original routes and meaning.
Snapshot-enabled inventory requires `YGGDRASIL_DIRECTORY_SNAPSHOT_HMAC_SECRET`
of at least 32 bytes, with no fallback. Do not store live secrets in examples.

Schema 1 response:

| Field | Meaning |
| --- | --- |
| `revision`, `observed_at` | Opaque principal/projection revision and fixed first-page UTC time |
| `offset`, `limit`, `total_records` | Combined record counts across all projected arrays |
| `complete`, `next_cursor` | Terminal-page flag and authenticated continuation |
| `contacts_included` | Whether the separately authorized contact projection is present |
| `collaborators` | UUID, slug, display name, lifecycle, manager, primary team, version, update time, `phone_profile_required` |
| `teams` | UUID, slug/name, free-text type/status, parent, resolved owner UUIDs, update time |
| `memberships` | UUID, team/person UUIDs, active flag, start/end boundaries, update time |
| `external_identities` | UUID, person UUID, exact instance UUID, external ID, update time |
| `phone_contacts` | One typed contact state per person, only with phone capability |

Collaborator lifecycle is `pending_start|active|on_leave|suspended|offboarded`.
Collaborator version 0 is valid. Team type conveys no authority; only exact
active status is active. Formal leadership is resolved team owners and the
manager chain, never job title, membership role or primary-team hint.
Membership authority uses `active` plus an active team and inclusive
`starts_at <= observed_at <= ends_at`; nil boundaries are open.

Phone states are `missing|declared|ambiguous`. `missing` means no typed contact,
not absence from generic legacy data. Declared records carry `phone_e164`,
`assurance:declared`, `declared_at`, declaration source and positive contact
version. Duplicate destinations are `ambiguous` and omit the number. The DTO
never includes ciphertext, wrapped keys, fingerprints or declaration actor.

Limit defaults 100/max 200, cursor expires after 10 minutes. Send `include_phone`
on every contact page; repeated limits must match the cursor. Each request
loads one bounded complete graph in a read-only repeatable-read transaction.
Invalid references/cycles and exceeded bounds fail closed without truncation.
Revision binds data and effective principal identity/lifecycle/capabilities/
allowlists, including rotation. `observed_at` stays stable across the cursor.
The effective credential is also bound internally even if rotation metadata is
unchanged; its digest is never a public JSON, log, audit or cursor field.
Drift answers 409 `directory.snapshot_changed`; discard the incomplete read
and restart at offset 0. Credential/capability refusals are 401/403.

A consumer must collect every contiguous page 0..total under one revision and
time before replacing its projection or pruning people. A terminal page alone
does not prove earlier pages were collected. Preserve the last complete view
on failure. Attributed responses/refusals require synchronous audit, without
phones, cursors, ciphertext, credentials or arbitrary data in logs/errors.

## Cutover prerequisites

Apply migration 53 through the normal migration owner, configure envelope and
snapshot HMAC keys, review separate machine capabilities/instance allowlist and
any human contact-read grant, deploy both Core and Console, then enable required
new-profile policy. Do not enroll existing humans again. Any backfill is a
separate authorized operation with declared provenance; live values never enter
repository artifacts or command output. CI proves the real migrated PostgreSQL
contact/profile/snapshot scenarios; local tests are prohibited.
