# ADR-0091: Admit a same-build replacement after an external-cause failed-installed disposal, proven by a promoted peer Guest of the same build

- **Status:** Proposed
- **Date:** 2026-11-02
- **Deciders:** Giovanni Martins
- **Scope:** yggdrasil-core / capacity failed-installed Guest disposal replacement gate and operator resolution
- **Supersedes:** —
- **Superseded by:** —

## Context

Production Hetzner dimension `original_notify_hetzner_vm_members` has two
failed-installed Guest disposals:

- `ac198bfd` (terminal since 2026-10-26) blocks Guest source `548734eef627…`
  with profile `3bc51d81…`.
- `8ef5f76c` (gen8, preregistration `b8076d1e…`, requested 2026-11-02 09:21Z)
  blocks Guest source `b50976579e12…` with profile `c9b7933281c9…`. It was
  admitted without `replacement_mode`.

Once a disposal is terminal, `requireFailedInstalledReplacementTx` checks every
disposal of the dimension. A historical disposal (no `replacement_mode`) only
passes when the new binding changes **both** its Guest source and its profile
SHA (`failedInstalledReplacementChanged`). Each Guest build and profile
approved so far for Hetzner is either `548734`/`3bc51d81` or `b509`/`c9b79`, so
after `8ef5f76c` becomes terminal no binding the running Core approves can pass
the gate. The Core-bound mode (ADR-0084, `original_canary_core_bound_v1`)
is fixed when a disposal is requested, is tied to one Core build, and asserts a
Core-side cause. It is not available for `8ef5f76c`.

gen8 did not fail because of its Guest build. Its canary read was held because
the RabbitMQ user `dakasa-notify` had no read or configure permission on the
`notify.guest-canary.*` queues. That was fixed in production on 2026-11-02 at
about 07:20Z and made durable. Afterwards, AWS gen10 (dimension
`original_notify_aws_vm_members`, preregistration `2a23af4b…`) ran the **same**
Guest source `b50976579e12…` with its AWS profile `196c3ecd…`. It reached
intent phase `promoted` with an accepted canary read at about 07:34Z.

The only ways forward under the existing rule are a new Guest build plus a new
Core release with a new compiled approval, or a rule change. A new build would
change nothing about the cause, which was outside the Guest.

## Decision

### 1. One immutable admission per disposal (migration 85)

A new table, `capacity_guest_failed_installed_external_cause_admissions`, holds
at most one admission per disposal and per disposed preregistration. Rows are
never updated or deleted. Its foreign key points at the disposal's
**terminal** row. Each row records:

- the disposal, its scope and the blocked Guest source and profile;
- the complete digest of the admitted binding, which is the SHA-256 of the
  disposed Guest's own stored `binding_wire`, and the current policy id and
  checksum;
- the original failed run and its `finished_at`;
- the peer preregistration, its scope, Guest source and profile;
- the peer's accepted read challenge, with the challenge and return times;
- the peer intent's generation and fence, and its resource id;
- the admitting Core build and the issuer (`collaborator:<uuid>`);
- the fixed reason `external_cause_same_build_replacement`;
- the operator's cause evidence and its SHA-256;
- `original_failure_preserved=true` and
  `original_failure_cause_claimed_by_core=false`.

The cause evidence is opaque UTF-8 text of at most 8 KiB, with no control
characters other than tab, CR and LF. Core never parses it and never treats it
as authority. The table CHECK refuses the same controls with a regular
expression (PostgreSQL text cannot hold NUL, and `chr(0)` itself raises, so it
never appears in the CHECK).

A `BEFORE INSERT` guard takes the disposal's scope advisory lock. That is the
same key Go's `lockMutationScope` uses, and like migrations 83 and 84 the guard
refuses scope names that the two sides would encode differently. It then
re-derives every recorded fact from the original rows:

- **The disposal:** both its requested and terminal rows exist and agree on
  scope and on the blocked source and profile, and neither carries
  `replacement_mode`. The current intent of the scope still names this disposal
  as `terminal`.
- **The original failed run:** it is the run in the disposal's own
  `original_run` record, its status is `failed`, and its finish time is the one
  recorded.
- **The blocked build:** it is the disposed preregistration's own binding
  (`binding_wire` Guest source and `profile_manifest_sha256`).
- **The peer's scope:** it comes from the peer's own create grant, it differs
  from the disposal's scope, and the peer's own binding has the blocked Guest
  source.
- **The peer's read:** a `read` challenge of that peer with an `accepted`
  return. Both the challenge and the return were recorded strictly after the
  original failed run finished.
- **The peer's dimension:**
  - its intent is `promoted`, with no failed-installed disposal, at the
    recorded generation and fence;
  - the peer's resource still occupies a non-tombstone slot;
  - the peer has no retirement intent and no failed-installed disposal of its
    own.

### 2. The operator route

`POST /api/v1/ops/capacity/failed-installed-guest-disposals/external-cause-replacements`
and `GET …/external-cause-replacements/{preregistrationId}` use the same
god-mode operator gate and CSRF middleware as the other disposal lanes. The
POST body is closed: exactly `preregistration_id` (of the disposed Guest),
`peer_preregistration_id` and `cause_evidence`, all strings. It rejects
duplicate, missing, null or unknown keys, trailing data and bodies over
64 KiB. A string value with invalid UTF-8 bytes or an unpaired UTF-16
surrogate escape is refused rather than decoded to U+FFFD, so the stored
evidence and its SHA-256 are exactly the bytes the operator sent. Responses carry identities, hashes, times and derived facts, never the
evidence body. They state `cause_evidence_is_authority=false`,
`original_failure_cause_claimed_by_core=false` and
`other_disposals_still_checked=true`.

`AdmitFailedInstalledExternalCauseReplacement` works in one transaction under
the disposal's scope lock. It refuses unless all of the following hold:

1. The disposal of `preregistration_id` is terminal, and neither of its rows
   carries `replacement_mode`.
2. No admission exists for it yet.
3. The current intent of the scope still names that terminal disposal.
4. The original failed run is the exact run the disposal recorded, status
   `failed`, with a finish time.
5. The current policy binding of the disposal's dimension is the blocked
   binding exactly. The current policy is the single active version of the
   policy that admitted the disposed Guest, and it must have the disposal's
   scope. "Exactly" means:
   - the same Guest source and the same profile SHA;
   - deep equality with the disposed Guest's stored binding;
   - approval by the compiled registry (`GuestBindingAuthorityCurrent`).
6. The peer is a different preregistration whose stored binding has the
   blocked Guest source. Its witness and enrollment load. Its scope, taken from
   its own policy revision and confirmed by its create grant, is a different
   dimension.
7. The peer's dimension intent is `promoted` (read `FOR SHARE`), carries no
   failed-installed disposal, and has a generation at least the peer's.
8. The peer is a current member, read only from Core's own durable state:
   - its enrolled tuple still occupies its non-tombstone slot with the same
     resource id and creation time;
   - it has no retirement intent and no failed-installed disposal.
9. The peer has an accepted `read` canary challenge whose challenge and return
   were both recorded strictly after the original failed run finished. The
   earliest one is chosen. Its stored challenge belongs to the peer's
   preregistration, policy, profile SHA and native tuple.

The route calls no provider, sends no canary, and moves no intent, fence,
grant or slot.

### 3. The gate accepts exactly that unchanged binding

`requireFailedInstalledReplacementTx` keeps its loop over every requested and
terminal disposal of the dimension. A disposal is permitted when either holds:

- `failedInstalledReplacementPermitted` (the both-changed branch or the
  Core-bound branch, both unchanged); or
- an admission exists for that disposal and names exactly this binding:
  - the disposal has no `replacement_mode`;
  - the binding has the same Guest source and profile SHA as the blocked
    build;
  - `admitted_binding_sha256` is the SHA-256 of the disposed Guest's stored
    `binding_wire`, and the binding is structurally equal to that wire
    decoded.

`GuestBindingAuthorityCurrent` is still required for every disposal, and the
requested-equals-terminal count still applies.

An admission applies only to its own disposal. Every other disposal of the
dimension keeps its own check. In production, `ac198bfd` blocked
`548734`/`3bc51d81`, which `b509`/`c9b79` differs from in both fields, so it
still passes through the changed branch.

A requested disposal cannot be admitted, because the admission references the
terminal row. A changed member, origin or Core authority in an otherwise
same-build binding changes the digest and is refused.

The gate gets its authority predicate through an internal seam
(`requireFailedInstalledReplacementWithAuthorityTx`). Production always passes
`capacity.GuestBindingAuthorityCurrent`.

### Rejected alternatives

- **Let the operator assert "cause fixed" alone.** That would put human text in
  the place of evidence. The peer's accepted read of the same build, recorded
  after the failure, is the only thing Core counts.
- **Relax the both-changed rule to either-changed.** That would weaken the
  barrier for every historical disposal, not just this one.
- **Rewrite `8ef5f76c` with a Core-bound marker.** Disposal records are
  immutable, and the Core-bound mode asserts a Core-side cause that did not
  happen.
- **Ship a no-op Guest build plus a new compiled approval.** This is possible,
  but it changes no cause and costs a full Guest and Core release cycle.

## Consequences

- After `8ef5f76c` is terminal and admitted, gen9 can use the unchanged v9
  Hetzner binding, provided the running Core still approves it.
- If the peer's read is later found to be wrong, nothing reopens. The
  admission is permanent provenance, and the next failure of that build needs
  its own disposal.
- An accepted peer read is evidence about the Guest build in another
  dimension. It is not proof that the Hetzner-specific path (profile, provider,
  network) is healthy. The ordinary first canary of the next generation still
  decides that.
- Migration 85 is forward-only, and its Down step raises.
- The Postgres tests are wired into the disposition Source workflow
  (schema 85):
  - the migration 85 guards: one exact accepted admission, forged facts and
    unqualified histories refused, immutability;
  - the Go admission refusals;
  - the gate: unchanged binding only with an admission and the compiled
    approval, older and requested disposals still checked.
- The HTTP closed-body, authentication and summary tests are wired into the
  same workflow. All of these run only in CI.
- No end-to-end positive Go admission is tested. A validated production Guest
  policy, signed enrollment and canary chain cannot be fabricated in a test.

## Related

- ADR-0079 (extends: failed-installed Guest disposal and its replacement gate)
- ADR-0084 (relates-to: the Core-bound replacement mode, unchanged)
- ADR-0089, ADR-0090 (relates-to: the operator-lane pattern reused here)
