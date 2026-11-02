# ADR-0099: Retain canonical and boot-v2 Guardian authorities across a new Core pair

- **Status:** Proposed
- **Date:** 2026-11-02
- **Deciders:** Giovanni Martins
- **Scope:** Owned operational network Guardian / image-pair succession and immutable authority inheritance
- **Supersedes:** —
- **Superseded by:** —

## Context

ADR-0097 introduced the G6 boot-v2 Guardian without changing the G6 controller
image pair. Canonical G6 source `6c2cc19f` and standing `be5b2549` remain
authorities for original records; the actual boot-v2 successor is source
`f3152cc6` and standing `faa6b2cb`. Both stand on controller config `8b74f1de`.
Treating the boot-v2 successor as another image-pair generation would invent
history. Replacing canonical G6 with boot-v2 would lose authentic old full120,
Cold and recovery records and could reset their budget accounting.

A later Core image needs a new controller pair and therefore a new controller
physical lifetime. Core image source R and separately versioned Guardian
operational source P have different provenance: P can admit an actual image
built from R without claiming that the image was built from P. Historical
qualification is not current network health or qualification of that new
controller lifetime.

## Decision

Version G7 as a distinct owned source package. Freeze historical G6 at the
actual amd64 manifest `750d5e46` and config `8b74f1de`, then append exactly one
G7 pair `[750d5e46, f8090403]`. Admit only actual manifest references for image
and imageID. Keep all earlier pair/config facts, overlap and no-readmission
guards. The current G7 config must equal the independently derived exact hash
`d68912a7e24b68e6cc51faeedba4c0987c65b2a14d439d18483706bd3fd18fbf`.
Only image pairs and a new concrete Root attestation differ from the original
G6 controller JSON; runtime14, endpoint, public CA and Core service UID remain
unchanged. The image remains bound to its original immutable Core source R.

Retain canonical G6 through the existing two `g6_predecessor_*` fields and
authenticated reader. Add exactly two dedicated boot-v2 fields:
`g6_boot_v2_predecessor_guardian_source_sha256` and
`g6_boot_v2_predecessor_standing_config_sha256`. Authenticate the actual F315
source bytes and faa6 standing at fixed paths, its closed old schema, original
canonical G6 fields, historical config8b74, d211/R13 ancestry, pair prefix,
same Hub and original proof/context references. Keep the current head equality
at d689 while preserving the historical equality at8b74. Neither an arbitrary
digest nor a source/standing pair assembled from different authorities is an
accepted successor.

Keep `PAIR_STANDING_CHAIN` through g5 byte-identical. Install canonical G6 and
boot-v2 as two dedicated authority pairs in both owner initialization and
static authentication. All original records retain their exact source,
standing, physical identity, paths, hashes, fixed120 windows and possible
effects. Both authorities continue to count under the same three-per-boot
recovery budget and cooldown; no record or counter is reset or relabelled.

Preserve all seven helper files and the31 original Owner methods byte-for-byte;
only initialization/static authority wiring changes inside Owner. Preserve
the initial-boot branch, authenticated current-lifetime initializer, finite512
current reader, all-ref cache rehash, native47 comparison, transport, kernel,
qualification deadlines and recovery mechanics. A new controller must earn
its own original full120, followed by its Guardian daemon's own current15 and
an independent fresh read-only closure. An old proof cannot supply its
initializer handles, a fresh current window or business capacity.

Package matching future Cold and Guardian units with the new source path/hash,
retaining all service limits and dependencies. The controller unit/config
transition belongs to the separately reviewed operational package. Cold and
Hub are not rerun during adoption. Any operational once-only STOP/CAS/START
must retain original possible-send/return custody and hold on uncertainty;
this source package grants no automatic retry, fallback, reset or replay.

## Consequences

The image-pair chain and source-authority chain become explicit independent
axes. Future builders and staged/live standing-output checks must validate
both dedicated authority pairs and the unchanged pair-standing prefix rather
than assuming one standing authority per image generation. Current config and
historical config checks remain exact despite their different values.

The package manifest binds eight source modules, two future units, all31
preserved Owner bodies and both ancestry pairs. Its expanded pair-chain hash
is labelled as changed; only the unchanged standing-chain hash is claimed
unchanged. Operational tools have their own reviewed roster and hashes.

CI must explicitly select both old G6 and new G7 packages and retain the
original historical fixture bytes and assertions. Added G7 cases reject
missing, mixed, foreign or corrupt authorities, config pins, references and
current15 evidence. Simulated native boundaries validate source behavior;
they do not qualify a host, a new full120, live current health, Guest readiness
or capacity. Exact operational source review and fresh host evidence remain
separate gates before installation or Core image CAS.

## Related

- [ADR-0097](0097-bind-current15-to-an-authenticated-current-lifetime-initializer.md) — extends its initializer and immutable historical-proof contract.
- [G7 source package](../../ops/network-guardian/g7pair/PACKAGE.json) — exact source, future units and preserved-body inventory.
