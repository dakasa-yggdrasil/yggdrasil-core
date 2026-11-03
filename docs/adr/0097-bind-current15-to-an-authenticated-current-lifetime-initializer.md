# ADR-0097: Bind current15 to an authenticated current-lifetime initializer

**Status:** Proposed
**Date:** 2026-11-02

## Context

The owned network Guardian's finite512 current15 reader always selected the
historical Core262/R43 initializer. After a reboot, the unchanged controller
legitimately initializes the same compiled 47-object structure through a new
zero-mutation owned read adoption and writes its own full120 proof. Its native
handles differ from the historical boot. Comparing them to the old initializer
correctly refuses `SAME_HONEST_ORIGINAL_INITIALIZER47_HANDLES_BY_EXPLICIT_KIND`,
despite a valid new lifetime. Replacing old handles, resetting the original
proof or weakening the kernel guard would destroy the evidence contract.

The G6 Guardian and standing pair are respectively
`6c2cc19f1f962d9d8eaec0cd5e6f813bf49004f8ff6fef9c9fe9f8f0310d8f1b`
and `be5b25495056bd25e1512827b5ccbe7236f84928b4d20515f5000383771dcc79`.
Their existing records include per-boot recovery spending and an immutable
original full120 qualification. A reader correction must inherit them without
claiming a new Core pair or a new controller start.

## Decision

Version the bounded `g6pair-boot-v2` operational source package independently
of the Core binary. Keep the initial-boot Core262/R43 selection unchanged.
On a later boot, select only the exact current controller physical lifetime's
original qualification, under a closed authenticated source/standing pair.
The identity binds boot, PID, start ticks, invocation, monotonic start, command
hash and initial-lifetime flag. Fixed ledger paths bind the original qualified
record, prefix and closing suffix; every consumed byte must match its SHA.
Every prefix row must match the same boot, PID and invocation, without cursor
duplication or backward/future timestamps. The existing coverage/journal math
must reproduce the original full120 window and original strict current15 at
the original finish, with the original bounded periodic eight-rule reads.

Expose the authenticated historical initializer measurement separately from
`original_qualification_exists`, which remains a boolean wrapper. Only the six
initializer fields reach the unchanged native kernel comparison. Provenance
retains the original identity, authority and exact proof references. The
current native 47-object structure must still match by explicit object kind,
and read adoption must never be relabelled as an apply echo. The current15
reader still requires its new finite512 tail, one closing suffix, unchanged
coverage/expiry rules, current native kernel, WG and transport observations.

Cache only recomputation of immutable historical proof bytes within the same
owning process. On every use, reread and rehash all three references, recheck
the exact current identity and closed authority pair, and invalidate the cache
on any consumed-byte change. Cache output carries no current window, health,
new epoch, packet delivery, Guest or capacity authority.

Authenticate the exact G6 standing bytes through dedicated
`g6_predecessor_guardian_source_sha256` and
`g6_predecessor_standing_config_sha256` fields. Keep the Core pair chains and
controller config unchanged. Add the old G6 pair to the same closed authority
roster used by existing boot/recovery accounting and reauthenticate it in the
static guard. Old records retain their source, standing, identity, fixed120 and
budget meaning. No original record is reset, rewritten or relabelled; the same
three-per-boot recovery budget and cooldown continue to count G6 operations.

Package matching future Cold and Guardian units with the successor source
path/hash, because Cold also authenticates the installed Guardian unit. The
operational adoption is separate and requires exact host review. This source
decision authorizes no controller start, Core CAS, runtime/seal change, ledger
write, service restart or production adoption.

## Consequences

A later lifetime can prove that today's native handles belong to its own
authenticated initializer while retaining the historical anchor. Missing,
foreign, corrupt or stale evidence remains a refusal. The original kernel,
coverage, journal and bounded-tail contracts retain their bytes, and unchanged
recovery/budget methods are pinned in the package manifest.

CI replays three exact compressed PUBLIC originals from an actual later boot,
tests the old initial-boot branch and current-lifetime selection, joins the
reader to the unchanged kernel guard and finite tail under simulated native
I/O, and rejects identity/authority/reference/hash/handle/AST/echo/expiry
failures. This validates source behavior, not a production network window.
There is no local functional execution and no production installer in this
package; operational review and new fresh host evidence remain independent.
