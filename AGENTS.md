# AGENTS — yggdrasil-yggdrasil-core

## Spec-driven docs (ADR + scratch) — mandatory

Two layers, federated per repo (the domain-wide model is defined in the monorepo root
`docs/adr/0001-adopt-adr-plus-scratch-model.md`):

- **`docs/adr/NNNN-title.md` — the tracked, curated record.** One durable architectural
  decision per file. Write an ADR ONLY when a decision has lasting architectural consequence
  (a contract, a topology choice, a convention others must follow). Not for routine work.
  Template: `docs/adr/TEMPLATE.md`. Index: `docs/adr/README.md`.
- **`docs/superpowers/**` — gitignored working scratch.** Brainstorming specs, implementation
  plans, and sub-session handoffs live here. Local-only; git does not track it. Disposable.

**Immutability:** never rewrite the Decision of an Accepted ADR. To change a decision, write a
NEW ADR that supersedes the old one and flip the old one's Status to `Superseded by NNNN`.

**Handoffs:** a sub-session still writes its handoff to `docs/superpowers/` and the main agent
still reads it off disk (anti-race). It is scratch — NOT versioned. If the session made a
durable decision, record that as an ADR; the handoff itself is disposable.

**Staleness:** a recalled memory or a `docs/superpowers/` scratch spec may be outdated — verify
against the current-status ADR and the code before asserting it as fact.

**Context files are durable-only (freshness discipline).** `CLAUDE.md` and `AGENTS.md` hold only current-state, durable instructions and policies — things expected to stay true. They MUST NOT accumulate time-bound content: no "recent work" or session-log sections, no dated phase/deploy status, no commit SHAs cited as progress, no machine-specific absolute paths. That content rots inside a durable file. Route a lasting decision to an ADR (`docs/adr/`, immutable, point-in-time); route transient status to gitignored `docs/superpowers/` scratch. Enforced in CI by `.github/workflows/context-freshness.yml` (fails on reintroduced time-bound sections and on structurally-broken ADRs).
