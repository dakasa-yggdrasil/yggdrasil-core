# AI docs freshness stamp

The reconciliation gate measures this source diff and actual generated context.
Earlier reviews remain in Git history and their owning Source/CI receipts.

verified_at_commit: 11508d6ec82ce2870929d72cad9157202f1a8084
verified_diff_sha256: 61c7621445c163fb39511274bfee2f0e235e6eff00958af940c576c0c6b58286
reconciler_schema: 1

Reviewed the exact published Commons dual-reader commit and complete tracked-tree
SHA256, the unchanged complete source selection, bounded deterministic v2 producer,
index paths and per-leaf hashes/sizes/counts, and all current service-contract
references. Static artifact comparison preserves every894 prior source fact after
normalizing the existing empty build-constraint default. Other10 evidence envelopes
are byte-identical. Two leaves plus index occupy147040bytes; limits stay128KiB per
file,2MiB including index,16 leaves and4096 unique facts.

CI first runs the actual new checker against published complete v1 Core34d664,
then verifies current v2 generation, every union fact and the same complete actual
source-tree walk. Independent whole bounded review reported no open finding.
Only static parsing, formatting/diff checks and the released Source/context
and reconciliation generators ran locally. No local tests/builds/vet or product
execution occurred. Actual CI remains required; this change activates no provider,
worker, private factory, capacity owner or production switch.
