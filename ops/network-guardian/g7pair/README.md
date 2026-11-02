# G7 network Guardian source

This independently versioned operational package admits the single next Core
image pair `[750d5e46, f8090403]`. Image f809 is the actual amd64 manifest built
from immutable Core source `c9f260432ce5a10886df0385c958ec7d643648df`; this later
Guardian source is a separate artifact. A Core build does not install it.

The historical G6 controller config remains `8b74f1de`. The current G7 config
is fixed at `d68912a7e24b68e6cc51faeedba4c0987c65b2a14d439d18483706bd3fd18fbf`.
It is the original G6 JSON with only the image pair and Root attestation
changed. All older image pairs, config pins, runtime14, endpoint/public CA,
Core service UID and overlap/no-readmission rules remain intact.

Two historical authorities remain distinct:

| Authority | Guardian source | Standing | Historical controller |
|---|---|---|---|
| Canonical G6 | `6c2cc19f` | `be5b2549` | `8b74f1de` |
| Actual G6 boot-v2 | `f3152cc6` | `faa6b2cb` | `8b74f1de` |

The canonical `g6_predecessor_*` fields stay unchanged. The two
`g6_boot_v2_predecessor_*` fields authenticate exact boot-v2 source/standing
bytes, its closed schema and the same canonical G6, d211/R13, Hub, original
refs and f5..g5 pair-standing prefix. Neither source/standing tuple is
relabelled or added as a fake image generation. Missing or mixed pairs refuse.

`PACKAGE.json` and `SHA256SUMS` bind all eight source modules and the future
Cold/Guardian units. The seven helper files and31 Owner method bodies retain
their exact F315 bytes. The expanded image-pair-chain AST hash is separately
named; `PAIR_STANDING_CHAIN` remains byte-identical. Operational tools under
`tools/` have their own reviewed hash roster and are outside this ten-file
source/unit inventory. No production standing is shipped by this manifest.

All old proof and recovery records retain their original physical lifetime,
source, standing, paths, hashes and budget meaning. The same three-per-boot
recovery limit and cooldown apply. Reads do not reset or create an epoch.
The new controller lifetime must earn its own actual original120 and native
initializer, then the owning Guardian daemon's first current15 and a separate
independent current15/all-four closure. Cache reuse rehashes every consumed
original and never turns historical qualification into current health.

Future units change only the reviewed source path/hash. Service limits,
dependencies, initial-boot handling, native47, bounded512 tail/closing reads,
transport and qualification deadlines remain unchanged. Both future Cold and
Guardian units must match the source; Cold and Hub are not rerun this boot.
Installation, once-only controller/Guardian stop-start custody, exact staged
standing checks and uncertain-outcome reconciliation require separate Root
review. This package supplies no automatic reset, fallback or replay.

CI explicitly retains and verifies the old G6 package while selecting G7 for
its new authority/config/manifest assertions. Historical PUBLIC fixtures keep
their original bytes and authority; native I/O is simulated. Passing source
tests is not a production network window, new actual120, Guest business
capacity or authorization to install or mutate the Core deployment.

See [ADR-0099](../../../docs/adr/0099-retain-canonical-and-boot-v2-guardian-authorities-across-a-new-core-pair.md).
