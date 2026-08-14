# Rust migration language-composition evidence

`scripts/report_rust_migration_composition.py` creates the commit-pinned source
and dependency evidence required by phase 9 of the consolidated Rust migration
roadmap. It reads `docs/rust-migration-ownership.json`, measures only Git-tracked
files, and maps canonical and legacy source back to each migration capability.

The final report must be produced from clean, immutable checkouts of all six
repositories. The command fails if a tracked file is modified or a required
repository mapping is missing:

```powershell
python scripts/report_rust_migration_composition.py `
  --require-all-repositories `
  --ownership C:\evidence\marty-ui\docs\rust-migration-ownership.json `
  --repository ElevenID/Marty=C:\evidence\Marty `
  --repository ElevenID/marty-authenticator=C:\evidence\marty-authenticator `
  --repository ElevenID/marty-core=C:\evidence\marty-core `
  --repository ElevenID/marty-credentials=C:\evidence\marty-credentials `
  --repository ElevenID/marty-subscriptions=C:\evidence\marty-subscriptions `
  --repository ElevenID/marty-ui=C:\evidence\marty-ui `
  --output evidence\rust-migration-composition.json
```

Capture the baseline with the same repository set and ownership manifest before
the gated deletions. After the deletion PRs land, pass it with `--baseline` to
include per-repository language and dependency additions/removals:

```powershell
python scripts/report_rust_migration_composition.py `
  --require-all-repositories `
  --ownership C:\evidence\marty-ui\docs\rust-migration-ownership.json `
  --baseline evidence\rust-migration-composition-baseline.json `
  --repository ElevenID/Marty=C:\evidence\Marty `
  --repository ElevenID/marty-authenticator=C:\evidence\marty-authenticator `
  --repository ElevenID/marty-core=C:\evidence\marty-core `
  --repository ElevenID/marty-credentials=C:\evidence\marty-credentials `
  --repository ElevenID/marty-subscriptions=C:\evidence\marty-subscriptions `
  --repository ElevenID/marty-ui=C:\evidence\marty-ui `
  --output evidence\rust-migration-composition-final.json
```

The report includes each repository's exact commit, dirty state, maintained
source files/bytes/physical lines/nonblank lines by language, and dependencies
declared in Cargo, Python, Node, and Dart manifests. Capability records expose
the same metrics for canonical and legacy ownership paths. Missing paths remain
explicit evidence; they are not converted to an empty successful result.

Generated, vendored, fixture, snapshot, coverage, and build-output directories
are excluded from the maintained-source totals. Their aggregate source metrics
remain in `excluded_from_maintained_source`, and the exact exclusion list is
embedded in every report. Database migrations are not excluded because they are
maintained runtime source.

`--allow-dirty` exists only for local investigation. Reports created with it
record `dirty: true` and are not acceptable as release or promotion evidence.
