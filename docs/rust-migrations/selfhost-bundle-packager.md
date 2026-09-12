# Self-host directory and ZIP packager restoration

The implementation invoked by `make package-selfhost-bundle` was deleted by
`a8d238fe12f180621085c8ba5216455e6545bcf9` while that same commit retained the
Make target and its documented feature. There was no replacement packaging
owner: `marty-devops bundle-assets` only lists paths; `beta-evidence-bundle`
transports three deployment evidence documents and is not a customer bundle.

The narrow `marty-selfhost-bundle` Rust crate restores staging and optional ZIP
creation. It does not start containers, publish images, authenticate release
provenance, select production routes or change key custody.

## Frozen reference and retained behavior

Original source: `31287d26676872736820f97ae6d6d30d0d8e65f1`,
`scripts/package-selfhost-bundle.py`, blob
`77c04ba60f7a31432d210526f50e136f6bde0545`.
`scripts/capture_selfhost_bundle_reference.py --check` verifies that Git blob
before executing the original functions against fresh synthetic fixtures.
Its renderer is controlled; its directory copying and ZIP creation are real.

`contracts/selfhost-bundle-python-reference.json` records 18 transformation,
image-predicate and error cases, exact staged binary/text file contents, ZIP
file/directory members, and the original Compose argv. Rust replays those
observations. The capture's Windows executable-bit observation is explicitly
not a POSIX mode claim; Unix tests independently check retained read-only modes,
top-level shell executable modes and archive mode metadata. ZIP compression
bytes and timestamps are not falsely treated as portable deterministic output.

Retained features include manifest assets (and historical defaults when the
manifest is absent), recursive directories/binary files, the README rename,
nested output directories, default `dist/selfhost-bundle`, optional
`--archive BASENAME` with appended `.zip`, no-interpolate Compose rendering,
build removal and whole-bundle build/mutable-tag checks. Rendered runtime paths
remain relative, including folded required-variable selectors, quoted paths,
Windows verbatim paths and list-first `source` fields without lost sibling
fields. Compose `extends.file` inputs must be staged assets; their transitive
closure is removed only from the completed generated bundle after flattening.
Current-user `~`, platform-supported `~user` output/archive expansion and harmless
`./asset` notation are retained; expansion precedes archive suffixing. Parent
traversal remains rejected. Windows follows the original profile/USERNAME rules;
Unix uses read-only reentrant account lookup with checked results and bounded
buffer growth. Missing accounts fail rather than creating literal tilde paths.
The separate `selfhost-bundle-path-reference.json` records actual Python312
`Path.expanduser` observations with real platform parsers, synthetic environments
and controlled account results; the original 18-case artifact remains unchanged.
Replay with `scripts/capture_selfhost_bundle_reference.py --path-reference --check`.

## Explicit safety corrections

- No blind recursive replacement of arbitrary output paths. Existing output is
  rejected unless `--replace` verifies its complete generated inventory. The old
  directory is retained as a recoverable backup and reported to the caller.
- The additional `.marty-selfhost-bundle.json` inventory covers file hashes and
  directories. It identifies unchanged local output, **not** signed provenance.
- Publication uses atomic no-replace moves (Linux/Apple/Redox via existing
  rustix, Windows via `MoveFileExW` without replacement flags). Unsupported
  platforms fail closed. A late foreign destination is never overwritten;
  failed publication retains new staging and any prior-bundle backup.
- Existing archive paths are never overwritten, including with `--replace`.
  ZIP publication uses no-clobber persistence. Directory and archive publication
  are not claimed to be a single filesystem transaction: on ZIP publication
  failure the completed directory and any old backup remain intact.
- Symlink/reparse paths, traversal, repository/workspace roots and source/output
  overlap are rejected. Packaging parents are operator-owned; this is not an
  adversarial filesystem sandbox or a release signing mechanism.
- Strict validation checks decoded images and bounded nested interpolation
  alternatives. This fixes the original quoted-literal and `${TAG:-latest}` /
  full-reference-default gaps without changing the frozen legacy predicate or
  banning legitimate registry/version/digest expressions. Unknown required
  operator image values still require later resolved release validation.
- Compose receives only OS/executable discovery variables and packaged example
  configuration. It does not inherit application secrets/proxies or resolve
  operator secret files. Diagnostics are withheld on failure. A 60-second
  deadline and 25ms checks of both output streams terminate/reap excess output;
  the 8MiB observed-stream limit is not a hard OS filesystem quota.

## Acceptance ownership

The unignored `actual_cli_packages_and_renders_extracted_bundle_with_contained_asset_references`
test runs the real CLI and real Compose against the current repository's bundle
descriptor, compares the independently enumerated source asset inventory with
the complete output (only documented README/source-closure/generated-file
deltas), and checks exact bidirectional ZIP/output/extracted files and directory
membership. It renders the extracted model and verifies every static bind,
config, secret and environment-file reference exists inside the extracted root;
only the closed operator secret/state selectors are explicitly external.
The source checkout still exists during the test: this proves reference closure,
not operating-system denial of source access. A separate real CLI call verifies
successful archive-free generation and absence of a ZIP. It is part of mandatory
`cargo test --locked --workspace`, not an optional or fake renderer gate.
`MARTY_SELFHOST_BUNDLE_TEST_COMPOSE` only selects a standalone Compose executable;
its absence uses `docker compose`, never skips the test. Root-discovered Python
guards reject removed/ignored/cfg-disabled or shallower executable tests.
`MARTY_SELFHOST_BUNDLE_TEST_REPO` selects an explicit additional reviewed source
revision for local acceptance; default mandatory CI always uses its own checkout.

Local Windows proof covers both baseline UI `47f7a7649` and the clean native-owner
descriptor at `05f7df2df9496797e5764c8953b72a081ddfbf68`, using actual Compose,
directory creation and ZIP extraction. Hosted Linux qualification remains
required for POSIX permission/no-replace behavior. Packaging
acceptance does not replace native main/secret-loader/PG/signing/wallet runtime
acceptance or the aggregate beta deployment/soak.

Dependencies add the local crate plus `zip 8.6.0` and `typed-path 0.12.3` only.
ZIP defaults are disabled; Deflate reuses the existing flate2 Rust backend.
Its declared Rust 1.88 minimum is below workspace 1.95. Existing dependency
versions/edges, Core/MMF revisions and deployed image pins remain unchanged.
The new crate also consumes already-locked libc for Unix account lookup; no new
dependency version or unrelated package edge is introduced. Local Windows gates
exercise 17 Windows vectors; the 9 POSIX vectors and real Unix account-lookup
test remain mandatory hosted Linux qualification.
