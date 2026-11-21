# Temporary dependency maintenance exception

RUSTSEC-2026-0543 identifies `chrono` as unmaintained, affects every version,
and provides no patched version. It is an informational maintenance advisory,
not a reported vulnerability. The approved exception is limited to this ID.
All other advisory settings, vulnerability checks, license checks, source
restrictions and crate bans remain in effect.

The exception expires at **2026-12-01 00:00 UTC**. The ordinary cargo-deny
entrypoint checks that deadline before downloading or invoking its unchanged,
digest-pinned tool. While this ID remains ignored, checks fail from the deadline
onward. The checker has no command-line or environment clock override. Removing
the ignore permits the ordinary audit to continue; expiry is not remediation.

The Marty platform maintainers own the migration before this deadline. Replace
the workspace's `chrono` consumers and SQLx integration, coordinate compatible
versions of pinned upstream dependencies, and verify timestamp serialization,
UTC/offset behavior and PostgreSQL timestamp compatibility. Remove this exception
after qualification. The temporary exception does not claim that migration is
complete or that the dependency is maintained. Changing the deadline requires
another reviewed policy decision through the normal protected source workflow.

Sources: [RustSec advisory](https://github.com/RustSec/advisory-db/blob/main/crates/chrono/RUSTSEC-2026-0543.md)
and [upstream maintenance announcement](https://github.com/chronotope/chrono/issues/1768).

## Retired frontend development risk disposition

On November 19, 2026, the source review for
[UI #2001](https://github.com/ElevenID/marty-ui/pull/2001) rechecked the
[primary GitHub advisory](https://github.com/advisories/GHSA-fc5q-39xc-vjpf).
GitHub marks GHSA-fc5q-39xc-vjpf withdrawn on November 18 and updated on
November 19, with the stated reason that it is not a security issue.
The temporary picomatch acceptance introduced in
[UI #1987](https://github.com/ElevenID/marty-ui/pull/1987) is retired.
This records an advisory withdrawal; it does not establish a patched package
version, bundle absence or general non-exploitability.

The review confirmed actual clean scanner results before removing admission:

- The [Security Scanning job](https://github.com/ElevenID/marty-ui/actions/runs/44575464897/job/135741771895)
  ran both real scanners successfully on November 19. Its PR source was
  `89bd5c6712f6739f5c1196b66d3de13980c00618`, checked out through integration
  commit `1fd80fcaffb9fc65fd1216974288eddba8c9bfa9`. The audit explicitly
  reported success without using the temporary disposition.
- Fresh local scans on the same candidate used Bun `1.4.4+38afee6c8` and the
  same scanner commands shown below. Both exited zero; Bun returned `{}`
  and npm returned an empty vulnerability map with every severity count zero.
  The raw JSON SHA-256 values were
  `ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356`
  for Bun and `c9a500aa694ae53fd484f38ec7ecf58c3036df89e88fd9dc13f39347f07a0f09`
  for npm. The policy retirement changes no dependency versions or lockfiles.

The entrypoint still runs these exact scopes:

```sh
bun audit --json --ignore GHSA-vfj7-8cjw-p6xm
npm audit --json --omit=optional --package-lock-only --audit-level=low
```

Every returned finding now fails, including the historical picomatch fixture
reports. The obsolete source-hash and expiry acceptance path is removed, so a
source change cannot inherit or renew that acceptance. There is no new ignore,
source-hash approval or deadline extension. The existing optional-prerenderer
braces ignore remains unchanged; npm continues to include nonoptional development
dependencies at its existing low threshold.

Duplicate JSON fields, malformed or incomplete reports, inconsistent vulnerability
counts, scanner errors and inconsistent exit statuses refuse admission. Both
scanner processes retain their timeout and noninteractive execution. The CLI
accepts no arguments and does not echo untrusted scanner documents. Regression
tests preserve these refusals and reject both historical advisory reports.
