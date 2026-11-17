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
