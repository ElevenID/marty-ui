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

## Temporary frontend development risk disposition

GHSA-fc5q-39xc-vjpf reports repeated-extglob regular-expression CPU denial in
picomatch through 4.0.7; no patched version is listed. The reviewed graph contains
picomatch 2.3.2 and 4.0.7 only under development tooling. Its production dependency
graph contains no picomatch. Static delivery and absent direct imports support
limited production exposure; they do not prove bundle absence or non-exploitability.
CI/development CPU-denial risk remains. Keep existing process and job limits.

Owner: Marty platform maintainers. Tracking: [UI #1987](https://github.com/ElevenID/marty-ui/pull/1987).
This exact advisory disposition expires **2026-11-24 00:00 UTC**. The audit script
binds it to the exact reviewed dependency files, both installed versions/paths,
dev-only metadata, frontend source/scripts, Vite configuration and production
image/edge inputs. Changed context or expiry refuses admission while the finding
remains. Actual UTC is sampled after scans and again at final admission after context
validation. There is no CLI/environment clock override. A new graph or source change
requires a new explicit review, rather than inheriting this assessment.

Bun and npm still run and every other finding, including low severity, is refused.
The existing optional-prerenderer braces disposition remains scoped as before.
Npm still audits nonoptional dev dependencies with its existing low threshold;
no omit-dev or severity relaxation is introduced. Indirect npm chains must resolve
to the exact reviewed advisory, remain dev-only and include an actual advisory
root; cycles alone cannot authorize acceptance. Malformed reports, unknown causes
and scanner failures refuse. Clean audits after real remediation need no extension.

TODO (Marty platform maintainers, before November 24): adopt a verified upstream
security release, or a separately reviewed pinned patch for both installed major
versions with compatibility/adversarial checks. Remove this temporary disposition
after remediation. No working patch or fixed release was established here, and
this exception does not claim either. Production connector work remains outside
the Canvas cleanup; this disposition preserves a protected source integration gate.

Sources: [GitHub advisory](https://github.com/advisories/GHSA-fc5q-39xc-vjpf).
The linked [upstream PR 194](https://github.com/micromatch/picomatch/pull/194)
addresses different wildcard behavior and is not treated as a security fix.
