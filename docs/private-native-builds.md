# Native build access

The whole-fork privacy plan keeps the existing repositories and pinned Git
dependencies: `ElevenID/isomdl-elevenid`, `ElevenID/ssi-elevenid`, and
`ElevenID/sd-jwt-rust`. It does not extract replacement crates or change their
upstream history, license files, or notices.

## Prepared, inactive boundary

`PRIVATE_FORKS_ENABLED` is a repository Actions variable. Leave it unset or
`false` until an authenticated consuming build works in a private environment
and the native CI/release pause is ready to take effect. This change does not
set the variable or change repository visibility.

When the variable is exactly `true`, public jobs that resolve the Rust workspace
or compile native service/migration images fail before dependency setup or
cache access. This includes native CI, native release tools, cache warmers,
supply-chain checks, and credential/wallet acceptance tooling that compiles
Rust. Existing CI Gate assertions remain intact: selected native jobs must
still succeed, so their deliberate failure blocks the native CI/release path.

Web/source checks, source-only CodeQL, and web-only production builds remain
public. Product/nightly image guards target the `services` and `migrations`
roles; the web, Go OpenBao, and Java Keycloak builders do not consume these Rust
forks. Artifact-only consumers retain their existing provenance checks.

## Authorized native work

Run native validation against trusted, exact Core and UI commits in the private
[`ElevenID/marty-commercial-rust` build repository](https://github.com/ElevenID/marty-commercial-rust).
Its manual coordinator must obtain read-only access to the three forks in its
own private build context. Keep that credential, dependency source, build logs,
Cargo Git cache, and Docker intermediate layers out of this public repository's
Actions jobs and artifacts. Authorized local builds can use the same Git URLs
with normal private-repository read credentials; no dependency repinning is
needed merely because visibility changes.

The manual coordinator is an initial native validation path. It does **not**
yet report PR/merge-queue checks or produce accepted release artifacts. A
successful private run cannot be substituted for a required public check or
the existing release provenance. Those integrations must be implemented and
validated before native CI and releases can resume under the new model.

Enable the switch only at the coordinated cutover, after private authentication
is working. Removing it later only re-enables the old anonymous workflows; it
does not restore access to private forks or complete a rollback. Keep ordinary
upstream fetch/merge workflows in the private forks and preserve all required
license notices when distributing compiled Marty artifacts.
