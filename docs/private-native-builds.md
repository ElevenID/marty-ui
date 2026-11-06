# Native build access

Marty UI uses the existing pinned Git dependencies in
`ElevenID/isomdl-elevenid`, `ElevenID/ssi-elevenid`, and
`ElevenID/sd-jwt-rust`. The whole repositories can become private without
extracting replacement crates or changing upstream history, license files,
notices, or dependency URLs.

## Enable authenticated builds

The repository Actions secret `PRIVATE_FORKS_READ_TOKEN` must have only
Contents read access to those three forks. Set the repository Actions variable
`PRIVATE_FORKS_ENABLED` to exactly `true` only after the authenticated workflow
changes have been reviewed and deployed. Leave the variable unset or `false`
while preparing the cutover; existing public build behavior then remains active.

Native jobs first check their event without receiving the reader. Only trusted
same-repository pull requests, admitted merge groups, and repository-owned
branch/tag builds may fetch private dependencies. External pull requests and
Dependabot runs cannot receive native source access. An owner must review and
import such a change to an internal branch before native validation. Drain any
external or Dependabot queue entries admitted under the old policy before
activation. Same-repository writers are trusted with the private fork source;
the organization currently reserves that write access to its owners.

A separate step uses the reader only for locked dependency fetches. Its Git
credential helper responds only to the three exact GitHub repository paths and
does not write a credential into Git configuration. Later Cargo compilation and
tests run offline without the reader. Existing test commands, applicable job
matrices, CI Gate requirements, and binary release provenance remain in force.
The private manual coordinator is an optional additional validation tool; it is
not required to satisfy the public CI Gate.

## Source and cache boundary

Private mode disables public Rust Git/target/compiler caches and native Docker
cache imports/exports. The three optional native cache warmers are skipped.
Frontend and source-only checks retain their existing behavior. Native test
logs remain public and can contain diagnostics or source excerpts; private mode
does not make the public Actions log confidential.

The three canonical Dockerfiles receive the reader through a BuildKit secret
only in a dedicated fetch instruction. Cargo-chef materializes its manifests
without compiling before that fetch. Subsequent builds use an isolated Cargo
home offline with no reader mount and no compiler cache. Final runtime stages
copy the existing binaries and runtime assets; they do not copy that Cargo home
or build-only helper. Never pass the reader as a Docker build argument or image
environment variable, vendor private dependencies into this public repository,
or publish their source directories, Git caches, or intermediate image layers.
Normal compiled images and native packages retain their existing publication
and attestation requirements.

## Authorized local builds

Use the unchanged Git URLs with normal private-repository read credentials.
For a canonical Docker build, supply `--build-arg PRIVATE_FORKS_ENABLED=true`
and `--secret id=private_forks_read_token,env=PRIVATE_FORKS_READ_TOKEN`; the
environment value is a read-only token authorized for the three forks. Keep
intermediate/source cache exports disabled for that build. No token belongs in
a command argument, source file, or image.

Keep ordinary upstream fetch/merge maintenance in the private forks and retain
all required notices when distributing compiled Marty artifacts. Changing
visibility does not retract previously published source or artifacts. Removing
the variable later only restores anonymous build behavior; it does not make a
private fork public or restore unauthenticated access.
