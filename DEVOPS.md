# GitHub automation and releases

`marty-ui` uses GitHub-hosted standard runners for pull requests and releases. Fork pull requests receive no secrets and no write token. Self-hosted runners are not part of the public workflow trust boundary.

## Pull requests

The repository CI workflow runs the open-source boundary check, tests, and builds from released dependencies. The default `GITHUB_TOKEN` permission is read-only. Marketplace actions and reusable workflows are pinned to full commit SHAs.

Repository settings must require approval before an outside collaborator's workflow runs. Required checks, dependency review, CodeQL, secret scanning with push protection, and branch protection are configured in GitHub rather than bypassed in workflow code.

## Component inputs

The release workflow consumes an immutable `release/stack-lock.json`. It must identify exact SemVer versions and commits for every component and immutable digests for OCI artifacts. Python and JavaScript dependencies come from PyPI and npm; source checkouts and repository-access PATs are not supported release inputs.

## Stack release

A protected `v*` tag runs `.github/workflows/cd.yml`. The workflow:

1. validates the stack lock and component evidence;
2. verifies OCI digests and GitHub provenance;
3. builds and attests the UI, services, and migration images;
4. checks that released images contain no commerce configuration;
5. checks out the exact public integration-suite commit;
6. reconstructs the stack from artifacts and runs the public smoke suite; and
7. publishes signed SBOMs, checksums, provenance, release notes, and `stack-manifest.json`.

The `stack-release` environment protects publication. Signing uses OIDC-backed keyless Cosign wherever possible. Registry credentials or repository PATs must not be added to fork CI.

## Cost and runner policy

Only `ubuntu-latest`, `windows-latest`, and `macos-latest` are allowed in public workflows. Larger-runner labels and public pull-request access to self-hosted runners are rejected by policy checks. The organization should retain a zero paid-usage Actions budget as an additional guardrail.

## Release order

Publish the shared dependency artifacts first (`marty-core`, `marty-common`, protocol packages, CLI API core, and blog). Publish verifier/authenticator artifacts next, then create the first `marty-ui` stack lock and release. Commerce overlays remain private and have separate internal automation.
