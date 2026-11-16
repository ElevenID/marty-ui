# Public GitHub repository bootstrap: ElevenID/canvas-integration

This is the creation checklist for the public repository. The repository must be public from creation; do not create a private staging copy.

## Repository settings

- Owner: `ElevenID`
- Name: `canvas-integration`
- Description: `Independent Canvas LMS integration for ElevenID using the public Common Gateway API`
- Visibility: **Public**
- Default branch: `main`
- Initialize with README: no (bootstrap commit below will be the first reviewed commit)
- Add .gitignore: no (use the reviewed repository-specific one)
- License: AGPL-3.0, matching Marty-ui unless a legal review explicitly approves a different license
- Preserve issue and PR workflows; do not enable unrestricted Actions write permissions.
- Enable secret scanning and push protection where available.
- Enable Dependabot alerts and dependency review.
- Enable CodeQL for the languages actually selected.
- Require pull requests, required checks, and CODEOWNERS review for security-sensitive paths.
- Use squash merge unless the organization has a more specific repository standard.
- Do not add production environments, credentials, secrets or deployment targets during repository creation.

## Initial contents

Create the repository with a clean, reviewed initial commit. Do not import the full Marty-ui Git history or all files with "canvas" in their path.

Initial files should include:
- `README.md` — scope, architecture, public Gateway-only rule, local development and security limitations.
- `LICENSE` — AGPL-3.0 and preserved notices.
- `SECURITY.md` — responsible disclosure and supported release policy.
- `CONTRIBUTING.md` — PR, testing, formatting and review requirements.
- `CODE_OF_CONDUCT.md` — organization standard.
- `CODEOWNERS` — owners for connector, gateway contract, deployment and security files.
- `.gitignore` — language/runtime/build-specific exclusions.
- `.github/workflows/ci.yml` — build, unit/integration tests, dependency checks and architectural boundary tests.
- `.github/workflows/security.yml` — secret scanning, dependency review and CodeQL.
- `docs/architecture/BOUNDARY.md` — the strict Common Gateway/API-key boundary.
- `contracts/gateway/` — only reviewed public Gateway schemas, no internal service DTOs.
- `connector/` — initially empty application structure or minimal compiling service skeleton.
- `deployment/` — examples with placeholders only; no live hostnames or secrets.

## Public repository content gate

Before the first push, scan every staged file and all imported history for:
- API keys, OAuth client secrets, Canvas access/refresh tokens, private keys, certificates with private material, signing grants and KMS/OpenBao credentials;
- customer/tenant identifiers, real Canvas base URLs, private hostnames, email addresses, student/learner data and non-synthetic evidence;
- AWS account/resource identifiers, private recovery data, internal operational logs, database dumps and production backups;
- proprietary binaries, generated artifacts, unreleased internal notes and private security findings;
- embedded credentials in Compose, Kubernetes, shell, PowerShell, Python, Rust, JavaScript, YAML and test fixtures.

Only synthetic fixtures and explicitly public standards/contracts may be published. A clean new Git history is required; cherry-pick or reconstruct selected source commits with provenance rather than copying Marty-ui history.

## Boundary checks required before first merge

CI must reject:
- Marty internal crate/package imports;
- direct Marty DB/Redis configuration or database driver usage for core persistence;
- internal service DNS names, private service URLs, `/internal/*`, service API keys and signing grants;
- privileged Gateway keys in client/browser bundles;
- Gateway calls without the server-side API-key client, explicit organization context, stable DTO validation and idempotency where needed;
- connector deployment network access to core private networks or data stores.

Network policy must permit only Canvas endpoints, connector-owned storage/secret services and the public Common Gateway origin. Static scans are not a substitute for runtime network isolation.

## Initial README statement

The public README must state prominently:

> This connector integrates Canvas LMS with ElevenID through the public Common Gateway API. All connector-to-ElevenID requests use an organization-scoped API key. Direct access to Marty services, databases, signing infrastructure, or private APIs is unsupported and prohibited.

## Creation and handoff status

The repository has not yet been created. The available browser connection in Chat mode is read-only, and the GitHub connector exposes repository read/write content operations but no repository-creation operation. Create this public repository through the signed-in GitHub webpage, then the GitHub connector can populate it and open its first pull request.
