# Open-source readiness

This repository is being prepared as the public Marty UI and service
distribution. `marty-subscriptions` remains private and contains payment,
checkout, subscription, commercial price-catalog, and billing authorization
implementation.

## Implemented boundary

- The public UI uses a no-op commerce extension by default and can inject a
  separately supplied extension at build time with
  `MARTY_COMMERCE_EXTENSION_PATH`.
- The public gateway starts without commerce routes or middleware and exposes a
  provider-neutral `MARTY_GATEWAY_EXTENSION_MODULE` hook for downstream images.
- Billing services, payment-provider secrets, commercial catalog data,
  migrations, deployment definitions, and release inputs are excluded from the
  public distribution.
- CI runs `scripts/check_oss_boundary.py` to prevent known commerce code and
  credentials from returning.
- Dependabot, dependency review, a security policy, and contribution guidance
  are configured for the public repository.
- Tagged public container releases generate GitHub artifact attestations after
  the repository becomes public.
- Release builds consume exact PyPI/npm versions and OCI digests from the stack
  lock; they do not build sibling repositories.

## Audit status (2026-07-16)

- The current-tree OSS policy and commerce-boundary audits pass.
- All Marketplace and reusable Actions are pinned to full commit SHAs.
- Full-history Gitleaks 8.30.1 passes. Historical fixture, generated-output,
  example, and documentation findings are accepted only by exact fingerprint
  in `.gitleaksignore`; no broad secret rule or path is disabled.
- The service boundary suite passes 429 Python tests and the affected frontend
  surface passes 20 tests.
- The UI production image builds from digest-verified API-core and blog release
  tarballs without sibling repositories and passes a production-topology smoke
  test.
- Visibility remains private pending legal approval. Registry-independent
  GitHub Release bootstrap workflows are prepared; no real release lock is
  fabricated before the corresponding tags and artifacts exist.

## Required before changing visibility

1. Confirm the copyright holder, final license, notices, contributor agreement
   policy, and third-party asset/license inventory with counsel.
2. Keep the complete-history Gitleaks gate required and review any new finding;
   rotate a real credential and rewrite history before publication if one is
   ever identified.
3. Run the full CI, migration, self-host, and real tagged release rehearsal from
   a clean clone with no access to `marty-subscriptions`.
4. Tag the GitHub Release bootstrap dependencies, record their immutable URLs
   and digests in `release/stack-lock.json`, and run the public integration,
   upgrade, rollback, and no-commerce suite against that lock.

## GitHub administrator checklist

- Make the repository public only after the history and legal gates pass.
- Enable CodeQL default setup, secret scanning, push protection, Dependabot
  alerts/security updates, and private vulnerability reporting.
- Create a `main` ruleset requiring pull requests, the OSS boundary check,
  tests, dependency review, and CodeQL; block force pushes and branch deletion.
- Restrict default workflow token permissions to read-only and allow write
  permissions only in the tagged release jobs that publish packages or
  attestations.
- Make the GHCR packages public and verify anonymous pulls.
- Configure release environments, reviewer requirements, tag protection, and
  immutable releases as appropriate for the organization.
- Select an organization code of conduct, support policy, maintainers/CODEOWNERS,
  issue forms, and whether GitHub Discussions should be enabled.
