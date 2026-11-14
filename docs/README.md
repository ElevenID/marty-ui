# Marty UI documentation

Start with the [repository README](../README.md) for product scope and qualification boundaries. This index groups development, operator, integration, and design material; historical status reports are not current release acceptance evidence.

## Start here

| Goal | Guide |
| --- | --- |
| Choose an installation path | [Installation paths and configuration owners](installation-paths.md) |
| Test a signed Linux candidate | [Linux installer tester guide](linux-installer-tester.md) |
| Develop locally | [Development setup](../DEVELOPMENT_SETUP.md) · [Quick start](../QUICK_START.md) |
| Find implementation code | [Repository navigation](../README.md#repository-navigation) · [Project structure](../PROJECT_STRUCTURE.md) |
| Call the API | [Machine API authentication](API_MACHINE_AUTHENTICATION.md) |
| Add or move repository files | [Repository layout conventions](development/repository-layout.md) |

## Architecture and design

- [Microservices architecture](architecture/MICROSERVICES.md)
- [UX contracts](ux-contracts/README.md) — component states, behavior, accessibility, and testing expectations.
- [Component quick reference](reference/COMPONENT_QUICK_REFERENCE.md)

## Development

- [Localization guide](development/LOCALIZATION.md)
- [Internationalization implementation status](development/I18N_STATUS.md) — retained progress notes; verify current coverage against code and tests.
- [Repository layout conventions](development/repository-layout.md)

## Deployment and operations

- [DevOps overview](operations/DEVOPS.md)
- [Manual readiness tasks](operations/MANUAL_READINESS_TASKS.md)
- [Release-readiness checklist](../RELEASE_READINESS.md)
- [Self-host production guide](../SELFHOST_PRODUCTION.md)
- [Self-host OpenBao guide](../SELFHOST_OPENBAO.md)
- [Self-host bundle guide](../SELFHOST_BUNDLE.md)
- [Disposable qualification runbook](selfhost-disposable-qualification-runbook.md)

## Testing and interoperability

- [OID4VCI testing guide](testing/OID4VCI_TESTING_GUIDE.md)
- [Official interoperability Docker guide](official-interoperability-docker.md)

## Project notes

These documents retain their implementation history and planning context; their status statements do not establish current production readiness.

- [Dashboard improvements](project/DASHBOARD_IMPROVEMENTS.md)
- [Open-source readiness](project/OPEN_SOURCE_READINESS.md)

## Operator and integration references

- [CONSOLIDATED_RUST_MIGRATION_ROADMAP.md](CONSOLIDATED_RUST_MIGRATION_ROADMAP.md) — cross-repository plan for replacing duplicated Python and Dart protocol kernels with single authoritative Rust implementations.
- [DEEP_LINK_SUPPORT.md](DEEP_LINK_SUPPORT.md) — OID4VCI deep-link format and backend wiring.
- [MIGRATION_GOVERNANCE.md](MIGRATION_GOVERNANCE.md) — migration lanes, reset-vs-upgrade policy, and profile-aware seeding strategy.
- [WALLET_ROUTING_IOS_COLLISION.md](WALLET_ROUTING_IOS_COLLISION.md) — iOS scheme-collision strategy: Digital Credentials API → per-wallet Universal Links → raw protocol fallback → user preference persistence. **Read this before adding a wallet or wiring an AASA.**
- [OID4VCI_AUTO_TRIGGER.md](OID4VCI_AUTO_TRIGGER.md) — auto-trigger flow for credential issuance.

Existing release-specific runbooks remain at their established paths in this first organization pass. Use the exact release's evidence and limitations when choosing operational instructions.
