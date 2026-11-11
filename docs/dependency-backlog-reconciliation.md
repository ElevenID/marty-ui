# Dependency PR reconciliation

This consolidation carries the useful dependency and toolchain changes from ten
open pull requests onto the current source. The individual branches are inputs;
their old lockfiles are not applied over newer application code.

| Original PR | Preserved intent |
| --- | --- |
| [#764](https://github.com/ElevenID/marty-ui/pull/764) | Node 24.22.1, refreshed coherent npm locks, and frozen-install/audit validation. The incidental whole-graph refresh is narrowed as described below. |
| [#817](https://github.com/ElevenID/marty-ui/pull/817) | Material UI `^9.4.0`. |
| [#824](https://github.com/ElevenID/marty-ui/pull/824) | Exact Canvas contract Playwright 1.64.1. |
| [#1088](https://github.com/ElevenID/marty-ui/pull/1088) | Web Vitals `^6.2.3`. |
| [#1089](https://github.com/ElevenID/marty-ui/pull/1089) | Date Pickers `^9.16.0`. |
| [#1090](https://github.com/ElevenID/marty-ui/pull/1090) | i18next `^26.5.7`. |
| [#1835](https://github.com/ElevenID/marty-ui/pull/1835) | All 14 action pin updates, with the corresponding current-workflow assertions. |
| [#1855](https://github.com/ElevenID/marty-ui/pull/1855) | All UI development package updates, the MSW 3 migration, refreshed Bun lock, and matching Storybook runtime/plugins. |
| [#1856](https://github.com/ElevenID/marty-ui/pull/1856) | Browser test Playwright, Node types, Axios and EventSource updates. |
| [#1857](https://github.com/ElevenID/marty-ui/pull/1857) | All Python dependency floors and exact protobuf/compiler and preview-tool updates. |

## Deliberate scope of monthly maintenance

The monthly automation also proposed a broad refresh of every transitive npm
dependency. This consolidation retains the existing supported React 19.2.8,
React DOM 19.2.8 and React Router 8.3.0 resolutions, along with unrelated
transitive versions already in the current locks. It refreshes the graph needed
for the explicit pending dependency requests and keeps the repository's security
overrides. It does not claim byte-equivalence to the monthly automation's older
lockfiles. Future ordinary maintenance can advance the remaining ranges without
holding the specific reviewed updates open.

## Migration details

MSW 3's Node transport uses native fetch. A failed transport now exposes the
native `fetch failed` message. Idempotent create operations recognize that form
alongside the existing browser error forms, retaining the same operation key on
the single retry and preserving unknown-operation evidence if confirmation still
fails. Existing action-lifetime cancellation and explicit retry opt-out behavior
remain covered.

Cookie and cache options are fetch-client metadata rather than HTTP wire fields.
Their tests observe the actual fetch invocation while continuing to use MSW for
the response, so `credentials: include` and `cache: no-store` remain required.

Storybook's runtime and its React/Vite integration packages share the same patch
range. The Bun lock is updated with the npm lock so the frozen security install
can admit the new package requirements. Current workflow pin assertions follow
the pin updates; historical observed-run fixtures keep their original hashes.

The consolidation changes action versions without altering workflow permissions,
required checks, release approval rules, or private-fork access rules. Hosted
checks still qualify the final combined source before merge.
