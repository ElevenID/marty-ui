# Signing Keys aggregate review manifest — 2026-09-27

This branch combines the reviewed Signing Keys changes from PRs #875, #876, #877, #878, #879, #882, #883, #884, #885, #886, and #889. Its parent is the merged #872 squash `0a82a8c79cae4fb93abd8c1813b7ffe89b8fd292`. The component PRs remain open until the aggregate has passed protected checks and merged; close them as superseded only after that merge.

## Patch identity

- The complete source patch from the old #872 head `084a2a5091eefc38ce29d0b5ca9c540c7139eedf` to the reviewed #889 head `1b5797736c2709a3b6340bb7555bd44d743a896a` applied cleanly onto the authoritative #872 squash. Its binary diff SHA-256 is `BACAD3495D6EB481868A222EFBBA91B32DD39007C0286E5DEAACDE36BD3EACB7`.
- Comparing the aggregate tree to the reviewed #889 tree yields only the three Cargo files already changed by Core 0.1.62 on main (`rust/Cargo.toml`, `rust/Cargo.lock`, `.github/feature-regression/rust-probe/Cargo.lock`), this review manifest, and the aggregate CI step. The aggregate lockfile retains the main Core 0.1.62 pins and corrects the gateway dependency from `marty-crypto 0.1.61` to `0.1.62`; `cargo +1.97.1 metadata --locked --offline` accepts it.
- The aggregate CI step runs all five ignored live Signing Keys contract suites on guarded disposable Redis DB 14 and 13, sequentially, with a test-only mock KMS token. It fails if the expected test count is not reported.

## Local gates

All local live tests used a disposable loopback Redis container and fresh DB 13/14 guard nonce. They did not use beta or production services.

| Gate | Result |
| --- | --- |
| `cargo +1.97.1 test --locked -p marty-signing-keys --lib` | 100 passed, 0 failed, 3 ignored |
| `public_config_resolve_live_contract` | 2 passed |
| `public_key_metadata_live_contract` | 2 passed |
| `service_rotation_live_contract` | 2 passed |
| `vdsnc_registration_live_contract` | 2 passed |
| `managed_key_create_live_contract` | 5 passed |
| Three authenticated Gateway Signing Keys route tests | 3 passed |
| `SigningKeysPage.test.tsx` | 11 passed |
| Signing Keys and Gateway scoped `cargo fmt --check` | Passed |
| `cargo +1.97.1 clippy --locked -p marty-signing-keys -p marty-gateway --lib -- -D warnings` | Passed |
| Signing contract JSON and CI workflow YAML parse; `git diff --check` | Passed |

The aggregate still requires independent exact-head maintainer review and protected CI before merging. This manifest records local evidence; it does not assert beta deployment or Python retirement.
