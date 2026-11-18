# Passport Rust aggregate review — 2026-09-27

Signing Keys aggregate PR #913 merged to protected main at
`c70aa64492f135d3ffd54dc10c8a9867fc39528f`. This passport migration and
beta acceptance aggregate is rebased on that exact main commit. Its original
source tree matched local reviewed union
`e413c1e89e8dd8bc2df96c7602b1582aac135119`.

The union includes passport aggregate #881 through the restacked #917
physical-profile and producer integration; #915–#917 workflow artifact
downloads have the independently reviewed repository binding from #917
`9d58ea57334c74a364403363901d357786e5b7e7`. It also includes the
#903 → #905 → #908 → #909 acceptance evidence chain and parallel #907 managed
SOD verification. The #909 and #907 merge results match all changed source
paths from their exact heads. Separate KMS hardening branches are excluded.

Local checks on the union tree:

| Gate | Result |
| --- | --- |
| Rust Gateway, Signing Keys, and Issuance `cargo check --locked` | Passed |
| Issuance Rust library unit tests | 558 passed, 1 ignored |
| Issuance `cargo fmt --check` | Passed |
| Passport provisioning and physical selector Python tests | 134 passed |
| Beta acceptance, release contract, and CI workflow Python tests | 195 passed |
| Independent exact-tree review of #917 workflow bindings, #909, and #907 integration | No P1/P2 findings |

The first protected aggregate run found that an unconditional provider-ingress
service URL changed the frozen default base Compose peer set. The fix moves
that URL into opt-in passport provider overlays, adds rendered Compose
regression coverage, and passed 68 focused tests, 91 adjacent tests, all 12
base-native renderer models, self-host renderer models, and conformance Compose
checks. An independent reviewer found no P1/P2 in the exact fix. This
aggregate's protected checks and merge-group gates remain required.

Physical provider allowlisting and live evidence remain blocked
pending governed provider details, KMS-backed issuer profiles, signed runtime
provenance, rollback proof, and nine-route acceptance. Python retirement PR
#305 remains draft until those gates pass. This note records local source and
test evidence; it does not claim deployment or acceptance.
