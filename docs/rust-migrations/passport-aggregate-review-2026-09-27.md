# Passport Rust aggregate review — 2026-09-27

This draft stacks the passport migration and beta acceptance source on Signing
Keys aggregate PR #913. Its parent is the exact reviewed #913 head
`10c7b6f62f86dd88720bc9d22450ba9bdfaea67c`. The aggregate source tree
before this note is `a7480d3538a974678787439550bf1ab747e2b384`, matching
local reviewed union `e413c1e89e8dd8bc2df96c7602b1582aac135119`.

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

The protected #913 merge and this aggregate's protected checks remain
required. Physical provider allowlisting and live evidence remain blocked
pending governed provider details, KMS-backed issuer profiles, signed runtime
provenance, rollback proof, and nine-route acceptance. Python retirement PR
#305 remains draft until those gates pass. This note records local source and
test evidence; it does not claim deployment or acceptance.
