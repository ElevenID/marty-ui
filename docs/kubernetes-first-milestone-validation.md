# First Kubernetes development trial — 2026-11-05

## Result

The standard infrastructure path passed its live bootstrap and same-node reboot
checks. **Application acceptance is blocked on a corrected signed runtime.**
The tested nightly panics when several services construct verified Redis TLS
clients with both Rustls providers enabled. The source correction and its
regression test are included in [PR #1809](https://github.com/ElevenID/marty-ui/pull/1809).
This report does not claim a successful application login, credential issuance,
complete gateway readiness, or consumer-installer qualification.

## Exact tested inputs

| Input | Value |
| --- | --- |
| Trial | Isolated AWS Free-plan development node; 2 vCPU, 8 GiB RAM |
| Host | Eligible `m7i-flex.large`, Ubuntu 24.04, encrypted 40 GiB gp3 |
| Cluster | K3s `v1.36.6+k3s1`, secret encryption enabled |
| Package manager | Helm `v3.22.1` |
| Certificate controller | Official cert-manager `v1.21.3` chart |
| Secret server | Official OpenBao chart `0.30.6`; signed Marty OpenBao 2.5.5 image |
| Runtime release | `v1.1.265-nightly.20261105.41944060538` |
| Runtime source | `9594f06f9c3c42180f9ef9a6ce2e93cb2f8556ad` |
| Producer | Nightly release run `41944428724`, attempt `1` |
| Last live chart source | `c4a3cac13e5b3377766ece1acf083ce946c28bb9` |
| Shutdown deadline | Absolute systemd timer: `2026-11-05 22:55:46 UTC` |

The account's Free plan and remaining credits, instance eligibility and AMI
eligibility were checked before launch. This trial did not create an EKS
cluster, NAT gateway, AWS load balancer, domain or paid account upgrade. Existing
demo instances remained stopped. Private credentials and recovery material are
retained only in the private operator state on the trial node.

## Observed live results

| Check | Result and evidence |
| --- | --- |
| Official tools | K3s, its installer, Helm and the release verifier binaries passed their pinned checksum checks. |
| Cluster | Node, DNS, Traefik, local-path storage and metrics became Ready. |
| Public HTTPS | cert-manager obtained a production IP certificate using HTTP-01 and the short-lived ACME profile. The operator browser reached Traefik over valid HTTPS. The application route returned `no available server` while gateway readiness remained blocked. |
| Release verification | Existing Sigstore and SLSA verification succeeded on EC2 for the complete five-subject installer artifact set. Images came from its authenticated digest inventory. |
| OpenBao | Initialized once; native Raft storage, static auto-unseal and the signed plugin loaded successfully. Existing native producers generated scoped application credentials and published the Kubernetes Secrets. |
| Redis | The cert-manager CA and Redis leaf became Ready; Redis ran with plaintext disabled and verified TLS probes. Organization and other services reached Ready using the new TLS configuration. |
| Keycloak | The native strict configuration Job completed after social login was explicitly disabled without Google credentials. User authentication through the complete application was not established. |
| Migrations | Several initial schema migrations completed. The second migration Job failed in native bootstrap on the Rustls provider panic. Issuance schema/readiness and full application acceptance remain incomplete. |
| Actual reboot | A changed Linux boot ID proved a host reboot. K3s returned to Ready; OpenBao unsealed automatically with the same cluster ID. |
| Persistence | The names, UIDs, bound volume names and phases of all four PVCs were unchanged: OpenBao, PostgreSQL, Redis and applicant storage. This establishes volume retention, not an issued-credential readback. |
| Certificate/timer retention | Public and Redis certificates remained Ready. The original shutdown deadline was unchanged after reboot. |
| Shutdown | The trial instance was stopped early and confirmed `stopped` at approximately 21:49 UTC. All five pre-existing demo instances also remained `stopped`. The encrypted disk and private diagnostic state were retained; storage remains an allocated resource. |

Before reboot, the partly started installation used approximately **2541 MiB**
of memory and **169 millicores** in one metrics sample. Immediately after
reboot, a sample showed **2427 MiB** and **1892 millicores** during startup.
Because several services were failing, these samples do **not** establish the
capacity of a healthy complete installation.

## Corrections produced by the trial and configuration audit

The Helm package now supplies verified Redis TLS, preserves upstream Redis
startup behavior, disables unconfigured social login, retains the public HTTPS
port in managed issuer configuration, supplies Flow's authenticated HTTPS
signer endpoint and CA, supplies Presentation Policy and Applicant with the
existing issuance API key required by their native API calls, and uses the
signer's Redis database for bootstrap registry records. The final configuration
audit checked all 18 service contracts and resolved all 87 secret-backed file
references against their volume projections and native Secret catalog.

The runtime correction explicitly selects the standard AWS-LC Rustls provider
before TLS construction in all 34 executables copied by the two signed service
image recipes. It follows the existing signing-service pattern and changes no
certificate validation. Thirty-one executables use a small helper in the
existing service-runtime crate; three standalone tools use the same standard
initialization directly. Dependency versions are unchanged.

Local validation passed **74 focused packaging tests**, including actual Helm
lint/render and release/bootstrap refusal tests. A separate **Rust 1.95
isolated-process regression passed**: it reproduces ambiguous implicit provider
selection with both providers compiled, then verifies explicit and repeated
initialization permits TLS client/server configuration. Two independent
reviewers checked the integration and substantive corrections. The Kubernetes
Helm package CI workflow also passed on the pushed correction checkpoint.
`cargo check --locked --manifest-path rust/Cargo.toml --workspace --bins`
passed with Rust 1.95, covering compilation of the entire workspace's binary
targets. The repository's protected-source CI remains a separate required gate.

## Protected-source CI follow-up

The complete PR CI run at `79c9acf` finished with one substantive failing job:
[Release Contract Tests](https://github.com/ElevenID/marty-ui/actions/runs/42117585720/job/127564190021).
Its existing real-`kubectl` Secret schema test exceeded the fixture's 20-second
aggregate deadline. The Rust image builds, native operators on both
architectures, service test matrices, credential lifecycle browser gate, lint
and security jobs passed. The separate Helm, CodeQL and policy workflows also
passed. A skipped installer-trial image job is not counted as a pass.

The failing integration path launches 33 real clients sequentially. Its test
budget is now 120 seconds; ordinary fixture calls keep the 20-second deadline,
and real client requests retain their three-second timeout. Publication still
stops on the first failure. The harness also terminates its owned POSIX process
group on timeout or interruption before tearing down the local API fixture.
No application code, Secret validation or release admission check changed in
this follow-up.

All **55 tests in the affected file passed without skips** using the same
`kubectl v1.37.2` as the CI runner. This includes the real 33-Secret client
contract and a regression proving a timed-out descendant releases its lock,
returns promptly and attempts only the first Secret. The local real-client
check took approximately 1.7 seconds; it does not establish the cause of the
slower CI run. The new checkpoint must still pass protected-source CI.

## Remaining acceptance sequence

1. The runtime correction completed the normal protected-source CI and merged
   in PR #1809 as `9cd6028da879a34b305bb643203e4a462f55f036`.
2. Use the existing signed nightly producer for the resulting exact main
   source. Authenticate its complete artifact set using the unchanged verifier
   and project its immutable images into Helm values.
3. Qualify the corrected chart/runtime on a bounded development trial with
   valid native credentials. Require every core workload to become Ready and
   both Jobs to complete before testing user journeys.
4. Run the existing-helper Kubernetes acceptance driver: real operator login,
   normal issuer/template configuration, native issuance, OID4VCI redemption,
   issuer signature and holder binding verification, then exact persisted
   transaction and credential readback after reboot.

The application workload identities are valid for eight hours and the
migration bootstrap token for two hours. Retained trial state must not be
treated as an indefinitely resumable installation. Public certificate renewal,
application-credential renewal, storage backup and production availability are
distinct concerns; only the bounded development behavior above was tested.

## Acceptance preparation follow-up — 2026-11-06 UTC

A fresh AWS inventory read found the original Kubernetes trial and all five
other retained development instances stopped. No instance was started for
this follow-up. The previously published runtime still preceded the Rustls
correction, so it was not used for another application trial.

Source review found two additional problems before live acceptance:

- The acceptance driver called internal issuance routes through the public
  gateway and sent the backend-only `offer_ttl_seconds` field. It now uses the
  public `POST /v1/issuance` and `GET /v1/issuance/{issuance_id}` contract and
  leaves the offer lifetime to that contract. The gateway continues to reject
  unknown request fields; no runtime API was widened.
- One-replica application Deployments used rolling updates with
  `maxUnavailable: 1`. Pinned Helm 3.22.1 waits for desired replicas minus
  maximum unavailable replicas, so that configuration could accept zero Ready
  pods. Single-replica applications now use `Recreate`, preserving the no-surge
  budget while requiring one Ready pod. The applicant remains a single writer;
  other applications with multiple replicas retain their rolling strategy.

The chart/bootstrap/provenance suite passed all 76 focused tests with no skips,
including actual rendering with the checksum-verified Helm 3.22.1 binary. The
new readiness regression also rejected the original chart as a negative
control. Four Node contract tests passed with controlled browser/HTTP
boundaries and the existing OID4VCI/signature helpers. They exercise issuance,
private-state retention, readback without new issuance, and rejection of a
changed stored hash or live issuer key. Restoring each old issuance URL or the
unsupported TTL field independently caused those tests to fail with the
expected 404 or 422 response.

These checks establish the source corrections; they do not establish
successful live application acceptance. The next trial still requires the
corrected signed runtime and the complete acceptance/reboot/readback sequence
above.
