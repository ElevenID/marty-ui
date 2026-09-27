# Passport beta acceptance evidence

`scripts/collect_passport_beta_acceptance.py` records a bounded prerequisite
report from an already deployed **official aggregate beta** release. Run it on
the beta host with the deployment's artifact directory:

```powershell
$env:PASSPORT_ACCEPTANCE_API_KEY = '<organization-scoped key from governed beta secrets>'
py -3.12 scripts/collect_passport_beta_acceptance.py --artifact-dir C:\path\to\beta-artifacts --output C:\path\to\private-evidence\passport-beta-prerequisite.json --verify-attestation
Remove-Item Env:PASSPORT_ACCEPTANCE_API_KEY
```

The collector checks the exact source and `marty.stack/v1` manifest identity,
each required running beta Compose container and digest-pinned image, and the
public Gateway's authenticated capability response and unauthenticated denial.
It does not write Docker environment values, the API key, or HTTP bodies to the
report. Keep the report in a private evidence directory. A local worktree
snapshot, missing passport service, drifted image, unready capability, or
unexpectedly open endpoint makes collection fail.

After the protected release is deployed and managed issuer profiles plus the
CSCA/DSC chain are enrolled, add `--application-file` with a private test
application JSON. This opt-in mode requires `--verify-attestation` and a ready
authenticated KMS issuer capability before it mutates beta. It creates one
application through Gateway, generates data groups and SOD, submits to the
bureau, polls production status, records an operator quality decision, and
activates the result. The report records exact route outcomes and hashes of
the input and job identifiers; it never writes applicant fields. This covers
seven application route identities. Capability checks add an eighth. Flow
ownership and the signed provider webhook remain separate probes. A passing
quality decision is not evidence of physical booklet quality. A failed run
writes a minimal `blocked` report and exits nonzero.

The protected manual `Passport Beta Prerequisite Evidence` workflow runs on
the beta WSL2 runner with the `beta-lifecycle` environment. Its input points
to the official deployment artifact directory on that runner. The optional
application exercise reads the beta organization's key and synthetic test
application from environment secrets. The workflow uploads only the sanitized
report, never the application file. It rechecks release and container identity
after the mutating probe so a concurrent beta change cannot be hidden.

The emitted schema is `marty.passport-beta-acceptance/v1` and its status is
always `blocked`. `--verify-attestation` checks the release checksum and
GitHub attestations for the manifest and all three UI OCI images; the result
sets `release.signed_manifest_verified`. Verification constrains the signer to
the official `cd.yml` workflow on protected main at the exact deployed source
commit and rejects self-hosted signer provenance. It requires authenticated `gh`
access to the release repository. The following probe keys
remain unverified until protected acceptance runs execute and publish exact
artifact lineage: `managed_csca_dsc_chain`, `sod_signature`,
`nine_route_gateway_flow`, `packaged_image`, `physical_bureau_submission`,
`signed_bureau_callback`, `legacy_drain`, `rollback`,
`production_isolation`, and `physical_booklet_verified`. The last key requires
independent provider evidence of a real personalized booklet. The beta bureau
simulator's status and callback cannot establish it. Separate supported base
Compose, self-host, and Kubernetes acceptance remains mandatory before Python
retirement.
