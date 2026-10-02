# Passport Rust qualification coordinate: 1.1.220

The 1.1.219 release stopped before promotion because the pinned public-stack
integration harness did not start native issuance. The corrected, independently
reviewed harness is published as `marty-integration-tests@v1.2.81` from protected
main. Its Rust overlay starts native issuance, selects it for migrated delivery
in retained Python, routes Auth, Applicant, Flow, and Gateway to the native
owner, and requires native health. The isolated artifact stack passed seven
public tests against the exact 1.1.219 build digests; its 995 unit tests passed
with two skips. The scoped stack was destroyed and production host preflight
passed before and after.

The stack lock selects `marty-ui@1.1.220` as the next unused pre-deletion
qualification coordinate and pins the exact `v1.2.81` source archive digest.
Merge this eligibility change through protected CI and maintainer review,
then use `prepare-stack-tag.yml` and `cd.yml` on one exact protected-main SHA.
Do not create the Marty UI tag or release by hand. Verify signed manifest,
attestations, checksums, source, and every OCI digest before the protected
disposable passport proof. This release is not a beta deployment. Continue
with the [aggregate beta acceptance sequence](next-aggregate-beta-acceptance.md)
and preserve production.

The protected release claim and publication succeeded on 2026-10-02 at commit
`86f059ff26a4a289b865a73ea4bdca50f58d2e28`. The subsequent disposable
producer did not pass: OpenBao's primary Docker network mode was the owned
`callback_signing` network, while the partial teardown guard expected only the
owned `private` network. The job failed closed and quarantined its disposable
project. After independent review of the narrow guard correction, the project
was removed using its attested plan, exact resource inventory, and ownership
checks. Production container identity and state matched the pre-run baseline.
No beta deployment or passport acceptance is claimed from this release. Continue
with the [1.1.221 qualification coordinate](passport-predeletion-release-1.1.221.md).
