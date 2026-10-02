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
