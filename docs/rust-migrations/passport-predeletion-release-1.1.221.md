# Passport Rust qualification coordinate: 1.1.221

The immutable 1.1.220 release passed its build and public-stack qualification,
but protected disposable producer run 36971849635 failed before issuing a Rust
acceptance receipt. Docker Compose chose the owned `callback_signing` network as
OpenBao's primary network mode. The partial teardown guard rejected that mode,
although the container was also attached to the required owned `private`
network. The runner quarantined the project. Controlled recovery removed only
the six containers, two internal networks, and five volumes bound to attested
plan run 36971313513; the pre- and post-recovery production inventories matched.

The stack lock selects `marty-ui@1.1.221` as an unused pre-deletion qualification
coordinate with the reviewed narrow teardown correction. The protected producer
must still pass its full disposable KMS, issuer-profile, route, callback, Flow,
restart, and cleanup gates. No 1.1.220 evidence is accepted for this source.

After this change passes protected CI and maintainer review, claim and publish
1.1.221 through `prepare-stack-tag.yml` and `cd.yml` at one exact protected-main
commit. Verify the signed manifest, source, assets, checksums, and OCI digests.
Do not deploy this qualification release to beta. Continue with the
[aggregate beta acceptance sequence](next-aggregate-beta-acceptance.md).
