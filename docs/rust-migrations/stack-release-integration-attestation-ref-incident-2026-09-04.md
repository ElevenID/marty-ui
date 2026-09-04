# Stack release integration-attestation reference incident

## Outcome

`marty-ui@v1.1.212` is a failed, non-published release transaction. Prepare
run `33918005955` claimed the coordinate for protected-main source
`3a91fde0f59e5f862c476657c77aa1d7f876b03b`. Stack release run
`33918094173` then stopped in `validate-stack` before any image build,
promotion, tag, GitHub release, or deployment job ran. Production and beta
were unchanged.

The release gate downloaded the exact `marty-integration-tests@v1.2.79`
source archive and verified its locked SHA-256. Its subsequent provenance
check incorrectly required `refs/heads/main`; GitHub's release attestation
correctly records the immutable release ref `refs/tags/v1.2.79` at pinned
source commit `7d24c73c1ef7e7dfb7e5cf119c6552321e58fa71`. The gate failed closed with:

```text
expected SourceRepositoryRef to be refs/heads/main, got refs/tags/v1.2.79
```

## Repair and recovery boundary

The release workflow now derives `refs/tags/v<version>` from the governed
integration component version, rejects non-numeric semantic versions, and
retains the exact source-commit, archive-digest, repository, and hosted-runner
attestation constraints. This corrects the expected ref without removing any
provenance check.

Claim `33918005955` must be tombstoned from its original
`stack-release-claim-v1.1.212` artifact. The failed coordinate must never be
reclaimed, retagged, or deployed. A separate reviewed activation must select a
fresh coordinate only after this repair and the tombstone have passed their
gates.
