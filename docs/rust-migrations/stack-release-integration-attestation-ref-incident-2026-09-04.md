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

Protected repair PR `#776` merged at
`3a8fccdb35ea51e06a023fe67d523e0888cd3e72` after all five merge-group workflows
passed. Verification against the real locked archive accepted the release-tag
ref and rejected the former default-branch ref; 89 focused tests and actionlint
also passed.

Tombstone run `33920259321` terminally sealed claim `33918005955` from its
original `stack-release-claim-v1.1.212` artifact. The retained artifact is
`9954730289` (`stack-release-tombstone-33918005955-33920259321`), with GitHub
artifact digest
`sha256:71e3c8375bcf91fe91274140b8cc159b82a5689a6d17ac5f89d6d700f16aae70`.
Its `release-transaction.json` has digest
`sha256:f65bf18d2550fbd1049ba576fb77ddf9a51dd671ecbf6bf8f059c2ecdfc47468`,
retains transaction ID
`f33613737801957ff8f70455b337af42259061004cc24ff46b2d483dbb451643`, and
records no images, qualification gates, promoted roles, or publication.

The tombstone evidence digest is
`sha256:3f682188ab62caa5612f956426482bc64a3630848da670b77e2a06501fa605ec`.
It identifies this incident document's Git blob at repair commit
`3a8fccdb35ea51e06a023fe67d523e0888cd3e72`, before this recovery addendum.
The earlier tombstone input attempt `33920198766` supplied bare hex and failed
before writing an artifact; the successful run supplied the required `sha256:`
prefix. The workflow input description now states that format explicitly.

The failed coordinate must never be reclaimed, retagged, or deployed.
Protected PR `#777` subsequently selected `v1.1.213`, retaining all component
pins and the held example. That transaction built all three images and passed
public-stack integration but stopped before verifier comparison at the
archive/history boundary; PR `#778` and tombstone run `33926833221` complete
its recovery. The [harness-history incident](stack-release-harness-history-incident-2026-09-04.md)
retains that evidence. The next separate activation selects verified-absent
`v1.1.214`; protected qualification, publication, a static integration pin,
and aggregate beta acceptance remain outstanding.
