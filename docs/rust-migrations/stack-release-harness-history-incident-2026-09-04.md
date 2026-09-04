# Stack release harness-history incident

`v1.1.213` claim run `33922450526` binds protected-main commit
`3bf4cc05d719161a0dc026351ca6f4f12075179a`. Release run `33922539581`
successfully validated all inputs, built and signed the UI/services/migrations
images, recorded their digests, and passed the public-stack integration suite.
The verifier differential failed before runtime comparison because the attested
integration source archive has no Git metadata. Its unchanged `harness_subject`
guard requires a clean Git tree and ancestry from the hardened harness floor.
The first Git command exited 129 outside a repository.

No version tag or GitHub release was promoted; qualification and publication
jobs were skipped. No beta or production deployment occurred. The retained
digest checkpoint is artifact `9956103150`
(`stack-release-digests-33922539581`), with artifact digest
`sha256:5ce34f5efe15da9e7b6b88b279f71de0fdf765ad1f89a484fb40ae300783596d`.
It records:

| Image | Digest |
|---|---|
| UI | `sha256:685f4cd76f936399e05c7bb31c577aef988d1d28ad64e686f27900e1dd8e8f99` |
| Services | `sha256:675f7792cfab5f92242ab8c3efc8d84dde096ccf85a9559fc8e9fab961159d9e` |
| Migrations | `sha256:66a279df406103b924436e7a68ea7780715435cc5fb0b0fea94ff6bf9bfa7822` |

The successful public gate is artifact `9956158005`
(`stack-release-public-gate-33922539581`). It is partial qualification evidence,
not permission to publish or deploy without the verifier differential.

The repair fetches real Git objects at the locked integration commit and
constructs its index without checking out source. The existing verified-archive
extractor attaches that history only after checking its identity and clean
index. It then rejects any changed, missing, or extra archive file, including
ignored extras. Executed harness files still come exclusively from the
digest- and provenance-verified release archive. No synthetic commit is created,
and no clean-tree, hardened-ancestry, or source-checkout prohibition is removed.

The real locked `v1.2.79` archive passed the unchanged `harness_subject` guard
after this binding, returning commit
`7d24c73c1ef7e7dfb7e5cf119c6552321e58fa71` and hardened floor
`f0062b4e48ea1a7a489d2576bcea0e5d1fce484b`. Its harness script digest remains
`sha256:2f9b3472d1aaab3cdfe89fea9ccba2cb74553825c3d0fc22049bc8a735a30932`.

Local artifact diagnostics subsequently passed with the exact services digest
above, independently verified image provenance, the unchanged released harness,
and hash-verified `requirements/official-py312.lock` dependencies on Windows
Python 3.12.10. Rust passed 21 checks; the immutable Python oracle passed its
19 checks; comparison matched all 19 shared checks and both Rust-only checks
with no blockers. The only documented difference remains
`validation.unknown-field-detail-minimized`. All disposable verifier containers
were removed by the harness. Evidence is retained in the workspace under
`_codex-tmp/integration-archive-213-proof/work/evidence`:

| File | SHA-256 of retained local bytes |
|---|---|
| `oracle.json` | `e399f529ad912bb1213448594bcea31409986937daa78c640795c893ca4c2215` |
| `transaction.json` | `0a6e85397ee6a24798e08a06ae27fb4722ed3c72986b0709e243daf56accf113` |
| `verifier-differential.json` | `62867aa35884bdf0141123f14e91eabeb40efb927e0c4f0eb056eba5e62611e5` |

These are diagnostic results, not a replacement for the protected release
workflow's qualification artifacts or beta acceptance. The repair also passed
105 focused archive, release-contract, transaction, and tag-gate tests plus
Ruff and actionlint.

Because the repair changes the claimed UI workflow source, the old transaction
cannot be resumed on the repaired commit. After the repair passes protected
gates, tombstone claim `33922450526` from its latest digest checkpoint, retain
the images as evidence, and separately activate a verified-unused coordinate.
Never reclaim, retag, or deploy `v1.1.213`.

## Protected repair and terminal recovery

Protected PR `#778` merged at
`ae00413780a5a3408af476aca5dca5eb6553bb62`, with exact tree equivalence to
reviewed head `ad6c71454007b6e6c5cf505446423b21d6861d31`. All PR and
merge-queue gates passed, including CI `33925825239` and Rust analysis
`33925825365`.

Successful tombstone run `33926833221` consumed the latest digest checkpoint,
not the earlier empty claim. Terminal artifact `9957092310`
(`stack-release-tombstone-33922450526-33926833221`) has artifact digest
`sha256:faee6043b1af05684d6d86bd5901b586718c01d09cf9685fc48b8ea1b261533c`.
Its transaction file digest is
`sha256:93d736fc4bb724c58deb0a7d07b1d0db3afedf63bb74bd7893fa774a6600172c`.
It preserves transaction ID
`739fb62644754724129fdfa5c140292dadd064efec8319ae15c0671602350fa6`,
all three images, no qualified gates, no promoted roles, and no publication.

The tombstone evidence digest is
`sha256:8d0661271cc59c7a25edc704917149d4d5033769de8de72442ecc6cd303992d6`.
It identifies this document's Git blob at the protected repair commit, before
this addendum. The untagged images remain retained evidence, not deployment
inputs. A separate activation selects `v1.1.214` after verifying absence of
its Git tag, GitHub release and all three registry version tags. All component
pins and the held example remain unchanged. Qualification, publication, the
static integration pin, beta demos and acceptance soak remain outstanding;
production is unchanged.
