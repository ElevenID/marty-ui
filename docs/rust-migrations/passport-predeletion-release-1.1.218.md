# Tombstoned passport Rust qualification coordinate: 1.1.218

The protected [claim](https://github.com/ElevenID/marty-ui/actions/runs/36865105951)
for `v1.1.218` selected source `737a52e1e0198f3953304f4bf446e90b8f98b7f1`.
Its [stack release](https://github.com/ElevenID/marty-ui/actions/runs/36865248181)
failed the verifier differential and public stack smoke gates before publication.
The [tombstone](https://github.com/ElevenID/marty-ui/actions/runs/36868613826)
sealed that claim. No Git tag, GitHub release, versioned UI, services or migrations
image, or beta deployment was produced. This coordinate must not be reused.

The verifier failure was a transaction SBOM format mismatch: current Syft emitted
CycloneDX 1.7 while the pinned harness requires 1.6. The failure happened before
the pinned SPDX oracle was read. The public stack smoke also found that the
migrations image lacked `psycopg` 3, which SQLAlchemy 2.1 selected for the
PostgreSQL URL. The tombstone's evidence hash
`sha256:d926f64df172150ae09584d8f2a8b87b9967c2eb973da661e11872073f927bba`
sealed an earlier diagnosis that incorrectly identified the SPDX oracle as the
failing input. This record corrects that diagnosis; the sealed evidence bytes
remain unchanged.

Use the [replacement 1.1.219 qualification coordinate](passport-predeletion-release-1.1.219.md)
only after its source repairs and protected checks pass.
