# Additional publication boundary reference

This is a source-pinned reference-only increment, not native adapter adoption or
HTTP/loop selection. The original `canvas-mirror-python-reference.json` and
51-case `canvas-mirror-adapter-reference.json` remain byte-for-byte unchanged.
The separate `canvas-publication-boundary-reference.json` contains 13 actual
original adapter observations against Credentials
`578e86ef43166be79add2d812e92ef650535edaa`; all executed application/model/seed
source blobs are verified using the existing loader and bounded child.

Eight cases cover bridge/Badgr issued/expiry timestamps with milliseconds,
microseconds, non-UTC fixed offsets and absent expiry. The original typed model
receives `datetime.fromisoformat` values; outbound adapter payloads show actual
Python `isoformat` behavior. For example, `.123` becomes `.123000`, and a
supplied `-06:00` offset remains `-06:00`. This is not evidence that PostgreSQL
`timestamptz` retains the input offset: repository UTC normalization remains a
distinct boundary to qualify in native persistence tests.

Two cases cancel actual bridge/Badgr adapter work after its controlled HTTP
callback is entered. The same cancellation/task-join helper serves the original
ASGI/loop cases, whose observations are unchanged. The complete child deadline
continues to bound swallowed cancellation; the in-process join is not claimed
to provide an independent hard deadline. Complete before/after state remains
equal. These direct-adapter cases do not claim native shutdown or durable
orchestrator cancellation semantics.

Three Badgr response cases distinguish an empty result array falling through to
`data`, a non-object first result element rejecting later/data fallback, and an
empty result object rejecting data fallback. Results remain tagged original
Python JSON text; errors retain exact original classes/messages. Every case
retains one actual controlled HTTP callback and complete state snapshots.

```text
python scripts/capture_canvas_mirror_reference.py <credentials-git-checkout> --publication-boundary-reference --check
python -m pytest tests/test_canvas_mirror_reference.py
```

`contracts/issuance-canvas-mirror.json` binds both new artifact hashes, the exact
8/2/3 counts and the original raw source revision. JSON artifact identity is
UTF-8 with CRLF normalized to LF only; Git source blobs still use raw byte
identity. Root-discovered guards retain hash/content-mutation, CRLF, source,
complete-case, response-shape, cancellation ownership and mutually exclusive
mode checks without importing application dependencies.

No filesystem-secret mode is introduced here. The capture still rejects
arbitrary `_FILE` selectors. A future separately audited owned synthetic file
rotation section must precede any filesystem-rotation claim. No production
Rust, Core, KMS, dependency pin, deployed configuration, route owner, native
publication capability or Python deletion is changed by this reference slice.
