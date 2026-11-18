# Rust beta soak evidence

`scripts/collect_rust_beta_soak_evidence.py` records one sanitized, read-only
operational sample for the canonical Rust event-stream and revocation-profile
services. It does not build, restart, replace, or deploy a container.

Run it on the beta Docker host with the immutable release and coordinated
source snapshot reported by the deployed runtime markers:

```powershell
python scripts/collect_rust_beta_soak_evidence.py `
  --compose-project elevenid-beta `
  --beta-origin https://beta.elevenidllc.com `
  --release-version 1.1.160 `
  --source-revision 347180823949a3b2b5d3f2c4689bec8bd4a39f28 `
  --output tests/artifacts/rust-beta-soak/2026-08-13.json
```

The collector fails closed when it cannot identify exactly one running service
container, resolve a published health port, read required endpoints, or parse
Docker evidence. A passing `marty.rust-beta-soak/v1` report proves, for that
sample:

- public services and UI markers match the expected release and source;
- both Rust containers match the expected OCI release/source labels, are
  running and healthy, and have zero restarts;
- recent logs contain no error or panic markers (warning counts remain visible);
- event-stream health/startup/readiness pass and its cumulative drop counter is
  zero;
- revocation PostgreSQL, Redis, and organization authorization dependencies are
  ready;
- the canonical `marty-status-rust` backend, expected capabilities, release,
  source revision, and native-readiness metric match;
- CPU, memory, network, block-I/O, PID, and allowlisted service metrics are
  captured without retaining raw logs, credentials, requests, holder data, or
  other personal data.

Keep each successful report immutable. A report is one observation, not an
entire soak window. Before v1, these samples are supporting operational and
promotion evidence; elapsed time is not a code-deletion blocker once the
implementation-independent behavioral, failure, ownership, packaging, and
regression gates pass. A failed sample must still be investigated and
documented. The collector never authorizes production promotion.

Before a deletion PR, verify the complete immutable sample set. The verifier
uses independent check inventories for each service, permits no gap longer than
26 hours, resets only the affected service window after a failed sample, and
rejects mixed release/source evidence:

```powershell
python scripts/verify_rust_beta_soak_window.py `
  --reports tests/artifacts/rust-beta-soak/*.json `
  --release-version 1.1.160 `
  --source-revision 347180823949a3b2b5d3f2c4689bec8bd4a39f28 `
  --cutover-at 2026-08-13T21:42:51Z `
  --require-eligible event-stream `
  --output tests/artifacts/rust-beta-soak-window.json
```

Use `--require-eligible revocation-profile` for a release-owner-requested
fourteen-day promotion window or `--require-eligible all` for a combined
operational audit. The generated
`marty.rust-beta-soak-window/v1` document records the current window start,
duration, samples, distinct UTC dates, interruptions, and independent deletion
eligibility. These optional windows do not restore or preserve a superseded
runtime implementation.
