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
entire soak window. Event-stream deletion still requires at least seven
consecutive days after its final beta cutover; security-sensitive revocation
deletion requires at least fourteen. Pair daily reports with the unchanged
contract, lifecycle, and failure suites before approving deletion. A failed or
missing sample must be investigated and documented; this tool never shortens a
roadmap gate or authorizes production promotion.

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

Use `--require-eligible revocation-profile` for the fourteen-day gate or
`--require-eligible all` for the final combined removal audit. The generated
`marty.rust-beta-soak-window/v1` document records the current window start,
duration, samples, distinct UTC dates, interruptions, and independent deletion
eligibility. A successful time window remains only one part of the full roadmap
deletion gate.
