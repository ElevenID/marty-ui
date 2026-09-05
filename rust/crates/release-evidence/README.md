# Release evidence utilities

`validate-stack-release-run` validates authenticated GitHub release-run lineage.
It does not replace signed release-manifest and exact-source verification.

## Lossless beta deployment transport

`beta-evidence-bundle` transports these three original deployment-runner files,
in this fixed order:

1. `local-deployment-manifest.json`
2. `deployed-demo-manifest.json`
3. `stack-manifest.json`

```sh
cargo run --locked --manifest-path rust/Cargo.toml -p marty-release-evidence \
  --bin beta-evidence-bundle -- pack ARTIFACT_DIRECTORY NEW_TRANSPORT_FILE
cargo run --locked --manifest-path rust/Cargo.toml -p marty-release-evidence \
  --bin beta-evidence-bundle -- unpack TRANSPORT_FILE NEW_OUTPUT_DIRECTORY
```

The versioned envelope contains an ordered array of base64-encoded original file
bytes. It is gzip-compressed and carried in JSON with a SHA-256 of the compressed
bytes. JSON in the documents is never parsed or normalized: original BOMs,
whitespace, duplicate members, Unicode and number representations survive.
Semantic validation remains the existing deployment/recorder validator's job.

Limits are 1 MiB per non-empty document, 5 MiB decompressed envelope and 48 KiB
serialized transport. Unknown/duplicate envelope fields, wrong schema or file
count, invalid encodings, hash mismatch and trailing compressed data are rejected.
The CLI requires regular non-symlink input files and new output paths; it never
overwrites an existing file or reuses an existing unpack directory. It validates
the complete bundle before creating the output directory. An I/O failure while
writing may leave a partial new directory; preserve it and choose a fresh path.

## Hosted consumption contract

Use the exact, reviewed release-tooling revision. A private recorder workflow can
receive the transport JSON string as `deployment_evidence` in either dispatch
inputs or `client_payload`. Do not echo it, interpolate it into shell code, or
put it into the step's displayed environment table. Read GitHub's event file:

```sh
cargo run --locked --manifest-path marty-ui/rust/Cargo.toml -p marty-release-evidence \
  --bin beta-evidence-bundle -- unpack-event "$GITHUB_EVENT_PATH" "$RUNNER_TEMP/deployment-evidence"
```

The event reader bounds input to 1 MiB and rejects missing or ambiguous evidence.
Then supply the unpacked `local-deployment-manifest.json` through the recorder's
existing `ELEVENID_LOCAL_DEPLOYMENT_MANIFEST` interface. Retain its official
manifest hash, exact release/source/component/image checks and live probe.

The envelope is integrity protection, **not** authentication, authorization or a
new release attestation. It contains retained operational metadata; send it only
through the approved private evidence workflow, never public issues or logs.
Do not rewrite a pending template or synthesize expected values from the live
probe. A qualifying binding report is not fresh recording/device/soak evidence.

The utility and local transport/qualification checks are implemented here.
Private recorder workflow intake and the lifecycle orchestration handoff still
need wiring and hosted acceptance; this patch does not claim those are complete.
