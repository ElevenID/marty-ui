# External command conformance gate

The exact protocol corpus is not redistributed in this public repository.
Obtain and independently verify an authorized checkout of `ElevenID/marty-protocol`
at revision `6126da7619e057be2ff58dd38a5d50f49891d1b3`, then run from `rust/`:

```bash
MARTY_DELEGATION_COMMAND_PROTOCOL_ROOT=/path/to/verified/protocol \
  cargo test --locked -p marty-delegated-authority \
  commands::tests::protocol_command_equality_vectors_and_unsupported_use_commands \
  -- --ignored --exact
```

This explicitly ignored test reads the corpus from that external path. It does
not fetch or copy protocol data. Ordinary public tests use freshly authored
synthetic commands, including an equality vector independently checked with the
pinned protocol reference. Neither test authenticates a caller or qualifies a
hosted runtime.
