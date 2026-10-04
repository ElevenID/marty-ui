#!/usr/bin/env bash
# The compiler cache is an optimization; a backend outage must not suppress
# mandatory Rust validation. The workflow's later cargo commands are unchanged.
set -euo pipefail

compiler="$(rustup which rustc --toolchain 1.95.0)"
if ! sccache "$compiler" -vV >/dev/null 2>&1; then
  printf 'RUSTC_WRAPPER=\n' >> "${GITHUB_ENV:?}"
  echo 'Compiler cache unavailable; Rust validation will use rustc directly.'
fi
