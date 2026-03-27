# Pre-built Rust Wheels

This directory contains pre-built Python wheels for Rust extensions to avoid compilation in CI/CD pipelines.

## Building Wheels

Run the build script from the `marty-ui` directory:

```bash
./scripts/build-rust-wheels.sh
```

This will compile:
- `marty-rs` from `marty-credentials/rust/marty-rs`
- `marty-verification` from `marty-core/marty-verification`

## Workflow

1. **Local Development**: Make changes to Rust code
2. **Build Wheels**: Run `./scripts/build-rust-wheels.sh`
3. **Test**: Verify with `docker compose -f docker-compose.base.yml -f docker-compose.profile.dev.yml up gateway`
4. **Commit**: `git add wheels/ && git commit -m "chore: update Rust wheels"`
5. **Push**: `git push`

## CI/CD Benefits

- ✅ No Rust compiler installation needed
- ✅ No 5-7 minute compilation time
- ✅ Faster CI/CD pipelines
- ✅ Lower compute costs

## Wheel Naming

Wheels are named with version and platform info:
- `marty_rs-0.1.0-cp311-abi3-linux_aarch64.whl`
- `marty_verification-0.1.0-cp311-abi3-linux_aarch64.whl`

The `abi3` indicates stable Python ABI compatibility across Python 3.11+.
