#!/bin/bash
# Build Rust wheels locally for CI/CD use
# This avoids expensive Rust compilation in CI pipelines

set -e

echo "Building Rust wheels locally..."
echo "================================"

# Create wheels directory
mkdir -p wheels

# Build marty-rs wheel
echo ""
echo "Building marty-rs..."
cd ../marty-credentials/rust/marty-rs
maturin build --release --out ../../../marty-ui/wheels
cd ../../../marty-ui

# Build marty-verification wheel
echo ""
echo "Building marty-verification..."
cd ../marty-core/marty-verification
maturin build --release --features python --out ../../marty-ui/wheels
cd ../../marty-ui

echo ""
echo "✅ Wheels built successfully!"
echo ""
echo "Built wheels:"
ls -lh wheels/*.whl
echo ""
echo "Next steps:"
echo "1. Test the wheels: docker compose --profile dev up oid4vc-api"
echo "2. Commit to repo: git add wheels/ && git commit -m 'chore: update Rust wheels'"
echo "3. Push to GitHub: git push"
