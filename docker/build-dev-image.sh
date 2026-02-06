#!/usr/bin/env bash
# build-dev-image.sh
# Builds the development Docker image with cached Rust layers
#
# This script uses a temporary build context that only includes necessary files,
# avoiding the 12GB+ context transfer issue when building from parent directory.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

# Create temporary build context
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "Creating temporary build context..."
mkdir -p "$TEMP_DIR/marty-ui"
mkdir -p "$TEMP_DIR/marty-credentials"
mkdir -p "$TEMP_DIR/marty-core"

# Copy only necessary files for building
echo "Copying marty-ui files..."
cp -r "$SCRIPT_DIR/../src" "$TEMP_DIR/marty-ui/"
cp -r "$SCRIPT_DIR/../config" "$TEMP_DIR/marty-ui/"
cp "$SCRIPT_DIR/api.dev.Dockerfile" "$TEMP_DIR/"

echo "Copying marty-credentials Rust source..."
cp -r "$PARENT_DIR/marty-credentials/rust" "$TEMP_DIR/marty-credentials/"
cp "$PARENT_DIR/marty-credentials/Cargo.toml" "$TEMP_DIR/marty-credentials/"

echo "Copying marty-core..."
# Exclude target directories to save space and time
rsync -a --exclude='target' --exclude='.git' "$PARENT_DIR/marty-core/" "$TEMP_DIR/marty-core/"

# Build the image
echo "Building Docker image with BuildKit..."
cd "$TEMP_DIR"
DOCKER_BUILDKIT=1 docker build -f api.dev.Dockerfile -t marty-ui-oid4vc-api:dev .

echo ""
echo "✅ Build complete! Image tagged as: marty-ui-oid4vc-api:dev"
echo ""
echo "To use this image:"
echo "  docker compose --profile dev up oid4vc-api"
