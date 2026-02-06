#!/bin/bash
# Setup local development environment for marty-ui using uv
# This script sets up a Python virtual environment and installs dependencies

set -e

echo "Setting up local development environment with uv..."
echo "================================================="

# Check for uv
if ! command -v uv &> /dev/null; then
    echo "Error: uv is not installed. Install it with: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Check for Python 3.11 (prefer ARM version from Homebrew)
if [ -f "/opt/homebrew/bin/python3.11" ]; then
    PYTHON_BIN="/opt/homebrew/bin/python3.11"
elif command -v python3.11 &> /dev/null; then
    PYTHON_BIN="python3.11"
else
    echo "Error: Python 3.11 not found."
    exit 1
fi

echo "Using Python: $($PYTHON_BIN --version) from $PYTHON_BIN"

# Create/Update virtual environment with uv
echo "Initializing virtual environment with uv..."
uv venv .venv --python $PYTHON_BIN

# Source venv for subsequent commands
source .venv/bin/activate

# Install essential build tools via uv
echo "Installing build tools..."
uv pip install maturin

# Install application dependencies (excluding marty-* packages initially)
echo "Installing application dependencies..."
grep -v "^marty-" src/requirements.txt > requirements-local.txt
uv pip install -r requirements-local.txt
rm requirements-local.txt

# Build and install Rust extensions in DEBUG mode (fast builds)
echo "Building Rust extensions in DEBUG mode..."

echo "Building marty-rs..."
pushd ../marty-credentials/rust/marty-rs
maturin develop
popd

echo "Building marty-verification..."
pushd ../marty-core/marty-verification
maturin develop --features python
popd

# Install local Marty packages in editable mode via uv
echo "Installing local Marty packages in editable mode..."
uv pip install -e ../marty-credentials
uv pip install -e ../marty-microservices-framework
uv pip install -e ../Marty/packages/marty-common

# Install UI dependencies
echo "Installing UI dependencies..."
pushd ui
bun install
popd

echo ""
echo "✅ Local setup complete!"
echo ""
echo "To start developing:"
echo "1. Start infrastructure: make infra"
echo "2. Activate venv: source .venv/bin/activate"
echo "3. Run API: cd src && uvicorn oid4vc_api:app --reload"
echo "4. Run UI (in another terminal): cd ui && bun run start"
